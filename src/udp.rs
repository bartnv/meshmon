use std::{ str, time::{ Duration, Instant }, net::{ SocketAddr, IpAddr }, default::Default, sync::RwLock, sync::Arc, collections::{ HashMap, VecDeque }, convert::TryInto };
use crypto_box::{ PublicKey, SalsaBox};
use serde_derive::{ Deserialize, Serialize };
use rmp_serde::decode::Error as DecodeError;
use tokio::{ net, sync };
use pnet::{ datalink::interfaces, ipnetwork::IpNetwork, ipnetwork::Ipv6Network };
use lazy_static::lazy_static;
use crate::{ Config, Runtime, Node, Control, Protocol, encrypt_frame, decrypt_frame };

static PINGFREQ: u8 = 60;
static SPREAD: u8 = 6;
static HISTSIZE: usize = 100;

#[derive(Debug)]
enum UdpControl {
    Frame(String, String, SocketAddr, Vec<u8>) // Node name, local port, remote port, encrypted frame
}
#[derive(Serialize, Deserialize)]
enum UdpProto {
    Ping(u128)
}

struct PingNode {
    rescan: bool,
    notify: bool,
    cohort: u8,
    sbox: Option<SalsaBox>,
    ports: Vec<PingPort>,
}
impl PingNode {
    fn from(runtime: &RwLock<Runtime>, node: &Node, cohort: &mut std::iter::Cycle<std::ops::Range<u8>>) -> PingNode {
        let mut keybytes: [u8; 32] = [0; 32];
        keybytes.copy_from_slice(&base64::decode(&node.pubkey).unwrap());
        PingNode {
            rescan: true,
            notify: true,
            cohort: cohort.next().unwrap(),
            sbox: Some(SalsaBox::new(&PublicKey::from(keybytes), runtime.read().unwrap().privkey.as_ref().unwrap())),
            ports: node.listen.iter().map(|port| PingPort::from(port, None, false)).collect()
        }
    }
    fn has_port(&self, port: &str) -> bool {
        let sa: SocketAddr = port.parse().unwrap();
        let ip = sa.ip().to_string();
        for item in &self.ports {
            if item.ip == ip && item.port == sa.port() { return true; }
        }
        false
    }
}
struct PingPort {
    label: String,
    ip: String,
    port: u16,
    route: String,
    usable: bool,
    waiting: bool,
    sent: u32,
    minrtt: u16,
    losspct: f32,
    state: PortState,
    hist: VecDeque<u16>,
}
impl PingPort {
    fn from(port: &str, route: Option<String>, usable: bool) -> PingPort {
        let sa: SocketAddr = port.parse().unwrap();
        let label = match sa {
            SocketAddr::V4(sa) => sa.ip().to_string(),
            SocketAddr::V6(sa) => Ipv6Network::new(*sa.ip(), 64).unwrap().network().to_string()
        };
        PingPort {
            label,
            ip: sa.ip().to_string(),
            port: sa.port(),
            route: route.unwrap_or_default(),
            usable,
            waiting: false,
            sent: 0,
            minrtt: u16::MAX,
            losspct: 0.0,
            state: PortState::New,
            hist: VecDeque::with_capacity(HISTSIZE),
        }
    }
    fn push_hist(&mut self, result: u16) {
        if self.hist.len() >= HISTSIZE { self.hist.pop_back().unwrap(); }
        self.hist.push_front(result);
    }
}
#[derive(Debug, PartialEq, PartialOrd)]
enum PortState {
    New,
    Init(u8), // Consecutive successes
    Ok,
    Loss(u8), // Consecutive failures
    Backoff(u8) // Exponential backoff
}

lazy_static! {
    static ref MYNAME: RwLock<Vec<u8>> = RwLock::new(vec![]);
    static ref EPOCH: Instant = Instant::now();
}

pub async fn run(config: Arc<RwLock<Config>>, ctrltx: sync::mpsc::Sender<Control>, mut udprx: sync::mpsc::Receiver<Control>) {
    let (readtx, mut readrx) = sync::mpsc::channel(10);
    let mut cohort = (0..SPREAD).cycle();
    let mut nodes: HashMap<String, PingNode> = HashMap::new();
    let mut socks = HashMap::new(); // Maps bound local IP addresses to their sockets
    let (myname, ports, debug) = {
        let config = config.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        if let Ok(mut bytes) = MYNAME.write() {
            bytes.extend(config.name.clone().into_bytes());
            bytes.push(0);
        };
        (config.name.clone(), runtime.listen.clone(), runtime.debug)
    };
    for port in ports {
        match net::UdpSocket::bind(&port).await {
            Ok(sock) => {
                println!("Started UDP listener on {}", port);
                let sock = Arc::new(sock);
                let sa: SocketAddr = port.parse().unwrap();
                let ip = sa.ip();
                socks.insert(ip.to_string(), sock.clone());
                let readtx = readtx.clone();
                tokio::spawn(async move {
                    udpreader(port, sock, readtx).await;
                });
            },
            Err(e) => {
                eprintln!("Failed to bind to UDP socket {}: {}", port, e);
            }
        }
    }

    let mut tick: u64 = 0;
    let mut interval = tokio::time::interval(Duration::from_secs((PINGFREQ/SPREAD).into()));
    loop {
        tokio::select!{
            _ = interval.tick() => {
                let round = (tick%SPREAD as u64) as u8;
                if round == 0 { ctrltx.send(Control::Round).await.unwrap(); }
                for (name, node) in nodes.iter_mut() {
                    if node.rescan {
                        node.rescan = false;
                        if debug { println!("Scanning node {} UDP ports", name); }
                        let mut prev = String::new();
                        node.ports.sort_by(|a, b| a.ip.partial_cmp(&b.ip).unwrap());
                        for target in node.ports.iter_mut() {
                            if target.ip == prev { continue; }
                            prev = target.ip.clone();
                            let ip: IpAddr = target.ip.parse().unwrap();
                            for i in interfaces() {
                                if i.is_up() && !i.is_loopback() {
                                    for addr in i.ips {
                                        if addr.contains(ip) || // Use interface if its netmask contains the target ip
                                            !isprivate(ip) && variant_eq(&ip, &addr.ip()) { // or it's global and the same family
                                            let route = addr.ip().to_string();
                                            if route.starts_with("fe80::") { continue; } // Probably no point in using a link local route
                                            if debug { println!("Sending UDP probe to {}:{} via {}", target.ip, target.port, route); }
                                            if !send_ping(&socks, &node.sbox, target, &route).await && debug {
                                                eprintln!("Failed to send UDP probe to {}:{} via {}", target.ip, target.port, route);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if node.notify {
                            ctrltx.send(Control::Scan(myname.clone(), name.clone())).await.unwrap();
                            node.notify = false;
                        }
                    }
                    else {
                        if round == node.cohort+1 || (round == 0 && node.cohort == SPREAD-1) {
                            for target in node.ports.iter_mut() {
                                if target.waiting { // No response seen from previous round
                                    target.waiting = false;
                                    if target.state > PortState::Init(0) { ctrltx.send(Control::Result(name.clone(), target.route.clone(), target.ip.clone(), 0)).await.unwrap(); }
                                    target.push_hist(0);
                                    match target.state {
                                        PortState::New => { target.state = PortState::Init(0); },
                                        PortState::Init(_) if target.sent > 15 => {
                                            if debug { println!("Node {} intf {} failed to initialize with 15 pings; giving up", name, target.ip); }
                                            target.sent = 0;
                                            target.usable = false;
                                        },
                                        PortState::Init(ref mut n) => { *n = 0; },
                                        PortState::Ok => {
                                            target.state = PortState::Loss(1);
                                            // Immediately send another ping in case the path just needs to be hole-punched again
                                            // send_ping(&socks, &node.sbox, &target, &target.route).await;
                                        },
                                        PortState::Loss(ref mut n) => {
                                            *n += 1;
                                            if *n >= 3 {
                                                while let Some(i) = target.hist.back() {
                                                    if *i == 0 { target.hist.pop_back(); }
                                                    else { break; }
                                                }
                                            }
                                            if *n == 3 {
                                                ctrltx.send(Control::Update(format!("{} {} is down", name, target.label))).await.unwrap();
                                            }
                                            if *n == 15 {
                                                target.state = PortState::Backoff(1);
                                            }
                                        },
                                        PortState::Backoff(ref mut n) => {
                                            *n += 1;
                                        }
                                    }
                                }
                            }
                        }
                        if round != node.cohort { continue; }
                        let mut count = 0;
                        for target in node.ports.iter_mut() {
                            if !target.usable { count += 1; continue; }
                            if let PortState::Backoff(ref mut n) = target.state {
                                if *n & (*n-1) != 0 { // Only ping every power-of-two rounds
                                    if *n == 255 { *n = 128; }
                                    else { *n += 1; }
                                    continue;
                                }
                            }
                            if send_ping(&socks, &node.sbox, target, &target.route).await {
                                target.sent += 1;
                                target.waiting = true;
                            }
                            else if debug {
                                eprintln!("Failed to send UDP ping to {}:{} via {}", target.ip, target.port, target.route);
                            }
                        }
                        if count > 15 { eprintln!("Node {} has {} unusable ports", name, count); }
                    }
                }
                if tick%(15*SPREAD as u64) == 0 { check_loss(&ctrltx, &mut nodes).await; }
                tick += 1;
            }
            res = readrx.recv() => { // UdpControl messages from udpreader tasks
                match res.unwrap() {
                    UdpControl::Frame(name, local, remote, frame) => {
                        let res = nodes.get_mut(&name);
                        if res.is_none() {
                            if debug { eprintln!("Received UDP packet from unknown node {} ({})", name, remote); }
                            continue;
                        }
                        let node = res.unwrap();
                        let frame = match decrypt_frame(&node.sbox, &frame) {
                            Ok(plaintext) => plaintext,
                            Err(e) => {
                                eprintln!("Failed to decrypt UDP frame from {}: {:?}", remote, e);
                                continue;
                            }
                        };
                        let result: Result<Protocol, DecodeError> = rmp_serde::from_read_ref(&frame);
                        if let Err(ref e) = result {
                            eprintln!("Deserialization error in UDP frame from {}: {:?}", remote, e);
                            continue;
                        }

                        let sa: SocketAddr = local.parse().unwrap();
                        let res = socks.get(&sa.ip().to_string());
                        if res.is_none() {
                            eprintln!("Failed to find local UDP socket for port {}", local);
                            continue;
                        }
                        let sock = res.unwrap();

                        let route = sa.ip().to_string();
                        let remoteip = remote.ip().to_string();
                        let res = node.ports.iter_mut().find(|p| p.ip == remoteip && p.route == route);
                        let mut port = match res {
                            Some(port) => port,
                            None => {
                                if debug { println!("Learned new port {} for node {} with route {}", remote, name, route); }
                                node.ports.push(PingPort::from(&remote.to_string(), Some(route), true));
                                node.ports.last_mut().unwrap()
                            }
                        };

                        match result.unwrap() {
                            Protocol::Ping { value } => {
                                let frame = build_frame(&node.sbox, Protocol::Pong { value });
                                if let Err(e) = sock.send_to(&frame, &remote).await {
                                    eprintln!("Failed to send UDP packet to {} via {}: {}", remote, sa.ip(), e);
                                }
                                if !port.usable || port.state > PortState::Loss(0) {
                                    if !send_ping(&socks, &node.sbox, port, &port.route).await && debug {
                                        eprintln!("Failed to send UDP probe to {}:{} via {}", port.ip, port.port, port.route);
                                    }
                                }
                            },
                            Protocol::Pong { value } => {
                                if !port.usable {
                                    port.usable = true;
                                    if debug { println!("Marked {} as pingable via {}", port.ip, port.route); }
                                }
                                let rtt = match (EPOCH.elapsed().as_millis() as u64-value) as u16 { 0 => 1, n => n };
                                if rtt < port.minrtt { port.minrtt = rtt; }
                                if port.waiting { // Probe pings don't have waiting set
                                    port.waiting = false;
                                    port.push_hist(rtt);
                                    ctrltx.send(Control::Result(name.clone(), sa.ip().to_string(), port.ip.clone(), rtt)).await.unwrap();
                                }
                                match port.state {
                                    PortState::New => { port.state = PortState::Init(1); },
                                    PortState::Init(n) if n == 5 => { port.state = PortState::Ok; },
                                    PortState::Init(ref mut n) => { *n += 1; },
                                    PortState::Ok => { },
                                    PortState::Loss(n) => {
                                        if n >= 3 {
                                            ctrltx.send(Control::Update(format!("{} {} is up after {} losses", name, port.label, n))).await.unwrap();
                                        }
                                        else if port.losspct == 0.0 {
                                            check_loss_port(port);
                                            ctrltx.send(Control::Update(format!("{} {} is suffering {:.0}% packet loss", name, port.label, port.losspct))).await.unwrap();
                                        }
                                        port.state = PortState::Ok;
                                    },
                                    PortState::Backoff(_) => {
                                        ctrltx.send(Control::Update(format!("{} {} is up", name, port.label))).await.unwrap();
                                        port.state = PortState::Ok;
                                    }
                                }
                            },
                            p => {
                                eprintln!("Received unexpected protocol message {:?} from {}", p, remote);
                            }
                        }
                    }
                }
            }
            res = udprx.recv() => { // Messages from control task
                match res.expect("Control task has crashed; exiting...") {
                    Control::ScanNode(name, external) => {
                        let config = config.read().unwrap();
                        let node = match config.nodes.iter().find(|i| i.name == name) {
                            Some(node) => node,
                            None => {
                                eprintln!("Received Control::ScanNode for nonexisting node {}", name);
                                continue;
                            }
                        };
                        match nodes.get_mut(&name) {
                            Some(pingnode) => {
                                pingnode.rescan = true;
                                pingnode.notify = !external;
                                for port in &node.listen {
                                    if pingnode.has_port(port) { continue; }
                                    pingnode.ports.push(PingPort::from(port, None, false));
                                }
                            },
                            None => {
                                nodes.insert(name, PingNode::from(&config.runtime, node, &mut cohort));
                            }
                        }
                    },
                    c => {
                        println!("Received Control message {:?}", c);
                    }
                }
            }
        }
    }
}

async fn udpreader(port: String, sock: Arc<net::UdpSocket>, readtx: sync::mpsc::Sender<UdpControl>) {
    let mut buf = [0; 1500];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                // println!("Received {} bytes on {} from {}", len, port, addr);
                if len < 2 { eprintln!("Short UDP message from {}", addr); continue; }
                let framelen = (buf[1] as usize) << 8 | buf[0] as usize; // len is little-endian
                if len < framelen+2 { eprintln!("Short UDP message from {}", addr); continue; }
                let res = buf.iter().skip(2).position(|x| *x == 0); // name is null-terminated
                if res.is_none() { eprintln!("Invalid UDP message from {}", addr); continue; }
                let (bytes, payload) = buf[2..framelen+2].split_at(res.unwrap());
                let name = String::from_utf8(bytes.to_vec());
                if name.is_err() { eprintln!("Invalid name in UDP message from {}", addr); continue; }
                let mut frame = Vec::new();
                frame.extend_from_slice(&payload[1..]);
                if let Err(e) = readtx.send(UdpControl::Frame(name.unwrap(), port.clone(), addr, frame)).await {
                    eprintln!("MPSC channel error: {}", e);
                }
            },
            Err(e) => {
                eprintln!("UDP error: {}", e);
            }
        }
    }
}

async fn check_loss(ctrltx: &tokio::sync::mpsc::Sender<Control>, nodes: &mut HashMap<String, PingNode>) {
    for (name, node) in nodes.iter_mut() {
        for port in node.ports.iter_mut() {
            if port.losspct != 0.0 {
                let pct = port.losspct;
                check_loss_port(port);
                if port.losspct == 0.0 {
                    ctrltx.send(Control::Update(format!("{} {} has recovered from packet loss", name, port.label))).await.unwrap();
                }
                else if (port.losspct - pct).abs() > f32::EPSILON {
                    ctrltx.send(Control::Update(format!("{} {} is suffering {:.0}% packet loss", name, port.label, port.losspct))).await.unwrap();
                }
            }
        }
    }
}
fn check_loss_port(port: &mut PingPort) {
    let mut count = 0;
    for x in &port.hist {
        if *x == 0 { count += 1; }
    }
    if count > 0 {
        port.losspct = (count as f32/port.hist.len() as f32)*100.0;
    }
    else {
        port.losspct = 0.0;
    }
}

fn isprivate(ip: std::net::IpAddr) -> bool {
    lazy_static!{
        static ref RANGES: Vec<IpNetwork> = vec![
            IpNetwork::new("10.0.0.0".parse().unwrap(), 8).unwrap(),
            IpNetwork::new("100.64.0.0".parse().unwrap(), 10).unwrap(),
            IpNetwork::new("169.254.0.0".parse().unwrap(), 16).unwrap(),
            IpNetwork::new("172.16.0.0".parse().unwrap(), 12).unwrap(),
            IpNetwork::new("192.168.0.0".parse().unwrap(), 16).unwrap(),
            IpNetwork::new("fc00::".parse().unwrap(), 7).unwrap(),
            IpNetwork::new("fe80::".parse().unwrap(), 10).unwrap()
        ];
    }

    for range in &*RANGES {
        if range.contains(ip) { return true; }
    }
    false
}

async fn send_ping(socks: &HashMap<String, Arc<net::UdpSocket>>, sbox: &Option<SalsaBox>, target: &PingPort, route: &String) -> bool {
    let res = socks.get(route);
    if res.is_none() { return false; }
    let sock = res.unwrap();
    let frame = build_frame(sbox, Protocol::Ping { value: EPOCH.elapsed().as_millis() as u64 });
    sock.send_to(&frame, (target.ip.as_ref(), target.port)).await.is_ok()
}
fn build_frame(sbox: &Option<SalsaBox>, proto: Protocol) -> Vec<u8> {
    // println!("Sending {:?}", proto);
    let payload = match sbox {
        Some(sbox) => encrypt_frame(sbox, &rmp_serde::to_vec(&proto).unwrap()),
        None => rmp_serde::to_vec(&proto).unwrap()
    };
    let mut frame: Vec<u8> = Vec::new();
    let name = MYNAME.read().unwrap();
    let len = name.len()+payload.len();
    let len: u16 = len.try_into().unwrap();
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&name);
    frame.extend_from_slice(&payload);
    frame
}

fn variant_eq<T>(a: &T, b: &T) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}
