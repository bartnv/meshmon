use std::{ str, time::{ Duration, Instant }, net::{ SocketAddr, IpAddr }, default::Default, sync::RwLock, sync::Arc, collections::{ HashMap, VecDeque }, convert::TryInto };
use crypto_box::{ PublicKey, SalsaBox};
use serde_derive::{ Deserialize, Serialize };
use rmp_serde::decode::Error as DecodeError;
use tokio::{ net, sync };
use pnet::{ datalink::interfaces, ipnetwork::IpNetwork };
use lazy_static::lazy_static;
use crate::{ Config, Runtime, Node, Control, Protocol, encrypt_frame, decrypt_frame };

static PINGFREQ: u8 = 60;
static SPREAD: u8 = 6;
static HISTSIZE: usize = 60;

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
    label: &'static str,
    ip: String,
    port: u16,
    route: String,
    usable: bool,
    waiting: bool,
    sent: u32,
    minrtt: u16,
    state: PortState,
    hist: VecDeque<u16>,
}
impl PingPort {
    fn from(port: &str, route: Option<String>, usable: bool) -> PingPort {
        let sa: SocketAddr = port.parse().unwrap();
        let private = isprivate(sa.ip());
        let label = match sa {
            SocketAddr::V4(_) => {
                match private {
                    true => "IPv4-private",
                    false => "IPv4-global"
                }
            },
            SocketAddr::V6(_) => {
                match private {
                    true => "IPv6-private",
                    false => "IPv6-global"
                }
            }
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

pub async fn run(config: Arc<RwLock<Config>>, ctrltx: sync::mpsc::Sender<Control>, mut udprx: sync::mpsc::Receiver<Control>) {
    let epoch = Instant::now();
    let (readtx, mut readrx) = sync::mpsc::channel(10);
    let mut cohort = (0..SPREAD).cycle();
    let mut nodes: HashMap<String, PingNode> = HashMap::new();
    let mut socks = HashMap::new(); // Maps bound local IP addresses to their sockets
    let (myname, namebytes, ports, debug) = {
        let config = config.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        let mut namebytes = config.name.clone().into_bytes();
        namebytes.push(0);
        (config.name.clone(), namebytes, runtime.listen.clone(), runtime.debug)
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
                                        if addr.contains(ip) || (!isprivate(ip) && (ip.is_ipv4() && addr.is_ipv4()) || (ip.is_ipv6() && addr.is_ipv6())) {
                                            let route = addr.ip().to_string();
                                            if let Some(sock) = socks.get(&route) {
                                                if debug { println!("Sending UDP probe to {}:{} via {}", target.ip, target.port, route); }
                                                let frame = build_frame(&namebytes, &node.sbox, Protocol::Ping { value: epoch.elapsed().as_millis() as u64 });
                                                if let Err(e) = sock.send_to(&frame, (target.ip.as_ref(), target.port)).await {
                                                    eprintln!("Failed to send UDP packet to {}:{} via {}: {}", target.ip, target.port, route, e);
                                                }
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
                                    if target.state > PortState::Init(15) { ctrltx.send(Control::Result(name.clone(), target.route.clone(), target.ip.clone(), 0)).await.unwrap(); }
                                    target.push_hist(0);
                                    match target.state {
                                        PortState::New => { target.state = PortState::Init(0); },
                                        PortState::Init(_) if target.sent > 15 => {
                                            if debug { println!("Node {} intf {} failed to initialize with 15 pings; giving up", name, target.ip); }
                                            target.sent = 0;
                                            target.usable = false;
                                        },
                                        PortState::Init(ref mut n) => { *n = 0; },
                                        PortState::Ok => { target.state = PortState::Loss(1); },
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
                            if let PortState::Backoff(n) = target.state {
                                if round%(n^2) != 0 { continue; }
                            }
                            let res = socks.get(&target.route);
                            if res.is_none() {
                                eprintln!("Failed to find local UDP socket {}", target.route);
                                continue;
                            }
                            let sock = res.unwrap();
                            let frame = build_frame(&namebytes, &node.sbox, Protocol::Ping { value: epoch.elapsed().as_millis() as u64 });
                            if let Err(e) = sock.send_to(&frame, (target.ip.as_ref(), target.port)).await {
                                eprintln!("Failed to send UDP packet to {} via {}: {}", target.port, target.route, e);
                            }
                            else {
                                target.sent += 1;
                                if !std::matches!(target.state, PortState::Backoff(_)) { target.waiting = true; }
                            }
                        }
                        if count > 15 { eprintln!("Node {} has {} unusable ports", name, count); }
                    }
                }
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
                                let frame = build_frame(&namebytes, &node.sbox, Protocol::Pong { value });
                                if let Err(e) = sock.send_to(&frame, &remote).await {
                                    eprintln!("Failed to send UDP packet to {} via {}: {}", remote, sa.ip(), e);
                                }
                                if !port.usable {
                                    let frame = build_frame(&namebytes, &node.sbox, Protocol::Ping { value: epoch.elapsed().as_millis() as u64 });
                                    if let Err(e) = sock.send_to(&frame, &remote).await {
                                        eprintln!("Failed to send UDP packet to {} via {}: {}", remote, sa.ip(), e);
                                    }
                                }
                            },
                            Protocol::Pong { value } => {
                                if !port.usable {
                                    port.usable = true;
                                    port.route = sa.ip().to_string();
                                    if debug { println!("Marked {} as pingable via {}", port.ip, port.route); }
                                }
                                let rtt = match (epoch.elapsed().as_millis() as u64-value) as u16 { 0 => 1, n => n };
                                if rtt < port.minrtt { port.minrtt = rtt; }
                                if port.waiting { // Probe pings don't have waiting set
                                    port.waiting = false;
                                    port.push_hist(rtt);
                                    ctrltx.send(Control::Result(name.clone(), sa.ip().to_string(), port.ip.clone(), rtt)).await.unwrap();
                                }
                                match port.state {
                                    PortState::New => { port.state = PortState::Init(1); },
                                    PortState::Init(n) if n == 5 => {
                                        if debug { println!("Port initialized with minrtt {}", port.minrtt); }
                                        port.state = PortState::Ok;
                                    },
                                    PortState::Init(ref mut n) => { *n += 1; },
                                    PortState::Ok => { },
                                    PortState::Loss(n) => {
                                        if n >= 3 {
                                            ctrltx.send(Control::Update(format!("{} {} is up after {} losses", name, port.label, n))).await.unwrap();
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
                match res.unwrap() {
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
                                    pingnode.ports.push(PingPort::from(&port, None, false));
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
                let (namebytes, payload) = buf[2..framelen+2].split_at(res.unwrap());
                let name = String::from_utf8(namebytes.to_vec());
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

fn build_frame(name: &[u8], sbox: &Option<SalsaBox>, proto: Protocol) -> Vec<u8> {
    // println!("Sending {:?}", proto);
    let payload = match sbox {
        Some(sbox) => encrypt_frame(&sbox, &rmp_serde::to_vec(&proto).unwrap()),
        None => rmp_serde::to_vec(&proto).unwrap()
    };
    let mut frame: Vec<u8> = Vec::new();
    let len = name.len()+payload.len();
    let len: u16 = len.try_into().unwrap();
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(name);
    frame.extend_from_slice(&payload);
    frame
}
