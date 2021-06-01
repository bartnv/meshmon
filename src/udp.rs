use std::{ str, time::{ Duration, Instant }, net::SocketAddr, default::Default, sync::RwLock, sync::Arc, collections::HashMap };
use crypto_box::{ PublicKey, SalsaBox};
use serde_derive::{ Deserialize, Serialize };
use rmp_serde::decode::Error as DecodeError;
use tokio::{ net, sync, time };
use pnet::{ datalink::interfaces, ipnetwork::IpNetwork };
use crate::{ Config, Control, Protocol, build_frame, decrypt_frame };

#[derive(Debug)]
enum UdpControl {
    Frame(String, SocketAddr, Vec<u8>) // Local port, remote port, encrypted frame
}
#[derive(Serialize, Deserialize)]
enum UdpProto {
    Ping(u128)
}

struct PingNode {
    name: String,
    scanned: bool,
    sbox: Option<SalsaBox>,
    ports: Vec<PingPort>
}
impl PingNode {
    fn has_port(&self, port: &str) -> bool {
        for item in &self.ports {
            if item.port == port { return true; }
        }
        false
    }
}
struct PingPort {
    port: String,
    route: String,
    usable: bool
}

pub async fn run(config: Arc<RwLock<Config>>, ctrltx: sync::mpsc::Sender<Control>, mut udprx: sync::mpsc::Receiver<Control>) {
    let epoch = Instant::now();
    let (readtx, mut readrx) = sync::mpsc::channel(10);
    let mut ports;
    let mut nodes: Vec<PingNode> = Vec::new();
    let mut socks = HashMap::new(); // Maps bound local IP addresses to their sockets
    {
        let config = config.read().unwrap();
        for node in &config.nodes {
            let mut keybytes: [u8; 32] = [0; 32];
            keybytes.copy_from_slice(&base64::decode(&node.pubkey).unwrap());
            nodes.push(
                PingNode {
                    name: node.name.clone(),
                    scanned: false,
                    sbox: Some(SalsaBox::new(&PublicKey::from(keybytes), &config.runtime.read().unwrap().privkey.as_ref().unwrap())),
                    ports: node.listen.iter().map(|port| PingPort { port: port.to_string(), route: String::new(), usable: false }).collect()
                }
            );
        }
        let runtime = config.runtime.read().unwrap();
        ports = runtime.listen.clone();
    }
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

    let mut interval = tokio::time::interval_at(time::Instant::now() + Duration::from_secs(10), Duration::from_secs(60));
    loop {
        tokio::select!{
            _ = interval.tick() => {
                for node in nodes.iter_mut() {
                    if node.scanned == true {
                        for target in &node.ports {
                            if target.usable == false { continue; }
                            println!("Would ping {} via {}", target.port, target.route);
                        }
                    }
                    else {
                        node.scanned = true;
                        for target in node.ports.iter_mut() {
                            let sa: SocketAddr = target.port.parse().unwrap();
                            let ip = sa.ip();
                            let port = sa.port();
                            let mut route = None;
                            'outer: for i in interfaces() {
                                if i.is_up() && !i.is_loopback() {
                                    for addr in i.ips {
                                        if addr.contains(ip) {
                                            route = Some(addr.ip().to_string());
                                            break 'outer;
                                        }
                                        else if route.is_none() && !isprivate(ip) {
                                            if (ip.is_ipv4() && addr.is_ipv4()) || (ip.is_ipv6() && addr.is_ipv6()) {
                                                route = Some(addr.ip().to_string()); // Assign the default route
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(route) = route {
                                match socks.get(&route) {
                                    Some(sock) => {
                                        println!("Sending UDP ping to {}:{} via {}", ip, port, route);
                                        let frame = build_frame(&node.sbox, Protocol::Ping { value: epoch.elapsed().as_millis() as u64 });
                                        if let Err(e) = sock.send_to(&frame, (ip, port)).await {
                                            eprintln!("Failed to send UDP packet to {}:{} via {}: {}", ip, port, route, e);
                                        }
                                    }
                                    None => {
                                        eprintln!("No valid route found for outgoing UDP packet to {}:{}", ip, port);
                                    }
                                }
                                target.route = route;
                            }
                        }
                    }
                }
            }
            res = readrx.recv() => { // UdpControl messages from udpreader tasks
                match res.unwrap() {
                    UdpControl::Frame(local, remote, frame) => {
                        let remote = remote.to_string();
                        let res = nodes.iter_mut().find(|n| n.has_port(&remote));
                        if res.is_none() {
                            println!("Received UDP packet from unknown port {}", remote);
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
                            println!("Deserialization error in UDP frame from {}: {:?}", remote, e);
                            continue;
                        }

                        let sa: SocketAddr = local.parse().unwrap();
                        let res = socks.get(&sa.ip().to_string());
                        if res.is_none() {
                            eprintln!("Failed to find local UDP socket {}", sa.ip());
                            continue;
                        }
                        let sock = res.unwrap();

                        let res = node.ports.iter_mut().find(|p| p.port == remote);
                        if res.is_none() {
                            eprintln!("Failed to find remote UDP port {}", remote);
                            continue;
                        }
                        let port = res.unwrap();

                        match result.unwrap() {
                            Protocol::Ping { value } => {
                                let frame = build_frame(&node.sbox, Protocol::Pong { value });
                                if let Err(e) = sock.send_to(&frame, &remote).await {
                                    eprintln!("Failed to send UDP packet to {} via {}: {}", remote, sa.ip(), e);
                                }
                                if port.usable == false {
                                    let frame = build_frame(&node.sbox, Protocol::Ping { value: epoch.elapsed().as_millis() as u64 });
                                    if let Err(e) = sock.send_to(&frame, &remote).await {
                                        eprintln!("Failed to send UDP packet to {} via {}: {}", remote, sa.ip(), e);
                                    }
                                }
                            },
                            Protocol::Pong { value } => {
                                if port.usable == false {
                                    port.usable = true;
                                    println!("Marked {} as pingable", port.port);
                                }
                                println!("Node {} port {} rtt {}ms", node.name, port.port, epoch.elapsed().as_millis() as u64-value);
                                break;
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
                println!("Received {} bytes on {} from {}", len, port, addr);
                if len < 2 { continue; }
                let framelen = (buf[1] as usize) << 8 | buf[0] as usize; // len is little-endian
                if len < framelen+2 { continue; }
                let mut frame = Vec::new();
                frame.extend_from_slice(&buf[2..framelen+2]);
                if let Err(e) = readtx.send(UdpControl::Frame(port.clone(), addr, frame)).await {
                    eprintln!("MPSC channel error: {}", e);
                }
            },
            Err(e) => {
                println!("UDP error: {}", e);
            }
        }
    }
}

fn isprivate(ip: std::net::IpAddr) -> bool {
    let mut ranges = vec![];
    ranges.push(IpNetwork::new("10.0.0.0".parse().unwrap(), 8).unwrap());
    ranges.push(IpNetwork::new("100.64.0.0".parse().unwrap(), 10).unwrap());
    ranges.push(IpNetwork::new("169.254.0.0".parse().unwrap(), 16).unwrap());
    ranges.push(IpNetwork::new("172.16.0.0".parse().unwrap(), 12).unwrap());
    ranges.push(IpNetwork::new("192.168.0.0".parse().unwrap(), 16).unwrap());
    ranges.push(IpNetwork::new("fc00::".parse().unwrap(), 7).unwrap());
    ranges.push(IpNetwork::new("fe80::".parse().unwrap(), 10).unwrap());
    for range in ranges {
        if range.contains(ip) { return true; }
    }
    false
}
