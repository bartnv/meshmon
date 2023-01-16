use crypto_box::{ PublicKey, SalsaBox};
use rmp_serde::decode::Error as DecodeError;
use std::{ time, time::{ Duration, Instant }, default::Default, sync::{ RwLock, Arc, atomic::Ordering }, convert::TryInto };
use tokio::{ net, sync, time::timeout, io::AsyncReadExt, io::AsyncWriteExt};
use base64::{ Engine as _, engine::general_purpose::STANDARD as base64 };
use crate::{ Config, Node, Connection, ConnState, Control, Protocol, LogLevel, encrypt_frame, decrypt_frame };

pub async fn run(config: Arc<RwLock<Config>>, mut socket: net::TcpStream, ctrltx: sync::mpsc::Sender<Control>, active: bool, learn: bool) {
    let (tx, mut ctrlrx) = sync::mpsc::channel(10);
    let mut conn = Connection::new(match socket.peer_addr() {
        Ok(a) => a.to_string(),
        Err(_) => String::from("{unknown}")
    });
    if active {
        conn.seq = {
            let config = config.read().unwrap();
            let mut runtime = config.runtime.write().unwrap();
            runtime.connseq += 1;
            runtime.connseq
        }
    }
    let mut sbox: Option<SalsaBox> = None;
    let mut buf = vec![0; 1500];
    let mut collector: Vec<u8> = vec![];
    // let mynode = graph::NodeIndex::new(0);
    let myname = {
        let config = config.read().unwrap();
        config.name.clone()
    };
    let debug = config.read().unwrap().runtime.read().unwrap().debug;
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(10); // Collects frames to send to our peer
    let mut control: Vec<Control> = Vec::with_capacity(10); // Collects Control msgs to send to the control task
    let mut links: Vec<(String, String, u32)> = Vec::with_capacity(10);
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    'select: loop {
        tokio::select!{
            _ = interval.tick() => {
                let idle = conn.lastdata.elapsed().as_secs();
                if conn.state == ConnState::New && idle >= 9 {
                    if debug { control.push(Control::Log(LogLevel::Status, format!("Connection from {} closed (intro timeout)", conn.nodename))); }
                    break;
                }
                if idle > 89 {
                    if debug { control.push(Control::Log(LogLevel::Status, format!("Connection with {} lost", conn.nodename))); }
                    break;
                }
                if idle > 59 {
                    frames.push(build_frame(&sbox, Protocol::Check { step: 1 }));
                }
            }
            res = ctrlrx.recv() => {
                if conn.state < ConnState::Synchronized {
                    if debug {
                        let text = String::from("Received Control message on tcp task before synchronization; ignoring");
                        control.push(Control::Log(LogLevel::Debug, text));
                    }
                    continue;
                }
                match res.unwrap() {
                    Control::Send(proto) => {
                        frames.push(build_frame(&sbox, proto));
                    },
                    _ => {
                        panic!("Received unexpected Control message on control task");
                    }
                }
            }
            res = socket.read(&mut buf) => {
                let n = match res {
                    Ok(n) if n > 0 => n,
                    Ok(_) => {
                        if debug {
                            let text = format!("Connection with {} closed", conn.nodename);
                            control.push(Control::Log(LogLevel::Debug, text));
                        }
                        break;
                    },
                    Err(_) => {
                        if debug {
                            let text = format!("Read error on connection with {}", conn.nodename);
                            control.push(Control::Log(LogLevel::Debug, text));
                        }
                        break;
                    }
                };
                // let mut hex = String::with_capacity(n*2);
                // for byte in &buf[0..n] { hex.push_str(&format!("{:02X} ", byte)); };
                // println!("Received data: {}", hex);
                collector.extend_from_slice(&buf[0..n]);
                conn.lastdata = Instant::now();
                let mut report = false;
                loop {
                    // In this loop, a regular break will restart the select!{} macro, a "break 'select" will
                    // exit the function *with* cleanup and a return will exit the function without cleanup
                    if collector.len() < 2 { break; }
                    let framelen = (collector[1] as usize) << 8 | collector[0] as usize; // len is little-endian
                    if collector.len() < framelen+2 { break; }
                    collector.drain(0..2); // Remove the length header
                    let mut frame: Vec<u8> = collector.drain(0..framelen).collect();
                    if conn.state != ConnState::New { // Frame will be encrypted
                        match decrypt_frame(&sbox, &frame[..]) {
                            Ok(plaintext) => { frame = plaintext; },
                            Err(e) => {
                                let text = format!("Failed to decrypt message: {:?}; dropping connection to {}", e, conn.nodename);
                                control.push(Control::Log(LogLevel::Error, text));
                                break 'select;
                            }
                        }
                    }
                    let result: Result<Protocol, DecodeError> = rmp_serde::from_slice(&frame);
                    if let Err(ref e) = result {
                        if matches!(e, DecodeError::Syntax { .. }) { break; } // Can happen when an unknown protocol message is received
                        if debug {
                            let text = format!("Deserialization error: {:?}; dropping connection to {}", e, conn.nodename);
                            control.push(Control::Log(LogLevel::Debug, text));
                        }
                        break 'select;
                    }
                    let proto = result.unwrap();
                    if debug {
                        if let Protocol::Check { .. } = proto { } // Don't log Check frames
                        else { control.push(Control::Log(LogLevel::Debug, format!("Received {:?} from {}", proto, conn.nodename))); }
                    }
                    match proto {
                        Protocol::Intro { version, name, pubkey } => {
                            if version != 1 {
                                let text = format!("Protocol mismatch: received unknown protocol version {} from {}; dropping", version, conn.nodename);
                                control.push(Control::Log(LogLevel::Error, text));
                                break 'select;
                            }
                            if conn.state != ConnState::New {
                                if debug {
                                    let text = format!("Protocol desync: received Intro after Crypt from {}; dropping", conn.nodename);
                                    control.push(Control::Log(LogLevel::Debug, text));
                                }
                                break 'select;
                            }
                            conn.state = ConnState::Introduced;
                            conn.nodename = name;

                            {
                                let mut config = config.write().unwrap();
                                let mut node = match config.nodes.iter_mut().find(|node| node.name == conn.nodename) {
                                    Some(node) => node,
                                    None => {
                                        if !learn {
                                            let text = format!("Connection received from unknown node {} ({})", conn.nodename, pubkey);
                                            control.push(Control::Log(LogLevel::Info, text));
                                            return;
                                        }
                                        config.nodes.push(Node { name: conn.nodename.clone(), pubkey: pubkey.clone(), .. Default::default() });
                                        config.modified.store(true, Ordering::Relaxed);
                                        config.nodes.last_mut().unwrap()
                                    }
                                };
                                if node.pubkey != pubkey {
                                    let text = format!("Connection received from node {} with changed pubkey ({})", conn.nodename, pubkey);
                                    control.push(Control::Log(LogLevel::Info, text));
                                    return;
                                }
                                if node.connected {
                                    let text = format!("Duplicate connection received from {}; dropping", conn.nodename);
                                    control.push(Control::Log(LogLevel::Debug, text));
                                    return;
                                }
                                node.connected = true;
                                let mut keybytes: [u8; 32] = [0; 32];
                                keybytes.copy_from_slice(&base64.decode(pubkey).unwrap());
                                conn.pubkey = Some(PublicKey::from(keybytes));

                                sbox = Some(SalsaBox::new(conn.pubkey.as_ref().unwrap(), config.runtime.read().unwrap().privkey.as_ref().unwrap()));
                            }

                            if active {
                                if debug { control.push(Control::Log(LogLevel::Debug, String::from("Switching to a secure line..."))); }
                                frames.push(build_frame(&sbox, Protocol::new_crypt(&config)));
                            }
                            else {
                                frames.push(build_frame(&None, Protocol::new_intro(&config)));
                            }
                        },
                        Protocol::Crypt { boottime, osversion } => {
                            if conn.state != ConnState::Introduced {
                                let text = format!("Protocol desync: received Crypt before Intro from {}; dropping", conn.nodename);
                                control.push(Control::Log(LogLevel::Debug, text));
                                break 'select;
                            }
                            conn.state = ConnState::Encrypted;

                            if active {
                                let config = config.read().unwrap();
                                let runtime = config.runtime.read().unwrap();
                                frames.push(build_frame(&sbox, Protocol::Ports { node: myname.clone(), ports: runtime.listen.clone() }));
                            }
                            else {
                                frames.push(build_frame(&sbox, Protocol::new_crypt(&config)));
                            }

                            let dur = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
                            let days = (dur.as_secs() - boottime)/86400;
                            let text = format!("Connection with {} authenticated; host up for {} days running {}", conn.nodename, days, osversion);
                            control.push(Control::Log(LogLevel::Info, text));
                        },
                        Protocol::Ports { node, ports } => {
                            if conn.state < ConnState::Encrypted {
                                let text = format!("Protocol desync: received Ports before Crypt from {}; dropping", conn.nodename);
                                control.push(Control::Log(LogLevel::Debug, text));
                                break 'select;
                            }
                            control.push(Control::Ports(conn.nodename.clone(), node, ports));
                            let config = config.read().unwrap();
                            if conn.state == ConnState::Encrypted {
                                let runtime = config.runtime.read().unwrap();
                                if active {
                                    if !runtime.graph.node_indices().any(|i| runtime.graph[i] == conn.nodename) {
                                        for edge in runtime.graph.raw_edges() {
                                            frames.push(build_frame(&sbox, Protocol::Link { from: runtime.graph[edge.source()].clone(), to: runtime.graph[edge.target()].clone(), seq: edge.weight }));
                                        }
                                        report = true;
                                    }
                                    else if debug {
                                        let text = format!("Not sending links to already-connected node {}", conn.nodename);
                                        control.push(Control::Log(LogLevel::Debug, text));
                                    }
                                    frames.push(build_frame(&sbox, Protocol::Sync { seq: conn.seq }));
                                }
                                else {
                                    frames.push(build_frame(&sbox, Protocol::Ports { node: myname.clone(), ports: runtime.listen.clone() }));
                                }
                            }
                        }
                        Protocol::Node { name, pubkey } => {
                            if conn.state < ConnState::Encrypted {
                                let text = format!("Protocol desync: received Node before Crypt from {}; dropping", conn.nodename);
                                control.push(Control::Log(LogLevel::Debug, text));
                                break 'select;
                            }
                            if pubkey.is_empty() { // This is a Node request
                                let config = config.read().unwrap();
                                match config.nodes.iter().find(|node| node.name == name) {
                                    Some(node) => {
                                        frames.push(build_frame(&sbox, Protocol::Node { name: name.clone(), pubkey: node.pubkey.clone() }));
                                        frames.push(build_frame(&sbox, Protocol::Ports { node: name, ports: node.listen.clone() }));
                                    },
                                    None => {
                                        let text = format!("Received Node request for unknown node {}", name);
                                        control.push(Control::Log(LogLevel::Debug, text));
                                    }
                                }
                            }
                            else if name != myname {
                                let mut config = config.write().unwrap();
                                match config.nodes.iter().find(|node| node.name == name) {
                                    Some(node) => {
                                        if node.pubkey != pubkey {
                                            let text = format!("Received Node message for {} with changed public key", name);
                                            control.push(Control::Log(LogLevel::Info, text));
                                        }
                                    },
                                    None => {
                                        let text = format!("Learned public key for node {}", name);
                                        control.push(Control::Log(LogLevel::Info, text));
                                        config.nodes.push(Node { name, pubkey, .. Default::default() });
                                        config.modified.store(true, Ordering::Relaxed);
                                    }
                                }
                            }
                        },
                        Protocol::Link { from, to, seq } => {
                            if conn.state < ConnState::Encrypted {
                                let text = format!("Protocol desync: received Link before Crypt from {}; dropping", conn.nodename);
                                control.push(Control::Log(LogLevel::Debug, text));
                                return;
                            }
                            let config = config.read().unwrap();
                            if from != myname && !config.nodes.iter().any(|node| node.name == from) {
                                frames.push(build_frame(&sbox, Protocol::Node{ name: from.clone(), pubkey: String::new() }));
                            }
                            if to != myname && !config.nodes.iter().any(|node| node.name == to) {
                                frames.push(build_frame(&sbox, Protocol::Node{ name: to.clone(), pubkey: String::new() }));
                            }
                            if conn.state == ConnState::Encrypted { // Buffer links received before Sync
                                links.push((from, to, seq));
                            }
                            else {
                                control.push(Control::NewLink(conn.nodename.clone(), from, to, seq));
                            }
                        },
                        Protocol::Sync { seq } => {
                            if conn.state < ConnState::Encrypted {
                                let text = format!("Protocol desync: received Sync before Crypt from {}; dropping", conn.nodename);
                                control.push(Control::Log(LogLevel::Debug, text));
                                return;
                            }
                            if !active {
                                let config = config.read().unwrap();
                                let runtime = config.runtime.read().unwrap();
                                if !runtime.graph.node_indices().any(|i| runtime.graph[i] == conn.nodename) {
                                    for edge in runtime.graph.raw_edges() {
                                        frames.push(build_frame(&sbox, Protocol::Link { from: runtime.graph[edge.source()].clone(), to: runtime.graph[edge.target()].clone(), seq: edge.weight }));
                                    }
                                    report = true;
                                }
                                else if debug {
                                    let text = format!("Not sending links to already-connected node {}", conn.nodename);
                                    control.push(Control::Log(LogLevel::Debug, text));
                                }
                                conn.seq = seq;
                                frames.push(build_frame(&sbox, Protocol::Sync { seq }));
                            }
                            if active { control.push(Control::NewLink(conn.nodename.clone(), myname.clone(), conn.nodename.clone(), seq)); }
                            else { control.push(Control::NewLink(conn.nodename.clone(), conn.nodename.clone(), myname.clone(), seq)); }
                            for (from, to, seq) in links.drain(..) {
                                control.push(Control::NewLink(conn.nodename.clone(), from, to, seq));
                            }
                            control.push(Control::NewPeer(conn.nodename.clone(), tx.clone(), report));
                            conn.state = ConnState::Synchronized;
                            let text = format!("Synchronized with {} ({}) with sequence no {}", conn.nodename, match active { true => "active", false => "passive" }, conn.seq);
                            control.push(Control::Log(LogLevel::Info, text));
                        },
                        Protocol::Drop { from, to } => {
                            control.push(Control::DropLink(conn.nodename.clone(), from, to));
                        },
                        Protocol::Check { step } => {
                            if step == 1 { frames.push(build_frame(&sbox, Protocol::Check { step: 2 })); }
                        },
                        Protocol::Scan { from, to } => {
                            control.push(Control::Scan(from, to));
                        },
                        Protocol::Path { from, to, fromintf, tointf, losspct } => {
                            control.push(Control::Path(conn.nodename.clone(), from, to, fromintf, tointf, losspct));
                        },
                        p => {
                            let text = format!("Received unexpected protocol message {:?} on TCP task", p);
                            control.push(Control::Log(LogLevel::Debug, text));
                        }
                    } // End of match proto
                } // End of loop over protocol messages
            } // End of socket.read() block
        } // End of select! macro
        if !frames.is_empty() {
            for frame in &frames {
                match timeout(Duration::from_secs(10), socket.write_all(frame)).await {
                    Ok(res) => {
                        if res.is_err() {
                            let text = format!("Write error to {}", conn.nodename);
                            control.push(Control::Log(LogLevel::Debug, text));
                            break;
                        }
                    }
                    Err(_) => {
                        let text = format!("Write timeout to {}", conn.nodename);
                        control.push(Control::Log(LogLevel::Debug, text));
                        break;
                    }
                }
            }
            frames.clear();
        }
        if !control.is_empty() {
            for msg in control.drain(..) {
                ctrltx.send(msg).await.unwrap();
            }
        }
    } // End of select! loop

    if conn.state >= ConnState::Introduced {
        ctrltx.send(Control::DropPeer(conn.nodename.clone())).await.unwrap();
        let mut config = config.write().unwrap();
        let res = config.nodes.iter_mut().find(|node| node.name == conn.nodename);
        if let Some(node) = res { node.connected = false; }
    }
}

pub async fn connect_node(config: Arc<RwLock<Config>>, control: sync::mpsc::Sender<Control>, ports: Vec<String>, learn: bool) {
    let debug = config.read().unwrap().runtime.read().unwrap().debug;
    for addr in ports {
        if debug { control.send(Control::Log(LogLevel::Debug, format!("Connecting to {}", addr))).await.unwrap(); }
        match timeout(Duration::from_secs(5), net::TcpStream::connect(&addr)).await {
            Ok(res) => {
                match res {
                    Ok(mut stream) => {
                        if debug { control.send(Control::Log(LogLevel::Debug, format!("Connected to {}", addr))).await.unwrap(); }
                        let frame = build_frame(&None, Protocol::new_intro(&config));
                        if timeout(Duration::from_secs(10), stream.write_all(&frame)).await.is_err() { continue; }
                        let config = config.clone();
                        let control = control.clone();
                        tokio::spawn(async move {
                            run(config, stream, control, true, learn).await;
                        });
                        return;
                    },
                    Err(e) => { if debug { control.send(Control::Log(LogLevel::Debug, format!("Error connecting to {}: {}", addr, e))).await.unwrap(); } }
                }
            },
            Err(_) => { if debug { control.send(Control::Log(LogLevel::Debug, format!("Timeout connecting to {}", addr))).await.unwrap(); } }
        }
    }
}

fn build_frame(sbox: &Option<SalsaBox>, proto: Protocol) -> Vec<u8> {
    let payload = match sbox {
        Some(sbox) => encrypt_frame(sbox, &rmp_serde::to_vec(&proto).unwrap()),
        None => rmp_serde::to_vec(&proto).unwrap()
    };
    let mut frame: Vec<u8> = Vec::new();
    let len: u16 = payload.len().try_into().unwrap();
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}
