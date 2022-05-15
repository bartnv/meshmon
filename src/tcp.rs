use crypto_box::{ PublicKey, SalsaBox};
use rmp_serde::decode::Error as DecodeError;
use std::{ time, time::{ Duration, Instant }, default::Default, sync::RwLock, sync::Arc, convert::TryInto };
use tokio::{ net, sync, time::timeout, io::AsyncReadExt, io::AsyncWriteExt};
use crate::{ Config, Node, Connection, ConnState, Control, Protocol, encrypt_frame, decrypt_frame };

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
                if idle > 89 {
                    if debug { println!("Connection with {} lost", conn.nodename); }
                    break;
                }
                if idle > 59 {
                    frames.push(build_frame(&sbox, Protocol::Check { step: 1 }));
                }
            }
            res = ctrlrx.recv() => {
                if conn.state < ConnState::Synchronized {
                    eprintln!("Received Control message on tcp task before synchronization; ignoring");
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
                        if debug { println!("Connection with {} closed", conn.nodename); }
                        break;
                    },
                    Err(_) => {
                        if debug { println!("Read error on connection with {}", conn.nodename); }
                        break;
                    }
                };
                // let mut hex = String::with_capacity(n*2);
                // for byte in &buf[0..n] { hex.push_str(&format!("{:02X} ", byte)); };
                // println!("Received data: {}", hex);
                collector.extend_from_slice(&buf[0..n]);
                conn.lastdata = Instant::now();
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
                                eprintln!("Failed to decrypt message: {:?}; dropping connection to {}", e, conn.nodename);
                                break 'select;
                            }
                        }
                    }
                    let result: Result<Protocol, DecodeError> = rmp_serde::from_read_ref(&frame);
                    if let Err(ref e) = result {
                        if debug { eprintln!("Deserialization error: {:?}; dropping connection to {}", e, conn.nodename); }
                        break 'select;
                    }
                    let proto = result.unwrap();
                    if debug {
                        if let Protocol::Check { .. } = proto { } // Don't log Check frames
                        else { println!("Received {:?} from {}", proto, conn.nodename); }
                    }
                    match proto {
                        Protocol::Intro { version, name, pubkey } => {
                            if version != 1 {
                                eprintln!("Protocol mismatch: received unknown protocol version {} from {}; dropping", version, conn.nodename);
                                break 'select;
                            }
                            if conn.state != ConnState::New {
                                eprintln!("Protocol desync: received Intro after Crypt from {}; dropping", conn.nodename);
                                break 'select;
                            }
                            conn.state = ConnState::Introduced;
                            conn.nodename = name;

                            {
                                let mut config = config.write().unwrap();
                                let mut node = match config.nodes.iter_mut().find(|node| node.name == conn.nodename) {
                                    Some(node) => node,
                                    None => {
                                        {
                                            if !learn {
                                                eprintln!("Connection received from unknown node {} ({})", conn.nodename, pubkey);
                                                return;
                                            }
                                        }
                                        config.nodes.push(Node { name: conn.nodename.clone(), pubkey: pubkey.clone(), .. Default::default() });
                                        config.modified = true;
                                        config.nodes.last_mut().unwrap()
                                    }
                                };
                                if node.pubkey != pubkey {
                                    eprintln!("Connection received from node {} with changed pubkey ({})", conn.nodename, pubkey);
                                    return;
                                }
                                if node.connected {
                                    eprintln!("Duplicate connection received from {}; dropping", conn.nodename);
                                    return;
                                }
                                node.connected = true;
                                let mut keybytes: [u8; 32] = [0; 32];
                                keybytes.copy_from_slice(&base64::decode(pubkey).unwrap());
                                conn.pubkey = Some(PublicKey::from(keybytes));

                                sbox = Some(SalsaBox::new(conn.pubkey.as_ref().unwrap(), config.runtime.read().unwrap().privkey.as_ref().unwrap()));
                            }

                            if active {
                                if debug { println!("Switching to a secure line..."); }
                                frames.push(build_frame(&sbox, Protocol::new_crypt(&config)));
                            }
                            else {
                                frames.push(build_frame(&None, Protocol::new_intro(&config)));
                            }
                        },
                        Protocol::Crypt { boottime, osversion } => {
                            if conn.state != ConnState::Introduced {
                                eprintln!("Protocol desync: received Crypt before Intro from {}; dropping", conn.nodename);
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
                            if debug { println!("Connection with {} authenticated; host up for {} days running {}", conn.nodename, days, osversion); }
                        },
                        Protocol::Ports { node, ports } => {
                            if conn.state < ConnState::Encrypted {
                                eprintln!("Protocol desync: received Ports before Crypt from {}; dropping", conn.nodename);
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
                                    }
                                    else if debug { println!("Not sending links to already-connected node {}", conn.nodename); }
                                    frames.push(build_frame(&sbox, Protocol::Sync { seq: conn.seq }));
                                }
                                else {
                                    frames.push(build_frame(&sbox, Protocol::Ports { node: myname.clone(), ports: runtime.listen.clone() }));
                                }
                            }
                        }
                        Protocol::Node { name, pubkey } => {
                            if conn.state < ConnState::Encrypted {
                                eprintln!("Protocol desync: received Node before Crypt from {}; dropping", conn.nodename);
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
                                        eprintln!("Received Node request for unknown node {}", name);
                                    }
                                }
                            }
                            else if name != myname {
                                let mut config = config.write().unwrap();
                                match config.nodes.iter().find(|node| node.name == name) {
                                    Some(node) => {
                                        if node.pubkey != pubkey {
                                            eprintln!("Received Node message for {} with changed public key", name);
                                        }
                                    },
                                    None => {
                                        if debug { println!("Learned public key for node {}", name); }
                                        config.nodes.push(Node { name, pubkey, .. Default::default() });
                                        config.modified = true;
                                    }
                                }
                            }
                        },
                        Protocol::Link { from, to, seq } => {
                            if conn.state < ConnState::Encrypted {
                                eprintln!("Protocol desync: received Link before Crypt from {}; dropping", conn.nodename);
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
                                eprintln!("Protocol desync: received Sync before Crypt from {}; dropping", conn.nodename);
                                return;
                            }
                            if !active {
                                let config = config.read().unwrap();
                                let runtime = config.runtime.read().unwrap();
                                if !runtime.graph.node_indices().any(|i| runtime.graph[i] == conn.nodename) {
                                    for edge in runtime.graph.raw_edges() {
                                        frames.push(build_frame(&sbox, Protocol::Link { from: runtime.graph[edge.source()].clone(), to: runtime.graph[edge.target()].clone(), seq: edge.weight }));
                                    }
                                }
                                else if debug { println!("Not sending links to already-connected node {}", conn.nodename); }
                                conn.seq = seq;
                                frames.push(build_frame(&sbox, Protocol::Sync { seq }));
                            }
                            if active { control.push(Control::NewLink(conn.nodename.clone(), myname.clone(), conn.nodename.clone(), seq)); }
                            else { control.push(Control::NewLink(conn.nodename.clone(), conn.nodename.clone(), myname.clone(), seq)); }
                            for (from, to, seq) in links.drain(..) {
                                control.push(Control::NewLink(conn.nodename.clone(), from, to, seq));
                            }
                            control.push(Control::NewPeer(conn.nodename.clone(), tx.clone()));
                            conn.state = ConnState::Synchronized;
                            if debug { println!("Synchronized with {} ({}) with sequence no {}", conn.nodename, match active { true => "active", false => "passive" }, conn.seq); }
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
                        p => {
                            eprintln!("Received unexpected protocol message {:?} on TCP task", p);
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
                            eprintln!("Write error to {}", conn.nodename);
                            break;
                        }
                    }
                    Err(_) => {
                        eprintln!("Write timeout to {}", conn.nodename);
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

    {
        let mut config = config.write().unwrap();
        let res = config.nodes.iter_mut().find(|node| node.name == conn.nodename);
        if let Some(node) = res { node.connected = false; }
    }
    ctrltx.send(Control::DropPeer(conn.nodename)).await.unwrap();
}

pub async fn connect_node(config: Arc<RwLock<Config>>, control: sync::mpsc::Sender<Control>, ports: Vec<String>, learn: bool) {
    let debug = config.read().unwrap().runtime.read().unwrap().debug;
    for addr in ports {
        if debug { println!("Connecting to {}", addr); }
        match timeout(Duration::from_secs(5), net::TcpStream::connect(&addr)).await {
            Ok(res) => {
                match res {
                    Ok(mut stream) => {
                        if debug { println!("Connected to {}", addr); }
                        let frame = build_frame(&None, Protocol::new_intro(&config));
                        if timeout(Duration::from_secs(10), stream.write_all(&frame)).await.is_err() { continue; }
                        let config = config.clone();
                        let control = control.clone();
                        tokio::spawn(async move {
                            run(config, stream, control, true, learn).await;
                        });
                        return;
                    },
                    Err(e) => { if debug { println!("Error connecting to {}: {}", addr, e); } }
                }
            },
            Err(_) => { if debug { println!("Timeout connecting to {}", addr); } }
        }
    }
}

fn build_frame(sbox: &Option<SalsaBox>, proto: Protocol) -> Vec<u8> {
    // println!("Sending {:?}", proto);
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
