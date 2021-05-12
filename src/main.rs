#![allow(dead_code, unused_imports, unused_variables, unused_mut, unreachable_patterns)] // Please be quiet, I'm coding
use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use serde_derive::{Deserialize, Serialize};
use rmp_serde::decode::Error as DecodeError;
use std::{str, time, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto, collections::HashMap };
use tokio::{fs, net, sync, io::AsyncReadExt, io::AsyncWriteExt};
use sysinfo::{SystemExt};
use generic_array::GenericArray;
use petgraph::{ graph, graph::UnGraph, dot, data::FromElements };
use clap::{ Arg, App, SubCommand };

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub trait GraphExt {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex>;
    fn add_edge_from_names(&mut self, from: &str, to: &str, weight: u8) -> bool;
    fn has_path(&self, from: graph::NodeIndex, to: &str) -> bool;
    fn print(&self);
}
impl GraphExt for UnGraph<String, u8> {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex> {
        self.node_indices().find(|i| self[*i] == name)
    }
    fn add_edge_from_names(&mut self, from: &str, to: &str, weight: u8) -> bool {
        let from = self.find_node(from).unwrap_or_else(|| self.add_node(from.to_string()));
        let to = self.find_node(to).unwrap_or_else(|| self.add_node(to.to_string()));
        match self.find_edge(from, to) {
            Some(idx) => {
                if self[idx] == weight { return false; }
                self[idx] = weight;
            },
            None => {
                self.add_edge(from, to, weight);
            }
        }
        true
    }
    fn has_path(&self, from: graph::NodeIndex, to: &str) -> bool {
        match self.find_node(to) {
            None => false,
            Some(node) => petgraph::algo::has_path_connecting(self, from, node, None)
        }
    }
    fn print(&self) {
        for edge in self.raw_edges().iter() {
            println!("Edge: {} -> {} ({})", self[edge.source()], self[edge.target()], edge.weight);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Config {
    name: String,
    listen: Vec<String>,
    privkey: String,
    nodes: Vec<Node>,
    targetpeers: u8,
    dotfile: Option<String>,
    #[serde(skip)]
    runtime: RwLock<Runtime>,
}

#[derive(Serialize, Deserialize)]
struct Node {
    name: String,
    listen: Vec<String>,
    pubkey: String,
    prio: u8,
    #[serde(skip)]
    connected: bool,
}

#[derive(Default)]
struct Runtime {
    privkey: Option<SecretKey>,
    pubkey: Option<PublicKey>,
    sysinfo: Option<sysinfo::System>,
    graph: UnGraph<String, u8>,
}

#[derive(Debug)]
struct Connection {
    nodename: String,
    lastdata: time::Instant,
    state: ConnState,
    pubkey: Option<PublicKey>,
    prio: u8,
    rtt: f32,
}
impl Connection {
    fn new(nodename: String) -> Connection {
        Connection {
            nodename,
            lastdata: time::Instant::now(),
            state: ConnState::New,
            pubkey: None,
            prio: 0,
            rtt: f32::NAN,
        }
    }
}
#[derive(Debug, PartialEq, PartialOrd)]
enum ConnState {
    New,
    Introduced,
    Encrypted,
    Synchronized,
}
#[derive(Debug)]
enum Control {
    Tick,
    NewPeer(String, sync::mpsc::Sender<Control>), // Node name, channel (for reverse control messages back to the connection task)
    Relay(String, Protocol), // Sender node, protocol message to relay
    Send(Protocol), // Protocol message to send
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum Protocol {
    Intro { version: u8, name: String, pubkey: String },
    Crypt { boottime: u64, osversion: String },
    Link { from: String, to: String, prio: u8 },
    Sync { weight: u8 },
}
impl Protocol {
    fn new_intro(config: &Arc<RwLock<Config>>) -> Protocol {
        let pubkey = base64::encode(config.read().unwrap().runtime.read().unwrap().pubkey.as_ref().unwrap().as_bytes());
        Protocol::Intro { version: 1, name: config.read().unwrap().name.clone(), pubkey }
    }
    fn new_crypt(config: &Arc<RwLock<Config>>) -> Protocol {
        let config = config.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        let sysinfo = runtime.sysinfo.as_ref().unwrap();
        let osversion = format!("{} {} ({} / {})",
            sysinfo.get_name().unwrap_or_else(|| "<unknown>".to_owned()),
            sysinfo.get_os_version().unwrap_or_else(|| "<unknown>".to_owned()),
            sysinfo.get_host_name().unwrap_or_else(|| "<unknown>".to_owned()),
            sysinfo.get_kernel_version().unwrap_or_else(|| "<unknown>".to_owned())
        );
        Protocol::Crypt { boottime: sysinfo.get_boot_time(), osversion }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = App::new("watcher")
        .version(VERSION)
        .author("Bart Noordervliet <bart@mmvi.nl>")
        .about("A distributed network monitor")
        .subcommand(SubCommand::with_name("init")
            .about("Create a new configuration file and exit")
            .arg(Arg::with_name("name").long("name").takes_value(true).help("The name for this node"))
        )
        .get_matches();
    let config: Arc<RwLock<Config>>;
    if let Some(args) = args.subcommand_matches("init") {
        let mut rng = rand::rngs::OsRng;
        let privkey = base64::encode(SecretKey::generate(&mut rng).to_bytes());
        config = Arc::new(RwLock::new(
            Config {
                name: args.value_of("name").unwrap_or("MyName").to_string(),
                listen: vec!["0.0.0.0:7531".to_owned()],
                privkey,
                nodes: Vec::new(),
                targetpeers: 3,
                dotfile: None,
                runtime: RwLock::new(Default::default()),
            }
        ));
        write_config(&*config.read().unwrap()).await?;
        return Ok(());
    }
    else { config = Arc::new(RwLock::new(toml::from_str(&fs::read_to_string("config.toml").await?)?)); }

    println!("Starting watcher {}", VERSION);
    {
        let rawkey: [u8; 32] = base64::decode(&config.read().unwrap().privkey)?
        .as_slice()
        .try_into()
        .expect("Entry 'privkey' in config.toml is not a valid base64 private key");
        let config = config.read().unwrap();
        let mut runtime = config.runtime.write().unwrap();
        runtime.privkey = Some(rawkey.into());
        runtime.pubkey = Some(runtime.privkey.as_ref().unwrap().public_key().clone());
    }
    println!("My pubkey is {}", base64::encode(config.read().unwrap().runtime.read().unwrap().pubkey.as_ref().unwrap().as_bytes()));

    println!("Initializing runtime data structures...");
    {
        let mut config = config.write().unwrap();
        let mut prio = 1;
        for node in config.nodes.iter_mut() {
            node.prio = prio;
            prio += 1;
        }
        let mut runtime = config.runtime.write().unwrap();
        runtime.sysinfo = Some(sysinfo::System::new_all());
        runtime.sysinfo.as_mut().unwrap().refresh_all();
        runtime.graph.add_node(config.name.clone());
    }

    // TCP listen ports; accepts connections and spawns a task to run the TCP protocol on them
    let (tx, mut rx) = sync::mpsc::channel(10); // Channel used to send updates to the control task
    for port in &config.read().unwrap().listen {
        let tx = tx.clone();
        let config = config.clone();
        let listener = net::TcpListener::bind(port).await?;
        println!("Started listening on {}", port);
        tokio::spawn(async move {
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    let tx = tx.clone();
                    let config = config.clone();
                    println!("Incoming connection from {} to {}", socket.peer_addr().unwrap(), socket.local_addr().unwrap());
                    tokio::spawn(async move {
                        run_tcp(config, socket, tx, false).await;
                    });
                }
            }
        });
    }

    // Timer loop; sends Tick messages to the control task at regular intervals
    let timertx = tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            timertx.send(Control::Tick).await.unwrap();
        }
    });

    // Control task; handles coordinating jobs
    let aconfig = config.clone();
    let control = tokio::spawn(async move {
        let mut peers = HashMap::new();
        let mut nodeidx = usize::MAX-1;
        let mut msp = graph::Graph::new_undirected();
        loop {
            match rx.recv().await.unwrap() {
                Control::Tick => {
                    println!("Tick");
                    let mut ports: Vec<String> = vec![];
                    {
                        let config = aconfig.read().unwrap();
                        let count = config.nodes.iter().filter(|i| i.connected).count();
                        if count < config.targetpeers.into() {
                            if let Some(idx) = find_next_node(&config.nodes, nodeidx) {
                                nodeidx = idx;
                                let node = config.nodes.get(nodeidx).unwrap();
                                for addr in &node.listen {
                                    ports.push(addr.clone());
                                }
                            }
                            if ports.is_empty() {
                                println!("Number of peers ({}) is below target number ({}), but I have no more available nodes", count, config.targetpeers);
                            }
                            else {
                                let config = aconfig.clone();
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    connect_node(config, tx, ports).await;
                                });
                            }
                        }
                        if let Some(file) = &config.dotfile {
                            let runtime = config.runtime.read().unwrap();
                            let file = file.clone();
                            let data = format!("{:?}", dot::Dot::with_config(&runtime.graph, &[dot::Config::EdgeNoLabel]));
                            tokio::spawn(async move {
                                fs::write(file, data).await.unwrap_or_else(|e| eprintln!("Failed to write dotfile: {}", e));
                            });
                        }
                    }
                },
                Control::NewPeer(name, tx) => {
                    println!("Received NewPeer Control message for {}", name);
                    let config = aconfig.read().unwrap();
                    let runtime = config.runtime.read().unwrap();
                    msp = calculate_msp(&runtime.graph);
                    peers.insert(name, tx);
                }
                Control::Relay(from, protocol) => {
                    let mut targets: Vec<sync::mpsc::Sender<Control>> = vec![];
                    for peer in msp.neighbors(graph::NodeIndex::new(0)) {
                        if msp[peer] == from { continue; }
                        match peers.get(&msp[peer]) {
                            Some(tx) => {
                                println!("Relaying {:?} to {}", protocol, msp[peer]);
                                targets.push(tx.clone());
                            },
                            None => {
                                println!("Peer {} not found", msp[peer]);
                            }
                        }

                    }
                    if !targets.is_empty() {
                        tokio::spawn(async move {
                            for tx in targets {
                                let proto = protocol.clone();
                                tx.send(Control::Send(proto)).await.unwrap();
                            }
                        });
                    }
                },
                _ => {
                    panic!("Received unexpected Control message on control task");
                }
            }
        }
    });
    let (res,) = tokio::join!(control);
    res.unwrap();
    tokio::time::sleep(time::Duration::from_secs(900)).await;
    write_config(&(*config).read().unwrap()).await?;
    Ok(())
}

fn find_next_node(nodes: &Vec<Node>, start: usize) -> Option<usize> {
    if nodes.is_empty() { return None; }
    let mut idx = start;
    let mut once = false;
    loop {
        if idx == start {
            if once { return None; }
            once = true;
        }
        idx += 1;
        if idx >= nodes.len() { idx = 0; }
        let node = nodes.get(idx).unwrap();
        if node.connected { continue; }
        if node.listen.is_empty() { continue; }
        return Some(idx);
    }
}
fn calculate_msp(graph: &UnGraph<String, u8>) -> UnGraph<String, u8> {
    graph::Graph::from_elements(petgraph::algo::min_spanning_tree(&graph))
}

async fn write_config(config: &Config) -> Result<(), Box<dyn Error>> {
    fs::write("config.toml", toml::to_string_pretty(&config)?).await?;
    Ok(())
}

async fn run_tcp(config: Arc<RwLock<Config>>, mut socket: net::TcpStream, ctrltx: sync::mpsc::Sender<Control>, active: bool) {
    let (tx, mut ctrlrx) = sync::mpsc::channel(10);
    let mut conn = Connection::new(match socket.peer_addr() {
        Ok(a) => a.to_string(),
        Err(_) => String::from("{unknown}")
    });
    let mut sbox: Option<SalsaBox> = None;
    let mut buf = vec![0; 1500];
    let mut collector: Vec<u8> = vec![];
    let mynode = graph::NodeIndex::new(0);
    let myname = {
        let config = config.read().unwrap();
        config.name.clone()
    };
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(10);
    'select: loop {
        tokio::select!{
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
                        println!("Connection with {} closed", conn.nodename);
                        break;
                    },
                    Err(_) => {
                        println!("Read error on connection with {}", conn.nodename);
                        break;
                    }
                };
                // let mut hex = String::with_capacity(n*2);
                // for byte in &buf[0..n] { hex.push_str(&format!("{:02X} ", byte)); };
                // println!("Received data: {}", hex);
                collector.extend_from_slice(&buf[0..n]);
                conn.lastdata = time::Instant::now();
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
                        println!("Deserialization error: {:?}; dropping connection to {}", e, conn.nodename);
                        break 'select;
                    }
                    let proto = result.unwrap();
                    println!("Received {:?}", proto);
                    match proto {
                        Protocol::Intro { version, name, pubkey } => {
                            conn.nodename = name;
                            conn.state = ConnState::Introduced;

                            {
                                let mut config = config.write().unwrap();
                                let res = config.nodes.iter_mut().find(|node| node.name == conn.nodename);
                                if res.is_none() {
                                    // let newnode = Node { name: conn.nodename.clone(), listen: vec![], pubkey };
                                    // config.write().unwrap().nodes.push(newnode);
                                    // node = config.read().unwrap().nodes.last()
                                    eprintln!("Connection received from unknown node {} ({})", conn.nodename, pubkey);
                                    return;
                                }
                                let node = res.unwrap();
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
                                conn.prio = node.prio;

                                sbox = Some(SalsaBox::new(&conn.pubkey.as_ref().unwrap(), &config.runtime.read().unwrap().privkey.as_ref().unwrap()));
                            }

                            if active {
                                println!("Switching to a secure line...");
                                frames.push(build_frame(&sbox, Protocol::new_crypt(&config)));
                            }
                            else {
                                frames.push(build_frame(&None, Protocol::new_intro(&config)));
                            }
                        },
                        Protocol::Crypt { boottime, osversion } => {
                            if conn.state != ConnState::Introduced {
                                eprintln!("Protocol desync: received Crypt before Intro from {}; dropping", conn.nodename);
                                return;
                            }
                            conn.state = ConnState::Encrypted;

                            if active {
                                let config = config.read().unwrap();
                                let runtime = config.runtime.read().unwrap();
                                if !runtime.graph.has_path(mynode, &conn.nodename) {
                                    for edge in runtime.graph.raw_edges() { // TODO: change to a petgraph::visit function
                                        frames.push(build_frame(&sbox, Protocol::Link { from: runtime.graph[edge.source()].clone(), to: runtime.graph[edge.target()].clone(), prio: edge.weight }));
                                    }
                                }
                                else { println!("Not sending links to already-connected node {}", conn.nodename); }
                                frames.push(build_frame(&sbox, Protocol::Sync { weight: conn.prio }));
                            }
                            else {
                                frames.push(build_frame(&sbox, Protocol::new_crypt(&config)));
                            }
                        },
                        Protocol::Link { from, to, prio } => {
                            let relay;
                            if conn.state < ConnState::Encrypted {
                                eprintln!("Protocol desync: received Link before Crypt from {}; dropping", conn.nodename);
                                return;
                            }
                            {
                                let config = config.read().unwrap();
                                let mut runtime = config.runtime.write().unwrap();
                                relay = runtime.graph.add_edge_from_names(&from, &to, prio); // True if a change was made
                            }
                            if relay { ctrltx.send(Control::Relay(conn.nodename.clone(), Protocol::Link { from, to, prio })).await.unwrap(); }
                        },
                        Protocol::Sync { weight } => {
                            if conn.state < ConnState::Encrypted {
                                eprintln!("Protocol desync: received Sync before Crypt from {}; dropping", conn.nodename);
                                return;
                            }
                            {
                                let config = config.read().unwrap();
                                let mut runtime = config.runtime.write().unwrap();
                                if !active {
                                    if !runtime.graph.has_path(mynode, &conn.nodename) {
                                        for edge in runtime.graph.raw_edges() {
                                            frames.push(build_frame(&sbox, Protocol::Link { from: runtime.graph[edge.source()].clone(), to: runtime.graph[edge.target()].clone(), prio: edge.weight }));
                                        }
                                    }
                                    else { println!("Not sending links to already-connected node {}", conn.nodename); }
                                    frames.push(build_frame(&sbox, Protocol::Sync { weight }));
                                }
                                let node = match runtime.graph.find_node(&conn.nodename) {
                                    Some(idx) => idx,
                                    None => runtime.graph.add_node(conn.nodename.clone())
                                };
                                if active { runtime.graph.update_edge(mynode, node, weight); }
                                else { runtime.graph.update_edge(node, mynode, weight); }
                                runtime.graph.print();
                            }
                            println!("Synchronized with {}", conn.nodename);
                            conn.state = ConnState::Synchronized;
                            let link = match active {
                                true => Protocol::Link { from: myname.clone(), to: conn.nodename.clone(), prio: weight },
                                false => Protocol::Link { from: conn.nodename.clone(), to: myname.clone(), prio: weight }
                            };
                            ctrltx.send(Control::Relay(conn.nodename.clone(), link)).await.unwrap();
                            ctrltx.send(Control::NewPeer(conn.nodename.clone(), tx.clone())).await.unwrap();
                        }
                    }
                } // End of loop over protocol messages
            } // End of socket.read() block
        } // End of select! macro
        if !frames.is_empty() {
            for frame in &frames {
                if socket.write_all(&frame).await.is_err() {
                    eprintln!("Write error to {}", conn.nodename);
                    break;
                }
            }
            frames.clear();
        }
    } // End of select loop

    let mut config = config.write().unwrap();
    let res = config.nodes.iter_mut().find(|node| node.name == conn.nodename);
    if let Some(node) = res { node.connected = false; }
    let mut runtime = config.runtime.write().unwrap();
    if let Some(nodeidx) = runtime.graph.find_node(&conn.nodename) {
        if let Some(edge) = runtime.graph.find_edge(mynode, nodeidx) {
            runtime.graph.remove_edge(edge);
        }
        let scc = petgraph::algo::kosaraju_scc(&runtime.graph);
        for group in scc {
            if group.contains(&nodeidx) {
                if group.len() > 1 { println!("Lost {} nodes behind {}", group.len()-1, conn.nodename); }
                runtime.graph.retain_edges(|g, edgeidx| !group.contains(&g.edge_endpoints(edgeidx).unwrap().0));
                break;
            }
        }
        runtime.graph.print();
    }
}

async fn connect_node(config: Arc<RwLock<Config>>, control: sync::mpsc::Sender<Control>, ports: Vec<String>) {
    for addr in ports {
        println!("Connecting to {}", addr);
        match net::TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                println!("Connected to {}", addr);
                let frame = build_frame(&None, Protocol::new_intro(&config));
                if stream.write_all(&frame).await.is_err() { continue; }
                let config = config.clone();
                let control = control.clone();
                tokio::spawn(async move {
                    run_tcp(config, stream, control, true).await;
                });
                return;
            },
            Err(e) => println!("Error connecting to {}: {}", addr, e)
        }
    }
}

fn build_frame(sbox: &Option<SalsaBox>, proto: Protocol) -> Vec<u8> {
    // println!("Sending {:?}", proto);
    let payload = match sbox {
        Some(sbox) => encrypt_frame(&sbox, &rmp_serde::to_vec(&proto).unwrap()),
        None => rmp_serde::to_vec(&proto).unwrap()
    };
    let mut frame: Vec<u8> = Vec::new();
    let len: u16 = payload.len().try_into().unwrap();
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn encrypt_frame(sbox: &SalsaBox, plaintext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::OsRng;
    let nonce = crypto_box::generate_nonce(&mut rng);
    let mut payload: Vec<u8> = vec![];
    payload.extend_from_slice(nonce.as_slice());
    payload.extend_from_slice(&sbox.encrypt(&nonce, plaintext).unwrap());
    payload
}
fn decrypt_frame(sbox: &Option<SalsaBox>, payload: &[u8]) -> Result<Vec<u8>, crypto_box::aead::Error> {
    let nonce = GenericArray::from_slice(&payload[0..24]);
    sbox.as_ref().unwrap().decrypt(nonce, &payload[24..])
}
