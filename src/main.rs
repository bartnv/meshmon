#![allow(dead_code, unused_imports, unused_variables)]
use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use serde_derive::{Deserialize, Serialize};
use rmp_serde::decode::Error as DecodeError;
use std::{str, time, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto};
use tokio::{fs, net, sync, io::AsyncReadExt, io::AsyncWriteExt};
use sysinfo::{SystemExt};
use generic_array::GenericArray;
use petgraph::{ Graph, graph };

#[derive(Serialize, Deserialize)]
struct Config {
    name: String,
    listen: Vec<String>,
    privkey: String,
    nodes: Vec<Node>,
    #[serde(skip)]
    runtime: RwLock<Runtime>,
}

#[derive(Serialize, Deserialize)]
struct Node {
    name: String,
    listen: Vec<String>,
    pubkey: String,
}

#[derive(Default)]
struct Runtime {
    privkey: Option<SecretKey>,
    pubkey: Option<PublicKey>,
    sysinfo: Option<sysinfo::System>,
    graph: Graph<String, f32>,
}

#[derive(Debug)]
struct Connection {
    nodename: String,
    lastdata: time::Instant,
    state: ConnState,
    pubkey: Option<PublicKey>,
}
impl Connection {
    fn new(nodename: String) -> Connection {
        Connection {
            nodename,
            lastdata: time::Instant::now(),
            state: ConnState::New,
            pubkey: None
        }
    }
}
#[derive(Debug, PartialEq)]
enum ConnState {
    New,
    Introduced,
    Encrypted,
    Synchronized,
    Closed,
}
#[derive(Debug)]
enum Control {
    NewConn(String, sync::mpsc::Sender<Control>),
}

#[derive(Debug, Serialize, Deserialize)]
enum Protocol {
    Intro { version: u8, name: String, pubkey: String },
    Crypt { boottime: u64, osversion: String },
    Edge { from: String, to: String, ms: f32 },
    Sync,
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
    let args: Vec<String> = env::args().collect();
    let config: Arc<RwLock<Config>>;
    if args.contains(&"--init".to_owned()) {
        let mut rng = rand::rngs::OsRng;
        let privkey = base64::encode(SecretKey::generate(&mut rng).to_bytes());
        config = Arc::new(RwLock::new(
            Config {
                name: String::from("MyName"),
                listen: vec!["0.0.0.0:7531".to_owned()],
                privkey,
                nodes: Vec::new(),
                runtime: RwLock::new(Default::default()),
            }
        ));
        write_config(&*config.read().unwrap()).await?;
    }
    else { config = Arc::new(RwLock::new(toml::from_str(&fs::read_to_string("config.toml").await?)?)); }

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

    println!("Reading system information...");
    {
        let config = config.read().unwrap();
        let mut runtime = config.runtime.write().unwrap();
        runtime.sysinfo = Some(sysinfo::System::new_all());
        runtime.sysinfo.as_mut().unwrap().refresh_all();
    }

    let (tx, mut rx) = sync::mpsc::channel(10);
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

    let aconfig = config.clone();
    let control = tokio::spawn(async move {
        connect_all_nodes(aconfig, tx.clone()).await;
        loop {
            if let Some(ctrl) = rx.recv().await {
                println!("Received control message {:?}", ctrl);
            }
            else { break; } // All Senders are gone... shouldn't happen
        }
    });
    let (res,) = tokio::join!(control);
    res.unwrap();
    tokio::time::sleep(time::Duration::from_secs(900)).await;
    write_config(&(*config).read().unwrap()).await?;
    Ok(())
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
    loop {
        let n = match socket.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            Ok(_) => {
                println!("Connection with {} closed", conn.nodename);
                return;
            },
            Err(_) => {
                println!("Read error on connection with {}", conn.nodename);
                return;
            }
        };
        // let mut hex = String::with_capacity(n*2);
        // for byte in &buf[0..n] { hex.push_str(&format!("{:02X} ", byte)); };
        // println!("Received data: {}", hex);
        collector.extend_from_slice(&buf[0..n]);
        if collector.len() < 2 { continue; }
        let framelen = (collector[1] as usize) << 8 | collector[0] as usize; // len is little-endian
        if collector.len() < framelen+2 { continue; }
        collector.drain(0..2); // Remove the length header
        let mut frame: Vec<u8> = collector.drain(0..framelen).collect();
        if conn.state != ConnState::New { // Frame will be encrypted
            let config = config.read().unwrap();
            let runtime = config.runtime.read().unwrap();
            match decrypt_frame(&sbox, &frame[..]) {
                Ok(plaintext) => { frame = plaintext; },
                Err(e) => {
                    eprintln!("Failed to decrypt message: {:?}; dropping connection to {}", e, conn.nodename);
                    return;
                }
            }
        }
        let result: Result<Protocol, DecodeError> = rmp_serde::from_read_ref(&frame);
        if let Err(ref e) = result {
            println!("Deserialization error: {:?}; dropping connection to {}", e, conn.nodename);
            return;
        }
        let proto = result.unwrap();
        println!("Received {:?}", proto);
        let mut frames: Vec<Vec<u8>> = Vec::with_capacity(10);
        match proto {
            Protocol::Intro { version, name, pubkey } => {
                conn.nodename = name;
                conn.state = ConnState::Introduced;

                {
                    let nodes = &config.read().unwrap().nodes;
                    let node = nodes.iter().find(|&node| node.name == conn.nodename);
                    if node.is_none() || (node.unwrap().pubkey != pubkey) {
                        // let newnode = Node { name: conn.nodename.clone(), listen: vec![], pubkey };
                        // config.write().unwrap().nodes.push(newnode);
                        // node = config.read().unwrap().nodes.last()
                        eprintln!("Connection received from unknown node {} ({})", conn.nodename, pubkey);
                        return;
                    }
                    let mut keybytes: [u8; 32] = [0; 32];
                    keybytes.copy_from_slice(&base64::decode(pubkey).unwrap());
                    conn.pubkey = Some(PublicKey::from(keybytes));
                }

                sbox = Some(SalsaBox::new(&conn.pubkey.as_ref().unwrap(), &config.read().unwrap().runtime.read().unwrap().privkey.as_ref().unwrap()));
                if active {
                    println!("Switching to a secure line...");
                    frames.push(build_frame(&sbox, Protocol::new_crypt(&config)));
                }
                else {
                    frames.push(build_frame(&None, Protocol::new_intro(&config)));
                }
            },
            Protocol::Crypt { boottime, osversion } => {
                conn.state = ConnState::Encrypted;
                ctrltx.send(Control::NewConn(conn.nodename.clone(), tx.clone())).await.unwrap();

                if active {
                    let config = config.read().unwrap();
                    let runtime = config.runtime.read().unwrap();
                    let nodes = runtime.graph.raw_nodes();
                    for edge in runtime.graph.raw_edges() {
                        println!("{:?}", edge);
                        // println!("{} -> {}", nodes[edge.source().into()].weight, nodes[edge.target().into()].weight);
                    }
                    frames.push(build_frame(&sbox, Protocol::Sync));
                }
                else {
                    frames.push(build_frame(&sbox, Protocol::new_crypt(&config)));
                }
            },
            Protocol::Edge { from, to, ms } => {

            },
            Protocol::Sync => {
                println!("Synchronized with {}", conn.nodename);
                if !active {
                    frames.push(build_frame(&sbox, Protocol::Sync));
                }
            }
        }
        for frame in frames {
            if socket.write_all(&frame).await.is_err() {
                eprintln!("Write error to {}", conn.nodename);
                break;
            }
        }
     }
}

async fn connect_all_nodes(config: Arc<RwLock<Config>>, control: sync::mpsc::Sender<Control>) {
    let mut targets: Vec<String> = vec![];
    for node in &config.read().unwrap().nodes {
        for addr in &node.listen {
            targets.push(addr.clone());
        }
    }
    for addr in targets {
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
            },
            Err(e) => println!("Error connecting to {}: {}", addr, e)
        }
    }
}

fn build_frame(sbox: &Option<SalsaBox>, proto: Protocol) -> Vec<u8> {
    println!("Sending {:?}", proto);
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
