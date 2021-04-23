// #![allow(dead_code, unused_imports, unused_variables)]
use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use serde_derive::{Deserialize, Serialize};
use rmp_serde::decode::Error as DecodeError;
use std::{str, time, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto};
use tokio::{fs, net, sync, io::AsyncReadExt, io::AsyncWriteExt};

#[derive(Serialize, Deserialize)]
struct Config {
    name: String,
    listen: Vec<String>,
    privkey: String,
    peers: Vec<Peer>,
    #[serde(skip)]
    runtime: RwLock<Runtime>,
}

#[derive(Serialize, Deserialize)]
struct Peer {
    name: String,
    listen: Vec<String>,
}

#[derive(Default)]
struct Runtime {
    privkey: Option<SecretKey>,
    pubkey: Option<PublicKey>,
}

#[derive(Debug)]
struct Connection {
    peername: String,
    socket: net::TcpStream,
    lastdata: time::Instant,
    state: ConnState,
}
impl Connection {
    fn new(socket: net::TcpStream) -> Connection {
        Connection {
            peername: String::new(),
            socket,
            lastdata: time::Instant::now(),
            state: ConnState::New,
        }
    }
}
#[derive(Debug)]
enum ConnState {
    New,
    Introduced,
    Encrypted,
    Synchronized,
    Closed,
}
#[derive(Debug)]
enum Control {
    NewPeer,
}

#[derive(Debug, Serialize, Deserialize)]
enum Protocol {
    Intro { version: u8, name: String, pubkey: String }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let config: Arc<Config>;
    if args.contains(&"--init".to_owned()) {
        let mut rng = rand::thread_rng();
        let privkey = base64::encode(SecretKey::generate(&mut rng).to_bytes());
        config = Arc::new(
            Config {
                name: String::from("MyName"),
                listen: vec!["0.0.0.0:7531".to_owned()],
                privkey,
                peers: Vec::new(),
                runtime: RwLock::new(Default::default()),
            }
        );
        write_config(&*config).await?;
    }
    else { config = Arc::new(toml::from_str(&fs::read_to_string("config.toml").await?)?); }
    let rawkey: [u8; 32] = base64::decode(&config.privkey)?
        .as_slice()
        .try_into()
        .expect("Entry 'privkey' in config.toml is not a valid base64 private key");
    {
        let mut runtime = config.runtime.write().unwrap();
        runtime.privkey = Some(rawkey.into());
        runtime.pubkey = Some(runtime.privkey.as_ref().unwrap().public_key().clone());
    }
    println!("My pubkey is {}", base64::encode(config.runtime.read().unwrap().pubkey.unwrap().to_bytes()));

    let (tx, mut rx) = sync::mpsc::channel(10);
    for port in &config.listen {
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
        connect_all_peers(aconfig, tx.clone()).await;
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
    write_config(&*config).await?;
    Ok(())
}

async fn write_config(config: &Config) -> Result<(), Box<dyn Error>> {
    fs::write("config.toml", toml::to_string_pretty(&config)?).await?;
    Ok(())
}

async fn run_tcp(config: Arc<Config>, mut socket: net::TcpStream, control: sync::mpsc::Sender<Control>, active: bool) {
    let mut peername = match socket.peer_addr() {
        Ok(a) => a.to_string(),
        Err(_) => String::from("{unknown}")
    };
    let mut buf = vec![0; 1500];
    let mut collector: Vec<u8> = vec![];
    loop {
        let n = match socket.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            Ok(_) => {
                println!("Connection with {} closed", peername);
                return;
            },
            Err(_) => {
                println!("Read error on connection with {}", peername);
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
        let result: Result<Protocol, DecodeError> = rmp_serde::from_read_ref(&collector[2..]);
        if let Err(ref e) = result { println!("Deserialization error: {:?}", e); }
        let proto = result.unwrap();
        println!("Received {:?}", proto);
        match proto {
            Protocol::Intro { version, name, pubkey } => {
                peername = name;
                if active {
                    println!("Switching to a secure line...");
                }
                else {
                    let pubkey = base64::encode(config.runtime.read().unwrap().pubkey.unwrap().to_bytes());
                    let frame = build_frame(Protocol::Intro { version: 1, name: config.name.clone(), pubkey });
                    if socket.write_all(&frame).await.is_err() {
                        eprintln!("Write error to {}", peername);
                        break;
                    }
                }
            }
        }
        control.send(Control::NewPeer).await.unwrap();
     }
}

async fn connect_all_peers(config: Arc<Config>, control: sync::mpsc::Sender<Control>) {
    for peer in &config.peers {
        for addr in &peer.listen {
            println!("Connecting to {}", addr);
            match net::TcpStream::connect(addr).await {
                Ok(mut stream) => {
                    println!("Connected to {}", addr);
                    let pubkey = base64::encode(config.runtime.read().unwrap().pubkey.unwrap().to_bytes());
                    let frame = build_frame(Protocol::Intro { version: 1, name: config.name.clone(), pubkey });
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
}

fn build_frame(proto: Protocol) -> Vec<u8> {
    println!("Sending {:?}", proto);
    let msgpack = rmp_serde::to_vec(&proto).unwrap();
    let mut frame: Vec<u8> = Vec::with_capacity(msgpack.len()+2);
    let len: u16 = msgpack.len().try_into().unwrap();
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&msgpack);
    frame
}
