// #![allow(dead_code, unused_imports, unused_variables, unused_mut, unreachable_patterns)] // Please be quiet, I'm coding
use crypto_box::{ aead::Aead, aead::AeadCore, PublicKey, SecretKey, SalsaBox};
use std::{ str, time::{ Duration, Instant, SystemTime, UNIX_EPOCH }, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto };
use serde_derive::{ Deserialize, Serialize };
use tokio::{ fs, net, sync };
use sysinfo::{ SystemExt };
use petgraph::graph::UnGraph;
use clap::{ Command, Arg, ArgAction };
use pnet_datalink::interfaces;
use generic_array::GenericArray;
use chrono::{ TimeZone, offset::Local };
use git_version::git_version;
use termion::event::Key;

mod control;
mod tcp;
mod udp;

#[derive(Serialize, Deserialize)]
pub struct Config {
    name: String,
    listen: Vec<String>,
    privkey: String,
    targetpeers: u8,
    dotfile: Option<String>,
    nodes: Vec<Node>,
    #[serde(skip)]
    modified: bool,
    #[serde(skip)]
    runtime: RwLock<Runtime>,
}

#[derive(Default, Serialize, Deserialize)]
struct Node {
    name: String,
    listen: Vec<String>,
    pubkey: String,
    #[serde(skip)]
    connected: bool,
    #[serde(skip)]
    lastconnseq: u32,
}

#[derive(Default)]
struct Runtime {
    listen: Vec<String>,
    privkey: Option<SecretKey>,
    pubkey: Option<PublicKey>,
    sysinfo: Option<sysinfo::System>,
    graph: UnGraph<String, u32>,
    msp: UnGraph<String, u32>,
    wsclients: Vec<sync::mpsc::UnboundedSender<Result<warp::ws::Message, warp::Error>>>,
    connseq: u32,
    acceptnewnodes: bool,
    tui: bool,
    debug: bool,
    results: bool
}

#[derive(Debug)]
struct Connection {
    nodename: String,
    lastdata: Instant,
    state: ConnState,
    pubkey: Option<PublicKey>,
    seq: u32
}
impl Connection {
    fn new(nodename: String) -> Connection {
        Connection {
            nodename,
            lastdata: Instant::now(),
            state: ConnState::New,
            pubkey: None,
            seq: 0
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
#[derive(Debug, PartialEq)]
pub enum LogLevel {
    Status,
    Info,
    Error,
    Debug
}
#[derive(Debug)]
pub enum Control {
    Tick,
    Round(u64), // Ping round number
    NewPeer(String, sync::mpsc::Sender<Control>, bool), // Node name, channel (for control messages to the TCP task), report (whether to send paths to peer)
    DropPeer(String), // Node name
    NewLink(String, String, String, u32), // Sender name, link from, link to, link seqno
    DropLink(String, String, String), // Sender name, link from, link to
    Ports(String, String, Vec<String>), // From node, about node, ports
    Relay(String, Protocol), // Sender name, protocol message
    Send(Protocol), // Protocol message to send
    Scan(String, String), // From node, to node
    ScanNode(String, bool), // Node name to (re)scan, initiated externally
    Result(String, String, String, u16), // Node name, interface address, port, rtt
    Log(LogLevel, String), // Status update
    Path(String, String, String, String, String, u8), // Peer name, from name, to name, from intf, to intf, losspct
    InputKey(Key) // Termion key event from tty stdin
}

// The wire protocol, sent in serialized form over the tcp connection between nodes
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Protocol {
    Intro { version: u8, name: String, pubkey: String },
    Crypt { boottime: u64, osversion: String },
    Ports { node: String, ports: Vec<String> },
    Node { name: String, pubkey: String },
    Link { from: String, to: String, seq: u32 },
    Sync { seq: u32 },
    Drop { from: String, to: String },
    Check { step: u8 },
    Ping { value: u64 },
    Pong { value: u64, source: String },
    Scan { from: String, to: String },
    Path { from: String, to: String, fromintf: String, tointf: String, losspct: u8 }
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
        let osversion = format!("{} {} ({})",
            sysinfo.name().unwrap_or_else(|| "<unknown>".to_owned()),
            sysinfo.os_version().unwrap_or_else(|| "<unknown>".to_owned()),
            sysinfo.kernel_version().unwrap_or_else(|| "<unknown>".to_owned())
        );
        Protocol::Crypt { boottime: sysinfo.boot_time(), osversion }
    }
}

const VERSION: &str = git_version!(args = ["--tags"], fallback = env!("CARGO_PKG_VERSION"));

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let app = Command::new("meshmon")
        .version(VERSION)
        .author("Bart Noordervliet <bart@mmvi.nl>")
        .about("A distributed full-mesh network monitor")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("init")
            .about("Create a new configuration file and exit")
            .arg(Arg::new("name").short('n').long("name").help("The name for this node").default_value("MyName"))
        )
        .subcommand(Command::new("run")
            .about("Run the monitor")
            .arg(Arg::new("acceptnewnodes").short('a').long("accept").action(ArgAction::SetTrue).help("Auto-accept new nodes"))
            .arg(Arg::new("connect").short('c').long("connect").action(ArgAction::Append).help("Connect to this <address:port>"))
            .arg(Arg::new("web").short('w').long("web").help("Start HTTP server on this <address:port>"))
            .arg(Arg::new("tui").short('t').long("tui").action(ArgAction::SetTrue).help("Activate the interactive terminal user-interface"))
            .arg(Arg::new("results").long("results").action(ArgAction::SetTrue).help("Log individual ping results"))
            .arg(Arg::new("debug").long("debug").action(ArgAction::SetTrue).help("Verbose logging"))
        );
    let args = app.get_matches();
    let config: Arc<RwLock<Config>>;
    if let Some(args) = args.subcommand_matches("init") {
        let mut rng = rand::rngs::OsRng;
        let privkey = base64::encode(SecretKey::generate(&mut rng).as_bytes());
        config = Arc::new(RwLock::new(
            Config {
                name: args.get_one::<&str>("name").unwrap().to_string(),
                listen: vec!["[::]:7531".to_owned()],
                privkey,
                nodes: Vec::new(),
                targetpeers: 3,
                dotfile: None,
                modified: false,
                runtime: RwLock::new(Default::default()),
            }
        ));
        let data = toml::to_string_pretty(&*config).unwrap();
        fs::write("config.toml", data).await.unwrap();
        println!("Wrote template configuration file to 'config.toml'");
        return Ok(());
    }
    else { config = Arc::new(RwLock::new(toml::from_str(&fs::read_to_string("config.toml").await?)?)); }
    let args = args.subcommand_matches("run").unwrap();

    println!("Starting meshmon {}", VERSION);
    {
        let rawkey: [u8; 32] = base64::decode(&config.read().unwrap().privkey)?
        .as_slice()
        .try_into()
        .expect("Entry 'privkey' in config.toml is not a valid base64 private key");
        let config = config.write().unwrap();
        let mut runtime = config.runtime.write().unwrap();
        runtime.listen = get_local_interfaces(&config.listen);
        runtime.privkey = Some(rawkey.into());
        runtime.pubkey = Some(runtime.privkey.as_ref().unwrap().public_key());
        runtime.acceptnewnodes = args.get_flag("acceptnewnodes");
        runtime.tui = args.get_flag("tui");
        runtime.results = args.get_flag("results");
        runtime.debug = args.get_flag("debug");
        runtime.sysinfo = Some(sysinfo::System::new_all());
        runtime.sysinfo.as_mut().unwrap().refresh_all();
        runtime.graph.add_node(config.name.clone());
        println!("Local listen ports: {}", runtime.listen.join(", "));
        println!("My pubkey is {}", base64::encode(runtime.pubkey.as_ref().unwrap().as_bytes()));
    }

    // Pass the SocketAddr for the http server to the control task if the --web argument is passed
    let web: Option<std::net::SocketAddr> = match args.get_one::<String>("web") {
        None => None,
        Some(port) => {
            println!("Starting http server on {}", port);
            Some(port.parse().expect("--web option did not contain a valid ip:port value"))
        }
    };

    let (ctrltx, ctrlrx) = sync::mpsc::channel(10); // Channel used to send updates to the control task

    // TCP listen ports; accept connections and spawn tasks to run the TCP protocol on them
    let learn = config.read().unwrap().runtime.read().unwrap().acceptnewnodes;
    for port in &config.read().unwrap().listen {
        let ctrltx = ctrltx.clone();
        let config = config.clone();
        let listener = net::TcpListener::bind(port).await?;
        println!("Started TCP listener on {}", port);
        tokio::spawn(async move {
            let debug = config.read().unwrap().runtime.read().unwrap().debug;
            loop {
                if let Ok((socket, addr)) = listener.accept().await {
                    let ctrltx = ctrltx.clone();
                    let config = config.clone();
                    if debug {
                        let text = format!("Incoming connection from {} to {}", addr, socket.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()));
                        ctrltx.send(Control::Log(LogLevel::Debug, text)).await.unwrap();
                    }
                    tokio::spawn(async move {
                        tcp::run(config, socket, ctrltx, false, learn).await;
                    });
                }
            }
        });
    }

    // UDP listener
    let (udptx, udprx) = sync::mpsc::channel(10); // Channel used to send messages to the UDP task
    {
        let config = config.clone();
        let ctrltx = ctrltx.clone();
        tokio::spawn(async move {
            udp::run(config, ctrltx, udprx).await;
        });
    }

    // Connect to the nodes passed in --connect arguments
    if let Some(params) = args.get_many::<&str>("connect") {
        for port in params {
            let ports = vec![port.to_string()];
            let config = config.clone();
            let ctrltx = ctrltx.clone();
            tokio::spawn(async move {
                tcp::connect_node(config, ctrltx, ports, true).await;
            });
        }
    }

    // Timer loop; sends Tick messages to the control task at regular intervals
    let timertx = ctrltx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            timertx.send(Control::Tick).await.unwrap();
        }
    });

    // Control task; handles coordinating jobs
    let aconfig = config.clone();
    let control = tokio::spawn(async move {
        control::run(aconfig, ctrlrx, ctrltx, udptx, web).await;
    });
    let (res,) = tokio::join!(control);
    res.unwrap();
    Ok(())
}

fn get_local_interfaces(listen: &[String]) -> Vec<String> {
    let mut res = vec![];
    for item in listen {
        if item.starts_with("0.0.0.0:") ||
           item.starts_with("[::]:") ||
           item.starts_with("*:") {
            if let Some((_, port)) = item.rsplit_once(':') {
                for i in interfaces() {
                    if i.is_up() && !i.is_loopback() {
                        for addr in i.ips {
                            let mut ip = addr.ip().to_string();
                            if ip.starts_with("fe80:") { continue; } // IPv6 link-local addresses need a zone index which isn't portable between hosts
                            if addr.is_ipv4() { res.push(ip + ":" + port); }
                            else {
                                ip.insert(0, '[');
                                res.push(ip + "]:" + port);
                            }
                        }
                    }
                }
            }
        }
        else { // TODO: consider how we handle hostnames here
            res.push(item.to_string());
        }
    }
    res
}

pub fn encrypt_frame(sbox: &SalsaBox, plaintext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::OsRng;
    let nonce = SalsaBox::generate_nonce(&mut rng);
    let mut payload: Vec<u8> = vec![];
    payload.extend_from_slice(nonce.as_slice());
    payload.extend_from_slice(&sbox.encrypt(&nonce, plaintext).unwrap());
    payload
}
pub fn decrypt_frame(sbox: &Option<SalsaBox>, payload: &[u8]) -> Result<Vec<u8>, crypto_box::aead::Error> {
    let nonce = GenericArray::from_slice(&payload[0..24]);
    sbox.as_ref().unwrap().decrypt(nonce, &payload[24..])
}

pub fn unixtime() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
pub fn timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}
pub fn timestamp_from(ts: u64) -> String {
    Local.timestamp_opt(ts as i64, 0).unwrap().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn variant_eq<T>(a: &T, b: &T) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}
