// #![allow(dead_code, unused_imports, unused_variables, unused_mut, unreachable_patterns)] // Please be quiet, I'm coding
use crypto_box::{ aead::Aead, PublicKey, SecretKey, SalsaBox};
use serde_derive::{ Deserialize, Serialize };
use std::{ str, time::{ Duration, Instant, SystemTime, UNIX_EPOCH }, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto, collections::HashMap };
use tokio::{ fs, net, sync };
use sysinfo::{ SystemExt };
use petgraph::{ graph, graph::UnGraph };
use clap::{ Arg, App, AppSettings };
use pnet::datalink::interfaces;
use warp::Filter;
use generic_array::GenericArray;

mod control;
mod tcp;
mod udp;

const VERSION: &str = env!("CARGO_PKG_VERSION");
static INDEX_FILE: &str = include_str!("index.html");

pub trait GraphExt {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex>;
    fn has_node(&self, name: &str) -> bool;
    fn drop_detached_nodes(&mut self) -> Vec<String>;
    fn print(&self);
    fn find_weakly_connected_nodes(&self) -> Vec<String>;
    fn weakly_connected_dfs(&self, v: graph::NodeIndex, visited: &mut Vec<graph::NodeIndex>, tin: &mut HashMap<graph::NodeIndex, i8>, low: &mut HashMap<graph::NodeIndex, i8>, timer: &mut i8, parent: Option<graph::NodeIndex>) -> Vec<String>;
}
impl GraphExt for UnGraph<String, u32> {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex> {
        self.node_indices().find(|i| self[*i] == name)
    }
    fn has_node(&self, name: &str) -> bool {
        self.node_indices().any(|i| self[i] == name)
    }
    fn drop_detached_nodes(&mut self) -> Vec<String> {
        let mynode = graph::NodeIndex::new(0);
        let scc = petgraph::algo::kosaraju_scc(&*self);
        let mut dropped: Vec<String> = vec![];
        let mut retain: Vec<graph::NodeIndex> = vec![];
        for group in scc {
            if group.contains(&mynode) {
                retain.extend_from_slice(&group);
                continue;
            }
            for nodeidx in group {
                dropped.push(self[nodeidx].clone());
            }
        }
        if !retain.is_empty() { self.retain_nodes(|_, nodeidx| retain.contains(&nodeidx)); }
        dropped
    }
    fn print(&self) {
        for edge in self.raw_edges().iter() {
            println!("Edge: {} -> {} ({})", self[edge.source()], self[edge.target()], edge.weight);
        }
    }
    fn find_weakly_connected_nodes(&self) -> Vec<String> {
        let mut timer: i8 = 0;
        let mut visited: Vec<graph::NodeIndex> = Vec::new();
        let mut tin: HashMap<graph::NodeIndex, i8> = HashMap::new();
        let mut low: HashMap<graph::NodeIndex, i8> = HashMap::new();

        self.weakly_connected_dfs(graph::NodeIndex::new(0), &mut visited, &mut tin, &mut low, &mut timer, None)
    }
    fn weakly_connected_dfs(&self, v: graph::NodeIndex, visited: &mut Vec<graph::NodeIndex>, tin: &mut HashMap<graph::NodeIndex, i8>, low: &mut HashMap<graph::NodeIndex, i8>, timer: &mut i8, parent: Option<graph::NodeIndex>) -> Vec<String> {
        let mut found: Vec<String> = vec![];
        visited.push(v);
        *timer += 1;
        tin.insert(v, *timer);
        low.insert(v, *timer);

        for to in self.neighbors(v) {
            if Some(to) == parent { continue; }
            if visited.contains(&to) {
                let atin = match tin.get(&to) { Some(i) => *i, None => -1 };
                let alow = *(low.get(&v).unwrap());
                low.insert(v, match alow < atin { true => alow, false => atin });
            }
            else {
                found.append(&mut self.weakly_connected_dfs(to, visited, tin, low, timer, Some(v)));
                let vlow = *(low.get(&v).unwrap());
                let tolow = match low.get(&to) { Some(i) => *i, None => -1 };
                low.insert(v, match vlow < tolow { true => vlow, false => tolow });
            }
        }
        if parent.is_some() {
            for to in self.neighbors(v) {
                if Some(to) == parent { continue; }
                if low.get(&to).unwrap() >= tin.get(&v).unwrap() {
                    found.push(self[to].clone());
                }
            }
        }
        found
    }
}

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
    connseq: u32,
    acceptnewnodes: bool,
    tui: bool,
    debug: bool,
    results: bool,
    log: Vec<(u64, String)> // Unix timestamp, log message
}

#[derive(Debug)]
struct Connection {
    nodename: String,
    lastdata: Instant,
    state: ConnState,
    pubkey: Option<PublicKey>,
    seq: u32,
    rtt: f32,
}
impl Connection {
    fn new(nodename: String) -> Connection {
        Connection {
            nodename,
            lastdata: Instant::now(),
            state: ConnState::New,
            pubkey: None,
            seq: 0,
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
pub enum Control {
    Tick,
    Round,
    NewPeer(String, sync::mpsc::Sender<Control>), // Node name, channel (for control messages to the TCP task)
    DropPeer(String), // Node name
    NewLink(String, String, String, u32), // Sender name, link from, link to, link seqno
    DropLink(String, String, String), // Sender name, link from, link to
    Ports(String, String, Vec<String>), // From node, about node, ports
    Relay(String, Protocol), // Sender name, protocol message
    Send(Protocol), // Protocol message to send
    Scan(String, String), // From node, to node
    ScanNode(String, bool), // Node name to (re)scan, initiated externally
    Result(String, String, String, u16), // Node name, interface address, port, rtt
    Update(String), // Status update
}

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
    Pong { value: u64 },
    Scan { from: String, to: String }
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let app = App::new("meshmon")
        .version(VERSION)
        .author("Bart Noordervliet <bart@mmvi.nl>")
        .about("A distributed full-mesh network monitor")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(App::new("init")
            .about("Create a new configuration file and exit")
            .arg(Arg::new("name").short('n').long("name").takes_value(true).help("The name for this node"))
        )
        .subcommand(App::new("run")
            .about("Run the monitor")
            .arg(Arg::new("acceptnewnodes").short('a').long("accept").help("Auto-accept new nodes"))
            .arg(
                Arg::new("connect").short('c').long("connect").help("Connect to this <address:port>")
                    .multiple_occurrences(true).takes_value(true).number_of_values(1)
            )
            .arg(Arg::new("web").short('w').long("web").takes_value(true).help("Start HTTP server on this <address:port>"))
            .arg(Arg::new("tui").short('t').long("tui").help("Activate the interactive terminal user-interface"))
            .arg(Arg::new("results").long("results").help("Log individual ping results"))
            .arg(Arg::new("debug").long("debug").help("Verbose logging").conflicts_with("tui"))
        );
    let args = app.get_matches();
    let config: Arc<RwLock<Config>>;
    if let Some(args) = args.subcommand_matches("init") {
        let mut rng = rand::rngs::OsRng;
        let privkey = base64::encode(SecretKey::generate(&mut rng).as_bytes());
        config = Arc::new(RwLock::new(
            Config {
                name: args.value_of("name").unwrap_or("MyName").to_string(),
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
        runtime.acceptnewnodes = args.is_present("acceptnewnodes");
        runtime.tui = args.is_present("tui");
        runtime.results = args.is_present("results");
        runtime.debug = args.is_present("debug");
        runtime.sysinfo = Some(sysinfo::System::new_all());
        runtime.sysinfo.as_mut().unwrap().refresh_all();
        runtime.graph.add_node(config.name.clone());
        println!("Local listen ports: {}", runtime.listen.join(", "));
        println!("My pubkey is {}", base64::encode(runtime.pubkey.as_ref().unwrap().as_bytes()));
    }

    // Start the http server if the --http argument is passed
    if let Some(port) = args.value_of("web") {
        println!("Starting http server on {}", port);
        let config = config.clone();
        let sa: std::net::SocketAddr = port.parse().expect("--web option did not contain a valid ip:port value");
        tokio::spawn(async move {
            let index = warp::path::end().map(|| warp::reply::html(INDEX_FILE));
            let rpc = warp::path("rpc")
                       .and(warp::post())
                       .and(warp::body::form())
                       .and(warp::any().map(move || config.clone()))
                       .map(http_rpc);
            warp::serve(index.or(rpc)).run(sa).await;
        });
    }

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
                if let Ok((socket, _)) = listener.accept().await {
                    let ctrltx = ctrltx.clone();
                    let config = config.clone();
                    if debug { println!("Incoming connection from {} to {}", socket.peer_addr().unwrap(), socket.local_addr().unwrap()); }
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
    if let Some(params) = args.values_of("connect") {
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
        control::run(aconfig, ctrlrx, ctrltx, udptx).await;
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
fn http_rpc(form: HashMap<String, String>, config: Arc<RwLock<Config>>) -> warp::reply::Json {
    #[derive(Default, Serialize)]
    struct JsonGraph {
        error: Option<String>,
        nodes: Vec<JsonNode>,
        edges: Vec<JsonEdge>,
        log: Vec<(u64, String)>
    }
    #[derive(Serialize)]
    struct JsonNode {
        id: usize,
        label: String
    }
    #[derive(Serialize)]
    struct JsonEdge {
        from: usize,
        to: usize,
        color: &'static str
    }

    let mut res: JsonGraph = Default::default();
    if let Some(req) = form.get("req") {
        match req.as_str() {
            "update" => {
                let config = config.read().unwrap();
                let runtime = config.runtime.read().unwrap();
                let nodes = runtime.graph.raw_nodes();
                for (i, node) in nodes.iter().enumerate() {
                    res.nodes.push(JsonNode { id: i, label: node.weight.clone() });
                }
                for edge in runtime.graph.raw_edges() {
                    let color = match runtime.msp.contains_edge(edge.source(), edge.target()) {
                        true => "rgb(0, 255, 0)",
                        false => "rgb(100,100,100)"
                    };
                    res.edges.push(JsonEdge { from: edge.source().index(), to: edge.target().index(), color });
                }
                if let Some(since) = form.get("since") {
                    let since: u64 = since.parse().unwrap_or(0);
                    for (ts, msg) in &runtime.log {
                        if *ts <= since { continue; }
                        res.log.push((*ts, msg.clone()));
                    }
                }
            },
            _ => {
                res.error = Some("Invalid request".to_string());
            }
        }
    }
    else { res.error = Some("No req parameter in POST".to_string()); }
    warp::reply::json(&res)
}

pub fn encrypt_frame(sbox: &SalsaBox, plaintext: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::OsRng;
    let nonce = crypto_box::generate_nonce(&mut rng);
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
