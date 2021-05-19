// #![allow(dead_code, unused_imports, unused_variables, unused_mut, unreachable_patterns)] // Please be quiet, I'm coding
use crypto_box::{ PublicKey, SecretKey };
use serde_derive::{ Deserialize, Serialize };
use std::{ str, time::{ Duration, Instant }, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto, collections::HashMap };
use tokio::{ fs, net, sync };
use sysinfo::{ SystemExt };
use petgraph::{ graph, graph::UnGraph };
use clap::{ Arg, App, SubCommand };
use pnet::datalink::interfaces;
use warp::Filter;

mod control;
mod tcp;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
static INDEX_FILE: &'static str = include_str!("index.html");

pub trait GraphExt {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex>;
    fn add_edge_from_names(&mut self, from: &str, to: &str, weight: u8) -> bool;
    fn drop_detached_edges(&mut self) -> usize;
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
    fn drop_detached_edges(&mut self) -> usize {
        let mynode = graph::NodeIndex::new(0);
        let start = self.edge_count();
        let scc = petgraph::algo::kosaraju_scc(&*self);
        for group in scc {
            if group.contains(&mynode) {
                self.retain_edges(|g, edgeidx| group.contains(&g.edge_endpoints(edgeidx).unwrap().0));
                break;
            }
        }
        start - self.edge_count()
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
    prio: u8,
    #[serde(skip)]
    connected: bool,
}

#[derive(Default)]
struct Runtime {
    listen: Vec<String>,
    privkey: Option<SecretKey>,
    pubkey: Option<PublicKey>,
    sysinfo: Option<sysinfo::System>,
    graph: UnGraph<String, u8>,
    acceptnewnodes: bool,
}

#[derive(Debug)]
struct Connection {
    nodename: String,
    lastdata: Instant,
    state: ConnState,
    pubkey: Option<PublicKey>,
    prio: u8,
    rtt: f32,
}
impl Connection {
    fn new(nodename: String) -> Connection {
        Connection {
            nodename,
            lastdata: Instant::now(),
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
pub enum Control {
    Tick,
    NewPeer(String, sync::mpsc::Sender<Control>), // Node name, channel (for reverse control messages back to the connection task)
    DropPeer(String), // Node name
    NewLink(String, String, String, u8), // Sender name, link from, link to, link weight
    DropLink(String, String, String), // Sender name, link from, link to
    Relay(String, Protocol), // Sender name, protocol message
    Send(Protocol), // Protocol message to send
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Protocol {
    Intro { version: u8, name: String, pubkey: String },
    Crypt { boottime: u64, osversion: String },
    Ports { node: String, ports: Vec<String> },
    Link { from: String, to: String, prio: u8 },
    Sync { weight: u8 },
    Drop { from: String, to: String },
    Ping { step: u8 },
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
            sysinfo.get_name().unwrap_or_else(|| "<unknown>".to_owned()),
            sysinfo.get_os_version().unwrap_or_else(|| "<unknown>".to_owned()),
            sysinfo.get_kernel_version().unwrap_or_else(|| "<unknown>".to_owned())
        );
        Protocol::Crypt { boottime: sysinfo.get_boot_time(), osversion }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = App::new("meshmon")
        .version(VERSION)
        .author("Bart Noordervliet <bart@mmvi.nl>")
        .about("A distributed full-mesh network monitor")
        .arg(Arg::with_name("acceptnewnodes").short("a").long("accept").help("Auto-accept new nodes"))
        .arg(
            Arg::with_name("connect").short("c").long("connect").help("Connect to this <address:port>")
                .multiple(true).takes_value(true).number_of_values(1)
        )
        .arg(Arg::with_name("http").short("h").long("http").takes_value(true).help("Start HTTP server on this <address:port>"))
        .subcommand(SubCommand::with_name("init")
            .about("Create a new configuration file and exit")
            .arg(Arg::with_name("name").short("n").long("name").takes_value(true).help("The name for this node"))
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
                modified: false,
                runtime: RwLock::new(Default::default()),
            }
        ));
        let data = toml::to_string_pretty(&*config).unwrap();
        fs::write("config.toml", data).await.unwrap();
        return Ok(());
    }
    else { config = Arc::new(RwLock::new(toml::from_str(&fs::read_to_string("config.toml").await?)?)); }

    println!("Starting meshmon {}", VERSION);
    {
        let rawkey: [u8; 32] = base64::decode(&config.read().unwrap().privkey)?
        .as_slice()
        .try_into()
        .expect("Entry 'privkey' in config.toml is not a valid base64 private key");
        let mut config = config.write().unwrap();
        let mut prio = 1;
        for node in config.nodes.iter_mut() {
            node.prio = prio;
            prio += 1;
        }
        let mut runtime = config.runtime.write().unwrap();
        runtime.listen = get_local_interfaces(&config.listen);
        runtime.privkey = Some(rawkey.into());
        runtime.pubkey = Some(runtime.privkey.as_ref().unwrap().public_key().clone());
        runtime.acceptnewnodes = args.is_present("acceptnewnodes");
        runtime.sysinfo = Some(sysinfo::System::new_all());
        runtime.sysinfo.as_mut().unwrap().refresh_all();
        runtime.graph.add_node(config.name.clone());
        println!("Local listen ports: {}", runtime.listen.join(", "));
        println!("My pubkey is {}", base64::encode(runtime.pubkey.as_ref().unwrap().as_bytes()));
    }

    // TCP listen ports; accepts connections and spawns a task to run the TCP protocol on them
    let (tx, rx) = sync::mpsc::channel(10); // Channel used to send updates to the control task
    let learn = config.read().unwrap().runtime.read().unwrap().acceptnewnodes;
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
                        tcp::run(config, socket, tx, false, learn).await;
                    });
                }
            }
        });
    }

    // Start the http server if the --web argument is passed
    if let Some(port) = args.value_of("http") {
        println!("Starting http server on {}", port);
        let config = config.clone();
        let sa: std::net::SocketAddr = port.parse().expect("--http option did not contain a valid ip:port value");
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

    // Connect to the nodes passed in --connect arguments
    if let Some(params) = args.values_of("connect") {
        for port in params {
            let ports = vec![port.to_string()];
            let config = config.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                tcp::connect_node(config, tx, ports, true).await;
            });
        }
    }

    // Timer loop; sends Tick messages to the control task at regular intervals
    let timertx = tx.clone();
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
        control::run(aconfig, rx, tx).await;
    });
    let (res,) = tokio::join!(control);
    res.unwrap();
    Ok(())
}

fn get_local_interfaces(listen: &Vec<String>) -> Vec<String> {
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
                            if ip.starts_with("fe80:") { continue; } // IPv6 link-local addresses need a zone index which we can't relay
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
        edges: Vec<JsonEdge>
    }
    #[derive(Serialize)]
    struct JsonNode {
        id: usize,
        label: String
    }
    #[derive(Serialize)]
    struct JsonEdge {
        from: usize,
        to: usize
    }

    let mut res: JsonGraph = Default::default();
    if let Some(req) = form.get("req") {
        match req.as_str() {
            "graph" => {
                let config = config.read().unwrap();
                let runtime = config.runtime.read().unwrap();
                let nodes = runtime.graph.raw_nodes();
                for i in 0..nodes.len() {
                    res.nodes.push(JsonNode { id: i, label: nodes[i].weight.clone() });
                }
                for edge in runtime.graph.raw_edges() {
                    res.edges.push(JsonEdge { from: edge.source().index(), to: edge.target().index() });
                }
            }
            _ => {
                res.error = Some("Invalid request".to_string());
            }
        }
    }
    else { res.error = Some("No req parameter in POST".to_string()); }
    warp::reply::json(&res)
}
