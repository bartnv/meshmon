use std::{ sync::{ RwLock, Arc }, sync::atomic::Ordering, mem::drop, collections::{ HashMap, VecDeque }, cmp };
use hyper_tungstenite::{HyperWebsocket, tungstenite::Message};
use regex::Regex;
use tokio::{ fs, sync, net::TcpListener };
use tokio_stream::wrappers::TcpListenerStream;
use futures_util::stream::StreamExt;
use petgraph::{ graph, graph::UnGraph, data::FromElements, algo };
use termion::{ raw::IntoRawMode, screen::IntoAlternateScreen, screen::AlternateScreen, raw::RawTerminal, input::TermRead, event::Key };
use tui::{ Terminal, Frame, backend::{ Backend, TermionBackend }, widgets::{ Block, Borders, List, ListItem, Table, Row }, layout::{ Layout, Constraint, Direction, Corner }, text::{ Span, Spans }, style::{ Style, Color } };
use lazy_static::lazy_static;
use rand::seq::SliceRandom;
use http_body_util::Full;
use hyper::{ Request, Response };
use hyper::body::{ Bytes, Incoming };
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls_acme::AcmeConfig;
use serde::Serialize;
use ring::digest::{ Context, SHA256 };
use base64::{ Engine as _, engine::general_purpose::STANDARD as base64 };
use async_trait::async_trait;
use rustls_acme::{ AccountCache, CertCache };
use crate::{ Config, Node, Control, Protocol, LogLevel, unixtime, timestamp, timestamp_from, get_local_interfaces, duration_from };

static HISTSIZE: usize = 1440;
static THRESHOLD: u16 = 4;
static MAX_LINGER: u64 = 86400; // Seconds to keep visualising links that are down
static INDEX_FILE: &str = include_str!("../web/index.html");
static ICON_FILE: &[u8] = include_bytes!("../web/favicon.ico");

trait GraphExt {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex>;
    fn has_node(&self, name: &str) -> bool;
    fn drop_detached_nodes(&mut self) -> Vec<String>;
    fn print(&self);
    fn find_weakly_connected_nodes(&self) -> Vec<String>;
    fn weakly_connected_dfs(&self, v: graph::NodeIndex, depth: u8, visited: &mut HashMap<graph::NodeIndex, u8>, found: &mut Vec<String>, parent: Option<graph::NodeIndex>) -> (u8, Vec<String>);
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
        let mut visited: HashMap<graph::NodeIndex, u8> = HashMap::new();
        let mut found: Vec<String> = vec![];

        self.weakly_connected_dfs(graph::NodeIndex::new(0), 0, &mut visited, &mut found, None);
        found
    }
    fn weakly_connected_dfs(&self, v: graph::NodeIndex, mut depth: u8, visited: &mut HashMap<graph::NodeIndex, u8>, found: &mut Vec<String>, parent: Option<graph::NodeIndex>) -> (u8, Vec<String>) {
        let mut children: Vec<String> = vec![];
        if let Some(parent) = parent {
            if parent.index() != 0 { children.push(self[v].clone()); }
        }
        depth += 1;
        visited.insert(v, depth);
        let mut low = depth;

        for to in self.neighbors(v) {
            if Some(to) == parent { continue; }
            if let Some(other) = visited.get(&to) {
                if *other < low { low = *other; }
            }
            else {
                let (lowest, mut names) = self.weakly_connected_dfs(to, depth, visited, found, Some(v));
                if v.index() == 0 { continue; }
                if lowest >= depth {
                    found.append(&mut names);
                }
                else if lowest < low { low = lowest; }
                children.append(&mut names);
            }
        }
        (low, children)
    }
}

struct PingResult {
    node: String,
    intf: String,
    port: String,
    min: u16,
    losspct: f32,
    last: Option<u16>,
    hist: VecDeque<u16>,
    statesince: u64 // Unix timestamp
}
impl PingResult {
    fn new(node: String, intf: String, port: String) -> PingResult {
        PingResult { node, intf, port, min: u16::MAX, losspct: 0.0, last: None, hist: VecDeque::with_capacity(HISTSIZE), statesince: unixtime() }
    }
    fn push_hist(&mut self, result: u16) {
        if self.hist.len() >= HISTSIZE { self.hist.pop_back().unwrap(); }
        self.hist.push_front(result);
    }
}
impl Ord for PingResult {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.node.cmp(&other.node) {
            cmp::Ordering::Equal => {
                match self.port.cmp(&other.port) { // TODO: better comparison for ip addresses
                    cmp::Ordering::Equal => self.intf.cmp(&other.intf),
                    ord => ord
                }
            },
            ord => ord
        }
    }
}
impl Eq for PingResult {}
impl PartialOrd for PingResult {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for PingResult {
    fn eq(&self, other: &Self) -> bool {
        self.node == other.node && self.port == other.port && self.intf == other.intf
    }
}

#[derive(Default)]
struct Data {
    log: RwLock<VecDeque<(u64, String)>>,
    ping: RwLock<VecDeque<String>>,
    intf: RwLock<HashMap<String, IntfStats>>,
    results: RwLock<Vec<PingResult>>,
    pathcache: RwLock<Vec<Path>>
}
impl Data {
    fn push_log(&self, ts: u64, line: String) {
        let mut log = self.log.write().unwrap();
        if log.len() >= 50 { log.pop_back().unwrap(); }
        log.push_front((ts, line));
    }
    fn push_ping(&self, line: String) {
        let mut ping = self.ping.write().unwrap();
        if ping.len() >= 50 { ping.pop_back().unwrap(); }
        ping.push_front(line);
    }
}
struct IntfStats {
    symbol: char,
    min: u16,
    lag: u16
}

#[derive(Debug)]
struct Path {
    from: String,
    to: String,
    fromintf: String,
    tointf: String,
    losspct: u8,
    since: u64
}
impl Path {
    fn new(from: String, to: String, fromintf: String, tointf: String, losspct: u8) -> Path {
        Path { from, to, fromintf, tointf, losspct, since: unixtime() }
    }
}
impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.from == other.from && self.to == other.to && self.fromintf == other.fromintf && self.tointf == other.tointf
    }
}

struct ConfigCache {
    config: Arc<RwLock<Config>>
}
impl ConfigCache {
    fn new(config: &Arc<RwLock<Config>>) -> ConfigCache {
        ConfigCache {
            config: config.clone()
        }
    }
    fn cached_account_key(&self, contact: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for el in contact {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = base64.encode(ctx.finish());
        format!("cached_account_{}", hash)
    }
    fn cached_cert_key(&self, domains: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for domain in domains {
            ctx.update(domain.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = base64.encode(ctx.finish());
        format!("cached_cert_{}", hash)
    }
}
#[async_trait]
impl CertCache for ConfigCache {
    type EC = std::io::Error;
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let key = self.cached_cert_key(&domains, directory_url);
        Ok(self.config.read().unwrap().cache.get(&key).map(|v| base64.decode(v).unwrap()))
    }
    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let key = self.cached_cert_key(&domains, directory_url);
        let mut config = self.config.write().unwrap();
        config.cache.insert(key, base64.encode(cert));
        config.modified.store(true, Ordering::Relaxed);
        Ok(())
    }
}
#[async_trait]
impl AccountCache for ConfigCache {
    type EA = std::io::Error;
    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let key = self.cached_account_key(&contact, directory_url);
        Ok(self.config.read().unwrap().cache.get(&key).map(|v| base64.decode(v).unwrap()))
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let key = self.cached_account_key(&contact, directory_url);
        let mut config = self.config.write().unwrap();
        config.cache.insert(key, base64.encode(account));
        config.modified.store(true, Ordering::Relaxed);
        Ok(())
    }
}

fn start_tui(data: Arc<Data>) -> Option<Terminal<TermionBackend<AlternateScreen<RawTerminal<std::io::Stdout>>>>> {
    let stdout = std::io::stdout().into_raw_mode().unwrap();
    let stdout = stdout.into_alternate_screen().unwrap();
    let backend = TermionBackend::new(stdout);
    let mut term = Terminal::new(backend).unwrap();
    term.clear().unwrap();
    term.draw(|f| draw(f, data)).unwrap();
    Some(term)
}

pub async fn run(aconfig: Arc<RwLock<Config>>, mut rx: sync::mpsc::Receiver<Control>, ctrltx: sync::mpsc::Sender<Control>, udptx: sync::mpsc::Sender<Control>) {
    let mut peers = HashMap::new();
    let mynode = graph::NodeIndex::new(0);
    let (myname, results, debug, http, https, letsencrypt) = {
        let config = aconfig.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        (config.name.clone(), runtime.results, runtime.debug, runtime.http.clone(), runtime.https.clone(), config.letsencrypt.clone())
    };
    let mut nodeidx = usize::MAX-1;
    let mut relaymsgs: Vec<(String, Protocol, bool)> = vec![];
    let mut directmsgs: Vec<(String, Protocol)> = vec![];
    let mut udpmsgs: Vec<Control> = vec![];
    let mut logmsgs: Vec<(LogLevel, String)> = vec![];
    let data: Arc<Data> = Arc::new(Default::default());

    if let Some(arg) = http {
        let config = aconfig.clone();
        let data = data.clone();
        let ctrltx = ctrltx.clone();
        tokio::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            let service = service_fn(move |req| {
                // if debug { println!("{} Received HTTP request {} {}", timestamp(), req.method(), req.uri()); }
                handle_http(req, config.clone(), data.clone())
            });
            let tcp_listener = match TcpListener::bind(&arg).await {
                Ok(x) => x,
                Err(e) => {
                    ctrltx.send(Control::Log(LogLevel::Error, format!("Failed to start http server on {arg}: {e}"))).await.unwrap();
                    return;
                }
            };
            ctrltx.send(Control::Log(LogLevel::Info, format!("Started HTTP server on {}", arg))).await.unwrap();
            while let Ok((stream, addr)) = tcp_listener.accept().await {
                if debug { ctrltx.send(Control::Log(LogLevel::Debug, format!("Incoming HTTP connection from {}", addr))).await.unwrap(); }
                let conn = http.serve_connection(TokioIo::new(stream), service.clone()).with_upgrades();
                if let Err(e) = tokio::spawn(async move { conn.await }).await {
                    ctrltx.send(Control::Log(LogLevel::Error, format!("Error: {e}"))).await.unwrap();
                }
            }
        });
    }
    if let Some(arg) = https {
        let config = aconfig.clone();
        let data = data.clone();
        let ctrltx = ctrltx.clone();
        tokio::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            let aconfig = config.clone();
            let service = service_fn(move |req| {
                // if debug { println!("{} Received HTTPS request {} {}", timestamp(), req.method(), req.uri()); }
                handle_http(req, aconfig.clone(), data.clone())
            });
            let tcp_listener = match TcpListener::bind(&arg).await {
                Ok(x) => x,
                Err(e) => {
                    ctrltx.send(Control::Log(LogLevel::Error, format!("Failed to start https server on {arg}: {e}"))).await.unwrap();
                    return;
                }
            };
            let domain = arg.rsplit_once(':').expect("No colon found in --https argument").0;
            if domain.contains(':') || domain.find(char::is_alphabetic).is_none() {
                ctrltx.send(Control::Log(LogLevel::Error, format!("Cannot use bare IP address with --https; use a fully qualified domain name"))).await.unwrap();
                return;
            }
            let tcp_incoming = TcpListenerStream::new(tcp_listener);
            let mut tls_incoming = AcmeConfig::new([ &domain ])
                .contact_push(format!("mailto:{}", letsencrypt.unwrap()))
                .cache(ConfigCache::new(&config))
                .directory_lets_encrypt(true)
                .tokio_incoming(tcp_incoming, Vec::new());
            ctrltx.send(Control::Log(LogLevel::Info, format!("Started HTTPS server on {}", arg))).await.unwrap();
            while let Some(tls) = tls_incoming.next().await {
                let stream = tls.unwrap();
                if debug { ctrltx.send(Control::Log(LogLevel::Debug, format!("Incoming HTTPS connection from {}", stream.get_ref().get_ref().0.get_ref().peer_addr().unwrap_or("0.0.0.0:0".parse().unwrap())))).await.unwrap(); }
                let conn = http.serve_connection(TokioIo::new(stream), service.clone()).with_upgrades();
                if let Err(e) = tokio::spawn(async move { conn.await }).await {
                    ctrltx.send(Control::Log(LogLevel::Error, format!("Error: {e}"))).await.unwrap();
                }
            }
        });
    }

    let mut term = match aconfig.read().unwrap().runtime.read().unwrap().tui {
        false => None,
        true => start_tui(data.clone())
    };
    let stdintx = ctrltx.clone();
    tokio::task::spawn_blocking(move || { // Thread to wait for input events
        let stdin = std::io::stdin();
        let mut keys = stdin.keys();
        while let Some(event) = keys.next() {
            match event {
                Ok(key) => match tokio::runtime::Runtime::new().unwrap().block_on(stdintx.send(Control::InputKey(key))) {
                    Ok(_) => (),
                    Err(_) => break
                },
                Err(e) => eprintln!("Error: {}", e)
            }
        }
    });

    let mut lastsymbol = 64;
    let mut redraw;
    let mut ticks: u32 = 0;
    loop {
        redraw = false;
        match rx.recv().await.unwrap() {
            Control::Tick => {
                ticks += 1;
                let mut ports: Vec<String> = vec![];
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
                        let text = format!("Number of peers ({}) is below target number ({}), but I have no more available nodes", count, config.targetpeers);
                        logmsgs.push((LogLevel::Info, text));
                    }
                    else if debug {
                        let text = format!("Selected node {} for uplink connection", config.nodes.get(nodeidx).unwrap().name);
                        logmsgs.push((LogLevel::Debug, text));
                    }
                }
                else {
                    nodeidx = usize::MAX-1; // Reset node index for regular connections
                    if ticks%60 == 0 { // Only check for weak connections once every hour
                        let runtime = config.runtime.read().unwrap();
                        if runtime.graph.node_count() > 4 {
                            let nodes = runtime.graph.find_weakly_connected_nodes();
                            if !nodes.is_empty() {
                                if debug { logmsgs.push((LogLevel::Debug, format!("Weakly connected to {}", nodes.join(",")))); }
                                let name = nodes.choose(&mut rand::thread_rng()).unwrap();
                                if let Some(node) = config.nodes.iter().find(|i| i.name == *name) {
                                    logmsgs.push((LogLevel::Info, format!("Connecting to node {} to fix weak connection in network", name)));
                                    for addr in &node.listen {
                                        ports.push(addr.clone());
                                    }
                                }
                            }
                        }
                    }
                }

                if !ports.is_empty() {
                    let config = aconfig.clone();
                    let ctrltx = ctrltx.clone();
                    tokio::spawn(async move {
                        crate::tcp::connect_node(config, ctrltx, ports, false).await;
                    });
                }

                let cutoff = unixtime()-MAX_LINGER; // Remove results down for longer than MAX_LINGER
                data.results.write().unwrap().retain(|res| { // TODO: replace with drain_filter() once stabilized
                    if res.losspct < 99.9 || res.statesince > cutoff { return true; }
                    logmsgs.push((LogLevel::Info, format!("Stopped reporting on {} {} via {} after being down for {}", res.node, res.port, res.intf, duration_from(unixtime()-res.statesince))));
                    false
                });
                data.pathcache.write().unwrap().retain(|p| p.since > cutoff);

                if config.modified.load(Ordering::Relaxed) {
                    if debug { logmsgs.push((LogLevel::Debug, "Saving configuration file".to_owned())); }
                    let data = toml::to_string_pretty(&*config).unwrap();
                    tokio::spawn(async move {
                        fs::write("config.toml", data).await
                    });
                    config.modified.store(false, Ordering::Relaxed);
                }

                if ticks%60 == 10 { // Check for changes in local interfaces after 10 mins and every hour thereafter
                    let refresh = get_local_interfaces(&config.listen);
                    let mut runtime = config.runtime.write().unwrap();
                    let mut found = false;
                    for intf in &refresh {
                        if !runtime.listen.contains(intf) {
                            logmsgs.push((LogLevel::Info, format!("Detected new local interface {}", intf)));
                            udpmsgs.push(Control::NewIntf(intf.clone()));
                            found = true;
                        }
                    }
                    for intf in &runtime.listen {
                        if !refresh.contains(intf) {
                            logmsgs.push((LogLevel::Info, format!("Detected removed local interface {}", intf)));
                            udpmsgs.push(Control::DropIntf(intf.clone()));
                            found = true;
                       }
                    }
                    if found {
                        runtime.listen = refresh;
                        // TODO: push this update to other nodes
                    }
                }
            },
            Control::Round(_round) => {
                // Update interface stats
                for i in data.intf.write().unwrap().values_mut() { i.lag = u16::MAX; }
                for result in data.results.read().unwrap().iter() {
                    if result.last.is_none() { continue; }
                    let last = result.last.unwrap();
                    if last != 0 { // 0 result means a timeout, don't use it for stats
                        data.intf.write().unwrap().entry(result.intf.clone())
                            .and_modify(|e| {
                                if e.min > last { e.min = last; }
                                if e.lag > last-result.min { e.lag = last-result.min; }
                            })
                            .or_insert_with(|| IntfStats { symbol: char::from_u32({ lastsymbol += 1; lastsymbol }).unwrap_or('?'), min: last, lag: last-result.min });
                    }
                }
                redraw = true;

                // Update port history
                for result in data.results.write().unwrap().iter_mut() {
                    if let Some(last) = result.last {
                        let mut report = false;
                        result.push_hist(last);
                        result.last = None;
                        if last == 0 && result.losspct < 99.9 { // Immediately update for losses unless port was already down
                            if result.losspct == 0.0 { // Immediately log a new loss result; updates will be sent from the periodic check_loss() runs
                                logmsgs.push((LogLevel::Debug, format!("{} {} is suffering 1% packet loss", &result.node, &result.port)));
                            }
                            check_loss_port(result);
                            if result.losspct > 99.9 { // Port is now marked down
                                logmsgs.push((LogLevel::Status, format!("{} {} is down", &result.node, &result.port)));
                                result.statesince = unixtime();
                            }
                            report = true;
                        }
                        else if result.hist.len() == 1 { report = true; }
                        if report {
                            let config = aconfig.read().unwrap();
                            let mut runtime = config.runtime.write().unwrap();
                            if !runtime.wsclients.is_empty() {
                                let json = format!("{{ \"msg\": \"pathstate\", \"fromname\": \"{}\", \"fromintf\": \"{}\",
                                    \"toname\": \"{}\", \"tointf\": \"{}\", \"losspct\": {} }}",
                                    &myname, &result.intf, &result.node, &result.port, result.losspct.round()
                                );
                                runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                            }
                            let path = Protocol::Path { from: myname.clone(), to: result.node.clone(), fromintf: result.intf.clone(), tointf: result.port.clone(), losspct: result.losspct.round() as u8 };
                            relaymsgs.push((myname.clone(), path, false));
                        }
                    }
                    else { result.push_hist(u16::MAX); }
                }

                for path in check_loss(&aconfig, &data.results) {
                    relaymsgs.push((myname.clone(), path, false));
                }
            },
            Control::NewLink(sender, from, to, seq) => {
                let mut config = aconfig.write().unwrap();
                if let Some(node) = config.nodes.iter_mut().find(|node| node.name == from) {
                    if node.lastconnseq == seq { continue; }
                    node.lastconnseq = seq;
                }
                drop(config);
                let config = aconfig.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                let fromidx = match runtime.graph.find_node(&from) {
                    Some(idx) => idx,
                    None => {
                        if config.nodes.iter().any(|node| node.name == from) {
                            udpmsgs.push(Control::ScanNode(from.clone(), false));
                        }
                        if !peers.is_empty() {
                            let text = format!("Node {} joined the network", from);
                            logmsgs.push((LogLevel::Status, text));
                        }
                        runtime.graph.add_node(from.clone())
                    }
                };
                let toidx = match runtime.graph.find_node(&to) {
                    Some(idx) => idx,
                    None => {
                        if config.nodes.iter().any(|node| node.name == to) {
                            udpmsgs.push(Control::ScanNode(to.clone(), false));
                        }
                        if !peers.is_empty() {
                            let text = format!("Node {} joined the network", to);
                            logmsgs.push((LogLevel::Status, text));
                        }
                        runtime.graph.add_node(to.clone())
                    }
                };
                let changes = match runtime.graph.find_edge(fromidx, toidx) {
                    Some(idx) => {
                        match runtime.graph[idx] {
                            val if val == seq => false,
                            _ => {
                                runtime.graph[idx] = seq;
                                true
                            }
                        }
                    },
                    None => {
                        runtime.graph.add_edge(fromidx, toidx, seq);
                        true
                    }
                };
                if changes {
                    relaymsgs.push((sender, Protocol::Link { from: from.clone(), to: to.clone(), seq }, true));
                    runtime.msp = calculate_msp(&runtime.graph);
                    if !runtime.wsclients.is_empty() {
                        let mode = match runtime.msp.contains_edge(fromidx, toidx) {
                            true => "active",
                            false => "standby"
                        };
                        let json = format!("{{ \"msg\": \"newlink\", \"from\": \"{from}\", \"to\": \"{to}\", \"mode\": \"{mode}\" }}");
                        runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                    }
                };
            },
            Control::DropLink(sender, from, to) => {
                let config = aconfig.write().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                let fres = runtime.graph.find_node(&from);
                let tres = runtime.graph.find_node(&to);
                if let (Some(fnode), Some(tnode)) = (fres, tres) {
                    let dropped;
                    if let Some(edge) = runtime.graph.find_edge(fnode, tnode) {
                        runtime.graph.remove_edge(edge);
                        dropped = runtime.graph.drop_detached_nodes();
                        if !dropped.is_empty() {
                            let mut pathcache = data.pathcache.write().unwrap();
                            pathcache.retain(|p| !dropped.contains(&p.from));
                            let text = match dropped.len() {
                                1 => format!("Node {} left the network", dropped[0]),
                                n => format!("Netsplit: lost connection to {} nodes ({})", n, dropped.join(", "))
                            };
                            logmsgs.push((LogLevel::Status, text));
                        }
                        runtime.msp = calculate_msp(&runtime.graph);
                        relaymsgs.push((sender, Protocol::Drop { from: from.clone(), to: to.clone() }, true));
                    }
                    if !runtime.wsclients.is_empty() {
                        let json = format!("{{ \"msg\": \"droplink\", \"from\": \"{from}\", \"to\": \"{to}\" }}");
                        runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                    }
                    drop(runtime);
                    // config.nodes.iter_mut().for_each(|node| { if dropped.contains(&node.name) { node.lastconnseq = 0; } });
                }
            },
            Control::NewPeer(name, tx, report) => {
                if peers.is_empty() {
                    let config = aconfig.read().unwrap();
                    let runtime = config.runtime.read().unwrap();
                    let text = format!("Joined the network with {} other nodes", runtime.graph.node_count()-1);
                    logmsgs.push((LogLevel::Status, text));
                }
                peers.insert(name.clone(), tx);

                if report {
                    let results = data.results.read().unwrap();
                    for result in results.iter() {
                        directmsgs.push((name.clone(), Protocol::Path { from: myname.clone(), to: result.node.clone(), fromintf: result.intf.clone(), tointf: result.port.clone(), losspct: result.losspct.round() as u8 }));
                    }
                    let pathcache = data.pathcache.read().unwrap();
                    for path in pathcache.iter() {
                        directmsgs.push((name.clone(), Protocol::Path { from: path.from.clone(), to: path.to.clone(), fromintf: path.fromintf.clone(), tointf: path.tointf.clone(), losspct: path.losspct }));
                    }
                }
                let config = aconfig.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                if !runtime.wsclients.is_empty() {
                    let json = format!("{{ \"msg\": \"newlink\", \"from\": \"{}\", \"to\": \"{name}\", \"mode\": \"unknown\" }}", myname.clone());
                    runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                }
            },
            Control::DropPeer(name) => {
                peers.remove(&name);
                let mut config = aconfig.write().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                let mut dropped = vec![];
                if let Some(nodeidx) = runtime.graph.find_node(&name) {
                    if let Some(edge) = runtime.graph.find_edge(mynode, nodeidx) {
                        relaymsgs.push((name.clone(), Protocol::Drop { from: myname.clone(), to: name.clone() }, true));
                        runtime.graph.remove_edge(edge);
                    }
                    dropped = runtime.graph.drop_detached_nodes();
                    if peers.is_empty() {
                        let text = format!("Disconnected from the network; lost {} node{}", dropped.len(), match dropped.len() { 1 => "", _ => "s" });
                        logmsgs.push((LogLevel::Status, text));
                    }
                    else {
                        let mut pathcache = data.pathcache.write().unwrap();
                        pathcache.retain(|p| !dropped.contains(&p.from));
                        for node in &dropped {
                            let text = format!("Node {} left the network", node);
                            logmsgs.push((LogLevel::Status, text));
                        }
                    }
                    redraw = true;
                }
                if !runtime.wsclients.is_empty() {
                    let json = format!("{{ \"msg\": \"droplink\", \"from\": \"{}\", \"to\": \"{name}\" }}", myname.clone());
                    runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                }
                runtime.msp = calculate_msp(&runtime.graph);
                drop(runtime);
                config.nodes.iter_mut().for_each(|node| { if dropped.contains(&node.name) { node.lastconnseq = 0; } });
            },
            Control::Ports(from, node, ports) => {
                let mut config = aconfig.write().unwrap();
                if let Some(entry) = config.nodes.iter_mut().find(|i| i.name == node) {
                    if ports != entry.listen {
                        entry.listen = ports.clone();
                        config.modified.store(true, Ordering::Relaxed);
                        relaymsgs.push((from, Protocol::Ports { node, ports }, false));
                    }
                }
            },
            Control::Relay(from, proto) => {
                relaymsgs.push((from, proto, false));
            },
            Control::Scan(from, to) => {
                if to == myname {
                    udpmsgs.push(Control::ScanNode(from, true));
                }
                else {
                    directmsgs.push((to.clone(), Protocol::Scan { from, to }));
                }
            },
            Control::Result(node, intf, port, rtt) => {
                let mut sort = false;
                let min = {
                    let mut results = data.results.write().unwrap();
                    let result = match results.iter_mut().find(|i| i.node == node && i.intf == intf && i.port == port) {
                        Some(result) => result,
                        None => {
                            if rtt == 0 { continue; } // Don't create new PingResult for a loss Result
                            sort = true;
                            results.push(PingResult::new(node.clone(), intf.clone(), port.clone()));
                            results.last_mut().unwrap()
                        }
                    };
                    if result.last.is_none() || rtt > 0 { result.last = Some(rtt); } // Don't overwrite a succesful ping result with a loss
                    if rtt > 0 {
                        if rtt < result.min { result.min = rtt; }
                        if result.losspct > 99.9 {
                            logmsgs.push((LogLevel::Status, format!("{} {} is up after {}", &node, &port, duration_from(unixtime()-result.statesince))));
                            check_loss_port(result);
                            result.statesince = unixtime();
                        }
                    }
                    result.min
                };
                if sort { data.results.write().unwrap().sort(); }
                if rtt == 0 {
                    data.push_ping(format!("Node {:10} {:26} -> {:26} lost", node, shorten_ipv6(intf), shorten_ipv6(port)));
                }
                else {
                    data.push_ping(match rtt-min {
                      n if n > THRESHOLD => format!("Node {:10} {:26} -> {:26} {:>4}ms (min {}/dif {}/cat {})", node, shorten_ipv6(intf), shorten_ipv6(port), rtt, min, rtt-min, ((n-THRESHOLD) as f32).sqrt() as u16),
                      _ => format!("Node {:10} {:26} -> {:26} {:>4}ms", node, shorten_ipv6(intf), shorten_ipv6(port), rtt)
                    });
                }
                if results { println!("{}", data.ping.read().unwrap().front().unwrap()); }
                redraw = true;
            },
            Control::Log(level, text) => {
                logmsgs.push((level, text));
            },
            Control::Path(peer, from, to, fromintf, tointf, losspct) => {
                if peer == myname { continue; } // Don't process relayed messages from ourselves
                let mut relay = true;
                let path = Path::new(from.clone(), to.clone(), fromintf.clone(), tointf.clone(), losspct);

                let mut pathcache = data.pathcache.write().unwrap();
                match pathcache.iter_mut().find(|e| **e == path) { // Comparison ignores losspct field
                    Some(found) => {
                        if found.losspct == path.losspct { relay = false; }
                        else { found.losspct = path.losspct; }
                        found.since = unixtime();
                    },
                    None => {
                        pathcache.push(path);
                    }
                }

                if relay {
                    let config = aconfig.read().unwrap();
                    let mut runtime = config.runtime.write().unwrap();
                    if !runtime.wsclients.is_empty() {
                        let json = format!("{{ \"msg\": \"pathstate\", \"fromname\": \"{}\", \"fromintf\": \"{}\",
                            \"toname\": \"{}\", \"tointf\": \"{}\", \"losspct\": {} }}",
                            &from, &fromintf, &to, &tointf, losspct
                        );
                        runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                    }
    
                    let protocol = Protocol::Path { from, to, fromintf, tointf, losspct };
                    relaymsgs.push((peer, protocol, false));
                }
            },
            Control::InputKey(key) => {
                match key {
                    Key::Char('t') => {
                        if let Some(mut terminal) = term {
                            terminal.clear().unwrap();
                            terminal.flush().unwrap();
                            drop(terminal);
                            term = None;
                            let log = data.log.read().unwrap();
                            for (ts, msg) in log.iter().rev() {
                                println!("{} {}", timestamp_from(*ts), msg);
                            }
                        }
                        else { term = start_tui(data.clone()); }
                    },
                    Key::Char('q') => return,
                    Key::Char('\n') => continue,
                    _ => { logmsgs.push((LogLevel::Info, format!("Received key: {:?}", key))); }
                }
            },
            _ => {
                panic!("Received unexpected Control message on control task");
            }
        }

        let mut targets: Vec<(sync::mpsc::Sender<Control>, Control)> = vec![];
        if !relaymsgs.is_empty() {
            let config = aconfig.read().unwrap();
            let runtime = config.runtime.read().unwrap();
            for (from, proto, broadcast) in relaymsgs.drain(..) {
                if broadcast {
                    for (name, tx) in &peers {
                        if *name == from { continue; }
                        targets.push((tx.clone(), Control::Send(proto.clone())));
                    }
                }
                else {
                    for peer in runtime.msp.neighbors(mynode) {
                        if runtime.msp[peer] == from { continue; }
                        match peers.get(&runtime.msp[peer]) {
                            Some(tx) => {
                                targets.push((tx.clone(), Control::Send(proto.clone())));
                            },
                            None => {
                                logmsgs.push((LogLevel::Error, format!("Peer {} not found", runtime.msp[peer])));
                            }
                        }
                    }
                }
            }
        }
        if !directmsgs.is_empty() {
            let config = aconfig.read().unwrap();
            let runtime = config.runtime.read().unwrap();
            for (to, proto) in directmsgs.drain(..) {
                let tonode = match runtime.graph.find_node(&to) {
                    Some(idx) => idx,
                    None => {
                        logmsgs.push((LogLevel::Error, format!("Node {} not found in graph", to)));
                        continue;
                    }
                };
                let res = algo::astar(&runtime.graph, mynode, |node| node == tonode, |e| *e.weight(), |_| 0);
                if let Some((_, path)) = res {
                    let name = &runtime.graph[*path.get(1).unwrap()];
                    match peers.get(name) {
                        Some(tx) => {
                            targets.push((tx.clone(), Control::Send(proto)));
                        },
                        None => {
                            logmsgs.push((LogLevel::Error, format!("Peer {} not found for directmessage", name)));
                        }
                    }
                }
            }
        }
        if !udpmsgs.is_empty() {
            for msg in udpmsgs.drain(..) {
                targets.push((udptx.clone(), msg));
            }
        }
        if !logmsgs.is_empty() {
            for (level, text) in logmsgs.drain(..) {
                if level == LogLevel::Debug && !debug { continue; }
                if level != LogLevel::Debug {
                    data.push_log(unixtime(), text.clone());
                    let config = aconfig.read().unwrap();
                    let mut runtime = config.runtime.write().unwrap();
                    if !runtime.wsclients.is_empty() {
                        let json = serde_json::json!({
                            "msg": "log",
                            "ts": unixtime(),
                            "text": text
                        }).to_string();
                        runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                    }
                }
                if term.is_none() { println!("{} {}", timestamp(), text); }
                else { redraw = true; }
            }
        }

        if !targets.is_empty() {
            tokio::spawn(async move {
                for (tx, proto) in targets {
                    let _ = tx.send(proto).await; // Can fail if the connection was dropped
                }
            });
        }

        if redraw {
            if let Some(ref mut term) = term {
                term.draw(|f| draw(f, data.clone())).unwrap();
            }
        }
    }
}

fn find_next_node(nodes: &[Node], start: usize) -> Option<usize> {
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
fn calculate_msp(graph: &UnGraph<String, u32>) -> UnGraph<String, u32> {
    // The resulting graph will have all nodes of the input graph with identical indices
    graph::Graph::from_elements(algo::min_spanning_tree(&graph))
}

fn check_loss(config: &Arc<RwLock<Config>>, results: &RwLock<Vec<PingResult>>) -> Vec<Protocol> {
    let mut ret = Vec::new();
    for result in results.write().unwrap().iter_mut() {
        if result.losspct != 0.0 {
            let prev = result.losspct.round();
            check_loss_port(result);
            if result.losspct.round() != prev {
                let config = config.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                if !runtime.wsclients.is_empty() {
                    let json = format!("{{ \"msg\": \"pathstate\", \"fromname\": \"{}\", \"fromintf\": \"{}\",
                        \"toname\": \"{}\", \"tointf\": \"{}\", \"losspct\": {} }}",
                        &config.name, &result.intf, &result.node, &result.port, result.losspct.round()
                    );
                    runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                }
                let path = Protocol::Path { from: config.name.clone(), to: result.node.clone(), fromintf: result.intf.clone(), tointf: result.port.clone(), losspct: result.losspct.round() as u8 };
                ret.push(path);
            }
        }
    }
    ret
}
fn check_loss_port(result: &mut PingResult) {
    let mut count = 0;
    let mut losses = 0;
    let mut conseq = 0; // Consecutive losses
    for x in &result.hist { // Hist starts with most recent results
        count += 1;
        if *x == 0 || *x == u16::MAX { // Loss result
            losses += 1;
            conseq += 1;
        }
        else {
            if conseq > 2 { losses -= conseq; } // Don't include downtime (3+ conseq losses) in loss percentage
            conseq = 0;
        }
        if count == 3 && conseq == 3 { // Last 3 results are losses; report downtime
            result.losspct = 100.0;
            return;
        }
        if count >= 100 { break; }
    }
    if conseq > 2 { losses -= conseq; }
    if losses > 0 {
        result.losspct = (losses as f32/count as f32)*100.0;
    }
    else {
        result.losspct = 0.0;
    }
}

fn draw<B: Backend>(f: &mut Frame<B>, data: Arc<Data>) {
    let resultssize = match data.results.read().unwrap().len() { 0 => 3, n => n+2 } as u16;
    let vert1 = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(12), Constraint::Length(resultssize) ].as_ref())
        .split(f.size());
    let hori = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Max(105), Constraint::Percentage(50)].as_ref())
        .split(vert1[0]);
    let vert2 = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length((data.intf.read().unwrap().len()+3) as u16)].as_ref())
        .split(hori[1]);

    let block = Block::default()
            .title(" Ping results ")
            .borders(Borders::ALL);
    let mut content: Vec<ListItem> = vec![];
    for line in data.ping.read().unwrap().iter().take(hori[0].height.into()) {
        content.push(ListItem::new(Span::from(line.clone())));
    }
    let list = List::new(content).block(block).start_corner(Corner::BottomLeft);
    f.render_widget(list, hori[0]);

    let block = Block::default()
            .title(" Network log ")
            .borders(Borders::ALL);
    let mut content: Vec<ListItem> = vec![];
    for (ts, line) in data.log.read().unwrap().iter().take(vert2[0].height.into()) {
        content.push(ListItem::new(Span::from(format!("{} {}", timestamp_from(*ts), line))));
    }
    let list = List::new(content).block(block).start_corner(Corner::BottomLeft);
    f.render_widget(list, vert2[0]);

    let block = Block::default()
            .title(" Local interface stats ")
            .borders(Borders::ALL);
    let mut content: Vec<Row> = vec![];
    {
        let intf = data.intf.read().unwrap();
        let mut rows: Vec<_> = intf.iter().collect();
        rows.sort_by(|a, b| a.1.symbol.cmp(&b.1.symbol));
        for (intf, stats) in rows {
            content.push(Row::new(vec![ format!(" {} ", stats.symbol), shorten_ipv6(intf.clone()), format!("{:^5}", stats.min), format!("{:^5}", stats.lag) ]));
        }
    }
    let table = Table::new(content)
        .block(block)
        .column_spacing(1)
        .header(Row::new(vec![ "Sym", "Interface", "Best", "Lag" ]))
        .widths(&[Constraint::Length(3), Constraint::Length(26), Constraint::Length(5), Constraint::Length(5)]);
    f.render_widget(table, vert2[1]);

    let block = Block::default()
        .title(" Results grid ")
        .borders(Borders::ALL);
    let mut content: Vec<ListItem> = vec![];
    let mut prev = String::new();
    let mut mark;
    for result in data.results.read().unwrap().iter() {
        if prev != result.node {
            prev = result.node.clone();
            mark = "▔";
        }
        else { mark = " "; }
        let symbol = match data.intf.read().unwrap().get(&result.intf) {
            Some(i) => i.symbol,
            None => ' '
        };
        let header = format!("{:10} {:26} {} ", result.node, shorten_ipv6(result.port.to_string()), symbol);
        let mut line = Vec::with_capacity((vert1[1].width).into());
        line.push(Span::from(header));
        if let Some(rtt) = result.last {
            line.push(draw_mark(rtt, result.min, mark));
        }
        else { line.push(Span::raw(" ")); }
        for rtt in result.hist.iter().take((vert1[1].width-43).into()) {
            line.push(draw_mark(*rtt, result.min, mark));
        }
        content.push(ListItem::new(Spans::from(line)));
    }
    if content.is_empty() { content.push(ListItem::new("No results yet")); }
    let list = List::new(content).block(block).start_corner(Corner::TopLeft);
    f.render_widget(list, vert1[1]);
}

fn draw_mark(rtt: u16, min: u16, mark: &'static str) -> Span<'static> {
    lazy_static!{
        static ref STYLES: Vec<Style> = vec![
            // Indexed colors overview: https://jonasjacek.github.io/colors/
            Style::default().fg(Color::Black).bg(Color::Indexed(46)),
            Style::default().fg(Color::Black).bg(Color::Indexed(82)),
            Style::default().fg(Color::Black).bg(Color::Indexed(118)),
            Style::default().fg(Color::Black).bg(Color::Indexed(154)),
            Style::default().fg(Color::Black).bg(Color::Indexed(190)),
            Style::default().fg(Color::Black).bg(Color::Indexed(226)),
            Style::default().fg(Color::Black).bg(Color::Indexed(220)),
            Style::default().fg(Color::Black).bg(Color::Indexed(214)),
            Style::default().fg(Color::Black).bg(Color::Indexed(208)),
            Style::default().fg(Color::Black).bg(Color::Indexed(202)),
            Style::default().fg(Color::Black).bg(Color::Indexed(196))
        ];
    }
    if rtt == 0 { return Span::styled("•", Style::default().fg(Color::Black).bg(Color::Indexed(196))); }
    if rtt == u16::MAX { return Span::raw(" "); }
    let delaycat = match rtt-min {
      n if n > THRESHOLD => ((n-THRESHOLD) as f32).sqrt() as usize,
      _ => 0
    };
    if delaycat < STYLES.len() { return Span::styled(mark, STYLES[delaycat]); }
    return Span::styled("^", (*STYLES.last().unwrap()).fg(Color::Black));
}

// async fn upgrade_websocket(ws: warp::ws::Ws, addr: Option<SocketAddr>, config: Arc<RwLock<Config>>, data: Arc<Data>) -> Result<impl warp::Reply, warp::Rejection> {
//     if addr.is_none() { return Err(warp::reject::reject()); }
//     Ok(ws.on_upgrade(move |socket| handle_websocket(socket, config, data)))
// }

async fn handle_http(mut request: Request<Incoming>, config: Arc<RwLock<Config>>, data: Arc<Data>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    if hyper_tungstenite::is_upgrade_request(&request) {
        let (response, websocket) = hyper_tungstenite::upgrade(&mut request, None)?;
        tokio::spawn(async move {
            let _ = handle_websocket(websocket, config, data).await;
        });
        Ok(response)
    } else {
        match request.uri().path() {
            "/" => Ok(Response::new(Full::<Bytes>::from(INDEX_FILE))),
            "/favicon.ico" => Ok(Response::new(Full::<Bytes>::from(ICON_FILE))),
            _ => Ok(Response::builder().status(hyper::StatusCode::NOT_FOUND).body(Full::<Bytes>::from("")).unwrap())
        }
    }

}

async fn handle_websocket(ws: HyperWebsocket, config: Arc<RwLock<Config>>, data: Arc<Data>) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    #[derive(Default, Serialize)]
    struct JsonGraph {
        msg: &'static str,
        nodes: Vec<JsonNode>,
        edges: Vec<JsonEdge>,
        paths: Vec<JsonPath>,
        log: Vec<JsonLog>
    }
    #[derive(Serialize)]
    struct JsonNode {
        name: String
    }
    #[derive(Serialize)]
    struct JsonEdge {
        from: String,
        to: String,
        mode: &'static str
    }
    #[derive(Serialize)]
    struct JsonPath {
        fromname: String,
        fromintf: String,
        toname: String,
        tointf: String,
        losspct: u8
    }
    #[derive(Serialize)]
    struct JsonLog {
        ts: u64,
        text: String
    }

    let (ws_tx, mut ws_rx) = ws.await?.split();
    let (tx, rx) = sync::mpsc::unbounded_channel();
    let rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
    tokio::spawn(rx.forward(ws_tx));

    let mut res = JsonGraph { msg: "init", ..Default::default() };
    {
        let config = config.read().unwrap();
        let mut runtime = config.runtime.write().unwrap();
        runtime.wsclients.push(tx.clone());

        let nodes = runtime.graph.raw_nodes();
        for node in nodes.iter() {
            res.nodes.push(JsonNode { name: node.weight.clone() });
        }
        for edge in runtime.graph.raw_edges() {
            let mode = match runtime.msp.contains_edge(edge.source(), edge.target()) {
                true => "active",
                false => "standby"
            };
            res.edges.push(JsonEdge { from: runtime.graph[edge.source()].clone(), to: runtime.graph[edge.target()].clone(), mode });
        }
        drop(runtime);
        let log = data.log.read().unwrap();
        for (ts, msg) in log.iter().rev() {
            res.log.push(JsonLog { ts: *ts, text: msg.clone() });
        }
        let results = data.results.read().unwrap();
        for result in results.iter() {
            res.paths.push(JsonPath { fromname: config.name.clone(), fromintf: result.intf.clone(), toname: result.node.clone(), tointf: result.port.clone(), losspct: result.losspct.round() as u8 });
        }
        let pathcache = data.pathcache.read().unwrap();
        for path in pathcache.iter() {
            res.paths.push(JsonPath { fromname: path.from.clone(), fromintf: path.fromintf.clone(), toname: path.to.clone(), tointf: path.tointf.clone(), losspct: path.losspct });
        }
    }
    tx.send(Ok(Message::text(serde_json::to_string(&res).unwrap())))?;

    while let Some(message) = ws_rx.next().await {
        match message? {
            Message::Text(msg) => {
                println!("Received text message: {}", msg);
            },
            Message::Binary(msg) => {
                println!("Received binary message: {:02X?}", msg);
            },
            Message::Ping(msg) => {
                println!("Received websocket ping message: {:02X?}", msg);
            },
            Message::Pong(msg) => {
                println!("Received websocket pong message: {:02X?}", msg);
            }
            Message::Close(_) => {},
            Message::Frame(_) => {}
        }
    }

    Ok(())
}

fn shorten_ipv6(ip: String) -> String {
    lazy_static!{
        static ref LONGIPV6: Regex = Regex::new(r"(?i)^([0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:)[0-9a-f]+:[0-9a-f]+:[0-9a-f]+(:[0-9a-f]+)$").unwrap();
    }
    if let Some(caps) = LONGIPV6.captures(&ip) { format!("{}*{}", &caps[1], &caps[2]) }
    else { ip }
}

// async fn handle_websocket(ws: warp::ws::WebSocket, config: Arc<RwLock<Config>>, data: Arc<Data>) {
//     let (ws_tx, mut ws_rx) = ws.split();
//     let (tx, rx) = sync::mpsc::unbounded_channel();
//     let rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
//     tokio::spawn(rx.forward(ws_tx));

//     tokio::task::spawn(async move {
//         while let Some(result) = ws_rx.next().await {
//             let msg = match result {
//                 Ok(msg) => msg,
//                 Err(_) => break
//             };
//             if msg.is_close() { break; }
//             println!("Received websocket message: {:?}", msg);
//         }
//     });
// }
