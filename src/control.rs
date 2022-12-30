use std::{ sync::RwLock, sync::Arc, mem::drop, collections::{ HashMap, VecDeque }, cmp::Ordering, net::SocketAddr };
use tokio::{ fs, sync };
use futures_util::stream::StreamExt;
use petgraph::{ graph, graph::UnGraph, data::FromElements, algo };
use termion::{ raw::IntoRawMode, screen::IntoAlternateScreen, screen::AlternateScreen, raw::RawTerminal, input::TermRead, event::Key };
use tui::{ Terminal, Frame, backend::{ Backend, TermionBackend }, widgets::{ Block, Borders, List, ListItem, Table, Row }, layout::{ Layout, Constraint, Direction, Corner }, text::{ Span, Spans }, style::{ Style, Color } };
use lazy_static::lazy_static;
use rand::seq::SliceRandom;
use warp::{ Filter, ws::Message };
use serde::Serialize;
use crate::{ Config, Node, Control, Protocol, LogLevel, unixtime, timestamp, timestamp_from };

static HISTSIZE: usize = 1440;
static THRESHOLD: u16 = 4;
static INDEX_FILE: &str = include_str!("index.html");
static ICON_FILE: &[u8] = include_bytes!("../favicon.ico");

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
}
impl PingResult {
    fn new(node: String, intf: String, port: String) -> PingResult {
        PingResult { node, intf, port, min: u16::MAX, losspct: 0.0, last: None, hist: VecDeque::with_capacity(HISTSIZE) }
    }
    fn push_hist(&mut self, result: u16) {
        if self.hist.len() >= HISTSIZE { self.hist.pop_back().unwrap(); }
        self.hist.push_front(result);
    }
}
impl Ord for PingResult {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.node.cmp(&other.node) {
            Ordering::Equal => {
                match self.port.cmp(&other.port) { // TODO: better comparison for ip addresses
                    Ordering::Equal => self.intf.cmp(&other.intf),
                    ord => ord
                }
            },
            ord => ord
        }
    }
}
impl Eq for PingResult {}
impl PartialOrd for PingResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
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
    losspct: u8
}
impl Path {
    fn new(from: String, to: String, fromintf: String, tointf: String, losspct: u8) -> Path {
        Path { from, to, fromintf, tointf, losspct }
    }
}
impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.from == other.from && self.to == other.to && self.fromintf == other.fromintf && self.tointf == other.tointf
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

pub async fn run(aconfig: Arc<RwLock<Config>>, mut rx: sync::mpsc::Receiver<Control>, ctrltx: sync::mpsc::Sender<Control>, udptx: sync::mpsc::Sender<Control>, web: Option<std::net::SocketAddr>) {
    let mut peers = HashMap::new();
    let mynode = graph::NodeIndex::new(0);
    let (myname, results, debug) = {
        let config = aconfig.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        (config.name.clone(), runtime.results, runtime.debug)
    };
    let mut nodeidx = usize::MAX-1;
    let mut relaymsgs: Vec<(String, Protocol, bool)> = vec![];
    let mut directmsgs: Vec<(String, Protocol)> = vec![];
    let mut udpmsgs: Vec<Control> = vec![];
    let mut logmsgs: Vec<(LogLevel, String)> = vec![];
    let data: Arc<Data> = Arc::new(Default::default());

    if let Some(sa) = web {
        let config = aconfig.clone();
        let data = data.clone();
        tokio::spawn(async move {
            let index = warp::path::end().map(|| warp::reply::html(INDEX_FILE));
            let icon = warp::path("favicon.ico").map(|| ICON_FILE);
            let websocket = warp::path("ws")
                       .and(warp::ws())
                       .and(warp::addr::remote())
                       .and(warp::any().map(move || config.clone()))
                       .and(warp::any().map(move || data.clone()))
                       .and_then(upgrade_websocket)
                       .with(warp::cors().allow_any_origin());
            warp::serve(index.or(icon).or(websocket)).run(sa).await;
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

                if config.modified {
                    let data = toml::to_string_pretty(&*config).unwrap();
                    tokio::spawn(async move {
                        fs::write("config.toml", data).await
                    });
                    drop(config);
                    let mut config = aconfig.write().unwrap();
                    config.modified = false;
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
                            .and_modify(|mut e| {
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
                        if last == 0 && result.losspct == 0.0 {
                            check_loss_port(result);
                            logmsgs.push((LogLevel::Debug, format!("{} {} is suffering {}% packet loss", &result.node, &result.port, result.losspct)));
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
                if let Some(mut node) = config.nodes.iter_mut().find(|node| node.name == from) {
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
                let mut config = aconfig.write().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                let fres = runtime.graph.find_node(&from);
                let tres = runtime.graph.find_node(&to);
                if let (Some(fnode), Some(tnode)) = (fres, tres) {
                    let mut dropped = vec![];
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
                    config.nodes.iter_mut().for_each(|node| { if dropped.contains(&node.name) { node.lastconnseq = 0; } });
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
                // let config = aconfig.read().unwrap();
                // let mut runtime = config.runtime.write().unwrap();
                // if !runtime.wsclients.is_empty() {
                //     let json = format!("{{ \"msg\": \"newlink\", \"from\": \"{}\", \"to\": \"{name}\", \"mode\": \"unknown\" }}", myname.clone());
                //     runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                // }
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
                if let Some(mut entry) = config.nodes.iter_mut().find(|i| i.name == node) {
                    if ports != entry.listen {
                        entry.listen = ports.clone();
                        config.modified = true;
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
                            sort = true;
                            results.push(PingResult::new(node.clone(), intf.clone(), port.clone()));
                            results.last_mut().unwrap()
                        }
                    };
                    result.last = Some(rtt);
                    if rtt > 0 && rtt < result.min { result.min = rtt; }
                    result.min
                };
                if sort { data.results.write().unwrap().sort(); }
                if rtt == 0 {
                    data.push_ping(format!("Node {:10} {:39} -> {:39} lost", node, intf, port));
                }
                else {
                    data.push_ping(match rtt-min {
                      n if n > THRESHOLD => format!("Node {:10} {:39} -> {:39} {:>4}ms (min {}/dif {}/cat {})", node, intf, port, rtt, min, rtt-min, ((n-THRESHOLD) as f32).sqrt() as u16),
                      _ => format!("Node {:10} {:39} -> {:39} {:>4}ms", node, intf, port, rtt)
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
                            term = None;
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
    let mut conseq = 0;
    for x in &result.hist {
        count += 1;
        if *x == 0 || *x == u16::MAX {
            losses += 1;
            conseq += 1;
        }
        else {
            if conseq > 2 { losses -= conseq; }
            conseq = 0;
        }
        if count == 3 && conseq == 3 {
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
        .constraints([Constraint::Min(10), Constraint::Length(resultssize) ].as_ref())
        .split(f.size());
    let hori = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(vert1[0]);
    let vert2 = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
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
            content.push(Row::new(vec![ format!(" {} ", stats.symbol), (*intf).clone(), format!("{:^5}", stats.min), format!("{:^5}", stats.lag) ]));
        }
    }
    let table = Table::new(content)
        .block(block)
        .column_spacing(1)
        .header(Row::new(vec![ "Sym", "Interface", "Best", "Lag" ]))
        .widths(&[Constraint::Length(3), Constraint::Length(20), Constraint::Length(5), Constraint::Length(5)]);
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
        let header = format!("{:10} {:39} {} ", result.node, result.port, symbol);
        let mut line = Vec::with_capacity((vert1[1].width-50).into());
        line.push(Span::from(header));
        if let Some(rtt) = result.last {
            line.push(draw_mark(rtt, result.min, mark));
        }
        else { line.push(Span::raw(" ")); }
        for rtt in result.hist.iter().take((vert1[1].width-50).into()) {
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

async fn upgrade_websocket(ws: warp::ws::Ws, addr: Option<SocketAddr>, config: Arc<RwLock<Config>>, data: Arc<Data>) -> Result<impl warp::Reply, warp::Rejection> {
    if addr.is_none() { return Err(warp::reject::reject()); }
    Ok(ws.on_upgrade(move |socket| handle_websocket(socket, config, data)))
}

async fn handle_websocket(ws: warp::ws::WebSocket, config: Arc<RwLock<Config>>, data: Arc<Data>) {
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

    let (ws_tx, mut ws_rx) = ws.split();
    let (tx, rx) = sync::mpsc::unbounded_channel();
    let rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
    tokio::spawn(rx.forward(ws_tx));

    {
        let config = config.read().unwrap();
        let mut runtime = config.runtime.write().unwrap();
        runtime.wsclients.push(tx.clone());
        let mut res = JsonGraph { msg: "init", ..Default::default() };
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
        tx.send(Ok(Message::text(serde_json::to_string(&res).unwrap()))).expect("Failed to send network graph to websocket");
    }

    tokio::task::spawn(async move {
        while let Some(result) = ws_rx.next().await {
            let msg = match result {
                Ok(msg) => msg,
                Err(_) => break
            };
            if msg.is_close() { break; }
            println!("Received websocket message: {:?}", msg);
        }
    });
}
