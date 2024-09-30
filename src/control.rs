// #![allow(dead_code, unused_imports, unused_variables, unused_mut, unreachable_patterns)] // Please be quiet, I'm coding
use std::{ sync::{ RwLock, Arc }, sync::atomic::Ordering, mem::drop, collections::HashMap };
use tokio::{ fs, sync };
use petgraph::{ graph, graph::UnGraph, data::FromElements, algo };
use rand::seq::SliceRandom;
use crate::{ Config, Control, Data, IntfStats, LogLevel, Node, Path, PingResult, Protocol, get_local_interfaces, duration_from, unixtime, shorten_ipv6, timestamp };

#[cfg(feature = "web")]
use crate::web::{ run_http, run_https };
#[cfg(feature = "web")]
use hyper_tungstenite::tungstenite::Message;

#[cfg(feature = "tui")]
use crate::{ timestamp_from, tui::{ draw, start_tui } };
#[cfg(feature = "tui")]
use termion::{ input::TermRead, event::Key };


static THRESHOLD: u16 = 4;
static MAX_LINGER: u64 = 86400; // Seconds to keep visualising links that are down

trait GraphExt {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex>;
    fn drop_detached_nodes(&mut self) -> Vec<String>;
    fn find_weakly_connected_nodes(&self) -> Vec<String>;
    fn weakly_connected_dfs(&self, v: graph::NodeIndex, depth: u8, visited: &mut HashMap<graph::NodeIndex, u8>, found: &mut Vec<String>, parent: Option<graph::NodeIndex>) -> (u8, Vec<String>);
}
impl GraphExt for UnGraph<String, u32> {
    fn find_node(&self, name: &str) -> Option<graph::NodeIndex> {
        self.node_indices().find(|i| self[*i] == name)
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

pub async fn run(aconfig: Arc<RwLock<Config>>, mut rx: sync::mpsc::Receiver<Control>, ctrltx: sync::mpsc::Sender<Control>, udptx: sync::mpsc::Sender<Control>) {
    let mut peers = HashMap::new();
    let mynode = graph::NodeIndex::new(0);
    #[allow(unused_variables)]
    let (myname, results, debug, http, https, letsencrypt) = {
        let config = aconfig.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        (config.name.clone(), runtime.results, runtime.debug, runtime.http.clone(), runtime.https.clone(), config.letsencrypt.clone())
    };
    let mut nodeidx = 0;
    let mut relaymsgs: Vec<(String, Protocol, bool)> = vec![];
    let mut directmsgs: Vec<(String, Protocol)> = vec![];
    let mut udpmsgs: Vec<Control> = vec![];
    let mut logmsgs: Vec<(LogLevel, String)> = vec![];
    let data: Arc<Data> = Arc::new(Default::default());

    #[cfg(feature = "web")]
    if let Some(arg) = http {
        let config = aconfig.clone();
        let data = data.clone();
        let ctrltx = ctrltx.clone();
        run_http(config, data, ctrltx, arg, debug);
    }
    #[cfg(feature = "web")]
    if let Some(arg) = https {
        let config = aconfig.clone();
        let data = data.clone();
        let ctrltx = ctrltx.clone();
        run_https(config, data, ctrltx, arg, letsencrypt, debug);
    }

    #[cfg(feature = "tui")]
    let mut term = match aconfig.read().unwrap().runtime.read().unwrap().tui {
        false => None,
        true => start_tui(data.clone())
    };
    #[cfg(not(feature = "tui"))]
    let term: Option<()> = None;
    #[cfg(feature = "tui")]
    let stdintx = ctrltx.clone();
    #[cfg(feature = "tui")]
    tokio::task::spawn_blocking(move || { // Thread to wait for input events
        let stdin = std::io::stdin();
        let keys = stdin.keys();
        for event in keys {
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
                    nodeidx = 0; // Reset node index for regular connections
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
                data.pathcache.write().unwrap().retain(|p| p.since > cutoff || p.losspct < 100);

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
                            #[cfg(feature = "web")]
                            {
                                let config = aconfig.read().unwrap();
                                let mut runtime = config.runtime.write().unwrap();
                                if !runtime.wsclients.is_empty() {
                                    let json = format!("{{ \"msg\": \"pathstate\", \"fromname\": \"{}\", \"fromintf\": \"{}\",
                                        \"toname\": \"{}\", \"tointf\": \"{}\", \"losspct\": {} }}",
                                        &myname, &result.intf, &result.node, &result.port, result.losspct.round()
                                    );
                                    runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                                }
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
                    if node.lastconnseq == seq { continue; } // Duplicate message; drop it
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
                    #[cfg(feature = "web")]
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
                    #[cfg(feature = "web")]
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
                #[cfg(feature = "web")]
                {
                    let config = aconfig.read().unwrap();
                    let mut runtime = config.runtime.write().unwrap();
                    if !runtime.wsclients.is_empty() {
                        let json = format!("{{ \"msg\": \"newlink\", \"from\": \"{}\", \"to\": \"{name}\", \"mode\": \"unknown\" }}", myname.clone());
                        runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                    }
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
                #[cfg(feature = "web")]
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
                if results && term.is_none() { println!("{}", data.ping.read().unwrap().front().unwrap()); }
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
                    #[cfg(feature = "web")]
                    {
                        let config = aconfig.read().unwrap();
                        let mut runtime = config.runtime.write().unwrap();
                        if !runtime.wsclients.is_empty() {
                            let json = format!("{{ \"msg\": \"pathstate\", \"fromname\": \"{}\", \"fromintf\": \"{}\",
                                \"toname\": \"{}\", \"tointf\": \"{}\", \"losspct\": {} }}",
                                &from, &fromintf, &to, &tointf, losspct
                            );
                            runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                        }
                    }
    
                    let protocol = Protocol::Path { from, to, fromintf, tointf, losspct };
                    relaymsgs.push((peer, protocol, false));
                }
            },
            #[cfg(feature = "tui")]
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
                    #[cfg(feature = "web")]
                    {
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
            #[cfg(feature = "tui")]
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
                #[cfg(feature = "web")]
                {
                    let mut runtime = config.runtime.write().unwrap();
                    if !runtime.wsclients.is_empty() {
                        let json = format!("{{ \"msg\": \"pathstate\", \"fromname\": \"{}\", \"fromintf\": \"{}\",
                            \"toname\": \"{}\", \"tointf\": \"{}\", \"losspct\": {} }}",
                            &config.name, &result.intf, &result.node, &result.port, result.losspct.round()
                        );
                        runtime.wsclients.retain(|tx| tx.send(Ok(Message::text(&json))).is_ok());
                    }
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
