use std::{ sync::RwLock, sync::Arc, mem::drop, collections::HashMap };
use tokio::{ fs, sync };
use petgraph::{ graph, graph::UnGraph, dot, data::FromElements, algo };
use crate::{ Config, Node, Control, Protocol, GraphExt, unixtime };

pub async fn run(aconfig: Arc<RwLock<Config>>, mut rx: sync::mpsc::Receiver<Control>, ctrltx: sync::mpsc::Sender<Control>, udptx: sync::mpsc::Sender<Control>) {
    let mut peers = HashMap::new();
    let mynode = graph::NodeIndex::new(0);
    let myname = {
        let config = aconfig.read().unwrap();
        config.name.clone()
    };
    let mut nodeidx = usize::MAX-1;
    let mut relaymsgs: Vec<(String, Protocol, bool)> = vec![];
    let mut directmsgs: Vec<(String, Protocol)> = vec![];
    let mut udpmsgs: Vec<Control> = vec![];
    loop {
        match rx.recv().await.unwrap() {
            Control::Tick => {
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
                        println!("Number of peers ({}) is below target number ({}), but I have no more available nodes", count, config.targetpeers);
                    }
                    else {
                        let config = aconfig.clone();
                        let ctrltx = ctrltx.clone();
                        tokio::spawn(async move {
                            crate::tcp::connect_node(config, ctrltx, ports, false).await;
                        });
                    }
                }
                else { nodeidx = usize::MAX-1; }

                if let Some(file) = &config.dotfile {
                    let runtime = config.runtime.read().unwrap();
                    let file = file.clone();
                    let data = format!("{:?}", dot::Dot::with_config(&runtime.graph, &[dot::Config::EdgeNoLabel]));
                    let msp = format!("{:?}", dot::Dot::with_config(&runtime.msp, &[dot::Config::EdgeNoLabel]));
                    tokio::spawn(async move {
                        let mspfile = "msp.dot";
                        fs::write(file, data).await.unwrap_or_else(|e| eprintln!("Failed to write dotfile: {}", e));
                        fs::write(mspfile, msp).await.unwrap_or_else(|e| eprintln!("Failed to write msp dotfile: {}", e));
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
            Control::NewLink(sender, from, to, prio) => {
                let config = aconfig.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                let fromidx = match runtime.graph.find_node(&from) {
                    Some(idx) => idx,
                    None => {
                        if config.nodes.iter().find(|node| node.name == from).is_some() {
                            udpmsgs.push(Control::ScanNode(from.clone(), false));
                        }
                        if peers.len() > 0 {
                            let text = format!("Node {} joined the network", from);
                            runtime.log.push((unixtime(), text));
                        }
                        runtime.graph.add_node(from.clone())
                    }
                };
                let toidx = match runtime.graph.find_node(&to) {
                    Some(idx) => idx,
                    None => {
                        if config.nodes.iter().find(|node| node.name == to).is_some() {
                            udpmsgs.push(Control::ScanNode(to.clone(), false));
                        }
                        if peers.len() > 0 {
                            let text = format!("Node {} joined the network", to);
                            runtime.log.push((unixtime(), text));
                        }
                        runtime.graph.add_node(to.clone())
                    }
                };
                let changes = match runtime.graph.find_edge(fromidx, toidx) {
                    Some(idx) => {
                        match runtime.graph[idx] {
                            val if val == prio => false,
                            _ => {
                                runtime.graph[idx] = prio;
                                true
                            }
                        }
                    },
                    None => {
                        runtime.graph.add_edge(fromidx, toidx, prio);
                        true
                    }
                };
                if changes { relaymsgs.push((sender, Protocol::Link { from, to, prio }, true)); };
                runtime.msp = calculate_msp(&runtime.graph);
            },
            Control::DropLink(sender, from, to) => {
                let config = aconfig.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                let fres = runtime.graph.find_node(&from);
                let tres = runtime.graph.find_node(&to);
                if let (Some(fnode), Some(tnode)) = (fres, tres) {
                    if let Some(edge) = runtime.graph.find_edge(fnode, tnode) {
                        runtime.graph.remove_edge(edge);
                        let dropped = runtime.graph.drop_detached_nodes();
                        if dropped.len() > 0 { println!("Lost {} node{}", dropped.len(), match dropped.len() { 1 => "", _ => "s" }); }
                        for node in dropped {
                            let text = format!("Node {} left the network", node);
                            runtime.log.push((unixtime(), text));
                        }
                    }
                }
                runtime.msp = calculate_msp(&runtime.graph);
            },
            Control::NewPeer(name, tx) => {
                if peers.len() == 0 {
                    let config = aconfig.read().unwrap();
                    let mut runtime = config.runtime.write().unwrap();
                    let text = format!("Joined the network with {} other nodes", runtime.graph.node_count()-1);
                    runtime.log.push((unixtime(), text));
                }
                peers.insert(name, tx);
            },
            Control::DropPeer(name) => {
                peers.remove(&name);
                let config = aconfig.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                if let Some(nodeidx) = runtime.graph.find_node(&name) {
                    if let Some(edge) = runtime.graph.find_edge(mynode, nodeidx) {
                        runtime.graph.remove_edge(edge);
                        relaymsgs.push((name.clone(), Protocol::Drop { from: myname.clone(), to: name.clone() }, true));
                    }
                    let dropped = runtime.graph.drop_detached_nodes();
                    if dropped.len() > 0 { println!("Lost {} node{}", dropped.len(), match dropped.len() { 1 => "", _ => "s" }); }
                    for node in dropped {
                        let text = format!("Node {} left the network", node);
                        runtime.log.push((unixtime(), text));
                    }
                }
                runtime.msp = calculate_msp(&runtime.graph);
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
            Control::Update(text) => {
                println!("{}", text);
                let config = aconfig.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                runtime.log.push((unixtime(), text));
                if runtime.log.len() > 25 {
                    let drain = runtime.log.len()-25;
                    runtime.log.drain(0..drain);
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
                                println!("Relaying {:?} to {}", proto, runtime.msp[peer]);
                                targets.push((tx.clone(), Control::Send(proto.clone())));
                            },
                            None => {
                                println!("Peer {} not found", runtime.msp[peer]);
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
                        eprintln!("Node {} not found in graph", to);
                        continue;
                    }
                };
                let res = algo::astar(&runtime.graph, mynode, |node| node == tonode, |e| *e.weight(), |_| 0);
                if let Some((cost, path)) = res {
                    let name = &runtime.graph[*path.get(1).unwrap()];
                    match peers.get(name) {
                        Some(tx) => {
                            targets.push((tx.clone(), Control::Send(proto)));
                        },
                        None => {
                            eprintln!("Peer {} not found for directmessage", name);
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

        if !targets.is_empty() {
            tokio::spawn(async move {
                for (tx, proto) in targets {
                    tx.send(proto).await.unwrap();
                }
            });
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
fn calculate_msp(graph: &UnGraph<String, u8>) -> UnGraph<String, u8> {
    // The resulting graph will have all nodes of the input graph with identical indices
    graph::Graph::from_elements(algo::min_spanning_tree(&graph))
}
