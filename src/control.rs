use std::{ sync::RwLock, sync::Arc, mem::drop, collections::HashMap };
use tokio::{ fs, sync };
use petgraph::{ graph, graph::UnGraph, dot, data::FromElements };
use crate::{ Config, Node, Control, Protocol, GraphExt };

pub async fn run(aconfig: Arc<RwLock<Config>>, mut rx: sync::mpsc::Receiver<Control>, ctrltx: sync::mpsc::Sender<Control>, udptx: sync::mpsc::Sender<Control>) {
    let mut peers = HashMap::new();
    let mynode = graph::NodeIndex::new(0);
    let myname = {
        let config = aconfig.read().unwrap();
        config.name.clone()
    };
    let mut nodeidx = usize::MAX-1;
    let mut relaymsgs: Vec<(String, Protocol, bool)> = vec![];
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
                        udpmsgs.push(Control::NewNode(from.clone()));
                        runtime.graph.add_node(from.clone())
                    }
                };
                let toidx = match runtime.graph.find_node(&to) {
                    Some(idx) => idx,
                    None => {
                        udpmsgs.push(Control::NewNode(to.clone()));
                        runtime.graph.add_node(to.clone())
                    }
                };
                let changes = match runtime.graph.find_edge(fromidx, toidx) {
                    Some(idx) => {
                        match runtime.graph[idx] {
                            prio => false,
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
                        let count = runtime.graph.drop_detached_nodes();
                        if count > 0 { println!("Lost {} nodes", count); }
                        relaymsgs.push((sender, Protocol::Drop { from, to }, true));
                    }
                }
                runtime.msp = calculate_msp(&runtime.graph);
            },
            Control::NewPeer(name, tx) => {
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
                    let count = runtime.graph.drop_detached_nodes();
                    if count > 0 { println!("Lost {} nodes", count); }
                }
                runtime.msp = calculate_msp(&runtime.graph);
            },
            Control::Relay(from, proto) => {
                relaymsgs.push((from, proto, false));
            },
            _ => {
                panic!("Received unexpected Control message on control task");
            }
        }
        if !relaymsgs.is_empty() {
            let config = aconfig.read().unwrap();
            let runtime = config.runtime.read().unwrap();
            for (from, proto, broadcast) in relaymsgs.drain(..) {
                let mut targets: Vec<sync::mpsc::Sender<Control>> = vec![];
                if broadcast {
                    for (name, tx) in &peers {
                        if *name == from { continue; }
                        targets.push(tx.clone());
                    }
                }
                else {
                    for peer in runtime.msp.neighbors(mynode) {
                        if runtime.msp[peer] == from { continue; }
                        match peers.get(&runtime.msp[peer]) {
                            Some(tx) => {
                                println!("Relaying {:?} to {}", proto, runtime.msp[peer]);
                                targets.push(tx.clone());
                            },
                            None => {
                                println!("Peer {} not found", runtime.msp[peer]);
                            }
                        }
                    }
                }
                if !targets.is_empty() {
                    tokio::spawn(async move {
                        for tx in targets {
                            let proto = proto.clone();
                            tx.send(Control::Send(proto)).await.unwrap();
                        }
                    });
                }
            }
        }
        if !udpmsgs.is_empty() {
            let tx = udptx.clone();
            let msgs: Vec<Control> = udpmsgs.drain(..).collect();
            tokio::spawn(async move {
                for msg in msgs.into_iter() {
                    tx.send(msg).await.unwrap();
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
    graph::Graph::from_elements(petgraph::algo::min_spanning_tree(&graph))
}
