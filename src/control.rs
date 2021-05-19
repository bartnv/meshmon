use std::{ sync::RwLock, sync::Arc, mem::drop, collections::HashMap };
use tokio::{ fs, sync };
use petgraph::{ graph, graph::UnGraph, dot, data::FromElements };
use crate::{ Config, Node, Control, Protocol, GraphExt };

pub async fn run(aconfig: Arc<RwLock<Config>>, mut rx: sync::mpsc::Receiver<Control>, tx: sync::mpsc::Sender<Control>) {
    let mut peers = HashMap::new();
    let mynode = graph::NodeIndex::new(0);
    let myname = {
        let config = aconfig.read().unwrap();
        config.name.clone()
    };
    let mut nodeidx = usize::MAX-1;
    let mut relays: Vec<(String, Protocol)> = vec![];
    loop {
        match rx.recv().await.unwrap() {
            Control::Tick => {
                println!("Tick");
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
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            crate::tcp::connect_node(config, tx, ports, false).await;
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
                if runtime.graph.add_edge_from_names(&from, &to, prio) { // True if a change was made
                    relays.push((sender, Protocol::Link { from, to, prio }));
                }
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
                        runtime.graph.drop_detached_edges();
                        relays.push((sender, Protocol::Drop { from, to }));
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
                        relays.push((name.clone(), Protocol::Drop { from: myname.clone(), to: name.clone() }));
                    }
                    let count = runtime.graph.drop_detached_edges();
                    println!("Removed {} links", count+1);
                }
                runtime.msp = calculate_msp(&runtime.graph);
            },
            Control::Relay(from, proto) => {
                relays.push((from, proto));
            },
            _ => {
                panic!("Received unexpected Control message on control task");
            }
        }
        if relays.len() > 0 {
            let config = aconfig.read().unwrap();
            let runtime = config.runtime.read().unwrap();
            for (from, proto) in relays.drain(..) {
                let mut targets: Vec<sync::mpsc::Sender<Control>> = vec![];
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
    }
}

fn find_next_node(nodes: &Vec<Node>, start: usize) -> Option<usize> {
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
