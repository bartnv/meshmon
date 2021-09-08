use std::{ sync::RwLock, sync::Arc, mem::drop, collections::{ HashMap, VecDeque }, cmp::Ordering };
use tokio::{ fs, sync };
use petgraph::{ graph, graph::UnGraph, dot, data::FromElements, algo };
use termion::{ raw::IntoRawMode, screen::AlternateScreen };
use tui::{ Terminal, Frame, backend::{ Backend, TermionBackend }, widgets::{ Block, Borders, List, ListItem, Table, Row }, layout::{ Layout, Constraint, Direction, Corner }, text::{ Span, Spans }, style::{ Style, Color } };
use lazy_static::lazy_static;
use crate::{ Config, Node, Control, Protocol, GraphExt, unixtime };

static HISTSIZE: usize = 1440;
static THRESHOLD: u16 = 4;

#[derive(Eq)]
struct PingResult {
    node: String,
    intf: String,
    port: String,
    min: u16,
    last: Option<u16>,
    hist: VecDeque<u16>,
}
impl PingResult {
    fn new(node: String, intf: String, port: String) -> PingResult {
        return PingResult { node, intf, port, min: u16::MAX, last: None, hist: VecDeque::with_capacity(HISTSIZE) };
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
    log: RwLock<VecDeque<String>>,
    ping: RwLock<VecDeque<String>>,
    intf: RwLock<HashMap<String, IntfStats>>,
    results: RwLock<Vec<PingResult>>
}
impl Data {
    fn push_log(&self, line: String) {
        let mut log = self.log.write().unwrap();
        if log.len() >= 50 { log.pop_back().unwrap(); }
        log.push_front(line);
    }
    fn push_ping(&self, line: String) {
        let mut ping = self.ping.write().unwrap();
        if ping.len() >= 50 { ping.pop_back().unwrap(); }
        ping.push_front(line);
    }
}
struct IntfStats {
    min: u16,
    lag: u16
}

pub async fn run(aconfig: Arc<RwLock<Config>>, mut rx: sync::mpsc::Receiver<Control>, ctrltx: sync::mpsc::Sender<Control>, udptx: sync::mpsc::Sender<Control>) {
    let mut peers = HashMap::new();
    let mynode = graph::NodeIndex::new(0);
    let (myname, debug) = {
        let config = aconfig.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        (config.name.clone(), runtime.debug)
    };
    let mut nodeidx = usize::MAX-1;
    let mut relaymsgs: Vec<(String, Protocol, bool)> = vec![];
    let mut directmsgs: Vec<(String, Protocol)> = vec![];
    let mut udpmsgs: Vec<Control> = vec![];
    let data: Arc<Data> = Arc::new(Default::default());

    let mut term = match aconfig.read().unwrap().runtime.read().unwrap().tui {
        false => None,
        true => {
            let stdout = std::io::stdout().into_raw_mode().unwrap();
            let stdout = AlternateScreen::from(stdout);
            let backend = TermionBackend::new(stdout);
            Some(Terminal::new(backend).unwrap())
        }
    };
    if let Some(ref mut term) = term {
        term.clear().unwrap();
        term.draw(|f| draw(f, data.clone())).unwrap();
    }

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
                        println!("Number of peers ({}) is below target number ({}), but I have no more available nodes", count, config.targetpeers);
                    }
                    else if debug { println!("Selected node {} for uplink connection", config.nodes.get(nodeidx).unwrap().name); }
                }
                else {
                    nodeidx = usize::MAX-1; // Reset node index for regular connections
                    if ticks%15 == 0 { // Only check for weak connections once every 15 minutes
                        let runtime = config.runtime.read().unwrap();
                        if runtime.graph.node_count() > 4 {
                            if let Some(name) = runtime.graph.find_weakly_connected_node() {
                                if let Some(node) = config.nodes.iter().find(|i| i.name == name) {
                                    if debug { println!("Connecting to node {} to fix weak connection in network", name); }
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
            Control::Round => {
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
                            .or_insert(IntfStats { min: last, lag: last-result.min });
                    }
                }
                for result in data.results.write().unwrap().iter_mut() {
                    if let Some(last) = result.last {
                        result.push_hist(last);
                        result.last = None;
                    }
                    else { result.push_hist(u16::MAX); }
                }
                redraw = true;
            },
            Control::NewLink(sender, from, to, prio) => {
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
                            data.push_log(text.clone());
                            runtime.log.push((unixtime(), text));
                            redraw = true;
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
                            data.push_log(text.clone());
                            runtime.log.push((unixtime(), text));
                            redraw = true;
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
                        if !dropped.is_empty() {
                            let text = match dropped.len() {
                                1 => format!("Node {} left the network", dropped[0]),
                                n => format!("Netsplit: lost connection to {} nodes ({})", n, dropped.join(", "))
                            };
                            data.push_log(text.clone());
                            runtime.log.push((unixtime(), text));
                            redraw = true;
                        }
                        relaymsgs.push((sender, Protocol::Drop { from, to }, true));
                        runtime.msp = calculate_msp(&runtime.graph);
                    }
                }
            },
            Control::NewPeer(name, tx) => {
                if peers.is_empty() {
                    let config = aconfig.read().unwrap();
                    let mut runtime = config.runtime.write().unwrap();
                    let text = format!("Joined the network with {} other nodes", runtime.graph.node_count()-1);
                    data.push_log(text.clone());
                    runtime.log.push((unixtime(), text));
                    redraw = true;
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
                    // if !dropped.is_empty() { println!("Lost {} node{}", dropped.len(), match dropped.len() { 1 => "", _ => "s" }); }
                    if peers.is_empty() {
                        let text = format!("Disconnected from the network; lost {} node{}", dropped.len(), match dropped.len() { 1 => "", _ => "s" });
                        data.push_log(text.clone());
                        runtime.log.push((unixtime(), text));
                    }
                    else {
                        for node in dropped {
                            let text = format!("Node {} left the network", node);
                            data.push_log(text.clone());
                            runtime.log.push((unixtime(), text));
                        }
                    }
                    redraw = true;
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
                if debug { println!("{}", data.ping.read().unwrap().front().unwrap()); }
                redraw = true;
            },
            Control::Update(text) => {
                data.push_log(text.clone());
                let config = aconfig.read().unwrap();
                let mut runtime = config.runtime.write().unwrap();
                data.push_log(text.clone());
                runtime.log.push((unixtime(), text));
                if runtime.log.len() > 25 {
                    let drain = runtime.log.len()-25;
                    runtime.log.drain(0..drain);
                }
                redraw = true;
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
                                if debug { println!("Relaying {:?} to {}", proto, runtime.msp[peer]); }
                                targets.push((tx.clone(), Control::Send(proto.clone())));
                            },
                            None => {
                                eprintln!("Peer {} not found", runtime.msp[peer]);
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
                if let Some((_, path)) = res {
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
fn calculate_msp(graph: &UnGraph<String, u8>) -> UnGraph<String, u8> {
    // The resulting graph will have all nodes of the input graph with identical indices
    graph::Graph::from_elements(algo::min_spanning_tree(&graph))
}

fn draw<B: Backend>(f: &mut Frame<B>, data: Arc<Data>) {
    let vert1 = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50) ].as_ref())
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
    for line in data.log.read().unwrap().iter().take(vert2[0].height.into()) {
        content.push(ListItem::new(Span::from(line.clone())));
    }
    let list = List::new(content).block(block).start_corner(Corner::BottomLeft);
    f.render_widget(list, vert2[0]);

    let block = Block::default()
            .title(" Local interface stats ")
            .borders(Borders::ALL);
    let mut content: Vec<Row> = vec![];
    for (intf, stats) in data.intf.read().unwrap().iter() {
        content.push(Row::new(vec![ (*intf).clone(), format!("{:^5}", stats.min), format!("{:^5}", stats.lag) ]));
    }
    let table = Table::new(content)
        .block(block)
        .column_spacing(1)
        .header(Row::new(vec![ "Interface", "Best", "Lag" ]))
        .widths(&[Constraint::Length(20), Constraint::Length(5), Constraint::Length(5)]);
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
        let header = format!("{:10} {:39} ", result.node, result.port);
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
