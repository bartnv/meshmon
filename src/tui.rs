#![cfg(feature = "tui")]
use std::sync::Arc;
use lazy_static::lazy_static;
use termion::{ raw::IntoRawMode, screen::IntoAlternateScreen, screen::AlternateScreen, raw::RawTerminal };
use tui::{ Terminal, Frame, backend::{ Backend, TermionBackend }, widgets::{ Block, Borders, List, ListItem, Table, Row }, layout::{ Layout, Constraint, Direction, Corner }, text::{ Span, Spans }, style::{ Style, Color } };
use crate::{ Data, shorten_ipv6, timestamp_from };


static THRESHOLD: u16 = 4;


pub fn start_tui(data: Arc<Data>) -> Option<Terminal<TermionBackend<AlternateScreen<RawTerminal<std::io::Stdout>>>>> {
    let stdout = std::io::stdout().into_raw_mode().unwrap();
    let stdout = stdout.into_alternate_screen().unwrap();
    let backend = TermionBackend::new(stdout);
    let mut term = Terminal::new(backend).unwrap();
    term.clear().unwrap();
    term.draw(|f| draw(f, data)).unwrap();
    Some(term)
}

pub fn draw<B: Backend>(f: &mut Frame<B>, data: Arc<Data>) {
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
