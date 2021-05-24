use std::{ str, time::{ Duration, Instant }, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto, collections::HashMap };
use tokio::{ fs, net, sync };
use crate::{ Config, Node, Connection, ConnState, Control, Protocol, GraphExt };

pub async fn run(config: Arc<RwLock<Config>>, ctrltx: sync::mpsc::Sender<Control>, udprx: sync::mpsc::Receiver<Control>) {
    let (readtx, mut readrx) = sync::mpsc::channel(10);
    let mut ports;
    let mut socks = HashMap::new();
    {
        let config = config.read().unwrap();
        let runtime = config.runtime.read().unwrap();
        ports = runtime.listen.clone();
    }
    for port in ports {
        match net::UdpSocket::bind(&port).await {
            Ok(sock) => {
                println!("Started UDP listener on {}", port);
                let sock = Arc::new(sock);
                socks.insert(port.clone(), sock.clone());
                let readtx = readtx.clone();
                tokio::spawn(async move {
                    udpreader(sock, readtx).await;
                });
            },
            Err(e) => {
                eprintln!("Failed to bind to UDP socket {}: {}", port, e);
            }
        }
    }

    loop {
        match readrx.recv().await.unwrap() {
            s => println!("Received UDP message: {}", s)
        }
    }
}

async fn udpreader(sock: Arc<net::UdpSocket>, readtx: sync::mpsc::Sender<String>) {
    let mut buf = [0; 1500];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                println!("Received {} bytes from {}", len, addr);
                readtx.send(String::from_utf8_lossy(&buf).to_string()).await.unwrap();
            },
            Err(e) => {
                println!("UDP error: {}", e);
            }
        }
    }
}
