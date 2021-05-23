use std::{ str, time::{ Duration, Instant }, env, default::Default, sync::RwLock, error::Error, sync::Arc, convert::TryInto, collections::HashMap };
use tokio::{ fs, net, sync };
use crate::{ Config, Node, Connection, ConnState, Control, Protocol, GraphExt };

pub async fn run(config: Arc<RwLock<Config>>, addr: String, mut sock: net::UdpSocket, ctrltx: sync::mpsc::Sender<Control>) {
    let (tx, mut ctrlrx) = sync::mpsc::channel(10);
    ctrltx.send(Control::UdpSock(addr.clone(), tx.clone())).await.unwrap();

    let mut buf = [0; 1500];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                println!("UDP received {} bytes from {}", len, addr);
            },
            Err(e) => {
                println!("UDP error: {}", e);
            }
        }
    }
}
