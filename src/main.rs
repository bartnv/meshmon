use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use serde_derive::{Deserialize, Serialize};
use std::{str, time, error::Error, convert::TryInto};
use tokio::{fs, net, sync, io::AsyncReadExt};

#[derive(Serialize, Deserialize)]
struct Config {
    name: String,
    listen: Vec<String>,
    privkey: String,
    peers: Vec<Peer>,
}

#[derive(Serialize, Deserialize)]
struct Peer {
    name: String,
    listen: Vec<String>,
}

struct Runtime {
    privkey: Option<SecretKey>,
    pubkey: Option<PublicKey>,
}

#[derive(Debug)]
struct Connection {
    peername: String,
    socket: net::TcpStream,
    lastdata: time::Instant,
    synced: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut config: Config = toml::from_str(&fs::read_to_string("config.toml").await?)?;
    let mut runtime = Runtime {
        privkey: None,
        pubkey: None,
    };
    let rawkey: [u8; 32] = base64::decode(&config.privkey)?
        .as_slice()
        .try_into()
        .expect("Entry 'privkey' in config.toml is not a valid base64 private key");
    runtime.privkey = Some(rawkey.into());
    runtime.pubkey = Some(runtime.privkey.unwrap().public_key());
    println!("My pubkey is {}", base64::encode(runtime.pubkey.unwrap().to_bytes()));

    let (tx, mut rx) = sync::mpsc::channel(10);
    for port in &config.listen {
        let tx = tx.clone();
        let local: std::net::SocketAddr = port.parse()?;
        let listener = net::TcpListener::bind(local).await?;
        println!("Started listening on {}", port);
        tokio::spawn(async move {
            loop {
                let tx = tx.clone();
                if let Ok((socket, remote)) = listener.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming_tcp(socket, local, remote).await {
                            tx.send(conn).await.unwrap();
                        }
                    });
                }
            }
        });
    }
    let control = tokio::spawn(async move {
        while let Some(conn) = rx.recv().await {
            println!("Connection from {} ({}) to {} at {:?}", conn.peername, conn.socket.peer_addr().unwrap(), conn.socket.local_addr().unwrap(), conn.lastdata);
        }
    });
    tokio::join!(control);
    // let mut rng = rand::thread_rng();
    // config.privkey = base64::encode(SecretKey::generate(&mut rng).to_bytes());
    tokio::time::sleep(time::Duration::from_secs(10)).await;
    fs::write("config.toml", toml::to_string_pretty(&config)?).await?;
    Ok(())
}

async fn incoming_tcp(mut socket: net::TcpStream, local: std::net::SocketAddr, remote: std::net::SocketAddr) -> Result<Connection, &'static str> {
    println!("Incoming connection from {} on {}", remote, local);
    let mut buf: Vec<u8> = vec![0; 1024];
    loop {
        let _n = match socket.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            Ok(_) => return Err("connection closed"),
            Err(_) => return Err("read error")
        };
        println!("Received data: {}", &str::from_utf8(&buf).unwrap());
        return Ok(Connection { peername: "test".to_string(), socket, lastdata: time::Instant::now(), synced: true });
    }
}
