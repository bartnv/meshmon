use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use serde_derive::{Deserialize, Serialize};
use std::{str, time, error::Error, convert::TryInto};
use tokio::{fs, net, io::AsyncReadExt};

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
}

struct Runtime {
    privkey: Option<SecretKey>,
    pubkey: Option<PublicKey>,
}

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
    let listener = net::TcpListener::bind(config.listen.first().unwrap()).await?;
    loop {
        if let Ok((mut socket, addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf: Vec<u8> = vec![0; 1024];
                loop {
                    let n = match socket.read(&mut buf).await {
                         Ok(n) if n == 0 => return,
                         Ok(n) => n,
                         Err(e) => {
                             eprintln!("failed to read from socket; err = {:?}", e);
                             return;
                         }
                     };
                     println!("Received data: {}", &str::from_utf8(&buf).unwrap());
                 }
            });
        }
    }
    // let mut rng = rand::thread_rng();
    // config.privkey = base64::encode(SecretKey::generate(&mut rng).to_bytes());
    fs::write("config.toml", toml::to_string_pretty(&config)?).await?;
    Ok(())
}
