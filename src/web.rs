#![cfg(feature = "web")]
use std::sync::{ Arc, RwLock, atomic::Ordering };
use tokio::sync;
use http_body_util::Full;
use hyper::{ Request, Response, body::{ Bytes, Incoming }, service::service_fn };
use hyper_util::rt::TokioIo;
use hyper_tungstenite::{HyperWebsocket, tungstenite::Message};
use tokio_stream::wrappers::TcpListenerStream;
use futures_util::stream::StreamExt;
use rustls_acme::{ AcmeConfig, AccountCache, CertCache };
use serde::Serialize;
use tokio::net::TcpListener;
use ring::digest::{ Context, SHA256 };
use async_trait::async_trait;
use base64::{ Engine as _, engine::general_purpose::STANDARD as base64 };

use crate::{ Config, Control, Data, LogLevel };


static INDEX_FILE: &str = include_str!("../web/index.html");
static ICON_FILE: &[u8] = include_bytes!("../web/favicon.ico");

struct ConfigCache {
    config: Arc<RwLock<Config>>
}
impl ConfigCache {
    fn new(config: &Arc<RwLock<Config>>) -> ConfigCache {
        ConfigCache {
            config: config.clone()
        }
    }
    fn cached_account_key(&self, contact: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for el in contact {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = base64.encode(ctx.finish());
        format!("cached_account_{}", hash)
    }
    fn cached_cert_key(&self, domains: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for domain in domains {
            ctx.update(domain.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = base64.encode(ctx.finish());
        format!("cached_cert_{}", hash)
    }
}

#[async_trait]
#[cfg(feature = "web")]
impl CertCache for ConfigCache {
    type EC = std::io::Error;
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let key = self.cached_cert_key(&domains, directory_url);
        Ok(self.config.read().unwrap().cache.get(&key).map(|v| base64.decode(v).unwrap()))
    }
    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let key = self.cached_cert_key(&domains, directory_url);
        let mut config = self.config.write().unwrap();
        config.cache.insert(key, base64.encode(cert));
        config.modified.store(true, Ordering::Relaxed);
        Ok(())
    }
}
#[async_trait]
#[cfg(feature = "web")]
impl AccountCache for ConfigCache {
    type EA = std::io::Error;
    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let key = self.cached_account_key(&contact, directory_url);
        Ok(self.config.read().unwrap().cache.get(&key).map(|v| base64.decode(v).unwrap()))
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let key = self.cached_account_key(&contact, directory_url);
        let mut config = self.config.write().unwrap();
        config.cache.insert(key, base64.encode(account));
        config.modified.store(true, Ordering::Relaxed);
        Ok(())
    }
}

pub fn run_http(config: Arc<RwLock<Config>>, data: Arc<Data>, ctrltx: sync::mpsc::Sender<Control>, arg: String, debug: bool) {
    tokio::spawn(async move {
        let http = hyper::server::conn::http1::Builder::new();
        let service = service_fn(move |req| {
            // if debug { println!("{} Received HTTP request {} {}", timestamp(), req.method(), req.uri()); }
            handle_http(req, config.clone(), data.clone())
        });
        let tcp_listener = match TcpListener::bind(&arg).await {
            Ok(x) => x,
            Err(e) => {
                ctrltx.send(Control::Log(LogLevel::Error, format!("Failed to start http server on {arg}: {e}"))).await.unwrap();
                return;
            }
        };
        ctrltx.send(Control::Log(LogLevel::Info, format!("Started HTTP server on {}", arg))).await.unwrap();
        while let Ok((stream, addr)) = tcp_listener.accept().await {
            if debug { ctrltx.send(Control::Log(LogLevel::Debug, format!("Incoming HTTP connection from {}", addr))).await.unwrap(); }
            let conn = http.serve_connection(TokioIo::new(stream), service.clone()).with_upgrades();
            if let Err(e) = tokio::spawn(async move { conn.await }).await {
                ctrltx.send(Control::Log(LogLevel::Error, format!("Error: {e}"))).await.unwrap();
            }
        }
    });
}

pub fn run_https(config: Arc<RwLock<Config>>, data: Arc<Data>, ctrltx: sync::mpsc::Sender<Control>, arg: String, letsencrypt: Option<String>, debug: bool) {
    tokio::spawn(async move {
        let http = hyper::server::conn::http1::Builder::new();
        let aconfig = config.clone();
        let service = service_fn(move |req| {
            // if debug { println!("{} Received HTTPS request {} {}", timestamp(), req.method(), req.uri()); }
            handle_http(req, aconfig.clone(), data.clone())
        });
        let tcp_listener = match TcpListener::bind(&arg).await {
            Ok(x) => x,
            Err(e) => {
                ctrltx.send(Control::Log(LogLevel::Error, format!("Failed to start https server on {arg}: {e}"))).await.unwrap();
                return;
            }
        };
        let domain = arg.rsplit_once(':').expect("No colon found in --https argument").0;
        if domain.contains(':') || domain.find(char::is_alphabetic).is_none() {
            ctrltx.send(Control::Log(LogLevel::Error, format!("Cannot use bare IP address with --https; use a fully qualified domain name"))).await.unwrap();
            return;
        }
        let tcp_incoming = TcpListenerStream::new(tcp_listener);
        let mut tls_incoming = AcmeConfig::new([ &domain ])
            .contact_push(format!("mailto:{}", letsencrypt.unwrap()))
            .cache(ConfigCache::new(&config))
            .directory_lets_encrypt(true)
            .tokio_incoming(tcp_incoming, Vec::new());
        ctrltx.send(Control::Log(LogLevel::Info, format!("Started HTTPS server on {}", arg))).await.unwrap();
        while let Some(tls) = tls_incoming.next().await {
            let stream = tls.unwrap();
            if debug { ctrltx.send(Control::Log(LogLevel::Debug, format!("Incoming HTTPS connection from {}", stream.get_ref().get_ref().0.get_ref().peer_addr().unwrap_or("0.0.0.0:0".parse().unwrap())))).await.unwrap(); }
            let conn = http.serve_connection(TokioIo::new(stream), service.clone()).with_upgrades();
            if let Err(e) = tokio::spawn(async move { conn.await }).await {
                ctrltx.send(Control::Log(LogLevel::Error, format!("Error: {e}"))).await.unwrap();
            }
        }
    });
}

pub async fn handle_http(mut request: Request<Incoming>, config: Arc<RwLock<Config>>, data: Arc<Data>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    if hyper_tungstenite::is_upgrade_request(&request) {
        let (response, websocket) = hyper_tungstenite::upgrade(&mut request, None)?;
        tokio::spawn(async move {
            let _ = handle_websocket(websocket, config, data).await;
        });
        Ok(response)
    } else {
        match request.uri().path() {
            "/" => Ok(Response::new(Full::<Bytes>::from(INDEX_FILE))),
            "/favicon.ico" => Ok(Response::new(Full::<Bytes>::from(ICON_FILE))),
            _ => Ok(Response::builder().status(hyper::StatusCode::NOT_FOUND).body(Full::<Bytes>::from("")).unwrap())
        }
    }

}

pub async fn handle_websocket(ws: HyperWebsocket, config: Arc<RwLock<Config>>, data: Arc<Data>) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    #[derive(Default, Serialize)]
    struct JsonGraph {
        msg: &'static str,
        nodes: Vec<JsonNode>,
        edges: Vec<JsonEdge>,
        paths: Vec<JsonPath>,
        log: Vec<JsonLog>
    }
    #[derive(Serialize)]
    struct JsonNode {
        name: String
    }
    #[derive(Serialize)]
    struct JsonEdge {
        from: String,
        to: String,
        mode: &'static str
    }
    #[derive(Serialize)]
    struct JsonPath {
        fromname: String,
        fromintf: String,
        toname: String,
        tointf: String,
        losspct: u8
    }
    #[derive(Serialize)]
    struct JsonLog {
        ts: u64,
        text: String
    }

    let (ws_tx, mut ws_rx) = ws.await?.split();
    let (tx, rx) = sync::mpsc::unbounded_channel();
    let rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
    tokio::spawn(rx.forward(ws_tx));

    let mut res = JsonGraph { msg: "init", ..Default::default() };
    {
        let config = config.read().unwrap();
        let mut runtime = config.runtime.write().unwrap();
        runtime.wsclients.push(tx.clone());

        let nodes = runtime.graph.raw_nodes();
        for node in nodes.iter() {
            res.nodes.push(JsonNode { name: node.weight.clone() });
        }
        for edge in runtime.graph.raw_edges() {
            let mode = match runtime.msp.contains_edge(edge.source(), edge.target()) {
                true => "active",
                false => "standby"
            };
            res.edges.push(JsonEdge { from: runtime.graph[edge.source()].clone(), to: runtime.graph[edge.target()].clone(), mode });
        }
        drop(runtime);
        let log = data.log.read().unwrap();
        for (ts, msg) in log.iter().rev() {
            res.log.push(JsonLog { ts: *ts, text: msg.clone() });
        }
        let results = data.results.read().unwrap();
        for result in results.iter() {
            res.paths.push(JsonPath { fromname: config.name.clone(), fromintf: result.intf.clone(), toname: result.node.clone(), tointf: result.port.clone(), losspct: result.losspct.round() as u8 });
        }
        let pathcache = data.pathcache.read().unwrap();
        for path in pathcache.iter() {
            res.paths.push(JsonPath { fromname: path.from.clone(), fromintf: path.fromintf.clone(), toname: path.to.clone(), tointf: path.tointf.clone(), losspct: path.losspct });
        }
    }
    tx.send(Ok(Message::text(serde_json::to_string(&res).unwrap())))?;

    while let Some(message) = ws_rx.next().await {
        match message? {
            Message::Text(msg) => {
                println!("Received text message: {}", msg);
            },
            Message::Binary(msg) => {
                println!("Received binary message: {:02X?}", msg);
            },
            Message::Ping(msg) => {
                println!("Received websocket ping message: {:02X?}", msg);
            },
            Message::Pong(msg) => {
                println!("Received websocket pong message: {:02X?}", msg);
            }
            Message::Close(_) => {},
            Message::Frame(_) => {}
        }
    }

    Ok(())
}
