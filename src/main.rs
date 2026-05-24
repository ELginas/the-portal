use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;

use http_body_util::BodyExt;
use http_body_util::Empty;
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use hyper::Method;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper::body;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::server::conn::http2;
use hyper::service::Service;
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::rt::TokioIo;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use reqwest::RequestBuilder;
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, Stream};
use time::{Duration, OffsetDateTime};
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::info;
use tracing::trace;
use tracing_subscriber::{self, prelude::*};
use url::Url;

fn generate_ca() -> (CertificateDer<'static>, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = params.not_before + Duration::days(30);
    params
        .distinguished_name
        .push(DnType::CommonName, "CA of Rust");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert = cert.into();
    (cert, Issuer::new(params, key_pair))
}

fn generate_cert(
    issuer: &Issuer<'static, KeyPair>,
    common_name: &str,
) -> (CertificateDer<'static>, KeyPair) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = params.not_before + Duration::days(30);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let dns_name = Ia5String::try_from(common_name).unwrap();
    params.subject_alt_names.push(SanType::DnsName(dns_name));
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key_pair, issuer).unwrap();
    let cert = cert.into();
    (cert, key_pair)
}

fn save_ca(cert_ca: &CertificateDer<'static>, issuer: &Issuer<'_, KeyPair>) {
    let mut file = File::create("ca_cert.der").unwrap();
    file.write_all(&cert_ca).unwrap();
    let mut file = File::create("ca_key.der").unwrap();
    file.write_all(issuer.key().serialized_der()).unwrap();
}

fn create_safe_file<P>(path: P) -> io::Result<File>
where
    P: AsRef<Path>,
{
    #[cfg(unix)]
    return OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(path);

    #[cfg(not(unix))]
    return OpenOptions::new().write(true).create(true).open(path);
}

fn save_cert(cert_ca: &CertificateDer<'static>, key_pair: &KeyPair) {
    let mut file = File::create("cert_cert.der").unwrap();
    file.write_all(&cert_ca).unwrap();
    let mut file = create_safe_file("cert_key.der").unwrap();
    file.write_all(key_pair.serialized_der()).unwrap();
}

fn load_ca() -> (CertificateDer<'static>, Issuer<'static, KeyPair>) {
    let mut file = File::open("ca_key.der").unwrap();
    let mut buf = vec![];
    file.read_to_end(&mut buf).unwrap();
    let key_pair = KeyPair::try_from(buf.as_slice()).unwrap();

    let mut file = File::open("ca_cert.der").unwrap();
    let mut buf = vec![];
    file.read_to_end(&mut buf).unwrap();
    let cert = buf.into();
    let issuer = Issuer::from_ca_cert_der(&cert, key_pair).unwrap();

    (cert, issuer)
}

fn load_cert() -> (CertificateDer<'static>, KeyPair) {
    let mut file = create_safe_file("cert_key.der").unwrap();
    let mut buf = vec![];
    file.read_to_end(&mut buf).unwrap();
    let key_pair = KeyPair::try_from(buf.as_slice()).unwrap();

    let mut file = File::open("cert_cert.der").unwrap();
    let mut buf = vec![];
    file.read_to_end(&mut buf).unwrap();
    let cert = buf.into();

    (cert, key_pair)
}

struct State {
    cert_ca: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    domain_configs: HashMap<String, Arc<ServerConfig>>,
    client: Arc<reqwest::Client>,
}

impl State {
    pub fn new() -> Self {
        let (cert_ca, issuer) = load_ca();
        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let client = Arc::new(client);

        Self {
            cert_ca,
            issuer,
            domain_configs: Default::default(),
            client,
        }
    }

    pub fn add_cert(&mut self, common_name: String) -> Arc<ServerConfig> {
        let (cert_domain, key_pair) = generate_cert(&self.issuer, &common_name);
        let certs: Vec<CertificateDer<'static>> = vec![cert_domain, self.cert_ca.clone()];
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_pair.into())
            .unwrap();
        let config = Arc::new(config);

        self.domain_configs.insert(common_name, config.clone());
        config
    }

    pub fn get_cert<'a>(&self, common_name: &'a str) -> Option<Arc<ServerConfig>> {
        self.domain_configs.get(common_name).map(|v| v.clone())
    }

    pub fn client(&self) -> Arc<reqwest::Client> {
        self.client.clone()
    }
}

async fn tls_stream<IO>(
    stream: IO,
    state: Arc<Mutex<State>>,
    uri: String,
) -> Result<(), Box<dyn std::error::Error>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    dbg!(&uri);
    let uri = "https://".to_owned() + &uri;
    let url = Url::parse(&uri).unwrap();

    let host = get_url_host(&url).unwrap().to_owned();
    let config = {
        let mut state = state.lock().unwrap();
        match state.get_cert(&host) {
            Some(v) => v,
            None => state.add_cert(host.to_owned()),
        }
    };

    let acceptor = TlsAcceptor::from(config);
    let tls_stream = acceptor.accept(stream).await.unwrap();

    let io = TokioIo::new(tls_stream);
    let host = Arc::new(host);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(|req| tls_server_req(req, state.clone(), host.clone())),
        )
        .await
        .unwrap();

    Ok(())
}

fn get_url_host(url: &Url) -> Result<&str, &'static str> {
    if url.scheme() != "https" {
        return Err("invalid scheme");
    }
    if url.username() != "" {
        return Err("invalid username");
    }
    if url.password() != None {
        return Err("invalid password");
    }
    let host = match url.host() {
        Some(v) => v,
        None => return Err("invalid host"),
    };
    let domain = match host {
        url::Host::Domain(v) => v,
        url::Host::Ipv4(_) => return Err("host IPv4 not allowed"),
        url::Host::Ipv6(_) => return Err("host IPv6 not allowed"),
    };
    if url.port() != None {
        return Err("invalid port");
    }
    if url.path() != "/" {
        return Err("invalid path");
    }
    if url.query() != None {
        return Err("invalid query");
    }
    if url.fragment() != None {
        return Err("invalid fragment");
    }
    if domain == "localhost" {
        return Err("localhost not allowed");
    }
    return Ok(domain);
}

async fn tls_server_req(
    req: Request<hyper::body::Incoming>,
    state: Arc<Mutex<State>>,
    host: Arc<String>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    dbg!(&req, &host);

    let path = req.uri();
    let url = Url::parse(&format!("https://{host}{path}")).unwrap();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = req.collect().await.unwrap().to_bytes();

    let client = {
        let state = state.lock().unwrap();
        state.client()
    };
    let request = client
        .request(method, url)
        .headers(headers)
        .body(body)
        .build()
        .unwrap();

    let res = client.execute(request).await.unwrap();
    dbg!(&res);

    let status = res.status();
    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().unwrap();
    for (header, value) in res.headers() {
        response_headers.insert(header, value.clone());
    }

    let body = res.bytes().await.unwrap();
    let response = response.body(Full::new(body)).unwrap();

    Ok(response)
}

async fn http_proxy_conn_process(
    stream: TcpStream,
    state: Arc<Mutex<State>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let io = TokioIo::new(stream);

    http1::Builder::new()
        .serve_connection(io, service_fn(|req| proxy(req, state.clone())))
        .with_upgrades()
        .await
        .unwrap();

    Ok(())
}

async fn proxy<'a>(
    req: Request<hyper::body::Incoming>,
    state: Arc<Mutex<State>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::CONNECT {
        let mut resp = Response::new(Full::new(Bytes::from("Only HTTPS hosts supported")));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(resp);
    }

    let uri = req.uri().authority().map(|v| v.to_string());
    let uri = match uri {
        Some(v) => v,
        None => {
            let mut resp = Response::new(Full::new(Bytes::from("No URI provided")));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
    };

    tokio::spawn(async move {
        let upgraded = upgrade::on(req).await.unwrap();
        let upgraded = TokioIo::new(upgraded);
        tls_stream(upgraded, state, uri).await.unwrap();
    });

    Ok(Response::new(empty()))
}

fn empty() -> Full<Bytes> {
    Full::new(Bytes::new())
}

#[derive(Clone)]
pub struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .finish()
        .init();

    let state = Arc::new(Mutex::new(State::new()));

    let port = 4443;
    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        let state = state.clone();
        tokio::spawn(async {
            http_proxy_conn_process(stream, state).await.unwrap();
        });
    }
}
