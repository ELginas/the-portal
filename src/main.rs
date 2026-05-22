use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Write};
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, Stream};
use time::{Duration, OffsetDateTime};

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

fn main() {
    // let (cert_ca, issuer) = generate_ca();
    // save_ca(&cert_ca, &issuer);
    let (cert_ca, issuer) = load_ca();

    let (cert_domain, key_pair) = generate_cert(&issuer, "discordo.com");
    save_cert(&cert_domain, &key_pair);

    // let (cert_domain, key_pair) = load_cert();

    let certs: Vec<CertificateDer<'static>> = vec![cert_domain, cert_ca];
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_pair.into())
        .unwrap();
    let config = Arc::new(config);

    let port = 4443;
    let listener = TcpListener::bind(format!("[::]:{}", port)).unwrap();

    loop {
        let l = || -> Result<(), Box<dyn std::error::Error>> {
            let (mut tcp_stream, _) = listener.accept()?;
            let mut conn = ServerConnection::new(config.clone())?;
            let mut tls_stream = Stream::new(&mut conn, &mut tcp_stream);

            tls_stream.write_all(b"Hello from the server")?;
            tls_stream.flush()?;
            let mut buf = [0; 64];
            let len = tls_stream.read(&mut buf)?;
            println!("Received message from client: {:?}", &buf[..len]);
            Ok(())
        };

        match l() {
            Ok(v) => (),
            Err(e) => eprintln!("Error: {e}"),
        }
    }
}
