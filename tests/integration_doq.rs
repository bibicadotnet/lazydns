#![cfg(all(feature = "doq", not(target_family = "wasm")))]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

#[tokio::test]
async fn integration_doq_request_response() {
    // Install process-level CryptoProvider for rustls v0.23
    let _ = rustls::crypto::ring::default_provider().install_default();

    use async_trait::async_trait;
    use rcgen::generate_simple_self_signed;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use lazydns::server::{DoqServer, RequestHandler};

    struct TestHandler;
    #[async_trait]
    impl RequestHandler for TestHandler {
        async fn handle(
            &self,
            mut request: lazydns::dns::Message,
        ) -> lazydns::Result<lazydns::dns::Message> {
            request.set_response(true);
            Ok(request)
        }
    }

    // Generate certificate and key PEM files
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    let cert_path = cert_file.path().to_path_buf();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();
    let key_path = key_file.path().to_path_buf();

    // Reserve an ephemeral UDP port for QUIC by binding a socket and taking its port
    let udp_socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let local_addr = udp_socket.local_addr().unwrap();
    drop(udp_socket);

    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), local_addr.port());
    let addr_str = format!("{}:{}", addr.ip(), addr.port());

    let handler = Arc::new(TestHandler);
    let server = DoqServer::new(
        addr_str.clone(),
        cert_path.to_string_lossy(),
        key_path.to_string_lossy(),
        handler,
    );

    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Allow server to start
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // Build a rustls client config that disables verification for test (accept any cert)
    use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, SignatureScheme};

    #[derive(Debug)]
    struct NoCertVerifier;
    impl ServerCertVerifier for NoCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        }
    }

    let client_rustls: ClientConfig = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    // Convert rustls client config into quinn QuicClientConfig
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_rustls))
        .expect("convert quic client crypto");
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

    // Create client endpoint and connect
    let endpoint =
        quinn::Endpoint::client(([0, 0, 0, 0], 0).into()).expect("create client endpoint");

    let connecting = endpoint
        .connect_with(client_cfg, addr, "localhost")
        .expect("connect_with");
    let connection = connecting.await.expect("connect await");

    // Open bi-directional stream and send a DNS query
    let (mut send, mut recv) = connection.open_bi().await.expect("open_bi");

    let mut req_msg = lazydns::dns::Message::new();
    req_msg.set_id(0xCAFE);
    req_msg.set_query(true);
    let data = lazydns::dns::wire::serialize_message(&req_msg).unwrap();
    let mut framed = Vec::with_capacity(2 + data.len());
    framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
    framed.extend_from_slice(&data);

    send.write_all(&framed).await.expect("send write");
    send.finish().expect("send finish");

    // Read response length
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await.expect("recv len");
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    recv.read_exact(&mut resp_buf).await.expect("recv body");

    let parsed = lazydns::dns::wire::parse_message(&resp_buf).expect("parse response");
    assert!(parsed.is_response());
    assert_eq!(parsed.id(), 0xCAFE);

    // Clean up
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    server_task.abort();
}

#[tokio::test]
async fn integration_doq_server_start_stop() {
    // Ensure rustls has a process-level CryptoProvider installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    use async_trait::async_trait;
    use lazydns::server::DoqServer;
    use lazydns::server::RequestHandler;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    struct TestHandler;
    #[async_trait]
    impl RequestHandler for TestHandler {
        async fn handle(
            &self,
            mut request: lazydns::dns::Message,
        ) -> lazydns::Result<lazydns::dns::Message> {
            request.set_response(true);
            Ok(request)
        }
    }

    // Generate self-signed cert and key using rcgen and write PEM files
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    let cert_path = cert_file.path().to_path_buf();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();
    let key_path = key_file.path().to_path_buf();

    let addr = "127.0.0.1:0".to_string();
    let handler = Arc::new(TestHandler);
    let server = DoqServer::new(
        addr.clone(),
        cert_path.to_string_lossy(),
        key_path.to_string_lossy(),
        handler,
    );

    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    server_task.abort();
}
