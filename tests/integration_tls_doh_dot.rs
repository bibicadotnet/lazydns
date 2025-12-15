#![cfg(feature = "tls")]

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn integration_doh_tls_post() {
    use async_trait::async_trait;
    use lazydns::server::RequestHandler;
    use lazydns::server::{DohServer, TlsConfig};
    use std::io::Write;
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
    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.get_key_pair().serialize_pem();

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    let cert_path = cert_file.path().to_path_buf();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();
    let key_path = key_file.path().to_path_buf();

    let tls = TlsConfig::from_files(cert_path, key_path).unwrap();

    // Ensure rustls has a process-level CryptoProvider installed (ring by default).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Reserve an ephemeral port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let addr = format!("127.0.0.1:{}", port);
    let handler = Arc::new(TestHandler);
    let server = DohServer::new(addr.clone(), tls, handler);

    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // give server a moment
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut req_msg = lazydns::dns::Message::new();
    req_msg.set_id(0xBEEF);
    req_msg.set_query(true);
    let data = lazydns::dns::wire::serialize_message(&req_msg).unwrap();

    let url = format!("https://{}/dns-query", addr);

    let resp = client
        .post(&url)
        .header("Content-Type", "application/dns-message")
        .body(data.clone())
        .send()
        .await
        .expect("request failed");

    assert!(resp.status().is_success());
    let bytes = resp.bytes().await.expect("read body");
    let parsed = lazydns::dns::wire::parse_message(&bytes).unwrap();
    assert!(parsed.is_response());
    assert_eq!(parsed.id(), 0xBEEF);

    server_task.abort();
}

// Minimal single-accept DoT TLS server helper used only by these integration tests.
async fn spawn_dot_single_accept(
    response_ip: &str,
) -> (std::net::SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>) {
    use lazydns::dns::types::{RecordClass, RecordType};
    use lazydns::dns::{RData, ResourceRecord};
    use rcgen::generate_simple_self_signed;
    use rustls_20::{Certificate, PrivateKey, ServerConfig};
    use std::sync::Arc;
    use tokio_rustls_23::TlsAcceptor;

    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.get_key_pair().serialize_der();

    let certs = vec![Certificate(cert_der.clone())];
    let priv_key = PrivateKey(key_der.clone());
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, priv_key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let ip = response_ip.to_string();

    let handle = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            if let Ok(mut tls_stream) = acceptor.accept(socket).await {
                // Read 2-byte length prefix
                let mut len_buf = [0u8; 2];
                let n = tls_stream.read(&mut len_buf).await.unwrap_or(0);
                if n < 2 {
                    return;
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; msg_len];
                let _ = tls_stream.read_exact(&mut buf).await;

                if let Ok(req_msg) = lazydns::dns::wire::parse_message(&buf) {
                    let mut resp = req_msg.clone();
                    resp.set_response(true);
                    resp.add_answer(ResourceRecord::new(
                        req_msg.questions()[0].qname().to_string(),
                        RecordType::A,
                        RecordClass::IN,
                        60,
                        RData::A(ip.parse().unwrap()),
                    ));
                    resp.set_id(req_msg.id());

                    if let Ok(data) = lazydns::dns::wire::serialize_message(&resp) {
                        let response_len = (data.len() as u16).to_be_bytes();
                        let _ = tls_stream.write_all(&response_len).await;
                        let _ = tls_stream.write_all(&data).await;
                    }
                }
            }
        }
    });

    (local_addr, cert_der, handle)
}

#[tokio::test]
async fn integration_dot_tls_exchange() {
    use tokio_rustls_23::rustls::{
        client::ServerName as ServerName23, Certificate as RCert, RootCertStore,
    };

    let (addr, cert_der, server_handle) = spawn_dot_single_accept("127.0.0.1").await;

    let mut root_store = RootCertStore::empty();
    root_store.add(&RCert(cert_der.clone())).unwrap();

    let client_cfg = tokio_rustls_23::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls_23::TlsConnector::from(Arc::new(client_cfg));

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName23::try_from("localhost").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    let mut req = lazydns::dns::Message::new();
    req.set_id(0x4321);
    req.set_query(true);
    req.add_question(lazydns::dns::Question::new(
        "localhost".to_string(),
        lazydns::dns::RecordType::A,
        lazydns::dns::RecordClass::IN,
    ));

    let data = lazydns::dns::wire::serialize_message(&req).unwrap();
    let mut framed = Vec::with_capacity(2 + data.len());
    framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
    framed.extend_from_slice(&data);

    tls_stream.write_all(&framed).await.unwrap();

    let mut len_buf = [0u8; 2];
    tls_stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    tls_stream.read_exact(&mut resp_buf).await.unwrap();

    let parsed = lazydns::dns::wire::parse_message(&resp_buf).unwrap();
    assert!(parsed.is_response());
    assert_eq!(parsed.id(), 0x4321);

    let _ = server_handle.await;
}

#[tokio::test]
async fn integration_dot_concurrent_clients() {
    use tokio::time::{sleep, Duration};
    use tokio_rustls_23::rustls::{
        client::ServerName as ServerName23, Certificate as RCert, RootCertStore,
    };

    async fn connect_tcp_retry(addr: std::net::SocketAddr) -> tokio::net::TcpStream {
        for _ in 0..20u8 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(s) => return s,
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        }
        panic!("failed to connect to {}", addr);
    }

    let mut client_handles = Vec::new();
    let mut server_handles = Vec::new();

    for i in 0..8u16 {
        let (addr, cert_der, server_handle) = spawn_dot_single_accept("127.0.0.1").await;
        server_handles.push(server_handle);

        let handle = tokio::spawn(async move {
            let mut root_store = RootCertStore::empty();
            root_store.add(&RCert(cert_der)).unwrap();

            let client_cfg = tokio_rustls_23::rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let connector = tokio_rustls_23::TlsConnector::from(std::sync::Arc::new(client_cfg));

            let stream = connect_tcp_retry(addr).await;
            let server_name = ServerName23::try_from("localhost").unwrap();
            let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

            let mut req = lazydns::dns::Message::new();
            req.set_id(i);
            req.set_query(true);
            req.add_question(lazydns::dns::Question::new(
                "localhost".to_string(),
                lazydns::dns::RecordType::A,
                lazydns::dns::RecordClass::IN,
            ));

            let data = lazydns::dns::wire::serialize_message(&req).unwrap();
            let mut framed = Vec::with_capacity(2 + data.len());
            framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
            framed.extend_from_slice(&data);

            tls_stream.write_all(&framed).await.unwrap();

            let mut len_buf = [0u8; 2];
            tls_stream.read_exact(&mut len_buf).await.unwrap();
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            tls_stream.read_exact(&mut resp_buf).await.unwrap();

            let parsed = lazydns::dns::wire::parse_message(&resp_buf).unwrap();
            assert!(parsed.is_response());
            assert_eq!(parsed.id(), i);
        });

        client_handles.push(handle);
    }

    for h in client_handles {
        h.await.unwrap();
    }
    for sh in server_handles {
        let _ = sh.await;
    }
}

#[tokio::test]
async fn integration_dot_malformed_frames() {
    use tokio::time::{sleep, Duration};
    use tokio_rustls_23::rustls::{
        client::ServerName as ServerName23, Certificate as RCert, RootCertStore,
    };

    async fn connect_tcp_retry(addr: std::net::SocketAddr) -> tokio::net::TcpStream {
        for _ in 0..20u8 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(s) => return s,
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        }
        panic!("failed to connect to {}", addr);
    }

    // Case 1: zero-length frame
    {
        let (addr, cert_der, server_handle) = spawn_dot_single_accept("127.0.0.1").await;
        let mut root_store = RootCertStore::empty();
        root_store.add(&RCert(cert_der.clone())).unwrap();
        let client_cfg = tokio_rustls_23::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls_23::TlsConnector::from(std::sync::Arc::new(client_cfg));
        let stream = connect_tcp_retry(addr).await;
        let server_name = ServerName23::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        tls_stream.write_all(&[0u8, 0u8]).await.unwrap();
        let mut len_buf = [0u8; 2];
        let res = tls_stream.read_exact(&mut len_buf).await;
        assert!(res.is_err());
        let _ = server_handle.await;
    }

    // Case 2: truncated payload
    {
        let (addr, cert_der, server_handle) = spawn_dot_single_accept("127.0.0.1").await;
        let mut root_store = RootCertStore::empty();
        root_store.add(&RCert(cert_der.clone())).unwrap();
        let client_cfg = tokio_rustls_23::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls_23::TlsConnector::from(std::sync::Arc::new(client_cfg));
        let stream = connect_tcp_retry(addr).await;
        let server_name = ServerName23::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        tls_stream.write_all(&10u16.to_be_bytes()).await.unwrap();
        tls_stream.write_all(&[1u8, 2u8, 3u8, 4u8]).await.unwrap();
        let _ = tls_stream.shutdown().await;
        let mut len_buf = [0u8; 2];
        let res = tls_stream.read_exact(&mut len_buf).await;
        assert!(res.is_err());
        let _ = server_handle.await;
    }

    // Case 3: no length prefix
    {
        let (addr, cert_der, server_handle) = spawn_dot_single_accept("127.0.0.1").await;
        let mut root_store = RootCertStore::empty();
        root_store.add(&RCert(cert_der.clone())).unwrap();
        let client_cfg = tokio_rustls_23::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls_23::TlsConnector::from(std::sync::Arc::new(client_cfg));
        let stream = connect_tcp_retry(addr).await;
        let server_name = ServerName23::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        let raw = vec![0u8; 12];
        tls_stream.write_all(&raw).await.unwrap();
        let _ = tls_stream.shutdown().await;
        let mut len_buf = [0u8; 2];
        let res = tls_stream.read_exact(&mut len_buf).await;
        assert!(res.is_err());
        let _ = server_handle.await;
    }
}

#[tokio::test]
async fn integration_dot_timeout_behavior() {
    use tokio::time::{timeout, Duration};
    use tokio_rustls_23::rustls::{
        client::ServerName as ServerName23, Certificate as RCert, RootCertStore,
    };

    let (addr, cert_der, _server_handle) = spawn_dot_single_accept("127.0.0.1").await;
    let mut root_store = RootCertStore::empty();
    root_store.add(&RCert(cert_der)).unwrap();
    let client_cfg = tokio_rustls_23::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls_23::TlsConnector::from(std::sync::Arc::new(client_cfg));

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName23::try_from("localhost").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    let mut len_buf = [0u8; 2];
    let res = timeout(
        Duration::from_millis(200),
        tls_stream.read_exact(&mut len_buf),
    )
    .await;
    assert!(res.is_err());
}
