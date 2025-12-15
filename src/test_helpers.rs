//! Test helpers for DoH HTTP/HTTPS servers used in unit tests.
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Spawn a minimal HTTP DoH server that responds with a single A record.
/// Returns the URL to use and the server JoinHandle.
pub async fn spawn_doh_http_server(response_ip: &str) -> (String, JoinHandle<()>) {
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{RData, ResourceRecord};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let ip = response_ip.to_string();

    let handle = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);

            let parts: Vec<&str> = req.split("\r\n\r\n").collect();
            if parts.len() < 2 {
                return;
            }
            let headers = parts[0];
            let mut body = parts[1].as_bytes().to_vec();

            // Content-Length handling
            let mut content_length = 0usize;
            for line in headers.lines() {
                if line.to_lowercase().starts_with("content-length:") {
                    if let Some(v) = line.split(':').nth(1) {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
            }

            while body.len() < content_length {
                let mut more = vec![0u8; 1024];
                let m = socket.read(&mut more).await.unwrap_or(0);
                if m == 0 {
                    break;
                }
                body.extend_from_slice(&more[..m]);
            }

            if let Ok(req_msg) =
                crate::dns::wire::parse_message(&body[..content_length.min(body.len())])
            {
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

                if let Ok(data) = crate::dns::wire::serialize_message(&resp) {
                    let resp_hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                        data.len()
                    );
                    let _ = socket.write_all(resp_hdr.as_bytes()).await;
                    let _ = socket.write_all(&data).await;
                }
            }
        }
    });

    let url = format!("http://127.0.0.1:{}/dns-query", local_addr.port());
    (url, handle)
}

/// Spawn a minimal HTTPS DoH server using a self-signed certificate.
/// Returns the HTTPS URL and server JoinHandle.
pub async fn spawn_doh_https_server(response_ip: &str) -> (String, JoinHandle<()>) {
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{RData, ResourceRecord};
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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let ip = response_ip.to_string();

    let handle = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            if let Ok(mut tls_stream) = acceptor.accept(socket).await {
                let mut buf = vec![0u8; 8192];
                let n = tls_stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                let parts: Vec<&str> = req.split("\r\n\r\n").collect();
                if parts.len() < 2 {
                    return;
                }
                let headers = parts[0];
                let mut body = parts[1].as_bytes().to_vec();

                let mut content_length = 0usize;
                for line in headers.lines() {
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(v) = line.split(':').nth(1) {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }
                }

                while body.len() < content_length {
                    let mut more = vec![0u8; 1024];
                    let m = tls_stream.read(&mut more).await.unwrap_or(0);
                    if m == 0 {
                        break;
                    }
                    body.extend_from_slice(&more[..m]);
                }

                if let Ok(req_msg) =
                    crate::dns::wire::parse_message(&body[..content_length.min(body.len())])
                {
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

                    if let Ok(data) = crate::dns::wire::serialize_message(&resp) {
                        let resp_hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            data.len()
                        );
                        let _ = tls_stream.write_all(resp_hdr.as_bytes()).await;
                        let _ = tls_stream.write_all(&data).await;
                    }
                }
            }
        }
    });

    let url = format!("https://localhost:{}/dns-query", local_addr.port());
    (url, handle)
}
