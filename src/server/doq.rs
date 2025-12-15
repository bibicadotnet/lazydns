//! DNS over QUIC (DoQ) server implementation using `quinn`.
//!
//! Each QUIC connection accepts bi-directional streams; each stream carries
//! a single DNS query/response using the same 2-byte length-prefixed wire
//! format as TCP.

use crate::server::RequestHandler;
use crate::Result;
use quinn::{Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info};

/// DNS over QUIC server
pub struct DoqServer {
    addr: String,
    cert_path: String,
    key_path: String,
    handler: Arc<dyn RequestHandler>,
}

impl DoqServer {
    pub fn new(
        addr: impl Into<String>,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
        handler: Arc<dyn RequestHandler>,
    ) -> Self {
        Self {
            addr: addr.into(),
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            handler,
        }
    }

    /// Run the DoQ server listening on the configured address.
    pub async fn run(self) -> Result<()> {
        info!(addr = %self.addr, "Starting DoQ server");

        // Build QUIC server config from TLS certificates
        let server_config = build_quic_server_config(&self.cert_path, &self.key_path)?;

        let addr: SocketAddr = self
            .addr
            .parse()
            .map_err(|e| crate::Error::Config(format!("Invalid DoQ bind address: {}", e)))?;

        let endpoint = Endpoint::server(server_config, addr)?;
        info!(local = %endpoint.local_addr().unwrap_or_else(|_| "unknown".parse().unwrap()), "DoQ listening");

        // Accept incoming QUIC connections
        while let Some(incoming) = endpoint.accept().await {
            let handler = Arc::clone(&self.handler);

            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        info!(remote = %connection.remote_address(), "Accepted QUIC connection");
                        // Per-connection: accept bi-directional streams
                        loop {
                            match connection.accept_bi().await {
                                Ok((send, recv)) => {
                                    let handler = Arc::clone(&handler);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_stream(recv, send, handler).await {
                                            debug!("DoQ stream error: {}", e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    debug!("Connection stream accept error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept incoming QUIC connection: {}", e);
                    }
                }
            });
        }

        Ok(())
    }
}

/// Handle a single bi-directional stream carrying a DNS query/response.
async fn handle_stream(
    mut recv: quinn::RecvStream,
    mut send: quinn::SendStream,
    handler: Arc<dyn RequestHandler>,
) -> Result<()> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| crate::Error::Io(std::io::Error::other(e)))?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    // Read DNS message
    let mut buf = vec![0u8; msg_len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| crate::Error::Io(std::io::Error::other(e)))?;

    // Parse DNS message and handle
    let request = crate::dns::wire::parse_message(&buf)?;
    let response = handler.handle(request).await?;
    let resp_data = crate::dns::wire::serialize_message(&response)?;

    // Write response with length prefix
    send.write_all(&(resp_data.len() as u16).to_be_bytes())
        .await
        .map_err(|e| crate::Error::Io(std::io::Error::other(e)))?;
    send.write_all(&resp_data)
        .await
        .map_err(|e| crate::Error::Io(std::io::Error::other(e)))?;

    // Finish the stream
    send.finish()
        .map_err(|e| crate::Error::Io(std::io::Error::other(e)))?;

    Ok(())
}

/// Build a QUIC server config from PEM-encoded TLS certificate and key files.
fn build_quic_server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs;

    let cert_bytes = fs::read(cert_path)
        .map_err(|e| crate::Error::Config(format!("Failed to read cert: {}", e)))?;
    let key_bytes = fs::read(key_path)
        .map_err(|e| crate::Error::Config(format!("Failed to read key: {}", e)))?;

    // Parse certificates from PEM: certs() returns an iterator that yields Result<CertificateDer, io::Error>
    let certs_result: std::result::Result<Vec<CertificateDer>, _> =
        rustls_pemfile::certs(&mut &cert_bytes[..]).collect();
    let certs = certs_result
        .map_err(|e| crate::Error::Config(format!("Failed to parse cert PEM: {}", e)))?;
    if certs.is_empty() {
        return Err(crate::Error::Config(
            "No certificates found in cert file".to_string(),
        ));
    }

    // Parse private key from PEM using read_one
    let mut key_reader = &key_bytes[..];
    let key = rustls_pemfile::read_one(&mut key_reader)
        .map_err(|e| crate::Error::Config(format!("Failed to parse key PEM: {}", e)))?
        .ok_or_else(|| crate::Error::Config("No private key found in key file".to_string()))?;

    let key_der = match key {
        rustls_pemfile::Item::Pkcs8Key(k) => PrivateKeyDer::Pkcs8(k),
        rustls_pemfile::Item::Sec1Key(k) => PrivateKeyDer::Sec1(k),
        rustls_pemfile::Item::Pkcs1Key(k) => PrivateKeyDer::Pkcs1(k),
        _ => {
            return Err(crate::Error::Config(
                "Unsupported private key type".to_string(),
            ))
        }
    };

    // Build rustls ServerConfig
    let rustls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| crate::Error::Config(format!("Failed to build rustls config: {}", e)))?;

    // Convert to quinn QuicServerConfig
    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg).map_err(|e| {
            crate::Error::Config(format!("Failed to convert rustls -> quinn crypto: {}", e))
        })?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

    Ok(server_config)
}

#[cfg(all(test, feature = "doq"))]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_build_quic_server_config_from_pem() {
        // Ensure a CryptoProvider is installed for rustls v0.23
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.serialize_pem().unwrap();
        let key_pem = cert.get_key_pair().serialize_pem();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();
        let key_path = key_file.path().to_str().unwrap().to_string();

        let cfg = build_quic_server_config(&cert_path, &key_path).expect("build quic cfg");
        // Basic sanity: ensure conversion succeeded (cfg constructed)
        let _ = cfg;
    }
}
