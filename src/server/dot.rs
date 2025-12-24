//! DNS over TLS (DoT) server implementation
//!
//! Implements RFC 7858 - DNS over TLS.
//!
//! This module provides a straightforward in-process DoT server that:
//! - Performs TLS handshakes using `tokio-rustls` (`TlsAcceptor`).
//! - Reads DNS-over-TCP framed messages (2-byte length prefix) from the
//!   negotiated TLS stream, parses them using `hickory-proto`, and dispatches
//!   them to a `RequestHandler` implementation.
//! - Serializes handler responses back to wire format and writes them to the
//!   TLS stream using the TCP framing (2-byte length prefix).
//!
//! The implementation favors clarity and testability for use in the test-suite
//! and simple deployments. For high-throughput production usage, consider
//! additional connection and buffer management, timeouts, and connection
//! limits.

use crate::error::{Error, Result};
use crate::server::{RequestHandler, TlsConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// DNS over TLS server
///
/// Listens for encrypted DNS queries over TLS (port 853 by default).
pub struct DotServer {
    /// Server listening address
    addr: String,
    /// TLS configuration
    tls_config: TlsConfig,
    /// Request handler
    handler: Arc<dyn RequestHandler>,
}

impl DotServer {
    /// Create a new DoT server
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to listen on (e.g., "0.0.0.0:853")
    /// * `tls_config` - TLS configuration with certificates
    /// * `handler` - Request handler for processing DNS queries
    ///
    /// # Example
    ///
    /// ```no_run
    /// use lazydns::server::{DotServer, TlsConfig, DefaultHandler};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tls = TlsConfig::from_files("cert.pem", "key.pem")?;
    /// let handler = Arc::new(DefaultHandler);
    /// let server = DotServer::new("0.0.0.0:853", tls, handler);
    /// // server.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        addr: impl Into<String>,
        tls_config: TlsConfig,
        handler: Arc<dyn RequestHandler>,
    ) -> Self {
        Self {
            addr: addr.into(),
            tls_config,
            handler,
        }
    }

    /// Start the DoT server
    ///
    /// Listens for TLS connections and processes DNS queries.
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await.map_err(Error::Io)?;

        info!("DoT server listening on {}", self.addr);

        let tls_config = self.tls_config.build_server_config()?;
        let acceptor = TlsAcceptor::from(tls_config);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            debug!("DoT connection from {}", peer_addr);

            let acceptor = acceptor.clone();
            let handler = Arc::clone(&self.handler);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, acceptor, handler).await {
                    error!("Error handling DoT connection from {}: {}", peer_addr, e);
                }
            });
        }
    }

    /// Handle a single TLS connection
    async fn handle_connection(
        stream: TcpStream,
        acceptor: TlsAcceptor,
        handler: Arc<dyn RequestHandler>,
    ) -> Result<()> {
        // Perform TLS handshake
        let mut tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::Other(format!("TLS handshake failed: {}", e)))?;

        // Process DNS queries over this TLS connection
        loop {
            // Read message length (2 bytes, big-endian) - same as TCP DNS
            let mut len_buf = [0u8; 2];
            match tls_stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client closed connection
                    debug!("DoT client closed connection");
                    break;
                }
                Err(e) => {
                    return Err(Error::Io(e));
                }
            }

            let msg_len = u16::from_be_bytes(len_buf) as usize;

            // Validate message length
            if msg_len == 0 || msg_len > 65535 {
                warn!("Invalid DoT message length: {}", msg_len);
                break;
            }

            // Read message data
            let mut buf = vec![0u8; msg_len];
            tls_stream.read_exact(&mut buf).await.map_err(Error::Io)?;

            // Parse request from wire-format bytes
            let request = Self::parse_request(&buf)?;

            // Handle request
            let response = handler.handle(request).await?;

            // Serialize response to wire-format bytes
            let response_data = Self::serialize_response(&response)?;

            // Write response length
            let response_len = response_data.len() as u16;
            tls_stream
                .write_all(&response_len.to_be_bytes())
                .await
                .map_err(Error::Io)?;

            // Write response data
            tls_stream
                .write_all(&response_data)
                .await
                .map_err(Error::Io)?;

            tls_stream.flush().await.map_err(Error::Io)?;
        }

        Ok(())
    }

    /// Parse DNS request from wire format
    ///
    /// Parses binary DNS wire format according to RFC 1035 using hickory-proto.
    fn parse_request(data: &[u8]) -> Result<crate::dns::Message> {
        crate::dns::wire::parse_message(data)
    }

    /// Serialize DNS response to wire format
    ///
    /// Serializes to binary DNS wire format according to RFC 1035 using hickory-proto.
    fn serialize_response(message: &crate::dns::Message) -> Result<Vec<u8>> {
        crate::dns::wire::serialize_message(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let data = vec![0u8; 12]; // Minimal DNS header
        let result = DotServer::parse_request(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_response() {
        let message = crate::dns::Message::new();
        let result = DotServer::serialize_response(&message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 12);
    }

    #[tokio::test]
    async fn test_parse_request_invalid() {
        // empty data should fail parsing
        let data: Vec<u8> = vec![];
        let result = DotServer::parse_request(&data);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_run_invalid_bind_address() {
        use rcgen::generate_simple_self_signed;
        use std::io::Write;
        use tempfile::NamedTempFile;

        // generate self-signed cert and key files
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        let cert_path = cert_file.path().to_path_buf();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();
        let key_path = key_file.path().to_path_buf();

        let tls = crate::server::TlsConfig::from_files(cert_path, key_path).unwrap();

        struct DummyHandler;
        #[async_trait::async_trait]
        impl crate::server::RequestHandler for DummyHandler {
            async fn handle(&self, req: crate::dns::Message) -> crate::Result<crate::dns::Message> {
                Ok(req)
            }
        }

        // Invalid bind address should return an Io error when attempting to bind
        let server = DotServer::new("not-a-valid-addr", tls, Arc::new(DummyHandler));
        let res = server.run().await;
        assert!(res.is_err());
        match res.unwrap_err() {
            Error::Io(_) => {}
            other => panic!("expected Io error, got: {:?}", other),
        }
    }

    // Integration tests moved to tests/integration_tls_doh_dot.rs
}
