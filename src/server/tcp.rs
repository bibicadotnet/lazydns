//! TCP DNS server implementation
//!
//! Provides a DNS server that listens on TCP for larger responses.

use crate::dns::Message;
use crate::server::{RequestHandler, ServerConfig};
use crate::{Error, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// TCP DNS server
///
/// Handles DNS queries over TCP protocol. TCP is used when responses
/// are too large for UDP (>512 bytes) or when reliable delivery is required.
///
/// # Example
///
/// ```rust,no_run
/// use lazydns::server::{TcpServer, ServerConfig, DefaultHandler};
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ServerConfig::default();
/// let handler = Arc::new(DefaultHandler::default());
/// let server = TcpServer::new(config, handler).await?;
/// server.run().await?;
/// # Ok(())
/// # }
/// ```
pub struct TcpServer {
    listener: TcpListener,
    handler: Arc<dyn RequestHandler>,
    config: ServerConfig,
}

impl TcpServer {
    /// Create a new TCP server
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `handler` - Request handler for processing queries
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot be bound to the configured address.
    pub async fn new(config: ServerConfig, handler: Arc<dyn RequestHandler>) -> Result<Self> {
        let addr = config
            .tcp_addr
            .ok_or_else(|| Error::Config("TCP address not configured".to_string()))?;

        let listener = TcpListener::bind(addr).await.map_err(Error::Io)?;

        info!("TCP server listening on {}", addr);

        Ok(Self {
            listener,
            handler,
            config,
        })
    }

    /// Run the TCP server
    ///
    /// This method runs the server loop, accepting connections and handling queries.
    /// It will run indefinitely until an error occurs or the task is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a network or processing error.
    pub async fn run(&self) -> Result<()> {
        info!("TCP server started");

        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("Accepted connection from {}", peer_addr);

                    let handler = Arc::clone(&self.handler);
                    let max_size = self.config.max_tcp_size;

                    // Spawn a task to handle this connection
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, handler, max_size).await {
                            error!("Error handling connection from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting TCP connection: {}", e);
                    // Continue serving despite errors
                }
            }
        }
    }

    /// Handle a single TCP connection
    ///
    /// TCP DNS messages are prefixed with a 2-byte length field.
    async fn handle_connection(
        mut stream: TcpStream,
        handler: Arc<dyn RequestHandler>,
        max_size: usize,
    ) -> Result<()> {
        // Read message length (2 bytes, big-endian)
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.map_err(Error::Io)?;

        let msg_len = u16::from_be_bytes(len_buf) as usize;

        if msg_len > max_size {
            return Err(Error::DnsProtocol(format!(
                "Message too large: {} > {}",
                msg_len, max_size
            )));
        }

        debug!("Reading {} bytes", msg_len);

        // Read message data
        let mut buf = vec![0u8; msg_len];
        stream.read_exact(&mut buf).await.map_err(Error::Io)?;

        // Parse request
        let request = Self::parse_request(&buf)?;

        debug!(
            "Processing query ID {} with {} questions",
            request.id(),
            request.question_count()
        );

        // Handle the request
        let response = handler.handle(request).await?;

        debug!(
            "Sending response ID {} with {} answers",
            response.id(),
            response.answer_count()
        );

        // Serialize response
        let response_data = Self::serialize_response(&response)?;

        // Write length prefix
        let len = response_data.len() as u16;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(Error::Io)?;

        // Write response data
        stream.write_all(&response_data).await.map_err(Error::Io)?;

        stream.flush().await.map_err(Error::Io)?;

        Ok(())
    }

    /// Parse DNS request from wire format
    ///
    /// Parses binary DNS wire format according to RFC 1035 using hickory-proto.
    fn parse_request(data: &[u8]) -> Result<Message> {
        crate::dns::wire::parse_message(data)
    }

    /// Serialize DNS response to wire format
    ///
    /// Serializes to binary DNS wire format according to RFC 1035 using hickory-proto.
    fn serialize_response(message: &Message) -> Result<Vec<u8>> {
        crate::dns::wire::serialize_message(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::DefaultHandler;

    #[tokio::test]
    async fn test_tcp_server_creation() {
        let config = ServerConfig::default().with_tcp_addr("127.0.0.1:0".parse().unwrap());
        let handler = Arc::new(DefaultHandler);

        let server = TcpServer::new(config, handler).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_parse_request_placeholder() {
        let data = vec![0u8; 12];
        let message = TcpServer::parse_request(&data);
        assert!(message.is_ok());
    }

    #[tokio::test]
    async fn test_serialize_response_placeholder() {
        let message = Message::new();
        let data = TcpServer::serialize_response(&message);
        assert!(data.is_ok());
        assert_eq!(data.unwrap().len(), 12); // DNS header size
    }
}
