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
    use crate::dns::wire;
    use crate::dns::{Question, RecordClass, RecordType};
    use crate::server::DefaultHandler;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_tcp_server_creation() {
        let config = ServerConfig::default().with_tcp_addr("127.0.0.1:0".parse().unwrap());
        let handler = Arc::new(DefaultHandler);

        let server = TcpServer::new(config, handler).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_parse_request_and_serialize_response() {
        // Build a real DNS query message and serialize it, then parse via parse_request
        let mut req = Message::new();
        req.set_id(0x42);
        req.set_query(true);
        req.add_question(Question::new(
            "example.test".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let data = wire::serialize_message(&req).expect("serialize request");
        let parsed = TcpServer::parse_request(&data).expect("parse request");
        assert_eq!(parsed.id(), 0x42);
        assert_eq!(parsed.question_count(), 1);

        // Turn parsed message into a response and serialize via serialize_response
        let mut resp = parsed.clone();
        resp.set_response(true);
        let resp_data = TcpServer::serialize_response(&resp).expect("serialize response");
        assert!(resp_data.len() >= 12);
    }

    #[tokio::test]
    async fn test_handle_connection_roundtrip() {
        // Create a listener and accept one connection to exercise handle_connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a server-side task that accepts one connection and runs handle_connection
        let server_task = tokio::spawn(async move {
            if let Ok((stream, _peer)) = listener.accept().await {
                let handler = Arc::new(DefaultHandler);
                // allow reasonably large messages
                let _ = TcpServer::handle_connection(stream, handler, 64 * 1024).await;
            }
        });

        // Create a client connection and send a request
        let mut client = TcpStream::connect(addr).await.unwrap();

        let mut req = Message::new();
        req.set_id(0x99);
        req.set_query(true);
        req.add_question(Question::new(
            "roundtrip.test".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let req_data = wire::serialize_message(&req).expect("serialize client request");
        let len = req_data.len() as u16;
        client
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| eprintln!("write len: {}", e))
            .ok();
        client
            .write_all(&req_data)
            .await
            .map_err(|e| eprintln!("write data: {}", e))
            .ok();

        // Read response length
        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();

        // Parse response and validate it was converted to a response by DefaultHandler
        let response = wire::parse_message(&resp_buf).expect("parse response");
        assert!(response.is_response());
        assert_eq!(response.id(), 0x99);

        let _ = server_task.await;
    }
}
