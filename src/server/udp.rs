//! UDP DNS server implementation
//!
//! Provides a DNS server that listens on UDP (standard DNS protocol).

use crate::dns::Message;
use crate::server::{RequestHandler, ServerConfig};
use crate::{Error, Result};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info};

/// UDP DNS server
///
/// Handles DNS queries over UDP protocol. This is the most common
/// DNS transport protocol for standard queries.
///
/// # Example
///
/// ```rust,no_run
/// use lazydns::server::{UdpServer, ServerConfig, DefaultHandler};
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ServerConfig::default();
/// let handler = Arc::new(DefaultHandler::default());
/// let server = UdpServer::new(config, handler).await?;
/// server.run().await?;
/// # Ok(())
/// # }
/// ```
pub struct UdpServer {
    socket: Arc<UdpSocket>,
    handler: Arc<dyn RequestHandler>,
    config: ServerConfig,
}

impl UdpServer {
    /// Create a new UDP server
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `handler` - Request handler for processing queries
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound to the configured address.
    pub async fn new(config: ServerConfig, handler: Arc<dyn RequestHandler>) -> Result<Self> {
        let addr = config
            .udp_addr
            .ok_or_else(|| Error::Config("UDP address not configured".to_string()))?;

        let socket = UdpSocket::bind(addr).await.map_err(Error::Io)?;

        info!("UDP server listening on {}", addr);

        Ok(Self {
            socket: Arc::new(socket),
            handler,
            config,
        })
    }

    /// Get the local address the server is bound to
    ///
    /// # Errors
    ///
    /// Returns an error if the socket address cannot be retrieved.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.socket.local_addr().map_err(Error::Io)
    }

    /// Run the UDP server
    ///
    /// This method runs the server loop, receiving queries and sending responses.
    /// It will run indefinitely until an error occurs or the task is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a network or processing error.
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; self.config.max_udp_size];

        info!("UDP server started");

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    debug!("Received {} bytes from {}", len, peer_addr);

                    // Copy the data so we can move it to the spawned task
                    let request_data = buf[..len].to_vec();
                    let handler = Arc::clone(&self.handler);
                    let socket = self.socket.clone();

                    // Spawn a task to handle this request
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_request(&request_data, peer_addr, handler, socket).await
                        {
                            error!("Error handling request from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error receiving UDP packet: {}", e);
                    // Continue serving despite errors
                }
            }
        }
    }

    /// Handle a single DNS request
    async fn handle_request(
        request_data: &[u8],
        peer_addr: std::net::SocketAddr,
        handler: Arc<dyn RequestHandler>,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        // Parse DNS wire format
        let request = Self::parse_request(request_data)?;

        debug!(
            "Processing query ID {} with {} questions from {}",
            request.id(),
            request.question_count(),
            peer_addr
        );

        // Handle the request
        // Call the handler and ensure response ID matches request ID
        let req_id = request.id();
        let mut response = handler.handle(request).await?;
        response.set_id(req_id);

        debug!(
            "Sending response ID {} with {} answers to {}",
            response.id(),
            response.answer_count(),
            peer_addr
        );

        // Serialize and send response
        let response_data = Self::serialize_response(&response)?;

        socket
            .send_to(&response_data, peer_addr)
            .await
            .map_err(Error::Io)?;

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

    #[tokio::test]
    async fn test_udp_server_creation() {
        let config = ServerConfig::default().with_udp_addr("127.0.0.1:0".parse().unwrap());
        let handler = Arc::new(DefaultHandler);

        let server = UdpServer::new(config, handler).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_udp_server_local_addr() {
        let config = ServerConfig::default().with_udp_addr("127.0.0.1:0".parse().unwrap());
        let handler = Arc::new(DefaultHandler);

        let server = UdpServer::new(config, handler).await.unwrap();
        let addr = server.local_addr();
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().ip(), std::net::Ipv4Addr::LOCALHOST);
    }

    #[tokio::test]
    async fn test_udp_server_creation_without_udp_addr() {
        let config = ServerConfig::new(None, None); // No UDP addr configured
        let handler = Arc::new(DefaultHandler);

        let server = UdpServer::new(config, handler).await;
        assert!(server.is_err());
        // Check that it's a config error
        if let Err(Error::Config(_)) = server {
            // Expected
        } else {
            panic!("Expected Config error");
        }
    }

    #[tokio::test]
    async fn test_parse_request_with_real_dns_message() {
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
        let parsed = UdpServer::parse_request(&data).expect("parse request");
        assert_eq!(parsed.id(), 0x42);
        assert_eq!(parsed.question_count(), 1);
        assert!(!parsed.is_response()); // Should be a query, not a response
    }

    #[tokio::test]
    async fn test_serialize_response_with_real_dns_message() {
        // Build a DNS response message and serialize via serialize_response
        let mut resp = Message::new();
        resp.set_id(0x99);
        resp.set_response(true);
        resp.add_question(Question::new(
            "example.test".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let data = UdpServer::serialize_response(&resp).expect("serialize response");
        assert!(data.len() >= 12); // DNS header is at least 12 bytes

        // Verify we can parse it back
        let parsed = wire::parse_message(&data).expect("parse serialized response");
        assert_eq!(parsed.id(), 0x99);
        assert!(parsed.is_response());
        assert_eq!(parsed.question_count(), 1);
    }

    #[tokio::test]
    async fn test_parse_request_placeholder() {
        let data = vec![0u8; 12];
        let message = UdpServer::parse_request(&data);
        assert!(message.is_ok());
    }

    #[tokio::test]
    async fn test_serialize_response_placeholder() {
        let message = Message::new();
        let data = UdpServer::serialize_response(&message);
        assert!(data.is_ok());
        assert_eq!(data.unwrap().len(), 12); // DNS header size
    }

    #[tokio::test]
    async fn test_parse_request_with_invalid_data() {
        let data = vec![0u8; 5]; // Too short for DNS message
        let message = UdpServer::parse_request(&data);
        assert!(message.is_err());
    }

    #[tokio::test]
    async fn test_serialize_response_with_complex_message() {
        let mut resp = Message::new();
        resp.set_id(0x1234);
        resp.set_response(true);
        resp.set_recursion_available(true);
        resp.add_question(Question::new(
            "complex.example.test".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let data = UdpServer::serialize_response(&resp).expect("serialize complex response");
        assert!(data.len() > 12); // Should be larger than header

        // Parse back and verify
        let parsed = wire::parse_message(&data).expect("parse complex response");
        assert_eq!(parsed.id(), 0x1234);
        assert!(parsed.is_response());
        assert!(parsed.recursion_available());
    }
}
