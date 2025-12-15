//! UDP DNS server implementation
//!
//! This module provides a high-performance DNS server implementation that listens
//! for DNS queries over the UDP protocol (port 53). UDP is the standard transport
//! protocol for DNS and is used by the majority of DNS clients worldwide.
//!
//! ## Features
//!
//! - **Asynchronous I/O**: Built on tokio for high concurrency and performance
//! - **Concurrent Request Handling**: Each DNS query is processed in a separate task
//! - **Configurable Buffer Sizes**: Supports custom maximum UDP payload sizes
//! - **Comprehensive Error Handling**: Graceful handling of malformed packets and network errors
//! - **Structured Logging**: Integrated with tracing for observability
//!
//! ## Protocol Details
//!
//! The server implements the DNS protocol as specified in RFC 1035, supporting:
//! - Standard DNS queries (A, AAAA, CNAME, MX, PTR, etc.)
//! - DNS message compression
//! - Response code handling (NXDOMAIN, SERVFAIL, etc.)
//!
//! ## Performance Characteristics
//!
//! - **Connectionless**: No connection overhead, suitable for high-throughput scenarios
//! - **Low Latency**: Minimal processing overhead per request
//! - **Memory Efficient**: Fixed-size buffers with configurable limits
//! - **Concurrent**: Handles multiple requests simultaneously without blocking
//!
//! ## Limitations
//!
//! - **Message Size**: Limited by UDP payload size (typically 4096 bytes)
//! - **Reliability**: UDP does not guarantee delivery (clients typically retry)
//! - **No Streaming**: Cannot handle very large responses that exceed UDP limits
//!
//! ## Example
//!
//! ```rust,no_run
//! use lazydns::server::{UdpServer, ServerConfig, DefaultHandler};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure the server to listen on port 53
//!     let config = ServerConfig::default()
//!         .with_udp_addr("0.0.0.0:53".parse()?);
//!
//!     // Create a default request handler
//!     let handler = Arc::new(DefaultHandler::default());
//!
//!     // Create and start the UDP server
//!     let server = UdpServer::new(config, handler).await?;
//!     println!("Server listening on {}", server.local_addr()?);
//!
//!     // Run the server (this will block)
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```

use crate::dns::Message;
use crate::server::{RequestHandler, ServerConfig};
use crate::{Error, Result};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info};

/// UDP DNS server
///
/// A high-performance, asynchronous DNS server that handles DNS queries over UDP.
/// Each instance binds to a single UDP socket and processes requests concurrently
/// using tokio's async runtime.
///
/// ## Architecture
///
/// The server uses a single-threaded event loop that:
/// 1. Receives UDP packets containing DNS queries
/// 2. Spawns asynchronous tasks to process each query independently
/// 3. Sends DNS responses back to clients
///
/// This design allows for high concurrency while maintaining low memory usage
/// and predictable performance characteristics.
///
/// ## Thread Safety
///
/// The server is designed to be used from a single thread. The internal `Arc<UdpSocket>`
/// allows request handler tasks to share the socket for sending responses, but the
/// server instance itself should not be shared across threads.
///
/// ## Fields
///
/// - `socket`: The UDP socket bound to the configured address
/// - `handler`: Request handler for processing DNS queries
/// - `config`: Server configuration including buffer sizes and timeouts
///
/// ## Example
///
/// ```rust,no_run
/// use lazydns::server::{UdpServer, ServerConfig, DefaultHandler};
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Configure for localhost testing
/// let config = ServerConfig::default()
///     .with_udp_addr("127.0.0.1:5353".parse()?);
///
/// let handler = Arc::new(DefaultHandler::default());
/// let server = UdpServer::new(config, handler).await?;
///
/// // Server is now ready to handle queries
/// println!("UDP server bound to {}", server.local_addr()?);
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
    /// Initializes a UDP socket bound to the address specified in the configuration
    /// and prepares the server for handling DNS queries. The server will bind to
    /// the UDP address specified in `config.udp_addr`.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration containing the UDP bind address and other settings.
    ///   The `udp_addr` field must be set, otherwise an error will be returned.
    /// * `handler` - Request handler that will process incoming DNS queries. The handler
    ///   is wrapped in an `Arc` to allow sharing across concurrent request processing tasks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if no UDP address is configured in the server config.
    ///
    /// Returns [`Error::Io`] if the socket cannot be bound to the specified address.
    /// This can happen if:
    /// - The port is already in use by another process
    /// - The address is invalid or unreachable
    /// - Insufficient permissions to bind to the port (e.g., ports < 1024 on Unix)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lazydns::server::{UdpServer, ServerConfig, DefaultHandler};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Configure server for standard DNS port
    /// let config = ServerConfig::default()
    ///     .with_udp_addr("127.0.0.1:53".parse()?);
    ///
    /// let handler = Arc::new(DefaultHandler::default());
    /// let server = UdpServer::new(config, handler).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// This method does not panic under normal circumstances.
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
    /// Returns the socket address that the UDP server is currently bound to.
    /// This is useful for logging, testing, or when the server was configured
    /// with port 0 (which gets assigned a random available port by the OS).
    ///
    /// # Returns
    ///
    /// The local [`std::net::SocketAddr`] that the server is listening on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the local address cannot be retrieved from the socket.
    /// This is extremely rare and usually indicates a serious system issue.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lazydns::server::{UdpServer, ServerConfig, DefaultHandler};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ServerConfig::default()
    ///     .with_udp_addr("127.0.0.1:0".parse()?); // Port 0 = auto-assign
    ///
    /// let handler = Arc::new(DefaultHandler::default());
    /// let server = UdpServer::new(config, handler).await?;
    ///
    /// // Get the actual port assigned by the OS
    /// let addr = server.local_addr()?;
    /// println!("Server listening on {}", addr);
    /// # Ok(())
    /// # }
    /// ```
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.socket.local_addr().map_err(Error::Io)
    }

    /// Run the UDP server
    ///
    /// Starts the main server loop that listens for incoming DNS queries and processes
    /// them asynchronously. This method will run indefinitely until an error occurs
    /// or the async task is cancelled.
    ///
    /// ## Processing Flow
    ///
    /// For each incoming UDP packet:
    /// 1. Receive the raw bytes and client address
    /// 2. Spawn an asynchronous task to handle the request
    /// 3. Parse the DNS message from wire format
    /// 4. Call the request handler to process the query
    /// 5. Serialize the response back to wire format
    /// 6. Send the response back to the client
    ///
    /// ## Concurrency
    ///
    /// Each DNS query is processed in a separate tokio task, allowing the server
    /// to handle multiple concurrent requests efficiently. The main loop continues
    /// to accept new requests while existing ones are being processed.
    ///
    /// ## Error Handling
    ///
    /// - Network errors during packet reception are logged but don't stop the server
    /// - Request processing errors are logged per-request and don't affect other requests
    /// - Fatal errors (like socket closure) cause the method to return
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if there's a fatal network error that prevents the server
    /// from continuing to operate, such as the UDP socket being closed unexpectedly.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lazydns::server::{UdpServer, ServerConfig, DefaultHandler};
    /// use std::sync::Arc;
    /// use tokio::signal;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ServerConfig::default()
    ///     .with_udp_addr("127.0.0.1:5353".parse()?);
    ///
    /// let handler = Arc::new(DefaultHandler::default());
    /// let server = UdpServer::new(config, handler).await?;
    ///
    /// println!("Starting UDP DNS server...");
    ///
    /// // Run until interrupted
    /// tokio::select! {
    ///     result = server.run() => {
    ///         if let Err(e) = result {
    ///             eprintln!("Server error: {}", e);
    ///         }
    ///     }
    ///     _ = signal::ctrl_c() => {
    ///         println!("Shutting down...");
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// This method does not panic under normal circumstances.
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
    /// Deserializes a DNS message from its binary wire format (as defined in RFC 1035)
    /// into a structured [`Message`] object. This method uses the hickory-proto library
    /// for robust parsing of DNS protocol elements including:
    ///
    /// - DNS header fields (ID, flags, counts)
    /// - Question records with name compression
    /// - Resource records (answers, authorities, additional)
    /// - DNS name compression and encoding
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the DNS message in network byte order
    ///
    /// # Returns
    ///
    /// A parsed [`Message`] containing the structured DNS data.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is malformed or incomplete:
    /// - Insufficient data for DNS header
    /// - Invalid DNS name encoding or compression
    /// - Corrupted record data
    /// - Unsupported record types or classes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lazydns::server::UdpServer;
    /// use lazydns::dns::Message;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Raw DNS query bytes (would come from network)
    /// let dns_packet = vec![0x12, 0x34, /* ... DNS data ... */];
    ///
    /// // Note: parse_request is an internal method used by the server
    /// // In practice, parsing is handled automatically by the server
    /// let message = Message::new(); // Placeholder for parsed message
    /// # Ok(())
    /// # }
    /// ```
    fn parse_request(data: &[u8]) -> Result<Message> {
        crate::dns::wire::parse_message(data)
    }

    /// Serialize DNS response to wire format
    ///
    /// Serializes a structured [`Message`] into its binary wire format for transmission
    /// over the network. This method handles DNS protocol serialization including:
    ///
    /// - DNS header with proper flags and counts
    /// - Question records with name compression
    /// - Resource records (answers, authorities, additional)
    /// - DNS name compression to minimize packet size
    /// - Proper byte ordering for network transmission
    ///
    /// # Arguments
    ///
    /// * `message` - The DNS message to serialize
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the serialized DNS message in network byte order,
    /// ready for transmission over UDP.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be serialized:
    /// - Invalid DNS names or labels
    /// - Unsupported record types or classes
    /// - Message too large for UDP transport
    /// - Internal serialization errors
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lazydns::server::UdpServer;
    /// use lazydns::dns::{Message, Question, RecordType, RecordClass};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut response = Message::new();
    /// response.set_id(0x1234);
    /// response.set_response(true);
    /// response.add_question(Question::new(
    ///     "example.com".to_string(),
    ///     RecordType::A,
    ///     RecordClass::IN,
    /// ));
    ///
    /// // Note: serialize_response is an internal method used by the server
    /// // In practice, serialization is handled automatically by the server
    /// let wire_data = vec![0u8; 12]; // Placeholder for serialized data
    /// println!("Would serialize {} bytes", wire_data.len());
    /// # Ok(())
    /// # }
    /// ```
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
