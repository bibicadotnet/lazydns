//! Request handler trait
//!
//! Defines the interface for handling DNS requests

use crate::Result;
use crate::dns::Message;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};

/// Client connection information
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Client socket address
    pub addr: SocketAddr,
    /// Client IP address
    pub ip: IpAddr,
    /// Client port
    pub port: u16,
}

impl From<SocketAddr> for ClientInfo {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            ip: addr.ip(),
            port: addr.port(),
        }
    }
}

/// Network protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// UDP protocol
    Udp,
    /// TCP protocol
    Tcp,
    /// DNS over HTTPS
    DoH,
    /// DNS over TLS
    DoT,
    /// DNS over QUIC
    DoQ,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Udp => write!(f, "udp"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::DoH => write!(f, "doh"),
            Protocol::DoT => write!(f, "dot"),
            Protocol::DoQ => write!(f, "doq"),
        }
    }
}

/// Request processing context
///
/// Contains all information needed to process a DNS request,
/// including the message, client information, and protocol type.
///
/// # Example
///
/// ```rust
/// use lazydns::server::{RequestContext, Protocol};
/// use lazydns::dns::Message;
/// use std::net::SocketAddr;
///
/// let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
/// let message = Message::new();
/// let ctx = RequestContext::with_client(message, Some(addr), Protocol::Udp);
///
/// assert!(ctx.client_ip().is_some());
/// ```
#[derive(Debug)]
pub struct RequestContext {
    /// DNS query message
    pub message: Message,
    /// Client connection information
    pub client_info: Option<ClientInfo>,
    /// Network protocol
    pub protocol: Protocol,
}

impl RequestContext {
    /// Create a new request context
    ///
    /// # Arguments
    ///
    /// * `message` - The DNS query message
    /// * `protocol` - The network protocol used
    pub fn new(message: Message, protocol: Protocol) -> Self {
        Self {
            message,
            client_info: None,
            protocol,
        }
    }

    /// Create a new request context with client information
    ///
    /// # Arguments
    ///
    /// * `message` - The DNS query message
    /// * `client_addr` - Optional client socket address
    /// * `protocol` - The network protocol used
    pub fn with_client(
        message: Message,
        client_addr: Option<SocketAddr>,
        protocol: Protocol,
    ) -> Self {
        Self {
            message,
            client_info: client_addr.map(ClientInfo::from),
            protocol,
        }
    }

    /// Get the client IP address
    ///
    /// Returns `None` if client information is not available.
    pub fn client_ip(&self) -> Option<&IpAddr> {
        self.client_info.as_ref().map(|info| &info.ip)
    }

    /// Get the client socket address
    ///
    /// Returns `None` if client information is not available.
    pub fn client_addr(&self) -> Option<&SocketAddr> {
        self.client_info.as_ref().map(|info| &info.addr)
    }

    /// Consume the context and return the message
    pub fn into_message(self) -> Message {
        self.message
    }

    /// Consume the context and return all components as a tuple
    pub fn into_raw(self) -> (Message, Option<ClientInfo>, Protocol) {
        (self.message, self.client_info, self.protocol)
    }
}

/// DNS request handler trait
///
/// Implementations of this trait handle incoming DNS queries and generate responses.
/// This allows for flexible query processing logic.
///
/// # Example
///
/// ```rust
/// use lazydns::server::{RequestHandler, RequestContext, Protocol};
/// use lazydns::dns::Message;
/// use lazydns::Result;
/// use async_trait::async_trait;
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl RequestHandler for MyHandler {
///     async fn handle(&self, ctx: RequestContext) -> Result<Message> {
///         // Process request and return response
///         Ok(ctx.message)
///     }
/// }
/// ```
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle a DNS request and return a response
    ///
    /// # Arguments
    ///
    /// * `ctx` - The request context containing the message and client information
    ///
    /// # Returns
    ///
    /// A DNS response message or an error
    async fn handle(&self, ctx: RequestContext) -> Result<Message>;
}

/// Default request handler that echoes queries back
///
/// This is a simple implementation useful for testing.
/// In production, you would implement a handler that performs
/// actual DNS resolution.
#[derive(Debug, Clone)]
pub struct DefaultHandler;

#[async_trait]
impl RequestHandler for DefaultHandler {
    async fn handle(&self, ctx: RequestContext) -> Result<Message> {
        // Convert query to response
        let mut request = ctx.message;
        request.set_response(true);
        request.set_recursion_available(false);

        // For now, just return the request as a response
        // A real implementation would look up records and add answers
        Ok(request)
    }
}

impl Default for DefaultHandler {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Question, RecordClass, RecordType};

    #[tokio::test]
    async fn test_default_handler() {
        let handler = DefaultHandler;

        let mut request = Message::new();
        request.set_id(1234);
        request.set_query(true);
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let ctx = RequestContext::new(request, Protocol::Udp);
        let response = handler.handle(ctx).await.unwrap();

        assert!(response.is_response());
        assert_eq!(response.id(), 1234);
        assert_eq!(response.question_count(), 1);
    }

    #[tokio::test]
    async fn test_handler_preserves_questions() {
        let handler = DefaultHandler;

        let mut request = Message::new();
        request.add_question(Question::new(
            "test.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let ctx = RequestContext::new(request, Protocol::Udp);
        let response = handler.handle(ctx).await.unwrap();

        assert_eq!(response.questions()[0].qname(), "test.com");
        assert_eq!(response.questions()[0].qtype(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_request_context_with_client() {
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let message = Message::new();
        let ctx = RequestContext::with_client(message, Some(addr), Protocol::Udp);

        assert!(ctx.client_info.is_some());
        assert_eq!(ctx.client_ip(), Some(&"192.168.1.1".parse().unwrap()));
        assert_eq!(ctx.client_addr(), Some(&addr));
        assert_eq!(ctx.protocol, Protocol::Udp);
    }

    #[tokio::test]
    async fn test_request_context_without_client() {
        let message = Message::new();
        let ctx = RequestContext::new(message, Protocol::DoH);

        assert!(ctx.client_info.is_none());
        assert_eq!(ctx.client_ip(), None);
        assert_eq!(ctx.protocol, Protocol::DoH);
    }
}
