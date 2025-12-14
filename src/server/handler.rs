//! Request handler trait
//!
//! Defines the interface for handling DNS requests

use crate::dns::Message;
use crate::Result;
use async_trait::async_trait;

/// DNS request handler trait
///
/// Implementations of this trait handle incoming DNS queries and generate responses.
/// This allows for flexible query processing logic.
///
/// # Example
///
/// ```rust
/// use lazydns::server::RequestHandler;
/// use lazydns::dns::Message;
/// use lazydns::Result;
/// use async_trait::async_trait;
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl RequestHandler for MyHandler {
///     async fn handle(&self, request: Message) -> Result<Message> {
///         // Process request and return response
///         Ok(request)
///     }
/// }
/// ```
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle a DNS request and return a response
    ///
    /// # Arguments
    ///
    /// * `request` - The DNS query message to handle
    ///
    /// # Returns
    ///
    /// A DNS response message or an error
    async fn handle(&self, request: Message) -> Result<Message>;
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
    async fn handle(&self, mut request: Message) -> Result<Message> {
        // Convert query to response
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

        let response = handler.handle(request).await.unwrap();

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

        let response = handler.handle(request).await.unwrap();

        assert_eq!(response.questions()[0].qname(), "test.com");
        assert_eq!(response.questions()[0].qtype(), RecordType::AAAA);
    }
}
