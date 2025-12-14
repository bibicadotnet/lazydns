//! Debug print plugin
//!
//! Prints debug information about DNS queries and responses to the log

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use tracing::{debug, info};

/// Plugin that prints debug information about DNS queries and responses
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::executable::DebugPrintPlugin;
///
/// // Print queries only
/// let plugin = DebugPrintPlugin::queries_only();
///
/// // Print responses only  
/// let plugin = DebugPrintPlugin::responses_only();
///
/// // Print both queries and responses
/// let plugin = DebugPrintPlugin::new();
/// ```
pub struct DebugPrintPlugin {
    /// Whether to print queries
    print_queries: bool,
    /// Whether to print responses
    print_responses: bool,
    /// Custom prefix for log messages
    prefix: String,
}

impl DebugPrintPlugin {
    /// Create a new debug print plugin that prints both queries and responses
    pub fn new() -> Self {
        Self {
            print_queries: true,
            print_responses: true,
            prefix: "DNS".to_string(),
        }
    }

    /// Create a debug print plugin that only prints queries
    pub fn queries_only() -> Self {
        Self {
            print_queries: true,
            print_responses: false,
            prefix: "DNS".to_string(),
        }
    }

    /// Create a debug print plugin that only prints responses
    pub fn responses_only() -> Self {
        Self {
            print_queries: false,
            print_responses: true,
            prefix: "DNS".to_string(),
        }
    }

    /// Set a custom prefix for log messages
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = prefix;
        self
    }
}

impl Default for DebugPrintPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DebugPrintPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebugPrintPlugin")
            .field("print_queries", &self.print_queries)
            .field("print_responses", &self.print_responses)
            .field("prefix", &self.prefix)
            .finish()
    }
}

#[async_trait]
impl Plugin for DebugPrintPlugin {
    fn name(&self) -> &str {
        "debug_print"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Print query information
        if self.print_queries {
            let request = ctx.request();
            if let Some(question) = request.questions().first() {
                info!(
                    "{} Query: {} {:?} {:?}",
                    self.prefix,
                    question.qname(),
                    question.qtype(),
                    question.qclass()
                );
            }
        }

        // Print response information
        if self.print_responses {
            if let Some(response) = ctx.response() {
                info!(
                    "{} Response: {} answers, rcode={:?}",
                    self.prefix,
                    response.answers().len(),
                    response.response_code()
                );

                // Print answer details
                for (i, answer) in response.answers().iter().enumerate() {
                    debug!(
                        "{} Answer[{}]: {} {:?} ttl={}",
                        self.prefix,
                        i,
                        answer.name(),
                        answer.rtype(),
                        answer.ttl()
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question, RData, ResourceRecord};

    #[tokio::test]
    async fn test_debug_print_queries_only() {
        let plugin = DebugPrintPlugin::queries_only();

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        assert!(plugin.execute(&mut ctx).await.is_ok());
    }

    #[tokio::test]
    async fn test_debug_print_responses_only() {
        let plugin = DebugPrintPlugin::responses_only();

        let request = Message::new();
        let mut ctx = Context::new(request);

        let mut response = Message::new();
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));
        ctx.set_response(Some(response));

        assert!(plugin.execute(&mut ctx).await.is_ok());
    }

    #[tokio::test]
    async fn test_debug_print_both() {
        let plugin = DebugPrintPlugin::new();

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        let mut response = Message::new();
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));
        ctx.set_response(Some(response));

        assert!(plugin.execute(&mut ctx).await.is_ok());
    }

    #[tokio::test]
    async fn test_debug_print_custom_prefix() {
        let plugin = DebugPrintPlugin::new().with_prefix("TEST".to_string());

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        assert!(plugin.execute(&mut ctx).await.is_ok());
        assert_eq!(plugin.prefix, "TEST");
    }
}
