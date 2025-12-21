//! Query type matcher plugin
//!
//! Matches DNS queries based on their query type (A, AAAA, CNAME, etc.)

use crate::Result;
use crate::dns::types::RecordType;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that matches queries based on their query type
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::QTypeMatcherPlugin;
/// use lazydns::dns::types::RecordType;
///
/// // Match A record queries
/// let matcher = QTypeMatcherPlugin::new(vec![RecordType::A]);
///
/// // Match A and AAAA queries
/// let matcher = QTypeMatcherPlugin::new(vec![RecordType::A, RecordType::AAAA]);
/// ```
pub struct QTypeMatcherPlugin {
    /// The query types to match
    query_types: Vec<RecordType>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl QTypeMatcherPlugin {
    /// Create a new QType matcher plugin
    ///
    /// # Arguments
    ///
    /// * `query_types` - List of query types to match
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::matcher::QTypeMatcherPlugin;
    /// use lazydns::dns::types::RecordType;
    ///
    /// let matcher = QTypeMatcherPlugin::new(vec![RecordType::A, RecordType::AAAA]);
    /// ```
    pub fn new(query_types: Vec<RecordType>) -> Self {
        Self {
            query_types,
            metadata_key: "qtype_matched".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if a query type matches
    fn matches_type(&self, qtype: RecordType) -> bool {
        self.query_types.contains(&qtype)
    }
}

impl fmt::Debug for QTypeMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QTypeMatcherPlugin")
            .field("query_types", &self.query_types)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for QTypeMatcherPlugin {
    fn name(&self) -> &str {
        "qtype_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Get the query type from the request
        let request = ctx.request();
        if let Some(question) = request.questions().first() {
            let matched = self.matches_type(question.qtype());

            if matched {
                debug!(
                    qtype = ?question.qtype(),
                    "QType matcher: matched"
                );
                ctx.set_metadata(self.metadata_key.clone(), true);
            } else {
                debug!(
                    qtype = ?question.qtype(),
                    expected = ?self.query_types,
                    "QType matcher: no match"
                );
                ctx.set_metadata(self.metadata_key.clone(), false);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, Question};

    #[tokio::test]
    async fn test_qtype_matcher_single() {
        let matcher = QTypeMatcherPlugin::new(vec![RecordType::A]);

        // Create a query for A record
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            crate::dns::types::RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        // Should be matched
        let matched = ctx.get_metadata::<bool>("qtype_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_qtype_matcher_no_match() {
        let matcher = QTypeMatcherPlugin::new(vec![RecordType::A]);

        // Create a query for AAAA record
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            crate::dns::types::RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        // Should not be matched
        let matched = ctx.get_metadata::<bool>("qtype_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_qtype_matcher_multiple() {
        let matcher = QTypeMatcherPlugin::new(vec![RecordType::A, RecordType::AAAA]);

        // Test A record - should match
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            crate::dns::types::RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("qtype_matched").unwrap();
        assert!(*matched);

        // Test AAAA record - should match
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            crate::dns::types::RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("qtype_matched").unwrap();
        assert!(*matched);

        // Test MX record - should not match
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::MX,
            crate::dns::types::RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("qtype_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_qtype_matcher_custom_key() {
        let matcher = QTypeMatcherPlugin::new(vec![RecordType::A])
            .with_metadata_key("my_custom_key".to_string());

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            crate::dns::types::RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        // Should use custom key
        let matched = ctx.get_metadata::<bool>("my_custom_key").unwrap();
        assert!(*matched);
    }
}
