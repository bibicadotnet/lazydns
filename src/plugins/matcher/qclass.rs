//! Query class matcher plugin
//!
//! Matches DNS queries based on their query class (IN, CH, HS)

use crate::dns::types::RecordClass;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that matches queries based on their query class
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::QClassMatcherPlugin;
/// use lazydns::dns::types::RecordClass;
///
/// // Match IN (Internet) class queries
/// let matcher = QClassMatcherPlugin::new(vec![RecordClass::IN]);
/// ```
pub struct QClassMatcherPlugin {
    /// The query classes to match
    query_classes: Vec<RecordClass>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl QClassMatcherPlugin {
    /// Create a new QClass matcher plugin
    pub fn new(query_classes: Vec<RecordClass>) -> Self {
        Self {
            query_classes,
            metadata_key: "qclass_matched".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if a query class matches
    fn matches_class(&self, qclass: RecordClass) -> bool {
        self.query_classes.contains(&qclass)
    }
}

impl fmt::Debug for QClassMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QClassMatcherPlugin")
            .field("query_classes", &self.query_classes)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for QClassMatcherPlugin {
    fn name(&self) -> &str {
        "qclass_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let request = ctx.request();
        if let Some(question) = request.questions().first() {
            let matched = self.matches_class(question.qclass());

            if matched {
                debug!(
                    qclass = ?question.qclass(),
                    "QClass matcher: matched"
                );
                ctx.set_metadata(self.metadata_key.clone(), true);
            } else {
                debug!(
                    qclass = ?question.qclass(),
                    expected = ?self.query_classes,
                    "QClass matcher: no match"
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
    use crate::dns::{types::RecordType, Message, Question};

    #[tokio::test]
    async fn test_qclass_matcher() {
        let matcher = QClassMatcherPlugin::new(vec![RecordClass::IN]);

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("qclass_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_qclass_matcher_no_match() {
        let matcher = QClassMatcherPlugin::new(vec![RecordClass::IN]);

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::CH,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("qclass_matched").unwrap();
        assert!(!(*matched));
    }
}
