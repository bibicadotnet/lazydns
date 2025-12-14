//! Has wanted answer matcher plugin
//!
//! Checks if the response contains the wanted answer types

use crate::dns::types::RecordType;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that checks if response contains wanted answer types
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::HasWantedAnsMatcherPlugin;
/// use lazydns::dns::types::RecordType;
///
/// // Check for A or AAAA records
/// let matcher = HasWantedAnsMatcherPlugin::new(vec![RecordType::A, RecordType::AAAA]);
/// ```
pub struct HasWantedAnsMatcherPlugin {
    /// Wanted record types
    wanted_types: Vec<RecordType>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl HasWantedAnsMatcherPlugin {
    /// Create a new has wanted answer matcher plugin
    pub fn new(wanted_types: Vec<RecordType>) -> Self {
        Self {
            wanted_types,
            metadata_key: "has_wanted_ans".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if response has wanted answer types
    fn has_wanted_answers(&self, ctx: &Context) -> bool {
        if let Some(response) = ctx.response() {
            // Check if any answer has one of the wanted types
            for answer in response.answers() {
                if self.wanted_types.contains(&answer.rtype()) {
                    return true;
                }
            }
        }
        false
    }
}

impl fmt::Debug for HasWantedAnsMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HasWantedAnsMatcherPlugin")
            .field("wanted_types", &self.wanted_types)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for HasWantedAnsMatcherPlugin {
    fn name(&self) -> &str {
        "has_wanted_ans"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let has_wanted = self.has_wanted_answers(ctx);

        if has_wanted {
            debug!("HasWantedAns matcher: found wanted answer types");
        } else {
            debug!("HasWantedAns matcher: no wanted answer types found");
        }

        ctx.set_metadata(self.metadata_key.clone(), has_wanted);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::RecordClass;
    use crate::dns::{Message, RData, ResourceRecord};

    #[tokio::test]
    async fn test_has_wanted_ans_with_wanted() {
        let matcher = HasWantedAnsMatcherPlugin::new(vec![RecordType::A]);

        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();

        let has_wanted = ctx.get_metadata::<bool>("has_wanted_ans").unwrap();
        assert!(*has_wanted);
    }

    #[tokio::test]
    async fn test_has_wanted_ans_without_wanted() {
        let matcher = HasWantedAnsMatcherPlugin::new(vec![RecordType::A]);

        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::CNAME,
            RecordClass::IN,
            300,
            RData::CNAME("target.example.com".to_string()),
        ));
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();

        let has_wanted = ctx.get_metadata::<bool>("has_wanted_ans").unwrap();
        assert!(!(*has_wanted));
    }

    #[tokio::test]
    async fn test_has_wanted_ans_multiple_types() {
        let matcher = HasWantedAnsMatcherPlugin::new(vec![RecordType::A, RecordType::AAAA]);

        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
            300,
            RData::AAAA("2001:db8::1".parse().unwrap()),
        ));
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();

        let has_wanted = ctx.get_metadata::<bool>("has_wanted_ans").unwrap();
        assert!(*has_wanted);
    }

    #[tokio::test]
    async fn test_has_wanted_ans_no_response() {
        let matcher = HasWantedAnsMatcherPlugin::new(vec![RecordType::A]);
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let has_wanted = ctx.get_metadata::<bool>("has_wanted_ans").unwrap();
        assert!(!(*has_wanted));
    }
}
