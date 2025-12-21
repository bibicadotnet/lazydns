//! CNAME matcher plugin
//!
//! Matches responses that contain CNAME records

use crate::Result;
use crate::dns::types::RecordType;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that matches responses containing CNAME records
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::CnameMatcherPlugin;
///
/// let matcher = CnameMatcherPlugin::new();
/// ```
pub struct CnameMatcherPlugin {
    /// Metadata key to set when matched
    metadata_key: String,
}

impl CnameMatcherPlugin {
    /// Create a new CNAME matcher plugin
    pub fn new() -> Self {
        Self {
            metadata_key: "cname_matched".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if response contains CNAME records
    fn has_cname(&self, ctx: &Context) -> bool {
        if let Some(response) = ctx.response() {
            // Check answer section for CNAME records
            for record in response.answers() {
                if record.rtype() == RecordType::CNAME {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for CnameMatcherPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CnameMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CnameMatcherPlugin")
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for CnameMatcherPlugin {
    fn name(&self) -> &str {
        "cname_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let matched = self.has_cname(ctx);

        if matched {
            debug!("CNAME matcher: matched");
            ctx.set_metadata(self.metadata_key.clone(), true);
        } else {
            debug!("CNAME matcher: no match");
            ctx.set_metadata(self.metadata_key.clone(), false);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, RData, ResourceRecord};

    #[tokio::test]
    async fn test_cname_matcher_with_cname() {
        let matcher = CnameMatcherPlugin::new();
        let mut ctx = Context::new(Message::new());

        let mut response = Message::new();
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::CNAME,
            crate::dns::types::RecordClass::IN,
            300,
            RData::CNAME("target.example.com".to_string()),
        ));
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("cname_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_cname_matcher_without_cname() {
        let matcher = CnameMatcherPlugin::new();
        let mut ctx = Context::new(Message::new());

        let mut response = Message::new();
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            crate::dns::types::RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("cname_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_cname_matcher_no_response() {
        let matcher = CnameMatcherPlugin::new();
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("cname_matched").unwrap();
        assert!(!(*matched));
    }
}
