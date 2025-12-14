//! Response existence matcher plugin
//!
//! Matches queries that have received a response

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that checks if a response exists in the context
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::HasRespMatcherPlugin;
///
/// let matcher = HasRespMatcherPlugin::new();
/// ```
pub struct HasRespMatcherPlugin {
    /// Metadata key to set when matched
    metadata_key: String,
}

impl HasRespMatcherPlugin {
    /// Create a new HasResp matcher plugin
    pub fn new() -> Self {
        Self {
            metadata_key: "has_resp".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }
}

impl Default for HasRespMatcherPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HasRespMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HasRespMatcherPlugin")
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for HasRespMatcherPlugin {
    fn name(&self) -> &str {
        "has_resp"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let has_response = ctx.response().is_some();

        if has_response {
            debug!("HasResp matcher: response exists");
        } else {
            debug!("HasResp matcher: no response");
        }

        ctx.set_metadata(self.metadata_key.clone(), has_response);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_has_resp_with_response() {
        let matcher = HasRespMatcherPlugin::new();
        let mut ctx = Context::new(Message::new());

        ctx.set_response(Some(Message::new()));

        matcher.execute(&mut ctx).await.unwrap();

        let has_resp = ctx.get_metadata::<bool>("has_resp").unwrap();
        assert!(*has_resp);
    }

    #[tokio::test]
    async fn test_has_resp_without_response() {
        let matcher = HasRespMatcherPlugin::new();
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let has_resp = ctx.get_metadata::<bool>("has_resp").unwrap();
        assert!(!(*has_resp));
    }

    #[tokio::test]
    async fn test_has_resp_custom_key() {
        let matcher = HasRespMatcherPlugin::new().with_metadata_key("my_custom_key".to_string());
        let mut ctx = Context::new(Message::new());

        ctx.set_response(Some(Message::new()));

        matcher.execute(&mut ctx).await.unwrap();

        let has_resp = ctx.get_metadata::<bool>("my_custom_key").unwrap();
        assert!(*has_resp);
    }
}
