//! Response code matcher plugin
//!
//! Matches DNS responses based on their response code (NOERROR, NXDOMAIN, etc.)

use crate::dns::types::ResponseCode;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that matches responses based on their response code
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::RCodeMatcherPlugin;
/// use lazydns::dns::types::ResponseCode;
///
/// // Match NXDOMAIN responses
/// let matcher = RCodeMatcherPlugin::new(vec![ResponseCode::NXDomain]);
/// ```
pub struct RCodeMatcherPlugin {
    /// The response codes to match
    rcodes: Vec<ResponseCode>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl RCodeMatcherPlugin {
    /// Create a new RCode matcher plugin
    pub fn new(rcodes: Vec<ResponseCode>) -> Self {
        Self {
            rcodes,
            metadata_key: "rcode_matched".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if a response code matches
    fn matches_rcode(&self, rcode: ResponseCode) -> bool {
        self.rcodes.contains(&rcode)
    }
}

impl fmt::Debug for RCodeMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RCodeMatcherPlugin")
            .field("rcodes", &self.rcodes)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for RCodeMatcherPlugin {
    fn name(&self) -> &str {
        "rcode_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if let Some(response) = ctx.response() {
            let matched = self.matches_rcode(response.response_code());

            if matched {
                debug!(
                    rcode = ?response.response_code(),
                    "RCode matcher: matched"
                );
                ctx.set_metadata(self.metadata_key.clone(), true);
            } else {
                debug!(
                    rcode = ?response.response_code(),
                    expected = ?self.rcodes,
                    "RCode matcher: no match"
                );
                ctx.set_metadata(self.metadata_key.clone(), false);
            }
        } else {
            // No response yet, set to false
            ctx.set_metadata(self.metadata_key.clone(), false);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_rcode_matcher() {
        let matcher = RCodeMatcherPlugin::new(vec![ResponseCode::NXDomain]);
        let mut ctx = Context::new(Message::new());

        let mut response = Message::new();
        response.set_response_code(ResponseCode::NXDomain);
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("rcode_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_rcode_matcher_no_match() {
        let matcher = RCodeMatcherPlugin::new(vec![ResponseCode::NXDomain]);
        let mut ctx = Context::new(Message::new());

        let mut response = Message::new();
        response.set_response_code(ResponseCode::NoError);
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("rcode_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_rcode_matcher_no_response() {
        let matcher = RCodeMatcherPlugin::new(vec![ResponseCode::NXDomain]);
        let mut ctx = Context::new(Message::new());

        // No response set
        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("rcode_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_rcode_matcher_multiple() {
        let matcher = RCodeMatcherPlugin::new(vec![ResponseCode::NXDomain, ResponseCode::ServFail]);

        // Test NXDOMAIN - should match
        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();
        response.set_response_code(ResponseCode::NXDomain);
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("rcode_matched").unwrap();
        assert!(*matched);

        // Test SERVFAIL - should match
        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();
        response.set_response_code(ResponseCode::ServFail);
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("rcode_matched").unwrap();
        assert!(*matched);

        // Test NOERROR - should not match
        let mut ctx = Context::new(Message::new());
        let mut response = Message::new();
        response.set_response_code(ResponseCode::NoError);
        ctx.set_response(Some(response));

        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("rcode_matched").unwrap();
        assert!(!(*matched));
    }
}
