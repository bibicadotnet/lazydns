//! Redirect plugin
//!
//! Redirects DNS queries to a different domain

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that redirects queries from one domain to another
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::executable::RedirectPlugin;
///
/// // Redirect example.com to example.net
/// let plugin = RedirectPlugin::new("example.com", "example.net");
///
/// // Redirect with wildcard
/// let mut plugin = RedirectPlugin::new("*.old.com", "*.new.com");
/// ```
pub struct RedirectPlugin {
    /// Source domain pattern
    from_domain: String,
    /// Target domain
    to_domain: String,
}

impl RedirectPlugin {
    /// Create a new redirect plugin
    ///
    /// # Arguments
    ///
    /// * `from_domain` - Domain pattern to match (can include wildcards)
    /// * `to_domain` - Target domain to redirect to
    pub fn new(from_domain: impl Into<String>, to_domain: impl Into<String>) -> Self {
        Self {
            from_domain: from_domain.into(),
            to_domain: to_domain.into(),
        }
    }

    /// Check if a domain matches the from pattern
    fn matches(&self, qname: &str) -> bool {
        let from_lower = self.from_domain.to_lowercase();
        let qname_lower = qname.to_lowercase();

        if let Some(suffix) = from_lower.strip_prefix("*.") {
            // Wildcard match
            qname_lower.ends_with(suffix) || qname_lower == suffix
        } else {
            // Exact match
            qname_lower == from_lower
        }
    }

    /// Perform the redirection
    fn redirect(&self, qname: &str) -> String {
        let from_lower = self.from_domain.to_lowercase();
        let qname_lower = qname.to_lowercase();
        let to_lower = self.to_domain.to_lowercase();

        if let (Some(from_suffix), Some(to_suffix)) =
            (from_lower.strip_prefix("*."), to_lower.strip_prefix("*."))
        {
            // Both are wildcards - replace suffix

            if let Some(mut prefix) = qname_lower.strip_suffix(from_suffix) {
                // Remove trailing dot if present to avoid double dots
                if prefix.ends_with('.') && to_suffix.starts_with('.') {
                    prefix = &prefix[..prefix.len() - 1];
                }
                return format!("{}{}", prefix, to_suffix);
            }
        }

        // Simple replacement - use original to_domain to preserve case
        self.to_domain.clone()
    }
}

impl fmt::Debug for RedirectPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectPlugin")
            .field("from_domain", &self.from_domain)
            .field("to_domain", &self.to_domain)
            .finish()
    }
}

#[async_trait]
impl Plugin for RedirectPlugin {
    fn name(&self) -> &str {
        "redirect"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let request = ctx.request_mut();

        if let Some(question) = request.questions_mut().first_mut() {
            let qname = question.qname().to_string();

            if self.matches(&qname) {
                let new_qname = self.redirect(&qname);

                debug!("Redirecting query from {} to {}", qname, new_qname);

                question.set_qname(new_qname);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question};

    #[tokio::test]
    async fn test_redirect_exact() {
        let plugin = RedirectPlugin::new("example.com", "example.net");

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        let request = ctx.request();
        assert_eq!(request.questions().first().unwrap().qname(), "example.net");
    }

    #[tokio::test]
    async fn test_redirect_wildcard() {
        let plugin = RedirectPlugin::new("*.old.com", "*.new.com");

        let mut request = Message::new();
        request.add_question(Question::new(
            "www.old.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        let request = ctx.request();
        assert_eq!(request.questions().first().unwrap().qname(), "www.new.com");
    }

    #[tokio::test]
    async fn test_redirect_no_match() {
        let plugin = RedirectPlugin::new("example.com", "example.net");

        let mut request = Message::new();
        request.add_question(Question::new(
            "different.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        // Should remain unchanged
        let request = ctx.request();
        assert_eq!(
            request.questions().first().unwrap().qname(),
            "different.com"
        );
    }

    #[tokio::test]
    async fn test_redirect_case_insensitive() {
        let plugin = RedirectPlugin::new("Example.COM", "example.net");

        let mut request = Message::new();
        request.add_question(Question::new(
            "EXAMPLE.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        let request = ctx.request();
        assert_eq!(request.questions().first().unwrap().qname(), "example.net");
    }
}
