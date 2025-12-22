//! Query name matcher plugin
//!
//! Matches queries based on the query name (domain)

use crate::Result;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that matches queries based on query name
///
/// This is a simple qname matcher that wraps the domain_matcher functionality
/// but focuses specifically on the query name.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::QNameMatcherPlugin;
///
/// let mut matcher = QNameMatcherPlugin::new();
/// matcher.add_domain("example.com");
/// matcher.add_domain("*.example.net");
/// ```
pub struct QNameMatcherPlugin {
    /// List of exact domain names to match
    exact_domains: Vec<String>,
    /// List of suffix patterns to match (e.g., "*.example.com")
    suffix_domains: Vec<String>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl QNameMatcherPlugin {
    /// Create a new QName matcher plugin
    pub fn new() -> Self {
        Self {
            exact_domains: Vec::new(),
            suffix_domains: Vec::new(),
            metadata_key: "qname_matched".to_string(),
        }
    }

    /// Add a domain to match (exact or wildcard)
    pub fn add_domain(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        if let Some(suffix) = domain_lower.strip_prefix("*.") {
            self.suffix_domains.push(suffix.to_string());
        } else {
            self.exact_domains.push(domain_lower);
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if a domain matches
    fn matches_domain(&self, qname: &str) -> bool {
        let qname_lower = qname.to_lowercase();

        // Check exact match
        if self.exact_domains.contains(&qname_lower) {
            return true;
        }

        // Check suffix match
        for suffix in &self.suffix_domains {
            if qname_lower.ends_with(suffix) || qname_lower == *suffix {
                return true;
            }
        }

        false
    }
}

impl Default for QNameMatcherPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for QNameMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QNameMatcherPlugin")
            .field("exact_domains", &self.exact_domains)
            .field("suffix_domains", &self.suffix_domains)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for QNameMatcherPlugin {
    fn name(&self) -> &str {
        "qname_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let request = ctx.request();
        if let Some(question) = request.questions().first() {
            let matched = self.matches_domain(question.qname());

            if matched {
                debug!(
                    qname = %question.qname(),
                    "QName matcher: matched"
                );
                ctx.set_metadata(self.metadata_key.clone(), true);
            } else {
                debug!(
                    qname = %question.qname(),
                    "QName matcher: no match"
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
    use crate::dns::{
        Message, Question,
        types::{RecordClass, RecordType},
    };

    #[tokio::test]
    async fn test_qname_matcher_exact() {
        let mut matcher = QNameMatcherPlugin::new();
        matcher.add_domain("example.com");

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("qname_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_qname_matcher_suffix() {
        let mut matcher = QNameMatcherPlugin::new();
        matcher.add_domain("*.example.com");

        let mut request = Message::new();
        request.add_question(Question::new(
            "www.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("qname_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_qname_matcher_no_match() {
        let mut matcher = QNameMatcherPlugin::new();
        matcher.add_domain("example.com");

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.net".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("qname_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_qname_matcher_case_insensitive() {
        let mut matcher = QNameMatcherPlugin::new();
        matcher.add_domain("Example.COM");

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("qname_matched").unwrap();
        assert!(*matched);
    }
}
