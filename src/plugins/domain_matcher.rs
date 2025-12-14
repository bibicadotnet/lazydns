//! Domain matching plugin
//!
//! This plugin matches DNS queries against domain patterns and sets a match result
//! in the context metadata. It supports exact matching, suffix matching (wildcards),
//! and can be used for domain-based routing decisions.
//!
//! # Features
//!
//! - **Exact matching**: Match exact domain names
//! - **Suffix matching**: Match domain suffixes with wildcard support (e.g., `*.example.com`)
//! - **Set operations**: Check if domain is in a predefined set
//! - **Metadata tagging**: Set match results in context for downstream plugins
//!
//! # Example
//!
//! ```rust
//! use lazydns::plugins::DomainMatcherPlugin;
//! use lazydns::plugin::Plugin;
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut matcher = DomainMatcherPlugin::new("blocked_domains");
//! matcher.add_domain("ads.example.com".to_string());
//! matcher.add_suffix("example.com".to_string()); // Matches *.example.com
//!
//! let plugin: Arc<dyn Plugin> = Arc::new(matcher);
//! # Ok(())
//! # }
//! ```

use crate::dns::RecordType;
use crate::error::Error;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::collections::HashSet;
use std::fmt;
use tracing::debug;

/// Domain matcher plugin for pattern-based domain matching
///
/// Supports exact domain matching and suffix-based wildcard matching.
/// Sets a boolean flag in the context metadata when a match is found.
pub struct DomainMatcherPlugin {
    /// Metadata key to set when domain matches
    match_key: String,
    /// Exact domain matches (normalized to lowercase)
    exact_domains: HashSet<String>,
    /// Suffix matches (normalized to lowercase, without leading dot)
    /// e.g., "example.com" matches "*.example.com"
    suffixes: HashSet<String>,
}

impl DomainMatcherPlugin {
    /// Create a new domain matcher plugin
    ///
    /// # Arguments
    ///
    /// * `match_key` - Metadata key to set when a domain matches
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::DomainMatcherPlugin;
    ///
    /// let matcher = DomainMatcherPlugin::new("is_blocked");
    /// ```
    pub fn new(match_key: impl Into<String>) -> Self {
        Self {
            match_key: match_key.into(),
            exact_domains: HashSet::new(),
            suffixes: HashSet::new(),
        }
    }

    /// Add an exact domain to match
    ///
    /// # Arguments
    ///
    /// * `domain` - Exact domain name (case-insensitive)
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::DomainMatcherPlugin;
    ///
    /// let mut matcher = DomainMatcherPlugin::new("match");
    /// matcher.add_domain("example.com".to_string());
    /// ```
    pub fn add_domain(&mut self, domain: String) {
        self.exact_domains.insert(domain.to_lowercase());
    }

    /// Add a suffix pattern to match
    ///
    /// Matches any domain ending with this suffix.
    /// The suffix should NOT include a leading wildcard or dot.
    ///
    /// # Arguments
    ///
    /// * `suffix` - Domain suffix (case-insensitive)
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::DomainMatcherPlugin;
    ///
    /// let mut matcher = DomainMatcherPlugin::new("match");
    /// // Matches *.example.com (including sub.example.com, example.com)
    /// matcher.add_suffix("example.com".to_string());
    /// ```
    pub fn add_suffix(&mut self, suffix: String) {
        let suffix = suffix.to_lowercase();
        // Remove leading dot if present
        let suffix = suffix.strip_prefix('.').unwrap_or(&suffix);
        self.suffixes.insert(suffix.to_string());
    }

    /// Load domains from a string (one per line)
    ///
    /// Lines starting with `#` are treated as comments.
    /// Lines starting with `.` or `*.` are treated as suffix patterns.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::DomainMatcherPlugin;
    ///
    /// let mut matcher = DomainMatcherPlugin::new("match");
    /// let domains = r#"
    /// # Comment line
    /// example.com
    /// *.ads.example.com
    /// .tracking.example.com
    /// "#;
    /// matcher.load_from_string(domains);
    /// ```
    pub fn load_from_string(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check if it's a suffix pattern
            if let Some(suffix) = line.strip_prefix("*.") {
                self.add_suffix(suffix.to_string());
            } else if let Some(suffix) = line.strip_prefix('.') {
                self.add_suffix(suffix.to_string());
            } else {
                self.add_domain(line.to_string());
            }
        }
    }

    /// Check if a domain matches any pattern
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to check
    ///
    /// # Returns
    ///
    /// `true` if the domain matches any exact or suffix pattern
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Check exact match
        if self.exact_domains.contains(&domain_lower) {
            return true;
        }

        // Check suffix match
        for suffix in &self.suffixes {
            // Match exact suffix or subdomain of suffix
            if domain_lower == *suffix || domain_lower.ends_with(&format!(".{}", suffix)) {
                return true;
            }
        }

        false
    }

    /// Get the number of exact domains
    pub fn exact_count(&self) -> usize {
        self.exact_domains.len()
    }

    /// Get the number of suffix patterns
    pub fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }

    /// Get total number of patterns
    pub fn len(&self) -> usize {
        self.exact_domains.len() + self.suffixes.len()
    }

    /// Check if the matcher is empty
    pub fn is_empty(&self) -> bool {
        self.exact_domains.is_empty() && self.suffixes.is_empty()
    }

    /// Clear all patterns
    pub fn clear(&mut self) {
        self.exact_domains.clear();
        self.suffixes.clear();
    }
}

impl fmt::Debug for DomainMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainMatcherPlugin")
            .field("match_key", &self.match_key)
            .field("exact_domains", &self.exact_count())
            .field("suffixes", &self.suffix_count())
            .finish()
    }
}

#[async_trait]
impl Plugin for DomainMatcherPlugin {
    async fn execute(&self, context: &mut Context) -> Result<(), Error> {
        // Get the first question
        let question = match context.request().questions().first() {
            Some(q) => q,
            None => return Ok(()),
        };

        // Only process A and AAAA queries
        let qtype = question.qtype();
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return Ok(());
        }

        // Check if domain matches (store domain string to avoid borrow issues)
        let domain = question.qname().to_string();
        let matched = self.matches(&domain);

        // Set match result in metadata
        context.set_metadata(self.match_key.clone(), matched);

        if matched {
            debug!("Domain matcher '{}': matched {}", self.match_key, domain);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "domain_matcher"
    }

    fn priority(&self) -> i32 {
        // Run early to tag requests
        80
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, Question, RecordClass};

    #[test]
    fn test_domain_matcher_creation() {
        let matcher = DomainMatcherPlugin::new("test");
        assert!(matcher.is_empty());
        assert_eq!(matcher.len(), 0);
    }

    #[test]
    fn test_add_domain() {
        let mut matcher = DomainMatcherPlugin::new("test");
        matcher.add_domain("example.com".to_string());

        assert_eq!(matcher.exact_count(), 1);
        assert_eq!(matcher.suffix_count(), 0);
        assert!(!matcher.is_empty());
    }

    #[test]
    fn test_add_suffix() {
        let mut matcher = DomainMatcherPlugin::new("test");
        matcher.add_suffix("example.com".to_string());

        assert_eq!(matcher.exact_count(), 0);
        assert_eq!(matcher.suffix_count(), 1);
    }

    #[test]
    fn test_exact_match() {
        let mut matcher = DomainMatcherPlugin::new("test");
        matcher.add_domain("example.com".to_string());

        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("Example.COM")); // Case insensitive
        assert!(!matcher.matches("sub.example.com"));
        assert!(!matcher.matches("other.com"));
    }

    #[test]
    fn test_suffix_match() {
        let mut matcher = DomainMatcherPlugin::new("test");
        matcher.add_suffix("example.com".to_string());

        assert!(matcher.matches("example.com")); // Exact match
        assert!(matcher.matches("sub.example.com")); // Subdomain
        assert!(matcher.matches("deep.sub.example.com")); // Deep subdomain
        assert!(!matcher.matches("notexample.com")); // Different domain
        assert!(!matcher.matches("example.org")); // Different TLD
    }

    #[test]
    fn test_suffix_with_leading_dot() {
        let mut matcher = DomainMatcherPlugin::new("test");
        matcher.add_suffix(".example.com".to_string());

        // Should work the same as without leading dot
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("sub.example.com"));
    }

    #[test]
    fn test_load_from_string() {
        let mut matcher = DomainMatcherPlugin::new("test");
        let content = r#"
# Comment
example.com
*.ads.example.com
.tracking.com
        "#;

        matcher.load_from_string(content);

        assert_eq!(matcher.exact_count(), 1);
        assert_eq!(matcher.suffix_count(), 2);

        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("sub.ads.example.com"));
        assert!(matcher.matches("tracking.com"));
    }

    #[test]
    fn test_clear() {
        let mut matcher = DomainMatcherPlugin::new("test");
        matcher.add_domain("example.com".to_string());
        matcher.add_suffix("test.com".to_string());

        assert_eq!(matcher.len(), 2);

        matcher.clear();

        assert_eq!(matcher.len(), 0);
        assert!(matcher.is_empty());
    }

    #[tokio::test]
    async fn test_domain_matcher_plugin_match() {
        let mut matcher = DomainMatcherPlugin::new("is_blocked");
        matcher.add_domain("blocked.com".to_string());

        let mut request = Message::new();
        request.add_question(Question::new(
            "blocked.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        matcher.execute(&mut context).await.unwrap();

        // Check metadata was set
        let matched: Option<&bool> = context.get_metadata("is_blocked");
        assert_eq!(matched, Some(&true));
    }

    #[tokio::test]
    async fn test_domain_matcher_plugin_no_match() {
        let mut matcher = DomainMatcherPlugin::new("is_blocked");
        matcher.add_domain("blocked.com".to_string());

        let mut request = Message::new();
        request.add_question(Question::new(
            "allowed.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        matcher.execute(&mut context).await.unwrap();

        // Check metadata was set to false
        let matched: Option<&bool> = context.get_metadata("is_blocked");
        assert_eq!(matched, Some(&false));
    }

    #[tokio::test]
    async fn test_domain_matcher_suffix_match() {
        let mut matcher = DomainMatcherPlugin::new("match");
        matcher.add_suffix("ads.example.com".to_string());

        let mut request = Message::new();
        request.add_question(Question::new(
            "tracker.ads.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        matcher.execute(&mut context).await.unwrap();

        let matched: Option<&bool> = context.get_metadata("match");
        assert_eq!(matched, Some(&true));
    }

    #[tokio::test]
    async fn test_domain_matcher_skips_non_a_aaaa() {
        let mut matcher = DomainMatcherPlugin::new("match");
        matcher.add_domain("example.com".to_string());

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::MX, // Not A or AAAA
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        matcher.execute(&mut context).await.unwrap();

        // Should not set metadata for non-A/AAAA queries
        let matched: Option<&bool> = context.get_metadata("match");
        assert_eq!(matched, None);
    }
}
