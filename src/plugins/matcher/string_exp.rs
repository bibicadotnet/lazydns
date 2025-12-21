//! String expression matcher plugin
//!
//! Matches strings using various comparison methods

use crate::Result;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use regex::Regex;
use std::fmt;
use tracing::debug;

/// String comparison method
#[derive(Debug, Clone)]
pub enum StringExpression {
    /// Exact match
    Exact(String),
    /// Prefix match
    Prefix(String),
    /// Suffix match
    Suffix(String),
    /// Contains substring
    Contains(String),
    /// Regex match
    Regex(Regex),
}

/// Plugin that matches based on string expressions
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::{StringExpMatcherPlugin, StringExpression};
///
/// // Exact match
/// let matcher = StringExpMatcherPlugin::new("domain", StringExpression::Exact("example.com".to_string()));
///
/// // Prefix match
/// let matcher = StringExpMatcherPlugin::new("domain", StringExpression::Prefix("www.".to_string()));
///
/// // Regex match
/// use regex::Regex;
/// let regex = Regex::new(r"^[a-z]+\.com$").unwrap();
/// let matcher = StringExpMatcherPlugin::new("domain", StringExpression::Regex(regex));
/// ```
pub struct StringExpMatcherPlugin {
    /// Metadata key to check
    metadata_key: String,
    /// String expression to match
    expression: StringExpression,
    /// Metadata key to set when matched
    result_key: String,
}

impl StringExpMatcherPlugin {
    /// Create a new string expression matcher
    pub fn new(metadata_key: impl Into<String>, expression: StringExpression) -> Self {
        Self {
            metadata_key: metadata_key.into(),
            expression,
            result_key: "string_matched".to_string(),
        }
    }

    /// Create an exact match matcher
    pub fn exact(metadata_key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(metadata_key, StringExpression::Exact(value.into()))
    }

    /// Create a prefix match matcher
    pub fn prefix(metadata_key: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self::new(metadata_key, StringExpression::Prefix(prefix.into()))
    }

    /// Create a suffix match matcher
    pub fn suffix(metadata_key: impl Into<String>, suffix: impl Into<String>) -> Self {
        Self::new(metadata_key, StringExpression::Suffix(suffix.into()))
    }

    /// Create a contains match matcher
    pub fn contains(metadata_key: impl Into<String>, substring: impl Into<String>) -> Self {
        Self::new(metadata_key, StringExpression::Contains(substring.into()))
    }

    /// Set custom result metadata key
    pub fn with_result_key(mut self, key: String) -> Self {
        self.result_key = key;
        self
    }

    /// Perform the string match
    fn matches(&self, actual: &str) -> bool {
        match &self.expression {
            StringExpression::Exact(expected) => actual == expected,
            StringExpression::Prefix(prefix) => actual.starts_with(prefix),
            StringExpression::Suffix(suffix) => actual.ends_with(suffix),
            StringExpression::Contains(substring) => actual.contains(substring),
            StringExpression::Regex(regex) => regex.is_match(actual),
        }
    }
}

impl fmt::Debug for StringExpMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringExpMatcherPlugin")
            .field("metadata_key", &self.metadata_key)
            .field("expression", &self.expression)
            .field("result_key", &self.result_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for StringExpMatcherPlugin {
    fn name(&self) -> &str {
        "string_exp"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Try to get string value from metadata
        let matched = if let Some(actual) = ctx.get_metadata::<String>(&self.metadata_key) {
            let result = self.matches(actual);

            if result {
                debug!(
                    key = %self.metadata_key,
                    value = %actual,
                    "String expression matcher: matched"
                );
            } else {
                debug!(
                    key = %self.metadata_key,
                    value = %actual,
                    "String expression matcher: no match"
                );
            }

            result
        } else {
            debug!(
                key = %self.metadata_key,
                "String expression matcher: metadata key not found"
            );
            false
        };

        ctx.set_metadata(self.result_key.clone(), matched);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_string_exp_exact() {
        let matcher = StringExpMatcherPlugin::exact("domain", "example.com");
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "example.com".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_string_exp_exact_no_match() {
        let matcher = StringExpMatcherPlugin::exact("domain", "example.com");
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "example.net".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_string_exp_prefix() {
        let matcher = StringExpMatcherPlugin::prefix("domain", "www.");
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "www.example.com".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_string_exp_suffix() {
        let matcher = StringExpMatcherPlugin::suffix("domain", ".com");
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "example.com".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_string_exp_contains() {
        let matcher = StringExpMatcherPlugin::contains("domain", "example");
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "www.example.com".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_string_exp_regex() {
        let regex = Regex::new(r"^[a-z]+\.com$").unwrap();
        let matcher = StringExpMatcherPlugin::new("domain", StringExpression::Regex(regex));
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "example.com".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_string_exp_regex_no_match() {
        let regex = Regex::new(r"^[a-z]+\.com$").unwrap();
        let matcher = StringExpMatcherPlugin::new("domain", StringExpression::Regex(regex));
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "example.net".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_string_exp_missing_metadata() {
        let matcher = StringExpMatcherPlugin::exact("missing", "value");
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("string_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_string_exp_custom_result_key() {
        let matcher = StringExpMatcherPlugin::exact("domain", "example.com")
            .with_result_key("my_result".to_string());
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("domain".to_string(), "example.com".to_string());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("my_result").unwrap();
        assert!(*matched);
    }
}
