//! Integer comparison matcher plugin
//!
//! Matches based on integer value comparisons (useful for metadata)

use crate::Result;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Comparison operator for integer matching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntComparison {
    /// Equal to
    Eq,
    /// Not equal to
    Ne,
    /// Greater than
    Gt,
    /// Greater than or equal to
    Ge,
    /// Less than
    Lt,
    /// Less than or equal to
    Le,
}

/// Plugin that matches based on integer value comparisons
///
/// This is useful for matching metadata values, TTLs, or other numeric properties.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::{BaseIntMatcherPlugin, IntComparison};
///
/// // Match if metadata value > 100
/// let matcher = BaseIntMatcherPlugin::new("query_count", IntComparison::Gt, 100);
///
/// // Match if TTL >= 300
/// let matcher = BaseIntMatcherPlugin::new("ttl", IntComparison::Ge, 300);
/// ```
pub struct BaseIntMatcherPlugin {
    /// Metadata key to check
    metadata_key: String,
    /// Comparison operator
    comparison: IntComparison,
    /// Value to compare against
    value: i64,
    /// Metadata key to set when matched
    result_key: String,
}

impl BaseIntMatcherPlugin {
    /// Create a new integer comparison matcher
    pub fn new(metadata_key: impl Into<String>, comparison: IntComparison, value: i64) -> Self {
        Self {
            metadata_key: metadata_key.into(),
            comparison,
            value,
            result_key: "int_matched".to_string(),
        }
    }

    /// Set custom result metadata key
    pub fn with_result_key(mut self, key: String) -> Self {
        self.result_key = key;
        self
    }

    /// Perform the comparison
    fn compare(&self, actual: i64) -> bool {
        match self.comparison {
            IntComparison::Eq => actual == self.value,
            IntComparison::Ne => actual != self.value,
            IntComparison::Gt => actual > self.value,
            IntComparison::Ge => actual >= self.value,
            IntComparison::Lt => actual < self.value,
            IntComparison::Le => actual <= self.value,
        }
    }
}

impl fmt::Debug for BaseIntMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseIntMatcherPlugin")
            .field("metadata_key", &self.metadata_key)
            .field("comparison", &self.comparison)
            .field("value", &self.value)
            .field("result_key", &self.result_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for BaseIntMatcherPlugin {
    fn name(&self) -> &str {
        "base_int"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Try to get integer value from metadata
        let matched = if let Some(actual) = ctx.get_metadata::<i64>(&self.metadata_key) {
            let result = self.compare(*actual);

            if result {
                debug!(
                    key = %self.metadata_key,
                    actual = actual,
                    comparison = ?self.comparison,
                    expected = self.value,
                    "Integer matcher: matched"
                );
            } else {
                debug!(
                    key = %self.metadata_key,
                    actual = actual,
                    comparison = ?self.comparison,
                    expected = self.value,
                    "Integer matcher: no match"
                );
            }

            result
        } else {
            debug!(
                key = %self.metadata_key,
                "Integer matcher: metadata key not found"
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
    async fn test_base_int_eq() {
        let matcher = BaseIntMatcherPlugin::new("count", IntComparison::Eq, 42);
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("count".to_string(), 42i64);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_base_int_ne() {
        let matcher = BaseIntMatcherPlugin::new("count", IntComparison::Ne, 42);
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("count".to_string(), 100i64);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_base_int_gt() {
        let matcher = BaseIntMatcherPlugin::new("ttl", IntComparison::Gt, 100);
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("ttl".to_string(), 300i64);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_base_int_ge() {
        let matcher = BaseIntMatcherPlugin::new("value", IntComparison::Ge, 100);

        // Test equal
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("value".to_string(), 100i64);
        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);

        // Test greater
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("value".to_string(), 200i64);
        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_base_int_lt() {
        let matcher = BaseIntMatcherPlugin::new("size", IntComparison::Lt, 1000);
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("size".to_string(), 500i64);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_base_int_le() {
        let matcher = BaseIntMatcherPlugin::new("value", IntComparison::Le, 100);

        // Test equal
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("value".to_string(), 100i64);
        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);

        // Test less
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("value".to_string(), 50i64);
        matcher.execute(&mut ctx).await.unwrap();
        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_base_int_no_match() {
        let matcher = BaseIntMatcherPlugin::new("count", IntComparison::Eq, 42);
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("size".to_string(), 500i64);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_base_int_missing_metadata() {
        let matcher = BaseIntMatcherPlugin::new("missing", IntComparison::Eq, 42);
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("int_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_base_int_custom_result_key() {
        let matcher = BaseIntMatcherPlugin::new("count", IntComparison::Eq, 42)
            .with_result_key("my_result".to_string());
        let mut ctx = Context::new(Message::new());
        ctx.set_metadata("count".to_string(), 42i64);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("my_result").unwrap();
        assert!(*matched);
    }
}
