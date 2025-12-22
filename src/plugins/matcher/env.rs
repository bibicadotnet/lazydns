//! Environment variable matcher plugin
//!
//! Matches based on environment variable values

use crate::Result;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::fmt;
use tracing::debug;

/// Plugin that matches based on environment variable values
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::EnvMatcherPlugin;
///
/// // Match if ENV_VAR equals "value"
/// let matcher = EnvMatcherPlugin::new("ENV_VAR", "value");
///
/// // Check if environment variable exists
/// let matcher = EnvMatcherPlugin::exists("MY_VAR");
/// ```
pub struct EnvMatcherPlugin {
    /// Environment variable name
    var_name: String,
    /// Expected value (None means just check existence)
    expected_value: Option<String>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl EnvMatcherPlugin {
    /// Create a new environment matcher that checks for exact value
    pub fn new(var_name: impl Into<String>, expected_value: impl Into<String>) -> Self {
        Self {
            var_name: var_name.into(),
            expected_value: Some(expected_value.into()),
            metadata_key: "env_matched".to_string(),
        }
    }

    /// Create an environment matcher that just checks existence
    pub fn exists(var_name: impl Into<String>) -> Self {
        Self {
            var_name: var_name.into(),
            expected_value: None,
            metadata_key: "env_matched".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if environment variable matches
    fn check_match(&self) -> bool {
        match std::env::var(&self.var_name) {
            Ok(value) => {
                if let Some(expected) = &self.expected_value {
                    value == *expected
                } else {
                    // Just checking existence
                    true
                }
            }
            Err(_) => false,
        }
    }
}

impl fmt::Debug for EnvMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvMatcherPlugin")
            .field("var_name", &self.var_name)
            .field("expected_value", &self.expected_value)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for EnvMatcherPlugin {
    fn name(&self) -> &str {
        "env_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let matched = self.check_match();

        if matched {
            debug!(
                var = %self.var_name,
                "Environment matcher: matched"
            );
        } else {
            debug!(
                var = %self.var_name,
                "Environment matcher: no match"
            );
        }

        ctx.set_metadata(self.metadata_key.clone(), matched);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_env_matcher_exact() {
        let var = "TEST_VAR_EXACT";
        unsafe {
            std::env::set_var(var, "test_value");
        }

        let matcher = EnvMatcherPlugin::new(var, "test_value");
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("env_matched").unwrap();
        assert!(*matched);

        unsafe {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn test_env_matcher_no_match() {
        let var = "TEST_VAR_NO_MATCH";
        unsafe {
            std::env::set_var(var, "wrong_value");
        }

        let matcher = EnvMatcherPlugin::new(var, "expected_value");
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("env_matched").unwrap();
        assert!(!(*matched));

        unsafe {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn test_env_matcher_exists() {
        let var = "TEST_VAR_EXISTS";
        unsafe {
            std::env::set_var(var, "any_value");
        }

        let matcher = EnvMatcherPlugin::exists(var);
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("env_matched").unwrap();
        assert!(*matched);

        unsafe {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn test_env_matcher_not_exists() {
        let var = "NONEXISTENT_VAR_ENV_MATCHER";
        unsafe {
            std::env::remove_var(var);
        }

        let matcher = EnvMatcherPlugin::exists(var);
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("env_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_env_matcher_custom_key() {
        let var = "TEST_VAR_CUSTOM_KEY";
        unsafe {
            std::env::set_var(var, "value");
        }

        let matcher =
            EnvMatcherPlugin::new(var, "value").with_metadata_key("my_env_key".to_string());
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("my_env_key").unwrap();
        assert!(*matched);

        unsafe {
            std::env::remove_var(var);
        }
    }
}
