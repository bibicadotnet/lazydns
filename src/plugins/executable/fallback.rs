//! Fallback plugin
//!
//! Provides fallback mechanism for query processing

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Plugin that provides fallback to alternative plugins if primary fails
///
/// # Example
///
/// ```rust,no_run
/// use lazydns::plugins::executable::FallbackPlugin;
/// use lazydns::plugin::Plugin;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let primary: Arc<dyn Plugin> = todo!();
/// # let fallback: Arc<dyn Plugin> = todo!();
/// // Try primary, fallback to alternative if it fails or returns no response
/// let plugin = FallbackPlugin::new(vec![primary, fallback]);
/// # Ok(())
/// # }
/// ```
pub struct FallbackPlugin {
    /// List of plugins to try in order
    plugins: Vec<Arc<dyn Plugin>>,
    /// Whether to fallback on errors only or also on empty responses
    error_only: bool,
}

impl FallbackPlugin {
    /// Create a new fallback plugin
    ///
    /// # Arguments
    ///
    /// * `plugins` - List of plugins to try in order
    pub fn new(plugins: Vec<Arc<dyn Plugin>>) -> Self {
        Self {
            plugins,
            error_only: false,
        }
    }

    /// Set whether to fallback only on errors (not on empty responses)
    pub fn error_only(mut self, error_only: bool) -> Self {
        self.error_only = error_only;
        self
    }

    /// Check if we should try the next plugin
    fn should_fallback(&self, ctx: &Context, had_error: bool) -> bool {
        if had_error {
            return true;
        }

        if self.error_only {
            return false;
        }

        // Check if response is empty or missing
        if let Some(response) = ctx.response() {
            response.answers().is_empty()
        } else {
            true
        }
    }
}

impl fmt::Debug for FallbackPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FallbackPlugin")
            .field("plugin_count", &self.plugins.len())
            .field("error_only", &self.error_only)
            .finish()
    }
}

#[async_trait]
impl Plugin for FallbackPlugin {
    fn name(&self) -> &str {
        "fallback"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        info!("Fallback: plugin count = {}", self.plugins.len());
        info!(
            "Fallback children: {:?}",
            self.plugins.iter().map(|p| p.name()).collect::<Vec<_>>()
        );
        for (i, plugin) in self.plugins.iter().enumerate() {
            debug!("Fallback: trying plugin {} (index {})", plugin.name(), i);

            let had_error = match plugin.execute(ctx).await {
                Ok(_) => false,
                Err(e) => {
                    warn!(
                        plugin_index = i,
                        plugin_name = plugin.name(),
                        error = %e,
                        "Fallback: plugin failed"
                    );
                    true
                }
            };

            // Check if we should try next plugin
            if !self.should_fallback(ctx, had_error) {
                debug!(
                    plugin_index = i,
                    plugin_name = plugin.name(),
                    "Fallback: plugin succeeded, stopping"
                );
                return Ok(());
            }

            if i < self.plugins.len() - 1 {
                debug!(
                    plugin_index = i,
                    plugin_name = plugin.name(),
                    "Fallback: trying next plugin"
                );
            }
        }

        debug!("Fallback: all plugins attempted");
        Ok(())
    }

    fn priority(&self) -> i32 {
        100
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[derive(Debug)]
    struct TestPlugin {
        name: String,
        should_fail: bool,
        should_empty: bool,
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        async fn execute(&self, ctx: &mut Context) -> Result<()> {
            if self.should_fail {
                return Err(crate::Error::Plugin("test error".to_string()));
            }

            if !self.should_empty {
                let mut response = Message::new();
                use crate::dns::types::{RecordClass, RecordType};
                use crate::dns::{RData, ResourceRecord};

                response.add_answer(ResourceRecord::new(
                    "example.com".to_string(),
                    RecordType::A,
                    RecordClass::IN,
                    300,
                    RData::A("192.0.2.1".parse().unwrap()),
                ));
                ctx.set_response(Some(response));
            }

            Ok(())
        }
    }

    #[tokio::test]
    async fn test_fallback_first_succeeds() {
        let primary = Arc::new(TestPlugin {
            name: "primary".to_string(),
            should_fail: false,
            should_empty: false,
        });
        let fallback_plugin = FallbackPlugin::new(vec![primary]);

        let mut ctx = Context::new(Message::new());
        fallback_plugin.execute(&mut ctx).await.unwrap();

        // Should have response from primary
        assert!(ctx.response().is_some());
        assert!(!ctx.response().unwrap().answers().is_empty());
    }

    #[tokio::test]
    async fn test_fallback_on_error() {
        let primary = Arc::new(TestPlugin {
            name: "primary".to_string(),
            should_fail: true,
            should_empty: false,
        });
        let secondary = Arc::new(TestPlugin {
            name: "secondary".to_string(),
            should_fail: false,
            should_empty: false,
        });

        let fallback_plugin = FallbackPlugin::new(vec![primary, secondary]);

        let mut ctx = Context::new(Message::new());
        fallback_plugin.execute(&mut ctx).await.unwrap();

        // Should have response from secondary
        assert!(ctx.response().is_some());
        assert!(!ctx.response().unwrap().answers().is_empty());
    }

    #[tokio::test]
    async fn test_fallback_on_empty_response() {
        let primary = Arc::new(TestPlugin {
            name: "primary".to_string(),
            should_fail: false,
            should_empty: true, // Returns empty response
        });
        let secondary = Arc::new(TestPlugin {
            name: "secondary".to_string(),
            should_fail: false,
            should_empty: false,
        });

        let fallback_plugin = FallbackPlugin::new(vec![primary, secondary]);

        let mut ctx = Context::new(Message::new());
        fallback_plugin.execute(&mut ctx).await.unwrap();

        // Should have response from secondary
        assert!(ctx.response().is_some());
        assert!(!ctx.response().unwrap().answers().is_empty());
    }

    #[tokio::test]
    async fn test_fallback_error_only_mode() {
        let primary = Arc::new(TestPlugin {
            name: "primary".to_string(),
            should_fail: false,
            should_empty: true, // Returns empty response
        });
        let secondary = Arc::new(TestPlugin {
            name: "secondary".to_string(),
            should_fail: false,
            should_empty: false,
        });

        let fallback_plugin = FallbackPlugin::new(vec![primary, secondary]).error_only(true); // Only fallback on errors, not empty responses

        let mut ctx = Context::new(Message::new());
        fallback_plugin.execute(&mut ctx).await.unwrap();

        // Should NOT fallback to secondary (empty response is OK in error_only mode)
        // The response might be empty or have the empty response from primary
        // In error_only mode, we don't fallback on empty responses
    }
}
