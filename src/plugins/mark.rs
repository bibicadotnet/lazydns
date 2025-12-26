//! Mark plugin
//!
//! Generic marking/tagging plugin for labeling queries and responses

use crate::Result;
use crate::config::PluginConfig;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;
use tracing::debug;

/// Plugin that adds marks/tags to the context
///
/// Marks are arbitrary metadata that can be set and checked by other plugins.
/// This is useful for implementing complex routing logic.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::MarkPlugin;
///
/// // Set a simple mark
/// let plugin = MarkPlugin::new("high_priority");
///
/// // Set a mark with a value
/// let plugin = MarkPlugin::with_value("priority", "100");
/// ```
pub struct MarkPlugin {
    /// Mark name/key
    mark_name: String,
    /// Optional mark value (if None, sets boolean true)
    mark_value: Option<String>,
}

impl MarkPlugin {
    /// Create a new mark plugin that sets a boolean mark
    pub fn new(mark_name: impl Into<String>) -> Self {
        Self {
            mark_name: mark_name.into(),
            mark_value: None,
        }
    }

    /// Create a mark plugin that sets a string value
    pub fn with_value(mark_name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            mark_name: mark_name.into(),
            mark_value: Some(value.into()),
        }
    }
}

impl fmt::Debug for MarkPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MarkPlugin")
            .field("mark_name", &self.mark_name)
            .field("mark_value", &self.mark_value)
            .finish()
    }
}

#[async_trait]
impl Plugin for MarkPlugin {
    fn name(&self) -> &str {
        "mark"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if let Some(value) = &self.mark_value {
            debug!(
                mark = %self.mark_name,
                value = %value,
                "Setting mark with value"
            );
            ctx.set_metadata(self.mark_name.clone(), value.clone());
        } else {
            debug!(
                mark = %self.mark_name,
                "Setting mark"
            );
            ctx.set_metadata(self.mark_name.clone(), true);
        }

        Ok(())
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();
        use serde_yaml::Value;

        // Parse mark_name parameter (required)
        let mark_name = match args.get("name") {
            Some(Value::String(name)) => name.clone(),
            Some(_) => {
                return Err(crate::Error::Config(
                    "mark name must be a string".to_string(),
                ));
            }
            None => return Err(crate::Error::Config("mark name is required".to_string())),
        };

        // Parse value parameter (optional)
        let mark_value = match args.get("value") {
            Some(Value::String(val)) => Some(val.clone()),
            Some(_) => {
                return Err(crate::Error::Config(
                    "mark value must be a string".to_string(),
                ));
            }
            None => None,
        };

        let plugin = if let Some(value) = mark_value {
            MarkPlugin::with_value(mark_name, value)
        } else {
            MarkPlugin::new(mark_name)
        };

        Ok(Arc::new(plugin))
    }
}

// Auto-register using the register macro
crate::register_plugin_builder!(MarkPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_mark_boolean() {
        let plugin = MarkPlugin::new("test_mark");
        let mut ctx = Context::new(Message::new());

        plugin.execute(&mut ctx).await.unwrap();

        let mark = ctx.get_metadata::<bool>("test_mark").unwrap();
        assert!(*mark);
    }

    #[tokio::test]
    async fn test_mark_with_value() {
        let plugin = MarkPlugin::with_value("priority", "high");
        let mut ctx = Context::new(Message::new());

        plugin.execute(&mut ctx).await.unwrap();

        let value = ctx.get_metadata::<String>("priority").unwrap();
        assert_eq!(value.as_str(), "high");
    }

    #[tokio::test]
    async fn test_mark_overwrite() {
        let plugin1 = MarkPlugin::with_value("status", "pending");
        let plugin2 = MarkPlugin::with_value("status", "approved");
        let mut ctx = Context::new(Message::new());

        plugin1.execute(&mut ctx).await.unwrap();
        let value = ctx.get_metadata::<String>("status").unwrap();
        assert_eq!(value.as_str(), "pending");

        plugin2.execute(&mut ctx).await.unwrap();
        let value = ctx.get_metadata::<String>("status").unwrap();
        assert_eq!(value.as_str(), "approved");
    }

    #[tokio::test]
    async fn test_multiple_marks() {
        let plugin1 = MarkPlugin::new("mark1");
        let plugin2 = MarkPlugin::new("mark2");
        let plugin3 = MarkPlugin::with_value("mark3", "value3");
        let mut ctx = Context::new(Message::new());

        plugin1.execute(&mut ctx).await.unwrap();
        plugin2.execute(&mut ctx).await.unwrap();
        plugin3.execute(&mut ctx).await.unwrap();

        assert!(ctx.get_metadata::<bool>("mark1").is_some());
        assert!(ctx.get_metadata::<bool>("mark2").is_some());
        assert!(ctx.get_metadata::<String>("mark3").is_some());
    }
}
