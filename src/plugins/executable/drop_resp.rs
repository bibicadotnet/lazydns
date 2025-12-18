use std::sync::Arc;

use crate::config::PluginConfig;
use crate::plugin::{Context, Plugin, PluginBuilder};
use crate::Result;
use async_trait::async_trait;

/// Plugin that clears any existing response from the execution `Context`.
///
/// This is a lightweight control-flow helper used in sequences or other
/// composite plugins when you want to discard a previously-set response
/// and continue processing with subsequent plugins.
///
/// Example:
///
/// ```rust
/// use lazydns::plugins::executable::drop_resp::DropRespPlugin;
/// use lazydns::plugin::Context;
///
/// let plugin = DropRespPlugin::new();
/// // in executor: plugin.execute(&mut ctx).await? will clear ctx.response()
/// ```
#[derive(Debug, Default)]
pub struct DropRespPlugin;

impl DropRespPlugin {
    /// Create a new `DropRespPlugin` instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for DropRespPlugin {
    /// Return the canonical plugin name `drop_resp`.
    fn name(&self) -> &str {
        "drop_resp"
    }

    /// Execute the plugin: clear any response currently stored in the
    /// `Context` so subsequent plugins see an empty response state.
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_response(None);
        Ok(())
    }
}

/// Implement PluginBuilder for DropRespPlugin
impl PluginBuilder for DropRespPlugin {
    fn create(_config: &PluginConfig) -> crate::Result<Arc<dyn Plugin>> {
        Ok(Arc::new(DropRespPlugin::new()))
    }

    fn plugin_type() -> &'static str {
        "drop_resp"
    }
}

crate::register_plugin_builder!(DropRespPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_drop_resp() {
        let plugin = DropRespPlugin;
        let req = Message::new();
        let mut ctx = Context::new(req);
        ctx.set_response(Some(Message::new()));
        plugin.execute(&mut ctx).await.unwrap();
        assert!(!ctx.has_response());
    }
}
