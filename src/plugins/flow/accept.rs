use crate::plugin::traits::PluginBuilder;
use crate::plugin::{Context, Plugin, RETURN_FLAG};
use async_trait::async_trait;
use std::sync::Arc;

/// Accept plugin - accepts the current response and stops execution
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptPlugin;

impl AcceptPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for AcceptPlugin {
    fn name(&self) -> &str {
        "accept"
    }

    async fn execute(&self, ctx: &mut Context) -> crate::Result<()> {
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_accept_plugin() {
        let plugin = AcceptPlugin::new();
        assert_eq!(plugin.name(), "accept");

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert_eq!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(&true));
    }
}

// ============================================================================
// Plugin Factory Registration
// ============================================================================

use crate::config::types::PluginConfig;

impl PluginBuilder for AcceptPlugin {
    fn create(_config: &PluginConfig) -> crate::Result<Arc<dyn Plugin>> {
        Ok(Arc::new(AcceptPlugin::new()))
    }

    fn plugin_type() -> &'static str {
        "accept"
    }
}

crate::register_plugin_builder!(AcceptPlugin);
