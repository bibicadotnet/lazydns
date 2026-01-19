use crate::{
    RegisterExecPlugin, Result,
    plugin::{Context, ExecPlugin, Plugin, RETURN_FLAG},
};
use async_trait::async_trait;
use std::sync::Arc;

/// Accept plugin - accepts the current response and stops execution
#[derive(Debug, Default, Clone, Copy, RegisterExecPlugin)]
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

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }
}

impl ExecPlugin for AcceptPlugin {
    fn quick_setup(prefix: &str, _exec_str: &str) -> Result<Arc<dyn Plugin>> {
        if prefix != "accept" {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected 'accept'",
                prefix
            )));
        }

        Ok(Arc::new(AcceptPlugin::new()))
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

    #[test]
    fn test_accept_plugin_debug() {
        let plugin = AcceptPlugin::new();
        let debug_str = format!("{:?}", plugin);
        assert!(debug_str.contains("AcceptPlugin"));
    }

    #[test]
    fn test_accept_plugin_default() {
        let plugin = AcceptPlugin::new();
        assert_eq!(plugin.name(), "accept");
    }

    #[test]
    fn test_accept_quick_setup() {
        let plugin = AcceptPlugin::quick_setup("accept", "").unwrap();
        assert_eq!(plugin.name(), "accept");
    }

    #[test]
    fn test_accept_quick_setup_invalid_prefix() {
        let result = AcceptPlugin::quick_setup("invalid", "");
        assert!(result.is_err());
    }
}
