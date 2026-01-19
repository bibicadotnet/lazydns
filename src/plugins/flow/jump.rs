use crate::plugin::{Context, ExecPlugin, Plugin, RETURN_FLAG};
use crate::{RegisterExecPlugin, Result};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone, RegisterExecPlugin)]
pub struct JumpPlugin {
    target: String,
}

impl JumpPlugin {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
        }
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

#[async_trait]
impl Plugin for JumpPlugin {
    fn name(&self) -> &str {
        "jump"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_metadata("jump_target", self.target.clone());
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }
}

impl ExecPlugin for JumpPlugin {
    fn quick_setup(prefix: &str, exec_str: &str) -> Result<Arc<dyn Plugin>> {
        if prefix != "jump" {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected 'jump'",
                prefix
            )));
        }

        let target = exec_str.trim();
        if target.is_empty() {
            return Err(crate::Error::Config(
                "jump exec requires a target argument".to_string(),
            ));
        }

        Ok(Arc::new(JumpPlugin::new(target)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[test]
    fn test_jump_new() {
        let plugin = JumpPlugin::new("target");
        assert_eq!(plugin.target(), "target");
    }

    #[test]
    fn test_jump_name() {
        let plugin = JumpPlugin::new("label");
        assert_eq!(plugin.name(), "jump");
    }

    #[test]
    fn test_jump_debug() {
        let plugin = JumpPlugin::new("test_target");
        let debug_str = format!("{:?}", plugin);
        assert!(debug_str.contains("JumpPlugin"));
        assert!(debug_str.contains("test_target"));
    }

    #[tokio::test]
    async fn test_jump_plugin() {
        let plugin = JumpPlugin::new("gfw-list");
        assert_eq!(plugin.name(), "jump");
        assert_eq!(plugin.target(), "gfw-list");

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert_eq!(
            ctx.get_metadata::<String>("jump_target"),
            Some(&"gfw-list".to_string())
        );
    }

    #[tokio::test]
    async fn test_jump_sets_return_flag() {
        let plugin = JumpPlugin::new("target");
        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert_eq!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(&true));
    }

    #[test]
    fn test_jump_quick_setup() {
        let plugin = <JumpPlugin as ExecPlugin>::quick_setup("jump", "my_target").unwrap();
        assert_eq!(plugin.name(), "jump");
    }

    #[test]
    fn test_jump_quick_setup_wrong_prefix() {
        let result = <JumpPlugin as ExecPlugin>::quick_setup("wrong", "target");
        assert!(result.is_err());
    }

    #[test]
    fn test_jump_quick_setup_empty_target() {
        let result = <JumpPlugin as ExecPlugin>::quick_setup("jump", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_jump_quick_setup_whitespace_only() {
        let result = <JumpPlugin as ExecPlugin>::quick_setup("jump", "   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_jump_quick_setup_trims_whitespace() {
        let plugin = <JumpPlugin as ExecPlugin>::quick_setup("jump", "  my_target  ").unwrap();
        assert_eq!(plugin.name(), "jump");
    }
}
