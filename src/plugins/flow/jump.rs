use crate::plugin::{Context, ExecPlugin, Plugin, RETURN_FLAG};
use crate::Result;
use std::sync::Arc;

// Auto-register exec factory only (no init factory implementation provided)
crate::register_exec_plugin_builder!(JumpPlugin);
use async_trait::async_trait;

#[derive(Debug, Clone)]
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
}
