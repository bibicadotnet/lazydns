use crate::plugin::traits::PluginBuilder;
use crate::plugin::{Context, Plugin, RETURN_FLAG};
use async_trait::async_trait;
use serde_yaml::Value;
use std::sync::Arc;

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

    fn create(config: &PluginConfig) -> crate::Result<Arc<dyn Plugin>> {
        let args = config.effective_args();

        let target = match args.get("target") {
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(crate::Error::Config("target must be a string".to_string())),
            None => {
                return Err(crate::Error::Config(
                    "target is required for jump plugin".to_string(),
                ))
            }
        };

        Ok(Arc::new(JumpPlugin::new(target)))
    }
    
    async fn execute(&self, ctx: &mut Context) -> crate::Result<()> {
        ctx.set_metadata("jump_target", self.target.clone());
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
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

use crate::config::types::PluginConfig;

impl PluginBuilder for JumpPlugin {
    fn create(config: &PluginConfig) -> crate::Result<Arc<dyn Plugin>> {
        let args = config.effective_args();

        let target = match args.get("target") {
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(crate::Error::Config("target must be a string".to_string())),
            None => {
                return Err(crate::Error::Config(
                    "target is required for jump plugin".to_string(),
                ))
            }
        };

        Ok(Arc::new(JumpPlugin::new(target)))
    }

    fn plugin_type() -> &'static str {
        "jump"
    }
}

crate::register_plugin_builder!(JumpPlugin);
