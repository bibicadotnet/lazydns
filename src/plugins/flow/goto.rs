use crate::RegisterExecPlugin;
use crate::plugin::{ExecPlugin, Plugin};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone, RegisterExecPlugin)]
pub struct GotoPlugin {
    label: String,
}

impl GotoPlugin {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

#[async_trait]
impl Plugin for GotoPlugin {
    async fn execute(&self, ctx: &mut crate::plugin::Context) -> crate::Result<()> {
        ctx.set_metadata("goto_label", self.label.clone());
        ctx.set_metadata(crate::plugin::RETURN_FLAG, true);
        Ok(())
    }

    fn name(&self) -> &str {
        "goto"
    }
}

impl ExecPlugin for GotoPlugin {
    fn quick_setup(prefix: &str, exec_str: &str) -> crate::Result<Arc<dyn Plugin>> {
        if prefix != "goto" {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected 'goto'",
                prefix
            )));
        }

        if exec_str.trim().is_empty() {
            return Err(crate::Error::Config(
                "goto exec action requires a label argument".to_string(),
            ));
        }

        Ok(Arc::new(GotoPlugin::new(exec_str.trim())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_goto_sets_label_and_return() {
        let plugin = GotoPlugin::new("target");
        let mut ctx = crate::plugin::Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert_eq!(
            ctx.get_metadata::<String>("goto_label"),
            Some(&"target".into())
        );
        assert_eq!(
            ctx.get_metadata::<bool>(crate::plugin::RETURN_FLAG),
            Some(&true)
        );
    }
}
