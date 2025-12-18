use crate::plugin::Plugin;
use async_trait::async_trait;
use std::sync::Arc;

pub struct IfPlugin {
    condition: Arc<dyn Fn(&crate::plugin::Context) -> bool + Send + Sync>,
    inner: Arc<dyn Plugin>,
}

impl std::fmt::Debug for IfPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IfPlugin").finish()
    }
}

impl IfPlugin {
    pub fn new(
        condition: Arc<dyn Fn(&crate::plugin::Context) -> bool + Send + Sync>,
        inner: Arc<dyn Plugin>,
    ) -> Self {
        Self { condition, inner }
    }
}

#[async_trait]
impl Plugin for IfPlugin {
    async fn execute(&self, ctx: &mut crate::plugin::Context) -> crate::Result<()> {
        if (self.condition)(ctx) {
            self.inner.execute(ctx).await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "if"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_if_plugin_executes_conditionally() {
        #[derive(Debug)]
        struct FlagSetter;

        #[async_trait]
        impl Plugin for FlagSetter {
            async fn execute(&self, ctx: &mut crate::plugin::Context) -> crate::Result<()> {
                ctx.set_metadata("flag", true);
                Ok(())
            }

            fn name(&self) -> &str {
                "flag"
            }
        }

        let inner = Arc::new(FlagSetter);
        let cond = Arc::new(|_ctx: &crate::plugin::Context| true);
        let plugin = IfPlugin::new(cond, inner);

        let mut ctx = crate::plugin::Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();
        assert_eq!(ctx.get_metadata::<bool>("flag"), Some(&true));
    }
}
