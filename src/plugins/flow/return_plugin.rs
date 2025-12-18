use crate::{
    config::PluginConfig,
    plugin::{Context, Plugin, RETURN_FLAG},
    Result,
};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Default, Clone, Copy)]
pub struct ReturnPlugin;

impl ReturnPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for ReturnPlugin {
    fn name(&self) -> &str {
        "return"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }

    fn create(_config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        Ok(Arc::new(ReturnPlugin::new()))
    }

    fn plugin_type() -> &'static str {
        "return"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use crate::plugin::Executor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_return_plugin_stops_execution() {
        #[derive(Debug)]
        struct Counter {
            counter: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl Plugin for Counter {
            async fn execute(&self, _ctx: &mut Context) -> crate::Result<()> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn name(&self) -> &str {
                "counter"
            }
        }

        let mut executor = Executor::new();
        executor.add_plugin(Arc::new(ReturnPlugin::new()));
        let counter = Arc::new(AtomicUsize::new(0));
        executor.add_plugin(Arc::new(Counter {
            counter: counter.clone(),
        }));

        let mut ctx = Context::new(Message::new());
        executor.execute(&mut ctx).await.unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(&true));
    }
}

crate::register_plugin_builder!(ReturnPlugin);
