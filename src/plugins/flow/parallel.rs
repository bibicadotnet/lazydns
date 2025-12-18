use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ParallelPlugin {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl ParallelPlugin {
    pub fn new(plugins: Vec<Arc<dyn Plugin>>) -> Self {
        Self { plugins }
    }
}

#[async_trait]
impl Plugin for ParallelPlugin {
    async fn execute(&self, ctx: &mut Context) -> crate::Result<()> {
        run_plugins(&self.plugins, ctx, true, true).await
    }

    fn name(&self) -> &str {
        "parallel"
    }
}

async fn run_plugins(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut Context,
    stop_on_return: bool,
    stop_on_response: bool,
) -> crate::Result<()> {
    for plugin in plugins {
        plugin.execute(ctx).await?;
        if stop_on_return
            && matches!(
                ctx.get_metadata::<bool>(crate::plugin::RETURN_FLAG),
                Some(true)
            )
        {
            break;
        }
        if stop_on_response && ctx.has_response() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_parallel_plugin_stops_on_response() {
        #[derive(Debug)]
        struct Responder;

        #[async_trait]
        impl Plugin for Responder {
            async fn execute(&self, ctx: &mut Context) -> crate::Result<()> {
                let mut resp = Message::new();
                resp.set_response(true);
                ctx.set_response(Some(resp));
                Ok(())
            }

            fn name(&self) -> &str {
                "responder"
            }
        }

        #[derive(Debug)]
        struct ShouldNotRun {
            hit: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl Plugin for ShouldNotRun {
            async fn execute(&self, _ctx: &mut Context) -> crate::Result<()> {
                self.hit.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn name(&self) -> &str {
                "after"
            }
        }

        let hit = Arc::new(AtomicUsize::new(0));
        let plugin = ParallelPlugin::new(vec![
            Arc::new(Responder),
            Arc::new(ShouldNotRun { hit: hit.clone() }),
        ]);

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert!(ctx.has_response());
        assert_eq!(hit.load(Ordering::SeqCst), 0);
    }
}
