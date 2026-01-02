use crate::{
    Result,
    plugin::{Context, ExecPlugin, Plugin, RETURN_FLAG},
};
use async_trait::async_trait;

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
}

#[async_trait]
impl ExecPlugin for ReturnPlugin {
    /// Parse exec string for return plugin: "return"
    ///
    /// Examples:
    /// - "return" - stops execution of the current sequence
    fn quick_setup(prefix: &str, exec_str: &str) -> Result<std::sync::Arc<dyn Plugin>> {
        if prefix != "return" {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected 'return'",
                prefix
            )));
        }

        // Return plugin doesn't take any arguments, just "return"
        if !exec_str.trim().is_empty() {
            return Err(crate::Error::Config(
                "return exec does not take any arguments".to_string(),
            ));
        }

        Ok(std::sync::Arc::new(ReturnPlugin::new()))
    }
}

// Auto-register exec plugin
crate::register_exec_plugin_builder!(ReturnPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use crate::plugin::Executor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[tokio::test]
    async fn test_exec_plugin_return() {
        let plugin = ReturnPlugin::quick_setup("return", "").unwrap();
        let mut ctx = Context::new(Message::new());

        plugin.execute(&mut ctx).await.unwrap();

        let return_flag = ctx.get_metadata::<bool>(RETURN_FLAG).unwrap();
        assert!(*return_flag);
    }

    #[tokio::test]
    async fn test_exec_plugin_invalid_prefix() {
        let result = ReturnPlugin::quick_setup("invalid", "");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_exec_plugin_with_args() {
        let result = ReturnPlugin::quick_setup("return", "some_arg");
        assert!(result.is_err());
    }
}
