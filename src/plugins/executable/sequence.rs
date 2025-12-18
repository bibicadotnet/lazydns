//! Sequence executor plugin (executable wrapper)
//!
//! This module provides the `SequencePlugin` used by the runtime to execute
//! a sequential list of plugins. It is extracted here from the larger
//! `plugins::advanced` module so it can be reused by executable/plugin
//! composition code and documented independently.

use crate::plugin::{Context, Plugin, RETURN_FLAG};
use crate::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::trace;

// Plugin builder registration for SequencePlugin
// Full sequence parsing with conditions is complex
// and should be handled by the builder system.
// crate::register_plugin_builder!(SequencePlugin);

/// A sequential execution step for `SequencePlugin`.
pub enum SequenceStep {
    /// Execute a plugin unconditionally
    Exec(Arc<dyn Plugin>),
    /// Execute a plugin conditionally
    If {
        /// Condition invoked with current `Context`
        condition: Arc<dyn Fn(&Context) -> bool + Send + Sync>,
        /// Plugin to execute when condition is true
        action: Arc<dyn Plugin>,
        /// Human-readable condition description (for tracing)
        desc: String,
    },
}

impl std::fmt::Debug for SequenceStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SequenceStep::Exec(plugin) => f.debug_tuple("Exec").field(plugin).finish(),
            SequenceStep::If { action, desc, .. } => f
                .debug_struct("If")
                .field("action", action)
                .field("cond", desc)
                .finish(),
        }
    }
}

/// Executes a sequence of plugins in order.
#[derive(Debug)]
pub struct SequencePlugin {
    steps: Vec<SequenceStep>,
}

impl SequencePlugin {
    /// Create a new sequence plugin from a simple list of plugins.
    pub fn new(plugins: Vec<Arc<dyn Plugin>>) -> Self {
        let steps = plugins.into_iter().map(SequenceStep::Exec).collect();
        Self { steps }
    }

    /// Create a sequence plugin with explicit steps (including conditional steps).
    pub fn with_steps(steps: Vec<SequenceStep>) -> Self {
        Self { steps }
    }
}

#[async_trait]
impl Plugin for SequencePlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        for step in &self.steps {
            match step {
                SequenceStep::Exec(plugin) => {
                    trace!(plugin = plugin.name(), "Sequence: executing plugin (exec)");
                    match plugin.execute(ctx).await {
                        Ok(_) => trace!(plugin = plugin.name(), "Sequence: exec succeeded"),
                        Err(e) => {
                            trace!(plugin = plugin.name(), error = %e, "Sequence: exec failed");
                            return Err(e);
                        }
                    }
                }
                SequenceStep::If {
                    condition,
                    action,
                    desc,
                } => {
                    let cond = condition(ctx);
                    trace!(condition = %desc, result = cond, plugin = action.name(), "Sequence: conditional step evaluated");
                    if cond {
                        trace!(plugin = action.name(), condition = %desc, "Sequence: executing conditional action");
                        match action.execute(ctx).await {
                            Ok(_) => {
                                trace!(plugin = action.name(), condition = %desc, "Sequence: conditional action succeeded")
                            }
                            Err(e) => {
                                trace!(plugin = action.name(), condition = %desc, error = %e, "Sequence: conditional action failed");
                                return Err(e);
                            }
                        }
                    }
                }
            }

            // If a plugin set the return flag, stop executing further steps.
            if matches!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(true)) {
                break;
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "sequence"
    }

    fn init(config: &crate::config::PluginConfig) -> Result<std::sync::Arc<dyn Plugin>> {
        // For now, implement a simple sequence that expects a "plugins" array
        // with plugin names. Full sequence parsing with conditions is complex
        // and should be handled by the builder system.
        let args = config.effective_args();

        if let Some(serde_yaml::Value::Sequence(_plugin_names)) = args.get("plugins") {
            // This is a simplified implementation - in practice, sequences with
            // plugin references need to be resolved later in the build process
            // For now, return an empty sequence that will be resolved later
            Ok(std::sync::Arc::new(Self::new(vec![])))
        } else {
            // Default to empty sequence
            Ok(std::sync::Arc::new(Self::new(vec![])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use crate::plugin::Context;
    use std::sync::Arc;

    #[tokio::test]
    async fn sequence_executes_in_order() {
        #[derive(Debug)]
        struct Recorder {
            order: Arc<std::sync::Mutex<Vec<&'static str>>>,
            label: &'static str,
        }

        #[async_trait]
        impl Plugin for Recorder {
            async fn execute(&self, ctx: &mut Context) -> Result<()> {
                ctx.set_metadata("seen", true);
                self.order.lock().unwrap().push(self.label);
                Ok(())
            }

            fn name(&self) -> &str {
                self.label
            }
        }

        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seq = SequencePlugin::new(vec![
            Arc::new(Recorder {
                order: order.clone(),
                label: "one",
            }),
            Arc::new(Recorder {
                order: order.clone(),
                label: "two",
            }),
        ]);

        let mut ctx = Context::new(Message::new());
        seq.execute(&mut ctx).await.unwrap();

        let logged = order.lock().unwrap().clone();
        assert_eq!(logged, vec!["one", "two"]);
    }
}
