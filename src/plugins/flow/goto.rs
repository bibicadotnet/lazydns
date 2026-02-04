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

    fn as_any(&self) -> &dyn std::any::Any {
        self
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

        let target = exec_str.trim();
        if target.is_empty() {
            return Err(crate::Error::Config(
                "goto exec action requires a label argument".to_string(),
            ));
        }

        // Strip leading $ if present (plugin reference: $plugin_name)
        let target_name = target.strip_prefix('$').unwrap_or(target);

        Ok(Arc::new(GotoPlugin::new(target_name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[test]
    fn test_goto_new() {
        let plugin = GotoPlugin::new("target");
        assert_eq!(plugin.label, "target");
    }

    #[test]
    fn test_goto_name() {
        let plugin = GotoPlugin::new("label");
        assert_eq!(plugin.name(), "goto");
    }

    #[test]
    fn test_goto_debug() {
        let plugin = GotoPlugin::new("test_label");
        let debug_str = format!("{:?}", plugin);
        assert!(debug_str.contains("GotoPlugin"));
        assert!(debug_str.contains("test_label"));
    }

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

    #[test]
    fn test_goto_quick_setup() {
        let plugin = <GotoPlugin as ExecPlugin>::quick_setup("goto", "my_label").unwrap();
        assert_eq!(plugin.name(), "goto");
    }

    #[test]
    fn test_goto_quick_setup_wrong_prefix() {
        let result = <GotoPlugin as ExecPlugin>::quick_setup("wrong", "label");
        assert!(result.is_err());
    }

    #[test]
    fn test_goto_quick_setup_empty_label() {
        let result = <GotoPlugin as ExecPlugin>::quick_setup("goto", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_goto_quick_setup_whitespace_only() {
        let result = <GotoPlugin as ExecPlugin>::quick_setup("goto", "   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_goto_quick_setup_trims_whitespace() {
        let plugin = <GotoPlugin as ExecPlugin>::quick_setup("goto", "  my_label  ").unwrap();
        assert_eq!(plugin.name(), "goto");
    }

    #[test]
    fn test_goto_quick_setup_strips_dollar_prefix() {
        let plugin = <GotoPlugin as ExecPlugin>::quick_setup("goto", "$sequence_gfwlist").unwrap();
        assert_eq!(plugin.name(), "goto");
        let gp = plugin.as_any().downcast_ref::<GotoPlugin>().unwrap();
        assert_eq!(gp.label, "sequence_gfwlist");
    }

    #[test]
    fn test_goto_quick_setup_strips_dollar_with_whitespace() {
        let plugin = <GotoPlugin as ExecPlugin>::quick_setup("goto", "  $my_sequence  ").unwrap();
        assert_eq!(plugin.name(), "goto");
        let gp = plugin.as_any().downcast_ref::<GotoPlugin>().unwrap();
        assert_eq!(gp.label, "my_sequence");
    }

    #[test]
    fn test_goto_quick_setup_accepts_label_without_dollar() {
        let plugin = <GotoPlugin as ExecPlugin>::quick_setup("goto", "label_name").unwrap();
        assert_eq!(plugin.name(), "goto");
        let gp = plugin.as_any().downcast_ref::<GotoPlugin>().unwrap();
        assert_eq!(gp.label, "label_name");
    }
}
