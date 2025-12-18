use crate::plugin::Plugin;
use async_trait::async_trait;

#[derive(Debug, Clone)]
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
