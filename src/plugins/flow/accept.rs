use crate::{
    plugin::{Context, Plugin, RETURN_FLAG},
    Result,
};
use async_trait::async_trait;

/// Accept plugin - accepts the current response and stops execution
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptPlugin;

impl AcceptPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for AcceptPlugin {
    fn name(&self) -> &str {
        "accept"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_metadata(RETURN_FLAG, true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_accept_plugin() {
        let plugin = AcceptPlugin::new();
        assert_eq!(plugin.name(), "accept");

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        assert_eq!(ctx.get_metadata::<bool>(RETURN_FLAG), Some(&true));
    }
}
