use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;

#[derive(Debug, Default)]
pub struct DropRespPlugin;

#[async_trait]
impl Plugin for DropRespPlugin {
    fn name(&self) -> &str {
        "drop_resp"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        ctx.set_response(None);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_drop_resp() {
        let plugin = DropRespPlugin;
        let req = Message::new();
        let mut ctx = Context::new(req);
        ctx.set_response(Some(Message::new()));
        plugin.execute(&mut ctx).await.unwrap();
        assert!(!ctx.has_response());
    }
}
