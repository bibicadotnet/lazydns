use crate::config::PluginConfig;
use crate::dns::{Message, ResponseCode};
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use serde_yaml::Value;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub struct RejectPlugin {
    rcode: u8,
}

impl RejectPlugin {
    pub fn new(rcode: u8) -> Self {
        Self { rcode }
    }

    pub fn nxdomain() -> Self {
        Self::new(3)
    }

    pub fn refused() -> Self {
        Self::new(5)
    }

    pub fn servfail() -> Self {
        Self::new(2)
    }
}

#[async_trait]
impl Plugin for RejectPlugin {
    fn name(&self) -> &str {
        "reject"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let mut response = Message::new();
        response.set_id(ctx.request().id());
        response.set_response_code(ResponseCode::from_u8(self.rcode));
        response.set_response(true);

        for question in ctx.request().questions() {
            response.add_question(question.clone());
        }

        ctx.set_response(Some(response));
        ctx.set_metadata(crate::plugin::RETURN_FLAG, true);
        Ok(())
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();

        let rcode = match args.get("rcode") {
            Some(Value::Number(n)) => n
                .as_i64()
                .ok_or_else(|| crate::Error::Config("Invalid rcode value".to_string()))?
                as u8,
            Some(_) => return Err(crate::Error::Config("rcode must be a number".to_string())),
            None => 3,
        };

        Ok(Arc::new(RejectPlugin::new(rcode)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_reject_plugin() {
        let plugin = RejectPlugin::new(3);
        assert_eq!(plugin.name(), "reject");

        let mut request = Message::new();
        request.set_id(12345);
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        assert!(ctx.has_response());
        let response = ctx.response().unwrap();
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(response.is_response());
        assert_eq!(response.id(), 12345);

        assert_eq!(
            ctx.get_metadata::<bool>(crate::plugin::RETURN_FLAG),
            Some(&true)
        );
    }

    #[tokio::test]
    async fn test_reject_helpers() {
        let nxdomain = RejectPlugin::nxdomain();
        let refused = RejectPlugin::refused();
        let servfail = RejectPlugin::servfail();

        assert_eq!(nxdomain.rcode, 3);
        assert_eq!(refused.rcode, 5);
        assert_eq!(servfail.rcode, 2);
    }
}

crate::register_plugin_builder!(RejectPlugin);
