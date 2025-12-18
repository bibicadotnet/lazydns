use crate::dns::RecordType;
use crate::plugin::Plugin;
use async_trait::async_trait;

// Auto-register using the register macro
crate::register_plugin_builder!(PreferIpv4Plugin);

#[derive(Debug, Default, Clone, Copy)]
pub struct PreferIpv4Plugin;

impl PreferIpv4Plugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for PreferIpv4Plugin {
    fn name(&self) -> &str {
        "prefer_ipv4"
    }

    fn init(
        _config: &crate::config::types::PluginConfig,
    ) -> crate::Result<std::sync::Arc<dyn Plugin>> {
        Ok(std::sync::Arc::new(PreferIpv4Plugin::new()))
    }

    async fn execute(&self, ctx: &mut crate::plugin::Context) -> crate::Result<()> {
        if let Some(response) = ctx.response_mut() {
            let answers = response.answers_mut();
            answers.retain(|record| !matches!(record.rtype(), RecordType::AAAA));

            let additional = response.additional_mut();
            additional.retain(|record| !matches!(record.rtype(), RecordType::AAAA));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, RData, RecordClass, ResourceRecord};

    #[tokio::test]
    async fn test_prefer_ipv4_plugin() {
        let plugin = PreferIpv4Plugin::new();
        assert_eq!(plugin.name(), "prefer_ipv4");

        let mut ctx = crate::plugin::Context::new(Message::new());
        let mut response = Message::new();

        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));

        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
            300,
            RData::AAAA("2001:db8::1".parse().unwrap()),
        ));

        ctx.set_response(Some(response));
        plugin.execute(&mut ctx).await.unwrap();

        let response = ctx.response().unwrap();
        assert_eq!(response.answers().len(), 1);
        assert!(matches!(response.answers()[0].rtype(), RecordType::A));
    }
}
