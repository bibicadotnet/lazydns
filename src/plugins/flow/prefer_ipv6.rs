use crate::RegisterExecPlugin;
use crate::dns::RecordType;
use crate::plugin::{ExecPlugin, Plugin};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Default, Clone, Copy, RegisterExecPlugin)]
pub struct PreferIpv6Plugin;

impl PreferIpv6Plugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for PreferIpv6Plugin {
    fn name(&self) -> &str {
        "prefer_ipv6"
    }

    async fn execute(&self, ctx: &mut crate::plugin::Context) -> crate::Result<()> {
        if let Some(response) = ctx.response_mut() {
            let answers = response.answers_mut();
            answers.retain(|record| !matches!(record.rtype(), RecordType::A));

            let additional = response.additional_mut();
            additional.retain(|record| !matches!(record.rtype(), RecordType::A));
        }
        Ok(())
    }
}

impl ExecPlugin for PreferIpv6Plugin {
    fn quick_setup(prefix: &str, _exec_str: &str) -> crate::Result<Arc<dyn Plugin>> {
        if prefix != "prefer_ipv6" {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected 'prefer_ipv6'",
                prefix
            )));
        }

        Ok(Arc::new(PreferIpv6Plugin::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, RData, RecordClass, ResourceRecord};

    #[tokio::test]
    async fn test_prefer_ipv6_plugin() {
        let plugin = PreferIpv6Plugin::new();
        assert_eq!(plugin.name(), "prefer_ipv6");

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
        assert!(matches!(response.answers()[0].rtype(), RecordType::AAAA));
    }

    #[tokio::test]
    async fn test_prefer_ipv6_no_response() {
        let plugin = PreferIpv6Plugin::new();
        let mut ctx = crate::plugin::Context::new(Message::new());

        // No response set
        plugin.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_none());
    }

    #[tokio::test]
    async fn test_prefer_ipv6_additional_records() {
        let plugin = PreferIpv6Plugin::new();
        let mut ctx = crate::plugin::Context::new(Message::new());
        let mut response = Message::new();

        response.add_additional(ResourceRecord::new(
            "ns.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A("192.0.2.1".parse().unwrap()),
        ));

        response.add_additional(ResourceRecord::new(
            "ns.example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
            300,
            RData::AAAA("2001:db8::1".parse().unwrap()),
        ));

        ctx.set_response(Some(response));
        plugin.execute(&mut ctx).await.unwrap();

        let response = ctx.response().unwrap();
        assert_eq!(response.additional().len(), 1);
        assert!(matches!(response.additional()[0].rtype(), RecordType::AAAA));
    }

    #[test]
    fn test_prefer_ipv6_quick_setup() {
        let plugin = PreferIpv6Plugin::quick_setup("prefer_ipv6", "").unwrap();
        assert_eq!(plugin.name(), "prefer_ipv6");
    }

    #[test]
    fn test_prefer_ipv6_quick_setup_invalid() {
        let result = PreferIpv6Plugin::quick_setup("invalid", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_prefer_ipv6_default() {
        let plugin = PreferIpv6Plugin::new();
        assert_eq!(plugin.name(), "prefer_ipv6");
    }
}
