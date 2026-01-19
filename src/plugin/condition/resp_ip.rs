use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use crate::plugin::traits::Matcher;
use std::sync::Arc;
use tracing::warn;

pub struct RespIpBuilder;

impl ConditionBuilder for RespIpBuilder {
    fn name(&self) -> &str {
        "resp_ip"
    }

    fn build(&self, condition_str: &str, builder: &PluginBuilder) -> Result<Condition> {
        let ip_set_ref = condition_str.strip_prefix("resp_ip ").ok_or_else(|| {
            crate::Error::Config(format!("Invalid resp_ip format: {}", condition_str))
        })?;

        let ip_set_name = if let Some(name) = ip_set_ref.strip_prefix('$') {
            name
        } else {
            ip_set_ref
        };

        if let Some(plugin) = builder.get_plugin(ip_set_name) {
            if plugin.name() == "ip_set" {
                let plugin_clone = Arc::clone(&plugin);
                Ok(Arc::new(move |ctx: &Context| {
                    if let Some(matcher) = plugin_clone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<crate::plugins::dataset::IpSetPlugin>()
                    {
                        matcher.matches_context(ctx)
                    } else {
                        false
                    }
                }))
            } else {
                warn!("Plugin '{}' is not an IP set plugin", ip_set_name);
                Ok(Arc::new(|_ctx: &Context| false))
            }
        } else {
            warn!("IP set plugin '{}' not found", ip_set_name);
            Ok(Arc::new(|_ctx: &Context| false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resp_ip_builder_name() {
        let builder = RespIpBuilder;
        assert_eq!(builder.name(), "resp_ip");
    }

    #[test]
    fn test_resp_ip_invalid_format() {
        let builder = RespIpBuilder;
        let plugin_builder = PluginBuilder::new();

        // Invalid format (missing resp_ip prefix)
        let result = builder.build("invalid_format", &plugin_builder);
        assert!(result.is_err());
    }

    #[test]
    fn test_resp_ip_plugin_not_found() {
        let builder = RespIpBuilder;
        let plugin_builder = PluginBuilder::new();

        // Plugin doesn't exist - should return a condition that always returns false
        let result = builder.build("resp_ip nonexistent", &plugin_builder);
        assert!(result.is_ok());

        let condition = result.unwrap();
        let ctx = Context::new(crate::dns::Message::new());
        assert!(!condition(&ctx));
    }

    #[test]
    fn test_resp_ip_with_dollar_prefix() {
        let builder = RespIpBuilder;
        let plugin_builder = PluginBuilder::new();

        // With $ prefix - should also work (plugin not found case)
        let result = builder.build("resp_ip $my_ip_set", &plugin_builder);
        assert!(result.is_ok());

        let condition = result.unwrap();
        let ctx = Context::new(crate::dns::Message::new());
        assert!(!condition(&ctx));
    }
}
