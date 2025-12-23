use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use crate::plugin::traits::Matcher;
use std::sync::Arc;
use tracing::warn;

pub struct RespIpNegBuilder;

impl ConditionBuilder for RespIpNegBuilder {
    fn name(&self) -> &str {
        "!resp_ip"
    }

    fn build(&self, condition_str: &str, builder: &PluginBuilder) -> Result<Condition> {
        let ip_set_ref = condition_str.strip_prefix("!resp_ip ").ok_or_else(|| {
            crate::Error::Config(format!("Invalid !resp_ip format: {}", condition_str))
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
                        !matcher.matches_context(ctx)
                    } else {
                        true
                    }
                }))
            } else {
                warn!("Plugin '{}' is not an IP set plugin", ip_set_name);
                Ok(Arc::new(|_ctx: &Context| true))
            }
        } else {
            warn!("IP set plugin '{}' not found", ip_set_name);
            Ok(Arc::new(|_ctx: &Context| true))
        }
    }
}
