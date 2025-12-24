use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use crate::plugin::traits::Matcher;
use std::sync::Arc;
use tracing::warn;

pub struct QnameBuilder;

impl ConditionBuilder for QnameBuilder {
    fn name(&self) -> &str {
        "qname"
    }

    fn build(&self, condition_str: &str, builder: &PluginBuilder) -> Result<Condition> {
        let domain_set_ref = condition_str.strip_prefix("qname ").ok_or_else(|| {
            crate::Error::Config(format!("Invalid qname format: {}", condition_str))
        })?;

        let domain_set_name = if let Some(name) = domain_set_ref.strip_prefix('$') {
            name
        } else {
            domain_set_ref
        };

        if let Some(plugin) = builder.get_plugin(domain_set_name) {
            if plugin.name() == "domain_set" {
                let plugin_clone = Arc::clone(&plugin);
                Ok(Arc::new(move |ctx: &Context| {
                    if let Some(matcher) = plugin_clone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<crate::plugins::dataset::DomainSetPlugin>(
                    ) {
                        matcher.matches_context(ctx)
                    } else {
                        false
                    }
                }))
            } else {
                warn!("Plugin '{}' is not a domain set plugin", domain_set_name);
                Ok(Arc::new(|_ctx: &Context| false))
            }
        } else {
            warn!("Domain set plugin '{}' not found", domain_set_name);
            Ok(Arc::new(|_ctx: &Context| false))
        }
    }
}
