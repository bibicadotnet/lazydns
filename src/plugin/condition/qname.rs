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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qname_builder_name() {
        let builder = QnameBuilder;
        assert_eq!(builder.name(), "qname");
    }

    #[test]
    fn test_qname_invalid_format() {
        let builder = QnameBuilder;
        let plugin_builder = PluginBuilder::new();

        // Invalid format (missing qname prefix)
        let result = builder.build("invalid_format", &plugin_builder);
        assert!(result.is_err());
    }

    #[test]
    fn test_qname_plugin_not_found() {
        let builder = QnameBuilder;
        let plugin_builder = PluginBuilder::new();

        // Plugin doesn't exist - should return a condition that always returns false
        let result = builder.build("qname nonexistent", &plugin_builder);
        assert!(result.is_ok());

        let condition = result.unwrap();
        let ctx = Context::new(crate::dns::Message::new());
        assert!(!condition(&ctx));
    }

    #[test]
    fn test_qname_with_dollar_prefix() {
        let builder = QnameBuilder;
        let plugin_builder = PluginBuilder::new();

        // With $ prefix - should also work (plugin not found case)
        let result = builder.build("qname $my_domain_set", &plugin_builder);
        assert!(result.is_ok());

        let condition = result.unwrap();
        let ctx = Context::new(crate::dns::Message::new());
        assert!(!condition(&ctx));
    }
}
