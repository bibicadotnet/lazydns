use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use std::sync::Arc;

pub struct QnameNegBuilder;

impl ConditionBuilder for QnameNegBuilder {
    fn name(&self) -> &str {
        "!qname"
    }

    fn build(&self, condition_str: &str, _builder: &PluginBuilder) -> Result<Condition> {
        let domain = condition_str.strip_prefix("!qname ").ok_or_else(|| {
            crate::Error::Config(format!("Invalid !qname format: {}", condition_str))
        })?;

        let domain_lower = domain.to_lowercase();
        Ok(Arc::new(move |ctx: &Context| {
            if let Some(question) = ctx.request().questions().first() {
                let qname = question.qname().to_string().to_lowercase();
                !qname.eq(&domain_lower)
            } else {
                true
            }
        }))
    }
}
