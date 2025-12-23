use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use std::sync::Arc;

pub struct HasCnameBuilder;

impl ConditionBuilder for HasCnameBuilder {
    fn name(&self) -> &str {
        "has_cname"
    }

    fn build(&self, condition_str: &str, _builder: &PluginBuilder) -> Result<Condition> {
        if condition_str != "has_cname" {
            return Err(crate::Error::Config(format!(
                "has_cname does not accept arguments: {}",
                condition_str
            )));
        }

        Ok(Arc::new(|ctx: &Context| {
            if let Some(response) = ctx.response() {
                response
                    .answers()
                    .iter()
                    .any(|rr| rr.rtype() == crate::dns::types::RecordType::CNAME)
            } else {
                false
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_cname_builder_name() {
        let builder = HasCnameBuilder;
        assert_eq!(builder.name(), "has_cname");
    }
}
