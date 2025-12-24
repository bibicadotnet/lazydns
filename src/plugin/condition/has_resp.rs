use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use std::sync::Arc;

pub struct HasRespBuilder;

impl ConditionBuilder for HasRespBuilder {
    fn name(&self) -> &str {
        "has_resp"
    }

    fn build(&self, condition_str: &str, _builder: &PluginBuilder) -> Result<Condition> {
        if condition_str != "has_resp" {
            return Err(crate::Error::Config(format!(
                "has_resp does not accept arguments: {}",
                condition_str
            )));
        }

        Ok(Arc::new(|ctx: &Context| ctx.has_response()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_resp_builder() {
        let builder = HasRespBuilder;
        assert_eq!(builder.name(), "has_resp");
    }
}
