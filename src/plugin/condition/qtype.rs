use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use std::sync::Arc;

pub struct QtypeBuilder;

impl ConditionBuilder for QtypeBuilder {
    fn name(&self) -> &str {
        "qtype"
    }

    fn build(&self, condition_str: &str, _builder: &PluginBuilder) -> Result<Condition> {
        let type_str = condition_str.strip_prefix("qtype ").ok_or_else(|| {
            crate::Error::Config(format!("Invalid qtype format: {}", condition_str))
        })?;

        let mut qtypes = Vec::new();
        for type_part in type_str.split_whitespace() {
            match type_part.parse::<u16>() {
                Ok(qtype_num) => {
                    qtypes.push(qtype_num);
                }
                Err(_) => {
                    return Err(crate::Error::Config(format!(
                        "Invalid query type number '{}': {}",
                        type_part, condition_str
                    )));
                }
            }
        }

        if qtypes.is_empty() {
            return Err(crate::Error::Config(format!(
                "No query types specified: {}",
                condition_str
            )));
        }

        Ok(Arc::new(move |ctx: &Context| {
            if let Some(question) = ctx.request().questions().first() {
                let qtype = question.qtype().to_u16();
                qtypes.contains(&qtype)
            } else {
                false
            }
        }))
    }
}
