use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use std::sync::Arc;

pub struct QclassBuilder;

impl ConditionBuilder for QclassBuilder {
    fn name(&self) -> &str {
        "qclass"
    }

    fn build(&self, condition_str: &str, _builder: &PluginBuilder) -> Result<Condition> {
        let class_str = condition_str.strip_prefix("qclass ").ok_or_else(|| {
            crate::Error::Config(format!("Invalid qclass format: {}", condition_str))
        })?;

        let mut qclasses = Vec::new();
        for class_part in class_str.split_whitespace() {
            let class_val = match class_part.to_uppercase().as_str() {
                "IN" => 1u16,
                "CH" => 3u16,
                "HS" => 4u16,
                _ => match class_part.parse::<u16>() {
                    Ok(num) => num,
                    Err(_) => {
                        return Err(crate::Error::Config(format!(
                            "Invalid query class '{}': {}",
                            class_part, condition_str
                        )));
                    }
                },
            };
            qclasses.push(class_val);
        }

        if qclasses.is_empty() {
            return Err(crate::Error::Config(format!(
                "No query classes specified: {}",
                condition_str
            )));
        }

        Ok(Arc::new(move |ctx: &Context| {
            if let Some(question) = ctx.request().questions().first() {
                let qclass = question.qclass().to_u16();
                qclasses.contains(&qclass)
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
    fn test_qclass_builder_name() {
        let builder = QclassBuilder;
        assert_eq!(builder.name(), "qclass");
    }
}
