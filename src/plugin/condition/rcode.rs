use crate::Result;
use crate::plugin::Context;
use crate::plugin::builder::PluginBuilder;
use crate::plugin::condition::builder::{Condition, ConditionBuilder};
use std::sync::Arc;

pub struct RcodeBuilder;

impl ConditionBuilder for RcodeBuilder {
    fn name(&self) -> &str {
        "rcode"
    }

    fn build(&self, condition_str: &str, _builder: &PluginBuilder) -> Result<Condition> {
        let rcode_str = condition_str.strip_prefix("rcode ").ok_or_else(|| {
            crate::Error::Config(format!("Invalid rcode format: {}", condition_str))
        })?;

        let mut rcodes = Vec::new();
        for rcode_part in rcode_str.split_whitespace() {
            let rcode_val = match rcode_part.to_uppercase().as_str() {
                "NOERROR" => 0u8,
                "FORMERR" | "FORMDERR" => 1u8,
                "SERVFAIL" => 2u8,
                "NXDOMAIN" | "NXDOM" => 3u8,
                "NOTIMP" | "NOTIMPL" => 4u8,
                "REFUSED" | "REFUSE" => 5u8,
                "YXDOMAIN" | "YXDOM" => 6u8,
                "YXRRSET" => 7u8,
                "NXRRSET" => 8u8,
                "NOTAUTH" | "NOTAUTHZ" => 9u8,
                "NOTZONE" => 10u8,
                _ => match rcode_part.parse::<u8>() {
                    Ok(num) => num,
                    Err(_) => {
                        return Err(crate::Error::Config(format!(
                            "Invalid response code '{}': {}",
                            rcode_part, condition_str
                        )));
                    }
                },
            };
            rcodes.push(rcode_val);
        }

        if rcodes.is_empty() {
            return Err(crate::Error::Config(format!(
                "No response codes specified: {}",
                condition_str
            )));
        }

        Ok(Arc::new(move |ctx: &Context| {
            if let Some(response) = ctx.response() {
                let rcode = response.response_code().to_u8();
                rcodes.contains(&rcode)
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
    fn test_rcode_builder_name() {
        let builder = RcodeBuilder;
        assert_eq!(builder.name(), "rcode");
    }
}
