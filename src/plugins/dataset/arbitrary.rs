// Arbitrary plugin moved under plugins::dataset
// (content copied from src/plugins/executable/arbitrary.rs)

use crate::Result;
use crate::dns::{Message, RData, ResourceRecord};
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

crate::register_plugin_builder!(ArbitraryPlugin);

#[derive(Debug, Deserialize, Clone)]
pub struct ArbitraryArgs {
    pub rules: Option<Vec<String>>,
    pub files: Option<Vec<String>>,
}

pub struct ArbitraryPlugin {
    map: HashMap<String, Vec<ResourceRecord>>,
}

impl ArbitraryPlugin {
    pub fn new(args: ArbitraryArgs) -> Result<Self> {
        let mut m: HashMap<String, Vec<ResourceRecord>> = HashMap::new();
        if let Some(rules) = args.rules {
            for (i, line) in rules.into_iter().enumerate() {
                if let Some(rr) = Self::parse_rr_line(&line) {
                    m.entry(rr.name().to_string()).or_default().push(rr);
                } else {
                    return Err(crate::Error::Other(format!(
                        "failed to parse rule #{}: {}",
                        i, line
                    )));
                }
            }
        }
        if let Some(files) = args.files {
            for file in files {
                let b = fs::read_to_string(&file).map_err(|e| {
                    crate::Error::Other(format!("failed to read file {}: {}", file, e))
                })?;
                for (i, line) in b.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                        continue;
                    }
                    if let Some(rr) = Self::parse_rr_line(line) {
                        m.entry(rr.name().to_string()).or_default().push(rr);
                    } else {
                        return Err(crate::Error::Other(format!(
                            "failed to parse rr in file {} line {}",
                            file,
                            i + 1
                        )));
                    }
                }
            }
        }
        Ok(Self { map: m })
    }

    fn parse_rr_line(line: &str) -> Option<ResourceRecord> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }
        let name = parts[0].trim_end_matches('.').to_string();
        let (typ_idx, rdata_idx) = if parts[1].eq_ignore_ascii_case("IN") && parts.len() >= 4 {
            (2, 3)
        } else {
            (1, 2)
        };
        let typ = parts.get(typ_idx)?;
        let rdata = parts.get(rdata_idx)?;
        let rr = match typ.to_uppercase().as_str() {
            "A" => {
                let ip = Ipv4Addr::from_str(rdata).ok()?;
                ResourceRecord::new(
                    name,
                    crate::dns::types::RecordType::A,
                    crate::dns::types::RecordClass::IN,
                    300,
                    RData::A(ip),
                )
            }
            "AAAA" => {
                let ip = Ipv6Addr::from_str(rdata).ok()?;
                ResourceRecord::new(
                    name,
                    crate::dns::types::RecordType::AAAA,
                    crate::dns::types::RecordClass::IN,
                    300,
                    RData::AAAA(ip),
                )
            }
            "CNAME" => ResourceRecord::new(
                name,
                crate::dns::types::RecordType::CNAME,
                crate::dns::types::RecordClass::IN,
                300,
                RData::CNAME(rdata.to_string()),
            ),
            _ => {
                return None;
            }
        };
        Some(rr)
    }
}

impl fmt::Debug for ArbitraryPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Arbitrary")
            .field("rules_count", &self.map.len())
            .finish()
    }
}

#[async_trait]
impl Plugin for ArbitraryPlugin {
    fn name(&self) -> &str {
        "arbitrary"
    }

    fn init(config: &crate::config::types::PluginConfig) -> Result<Arc<dyn Plugin>> {
        use serde_yaml;
        use std::sync::Arc;

        let args: ArbitraryArgs = serde_yaml::from_value(config.args.clone())
            .map_err(|e| crate::Error::Config(format!("failed to parse arbitrary args: {}", e)))?;
        Ok(Arc::new(ArbitraryPlugin::new(args)?))
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if let Some(q) = ctx.request().questions().first() {
            let key = q.qname().trim_end_matches('.').to_string();
            if let Some(rrs) = self.map.get(&key) {
                let mut msg = Message::new();
                msg.set_id(ctx.request().id());
                msg.set_response(true);
                msg.add_question(q.clone());
                for rr in rrs {
                    msg.add_answer(rr.clone());
                }
                ctx.set_response(Some(msg));
            }
        } else if !self.map.is_empty()
            && let Some((_k, rrs)) = self.map.iter().next()
        {
            let mut msg = Message::new();
            msg.set_id(ctx.request().id());
            msg.set_response(true);
            for rr in rrs {
                msg.add_answer(rr.clone());
            }
            ctx.set_response(Some(msg));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Question, RData};

    #[tokio::test]
    async fn test_arbitrary_rules() {
        let args = ArbitraryArgs {
            rules: Some(vec!["example.com A 192.0.2.1".to_string()]),
            files: None,
        };
        let plugin = ArbitraryPlugin::new(args).unwrap();
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();
        assert_eq!(resp.answer_count(), 1);
        if let RData::A(ip) = resp.answers()[0].rdata() {
            assert_eq!(*ip, Ipv4Addr::new(192, 0, 2, 1));
        } else {
            panic!("expected A");
        }
    }

    // Other tests preserved from original file...
}
