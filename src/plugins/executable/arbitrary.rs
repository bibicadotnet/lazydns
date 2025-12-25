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

// Auto-register using the register macro for Plugin factory
crate::register_plugin_builder!(ArbitraryPlugin);

#[derive(Debug, Deserialize, Clone)]
/// Configuration arguments for the ArbitraryPlugin.
///
/// This struct defines the input parameters for creating an ArbitraryPlugin instance.
/// It allows specifying DNS rules either directly as strings or from files.
pub struct ArbitraryArgs {
    /// Optional list of DNS rules as strings, e.g., "example.com A 192.0.2.1"
    pub rules: Option<Vec<String>>,
    /// Optional list of file paths containing DNS rules
    pub files: Option<Vec<String>>,
}

/// A plugin that provides arbitrary DNS responses based on predefined rules.
///
/// The ArbitraryPlugin allows users to define custom DNS resource records
/// that will be returned for matching queries. Rules can be provided inline
/// or loaded from files. It supports A, AAAA, and CNAME record types.
pub struct ArbitraryPlugin {
    // map qname -> vector of resource records to reply
    map: HashMap<String, Vec<ResourceRecord>>,
}

impl ArbitraryPlugin {
    /// Creates a new ArbitraryPlugin instance.
    ///
    /// Parses the provided rules and files to build a mapping of domain names
    /// to resource records.
    ///
    /// # Arguments
    /// * `args` - The configuration arguments containing rules and file paths.
    ///
    /// # Returns
    /// A Result containing the plugin or an error if parsing fails.
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

    /// Parses a single line into a ResourceRecord.
    ///
    /// Supports simple formats like "example.com A 1.2.3.4", "example.com AAAA 2001:db8::1",
    /// or "example.com CNAME target.". Ignores lines starting with ';' or '#', and empty lines.
    ///
    /// # Arguments
    /// * `line` - The string to parse.
    ///
    /// # Returns
    /// An Option containing the parsed ResourceRecord or None if parsing fails.
    fn parse_rr_line(line: &str) -> Option<ResourceRecord> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }
        // name may be first part
        let name = parts[0].trim_end_matches('.').to_string();
        // type may be in parts[1] or parts[2] depending on presence of TTL/class; handle common simple case
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
    /// Returns the name of the plugin.
    fn name(&self) -> &str {
        "arbitrary"
    }

    /// Initialize plugin from configuration.
    ///
    /// Parses the `args` field from the plugin configuration into `ArbitraryArgs`.
    fn init(config: &crate::config::types::PluginConfig) -> Result<Arc<dyn Plugin>> {
        use serde_yaml;
        use std::sync::Arc;

        let args: ArbitraryArgs = serde_yaml::from_value(config.args.clone())
            .map_err(|e| crate::Error::Config(format!("failed to parse arbitrary args: {}", e)))?;
        Ok(Arc::new(ArbitraryPlugin::new(args)?))
    }

    /// Executes the plugin logic.
    ///
    /// If the request contains a question, it looks up the corresponding records
    /// and sets a response. If no question is present but rules exist, it uses
    /// the first rule as a fallback.
    ///
    /// # Arguments
    /// * `ctx` - The plugin context containing the request and response.
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // If there is a question in the request, use it to select rules.
        // Otherwise, if the plugin has at least one rule, fall back to the
        // first rule entry so executable compositions (like Sequence) can
        // be used in tests and quick setups where an explicit request
        // question may not be present.
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
        } else if !self.map.is_empty() {
            // No request question — pick the first rule entry as a sensible default.
            if let Some((_k, rrs)) = self.map.iter().next() {
                let mut msg = Message::new();
                msg.set_id(ctx.request().id());
                msg.set_response(true);
                // No original question available; do not add question.
                for rr in rrs {
                    msg.add_answer(rr.clone());
                }
                ctx.set_response(Some(msg));
            }
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

    #[tokio::test]
    async fn test_arbitrary_aaaa() {
        let args = ArbitraryArgs {
            rules: Some(vec!["example.com AAAA 2001:db8::1".to_string()]),
            files: None,
        };
        let plugin = ArbitraryPlugin::new(args).unwrap();
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();
        assert_eq!(resp.answer_count(), 1);
        if let RData::AAAA(ip) = resp.answers()[0].rdata() {
            assert_eq!(*ip, Ipv6Addr::from_str("2001:db8::1").unwrap());
        } else {
            panic!("expected AAAA");
        }
    }

    #[tokio::test]
    async fn test_arbitrary_cname() {
        let args = ArbitraryArgs {
            rules: Some(vec!["example.com CNAME target.example.com".to_string()]),
            files: None,
        };
        let plugin = ArbitraryPlugin::new(args).unwrap();
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::CNAME,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();
        assert_eq!(resp.answer_count(), 1);
        if let RData::CNAME(name) = resp.answers()[0].rdata() {
            assert_eq!(name, "target.example.com");
        } else {
            panic!("expected CNAME");
        }
    }

    #[tokio::test]
    async fn test_arbitrary_files() {
        let temp_path = "test_arbitrary.tmp";
        fs::write(
            temp_path,
            "example.com A 192.0.2.2\n# comment\n\ntest.com AAAA 2001:db8::2\n",
        )
        .unwrap();

        let args = ArbitraryArgs {
            rules: None,
            files: Some(vec![temp_path.to_string()]),
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
            assert_eq!(*ip, Ipv4Addr::new(192, 0, 2, 2));
        } else {
            panic!("expected A");
        }

        fs::remove_file(temp_path).unwrap();
    }

    #[tokio::test]
    async fn test_invalid_rule() {
        let args = ArbitraryArgs {
            rules: Some(vec!["invalid rule".to_string()]),
            files: None,
        };
        assert!(ArbitraryPlugin::new(args).is_err());
    }

    #[tokio::test]
    async fn test_no_match() {
        let args = ArbitraryArgs {
            rules: Some(vec!["example.com A 192.0.2.1".to_string()]),
            files: None,
        };
        let plugin = ArbitraryPlugin::new(args).unwrap();
        let mut req = Message::new();
        req.add_question(Question::new(
            "nomatch.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_none());
    }

    #[tokio::test]
    async fn test_fallback_no_question() {
        let args = ArbitraryArgs {
            rules: Some(vec!["example.com A 192.0.2.1".to_string()]),
            files: None,
        };
        let plugin = ArbitraryPlugin::new(args).unwrap();
        let req = Message::new(); // No question
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        assert!(ctx.response().is_some());
        let resp = ctx.response().unwrap();
        assert_eq!(resp.answer_count(), 1);
    }
}
