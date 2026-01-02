use crate::Result;
use crate::config::PluginConfig;
use crate::dns::{Message, RData, ResourceRecord};
use crate::plugin::{Context, ExecPlugin, Plugin};
use async_trait::async_trait;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const PLUGIN_BLACKHOLE_IDENTIFIER: &str = "blackhole";
// Auto-register using the register macro for Plugin factory
crate::register_plugin_builder!(BlackholePlugin);
// Auto-register using the exec register macro (now supports aliases)
crate::register_exec_plugin_builder!(BlackholePlugin);

/// Black hole plugin: returns configured A/AAAA answers for a query
pub struct BlackholePlugin {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

impl BlackholePlugin {
    /// Create from iterator of address strings
    pub fn new_from_strs<I, S>(ips: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for s in ips {
            let s = s.as_ref();
            if let Ok(a4) = s.parse::<Ipv4Addr>() {
                ipv4.push(a4);
            } else if let Ok(a6) = s.parse::<Ipv6Addr>() {
                ipv6.push(a6);
            } else {
                return Err(crate::Error::Other(format!("invalid ip: {}", s)));
            }
        }
        Ok(Self { ipv4, ipv6 })
    }

    fn make_response_for_a(&self, req: &Message) -> Option<Message> {
        if req.question_count() != 1 || self.ipv4.is_empty() {
            return None;
        }
        let q = &req.questions()[0];
        if q.qtype() != crate::dns::types::RecordType::A {
            return None;
        }
        let mut r = Message::new();
        r.set_id(req.id());
        r.set_response(true);
        r.add_question(q.clone());
        for ip in &self.ipv4 {
            r.add_answer(ResourceRecord::new(
                q.qname().to_string(),
                crate::dns::types::RecordType::A,
                crate::dns::types::RecordClass::IN,
                300,
                RData::A(*ip),
            ));
        }
        Some(r)
    }

    fn make_response_for_aaaa(&self, req: &Message) -> Option<Message> {
        if req.question_count() != 1 || self.ipv6.is_empty() {
            return None;
        }
        let q = &req.questions()[0];
        if q.qtype() != crate::dns::types::RecordType::AAAA {
            return None;
        }
        let mut r = Message::new();
        r.set_id(req.id());
        r.set_response(true);
        r.add_question(q.clone());
        for ip in &self.ipv6 {
            r.add_answer(ResourceRecord::new(
                q.qname().to_string(),
                crate::dns::types::RecordType::AAAA,
                crate::dns::types::RecordClass::IN,
                300,
                RData::AAAA(*ip),
            ));
        }
        Some(r)
    }
}

impl fmt::Debug for BlackholePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlackHolePlugin")
            .field("ipv4_count", &self.ipv4.len())
            .field("ipv6_count", &self.ipv6.len())
            .finish()
    }
}

#[async_trait]
impl Plugin for BlackholePlugin {
    fn name(&self) -> &str {
        PLUGIN_BLACKHOLE_IDENTIFIER
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let req = ctx.request();
        if let Some(resp) = self
            .make_response_for_a(req)
            .or_else(|| self.make_response_for_aaaa(req))
        {
            ctx.set_response(Some(resp));
        }
        Ok(())
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();
        use serde_yaml::Value;

        // Blackhole plugin can accept a list of IPs or be empty (defaults to common sinkhole IPs)
        let ips: Vec<String> = if let Some(Value::Sequence(seq)) = args.get("ips") {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new() // Empty will use default sinkhole IPs
        };

        let plugin = BlackholePlugin::new_from_strs(ips)?;
        Ok(Arc::new(plugin))
    }

    fn aliases() -> &'static [&'static str] {
        &["sinkhole", "black_hole", "null_dns"]
    }
}

impl ExecPlugin for BlackholePlugin {
    /// Parse a quick configuration string for blackhole plugin.
    ///
    /// Accepts a comma-separated list of IP addresses.
    /// Examples: "192.0.2.1", "192.0.2.1,2001:db8::1", "0.0.0.0"
    fn quick_setup(prefix: &str, exec_str: &str) -> Result<Arc<dyn Plugin>> {
        // Accept the main name and all aliases
        if prefix != PLUGIN_BLACKHOLE_IDENTIFIER && !Self::aliases().contains(&prefix) {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected one of {:?}",
                prefix,
                Self::aliases()
            )));
        }

        // Parse comma-separated IP addresses
        let ips: Vec<String> = exec_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let plugin = BlackholePlugin::new_from_strs(ips)?;
        Ok(Arc::new(plugin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};

    #[tokio::test]
    async fn test_black_hole_a() {
        let plugin = BlackholePlugin::new_from_strs(["192.0.2.1"]).unwrap();
        let mut req = Message::new();
        req.add_question(crate::dns::question::Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        let resp = ctx.response().unwrap();
        assert_eq!(resp.answer_count(), 1);
        if let RData::A(ip) = resp.answers()[0].rdata() {
            assert_eq!(*ip, Ipv4Addr::new(192, 0, 2, 1));
        } else {
            panic!("expected A");
        }
    }

    #[test]
    fn test_exec_plugin_quick_setup() {
        // Test that ExecPlugin::quick_setup works correctly
        let plugin =
            <BlackholePlugin as ExecPlugin>::quick_setup("blackhole", "192.0.2.1").unwrap();
        assert_eq!(plugin.name(), "blackhole");

        // Test invalid prefix
        let result = <BlackholePlugin as ExecPlugin>::quick_setup("invalid", "192.0.2.1");
        assert!(result.is_err());

        // Test multiple IPs
        let plugin =
            <BlackholePlugin as ExecPlugin>::quick_setup("blackhole", "192.0.2.1,2001:db8::1")
                .unwrap();
        assert_eq!(plugin.name(), "blackhole");
    }
}
