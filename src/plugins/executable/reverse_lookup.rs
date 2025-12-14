use crate::dns::{Message, RData, ResourceRecord};
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ReverseLookupArgs {
    pub size: usize,
    pub handle_ptr: bool,
    pub ttl: u32,
}

impl Default for ReverseLookupArgs {
    fn default() -> Self {
        Self {
            size: 64 * 1024,
            handle_ptr: true,
            ttl: 7200,
        }
    }
}

/// Simple reverse lookup cache entry: fqdn + expiration
type Entry = (String, Instant);

/// Reverse lookup plugin: collect A/AAAA answers and serve PTR from cache
pub struct ReverseLookup {
    cache: Arc<DashMap<String, Entry>>,
    args: ReverseLookupArgs,
}

impl ReverseLookup {
    pub fn new(args: ReverseLookupArgs) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            args,
        }
    }

    fn parse_ptr(qname: &str) -> Option<IpAddr> {
        let s = qname.trim_end_matches('.').to_ascii_lowercase();
        if s.ends_with(".in-addr.arpa") {
            let without = s.trim_end_matches(".in-addr.arpa").trim_end_matches('.');
            let parts: Vec<&str> = without.split('.').collect();
            if parts.len() == 4 {
                let rev: Vec<&str> = parts.into_iter().rev().collect();
                let ip = rev.join(".");
                return ip.parse::<IpAddr>().ok();
            }
        } else if s.ends_with(".ip6.arpa") {
            // attempt to parse nibble format: labels are nibbles in reverse order
            let without = s.trim_end_matches(".ip6.arpa").trim_end_matches('.');
            let labels: Vec<&str> = without.split('.').collect();
            let mut hex = String::new();
            for label in labels.into_iter().rev() {
                if label.len() != 1 {
                    return None;
                }
                hex.push_str(label);
            }
            // group into bytes
            if !hex.len().is_multiple_of(2) {
                hex.push('0');
            }
            let bytes_res: std::result::Result<Vec<u8>, std::num::ParseIntError> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect();
            if let Ok(bytes) = bytes_res {
                if bytes.len() == 16 {
                    use std::net::Ipv6Addr;
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&bytes);
                    return Some(IpAddr::V6(Ipv6Addr::from(arr)));
                }
            }
        }
        None
    }

    fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let key = ip.to_string();
        if let Some(v) = self.cache.get(&key) {
            if v.value().1 > Instant::now() {
                return Some(v.value().0.clone());
            } else {
                // expired
                self.cache.remove(&key);
            }
        }
        None
    }

    fn save_from_response(&self, req: &Message, resp: &Message) {
        if resp.answer_count() == 0 {
            return;
        }
        let now = Instant::now();
        for rr in resp.answers() {
            match rr.rdata() {
                RData::A(ipv4) => {
                    let ip = IpAddr::V4(*ipv4);
                    let ttl = rr.ttl().min(self.args.ttl);
                    let exp = now + Duration::from_secs(ttl as u64);
                    let name = if req.question_count() == 1 {
                        req.questions()[0].qname().to_string()
                    } else {
                        rr.name().to_string()
                    };
                    self.cache.insert(ip.to_string(), (name, exp));
                }
                RData::AAAA(ipv6) => {
                    let ip = IpAddr::V6(*ipv6);
                    let ttl = rr.ttl().min(self.args.ttl);
                    let exp = now + Duration::from_secs(ttl as u64);
                    let name = if req.question_count() == 1 {
                        req.questions()[0].qname().to_string()
                    } else {
                        rr.name().to_string()
                    };
                    self.cache.insert(ip.to_string(), (name, exp));
                }
                _ => {}
            }
        }
    }
}

impl fmt::Debug for ReverseLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReverseLookup").finish()
    }
}

#[async_trait]
impl Plugin for ReverseLookup {
    fn name(&self) -> &str {
        "reverse_lookup"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // If PTR and configured, attempt to reply from cache
        let req = ctx.request();
        if self.args.handle_ptr {
            if let Some(q) = req.questions().first() {
                if q.qtype() == crate::dns::types::RecordType::PTR {
                    if let Some(ip) = Self::parse_ptr(q.qname()) {
                        if let Some(fqdn) = self.lookup(&ip) {
                            let mut r = Message::new();
                            r.set_id(req.id());
                            r.set_response(true);
                            r.add_question(q.clone());
                            r.add_answer(ResourceRecord::new(
                                q.qname().to_string(),
                                crate::dns::types::RecordType::PTR,
                                crate::dns::types::RecordClass::IN,
                                5,
                                RData::PTR(fqdn),
                            ));
                            ctx.set_response(Some(r));
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Otherwise do nothing here; saving of IPs is expected to be triggered
        // by sequence runner after response is available via `save_ips_after`.
        Ok(())
    }
}

impl ReverseLookup {
    /// Helper to be called by sequence runner after response is populated.
    pub fn save_ips_after(&self, req: &Message, resp: &Message) {
        self.save_from_response(req, resp);
    }

    /// Expose lookup for tests: return the cached fqdn for an IP if present
    pub fn lookup_cached(&self, ip: &IpAddr) -> Option<String> {
        self.lookup(ip)
    }

    /// Create quick setup similar to upstream: size only
    pub fn quick_setup(s: &str) -> Self {
        let mut args = ReverseLookupArgs::default();
        if !s.is_empty() {
            if let Ok(n) = s.parse::<usize>() {
                args.size = n;
            }
        }
        Self::new(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // test only uses parse_ptr

    #[tokio::test]
    async fn test_parse_ipv4_ptr() {
        let s = "1.2.3.4.in-addr.arpa.";
        let ip = ReverseLookup::parse_ptr(s).unwrap();
        assert_eq!(ip.to_string(), "4.3.2.1");
    }

    #[test]
    fn test_save_ips_after_and_lookup_cached() {
        use crate::dns::{Message, Question, RData, RecordClass, RecordType, ResourceRecord};
        use std::net::Ipv4Addr;

        // Build request with single question
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        // Build response with one A answer
        let mut resp = Message::new();
        resp.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        ));

        let rl = ReverseLookup::new(ReverseLookupArgs::default());

        // Ensure no entry initially
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(rl.lookup_cached(&ip).is_none());

        // Invoke save hook
        rl.save_ips_after(&req, &resp);

        // Now the lookup should return the fqdn from the request
        let got = rl.lookup_cached(&ip).expect("expected cached name");
        assert_eq!(got, "example.com");
    }
}
