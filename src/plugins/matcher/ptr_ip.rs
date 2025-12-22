//! PTR IP matcher plugin
//!
//! Matches PTR queries based on the IP address in the query name
//!
//! # Limitations
//!
//! - IPv6 PTR parsing is not yet fully implemented. Only IPv4 PTR records
//!   (in-addr.arpa format) are supported.
//! - Full IPv6 support (ip6.arpa format) requires nibble reversal and is planned
//!   for a future update.

use crate::Result;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use ipnet::IpNet;
use std::fmt;
use std::net::IpAddr;
use tracing::debug;

/// Plugin that matches PTR queries by IP address
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::PtrIpMatcherPlugin;
///
/// let mut matcher = PtrIpMatcherPlugin::new();
/// matcher.add_cidr("192.168.1.0/24".parse().unwrap()).unwrap();
/// ```
pub struct PtrIpMatcherPlugin {
    /// List of CIDR ranges to match
    cidrs: Vec<IpNet>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl PtrIpMatcherPlugin {
    /// Create a new PTR IP matcher plugin
    pub fn new() -> Self {
        Self {
            cidrs: Vec::new(),
            metadata_key: "ptr_ip_matched".to_string(),
        }
    }

    /// Add a CIDR range to match
    pub fn add_cidr(&mut self, cidr: IpNet) -> Result<()> {
        self.cidrs.push(cidr);
        Ok(())
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Parse IP from PTR query name (e.g., "1.2.168.192.in-addr.arpa" → 192.168.2.1)
    fn parse_ptr_ip(qname: &str) -> Option<IpAddr> {
        let qname_lower = qname.to_lowercase();

        // IPv4 PTR: X.X.X.X.in-addr.arpa
        if let Some(prefix) = qname_lower.strip_suffix(".in-addr.arpa") {
            let parts: Vec<&str> = prefix.split('.').collect();
            if parts.len() == 4 {
                // Reverse the octets
                let ip_str = format!("{}.{}.{}.{}", parts[3], parts[2], parts[1], parts[0]);
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        // IPv6 PTR: X.X.X...X.ip6.arpa (not fully implemented - simplified)
        if qname_lower.ends_with(".ip6.arpa") {
            // IPv6 PTR is complex, simplified implementation
            // Full implementation would reverse nibbles
            return None; // TODO: implement full IPv6 PTR parsing
        }

        None
    }

    /// Check if an IP address matches any CIDR
    fn matches_ip(&self, ip: IpAddr) -> bool {
        for cidr in &self.cidrs {
            if cidr.contains(&ip) {
                return true;
            }
        }
        false
    }
}

impl Default for PtrIpMatcherPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PtrIpMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtrIpMatcherPlugin")
            .field("cidrs", &self.cidrs)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for PtrIpMatcherPlugin {
    fn name(&self) -> &str {
        "ptr_ip_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let request = ctx.request();

        if let Some(question) = request.questions().first() {
            let qname = question.qname();

            if let Some(ip) = Self::parse_ptr_ip(qname) {
                let matched = self.matches_ip(ip);

                if matched {
                    debug!(
                        ip = %ip,
                        "PTR IP matcher: matched"
                    );
                    ctx.set_metadata(self.metadata_key.clone(), true);
                } else {
                    debug!(
                        ip = %ip,
                        "PTR IP matcher: no match"
                    );
                    ctx.set_metadata(self.metadata_key.clone(), false);
                }
            } else {
                // Not a PTR query or couldn't parse
                ctx.set_metadata(self.metadata_key.clone(), false);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question};

    #[tokio::test]
    async fn test_ptr_ip_matcher() {
        let mut matcher = PtrIpMatcherPlugin::new();
        matcher.add_cidr("192.168.1.0/24".parse().unwrap()).unwrap();

        let mut request = Message::new();
        // PTR query for 192.168.1.100
        request.add_question(Question::new(
            "100.1.168.192.in-addr.arpa".to_string(),
            RecordType::PTR,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("ptr_ip_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_ptr_ip_matcher_no_match() {
        let mut matcher = PtrIpMatcherPlugin::new();
        matcher.add_cidr("192.168.1.0/24".parse().unwrap()).unwrap();

        let mut request = Message::new();
        // PTR query for 10.0.0.1
        request.add_question(Question::new(
            "1.0.0.10.in-addr.arpa".to_string(),
            RecordType::PTR,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("ptr_ip_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_ptr_ip_parser() {
        // Test IPv4 PTR parsing
        let ip = PtrIpMatcherPlugin::parse_ptr_ip("1.0.168.192.in-addr.arpa");
        assert_eq!(ip, Some("192.168.0.1".parse().unwrap()));

        let ip = PtrIpMatcherPlugin::parse_ptr_ip("254.253.252.10.in-addr.arpa");
        assert_eq!(ip, Some("10.252.253.254".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_ptr_ip_matcher_not_ptr() {
        let mut matcher = PtrIpMatcherPlugin::new();
        matcher.add_cidr("192.168.1.0/24".parse().unwrap()).unwrap();

        let mut request = Message::new();
        // Regular A query, not PTR
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("ptr_ip_matched").unwrap();
        assert!(!(*matched));
    }
}
