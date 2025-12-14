//! IP address matching plugin
//!
//! This plugin matches DNS response IP addresses against CIDR ranges and sets
//! a match result in the context metadata. Useful for geolocation-based routing,
//! blocking specific IP ranges, or other IP-based filtering.
//!
//! # Features
//!
//! - **CIDR matching**: Match IPv4 and IPv6 CIDR ranges
//! - **Individual IP matching**: Match specific IP addresses
//! - **Response inspection**: Checks answer section of DNS responses
//! - **Metadata tagging**: Sets match results in context
//!
//! # Example
//!
//! ```rust
//! use lazydns::plugins::IpMatcherPlugin;
//! use lazydns::plugin::Plugin;
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut matcher = IpMatcherPlugin::new("is_china");
//! // Add China IP ranges (example)
//! matcher.add_cidr("1.0.1.0/24".parse()?)?;
//! matcher.add_cidr("2001:db8::/32".parse()?)?;
//!
//! let plugin: Arc<dyn Plugin> = Arc::new(matcher);
//! # Ok(())
//! # }
//! ```

use crate::dns::{Message, RData};
use crate::error::Error;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use ipnet::IpNet;
use std::fmt;
use std::net::IpAddr;
use tracing::debug;

/// IP matcher plugin for CIDR-based IP matching
///
/// Matches IP addresses in DNS responses against CIDR ranges.
/// Sets a boolean flag in the context metadata when a match is found.
pub struct IpMatcherPlugin {
    /// Metadata key to set when IP matches
    match_key: String,
    /// CIDR ranges to match against
    cidrs: Vec<IpNet>,
}

impl IpMatcherPlugin {
    /// Create a new IP matcher plugin
    ///
    /// # Arguments
    ///
    /// * `match_key` - Metadata key to set when an IP matches
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::IpMatcherPlugin;
    ///
    /// let matcher = IpMatcherPlugin::new("is_local");
    /// ```
    pub fn new(match_key: impl Into<String>) -> Self {
        Self {
            match_key: match_key.into(),
            cidrs: Vec::new(),
        }
    }

    /// Add a CIDR range to match
    ///
    /// # Arguments
    ///
    /// * `cidr` - CIDR range (IPv4 or IPv6)
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::IpMatcherPlugin;
    /// use ipnet::IpNet;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut matcher = IpMatcherPlugin::new("match");
    /// matcher.add_cidr("192.168.0.0/16".parse()?)?;
    /// matcher.add_cidr("2001:db8::/32".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_cidr(&mut self, cidr: IpNet) -> Result<(), Error> {
        self.cidrs.push(cidr);
        Ok(())
    }

    /// Load CIDR ranges from a string (one per line)
    ///
    /// Lines starting with `#` are treated as comments.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::IpMatcherPlugin;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut matcher = IpMatcherPlugin::new("match");
    /// let cidrs = r#"
    /// # Private networks
    /// 192.168.0.0/16
    /// 10.0.0.0/8
    /// 172.16.0.0/12
    /// "#;
    /// matcher.load_from_string(cidrs)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_from_string(&mut self, content: &str) -> Result<(), Error> {
        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse CIDR
            let cidr: IpNet = line
                .parse()
                .map_err(|e| Error::Config(format!("Invalid CIDR '{}': {}", line, e)))?;

            self.add_cidr(cidr)?;
        }

        Ok(())
    }

    /// Check if an IP address matches any CIDR range
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to check
    ///
    /// # Returns
    ///
    /// `true` if the IP matches any CIDR range
    pub fn matches(&self, ip: &IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    /// Get the number of CIDR ranges
    pub fn len(&self) -> usize {
        self.cidrs.len()
    }

    /// Check if the matcher is empty
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// Clear all CIDR ranges
    pub fn clear(&mut self) {
        self.cidrs.clear();
    }

    /// Check if response contains any matching IPs
    fn check_response(&self, response: &Message) -> bool {
        // Check answer section for A and AAAA records
        for record in response.answers() {
            if let Some(ip) = Self::extract_ip(record.rdata()) {
                if self.matches(&ip) {
                    return true;
                }
            }
        }

        false
    }

    /// Extract IP address from RData
    pub fn extract_ip(rdata: &RData) -> Option<IpAddr> {
        match rdata {
            RData::A(ipv4) => Some(IpAddr::V4(*ipv4)),
            RData::AAAA(ipv6) => Some(IpAddr::V6(*ipv6)),
            _ => None,
        }
    }
}

impl fmt::Debug for IpMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpMatcherPlugin")
            .field("match_key", &self.match_key)
            .field("cidr_count", &self.len())
            .finish()
    }
}

#[async_trait]
impl Plugin for IpMatcherPlugin {
    async fn execute(&self, context: &mut Context) -> Result<(), Error> {
        // Only check if we have a response
        let response = match context.response() {
            Some(r) => r,
            None => return Ok(()),
        };

        // Check if any IP in response matches
        let matched = self.check_response(response);

        // Set match result in metadata
        context.set_metadata(self.match_key.clone(), matched);

        if matched {
            debug!("IP matcher '{}': matched response IPs", self.match_key);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "ip_matcher"
    }

    fn priority(&self) -> i32 {
        // Run after forward/cache plugins have set response
        -10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, RecordClass, RecordType, ResourceRecord};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip_matcher_creation() {
        let matcher = IpMatcherPlugin::new("test");
        assert!(matcher.is_empty());
        assert_eq!(matcher.len(), 0);
    }

    #[test]
    fn test_add_cidr() {
        let mut matcher = IpMatcherPlugin::new("test");
        let cidr: IpNet = "192.168.0.0/16".parse().unwrap();

        matcher.add_cidr(cidr).unwrap();

        assert_eq!(matcher.len(), 1);
        assert!(!matcher.is_empty());
    }

    #[test]
    fn test_ipv4_match() {
        let mut matcher = IpMatcherPlugin::new("test");
        matcher.add_cidr("192.168.0.0/16".parse().unwrap()).unwrap();

        assert!(matcher.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(matcher.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!matcher.matches(&IpAddr::V4(Ipv4Addr::new(192, 169, 0, 1))));
        assert!(!matcher.matches(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_ipv6_match() {
        let mut matcher = IpMatcherPlugin::new("test");
        matcher.add_cidr("2001:db8::/32".parse().unwrap()).unwrap();

        assert!(matcher.matches(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(matcher.matches(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        ))));
        assert!(!matcher.matches(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_single_ip_as_cidr() {
        let mut matcher = IpMatcherPlugin::new("test");
        // Single IP as /32
        matcher.add_cidr("192.168.1.1/32".parse().unwrap()).unwrap();

        assert!(matcher.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!matcher.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn test_load_from_string() {
        let mut matcher = IpMatcherPlugin::new("test");
        let content = r#"
# Private networks
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
        "#;

        matcher.load_from_string(content).unwrap();

        assert_eq!(matcher.len(), 3);
        assert!(matcher.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(matcher.matches(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(matcher.matches(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[test]
    fn test_load_from_string_invalid() {
        let mut matcher = IpMatcherPlugin::new("test");
        let content = "invalid.cidr.range";

        let result = matcher.load_from_string(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_clear() {
        let mut matcher = IpMatcherPlugin::new("test");
        matcher.add_cidr("192.168.0.0/16".parse().unwrap()).unwrap();

        assert_eq!(matcher.len(), 1);

        matcher.clear();

        assert_eq!(matcher.len(), 0);
        assert!(matcher.is_empty());
    }

    #[tokio::test]
    async fn test_ip_matcher_plugin_match() {
        let mut matcher = IpMatcherPlugin::new("is_private");
        matcher.add_cidr("192.168.0.0/16".parse().unwrap()).unwrap();

        // Create a response with a matching IP
        let mut response = Message::new();
        response.set_response(true);
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A(Ipv4Addr::new(192, 168, 1, 1)),
        ));

        let mut context = Context::new(Message::new());
        context.set_response(Some(response));

        matcher.execute(&mut context).await.unwrap();

        // Check metadata was set
        let matched: Option<&bool> = context.get_metadata("is_private");
        assert_eq!(matched, Some(&true));
    }

    #[tokio::test]
    async fn test_ip_matcher_plugin_no_match() {
        let mut matcher = IpMatcherPlugin::new("is_private");
        matcher.add_cidr("192.168.0.0/16".parse().unwrap()).unwrap();

        // Create a response with a non-matching IP
        let mut response = Message::new();
        response.set_response(true);
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A(Ipv4Addr::new(8, 8, 8, 8)),
        ));

        let mut context = Context::new(Message::new());
        context.set_response(Some(response));

        matcher.execute(&mut context).await.unwrap();

        // Check metadata was set to false
        let matched: Option<&bool> = context.get_metadata("is_private");
        assert_eq!(matched, Some(&false));
    }

    #[tokio::test]
    async fn test_ip_matcher_no_response() {
        let mut matcher = IpMatcherPlugin::new("match");
        matcher.add_cidr("192.168.0.0/16".parse().unwrap()).unwrap();

        let mut context = Context::new(Message::new());
        // No response set

        matcher.execute(&mut context).await.unwrap();

        // Should not set metadata if no response
        let matched: Option<&bool> = context.get_metadata("match");
        assert_eq!(matched, None);
    }

    #[tokio::test]
    async fn test_ip_matcher_ipv6() {
        let mut matcher = IpMatcherPlugin::new("is_ipv6");
        matcher.add_cidr("2001:db8::/32".parse().unwrap()).unwrap();

        // Create a response with IPv6 address
        let mut response = Message::new();
        response.set_response(true);
        response.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
            300,
            RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ));

        let mut context = Context::new(Message::new());
        context.set_response(Some(response));

        matcher.execute(&mut context).await.unwrap();

        let matched: Option<&bool> = context.get_metadata("is_ipv6");
        assert_eq!(matched, Some(&true));
    }
}
