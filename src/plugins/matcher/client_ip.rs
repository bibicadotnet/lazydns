//! Client IP matcher plugin
//!
//! Matches queries based on the client's IP address

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use ipnet::IpNet;
use std::fmt;
use std::net::IpAddr;
use tracing::debug;

/// Plugin that matches queries based on client IP address
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::ClientIpMatcherPlugin;
/// use std::net::IpAddr;
///
/// let mut matcher = ClientIpMatcherPlugin::new();
/// matcher.add_ip("192.168.1.100".parse().unwrap());
/// matcher.add_cidr("10.0.0.0/8".parse().unwrap()).unwrap();
/// ```
pub struct ClientIpMatcherPlugin {
    /// List of allowed IP addresses
    allowed_ips: Vec<IpAddr>,
    /// List of allowed CIDR ranges
    allowed_cidrs: Vec<IpNet>,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl ClientIpMatcherPlugin {
    /// Create a new client IP matcher plugin
    pub fn new() -> Self {
        Self {
            allowed_ips: Vec::new(),
            allowed_cidrs: Vec::new(),
            metadata_key: "client_ip_matched".to_string(),
        }
    }

    /// Add a specific IP address to match
    pub fn add_ip(&mut self, ip: IpAddr) {
        self.allowed_ips.push(ip);
    }

    /// Add a CIDR range to match
    pub fn add_cidr(&mut self, cidr: IpNet) -> Result<()> {
        self.allowed_cidrs.push(cidr);
        Ok(())
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if an IP address matches
    fn matches_ip(&self, ip: IpAddr) -> bool {
        // Check exact match
        if self.allowed_ips.contains(&ip) {
            return true;
        }

        // Check CIDR ranges
        for cidr in &self.allowed_cidrs {
            if cidr.contains(&ip) {
                return true;
            }
        }

        false
    }
}

impl Default for ClientIpMatcherPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ClientIpMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIpMatcherPlugin")
            .field("allowed_ips", &self.allowed_ips)
            .field("allowed_cidrs", &self.allowed_cidrs)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for ClientIpMatcherPlugin {
    fn name(&self) -> &str {
        "client_ip_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Get client IP from context metadata
        if let Some(client_ip) = ctx.get_metadata::<IpAddr>("client_ip") {
            let matched = self.matches_ip(*client_ip);

            if matched {
                debug!(
                    client_ip = %client_ip,
                    "Client IP matcher: matched"
                );
                ctx.set_metadata(self.metadata_key.clone(), true);
            } else {
                debug!(
                    client_ip = %client_ip,
                    "Client IP matcher: no match"
                );
                ctx.set_metadata(self.metadata_key.clone(), false);
            }
        } else {
            // No client IP in context
            ctx.set_metadata(self.metadata_key.clone(), false);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_client_ip_matcher_exact() {
        let mut matcher = ClientIpMatcherPlugin::new();
        matcher.add_ip("192.168.1.100".parse().unwrap());

        let mut ctx = Context::new(Message::new());
        ctx.set_metadata(
            "client_ip".to_string(),
            "192.168.1.100".parse::<IpAddr>().unwrap(),
        );

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("client_ip_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_client_ip_matcher_no_match() {
        let mut matcher = ClientIpMatcherPlugin::new();
        matcher.add_ip("192.168.1.100".parse().unwrap());

        let mut ctx = Context::new(Message::new());
        ctx.set_metadata(
            "client_ip".to_string(),
            "192.168.1.200".parse::<IpAddr>().unwrap(),
        );

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("client_ip_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_client_ip_matcher_cidr() {
        let mut matcher = ClientIpMatcherPlugin::new();
        matcher.add_cidr("192.168.1.0/24".parse().unwrap()).unwrap();

        let mut ctx = Context::new(Message::new());
        ctx.set_metadata(
            "client_ip".to_string(),
            "192.168.1.100".parse::<IpAddr>().unwrap(),
        );

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("client_ip_matched").unwrap();
        assert!(*matched);
    }

    #[tokio::test]
    async fn test_client_ip_matcher_cidr_no_match() {
        let mut matcher = ClientIpMatcherPlugin::new();
        matcher.add_cidr("192.168.1.0/24".parse().unwrap()).unwrap();

        let mut ctx = Context::new(Message::new());
        ctx.set_metadata(
            "client_ip".to_string(),
            "192.168.2.100".parse::<IpAddr>().unwrap(),
        );

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("client_ip_matched").unwrap();
        assert!(!(*matched));
    }

    #[tokio::test]
    async fn test_client_ip_matcher_no_client_ip() {
        let matcher = ClientIpMatcherPlugin::new();
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("client_ip_matched").unwrap();
        assert!(!(*matched));
    }
}
