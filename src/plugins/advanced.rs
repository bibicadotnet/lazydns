//! Advanced and utility plugins mirroring upstream mosdns behaviors.
//!
//! This module groups smaller plugins that provide control-flow helpers
//! and response mutations that exist in the upstream implementation.
//! They are lightweight, dependency-free Rust ports designed to be
//! configuration-compatible with their mosdns counterparts.

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::net::IpAddr;
// atomic types are provided by executable collector; keep advanced.rs free of them
use tracing::debug;

// Re-export the executable implementation of the metrics collector so
// callers that referenced `MetricsCollectorPlugin` from this module
// continue to compile while the canonical implementation lives under
// `plugins::executable::collector`.
pub use crate::plugins::executable::collector::MetricsCollectorPlugin;
// Re-exports are provided above for compatibility.

// `ReturnPlugin` and `ParallelPlugin` have been moved to `plugins::control_flow`.
// They are re-exported from this module for backward compatibility.

// `IfPlugin` and `GotoPlugin` have been moved to `plugins::control_flow`.
// They are re-exported above to preserve compatibility.

/// ECS plugin: adds EDNS Client Subnet information to queries.
///
/// This plugin implements RFC 7871 (Client Subnet in DNS Queries) by adding
/// an EDNS0 CLIENT-SUBNET option to outgoing DNS queries. This allows
/// authoritative servers to provide geographically-appropriate responses.
#[derive(Debug, Clone)]
pub struct EcsPlugin {
    client_ip: IpAddr,
    source_prefix_len: u8,
}

impl EcsPlugin {
    /// Create a new ECS plugin with the provided client IP.
    ///
    /// The source prefix length defaults to 24 for IPv4 and 56 for IPv6.
    pub fn new(client_ip: IpAddr) -> Self {
        let source_prefix_len = match client_ip {
            IpAddr::V4(_) => 24,
            IpAddr::V6(_) => 56,
        };
        Self {
            client_ip,
            source_prefix_len,
        }
    }

    /// Create a new ECS plugin with a custom source prefix length.
    pub fn with_prefix_len(client_ip: IpAddr, source_prefix_len: u8) -> Self {
        Self {
            client_ip,
            source_prefix_len,
        }
    }

    /// Generate ECS option data according to RFC 7871.
    ///
    /// Format: FAMILY (2 bytes) | SOURCE PREFIX-LENGTH (1 byte) |
    ///         SCOPE PREFIX-LENGTH (1 byte) | ADDRESS (variable)
    #[allow(clippy::manual_div_ceil)]
    fn generate_ecs_data(&self) -> Vec<u8> {
        let mut data = Vec::new();

        match self.client_ip {
            IpAddr::V4(ipv4) => {
                // Family: 1 = IPv4
                data.push(0);
                data.push(1);
                // Source prefix length
                data.push(self.source_prefix_len);
                // Scope prefix length (0 in queries)
                data.push(0);
                // Address bytes (only prefix bytes needed)
                let addr_bytes = ipv4.octets();
                let num_bytes = ((self.source_prefix_len + 7) / 8) as usize;
                data.extend_from_slice(&addr_bytes[..num_bytes.min(4)]);
            }
            IpAddr::V6(ipv6) => {
                // Family: 2 = IPv6
                data.push(0);
                data.push(2);
                // Source prefix length
                data.push(self.source_prefix_len);
                // Scope prefix length (0 in queries)
                data.push(0);
                // Address bytes (only prefix bytes needed)
                let addr_bytes = ipv6.octets();
                let num_bytes = ((self.source_prefix_len + 7) / 8) as usize;
                data.extend_from_slice(&addr_bytes[..num_bytes.min(16)]);
            }
        }

        data
    }
}

#[async_trait]
impl Plugin for EcsPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Store ECS data in metadata for use by forward plugin
        ctx.set_metadata("ecs_client_ip", self.client_ip);
        ctx.set_metadata("ecs_source_prefix_len", self.source_prefix_len);

        // Store the ECS option data for integration with EDNS0
        let ecs_data = self.generate_ecs_data();
        ctx.set_metadata("ecs_option_data", ecs_data);

        debug!(
            "ECS plugin: set client subnet {}/{} for forwarding",
            self.client_ip, self.source_prefix_len
        );

        Ok(())
    }

    fn name(&self) -> &str {
        "ecs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ecs_sets_metadata() {
        let plugin = EcsPlugin::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_metadata::<IpAddr>("ecs_client_ip"),
            Some(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
    }
}
