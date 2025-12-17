//! DNS plugins collection
//!
//! This module contains concrete implementations of DNS plugins.
//! Each plugin implements the Plugin trait and provides specific
//! DNS query processing functionality.
//!
//! # Available Plugins
//!
//! - **forward**: Forward queries to upstream DNS servers
//! - **cache**: Cache DNS responses with TTL-based expiration and LRU eviction
//! - **hosts**: Resolve from local hosts file mappings
//! - **domain_matcher**: Match domains against patterns with wildcard support
//! - **ip_matcher**: Match response IPs against CIDR ranges
//! - **geoip**: Geographic IP address matching
//! - **geosite**: Geographic domain name matching
//! - **advanced**: Upstream control/utility plugins (TTL rewrite, blackhole, etc.)
//!
//! # Example
//!
//! ```rust,no_run
//! use lazydns::plugins::ForwardPlugin;
//! use lazydns::plugin::{Plugin, Context};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let plugin = ForwardPlugin::new(vec!["8.8.8.8:53".to_string()]);
//! let plugin: Arc<dyn Plugin> = Arc::new(plugin);
//! # Ok(())
//! # }
//! ```

pub mod acl;
pub mod advanced;
pub mod cache;
pub mod control_flow;
pub mod data_provider;
pub mod domain_matcher;
pub mod executable;
pub mod forward;
pub mod geoip;
pub mod geosite;
pub mod hosts;
pub mod ip_matcher;
pub mod mark;
pub mod matcher;
pub mod ratelimit;
pub mod server;
// utils module moved to crate-level `src/utils.rs`

// Re-export plugins
pub use acl::{AclAction, QueryAclPlugin};
pub use advanced::{
    ArbitraryPlugin, ArbitraryRecordBuilder, BlackholePlugin, DropResponsePlugin, EcsPlugin,
    GotoPlugin, IfPlugin, IpsetPlugin, MetricsCollectorPlugin, NftsetPlugin, ParallelPlugin,
    QuerySummaryPlugin, ReturnPlugin, ReverseLookupPlugin, SequencePlugin, TtlPlugin,
};
pub use cache::{CachePlugin, CacheStorePlugin};
pub use control_flow::{
    AcceptPlugin, JumpPlugin, PreferIpv4Plugin, PreferIpv6Plugin, RejectPlugin,
};
pub use data_provider::{DomainSetPlugin, IpSetPlugin};
pub use domain_matcher::DomainMatcherPlugin;
pub use executable::HostsPlugin;
pub use forward::{ForwardPlugin, ForwardPluginBuilder, LoadBalanceStrategy};
pub use geoip::GeoIpPlugin;
pub use geosite::GeoSitePlugin;
pub use ip_matcher::IpMatcherPlugin;
pub use mark::MarkPlugin;
pub use ratelimit::RateLimitPlugin;

// Re-export matcher plugins
pub use matcher::{
    BaseIntMatcherPlugin, ClientIpMatcherPlugin, CnameMatcherPlugin, EnvMatcherPlugin,
    HasRespMatcherPlugin, HasWantedAnsMatcherPlugin, IntComparison, PtrIpMatcherPlugin,
    QClassMatcherPlugin, QNameMatcherPlugin, QTypeMatcherPlugin, RCodeMatcherPlugin,
    RandomMatcherPlugin, StringExpMatcherPlugin, StringExpression,
};

// Re-export executable plugins
pub use executable::{
    DebugPrintPlugin, DualSelectorPlugin, Edns0Option, FallbackPlugin, ForwardEdns0OptPlugin,
    IpPreference, RedirectPlugin, RosAddrListPlugin, SleepPlugin,
};

// Re-export server plugins
pub use server::{TcpServerPlugin, UdpServerPlugin};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::Plugin;
    use std::sync::Arc;

    #[test]
    fn test_forward_plugin_accessible() {
        // Verify ForwardPlugin can be created
        let plugin = ForwardPlugin::new(vec!["8.8.8.8:53".to_string()]);
        assert_eq!(plugin.name(), "forward");
    }

    #[test]
    fn test_cache_plugin_accessible() {
        // Verify CachePlugin can be created
        let plugin = CachePlugin::new(100);
        assert_eq!(plugin.name(), "cache");
    }

    #[test]
    fn test_hosts_plugin_accessible() {
        // Verify HostsPlugin can be created
        let plugin = HostsPlugin::new();
        assert_eq!(plugin.name(), "hosts");
    }

    #[test]
    fn test_domain_matcher_plugin_accessible() {
        // Verify DomainMatcherPlugin can be created
        let plugin = DomainMatcherPlugin::new("match_key");
        assert_eq!(plugin.name(), "domain_matcher");
    }

    #[test]
    fn test_ip_matcher_plugin_accessible() {
        // Verify IpMatcherPlugin can be created
        let plugin = IpMatcherPlugin::new("match_key");
        assert_eq!(plugin.name(), "ip_matcher");
    }

    #[test]
    fn test_ratelimit_plugin_accessible() {
        // Verify RateLimitPlugin can be created
        let plugin = RateLimitPlugin::new(10, 60);
        assert_eq!(plugin.name(), "rate_limit"); // Note: actual name is "rate_limit" with underscore
    }

    #[test]
    fn test_advanced_plugins_accessible() {
        // Verify advanced plugin types are accessible
        let _blackhole = BlackholePlugin;
        let _ttl = TtlPlugin::new(300);
        let _return = ReturnPlugin;
    }

    #[test]
    fn test_load_balance_strategy() {
        // Verify LoadBalanceStrategy enum is accessible
        let _rr = LoadBalanceStrategy::RoundRobin;
        let _random = LoadBalanceStrategy::Random;
        let _fastest = LoadBalanceStrategy::Fastest;

        assert_eq!(
            LoadBalanceStrategy::RoundRobin,
            LoadBalanceStrategy::RoundRobin
        );
    }

    #[test]
    fn test_acl_action() {
        // Verify AclAction enum is accessible
        let _allow = AclAction::Allow;
        let _deny = AclAction::Deny;
    }

    #[test]
    fn test_plugins_implement_trait() {
        // Verify plugins can be used as trait objects
        let forward: Arc<dyn Plugin> = Arc::new(ForwardPlugin::new(vec!["8.8.8.8:53".to_string()]));
        let cache: Arc<dyn Plugin> = Arc::new(CachePlugin::new(100));
        let hosts: Arc<dyn Plugin> = Arc::new(HostsPlugin::new());

        assert_eq!(forward.name(), "forward");
        assert_eq!(cache.name(), "cache");
        assert_eq!(hosts.name(), "hosts");
    }
}
