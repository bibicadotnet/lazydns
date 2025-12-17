//! Hosts file plugin
//!
//! This plugin resolves DNS queries using a hosts file, similar to `/etc/hosts`.
//! It provides local DNS resolution for specific domain names.
//!
//! # Features
//!
//! - **Static mappings**: Map domain names to IP addresses
//! - **Multiple addresses**: Support multiple IPs per domain
//! - **Case-insensitive**: Domain name matching is case-insensitive
//! - **Fast lookup**: HashMap-based O(1) lookups
//! - **Auto-reload**: Watch files for changes and reload automatically
//!
//! # Example
//!
//! ```rust
//! use lazydns::plugins::HostsPlugin;
//! use lazydns::plugin::Plugin;
//! use std::sync::Arc;
//! use std::net::{Ipv4Addr, Ipv6Addr};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut hosts = HostsPlugin::new();
//! hosts.add_host("localhost".to_string(), Ipv4Addr::new(127, 0, 0, 1).into());
//! hosts.add_host("localhost".to_string(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into());
//!
//! let plugin: Arc<dyn Plugin> = Arc::new(hosts);
//! # Ok(())
//! # }
//! ```

use crate::error::Error;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

/// Hosts file plugin for local DNS resolution
///
/// Maps domain names to IP addresses, similar to `/etc/hosts` file.
/// Supports both IPv4 and IPv6 addresses with optional auto-reload.
/// Core hosts parsing and lookup store.
///
/// This struct contains the parsing/lookup logic only. Plugin-related
/// lifecycle (file-watching, conversion to DNS responses, Plugin trait)
/// has been moved to `plugins::executable::HostsPlugin`.
pub struct Hosts {
    /// Domain name to list of IP addresses
    hosts: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
}

impl Hosts {
    /// Create a new hosts plugin
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::hosts::Hosts;
    ///
    /// let hosts = Hosts::new();
    /// ```
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a host mapping
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name (case-insensitive)
    /// * `ip` - IP address (IPv4 or IPv6)
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::hosts::Hosts;
    /// use std::net::Ipv4Addr;
    ///
    /// let hosts = Hosts::new();
    /// hosts.add_host("example.com".to_string(), Ipv4Addr::new(93, 184, 216, 34).into());
    /// ```
    pub fn add_host(&self, domain: String, ip: IpAddr) {
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.hosts.write().entry(domain_lower).or_default().push(ip);
    }

    /// Remove all mappings for a domain
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to remove
    pub fn remove_host(&self, domain: &str) -> bool {
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.hosts.write().remove(&domain_lower).is_some()
    }

    /// Get all IP addresses for a domain
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to lookup
    pub fn get_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.hosts.read().get(&domain_lower).cloned()
    }

    /// Get the number of host entries
    pub fn len(&self) -> usize {
        self.hosts.read().len()
    }

    /// Check if the hosts file is empty
    pub fn is_empty(&self) -> bool {
        self.hosts.read().is_empty()
    }

    /// Clear all host entries
    pub fn clear(&self) {
        self.hosts.write().clear();
    }

    /// Load hosts from a string in hosts file format
    ///
    /// Format: `<ip> <hostname1> [hostname2] ...`
    ///
    /// Lines starting with `#` are treated as comments.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::hosts::Hosts;
    ///
    /// let hosts = Hosts::new();
    /// let content = r#"
    /// 127.0.0.1 localhost
    /// ::1 localhost
    /// 93.184.216.34 example.com www.example.com
    /// "#;
    /// hosts.load_from_string(content).unwrap();
    /// assert_eq!(hosts.len(), 3); // localhost, example.com, www.example.com
    /// ```
    pub fn load_from_string(&self, content: &str) -> Result<(), Error> {
        let mut new_hosts = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: supports both formats:
            // - <ip> <hostname1> [hostname2] ...
            // - <hostname1> [hostname2] ... <ip>
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue; // Skip malformed lines
            }

            // Collect all IP tokens and hostname tokens regardless of order.
            let mut ips: Vec<IpAddr> = Vec::new();
            let mut hostnames: Vec<&str> = Vec::new();

            for &token in &parts {
                if let Ok(ip) = token.parse::<IpAddr>() {
                    ips.push(ip);
                } else {
                    hostnames.push(token);
                }
            }

            if ips.is_empty() {
                return Err(Error::Config(format!(
                    "No valid IP found in hosts line: {}",
                    line
                )));
            }

            // Map every hostname to all discovered IPs on this line
            for &hostname in &hostnames {
                let domain_lower = hostname.to_lowercase();
                new_hosts
                    .entry(domain_lower)
                    .or_insert_with(Vec::new)
                    .extend(ips.iter().cloned());
            }
        }

        *self.hosts.write() = new_hosts;
        Ok(())
    }

    /// Load hosts from a file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the hosts file
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use lazydns::plugins::hosts::Hosts;
    ///
    /// let hosts = Hosts::new();
    /// hosts.load_file("hosts.txt").unwrap();
    /// ```
    pub fn load_file(&self, path: &str) -> Result<(), Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read hosts file '{}': {}", path, e)))?;
        self.load_from_string(&content)
    }
}

impl Default for Hosts {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Hosts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hosts")
            .field("entries", &self.hosts.read().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_hosts_creation() {
        let hosts = Hosts::new();
        assert!(hosts.is_empty());
        assert_eq!(hosts.len(), 0);
    }

    #[test]
    fn test_add_host() {
        let hosts = Hosts::new();
        let ip = Ipv4Addr::new(127, 0, 0, 1);

        hosts.add_host("localhost".to_string(), ip.into());

        assert_eq!(hosts.len(), 1);
        assert!(!hosts.is_empty());
    }

    #[test]
    fn test_case_insensitive() {
        let hosts = Hosts::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);

        hosts.add_host("Example.COM".to_string(), ip.into());

        // Should be able to lookup with different casing
        assert!(hosts.get_ips("example.com").is_some());
        assert!(hosts.get_ips("EXAMPLE.COM").is_some());
        assert!(hosts.get_ips("Example.Com").is_some());
        // Trailing dot should be tolerated
        assert!(hosts.get_ips("Example.Com.").is_some());
    }

    #[test]
    fn test_multiple_ips() {
        let hosts = Hosts::new();
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

        hosts.add_host("localhost".to_string(), ipv4.into());
        hosts.add_host("localhost".to_string(), ipv6.into());

        let ips = hosts.get_ips("localhost").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_remove_host() {
        let hosts = Hosts::new();
        let ip = Ipv4Addr::new(127, 0, 0, 1);

        hosts.add_host("localhost".to_string(), ip.into());
        assert_eq!(hosts.len(), 1);

        assert!(hosts.remove_host("localhost"));
        assert_eq!(hosts.len(), 0);
        assert!(hosts.is_empty());

        // Removing non-existent host returns false
        assert!(!hosts.remove_host("localhost"));
    }

    #[test]
    fn test_clear() {
        let hosts = Hosts::new();
        hosts.add_host("example.com".to_string(), Ipv4Addr::new(1, 2, 3, 4).into());
        hosts.add_host("test.com".to_string(), Ipv4Addr::new(5, 6, 7, 8).into());

        assert_eq!(hosts.len(), 2);

        hosts.clear();

        assert_eq!(hosts.len(), 0);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_load_from_string() {
        let hosts = Hosts::new();
        let content = r#"
# Comment line
127.0.0.1 localhost
::1 localhost ip6-localhost
93.184.216.34 example.com www.example.com
        "#;

        hosts.load_from_string(content).unwrap();

        assert!(!hosts.is_empty());
        assert!(hosts.get_ips("localhost").is_some());
        assert!(hosts.get_ips("example.com").is_some());
        assert!(hosts.get_ips("www.example.com").is_some());
        assert!(hosts.get_ips("ip6-localhost").is_some());
    }

    #[test]
    fn test_load_from_string_invalid_ip() {
        let hosts = Hosts::new();
        let content = "invalid.ip.address example.com";

        let result = hosts.load_from_string(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_string_hostname_first() {
        let hosts = Hosts::new();
        let content = r#"
# hostname-first format
localhost 127.0.0.1
example.com www.example.com 93.184.216.34 2606:50c0:8001::154
example.com 2606:50c0:8001::158
"#;

        hosts.load_from_string(content).unwrap();

        assert!(!hosts.is_empty());
        assert!(hosts.get_ips("localhost").is_some());
        assert!(hosts.get_ips("example.com").is_some());
        assert!(hosts.get_ips("www.example.com").is_some());

        // Ensure IPv6 was parsed as well
        let ips = hosts.get_ips("example.com").unwrap();
        assert!(ips.iter().any(|ip| matches!(ip, IpAddr::V6(_))));
        assert_eq!(ips.len(), 3);

        // Ensure domain aliases was parsed as well
        let ips = hosts.get_ips("www.example.com").unwrap();
        assert!(ips.iter().any(|ip| matches!(ip, IpAddr::V6(_))));
        assert_eq!(ips.len(), 2)
    }

    #[test]
    fn test_load_from_string_mixed_orders() {
        let hosts = Hosts::new();
        let content = r#"
# hostname-first format
localhost 127.0.0.1
example.com www.example.com 93.184.216.34 2606:50c0:8001::154
2606:50c0:8001::158 example.com
1.1.1.1 global-dns.com
"#;
        hosts.load_from_string(content).unwrap();
        assert!(hosts.get_ips("localhost").is_some());
        assert!(hosts.get_ips("example.com").is_some());
        assert!(hosts.get_ips("www.example.com").is_some());
        assert!(hosts.get_ips("global-dns.com").is_some());
    }
}
