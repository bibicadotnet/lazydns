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
//! let plugin = HostsPlugin::new();
//! plugin.add_host("localhost".to_string(), Ipv4Addr::new(127, 0, 0, 1).into());
//! plugin.add_host("localhost".to_string(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into());
//!
//! let arc_plugin: Arc<dyn Plugin> = Arc::new(plugin);
//! # Ok(())
//! # }
//! ```

use crate::config::PluginConfig;
use crate::dns::{Message, Question, RData, RecordType, ResourceRecord};
use crate::error::Error;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

// Auto-register using the register macro
crate::register_plugin_builder!(HostsPlugin);

/// Core hosts parsing and lookup store
///
/// Maps domain names to IP addresses, similar to `/etc/hosts` file.
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
    pub fn load_from_string(&self, content: &str) -> Result<()> {
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
    #[allow(dead_code)]
    pub fn load_file(&self, path: &str) -> Result<()> {
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

/// Hosts plugin wrapper: lifecycle, file watching and Plugin impl
pub struct HostsPlugin {
    hosts: Arc<Hosts>,
    files: Vec<PathBuf>,
    auto_reload: bool,
}

impl HostsPlugin {
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(Hosts::new()),
            files: Vec::new(),
            auto_reload: false,
        }
    }

    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = files.into_iter().map(PathBuf::from).collect();
        self
    }

    pub fn with_auto_reload(mut self, enabled: bool) -> Self {
        self.auto_reload = enabled;
        self
    }

    pub fn add_host(&self, domain: String, ip: IpAddr) {
        self.hosts.add_host(domain, ip);
    }

    pub fn remove_host(&self, domain: &str) -> bool {
        self.hosts.remove_host(domain)
    }

    pub fn get_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        self.hosts.get_ips(domain)
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn clear(&self) {
        self.hosts.clear();
    }

    /// Load hosts from configured files (aggregated)
    pub fn load_hosts(&self) -> Result<()> {
        let mut combined = String::new();
        for file_path in &self.files {
            match std::fs::read_to_string(file_path) {
                Ok(c) => {
                    combined.push_str(&c);
                    combined.push('\n');
                }
                Err(e) => warn!(file = ?file_path, error = %e, "Failed to read hosts file"),
            }
        }

        if !combined.is_empty() {
            self.hosts.load_from_string(&combined)?;
        }

        info!(
            entries = self.len(),
            files = self.files.len(),
            "Hosts loaded (wrapper)"
        );
        Ok(())
    }

    /// Start file watcher if auto-reload is enabled
    pub fn start_file_watcher(&self) {
        if !self.auto_reload || self.files.is_empty() {
            return;
        }

        let files = self.files.clone();
        let hosts = Arc::clone(&self.hosts);

        info!(auto_reload = true, files = ?files, "file auto-reload status");

        const DEBOUNCE_MS: u64 = 200;

        crate::utils::spawn_file_watcher(
            "hosts",
            files.clone(),
            DEBOUNCE_MS,
            move |_path, files| {
                let file_name = files
                    .first()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                // Aggregate file contents and reload using core parser
                let start = std::time::Instant::now();
                let mut combined = String::new();

                for file_path in files {
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        combined.push_str(&content);
                        combined.push('\n');
                    } else {
                        warn!(file = ?file_path, "Failed to read hosts file");
                    }
                }

                if !combined.is_empty() {
                    if let Err(e) = hosts.load_from_string(&combined) {
                        warn!(error = %e, "Failed to parse hosts file during auto-reload");
                    }
                }

                let duration = start.elapsed();
                info!(filename = file_name, duration = ?duration, "scheduled auto-reload completed");
            },
        );
    }

    /// Build a DNS response for the provided question and IPs
    fn create_response(&self, question: &Question, ips: &[IpAddr]) -> Message {
        let mut response = Message::new();
        response.set_response(true);
        response.set_authoritative(true);
        response.set_recursion_available(false);

        response.add_question(question.clone());

        let qtype = question.qtype();
        let qname = question.qname().to_string();
        let qclass = question.qclass();

        for ip in ips {
            let record = match (ip, qtype) {
                (IpAddr::V4(ipv4), RecordType::A) => Some(ResourceRecord::new(
                    qname.clone(),
                    RecordType::A,
                    qclass,
                    3600,
                    RData::A(*ipv4),
                )),
                (IpAddr::V6(ipv6), RecordType::AAAA) => Some(ResourceRecord::new(
                    qname.clone(),
                    RecordType::AAAA,
                    qclass,
                    3600,
                    RData::AAAA(*ipv6),
                )),
                _ => None,
            };

            if let Some(r) = record {
                response.add_answer(r);
            }
        }

        response
    }
}

impl Default for HostsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HostsPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostsPlugin")
            .field("entries", &self.hosts.len())
            .finish()
    }
}

#[async_trait]
impl Plugin for HostsPlugin {
    async fn execute(&self, context: &mut Context) -> Result<()> {
        if context.response().is_some() {
            return Ok(());
        }

        let question = match context.request().questions().first() {
            Some(q) => q,
            None => return Ok(()),
        };

        let qtype = question.qtype();
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return Ok(());
        }

        let domain = question.qname();
        if let Some(ips) = self.get_ips(domain) {
            debug!("Hosts plugin: Found {} IPs for {}", ips.len(), domain);

            let mut response = self.create_response(question, &ips);
            response.set_id(context.request().id());
            response.set_response_code(crate::dns::ResponseCode::NoError);

            context.set_response(Some(response));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "hosts"
    }

    fn priority(&self) -> i32 {
        100
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();
        use serde_yaml::Value;

        let mut plugin = HostsPlugin::new();

        if let Some(files_val) = args.get("files") {
            match files_val {
                Value::Sequence(seq) => {
                    let files: Vec<String> = seq
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    plugin = plugin.with_files(files);
                }
                Value::String(s) => {
                    plugin = plugin.with_files(vec![s.clone()]);
                }
                _ => {}
            }
        }

        if let Some(Value::Bool(b)) = args.get("auto_reload") {
            plugin = plugin.with_auto_reload(*b);
        }

        // Load hosts immediately
        if let Err(e) = plugin.load_hosts() {
            tracing::warn!(error = %e, "Failed to load hosts during init, continuing");
        }

        // Start file watcher if auto-reload is enabled
        plugin.start_file_watcher();

        Ok(Arc::new(plugin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordClass;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- Core Hosts tests ---

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

    // --- HostsPlugin tests ---

    #[tokio::test]
    async fn test_hosts_plugin_a_query() {
        let plugin = HostsPlugin::new();
        plugin.add_host(
            "example.com".to_string(),
            Ipv4Addr::new(93, 184, 216, 34).into(),
        );

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        let response = context.response();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rtype(), RecordType::A);
    }

    #[tokio::test]
    async fn test_hosts_plugin_aaaa_query() {
        let plugin = HostsPlugin::new();
        plugin.add_host(
            "example.com".to_string(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
        );

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        let response = context.response();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rtype(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_hosts_plugin_hostname_first_ipv4_and_ipv6() {
        let plugin = HostsPlugin::new();
        let content = "media.githubusercontent.com 185.199.108.133 2606:50c0:8001::154";
        plugin.load_hosts().unwrap();
        // load_hosts() uses configured files; instead parse directly
        plugin.hosts.load_from_string(content).unwrap();

        // A query
        let mut request_a = Message::new();
        request_a.add_question(Question::new(
            "media.githubusercontent.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx_a = Context::new(request_a);
        plugin.execute(&mut ctx_a).await.unwrap();
        let resp_a = ctx_a.response().unwrap();
        assert_eq!(resp_a.answers().len(), 1);
        assert_eq!(resp_a.answers()[0].rtype(), RecordType::A);

        // AAAA query
        let mut request_aaaa = Message::new();
        request_aaaa.add_question(Question::new(
            "media.githubusercontent.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));
        let mut ctx_aaaa = Context::new(request_aaaa);
        plugin.execute(&mut ctx_aaaa).await.unwrap();
        let resp_aaaa = ctx_aaaa.response().unwrap();
        assert_eq!(resp_aaaa.answers().len(), 1);
        assert_eq!(resp_aaaa.answers()[0].rtype(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_hosts_plugin_no_match() {
        let plugin = HostsPlugin::new();
        plugin.add_host(
            "example.com".to_string(),
            Ipv4Addr::new(93, 184, 216, 34).into(),
        );

        let mut request = Message::new();
        request.add_question(Question::new(
            "notfound.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        // Should not set a response
        assert!(context.response().is_none());
    }

    #[tokio::test]
    async fn test_hosts_plugin_wrong_type() {
        let plugin = HostsPlugin::new();
        // Add IPv4 address
        plugin.add_host(
            "example.com".to_string(),
            Ipv4Addr::new(93, 184, 216, 34).into(),
        );

        // Query for AAAA (IPv6)
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        // Should set response but with no answers
        let response = context.response();
        assert!(response.is_some());
        assert_eq!(response.unwrap().answers().len(), 0);
    }

    #[tokio::test]
    async fn test_hosts_plugin_skips_if_response_set() {
        let plugin = HostsPlugin::new();
        plugin.add_host("example.com".to_string(), Ipv4Addr::new(1, 2, 3, 4).into());

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);

        // Pre-set a response
        let mut pre_response = Message::new();
        pre_response.set_id(999);
        context.set_response(Some(pre_response));

        plugin.execute(&mut context).await.unwrap();

        // Should not modify the pre-set response
        assert_eq!(context.response().unwrap().id(), 999);
    }
}
