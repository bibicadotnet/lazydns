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

use crate::dns::{Message, Question, RData, RecordType, ResourceRecord};
use crate::error::Error;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Hosts file plugin for local DNS resolution
///
/// Maps domain names to IP addresses, similar to `/etc/hosts` file.
/// Supports both IPv4 and IPv6 addresses with optional auto-reload.
pub struct HostsPlugin {
    /// Domain name to list of IP addresses (shared for auto-reload)
    hosts: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    /// Files to load hosts from
    files: Vec<PathBuf>,
    /// Whether to auto-reload files
    auto_reload: bool,
}

impl HostsPlugin {
    /// Create a new hosts plugin
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::HostsPlugin;
    ///
    /// let hosts = HostsPlugin::new();
    /// ```
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            files: Vec::new(),
            auto_reload: false,
        }
    }

    /// Set files to load hosts from
    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = files.into_iter().map(PathBuf::from).collect();
        self
    }

    /// Enable auto-reload
    pub fn with_auto_reload(mut self, enabled: bool) -> Self {
        self.auto_reload = enabled;
        self
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
    /// use lazydns::plugins::HostsPlugin;
    /// use std::net::Ipv4Addr;
    ///
    /// let mut hosts = HostsPlugin::new();
    /// hosts.add_host("example.com".to_string(), Ipv4Addr::new(93, 184, 216, 34).into());
    /// ```
    pub fn add_host(&mut self, domain: String, ip: IpAddr) {
        let domain_lower = domain.to_lowercase();
        self.hosts.write().entry(domain_lower).or_default().push(ip);
    }

    /// Remove all mappings for a domain
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to remove
    pub fn remove_host(&mut self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.hosts.write().remove(&domain_lower).is_some()
    }

    /// Get all IP addresses for a domain
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to lookup
    pub fn get_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let domain_lower = domain.to_lowercase();
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
    pub fn clear(&mut self) {
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
    /// use lazydns::plugins::HostsPlugin;
    ///
    /// let mut hosts = HostsPlugin::new();
    /// let content = r#"
    /// 127.0.0.1 localhost
    /// ::1 localhost
    /// 93.184.216.34 example.com www.example.com
    /// "#;
    /// hosts.load_from_string(content).unwrap();
    /// assert_eq!(hosts.len(), 3); // localhost, example.com, www.example.com
    /// ```
    pub fn load_from_string(&mut self, content: &str) -> Result<(), Error> {
        let mut new_hosts = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: <ip> <hostname1> [hostname2] ...
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue; // Skip malformed lines
            }

            let ip: IpAddr = parts[0]
                .parse()
                .map_err(|_| Error::Config(format!("Invalid IP address: {}", parts[0])))?;

            // Add all hostnames for this IP
            for hostname in &parts[1..] {
                let domain_lower = hostname.to_lowercase();
                new_hosts
                    .entry(domain_lower)
                    .or_insert_with(Vec::new)
                    .push(ip);
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
    /// use lazydns::plugins::HostsPlugin;
    ///
    /// let mut hosts = HostsPlugin::new();
    /// hosts.load_file("hosts.txt").unwrap();
    /// ```
    pub fn load_file(&mut self, path: &str) -> Result<(), Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read hosts file '{}': {}", path, e)))?;
        self.load_from_string(&content)
    }

    /// Load hosts from all configured files
    pub fn load_hosts(&self) -> Result<(), Error> {
        let mut all_hosts = HashMap::new();

        for file_path in &self.files {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 2 {
                        continue;
                    }

                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                        for hostname in &parts[1..] {
                            let domain_lower = hostname.to_lowercase();
                            all_hosts
                                .entry(domain_lower)
                                .or_insert_with(Vec::new)
                                .push(ip);
                        }
                    }
                }
            } else {
                warn!(file = ?file_path, "Failed to read hosts file");
            }
        }

        *self.hosts.write() = all_hosts;
        info!(
            entries = self.len(),
            files = self.files.len(),
            "Hosts loaded"
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

        info!(
            auto_reload = true,
            files = ?files,
            "file auto-reload status"
        );

        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel(100);

            let mut watcher =
                match notify::recommended_watcher(move |res: notify::Result<Event>| match res {
                    Ok(event) => {
                        if matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                        ) {
                            let _ = tx.blocking_send(event);
                        }
                    }
                    Err(e) => {
                        error!("file watcher error: {:?}", e);
                    }
                }) {
                    Ok(w) => w,
                    Err(e) => {
                        error!(error = %e, "failed to create file watcher");
                        return;
                    }
                };

            // Canonicalize file paths for accurate comparison with event paths
            let canonical_files: Vec<PathBuf> =
                files.iter().filter_map(|p| p.canonicalize().ok()).collect();

            // Track last reload times to debounce rapid successive events
            let mut last_reload: HashMap<PathBuf, Instant> = HashMap::new();
            const DEBOUNCE_MS: u64 = 200;

            // Watch all files
            for file_path in &files {
                debug!(file = ?file_path, "start watching file");
                if let Err(e) = watcher.watch(file_path, RecursiveMode::NonRecursive) {
                    warn!(file = ?file_path, error = %e, "failed to watch file");
                }
            }

            info!("file watcher started successfully");
            debug!("file watcher loop started");

            // Process file change events
            while let Some(event) = rx.recv().await {
                for path in &event.paths {
                    // Compare with canonical paths
                    let canonical_path = path.canonicalize().ok();
                    if canonical_path
                        .as_ref()
                        .is_some_and(|cp| canonical_files.contains(cp))
                    {
                        let file_name = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");

                        // Debounce rapid reloads per-file
                        let now = Instant::now();
                        if let Some(cp) = canonical_path.as_ref() {
                            if let Some(prev) = last_reload.get(cp) {
                                if now.duration_since(*prev) < Duration::from_millis(DEBOUNCE_MS) {
                                    debug!(file = file_name, "skipping reload due to debounce");
                                    continue;
                                }
                            }
                            last_reload.insert(cp.clone(), now);
                        }

                        // Handle file removal/rename
                        if matches!(event.kind, EventKind::Remove(_)) {
                            info!(
                                file = file_name,
                                "file removed or renamed, attempting to re-watch"
                            );

                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                            if path.exists() {
                                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                                    warn!(file = file_name, error = %e, "failed to re-watch file");
                                } else {
                                    info!(
                                        file = file_name,
                                        "successfully re-added file to watch list"
                                    );
                                }
                            }
                        }

                        // Reload hosts
                        info!(file = file_name, "scheduled reload: invoking callback");

                        let start = std::time::Instant::now();
                        let mut all_hosts = HashMap::new();

                        for file_path in &files {
                            if let Ok(content) = std::fs::read_to_string(file_path) {
                                for line in content.lines() {
                                    let line = line.trim();
                                    if line.is_empty() || line.starts_with('#') {
                                        continue;
                                    }

                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() < 2 {
                                        continue;
                                    }

                                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                                        for hostname in &parts[1..] {
                                            let domain_lower = hostname.to_lowercase();
                                            all_hosts
                                                .entry(domain_lower)
                                                .or_insert_with(Vec::new)
                                                .push(ip);
                                        }
                                    }
                                }
                            }
                        }

                        *hosts.write() = all_hosts;
                        let duration = start.elapsed();

                        info!(
                            filename = file_name,
                            duration = ?duration,
                            "scheduled auto-reload completed"
                        );

                        break;
                    }
                }
            }

            debug!("file watcher closed, exiting loop");
        });
    }

    /// Create a DNS response with the given IPs
    fn create_response(&self, question: &Question, ips: &[IpAddr]) -> Message {
        let mut response = Message::new();
        response.set_response(true);
        response.set_authoritative(true);
        response.set_recursion_available(false);

        // Add the question
        response.add_question(question.clone());

        // Add answer records
        let qtype = question.qtype();
        let qname = question.qname().to_string();
        let qclass = question.qclass();

        for ip in ips {
            let record = match (ip, qtype) {
                // IPv4 address and A query
                (IpAddr::V4(ipv4), RecordType::A) => Some(ResourceRecord::new(
                    qname.clone(),
                    RecordType::A,
                    qclass,
                    3600, // 1 hour TTL
                    RData::A(*ipv4),
                )),
                // IPv6 address and AAAA query
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
            .field("entries", &self.hosts.read().len())
            .finish()
    }
}

#[async_trait]
impl Plugin for HostsPlugin {
    async fn execute(&self, context: &mut Context) -> Result<(), Error> {
        // If response is already set, skip
        if context.response().is_some() {
            return Ok(());
        }

        // Get the first question
        let question = match context.request().questions().first() {
            Some(q) => q,
            None => return Ok(()),
        };

        // Only handle A and AAAA queries
        let qtype = question.qtype();
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return Ok(());
        }

        // Lookup in hosts file
        let domain = question.qname();
        if let Some(ips) = self.get_ips(domain) {
            debug!("Hosts plugin: Found {} IPs for {}", ips.len(), domain);

            // Create response
            let mut response = self.create_response(question, &ips);

            // Copy request ID to response
            response.set_id(context.request().id());

            // Set response code
            response.set_response_code(crate::dns::ResponseCode::NoError);

            context.set_response(Some(response));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "hosts"
    }

    fn priority(&self) -> i32 {
        // Hosts should run early, before forward
        100
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordClass;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_hosts_plugin_creation() {
        let hosts = HostsPlugin::new();
        assert!(hosts.is_empty());
        assert_eq!(hosts.len(), 0);
    }

    #[test]
    fn test_add_host() {
        let mut hosts = HostsPlugin::new();
        let ip = Ipv4Addr::new(127, 0, 0, 1);

        hosts.add_host("localhost".to_string(), ip.into());

        assert_eq!(hosts.len(), 1);
        assert!(!hosts.is_empty());
    }

    #[test]
    fn test_case_insensitive() {
        let mut hosts = HostsPlugin::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);

        hosts.add_host("Example.COM".to_string(), ip.into());

        // Should be able to lookup with different casing
        assert!(hosts.get_ips("example.com").is_some());
        assert!(hosts.get_ips("EXAMPLE.COM").is_some());
        assert!(hosts.get_ips("Example.Com").is_some());
    }

    #[test]
    fn test_multiple_ips() {
        let mut hosts = HostsPlugin::new();
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

        hosts.add_host("localhost".to_string(), ipv4.into());
        hosts.add_host("localhost".to_string(), ipv6.into());

        let ips = hosts.get_ips("localhost").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_remove_host() {
        let mut hosts = HostsPlugin::new();
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
        let mut hosts = HostsPlugin::new();
        hosts.add_host("example.com".to_string(), Ipv4Addr::new(1, 2, 3, 4).into());
        hosts.add_host("test.com".to_string(), Ipv4Addr::new(5, 6, 7, 8).into());

        assert_eq!(hosts.len(), 2);

        hosts.clear();

        assert_eq!(hosts.len(), 0);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_load_from_string() {
        let mut hosts = HostsPlugin::new();
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
        let mut hosts = HostsPlugin::new();
        let content = "invalid.ip.address example.com";

        let result = hosts.load_from_string(content);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_hosts_plugin_a_query() {
        let mut hosts = HostsPlugin::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        hosts.add_host("example.com".to_string(), ip.into());

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        hosts.execute(&mut context).await.unwrap();

        let response = context.response();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rtype(), RecordType::A);
    }

    #[tokio::test]
    async fn test_hosts_plugin_aaaa_query() {
        let mut hosts = HostsPlugin::new();
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        hosts.add_host("example.com".to_string(), ip.into());

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        hosts.execute(&mut context).await.unwrap();

        let response = context.response();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rtype(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_hosts_plugin_no_match() {
        let mut hosts = HostsPlugin::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        hosts.add_host("example.com".to_string(), ip.into());

        let mut request = Message::new();
        request.add_question(Question::new(
            "notfound.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        hosts.execute(&mut context).await.unwrap();

        // Should not set a response
        assert!(context.response().is_none());
    }

    #[tokio::test]
    async fn test_hosts_plugin_wrong_type() {
        let mut hosts = HostsPlugin::new();
        // Add IPv4 address
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        hosts.add_host("example.com".to_string(), ip.into());

        // Query for AAAA (IPv6)
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        hosts.execute(&mut context).await.unwrap();

        // Should set response but with no answers
        let response = context.response();
        assert!(response.is_some());
        assert_eq!(response.unwrap().answers().len(), 0);
    }

    #[tokio::test]
    async fn test_hosts_plugin_skips_if_response_set() {
        let mut hosts = HostsPlugin::new();
        hosts.add_host("example.com".to_string(), Ipv4Addr::new(1, 2, 3, 4).into());

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

        hosts.execute(&mut context).await.unwrap();

        // Should not modify the pre-set response
        assert_eq!(context.response().unwrap().id(), 999);
    }
}
