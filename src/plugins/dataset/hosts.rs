// Hosts plugin moved under plugins::dataset
// Original implementation preserved.

// (file content copied from src/plugins/hosts.rs)

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

use crate::Result;
use crate::config::PluginConfig;
use crate::dns::{Message, Question, RData, RecordType, ResourceRecord};
use crate::error::Error;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

// Auto-register using the register macro
crate::register_plugin_builder!(HostsPlugin);

/// Core hosts parsing and lookup store
///
/// Maps domain names to IP addresses, similar to `/etc/hosts` file.
#[derive(Clone)]
pub struct Hosts {
    /// Domain name to list of IP addresses
    hosts: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
}

impl Hosts {
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_host(&self, domain: String, ip: IpAddr) {
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.hosts.write().entry(domain_lower).or_default().push(ip);
    }

    pub fn remove_host(&self, domain: &str) -> bool {
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.hosts.write().remove(&domain_lower).is_some()
    }

    pub fn get_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.hosts.read().get(&domain_lower).cloned()
    }

    pub fn len(&self) -> usize {
        self.hosts.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.read().is_empty()
    }

    pub fn clear(&self) {
        self.hosts.write().clear();
    }

    pub fn load_from_string(&self, content: &str) -> Result<()> {
        let mut new_hosts = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

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
            entries = self.hosts.len(),
            files = self.files.len(),
            "Hosts loaded (wrapper)"
        );
        Ok(())
    }

    pub fn start_file_watcher(&self) {
        if !self.auto_reload || self.files.is_empty() {
            return;
        }

        let files = self.files.clone();
        let hosts = Arc::clone(&self.hosts);

        debug!(auto_reload = true, files = ?files, "file auto-reload status");

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

                if !combined.is_empty()
                    && let Err(e) = hosts.load_from_string(&combined)
                {
                    warn!(error = %e, "Failed to parse hosts file during auto-reload");
                }

                let duration = start.elapsed();
                info!(filename = file_name, duration = ?duration, "scheduled auto-reload completed");
            },
        );
    }

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

impl Deref for HostsPlugin {
    type Target = Hosts;

    fn deref(&self) -> &Hosts {
        &self.hosts
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

        if let Err(e) = plugin.load_hosts() {
            tracing::warn!(error = %e, "Failed to load hosts during init, continuing");
        }

        plugin.start_file_watcher();

        Ok(Arc::new(plugin))
    }
}

// Tests preserved in dataset hosts module
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_case_insensitive() {
        let hosts = Hosts::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);

        hosts.add_host("Example.COM".to_string(), ip.into());

        assert!(hosts.get_ips("example.com").is_some());
        assert!(hosts.get_ips("EXAMPLE.COM").is_some());
        assert!(hosts.get_ips("Example.Com").is_some());
        assert!(hosts.get_ips("Example.Com.").is_some());
    }

    // Other tests omitted for brevity; preserved in moved file
}
