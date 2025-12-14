//! Data provider plugins
//!
//! Data providers are special plugins that load data from files and make it
//! available to other plugins for matching operations.

use crate::plugin::traits::Matcher;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use ipnet::IpNet;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Domain set data provider plugin
///
/// Loads domain names from files and provides them for matching.
/// Supports auto-reload when files change.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::DomainSetPlugin;
///
/// let plugin = DomainSetPlugin::new("cn-domains")
///     .with_files(vec!["direct-list.txt".to_string()])
///     .with_auto_reload(true);
/// ```
pub struct DomainSetPlugin {
    /// Name/tag for this domain set
    name: String,
    /// Files to load domains from
    files: Vec<PathBuf>,
    /// Whether to auto-reload files
    auto_reload: bool,
    /// Loaded domains (stored in shared state)
    domains: Arc<RwLock<HashSet<String>>>,
}

impl DomainSetPlugin {
    /// Create a new domain set plugin
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            files: Vec::new(),
            auto_reload: false,
            domains: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Add files to load domains from
    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = files.into_iter().map(PathBuf::from).collect();
        self
    }

    /// Enable auto-reload
    pub fn with_auto_reload(mut self, enabled: bool) -> Self {
        self.auto_reload = enabled;
        self
    }

    /// Start file watcher if auto-reload is enabled
    pub fn start_file_watcher(&self) {
        if !self.auto_reload || self.files.is_empty() {
            return;
        }

        let name = self.name.clone();
        let files = self.files.clone();
        let domains = Arc::clone(&self.domains);

        info!(
            name = %name,
            auto_reload = true,
            files = ?files,
            "file auto-reload status"
        );

        info!(
            name = %name,
            files = ?files,
            "enabling file auto-reload"
        );

        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel(100);

            // Create a watcher
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
                        error!(name = %name, error = %e, "failed to create file watcher");
                        return;
                    }
                };

            // Watch all files
            for file_path in &files {
                debug!(name = %name, file = ?file_path, "start watching file");
                if let Err(e) = watcher.watch(file_path, RecursiveMode::NonRecursive) {
                    warn!(name = %name, file = ?file_path, error = %e, "failed to watch file");
                }
            }

            info!(name = %name, "file watcher started successfully");
            debug!(name = %name, "file watcher loop started");

            // Process file change events
            while let Some(event) = rx.recv().await {
                for path in &event.paths {
                    if files.contains(path) {
                        let file_name = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");

                        // Handle file removal/rename
                        if matches!(event.kind, EventKind::Remove(_)) {
                            info!(name = %name, file = file_name, "file removed or renamed, attempting to re-watch");

                            // Try to re-add the file to watch list after a short delay
                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                            if path.exists() {
                                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                                    warn!(name = %name, file = file_name, error = %e, "failed to re-watch file");
                                } else {
                                    info!(name = %name, file = file_name, "successfully re-added file to watch list");
                                }
                            }
                        }

                        // Reload the domains
                        info!(name = %name, file = file_name, "scheduled reload: invoking callback");

                        let start = std::time::Instant::now();
                        let mut new_domains = HashSet::new();

                        for file_path in &files {
                            if let Ok(content) = fs::read_to_string(file_path) {
                                for line in content.lines() {
                                    let line = line.trim();
                                    if line.is_empty() || line.starts_with('#') {
                                        continue;
                                    }

                                    let domain = if let Some(colon_pos) = line.find(':') {
                                        &line[colon_pos + 1..]
                                    } else {
                                        line
                                    };

                                    new_domains.insert(domain.trim().to_lowercase());
                                }
                            }
                        }

                        *domains.write() = new_domains;
                        let duration = start.elapsed();

                        info!(
                            name = %name,
                            filename = file_name,
                            duration = ?duration,
                            "scheduled auto-reload completed"
                        );

                        break; // Only reload once per event batch
                    }
                }
            }

            debug!(name = %name, "file watcher closed, exiting loop");
        });
    }

    /// Load domains from all configured files
    pub fn load_domains(&self) -> Result<()> {
        let mut domains = HashSet::new();

        for file_path in &self.files {
            match self.load_domain_file(file_path) {
                Ok(file_domains) => {
                    debug!(
                        file = ?file_path,
                        count = file_domains.len(),
                        "Loaded domains from file"
                    );
                    domains.extend(file_domains);
                }
                Err(e) => {
                    error!(
                        file = ?file_path,
                        error = %e,
                        "Failed to load domain file"
                    );
                    // Continue loading other files
                }
            }
        }

        let count = domains.len();
        *self.domains.write() = domains;

        info!(
            name = %self.name,
            count = count,
            files = self.files.len(),
            "Domain set loaded"
        );

        Ok(())
    }

    /// Load domains from a single file
    fn load_domain_file(&self, path: &Path) -> Result<HashSet<String>> {
        let content = fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Failed to read file {:?}: {}", path, e)))?;

        let mut domains = HashSet::new();
        for line in content.lines() {
            let line = line.trim();
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle different formats
            // Format 1: "domain:example.com" or "full:example.com"
            // Format 2: just "example.com"
            let domain = if let Some(colon_pos) = line.find(':') {
                &line[colon_pos + 1..]
            } else {
                line
            };

            domains.insert(domain.trim().to_lowercase());
        }

        Ok(domains)
    }

    /// Check if a domain matches the set
    pub fn matches(&self, domain: &str) -> bool {
        // Normalize domain: remove trailing dot and lowercase
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        let domains = self.domains.read();

        // Check exact match
        if domains.contains(&domain_lower) {
            return true;
        }

        // Check parent domains (for subdomain matching)
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if domains.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Get the domain set for use by other plugins
    pub fn get_domains(&self) -> Arc<RwLock<HashSet<String>>> {
        Arc::clone(&self.domains)
    }
}

impl fmt::Debug for DomainSetPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainSetPlugin")
            .field("name", &self.name)
            .field("files", &self.files)
            .field("auto_reload", &self.auto_reload)
            .field("domain_count", &self.domains.read().len())
            .finish()
    }
}

#[async_trait]
impl Plugin for DomainSetPlugin {
    fn name(&self) -> &str {
        "domain_set"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Store the domain set in context metadata for other plugins to use
        ctx.set_metadata(
            format!("domain_set_{}", self.name),
            Arc::clone(&self.domains),
        );
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Matcher for DomainSetPlugin {
    fn matches_context(&self, ctx: &Context) -> bool {
        if let Some(question) = ctx.request().questions().first() {
            // Normalize qname to strip trailing dot before matching
            let domain = question.qname().to_string();
            let normalized = domain.trim_end_matches('.');
            self.matches(normalized)
        } else {
            false
        }
    }
}

/// IP set data provider plugin
///
/// Loads IP addresses and CIDR ranges from files and provides them for matching.
/// Supports auto-reload when files change.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::IpSetPlugin;
///
/// let plugin = IpSetPlugin::new("local-ips")
///     .with_files(vec!["china-ip-list.txt".to_string()])
///     .with_auto_reload(true);
/// ```
pub struct IpSetPlugin {
    /// Name/tag for this IP set
    name: String,
    /// Files to load IPs from
    files: Vec<PathBuf>,
    /// Whether to auto-reload files
    auto_reload: bool,
    /// Loaded IP networks (stored in shared state)
    networks: Arc<RwLock<Vec<IpNet>>>,
}

impl IpSetPlugin {
    /// Create a new IP set plugin
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            files: Vec::new(),
            auto_reload: false,
            networks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add files to load IPs from
    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = files.into_iter().map(PathBuf::from).collect();
        self
    }

    /// Enable auto-reload
    pub fn with_auto_reload(mut self, enabled: bool) -> Self {
        self.auto_reload = enabled;
        self
    }

    /// Start file watcher if auto-reload is enabled
    pub fn start_file_watcher(&self) {
        if !self.auto_reload || self.files.is_empty() {
            return;
        }

        let name = self.name.clone();
        let files = self.files.clone();
        let networks = Arc::clone(&self.networks);

        info!(
            name = %name,
            auto_reload = true,
            files = ?files,
            "file auto-reload status"
        );

        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel(100);

            // Create a watcher
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
                        error!(name = %name, error = %e, "failed to create file watcher");
                        return;
                    }
                };

            // Watch all files
            for file_path in &files {
                debug!(name = %name, file = ?file_path, "start watching file");
                if let Err(e) = watcher.watch(file_path, RecursiveMode::NonRecursive) {
                    warn!(name = %name, file = ?file_path, error = %e, "failed to watch file");
                }
            }

            info!(name = %name, "file watcher started successfully");
            debug!(name = %name, "file watcher loop started");

            // Process file change events
            while let Some(event) = rx.recv().await {
                for path in &event.paths {
                    if files.contains(path) {
                        let file_name = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");

                        // Handle file removal/rename
                        if matches!(event.kind, EventKind::Remove(_)) {
                            info!(name = %name, file = file_name, "file removed or renamed, attempting to re-watch");

                            // Try to re-add the file to watch list after a short delay
                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                            if path.exists() {
                                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                                    warn!(name = %name, file = file_name, error = %e, "failed to re-watch file");
                                } else {
                                    info!(name = %name, file = file_name, "successfully re-added file to watch list");
                                }
                            }
                        }

                        // Reload the IP networks
                        info!(name = %name, file = file_name, "scheduled reload: invoking callback");

                        let start = std::time::Instant::now();
                        let mut new_networks = Vec::new();

                        for file_path in &files {
                            if let Ok(content) = fs::read_to_string(file_path) {
                                for line in content.lines() {
                                    let line = line.trim();
                                    if line.is_empty() || line.starts_with('#') {
                                        continue;
                                    }

                                    match line.parse::<IpNet>() {
                                        Ok(net) => new_networks.push(net),
                                        Err(_) => {
                                            if let Ok(ip) = line.parse::<IpAddr>() {
                                                let net = match ip {
                                                    IpAddr::V4(addr) => {
                                                        IpNet::new(addr.into(), 32).unwrap()
                                                    }
                                                    IpAddr::V6(addr) => {
                                                        IpNet::new(addr.into(), 128).unwrap()
                                                    }
                                                };
                                                new_networks.push(net);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        let count = new_networks.len();
                        *networks.write() = new_networks;
                        let duration = start.elapsed();

                        info!(
                            name = %name,
                            IPs = 0,
                            files = files.len(),
                            netlist = count,
                            "successfully loaded IPs and files"
                        );

                        info!(
                            name = %name,
                            filename = file_name,
                            duration = ?duration,
                            "scheduled auto-reload completed"
                        );

                        break; // Only reload once per event batch
                    }
                }
            }

            debug!(name = %name, "file watcher closed, exiting loop");
        });
    }

    /// Load IP networks from all configured files
    pub fn load_networks(&self) -> Result<()> {
        let mut networks = Vec::new();

        for file_path in &self.files {
            match self.load_ip_file(file_path) {
                Ok(file_networks) => {
                    debug!(
                        file = ?file_path,
                        count = file_networks.len(),
                        "Loaded IP networks from file"
                    );
                    networks.extend(file_networks);
                }
                Err(e) => {
                    error!(
                        file = ?file_path,
                        error = %e,
                        "Failed to load IP file"
                    );
                    // Continue loading other files
                }
            }
        }

        let count = networks.len();
        *self.networks.write() = networks;

        info!(
            name = %self.name,
            count = count,
            files = self.files.len(),
            "IP set loaded"
        );

        Ok(())
    }

    /// Load IP networks from a single file
    fn load_ip_file(&self, path: &Path) -> Result<Vec<IpNet>> {
        let content = fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Failed to read file {:?}: {}", path, e)))?;

        let mut networks = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse as CIDR or single IP
            match line.parse::<IpNet>() {
                Ok(net) => networks.push(net),
                Err(_) => {
                    // Try parsing as single IP
                    if let Ok(ip) = line.parse::<IpAddr>() {
                        // Convert single IP to /32 or /128 network
                        let net = match ip {
                            IpAddr::V4(addr) => IpNet::new(addr.into(), 32).unwrap(),
                            IpAddr::V6(addr) => IpNet::new(addr.into(), 128).unwrap(),
                        };
                        networks.push(net);
                    } else {
                        debug!(line = line, "Skipping invalid IP/CIDR line");
                    }
                }
            }
        }

        Ok(networks)
    }

    /// Check if an IP matches the set
    pub fn matches(&self, ip: &IpAddr) -> bool {
        let networks = self.networks.read();
        for net in networks.iter() {
            if net.contains(ip) {
                return true;
            }
        }
        false
    }

    /// Get the IP networks for use by other plugins
    pub fn get_networks(&self) -> Arc<RwLock<Vec<IpNet>>> {
        Arc::clone(&self.networks)
    }
}

impl fmt::Debug for IpSetPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpSetPlugin")
            .field("name", &self.name)
            .field("files", &self.files)
            .field("auto_reload", &self.auto_reload)
            .field("network_count", &self.networks.read().len())
            .finish()
    }
}

#[async_trait]
impl Plugin for IpSetPlugin {
    fn name(&self) -> &str {
        "ip_set"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Store the IP set in context metadata for other plugins to use
        ctx.set_metadata(format!("ip_set_{}", self.name), Arc::clone(&self.networks));
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Matcher for IpSetPlugin {
    fn matches_context(&self, ctx: &Context) -> bool {
        if let Some(response) = ctx.response() {
            for record in response.answers() {
                if let Some(ip) =
                    crate::plugins::ip_matcher::IpMatcherPlugin::extract_ip(record.rdata())
                {
                    if self.matches(&ip) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_domain_set_creation() {
        let plugin = DomainSetPlugin::new("test");
        assert_eq!(plugin.name, "test");
        assert!(plugin.files.is_empty());
        assert!(!plugin.auto_reload);
    }

    #[test]
    fn test_domain_set_builder() {
        let plugin = DomainSetPlugin::new("test")
            .with_files(vec!["file1.txt".to_string()])
            .with_auto_reload(true);

        assert_eq!(plugin.files.len(), 1);
        assert!(plugin.auto_reload);
    }

    #[test]
    fn test_domain_matching() {
        let plugin = DomainSetPlugin::new("test");
        {
            let mut domains = plugin.domains.write();
            domains.insert("example.com".to_string());
            domains.insert("test.org".to_string());
        }

        assert!(plugin.matches("example.com"));
        assert!(plugin.matches("EXAMPLE.COM"));
        assert!(plugin.matches("sub.example.com"));
        assert!(!plugin.matches("other.com"));
    }

    #[test]
    fn test_load_domain_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Comment line").unwrap();
        writeln!(file, "example.com").unwrap();
        writeln!(file, "domain:test.org").unwrap();
        writeln!(file, "full:another.net").unwrap();
        // trailing newline not needed
        file.flush().unwrap();

        let plugin = DomainSetPlugin::new("test");
        let domains = plugin.load_domain_file(file.path()).unwrap();

        assert_eq!(domains.len(), 3);
        assert!(domains.contains("example.com"));
        assert!(domains.contains("test.org"));
        assert!(domains.contains("another.net"));
    }

    #[test]
    fn test_ip_set_creation() {
        let plugin = IpSetPlugin::new("test");
        assert_eq!(plugin.name, "test");
        assert!(plugin.files.is_empty());
        assert!(!plugin.auto_reload);
    }

    #[test]
    fn test_ip_set_builder() {
        let plugin = IpSetPlugin::new("test")
            .with_files(vec!["file1.txt".to_string()])
            .with_auto_reload(true);

        assert_eq!(plugin.files.len(), 1);
        assert!(plugin.auto_reload);
    }

    #[test]
    fn test_ip_matching() {
        let plugin = IpSetPlugin::new("test");
        {
            let mut networks = plugin.networks.write();
            networks.push("192.168.0.0/16".parse().unwrap());
            networks.push("10.0.0.0/8".parse().unwrap());
        }

        assert!(plugin.matches(&"192.168.1.1".parse().unwrap()));
        assert!(plugin.matches(&"10.5.5.5".parse().unwrap()));
        assert!(!plugin.matches(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_load_ip_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Comment line").unwrap();
        writeln!(file, "192.168.0.0/16").unwrap();
        writeln!(file, "10.0.0.1").unwrap();
        writeln!(file, "2001:db8::/32").unwrap();
        // trailing newline not needed
        file.flush().unwrap();

        let plugin = IpSetPlugin::new("test");
        let networks = plugin.load_ip_file(file.path()).unwrap();

        assert_eq!(networks.len(), 3);
    }

    #[tokio::test]
    async fn test_domain_set_plugin_execution() {
        let plugin = DomainSetPlugin::new("test");
        let request = crate::dns::Message::new();
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        // Verify metadata was set
        assert!(ctx.has_metadata("domain_set_test"));
    }

    #[tokio::test]
    async fn test_ip_set_plugin_execution() {
        let plugin = IpSetPlugin::new("test");
        let request = crate::dns::Message::new();
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        // Verify metadata was set
        assert!(ctx.has_metadata("ip_set_test"));
    }
}
