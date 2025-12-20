use crate::config::PluginConfig;
use crate::plugin::traits::Matcher;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info};

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
#[derive(Clone)]
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

        debug!(
            name = %name,
            files = ?files,
            "enabling file auto-reload"
        );

        const DEBOUNCE_MS: u64 = 200;

        crate::utils::spawn_file_watcher(
            name.clone(),
            files.clone(),
            DEBOUNCE_MS,
            move |path, files| {
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                // Reload the domains (same logic as previous implementation)
                let start = std::time::Instant::now();
                let mut new_domains = HashSet::new();

                for file_path in files {
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

                info!(name = %name, filename = file_name, duration = ?duration, "scheduled auto-reload completed");
            },
        );
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

    fn init(config: &PluginConfig) -> Result<std::sync::Arc<dyn Plugin>> {
        let args = config.effective_args();
        use serde_yaml::Value;

        let tag = args.get("tag").and_then(|v| v.as_str()).unwrap_or("");
        let name = if !tag.is_empty() {
            tag.to_string()
        } else {
            config.effective_name().to_string()
        };

        let mut plugin = DomainSetPlugin::new(name);

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

        // Load and start watcher as per legacy behavior
        if let Err(e) = plugin.load_domains() {
            tracing::warn!(error = %e, "Failed to load domains during init, continuing");
        }
        plugin.start_file_watcher();

        Ok(Arc::new(plugin))
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

    #[tokio::test]
    async fn test_domain_set_plugin_execution() {
        let plugin = DomainSetPlugin::new("test");
        let request = crate::dns::Message::new();
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        // Verify metadata was set
        assert!(ctx.has_metadata("domain_set_test"));
    }
}

crate::register_plugin_builder!(DomainSetPlugin);
