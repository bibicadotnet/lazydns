//! Configuration hot reload support
//!
//! Provides the ability to reload configuration without restarting the server.

use crate::config::Config;
use crate::{Error, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Configuration reload handler
///
/// Monitors configuration file for changes and triggers reload.
///
/// # Example
///
/// ```no_run
/// use lazydns::config::reload::ConfigReloader;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Arc::new(RwLock::new(lazydns::config::Config::new()));
/// let reloader = ConfigReloader::new("config.yaml", Arc::clone(&config));
/// reloader.start_watching().await?;
/// # Ok(())
/// # }
/// ```
pub struct ConfigReloader {
    config_path: PathBuf,
    config: Arc<RwLock<Config>>,
}

impl ConfigReloader {
    /// Create a new configuration reloader
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the configuration file
    /// * `config` - Shared configuration reference
    pub fn new(config_path: impl AsRef<Path>, config: Arc<RwLock<Config>>) -> Self {
        Self {
            config_path: config_path.as_ref().to_path_buf(),
            config,
        }
    }

    /// Start watching for configuration changes
    ///
    /// This function starts a background task that monitors the configuration
    /// file for changes and automatically reloads it.
    pub async fn start_watching(self) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);

        // Create file watcher
        let mut watcher: RecommendedWatcher = Watcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    if matches!(
                        event.kind,
                        notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                    ) {
                        let _ = tx.blocking_send(());
                    }
                }
            },
            notify::Config::default(),
        )
        .map_err(|e| Error::Config(format!("Failed to create file watcher: {}", e)))?;

        // Watch the config file
        watcher
            .watch(&self.config_path, RecursiveMode::NonRecursive)
            .map_err(|e| Error::Config(format!("Failed to watch config file: {}", e)))?;

        info!("Started watching config file: {:?}", self.config_path);

        // Spawn background task to handle reload events
        tokio::spawn(async move {
            // Keep watcher alive
            let _watcher = watcher;

            while rx.recv().await.is_some() {
                // Debounce: wait a bit to avoid multiple rapid reloads
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                // Drain any additional events
                while rx.try_recv().is_ok() {}

                info!("Config file changed, reloading...");
                match Self::reload_config(&self.config_path, &self.config).await {
                    Ok(()) => info!("Configuration reloaded successfully"),
                    Err(e) => error!("Failed to reload configuration: {}", e),
                }
            }
        });

        Ok(())
    }

    /// Reload configuration from file
    async fn reload_config(path: &Path, config: &Arc<RwLock<Config>>) -> Result<()> {
        // Load new configuration
        let new_config = crate::config::loader::load_from_file(path)?;

        // Validate the new configuration
        new_config.validate()?;

        // Acquire write lock and update
        let mut config_guard = config.write().await;
        *config_guard = new_config;

        Ok(())
    }

    /// Manually trigger a configuration reload
    ///
    /// This can be called to reload configuration without waiting for file changes.
    pub async fn reload(&self) -> Result<()> {
        info!("Manual configuration reload triggered");
        Self::reload_config(&self.config_path, &self.config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_reloader_creation() {
        let config = Arc::new(RwLock::new(Config::new()));
        let reloader = ConfigReloader::new("test.yaml", config);
        assert_eq!(reloader.config_path, PathBuf::from("test.yaml"));
    }

    #[tokio::test]
    async fn test_manual_reload() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
log_level: info
server:
  timeout_secs: 5
"#;
        write!(temp_file, "{}", config_content).unwrap();
        temp_file.flush().unwrap();

        let config = Arc::new(RwLock::new(Config::new()));
        let reloader = ConfigReloader::new(temp_file.path(), Arc::clone(&config));

        // Manual reload should succeed
        let result = reloader.reload().await;
        assert!(result.is_ok());

        // Check config was updated
        let config_guard = config.read().await;
        assert_eq!(config_guard.log_level, "info");
    }

    #[tokio::test]
    async fn test_reload_invalid_config() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "invalid: yaml: {{").unwrap();
        temp_file.flush().unwrap();

        let config = Arc::new(RwLock::new(Config::new()));
        let reloader = ConfigReloader::new(temp_file.path(), config);

        // Reload should fail with invalid YAML
        let result = reloader.reload().await;
        assert!(result.is_err());
    }
}
