//! File downloader plugin for updating rule files
//!
//! This plugin provides a simple way to download files from URLs and save them locally.
//! Designed to work with CronPlugin for scheduled file updates.
//!
//! Configuration example:
//! ```yaml
//! - tag: file_downloader
//!   type: downloader
//!   args:
//!     files:
//!       - url: "https://example.com/reject-list.txt"
//!         path: "reject-list.txt"
//!       - url: "https://example.com/gfw.txt"
//!         path: "gfw.txt"
//!     timeout_secs: 30
//!     concurrent: false
//! ```

#![allow(dead_code)]

use crate::Result;
use crate::config::types::PluginConfig;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use serde_yaml::Value;
use std::any::Any;
use std::fs;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// File download specification
#[derive(Debug, Clone)]
pub(crate) struct FileDownloadSpec {
    url: String,
    path: String,
}

/// Downloader plugin for downloading and updating files
#[derive(Debug)]
pub struct DownloaderPlugin {
    files: Vec<FileDownloadSpec>,
    timeout_secs: u64,
    concurrent: bool,
}

impl DownloaderPlugin {
    /// Create a new downloader plugin
    pub(crate) fn new(files: Vec<FileDownloadSpec>, timeout_secs: u64, concurrent: bool) -> Self {
        Self {
            files,
            timeout_secs,
            concurrent,
        }
    }

    /// Download all files
    async fn download_files(&self) -> Result<()> {
        if self.files.is_empty() {
            return Ok(());
        }

        info!(
            count = self.files.len(),
            concurrent = self.concurrent,
            "Starting file downloads"
        );

        let start = std::time::Instant::now();

        if self.concurrent {
            self.download_concurrent().await
        } else {
            self.download_sequential().await
        }?;

        let duration = start.elapsed();
        info!(
            count = self.files.len(),
            duration_ms = duration.as_millis(),
            "All files downloaded successfully"
        );

        Ok(())
    }

    /// Download files sequentially
    async fn download_sequential(&self) -> Result<()> {
        for spec in &self.files {
            self.download_single(spec).await?;
        }
        Ok(())
    }

    /// Download files concurrently
    async fn download_concurrent(&self) -> Result<()> {
        let handles: Vec<_> = self
            .files
            .iter()
            .map(|spec| {
                let spec_clone = spec.clone();
                tokio::spawn(async move { Self::download_single_static(&spec_clone).await })
            })
            .collect();

        for handle in handles {
            handle
                .await
                .map_err(|e| crate::Error::Config(format!("Download task failed: {}", e)))??;
        }

        Ok(())
    }

    /// Download a single file (static version for concurrent tasks)
    async fn download_single_static(spec: &FileDownloadSpec) -> Result<()> {
        let start = std::time::Instant::now();
        let client = reqwest::Client::new();

        debug!(url = %spec.url, path = %spec.path, "Downloading file");

        let resp = client
            .get(&spec.url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| crate::Error::Config(format!("Failed to download {}: {}", spec.url, e)))?;

        if !resp.status().is_success() {
            return Err(crate::Error::Config(format!(
                "HTTP {} for {}",
                resp.status(),
                spec.url
            )));
        }

        let content = resp
            .text()
            .await
            .map_err(|e| crate::Error::Config(format!("Failed to read response body: {}", e)))?;

        if content.is_empty() {
            return Err(crate::Error::Config("Downloaded file is empty".to_string()));
        }

        // Write to temporary file first
        let temp_path = format!("{}.tmp", spec.path);
        fs::write(&temp_path, &content)
            .map_err(|e| crate::Error::Config(format!("Failed to write temp file: {}", e)))?;

        // Then rename to target (atomic operation)
        fs::rename(&temp_path, &spec.path).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            crate::Error::Config(format!("Failed to move file to {}: {}", spec.path, e))
        })?;

        let duration = start.elapsed();
        let size_bytes = content.len();

        info!(
            url = %spec.url,
            path = %spec.path,
            size_bytes = size_bytes,
            duration_ms = duration.as_millis(),
            "File downloaded"
        );

        Ok(())
    }

    /// Download a single file (instance method)
    async fn download_single(&self, spec: &FileDownloadSpec) -> Result<()> {
        Self::download_single_static(spec).await
    }
}

impl Default for DownloaderPlugin {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            timeout_secs: 30,
            concurrent: false,
        }
    }
}

#[async_trait]
impl Plugin for DownloaderPlugin {
    fn name(&self) -> &str {
        "downloader"
    }

    async fn execute(&self, _ctx: &mut Context) -> Result<()> {
        self.download_files().await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();

        let mut files = Vec::new();

        // Parse files configuration
        if let Some(files_val) = args.get("files") {
            match files_val {
                Value::Sequence(seq) => {
                    for item in seq {
                        if let Value::Mapping(map) = item {
                            let url = map
                                .get(Value::String("url".to_string()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            let path = map
                                .get(Value::String("path".to_string()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            if !url.is_empty() && !path.is_empty() {
                                files.push(FileDownloadSpec {
                                    url: url.to_string(),
                                    path: path.to_string(),
                                });
                            } else {
                                warn!("Skipping file entry with missing url or path");
                            }
                        }
                    }
                }
                _ => {
                    return Err(crate::Error::Config(
                        "files must be a sequence of {url, path} objects".to_string(),
                    ));
                }
            }
        }

        if files.is_empty() {
            return Err(crate::Error::Config(
                "Downloader plugin requires at least one file to download".to_string(),
            ));
        }

        let timeout_secs = args
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);

        let concurrent = args
            .get("concurrent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        info!(
            file_count = files.len(),
            timeout_secs = timeout_secs,
            concurrent = concurrent,
            "Downloader plugin initialized"
        );

        Ok(Arc::new(DownloaderPlugin::new(
            files,
            timeout_secs,
            concurrent,
        )))
    }
}

crate::register_plugin_builder!(DownloaderPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[test]
    fn test_downloader_plugin_creation() {
        let spec = FileDownloadSpec {
            url: "https://example.com/test.txt".to_string(),
            path: "test.txt".to_string(),
        };
        let plugin = DownloaderPlugin::new(vec![spec], 30, false);
        assert_eq!(plugin.name(), "downloader");
        assert_eq!(plugin.files.len(), 1);
    }

    #[test]
    fn test_downloader_plugin_default() {
        let plugin = DownloaderPlugin::default();
        assert_eq!(plugin.timeout_secs, 30);
        assert!(!plugin.concurrent);
        assert!(plugin.files.is_empty());
    }

    #[tokio::test]
    async fn test_downloader_plugin_execute() {
        let spec = FileDownloadSpec {
            url: "https://example.com/test.txt".to_string(),
            path: "test.txt".to_string(),
        };
        let plugin = DownloaderPlugin::new(vec![spec], 30, false);
        let mut ctx = Context::new(Message::new());

        // This will fail due to network, but the execute method should be callable
        let result = plugin.execute(&mut ctx).await;
        // We expect an error since we're not actually downloading
        assert!(result.is_err());
    }

    #[test]
    fn test_downloader_plugin_init() {
        let mut config = PluginConfig::new("downloader".to_string());

        // Build configuration
        let mut files_map = serde_yaml::Mapping::new();
        files_map.insert(
            Value::String("url".to_string()),
            Value::String("https://example.com/test.txt".to_string()),
        );
        files_map.insert(
            Value::String("path".to_string()),
            Value::String("test.txt".to_string()),
        );

        let files = Value::Sequence(vec![Value::Mapping(files_map)]);
        let mut args = serde_yaml::Mapping::new();
        args.insert(Value::String("files".to_string()), files);
        args.insert(
            Value::String("timeout_secs".to_string()),
            Value::Number(serde_yaml::Number::from(60u64)),
        );
        args.insert(Value::String("concurrent".to_string()), Value::Bool(true));

        config.args = Value::Mapping(args);

        let result = DownloaderPlugin::init(&config);
        assert!(result.is_ok());

        if let Ok(plugin) = result {
            let downloader = plugin.as_any().downcast_ref::<DownloaderPlugin>();
            assert!(downloader.is_some());
        }
    }

    #[test]
    fn test_downloader_missing_url() {
        let mut config = PluginConfig::new("downloader".to_string());

        let mut files_map = serde_yaml::Mapping::new();
        // Missing URL
        files_map.insert(
            Value::String("path".to_string()),
            Value::String("test.txt".to_string()),
        );

        let files = Value::Sequence(vec![Value::Mapping(files_map)]);
        let mut args = serde_yaml::Mapping::new();
        args.insert(Value::String("files".to_string()), files);

        config.args = Value::Mapping(args);

        let result = DownloaderPlugin::init(&config);
        // Should fail because no valid files
        assert!(result.is_err());
    }
}
