//! File downloader plugin for updating rule files
//!
//! This plugin provides a simple way to download files from URLs and save them locally.
//! It can be used in two ways:
//! 1. Direct configuration as a plugin (files configured in this plugin's args)
//! 2. Called by other plugins like CronPlugin via invoke_plugin (files passed as args)
//!
//! ## Direct configuration example:
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
//!
//! ## Called by CronPlugin example:
//! ```yaml
//! - tag: cron_scheduler
//!   type: cron
//!   args:
//!     jobs:
//!       - name: auto_update
//!         cron: "0 0 */6 * * *"  # every 6 hours
//!         action:
//!           invoke_plugin:
//!             type: "downloader"
//!             args:
//!               files:
//!                 - url: "https://example.com/reject-list.txt"
//!                   path: "reject-list.txt"
//!               timeout_secs: 30
//!               concurrent: false
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
use tracing::{debug, info, trace, warn};

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
            warn!("No files configured for download");
            return Ok(());
        }

        info!(
            count = self.files.len(),
            concurrent = self.concurrent,
            timeout_secs = self.timeout_secs,
            "Downloader: Starting file downloads"
        );

        let start = std::time::Instant::now();

        let result = if self.concurrent {
            self.download_concurrent().await
        } else {
            self.download_sequential().await
        };

        let duration = start.elapsed();
        match result {
            Ok(()) => {
                info!(
                    count = self.files.len(),
                    duration_ms = duration.as_millis(),
                    "Downloader: All files downloaded successfully"
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    count = self.files.len(),
                    duration_ms = duration.as_millis(),
                    error = %e,
                    "Downloader: File download failed"
                );
                Err(e)
            }
        }
    }

    /// Download files sequentially
    async fn download_sequential(&self) -> Result<()> {
        info!(
            count = self.files.len(),
            "Downloader: Starting sequential downloads"
        );
        for (idx, spec) in self.files.iter().enumerate() {
            debug!(idx = idx, file_count = self.files.len(), url = %spec.url, "Downloader: Downloading file");
            self.download_single(spec).await?;
        }
        info!("Downloader: Sequential downloads completed");
        Ok(())
    }

    /// Download files concurrently
    async fn download_concurrent(&self) -> Result<()> {
        info!(
            count = self.files.len(),
            "Downloader: Starting concurrent downloads"
        );
        let handles: Vec<_> = self
            .files
            .iter()
            .enumerate()
            .map(|(idx, spec)| {
                let spec_clone = spec.clone();
                tokio::spawn(async move {
                    debug!(idx = idx, url = %spec_clone.url, "Downloader: Downloading file concurrently");
                    Self::download_single_static(&spec_clone).await
                })
            })
            .collect();

        debug!(
            task_count = handles.len(),
            "Downloader: Waiting for {} concurrent download tasks",
            handles.len()
        );
        for (idx, handle) in handles.into_iter().enumerate() {
            handle.await.map_err(|e| {
                warn!(idx = idx, error = %e, "Downloader: Download task panicked");
                crate::Error::Config(format!("Download task {} failed: {}", idx, e))
            })??;
        }
        info!("Downloader: Concurrent downloads completed");
        Ok(())
    }

    /// Download a single file (static version for concurrent tasks)
    async fn download_single_static(spec: &FileDownloadSpec) -> Result<()> {
        let start = std::time::Instant::now();
        let client = reqwest::Client::new();

        debug!(url = %spec.url, path = %spec.path, "Downloader: Connecting to URL");

        let resp = client
            .get(&spec.url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                warn!(url = %spec.url, error = %e, "Downloader: Failed to download file");
                crate::Error::Config(format!("Failed to download {}: {}", spec.url, e))
            })?;

        debug!(url = %spec.url, status = %resp.status(), "Downloader: Received response");

        if !resp.status().is_success() {
            warn!(url = %spec.url, status = %resp.status(), "Downloader: HTTP error");
            return Err(crate::Error::Config(format!(
                "HTTP {} for {}",
                resp.status(),
                spec.url
            )));
        }

        let content = resp.text().await.map_err(|e| {
            warn!(url = %spec.url, error = %e, "Downloader: Failed to read response body");
            crate::Error::Config(format!("Failed to read response body: {}", e))
        })?;

        trace!(url = %spec.url, content_len = content.len(), "Downloader: Response received");

        if content.is_empty() {
            warn!(url = %spec.url, "Downloader: Downloaded file is empty");
            return Err(crate::Error::Config("Downloaded file is empty".to_string()));
        }

        // Write to temporary file first
        let temp_path = format!("{}.tmp", spec.path);
        trace!(path = %spec.path, temp_path = %temp_path, "Downloader: Writing temporary file");
        fs::write(&temp_path, &content).map_err(|e| {
            warn!(temp_path = %temp_path, error = %e, "Downloader: Failed to write temp file");
            crate::Error::Config(format!("Failed to write temp file: {}", e))
        })?;

        // Then rename to target (atomic operation)
        trace!(temp_path = %temp_path, final_path = %spec.path, "Downloader: Moving temporary file to final path");
        fs::rename(&temp_path, &spec.path).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            warn!(temp_path = %temp_path, final_path = %spec.path, error = %e, "Downloader: Failed to move file to final path");
            crate::Error::Config(format!("Failed to move file to {}: {}", spec.path, e))
        })?;

        let duration = start.elapsed();
        let size_bytes = content.len();

        info!(
            url = %spec.url,
            path = %spec.path,
            size_bytes = size_bytes,
            duration_ms = duration.as_millis(),
            "Downloader: File downloaded successfully"
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
