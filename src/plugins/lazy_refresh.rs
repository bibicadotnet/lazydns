//! LazyCache background refresh plugin
//!
//! This plugin implements background refresh logic for the LazyCache optimization.
//! When a cache entry is marked for lazy refresh via the context metadata,
//! this plugin can trigger an upstream query to keep the entry fresh.
//!
//! This is an optional plugin that works in conjunction with the cache plugin.

use crate::Result;
use crate::config::PluginConfig;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

// Auto-register using the register macro
crate::register_plugin_builder!(LazyRefreshPlugin);

/// Statistics for lazy refresh operations
#[derive(Debug, Default)]
pub struct LazyRefreshStats {
    /// Number of refresh operations triggered
    triggered: AtomicU64,
    /// Number of successful refreshes
    successful: AtomicU64,
    /// Number of failed refreshes
    failed: AtomicU64,
}

impl LazyRefreshStats {
    fn new() -> Self {
        Self::default()
    }

    pub fn triggered(&self) -> u64 {
        self.triggered.load(Ordering::Relaxed)
    }

    pub fn successful(&self) -> u64 {
        self.successful.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

/// LazyCache background refresh plugin
///
/// Detects when cache entries are marked for lazy refresh and handles
/// the refresh logic asynchronously. This allows the cache to stay fresh
/// without blocking the main query path.
#[derive(Debug)]
#[allow(dead_code)]
pub struct LazyRefreshPlugin {
    /// Statistics for refresh operations
    stats: Arc<LazyRefreshStats>,
}

impl LazyRefreshPlugin {
    /// Create a new lazy refresh plugin
    pub fn new() -> Self {
        Self {
            stats: Arc::new(LazyRefreshStats::new()),
        }
    }

    /// Get refresh statistics
    pub fn stats(&self) -> &LazyRefreshStats {
        &self.stats
    }
}

impl Default for LazyRefreshPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for LazyRefreshPlugin {
    async fn execute(&self, context: &mut Context) -> Result<()> {
        // Check if this query requires lazy refresh
        if let Some(refresh_flag) = context.get_metadata::<bool>("needs_lazycache_refresh")
            && *refresh_flag
        {
            self.stats.triggered.fetch_add(1, Ordering::Relaxed);
            debug!(
                "LazyRefreshPlugin: Detected lazy refresh request, restoring cached response to client"
            );

            // Get the cached response that was stored in metadata
            if let Some(cached_response) =
                context.get_metadata::<crate::dns::Message>("cached_response")
            {
                // Set it as the response to be returned to the client
                context.set_response(Some(cached_response.clone()));
                debug!(
                    "LazyRefreshPlugin: Cached response set for client, pipeline continues for background refresh"
                );
            } else {
                debug!(
                    "LazyRefreshPlugin: Warning - needs_lazycache_refresh set but no cached_response in metadata"
                );
            }
        }

        // Allow the pipeline to continue downstream
        // Forward plugin will fetch a fresh response which Cache plugin will store
        Ok(())
    }

    fn name(&self) -> &str {
        "lazy_refresh"
    }

    fn priority(&self) -> i32 {
        // Run after cache but before accepting response
        // This allows us to detect refresh needs early
        45
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        // LazyRefresh plugin doesn't require configuration
        let _ = config;
        Ok(Arc::new(LazyRefreshPlugin::new()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lazy_refresh_stats() {
        let stats = LazyRefreshStats::new();
        assert_eq!(stats.triggered(), 0);
        assert_eq!(stats.successful(), 0);
        assert_eq!(stats.failed(), 0);

        stats.triggered.fetch_add(1, Ordering::Relaxed);
        stats.successful.fetch_add(1, Ordering::Relaxed);

        assert_eq!(stats.triggered(), 1);
        assert_eq!(stats.successful(), 1);
    }

    #[test]
    fn test_lazy_refresh_plugin_creation() {
        let plugin = LazyRefreshPlugin::new();
        assert_eq!(plugin.name(), "lazy_refresh");
        assert_eq!(plugin.priority(), 45);
    }
}
