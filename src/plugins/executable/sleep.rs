//! Sleep plugin
//!
//! Adds a delay before processing continues

use crate::RegisterExecPlugin;
use crate::Result;
use crate::plugin::{Context, ExecPlugin, Plugin};
use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

const PLUGIN_SLEEP_IDENTIFIER: &str = "sleep";

/// Plugin that adds a delay to query processing
///
/// Useful for testing, rate limiting, or simulating slow networks.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::executable::SleepPlugin;
/// use std::time::Duration;
///
/// // Sleep for 100ms
/// let plugin = SleepPlugin::new(Duration::from_millis(100));
///
/// // Sleep for 1 second
/// let plugin = SleepPlugin::from_secs(1);
/// ```
#[derive(RegisterExecPlugin)]
pub struct SleepPlugin {
    /// Duration to sleep
    duration: Duration,
}

impl SleepPlugin {
    /// Create a new sleep plugin with the specified duration
    pub fn new(duration: Duration) -> Self {
        Self { duration }
    }

    /// Create a sleep plugin from seconds
    pub fn from_secs(secs: u64) -> Self {
        Self {
            duration: Duration::from_secs(secs),
        }
    }

    /// Create a sleep plugin from milliseconds
    pub fn from_millis(millis: u64) -> Self {
        Self {
            duration: Duration::from_millis(millis),
        }
    }
}

impl fmt::Debug for SleepPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SleepPlugin")
            .field("duration", &self.duration)
            .finish()
    }
}

#[async_trait]
impl Plugin for SleepPlugin {
    fn name(&self) -> &str {
        PLUGIN_SLEEP_IDENTIFIER
    }

    async fn execute(&self, _ctx: &mut Context) -> Result<()> {
        debug!("Sleeping for {:?}", self.duration);
        tokio::time::sleep(self.duration).await;
        Ok(())
    }

    fn aliases() -> &'static [&'static str] {
        &["delay"]
    }
}

impl ExecPlugin for SleepPlugin {
    /// Parse a quick configuration string for sleep plugin.
    ///
    /// Accepts duration strings like "100ms", "1s", "500ms"
    /// Examples: "100ms", "1s", "500ms"
    fn quick_setup(prefix: &str, exec_str: &str) -> Result<Arc<dyn Plugin>> {
        // Accept the main name and all aliases
        if prefix != PLUGIN_SLEEP_IDENTIFIER && !Self::aliases().contains(&prefix) {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected one of {:?}",
                prefix,
                Self::aliases()
            )));
        }

        let duration = if let Some(ms_str) = exec_str.strip_suffix("ms") {
            if let Ok(ms) = ms_str.parse::<u64>() {
                Duration::from_millis(ms)
            } else {
                return Err(crate::Error::Config(format!(
                    "Invalid milliseconds: {}",
                    ms_str
                )));
            }
        } else if let Some(s_str) = exec_str.strip_suffix('s') {
            if let Ok(s) = s_str.parse::<u64>() {
                Duration::from_secs(s)
            } else {
                return Err(crate::Error::Config(format!("Invalid seconds: {}", s_str)));
            }
        } else {
            return Err(crate::Error::Config(format!(
                "Invalid duration format: '{}'. Use '100ms' or '1s'",
                exec_str
            )));
        };

        let plugin = SleepPlugin::new(duration);
        Ok(Arc::new(plugin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use std::time::Instant;

    #[tokio::test]
    async fn test_sleep_plugin() {
        let plugin = SleepPlugin::from_millis(100);
        let mut ctx = Context::new(Message::new());

        let start = Instant::now();
        plugin.execute(&mut ctx).await.unwrap();
        let elapsed = start.elapsed();

        // Should sleep for at least 90ms (allowing some tolerance)
        assert!(elapsed.as_millis() >= 90);
    }

    #[tokio::test]
    async fn test_sleep_from_secs() {
        let plugin = SleepPlugin::from_secs(0); // 0 seconds for fast test
        let mut ctx = Context::new(Message::new());

        assert!(plugin.execute(&mut ctx).await.is_ok());
    }

    #[test]
    fn test_sleep_debug() {
        let plugin = SleepPlugin::from_millis(100);
        let debug_str = format!("{:?}", plugin);
        assert!(debug_str.contains("SleepPlugin"));
        assert!(debug_str.contains("duration"));
    }

    #[test]
    fn test_exec_plugin_quick_setup() {
        // Test that ExecPlugin::quick_setup works correctly
        let plugin = <SleepPlugin as ExecPlugin>::quick_setup("sleep", "100ms").unwrap();
        assert_eq!(plugin.name(), "sleep");

        // Test invalid prefix
        let result = <SleepPlugin as ExecPlugin>::quick_setup("invalid", "100ms");
        assert!(result.is_err());

        // Test milliseconds
        let plugin = <SleepPlugin as ExecPlugin>::quick_setup("sleep", "200ms").unwrap();
        if let Some(sp) = plugin.as_any().downcast_ref::<SleepPlugin>() {
            assert_eq!(sp.duration, Duration::from_millis(200));
        }

        // Test seconds
        let plugin = <SleepPlugin as ExecPlugin>::quick_setup("sleep", "2s").unwrap();
        if let Some(sp) = plugin.as_any().downcast_ref::<SleepPlugin>() {
            assert_eq!(sp.duration, Duration::from_secs(2));
        }

        // Test invalid format
        let result = <SleepPlugin as ExecPlugin>::quick_setup("sleep", "100");
        assert!(result.is_err());
    }
}
