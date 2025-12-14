//! Sleep plugin
//!
//! Adds a delay before processing continues

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use std::time::Duration;
use tracing::debug;

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
        "sleep"
    }

    async fn execute(&self, _ctx: &mut Context) -> Result<()> {
        debug!("Sleeping for {:?}", self.duration);
        tokio::time::sleep(self.duration).await;
        Ok(())
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
}
