//! Random matcher plugin
//!
//! Randomly matches queries based on a probability

use crate::Result;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use rand::Rng;
use std::fmt;
use tracing::debug;

/// Plugin that randomly matches based on probability
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::matcher::RandomMatcherPlugin;
///
/// // 50% probability of matching
/// let matcher = RandomMatcherPlugin::new(0.5);
///
/// // Always match
/// let matcher = RandomMatcherPlugin::new(1.0);
///
/// // Never match
/// let matcher = RandomMatcherPlugin::new(0.0);
/// ```
pub struct RandomMatcherPlugin {
    /// Probability of matching (0.0 to 1.0)
    probability: f64,
    /// Metadata key to set when matched
    metadata_key: String,
}

impl RandomMatcherPlugin {
    /// Create a new random matcher plugin
    ///
    /// # Arguments
    ///
    /// * `probability` - Probability of matching (0.0 to 1.0)
    ///
    /// # Panics
    ///
    /// Panics if probability is not between 0.0 and 1.0
    pub fn new(probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "Probability must be between 0.0 and 1.0"
        );
        Self {
            probability,
            metadata_key: "random_matched".to_string(),
        }
    }

    /// Create with custom metadata key
    pub fn with_metadata_key(mut self, key: String) -> Self {
        self.metadata_key = key;
        self
    }

    /// Check if should match based on probability
    fn should_match(&self) -> bool {
        let mut rng = rand::thread_rng();
        rng.gen_bool(self.probability)
    }
}

impl fmt::Debug for RandomMatcherPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RandomMatcherPlugin")
            .field("probability", &self.probability)
            .field("metadata_key", &self.metadata_key)
            .finish()
    }
}

#[async_trait]
impl Plugin for RandomMatcherPlugin {
    fn name(&self) -> &str {
        "random_matcher"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let matched = self.should_match();

        if matched {
            debug!(probability = self.probability, "Random matcher: matched");
        } else {
            debug!(probability = self.probability, "Random matcher: no match");
        }

        ctx.set_metadata(self.metadata_key.clone(), matched);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_random_matcher_always() {
        let matcher = RandomMatcherPlugin::new(1.0);

        // Test multiple times to ensure it always matches
        for _ in 0..10 {
            let mut ctx = Context::new(Message::new());
            matcher.execute(&mut ctx).await.unwrap();

            let matched = ctx.get_metadata::<bool>("random_matched").unwrap();
            assert!(*matched);
        }
    }

    #[tokio::test]
    async fn test_random_matcher_never() {
        let matcher = RandomMatcherPlugin::new(0.0);

        // Test multiple times to ensure it never matches
        for _ in 0..10 {
            let mut ctx = Context::new(Message::new());
            matcher.execute(&mut ctx).await.unwrap();

            let matched = ctx.get_metadata::<bool>("random_matched").unwrap();
            assert!(!(*matched));
        }
    }

    #[tokio::test]
    async fn test_random_matcher_probability() {
        let matcher = RandomMatcherPlugin::new(0.5);

        let mut match_count = 0;
        let iterations = 1000;

        for _ in 0..iterations {
            let mut ctx = Context::new(Message::new());
            matcher.execute(&mut ctx).await.unwrap();

            let matched = ctx.get_metadata::<bool>("random_matched").unwrap();
            if *matched {
                match_count += 1;
            }
        }

        // With 50% probability and 1000 iterations, we expect around 500 matches
        // Allow for some variance (between 40% and 60%)
        let ratio = match_count as f64 / iterations as f64;
        assert!(
            ratio > 0.4 && ratio < 0.6,
            "Match ratio {} outside expected range",
            ratio
        );
    }

    #[tokio::test]
    async fn test_random_matcher_custom_key() {
        let matcher = RandomMatcherPlugin::new(1.0).with_metadata_key("my_random_key".to_string());
        let mut ctx = Context::new(Message::new());

        matcher.execute(&mut ctx).await.unwrap();

        let matched = ctx.get_metadata::<bool>("my_random_key").unwrap();
        assert!(*matched);
    }

    #[test]
    #[should_panic(expected = "Probability must be between 0.0 and 1.0")]
    fn test_random_matcher_invalid_probability_high() {
        RandomMatcherPlugin::new(1.5);
    }

    #[test]
    #[should_panic(expected = "Probability must be between 0.0 and 1.0")]
    fn test_random_matcher_invalid_probability_low() {
        RandomMatcherPlugin::new(-0.1);
    }
}
