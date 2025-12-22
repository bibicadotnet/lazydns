//! Forward with EDNS0 options plugin
//!
//! Forwards queries with custom EDNS0 options

use crate::Result;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::fmt;
use tracing::{debug, trace};

/// EDNS0 option code and data
#[derive(Debug, Clone)]
pub struct Edns0Option {
    /// Option code
    pub code: u16,
    /// Option data
    pub data: Vec<u8>,
}

impl Edns0Option {
    /// Create a new EDNS0 option
    pub fn new(code: u16, data: Vec<u8>) -> Self {
        Self { code, data }
    }
}

/// Plugin that adds EDNS0 options to forwarded queries
///
/// This plugin allows adding custom EDNS0 options when forwarding queries.
/// Useful for adding client subnet information, cookies, or other EDNS0 extensions.
///
/// # Example
///
/// ```rust
/// use lazydns::plugins::executable::{ForwardEdns0OptPlugin, Edns0Option};
///
/// // Add EDNS Client Subnet option (code 8)
/// let ecs_data = vec![0, 1, 24, 0, 192, 168, 1]; // Example ECS data
/// let plugin = ForwardEdns0OptPlugin::new()
///     .add_option(Edns0Option::new(8, ecs_data.clone()));
///
/// // Add multiple options
/// let plugin = ForwardEdns0OptPlugin::new()
///     .add_option(Edns0Option::new(8, ecs_data.clone()))
///     .add_option(Edns0Option::new(10, vec![1, 2, 3, 4])); // DNS Cookie
/// ```
pub struct ForwardEdns0OptPlugin {
    /// EDNS0 options to add
    options: Vec<Edns0Option>,
    /// Whether to preserve existing EDNS0 options
    preserve_existing: bool,
}

impl ForwardEdns0OptPlugin {
    /// Create a new EDNS0 options plugin
    pub fn new() -> Self {
        Self {
            options: Vec::new(),
            preserve_existing: true,
        }
    }

    /// Add an EDNS0 option
    pub fn add_option(mut self, option: Edns0Option) -> Self {
        self.options.push(option);
        self
    }

    /// Set whether to preserve existing EDNS0 options
    pub fn preserve_existing(mut self, preserve: bool) -> Self {
        self.preserve_existing = preserve;
        self
    }
}

impl Default for ForwardEdns0OptPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ForwardEdns0OptPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardEdns0OptPlugin")
            .field("options_count", &self.options.len())
            .field("preserve_existing", &self.preserve_existing)
            .finish()
    }
}

#[async_trait]
impl Plugin for ForwardEdns0OptPlugin {
    fn name(&self) -> &str {
        "forward_edns0opt"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Store EDNS0 options in metadata for the forward plugin to use
        if !self.options.is_empty() {
            debug!(
                option_count = self.options.len(),
                preserve = self.preserve_existing,
                "Adding EDNS0 options to query"
            );

            // Store options in metadata
            for (idx, option) in self.options.iter().enumerate() {
                trace!(
                    index = idx,
                    code = option.code,
                    data_len = option.data.len(),
                    "EDNS0 option"
                );
            }

            ctx.set_metadata("edns0_options".to_string(), self.options.clone());
            ctx.set_metadata(
                "edns0_preserve_existing".to_string(),
                self.preserve_existing,
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_forward_edns0opt_single_option() {
        let option = Edns0Option::new(8, vec![0, 1, 24, 0]);
        let plugin = ForwardEdns0OptPlugin::new().add_option(option);

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        // Check that options were stored in metadata
        let options = ctx.get_metadata::<Vec<Edns0Option>>("edns0_options");
        assert!(options.is_some());
        let options = options.unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].code, 8);
    }

    #[tokio::test]
    async fn test_forward_edns0opt_multiple_options() {
        let option1 = Edns0Option::new(8, vec![0, 1, 24, 0]);
        let option2 = Edns0Option::new(10, vec![1, 2, 3, 4]);
        let plugin = ForwardEdns0OptPlugin::new()
            .add_option(option1)
            .add_option(option2);

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        let options = ctx.get_metadata::<Vec<Edns0Option>>("edns0_options");
        assert!(options.is_some());
        let options = options.unwrap();
        assert_eq!(options.len(), 2);
        assert_eq!(options[0].code, 8);
        assert_eq!(options[1].code, 10);
    }

    #[tokio::test]
    async fn test_forward_edns0opt_preserve_flag() {
        let option = Edns0Option::new(8, vec![0, 1, 24, 0]);
        let plugin = ForwardEdns0OptPlugin::new()
            .add_option(option)
            .preserve_existing(false);

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        let preserve = ctx.get_metadata::<bool>("edns0_preserve_existing");
        assert!(preserve.is_some());
        assert!(!(*preserve.unwrap()));
    }

    #[tokio::test]
    async fn test_forward_edns0opt_no_options() {
        let plugin = ForwardEdns0OptPlugin::new();

        let mut ctx = Context::new(Message::new());
        plugin.execute(&mut ctx).await.unwrap();

        // Should not set metadata when no options
        let options = ctx.get_metadata::<Vec<Edns0Option>>("edns0_options");
        assert!(options.is_none());
    }

    #[tokio::test]
    async fn test_forward_edns0opt_default() {
        let plugin = ForwardEdns0OptPlugin::default();
        assert_eq!(plugin.options.len(), 0);
        assert!(plugin.preserve_existing);
    }
}
