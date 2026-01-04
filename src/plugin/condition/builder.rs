//! Condition builder framework for extensible condition system
//!
//! This module provides a trait-based system for building DNS query conditions
//! without the need to modify the main parse_condition function.
//!
//! # Architecture
//!
//! - **ConditionBuilder trait**: Define how a condition is parsed and built
//! - **ConditionBuilderRegistry**: Central registry for all condition builders
//! - **Condition type**: Type alias for the condition closure

use crate::Result;
use crate::plugin::{Context, builder::PluginBuilder};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Type alias for a condition closure
/// A condition is a function that takes a Context and returns a boolean result
pub type Condition = Arc<dyn Fn(&Context) -> bool + Send + Sync>;

/// Trait for building conditions from string specifications
pub trait ConditionBuilder: Send + Sync {
    /// Return the name/prefix of this condition builder
    /// For prefix-based conditions like "qtype 1 2", return "qtype"
    /// For exact-match conditions like "has_resp", return "has_resp"
    fn name(&self) -> &str;

    /// Check if this builder can handle the given condition string
    /// Default implementation checks if the condition starts with the builder's name
    fn can_handle(&self, condition_str: &str) -> bool {
        let condition_name = condition_str.split_whitespace().next().unwrap_or("");
        condition_name == self.name()
            || condition_name.starts_with(&format!("{}.", self.name()))
            || (self.name().starts_with('!') && condition_str.starts_with(self.name()))
    }

    /// Build a condition from the given string
    /// The builder is passed in case the condition needs to reference plugins
    fn build(&self, condition_str: &str, builder: &PluginBuilder) -> Result<Condition>;
}

/// Registry for condition builders
/// This allows dynamic registration of new condition types without modifying parse_condition
pub struct ConditionBuilderRegistry {
    builders: HashMap<String, Arc<dyn ConditionBuilder>>,
}

impl ConditionBuilderRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            builders: HashMap::new(),
        }
    }
}

impl Default for ConditionBuilderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionBuilderRegistry {
    pub fn register(&mut self, builder: Arc<dyn ConditionBuilder>) {
        let name = builder.name().to_string();
        if self.builders.insert(name.clone(), builder).is_some() {
            warn!("Overwriting existing condition builder: {}", name);
        } else {
            debug!("Registered condition builder: {}", name);
        }
    }

    /// Get a builder for the given condition string
    pub fn get_builder(&self, condition_str: &str) -> Option<Arc<dyn ConditionBuilder>> {
        // Try exact match first
        let condition_name = condition_str.split_whitespace().next().unwrap_or("");
        if let Some(builder) = self.builders.get(condition_name) {
            return Some(Arc::clone(builder));
        }

        // Try all builders to find one that can handle this condition
        for builder in self.builders.values() {
            if builder.can_handle(condition_str) {
                return Some(Arc::clone(builder));
            }
        }

        None
    }

    /// Get all registered builder names
    pub fn builder_names(&self) -> Vec<&str> {
        self.builders.keys().map(|s| s.as_str()).collect()
    }
}

/// Global registry instance (lazy-initialized)
use std::sync::OnceLock;

static CONDITION_BUILDER_REGISTRY: OnceLock<ConditionBuilderRegistry> = OnceLock::new();

/// Initialize the global condition builder registry with all default builders
pub fn init_condition_builders() {
    let _ = CONDITION_BUILDER_REGISTRY.get_or_init(|| {
        let mut registry = ConditionBuilderRegistry::new();

        // Register all built-in condition builders
        use crate::plugin::condition::*;

        registry.register(Arc::new(HasRespBuilder));
        registry.register(Arc::new(RespIpBuilder));
        registry.register(Arc::new(RespIpNegBuilder));
        registry.register(Arc::new(QnameBuilder));
        registry.register(Arc::new(QnameNegBuilder));
        registry.register(Arc::new(QtypeBuilder));
        registry.register(Arc::new(QclassBuilder));
        registry.register(Arc::new(RcodeBuilder));
        registry.register(Arc::new(HasCnameBuilder));

        info!("Condition builder registry initialized");

        registry
    });
}

/// Get the global condition builder registry
pub fn get_condition_builder_registry() -> &'static ConditionBuilderRegistry {
    init_condition_builders();
    CONDITION_BUILDER_REGISTRY
        .get()
        .expect("Registry should be initialized")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestBuilder;

    impl ConditionBuilder for TestBuilder {
        fn name(&self) -> &str {
            "test_condition"
        }

        fn build(&self, condition_str: &str, _builder: &PluginBuilder) -> Result<Condition> {
            if condition_str == "test_condition" {
                Ok(Arc::new(|_: &Context| true))
            } else {
                Err(crate::Error::Config("Invalid test condition".to_string()))
            }
        }
    }

    #[test]
    fn test_registry_registration() {
        let mut registry = ConditionBuilderRegistry::new();
        let builder: Arc<dyn ConditionBuilder> = Arc::new(TestBuilder);

        registry.register(Arc::clone(&builder));

        assert!(registry.get_builder("test_condition").is_some());
    }

    #[test]
    fn test_registry_lookup() {
        let mut registry = ConditionBuilderRegistry::new();
        let builder: Arc<dyn ConditionBuilder> = Arc::new(TestBuilder);

        registry.register(builder);

        let found = registry.get_builder("test_condition");
        assert!(found.is_some());

        let not_found = registry.get_builder("unknown");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_builder_names() {
        let mut registry = ConditionBuilderRegistry::new();
        let builder: Arc<dyn ConditionBuilder> = Arc::new(TestBuilder);

        registry.register(builder);

        let names = registry.builder_names();
        assert!(names.contains(&"test_condition"));
    }

    #[test]
    fn test_default_builders_registered() {
        // Ensure the global registry is initialized and contains built-in builders
        init_condition_builders();
        let registry = get_condition_builder_registry();
        let names = registry.builder_names();

        let expected = [
            "has_resp",
            "resp_ip",
            "!resp_ip",
            "qname",
            "!qname",
            "qtype",
            "qclass",
            "rcode",
            "has_cname",
        ];

        for &n in expected.iter() {
            assert!(
                names.contains(&n),
                "Expected condition builder '{}' to be registered",
                n
            );
        }
    }
}
