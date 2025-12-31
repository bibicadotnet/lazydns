//! Domain Validator Plugin
//!
//! Validates DNS query domain names for RFC compliance and filters invalid/malicious queries.

use crate::Result;
use crate::dns::ResponseCode;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use lru::LruCache;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Validation result
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid,
    InvalidChars,
    InvalidLength,
    InvalidFormat,
    Blacklisted,
}

/// Domain validator plugin
#[derive(Debug)]
pub struct DomainValidatorPlugin {
    /// Enable strict RFC compliance mode
    strict_mode: bool,
    /// LRU cache for validation results
    cache: Arc<RwLock<LruCache<String, ValidationResult>>>,
    /// Blacklist of domains to reject
    blacklist: HashSet<String>,
}

impl DomainValidatorPlugin {
    /// Create a new domain validator
    pub fn new(strict_mode: bool, cache_size: usize, blacklist: Vec<String>) -> Self {
        let cache = if cache_size > 0 {
            LruCache::new(NonZeroUsize::new(cache_size).unwrap())
        } else {
            LruCache::new(NonZeroUsize::new(1).unwrap()) // Minimal cache
        };

        Self {
            strict_mode,
            cache: Arc::new(RwLock::new(cache)),
            blacklist: blacklist.into_iter().collect(),
        }
    }

    /// Validate a domain name
    pub fn validate_domain(&self, domain: &str) -> ValidationResult {
        // Check blacklist first
        if self.blacklist.contains(domain)
            || self
                .blacklist
                .iter()
                .any(|b| domain.ends_with(&format!(".{}", b)))
        {
            return ValidationResult::Blacklisted;
        }

        // Basic checks
        if domain.is_empty() || domain.len() > 253 {
            return ValidationResult::InvalidLength;
        }

        // Allow root domain
        if domain == "." {
            return ValidationResult::Valid;
        }

        let labels: Vec<&str> = domain.split('.').collect();

        for label in labels {
            if label.is_empty() || label.len() > 63 {
                return ValidationResult::InvalidLength;
            }

            // Check characters
            let bytes = label.as_bytes();
            if bytes.is_empty() {
                return ValidationResult::InvalidLength;
            }

            // First character must be alphanumeric
            if !bytes[0].is_ascii_alphanumeric() {
                return ValidationResult::InvalidChars;
            }

            // Last character must be alphanumeric
            let last = bytes[bytes.len() - 1];
            if !last.is_ascii_alphanumeric() {
                return ValidationResult::InvalidChars;
            }

            // Middle characters: alphanumeric or hyphen (only if there are middle characters)
            if bytes.len() > 2 {
                for &b in &bytes[1..bytes.len() - 1] {
                    if !b.is_ascii_alphanumeric() && b != b'-' {
                        return ValidationResult::InvalidChars;
                    }
                }
            }

            // No consecutive hyphens in strict mode
            if self.strict_mode && label.contains("--") {
                return ValidationResult::InvalidFormat;
            }
        }

        ValidationResult::Valid
    }
}

#[async_trait]
impl Plugin for DomainValidatorPlugin {
    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        #[cfg(feature = "metrics")]
        let start = std::time::Instant::now();
        let qname = ctx
            .request()
            .questions()
            .first()
            .map(|q| q.qname().to_string())
            .unwrap_or_default();

        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(result) = cache.get(&qname) {
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::DNS_DOMAIN_VALIDATION_CACHE_HITS_TOTAL.inc();
                    let duration = start.elapsed().as_secs_f64();
                    crate::metrics::DNS_DOMAIN_VALIDATION_DURATION_SECONDS.observe(duration);
                }
                return handle_result(result.clone(), &qname, ctx);
            }
        }

        // Validate
        let result = self.validate_domain(&qname);

        // Record metrics
        #[cfg(feature = "metrics")]
        {
            let result_label = match &result {
                ValidationResult::Valid => "valid",
                ValidationResult::InvalidChars => "invalid_chars",
                ValidationResult::InvalidLength => "invalid_length",
                ValidationResult::InvalidFormat => "invalid_format",
                ValidationResult::Blacklisted => "blacklisted",
            };
            crate::metrics::DNS_DOMAIN_VALIDATION_TOTAL
                .with_label_values(&[result_label])
                .inc();
        }

        // Cache result
        {
            let mut cache = self.cache.write().await;
            cache.put(qname.clone(), result.clone());
        }

        #[cfg(feature = "metrics")]
        {
            let duration = start.elapsed().as_secs_f64();
            crate::metrics::DNS_DOMAIN_VALIDATION_DURATION_SECONDS.observe(duration);
        }

        handle_result(result, &qname, ctx)
    }

    fn name(&self) -> &str {
        "domain_validator"
    }

    fn priority(&self) -> i32 {
        2100 // High priority, run early
    }

    fn init(config: &crate::config::PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();
        let strict_mode = args
            .get("strict_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let cache_size = args
            .get("cache_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;
        let blacklist = args
            .get("blacklist")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Arc::new(Self::new(strict_mode, cache_size, blacklist)))
    }
}

fn handle_result(result: ValidationResult, qname: &str, ctx: &mut Context) -> Result<()> {
    match result {
        ValidationResult::Valid => Ok(()),
        ValidationResult::Blacklisted => {
            warn!("Rejected blacklisted domain: {}", qname);
            set_refused_response(ctx);
            Ok(())
        }
        ValidationResult::InvalidChars => {
            debug!("Rejected domain with invalid characters: {}", qname);
            set_refused_response(ctx);
            Ok(())
        }
        ValidationResult::InvalidLength => {
            debug!("Rejected domain with invalid length: {}", qname);
            set_refused_response(ctx);
            Ok(())
        }
        ValidationResult::InvalidFormat => {
            debug!("Rejected domain with invalid format: {}", qname);
            set_refused_response(ctx);
            Ok(())
        }
    }
}

fn set_refused_response(ctx: &mut Context) {
    let mut response = crate::dns::Message::new();
    response.set_id(ctx.request().id());
    response.set_response(true);
    response.set_response_code(ResponseCode::Refused);
    ctx.set_response(Some(response));
}

impl Default for DomainValidatorPlugin {
    fn default() -> Self {
        Self::new(true, 1000, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_valid_domains() {
        let plugin = DomainValidatorPlugin::default();
        assert_eq!(
            plugin.validate_domain("example.com"),
            ValidationResult::Valid
        );
        assert_eq!(
            plugin.validate_domain("sub.example.co.uk"),
            ValidationResult::Valid
        );
        assert_eq!(plugin.validate_domain("localhost"), ValidationResult::Valid);
        assert_eq!(plugin.validate_domain("."), ValidationResult::Valid);
    }

    #[tokio::test]
    async fn test_invalid_chars() {
        let plugin = DomainValidatorPlugin::default();
        assert_eq!(
            plugin.validate_domain("test space.com"),
            ValidationResult::InvalidChars
        );
        assert_eq!(
            plugin.validate_domain("test@domain.com"),
            ValidationResult::InvalidChars
        );
        assert_eq!(
            plugin.validate_domain("-test.com"),
            ValidationResult::InvalidChars
        );
        assert_eq!(
            plugin.validate_domain("test-.com"),
            ValidationResult::InvalidChars
        );
    }

    #[tokio::test]
    async fn test_single_char_labels() {
        let plugin = DomainValidatorPlugin::default();
        assert_eq!(plugin.validate_domain("a.com"), ValidationResult::Valid);
        assert_eq!(plugin.validate_domain("a.b.com"), ValidationResult::Valid);
        assert_eq!(plugin.validate_domain("x.y.z"), ValidationResult::Valid);
    }

    #[tokio::test]
    async fn test_invalid_length() {
        let plugin = DomainValidatorPlugin::default();
        let long_label = "a".repeat(64) + ".com";
        assert_eq!(
            plugin.validate_domain(&long_label),
            ValidationResult::InvalidLength
        );
        let long_domain = "a.".repeat(126) + "com";
        assert_eq!(
            plugin.validate_domain(&long_domain),
            ValidationResult::InvalidLength
        );
    }

    #[tokio::test]
    async fn test_strict_mode() {
        let strict_plugin = DomainValidatorPlugin::new(true, 1000, vec![]);
        assert_eq!(
            strict_plugin.validate_domain("te--st.com"),
            ValidationResult::InvalidFormat
        );

        let lenient_plugin = DomainValidatorPlugin::new(false, 1000, vec![]);
        assert_eq!(
            lenient_plugin.validate_domain("te--st.com"),
            ValidationResult::Valid
        );
    }

    #[tokio::test]
    async fn test_blacklist() {
        let plugin = DomainValidatorPlugin::new(true, 1000, vec!["malicious.com".to_string()]);
        assert_eq!(
            plugin.validate_domain("malicious.com"),
            ValidationResult::Blacklisted
        );
        assert_eq!(
            plugin.validate_domain("sub.malicious.com"),
            ValidationResult::Blacklisted
        );
    }

    #[tokio::test]
    async fn test_cache() {
        use crate::dns::{Message, Question, RecordClass, RecordType};

        let plugin = DomainValidatorPlugin::new(true, 10, vec![]);

        // Create a test request
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".parse().unwrap(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(request);

        // First execution
        let result = plugin.execute(&mut ctx).await;
        assert!(result.is_ok());
        assert!(ctx.response().is_none()); // Valid domain, no response set

        // Check cache
        {
            let cache = plugin.cache.write().await;
            assert!(cache.contains("example.com"));
        }
    }
}

crate::register_plugin_builder!(DomainValidatorPlugin);
