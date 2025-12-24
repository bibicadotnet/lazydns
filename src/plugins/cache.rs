//! DNS response caching plugin
//!
//! This plugin caches DNS responses to improve performance and reduce load on upstream servers.
//!
//! # Features
//!
//! - **TTL-based expiration**: Respects DNS record TTL values
//! - **LRU eviction**: Least Recently Used eviction when cache is full
//! - **Size limits**: Configurable maximum cache size
//! - **Statistics**: Track hits, misses, and evictions
//!
//! # Usage Example (in code)
//!
//! ```rust
//! use lazydns::plugins::CachePlugin;
//! use lazydns::plugin::{Plugin, Context};
//! use lazydns::dns::Message;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create cache with max 1000 entries
//! let cache = CachePlugin::new(1000);
//! let plugin: Arc<dyn Plugin> = Arc::new(cache);
//!
//! // Use in plugin chain
//! let mut context = Context::new(Message::new());
//! plugin.execute(&mut context).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Configuration (YAML)
//!
//! Example showing how to register a named cache and reference it from a
//! `sequence` plugin. Adjust tags and pipeline composition to match your
//! project's configuration conventions.
//!
//! ```yaml
//! plugins:
//!   - tag: my_cache
//!     type: cache
//!     config:
//!       size: 1024
//!       negative_cache: true
//!       negative_ttl: 300
//!
//!   - tag: resolver_sequence
//!     type: sequence
//!     args:
//!       - exec: "$my_cache"
//! ```
//!
//! # Notes
//!
//! - Place `CachePlugin` early in the plugin chain so cached responses can
//!   be returned before invoking expensive upstream resolvers.
//! - CachePlugin automatically handles both cache reads (before sequence) and
//!   cache writes (after sequence completes), eliminating the need for a separate
//!   store plugin.
use crate::Result;
use crate::config::PluginConfig;
use crate::dns::Message;
use crate::error::Error;
#[cfg(feature = "metrics")]
use crate::metrics;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use dashmap::DashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

// Auto-register using the register macro
crate::register_plugin_builder!(CachePlugin);

/// Cache entry storing a DNS response with metadata
#[derive(Clone)]
struct CacheEntry {
    /// Cached DNS response message
    response: Message,
    /// When this entry was created
    cached_at: Instant,
    /// Time-to-live for this entry (in seconds)
    ttl: u32,
    /// Last access time for LRU tracking
    last_accessed: Instant,
}

impl CacheEntry {
    /// Create a new cache entry
    fn new(response: Message, ttl: u32) -> Self {
        let now = Instant::now();
        Self {
            response,
            cached_at: now,
            ttl,
            last_accessed: now,
        }
    }

    /// Check if this entry has expired
    fn is_expired(&self) -> bool {
        // Entries with a TTL of 0 should be considered expired immediately.
        if self.ttl == 0 {
            return true;
        }

        // Use >= to avoid timing races where elapsed may equal the TTL.
        self.cached_at.elapsed() >= Duration::from_secs(self.ttl as u64)
    }

    /// Update last accessed time
    fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    /// Get remaining TTL in seconds
    fn remaining_ttl(&self) -> u32 {
        let elapsed = self.cached_at.elapsed().as_secs() as u32;
        self.ttl.saturating_sub(elapsed)
    }
}

/// Statistics for the cache
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Number of cache hits
    hits: AtomicU64,
    /// Number of cache misses
    misses: AtomicU64,
    /// Number of entries evicted due to size limit
    evictions: AtomicU64,
    /// Number of entries expired due to TTL
    expirations: AtomicU64,
}

impl CacheStats {
    /// Create new cache statistics
    fn new() -> Self {
        Self::default()
    }

    /// Increment hit counter
    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        // Update Prometheus metric
        #[cfg(feature = "metrics")]
        {
            metrics::CACHE_HITS_TOTAL.inc();
        }
    }

    /// Increment miss counter
    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        // Update Prometheus metric
        #[cfg(feature = "metrics")]
        {
            metrics::CACHE_MISSES_TOTAL.inc();
        }
    }

    /// Increment eviction counter
    fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment expiration counter
    fn record_expiration(&self) {
        self.expirations.fetch_add(1, Ordering::Relaxed);
    }

    /// Get number of hits
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get number of misses
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get number of evictions
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Get number of expirations
    pub fn expirations(&self) -> u64 {
        self.expirations.load(Ordering::Relaxed)
    }

    /// Calculate hit rate (0.0 to 1.0)
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits();
        let total = hits + self.misses();
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Get total number of requests
    pub fn total_requests(&self) -> u64 {
        self.hits() + self.misses()
    }
}

impl fmt::Display for CacheStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CacheStats {{ hits: {}, misses: {}, evictions: {}, expirations: {}, hit_rate: {:.2}% }}",
            self.hits(),
            self.misses(),
            self.evictions(),
            self.expirations(),
            self.hit_rate() * 100.0
        )
    }
}

/// DNS response cache plugin
///
/// Caches DNS responses based on their TTL values. When the cache is full,
/// uses LRU (Least Recently Used) eviction policy.
pub struct CachePlugin {
    /// The cache storage (domain name -> cache entry)
    cache: Arc<DashMap<String, CacheEntry>>,
    /// Maximum number of entries in the cache
    max_size: usize,
    /// Cache statistics
    stats: Arc<CacheStats>,
    /// Enable negative caching (cache NXDOMAIN/SERVFAIL responses)
    negative_cache: bool,
    /// TTL for negative cache entries (in seconds)
    negative_ttl: u32,
    /// Enable cache prefetch (refresh entries before they expire)
    enable_prefetch: bool,
    /// Prefetch threshold (refresh when TTL drops below this percentage)
    prefetch_threshold: f32,
}

impl CachePlugin {
    /// Create a new cache plugin with the specified maximum size
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of entries to store in the cache
    ///
    /// # Example
    ///
    /// ```rust
    /// use lazydns::plugins::CachePlugin;
    ///
    /// let cache = CachePlugin::new(1000);
    /// ```
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            max_size,
            stats: Arc::new(CacheStats::new()),
            negative_cache: false,
            negative_ttl: 300, // 5 minutes default
            enable_prefetch: false,
            prefetch_threshold: 0.1, // Refresh at 10% remaining TTL
        }
    }

    /// Enable negative caching for error responses
    ///
    /// # Arguments
    ///
    /// * `ttl` - TTL in seconds for negative cache entries
    pub fn with_negative_cache(mut self, ttl: u32) -> Self {
        self.negative_cache = true;
        self.negative_ttl = ttl;
        self
    }

    /// Enable cache prefetch
    ///
    /// # Arguments
    ///
    /// * `threshold` - Refresh when remaining TTL drops below this percentage (0.0-1.0)
    pub fn with_prefetch(mut self, threshold: f32) -> Self {
        self.enable_prefetch = true;
        self.prefetch_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Get a reference to the cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get the current number of entries in the cache
    pub fn size(&self) -> usize {
        self.cache.len()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        self.cache.clear();
        // Update cache size metric
        #[cfg(feature = "metrics")]
        {
            metrics::CACHE_SIZE.set(0);
        }
    }

    /// Generate a cache key from a DNS query
    ///
    /// Cache key includes:
    /// - Domain name (lowercased for case-insensitive matching)
    /// - Query type
    /// - Query class
    /// - EDNS0 flags (AD, CD, DO bits) if present
    fn make_key(message: &Message) -> Option<String> {
        // Use the first question as the cache key
        message.questions().first().map(|q| {
            // Normalize domain name to lowercase for case-insensitive matching
            let qname_lower = q.qname().to_lowercase();

            // Build key with EDNS0 considerations
            // Like mosdns, include AD, CD, DO flags in the key for proper caching
            let key = format!(
                "{}:{}:{}",
                qname_lower,
                q.qtype().to_u16(),
                q.qclass().to_u16()
            );

            // TODO: Add EDNS0 flags if message has EDNS0
            // This would ensure DNSSEC queries are cached separately from non-DNSSEC
            // Currently, we focus on the main fix: domain name normalization

            key
        })
    }

    /// Check if cache is at capacity
    #[allow(dead_code)]
    fn is_full(&self) -> bool {
        self.cache.len() >= self.max_size
    }

    /// Evict least recently used entry
    #[allow(dead_code)]
    fn evict_lru(&self) {
        if self.cache.is_empty() {
            return;
        }

        // Find the entry with the oldest last_accessed time
        let mut oldest_key: Option<String> = None;
        let mut oldest_time: Option<Instant> = None;

        for entry in self.cache.iter() {
            let last_accessed = entry.value().last_accessed;
            if oldest_time.is_none() || last_accessed < oldest_time.unwrap() {
                oldest_time = Some(last_accessed);
                oldest_key = Some(entry.key().clone());
            }
        }

        // Remove the oldest entry
        if let Some(key) = oldest_key {
            self.cache.remove(&key);
            self.stats.record_eviction();
            // Update cache size metric
            #[cfg(feature = "metrics")]
            {
                metrics::CACHE_SIZE.set(self.size() as i64);
            }
            debug!("Evicted LRU cache entry: {}", key);
        }
    }

    /// Store a response in the cache
    #[allow(dead_code)]
    fn store(&self, key: String, entry: CacheEntry) {
        // Evict if necessary
        if self.is_full() {
            self.evict_lru();
        }

        self.cache.insert(key, entry);
        // Update cache size metric
        #[cfg(feature = "metrics")]
        {
            metrics::CACHE_SIZE.set(self.size() as i64);
        }
    }

    /// Get minimum TTL from a DNS message
    fn get_min_ttl(message: &Message) -> u32 {
        let mut min_ttl = u32::MAX;

        // Check answer section
        for record in message.answers() {
            min_ttl = min_ttl.min(record.ttl());
        }

        // Check authority section
        for record in message.authority() {
            min_ttl = min_ttl.min(record.ttl());
        }

        // Check additional section
        for record in message.additional() {
            min_ttl = min_ttl.min(record.ttl());
        }

        // Default to 300 seconds (5 minutes) if no records found
        if min_ttl == u32::MAX {
            300
        } else {
            // Don't cache for less than 1 second
            min_ttl.max(1)
        }
    }

    /// Update TTLs in a cached response
    fn update_ttls(message: &mut Message, remaining_ttl: u32) {
        // Update TTLs in answer section
        for record in message.answers_mut() {
            record.set_ttl(remaining_ttl);
        }

        // Update TTLs in authority section
        for record in message.authority_mut() {
            record.set_ttl(remaining_ttl);
        }

        // Update TTLs in additional section
        for record in message.additional_mut() {
            record.set_ttl(remaining_ttl);
        }
    }
}

impl fmt::Debug for CachePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachePlugin")
            .field("max_size", &self.max_size)
            .field("current_size", &self.size())
            .field("stats", &self.stats())
            .finish()
    }
}

#[async_trait]
impl Plugin for CachePlugin {
    async fn execute(&self, context: &mut Context) -> Result<()> {
        // Generate cache key from request
        let key = match Self::make_key(context.request()) {
            Some(k) => k,
            None => {
                debug!("Cannot generate cache key, no questions in request");
                return Ok(());
            }
        };

        // Phase 1: Try to read from cache (only if no response yet)
        if context.response().is_none() {
            // Try to get from cache
            if let Some(mut entry_ref) = self.cache.get_mut(&key) {
                let entry = entry_ref.value_mut();

                // Check if expired
                if entry.is_expired() {
                    debug!("Cache entry expired: {}", key);
                    drop(entry_ref); // Release lock before removing
                    self.cache.remove(&key);
                    self.stats.record_expiration();
                    self.stats.record_miss();
                    // Update cache size metric after removal
                    #[cfg(feature = "metrics")]
                    {
                        metrics::CACHE_SIZE.set(self.size() as i64);
                    }
                    return Ok(());
                }

                // Cache hit!
                debug!("Cache hit: {}", key);
                self.stats.record_hit();

                // Update last accessed time
                entry.touch();

                // Clone the response and update TTLs
                let mut response = entry.response.clone();
                let remaining_ttl = entry.remaining_ttl();
                Self::update_ttls(&mut response, remaining_ttl);

                // Copy request ID to response
                response.set_id(context.request().id());

                // Set the response in context
                context.set_response(Some(response));

                return Ok(());
            }

            // Cache miss
            self.stats.record_miss();
            debug!("Cache miss: {}", key);
        } else {
            // Phase 2: A response exists (set by a downstream plugin like forward)
            // We should store it in cache for future queries
            if let Some(response) = context.response() {
                let response_code = response.response_code();
                let is_error = response_code != crate::dns::ResponseCode::NoError;

                // Handle negative caching
                if is_error {
                    if self.negative_cache {
                        // Cache error responses with negative TTL
                        debug!(
                            "Caching negative response: {:?} (TTL: {}s)",
                            response_code, self.negative_ttl
                        );

                        // Evict if necessary
                        if self.is_full() {
                            self.evict_lru();
                        }

                        let entry = CacheEntry::new(response.clone(), self.negative_ttl);
                        self.cache.insert(key.clone(), entry);
                    } else {
                        debug!("Not caching error response: {:?}", response_code);
                    }
                } else if !response.answers().is_empty() {
                    // Cache successful responses with answers
                    let ttl = Self::get_min_ttl(response);

                    if ttl > 0 {
                        debug!("Storing response in cache: {} (TTL: {}s)", key, ttl);
                        // Evict if necessary
                        if self.is_full() {
                            self.evict_lru();
                        }

                        let entry = CacheEntry::new(response.clone(), ttl);
                        self.cache.insert(key.clone(), entry);
                        // Update cache size metric
                        #[cfg(feature = "metrics")]
                        {
                            metrics::CACHE_SIZE.set(self.size() as i64);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "cache"
    }

    fn priority(&self) -> i32 {
        // Cache should run early to check for cached responses
        // and after it's been populated (when returning from other plugins)
        50
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        let args = config.effective_args();
        use serde_yaml::Value;

        // Parse size parameter (default: 1024)
        let size = match args.get("size") {
            Some(Value::Number(n)) => n
                .as_i64()
                .ok_or_else(|| Error::Config("Invalid size value".to_string()))?
                as usize,
            Some(_) => return Err(Error::Config("size must be a number".to_string())),
            None => 1024,
        };

        let mut cache = CachePlugin::new(size);

        // Parse negative_cache parameter (default: false)
        if let Some(Value::Bool(true)) = args.get("negative_cache") {
            let negative_ttl = match args.get("negative_ttl") {
                Some(Value::Number(n)) => n
                    .as_i64()
                    .ok_or_else(|| Error::Config("Invalid negative_ttl value".to_string()))?
                    as u32,
                Some(_) => return Err(Error::Config("negative_ttl must be a number".to_string())),
                None => 300,
            };
            cache = cache.with_negative_cache(negative_ttl);
        }

        // Parse prefetch parameter (default: false)
        if let Some(Value::Bool(true)) = args.get("enable_prefetch") {
            let threshold = match args.get("prefetch_threshold") {
                Some(Value::Number(n)) => n
                    .as_f64()
                    .ok_or_else(|| Error::Config("Invalid prefetch_threshold value".to_string()))?
                    as f32,
                Some(_) => {
                    return Err(Error::Config(
                        "prefetch_threshold must be a number".to_string(),
                    ));
                }
                None => 0.1,
            };
            cache = cache.with_prefetch(threshold);
        }

        Ok(Arc::new(cache))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, Question, RData, RecordClass, RecordType, ResourceRecord};
    use std::net::Ipv4Addr;

    fn create_test_message() -> Message {
        let mut msg = Message::new();
        msg.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        msg
    }

    fn create_test_response() -> Message {
        let mut msg = create_test_message();
        msg.add_answer(ResourceRecord::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
            300,
            RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        ));
        msg
    }

    #[test]
    fn test_cache_entry_creation() {
        let response = create_test_response();
        let entry = CacheEntry::new(response.clone(), 300);

        assert_eq!(entry.ttl, 300);
        assert!(!entry.is_expired());
        assert_eq!(entry.response.answers().len(), response.answers().len());
    }

    #[test]
    fn test_cache_entry_expiration() {
        let response = create_test_response();
        let entry = CacheEntry::new(response, 0);

        // Entry with 0 TTL should be immediately expired
        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_entry_remaining_ttl() {
        let response = create_test_response();
        let entry = CacheEntry::new(response, 300);

        let remaining = entry.remaining_ttl();
        assert!(remaining <= 300);
        assert!(remaining >= 299); // Should be very close to 300
    }

    #[test]
    fn test_cache_stats() {
        let stats = CacheStats::new();

        assert_eq!(stats.hits(), 0);
        assert_eq!(stats.misses(), 0);
        assert_eq!(stats.evictions(), 0);

        stats.record_hit();
        stats.record_hit();
        stats.record_miss();

        assert_eq!(stats.hits(), 2);
        assert_eq!(stats.misses(), 1);
        assert_eq!(stats.hit_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_cache_plugin_creation() {
        let cache = CachePlugin::new(100);

        assert_eq!(cache.max_size, 100);
        assert_eq!(cache.size(), 0);
        assert_eq!(cache.stats().hits(), 0);
    }

    #[test]
    fn test_make_key() {
        let msg = create_test_message();
        let key = CachePlugin::make_key(&msg);

        assert!(key.is_some());
        assert_eq!(key.unwrap(), "example.com:1:1");
    }

    #[test]
    fn test_make_key_case_insensitive() {
        // Test that different casings produce the same cache key
        let msg_lower = create_test_message();
        let mut msg_upper = create_test_message();

        // Change question to uppercase
        msg_upper.questions_mut()[0].set_qname("EXAMPLE.COM".to_string());

        let key_lower = CachePlugin::make_key(&msg_lower);
        let key_upper = CachePlugin::make_key(&msg_upper);

        assert!(key_lower.is_some());
        assert!(key_upper.is_some());
        // Both should produce the same lowercase key
        let key_lower_str = key_lower.unwrap();
        let key_upper_str = key_upper.unwrap();
        assert_eq!(key_lower_str, key_upper_str);
        assert_eq!(key_lower_str, "example.com:1:1");
    }

    #[test]
    fn test_make_key_no_questions() {
        let msg = Message::new();
        let key = CachePlugin::make_key(&msg);

        assert!(key.is_none());
    }

    #[test]
    fn test_get_min_ttl() {
        let response = create_test_response();
        let ttl = CachePlugin::get_min_ttl(&response);

        assert_eq!(ttl, 300);
    }

    #[test]
    fn test_get_min_ttl_no_records() {
        let msg = create_test_message();
        let ttl = CachePlugin::get_min_ttl(&msg);

        // Should return default TTL of 300
        assert_eq!(ttl, 300);
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn test_cache_miss() {
        let cache = CachePlugin::new(100);
        let request = create_test_message();
        let mut context = Context::new(request);

        let prev_misses = metrics::CACHE_MISSES_TOTAL.get();

        cache.execute(&mut context).await.unwrap();

        assert!(context.response().is_none());
        assert_eq!(cache.stats().misses(), 1);
        assert_eq!(cache.stats().hits(), 0);
        // Global metric incremented
        assert_eq!(metrics::CACHE_MISSES_TOTAL.get(), prev_misses + 1);
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn test_cache_hit() {
        let cache = CachePlugin::new(100);

        // Store an entry in the cache via store() so metric is updated
        let response = create_test_response();
        let key = "example.com:1:1".to_string();
        let entry = CacheEntry::new(response.clone(), 300);
        cache.store(key.clone(), entry);

        // Cache size metric should be updated
        assert_eq!(metrics::CACHE_SIZE.get(), cache.size() as i64);

        // Try to retrieve it
        let request = create_test_message();
        let mut context = Context::new(request);

        let prev_hits = metrics::CACHE_HITS_TOTAL.get();

        cache.execute(&mut context).await.unwrap();

        assert!(context.response().is_some());
        assert_eq!(cache.stats().hits(), 1);
        assert_eq!(cache.stats().misses(), 0);
        // Global metric incremented
        assert_eq!(metrics::CACHE_HITS_TOTAL.get(), prev_hits + 1);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = CachePlugin::new(100);

        // Store an entry with 0 TTL (immediately expired)
        let response = create_test_response();
        let key = "example.com:1:1".to_string();
        let entry = CacheEntry::new(response.clone(), 0);
        cache.cache.insert(key.clone(), entry);

        // Try to retrieve it
        let request = create_test_message();
        let mut context = Context::new(request);

        cache.execute(&mut context).await.unwrap();

        // Should be a miss because entry expired
        assert!(context.response().is_none());
        assert_eq!(cache.stats().misses(), 1);
        assert_eq!(cache.stats().expirations(), 1);

        // Entry should be removed from cache
        assert!(!cache.cache.contains_key(&key));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_cache_clear() {
        let cache = CachePlugin::new(100);

        // Add some entries via store() so metric is updated
        let response = create_test_response();
        let entry = CacheEntry::new(response.clone(), 300);
        cache.store("key1".to_string(), entry.clone());
        cache.store("key2".to_string(), entry.clone());

        assert_eq!(cache.size(), 2);
        assert_eq!(metrics::CACHE_SIZE.get(), 2);

        cache.clear();

        assert_eq!(cache.size(), 0);
        assert_eq!(metrics::CACHE_SIZE.get(), 0);
    }

    #[test]
    fn test_lru_eviction() {
        let cache = CachePlugin::new(2); // Small cache

        let response = create_test_response();
        let entry1 = CacheEntry::new(response.clone(), 300);
        let entry2 = CacheEntry::new(response.clone(), 300);
        let entry3 = CacheEntry::new(response.clone(), 300);

        // Fill cache
        cache.cache.insert("key1".to_string(), entry1);
        cache.cache.insert("key2".to_string(), entry2);

        assert_eq!(cache.size(), 2);

        // Add one more - should evict the LRU entry
        cache.store("key3".to_string(), entry3);

        assert_eq!(cache.size(), 2);
        assert_eq!(cache.stats().evictions(), 1);
    }

    #[tokio::test]
    async fn test_configured_cache_sequence_execution() {
        // YAML config: registers a named cache and a sequence that execs it by name
        let yaml = r#"
plugins:
  - tag: my_cache
    type: cache
    config:
      size: 16

  - tag: seq
    type: sequence
    args:
      - exec: "$my_cache"
"#;

        let cfg = crate::config::Config::from_yaml(yaml).expect("parse yaml");

        let mut builder = crate::plugin::builder::PluginBuilder::new();

        // Build all plugins from config
        for pc in &cfg.plugins {
            builder.build(pc).expect("build plugin");
        }

        // Resolve references (sequence -> $my_cache)
        builder
            .resolve_references(&cfg.plugins)
            .expect("resolve refs");

        // Get the sequence plugin and execute it
        let plugin = builder.get_plugin("seq").expect("sequence exists");
        let mut ctx = crate::plugin::Context::new(crate::dns::Message::new());
        plugin.execute(&mut ctx).await.expect("execute sequence");

        // Execution should succeed and the sequence plugin name is 'sequence'
        assert_eq!(plugin.name(), "sequence");
    }
}
