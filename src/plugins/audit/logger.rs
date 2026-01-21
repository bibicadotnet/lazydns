//! Audit logger implementation
//!
//! Provides async file-based audit logging with buffering and rotation.

use super::config::{AuditConfig, QueryLogConfig, SecurityEventConfig};
use super::event::{AuditEvent, QueryLogEntry, SecurityEventType};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Global audit logger instance
pub static AUDIT_LOGGER: Lazy<AuditLogger> = Lazy::new(AuditLogger::new);

/// Audit logger with async write support
pub struct AuditLogger {
    /// Configuration
    config: RwLock<Option<AuditConfig>>,

    /// Query log sender channel
    query_tx: RwLock<Option<mpsc::UnboundedSender<QueryLogEntry>>>,

    /// Security event sender channel
    security_tx: RwLock<Option<mpsc::UnboundedSender<AuditEvent>>>,

    /// Enabled security event types (empty = all)
    enabled_events: RwLock<HashSet<SecurityEventType>>,

    /// Sampling threshold (scaled to u64 range)
    sampling_threshold: AtomicU64,

    /// Statistics
    queries_logged: AtomicU64,
    queries_sampled_out: AtomicU64,
    security_events_logged: AtomicU64,
}

impl AuditLogger {
    /// Create a new disabled audit logger
    pub fn new() -> Self {
        Self {
            config: RwLock::new(None),
            query_tx: RwLock::new(None),
            security_tx: RwLock::new(None),
            enabled_events: RwLock::new(HashSet::new()),
            sampling_threshold: AtomicU64::new(u64::MAX), // 100% by default
            queries_logged: AtomicU64::new(0),
            queries_sampled_out: AtomicU64::new(0),
            security_events_logged: AtomicU64::new(0),
        }
    }

    /// Initialize the audit logger with configuration
    pub async fn init(&self, config: AuditConfig) -> crate::Result<()> {
        if !config.enabled {
            info!("Audit logging disabled");
            return Ok(());
        }

        info!("Initializing audit logger");

        // Set up query logging
        if let Some(ref query_config) = config.query_log {
            self.init_query_log(&config, query_config).await?;
        }

        // Set up security event logging
        if let Some(ref security_config) = config.security_events {
            self.init_security_log(&config, security_config).await?;
        }

        *self.config.write().await = Some(config);
        Ok(())
    }

    /// Initialize query logging
    async fn init_query_log(
        &self,
        audit_config: &AuditConfig,
        config: &QueryLogConfig,
    ) -> crate::Result<()> {
        debug!("Initializing query log with path: {}", config.path);

        // Create parent directories if needed
        if let Some(parent) = Path::new(&config.path).parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::Error::Config(format!(
                    "Failed to create query log directory {:?}: {}",
                    parent, e
                ))
            })?;
            debug!("Created query log directory: {:?}", parent);
        }

        // Set sampling threshold
        let threshold = if config.sampling_rate >= 1.0 {
            u64::MAX
        } else if config.sampling_rate <= 0.0 {
            0
        } else {
            (config.sampling_rate * u64::MAX as f64) as u64
        };
        self.sampling_threshold.store(threshold, Ordering::Relaxed);
        debug!("Set sampling threshold: {}", threshold);

        // Create channel for async writes
        let (tx, rx) = mpsc::unbounded_channel();
        *self.query_tx.write().await = Some(tx);
        debug!("Created query log channel");

        // Spawn writer task - inherit rotation parameters from audit config if not overridden
        let path = config.path.clone();
        let format = config.format.clone();
        let buffer_size = config.buffer_size.unwrap_or(audit_config.buffer_size);
        let max_file_size = config.max_file_size.unwrap_or(audit_config.max_file_size);
        let max_files = config.max_files.unwrap_or(audit_config.max_files);

        tokio::spawn(async move {
            debug!("Query log writer task started");
            query_log_writer(rx, path, format, buffer_size, max_file_size, max_files).await;
        });

        info!(
            path = %config.path,
            sampling_rate = config.sampling_rate,
            format = %config.format,
            "Query logging initialized"
        );

        Ok(())
    }

    /// Initialize security event logging
    async fn init_security_log(
        &self,
        audit_config: &AuditConfig,
        config: &SecurityEventConfig,
    ) -> crate::Result<()> {
        if !config.enabled {
            return Ok(());
        }

        // Create parent directories if needed
        if let Some(parent) = Path::new(&config.path).parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::Error::Config(format!(
                    "Failed to create security log directory {:?}: {}",
                    parent, e
                ))
            })?;
            debug!("Created security log directory: {:?}", parent);
        }

        // Parse enabled events
        let mut enabled = HashSet::new();
        for event_str in &config.events {
            if let Some(event_type) = SecurityEventType::parse(event_str) {
                enabled.insert(event_type);
            } else {
                warn!(event = %event_str, "Unknown security event type");
            }
        }
        *self.enabled_events.write().await = enabled;

        // Create channel for async writes
        let (tx, rx) = mpsc::unbounded_channel();
        *self.security_tx.write().await = Some(tx);

        // Spawn writer task - inherit rotation parameters from audit config if not overridden
        let path = config.path.clone();
        let buffer_size = config.buffer_size.unwrap_or(audit_config.buffer_size);
        let max_file_size = config.max_file_size.unwrap_or(audit_config.max_file_size);
        let max_files = config.max_files.unwrap_or(audit_config.max_files);

        tokio::spawn(async move {
            security_log_writer(rx, path, buffer_size, max_file_size, max_files).await;
        });

        info!(
            path = %config.path,
            events = ?config.events,
            "Security event logging initialized"
        );

        Ok(())
    }

    /// Check if audit logging is enabled
    pub async fn is_enabled(&self) -> bool {
        self.config.read().await.as_ref().is_some_and(|c| c.enabled)
    }

    /// Check if query logging is enabled
    pub async fn is_query_log_enabled(&self) -> bool {
        self.query_tx.read().await.is_some()
    }

    /// Check if a query should be logged (based on sampling)
    pub fn should_sample(&self) -> bool {
        let threshold = self.sampling_threshold.load(Ordering::Relaxed);
        if threshold == u64::MAX {
            return true;
        }
        if threshold == 0 {
            return false;
        }

        // Use random sampling (use thread-local RNG to avoid recreating RNG per call)
        let sample: u64 = rand::random::<u64>();
        sample <= threshold
    }

    /// Log a DNS query
    pub async fn log_query(&self, entry: QueryLogEntry) {
        // Check sampling
        if !self.should_sample() {
            self.queries_sampled_out.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let tx_lock = self.query_tx.read().await;
        if let Some(ref tx) = *tx_lock {
            if tx.send(entry).is_ok() {
                self.queries_logged.fetch_add(1, Ordering::Relaxed);
                trace!("Query logged successfully");
            } else {
                error!("Failed to send query to channel");
            }
        } else {
            error!("Query channel not initialized!");
        }
    }

    /// Log a security event
    pub async fn log_security(&self, event: AuditEvent) {
        // Check if security logging is enabled
        let tx_lock = self.security_tx.read().await;
        if tx_lock.is_none() {
            // Security logging not configured
            return;
        }

        // Check if this event type is enabled
        if let AuditEvent::Security { event_type, .. } = &event {
            let enabled = self.enabled_events.read().await;
            // If enabled set is not empty, check if this event is in it
            // If enabled set is empty, log all events (no filtering)
            if !enabled.is_empty() && !enabled.contains(event_type) {
                return;
            }
        }

        if let Some(ref tx) = *tx_lock {
            if tx.send(event).is_err() {
                error!("Failed to send security event to channel");
            } else {
                self.security_events_logged.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Log a security event (convenience method)
    pub async fn log_security_event(
        &self,
        event_type: SecurityEventType,
        message: impl Into<String>,
        client_ip: Option<std::net::IpAddr>,
        qname: Option<String>,
    ) {
        // Respect include_client_ip setting from configuration: if the audit config
        // disables including client IP, omit it from the recorded event.
        let include_ip = {
            if let Some(cfg) = self.config.read().await.as_ref() {
                cfg.query_log
                    .as_ref()
                    .map(|q| q.include_client_ip)
                    .unwrap_or(true)
            } else {
                true
            }
        };

        let ip_to_use = if include_ip { client_ip } else { None };

        let event = AuditEvent::security_with_client(event_type, message, ip_to_use, qname);
        self.log_security(event).await;
    }

    /// Get statistics
    pub fn stats(&self) -> AuditStats {
        AuditStats {
            queries_logged: self.queries_logged.load(Ordering::Relaxed),
            queries_sampled_out: self.queries_sampled_out.load(Ordering::Relaxed),
            security_events_logged: self.security_events_logged.load(Ordering::Relaxed),
        }
    }

    /// Shutdown the audit logger
    pub async fn shutdown(&self) {
        // Drop senders to signal writers to stop
        *self.query_tx.write().await = None;
        *self.security_tx.write().await = None;
        *self.config.write().await = None;

        info!(
            queries = self.queries_logged.load(Ordering::Relaxed),
            sampled_out = self.queries_sampled_out.load(Ordering::Relaxed),
            security_events = self.security_events_logged.load(Ordering::Relaxed),
            "Audit logger shutdown"
        );
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Audit statistics
#[derive(Debug, Clone, Default)]
pub struct AuditStats {
    pub queries_logged: u64,
    pub queries_sampled_out: u64,
    pub security_events_logged: u64,
}

/// Background task for writing query logs
async fn query_log_writer(
    mut rx: mpsc::UnboundedReceiver<QueryLogEntry>,
    path: String,
    format: String,
    buffer_size: usize,
    max_file_size: u64,
    max_files: u32,
) {
    debug!("Query log writer task started for path: {}", path);

    let mut buffer: Vec<QueryLogEntry> = Vec::with_capacity(buffer_size);
    let use_json = format == "json";

    loop {
        tokio::select! {
            entry = rx.recv() => {
                match entry {
                    Some(entry) => {
                        trace!("Received query log entry: {:?}", entry.qname);
                        buffer.push(entry);
                        if buffer.len() >= buffer_size {
                            debug!("Buffer full ({} entries), flushing", buffer.len());
                            flush_query_buffer(&mut buffer, &path, use_json, max_file_size, max_files);
                        }
                    }
                    None => {
                        // Channel closed, flush remaining and exit
                        if !buffer.is_empty() {
                            debug!("Channel closed, flushing {} remaining entries", buffer.len());
                            flush_query_buffer(&mut buffer, &path, use_json, max_file_size, max_files);
                        }
                        break;
                    }
                }
            }
            // Periodic flush every 5 seconds
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                if !buffer.is_empty() {
                    debug!("Periodic flush: flushing {} entries", buffer.len());
                    flush_query_buffer(&mut buffer, &path, use_json, max_file_size, max_files);
                }
            }
        }
    }

    debug!("Query log writer stopped");
}

/// Flush query log buffer to file
fn flush_query_buffer(
    buffer: &mut Vec<QueryLogEntry>,
    path: &str,
    use_json: bool,
    max_file_size: u64,
    max_files: u32,
) {
    debug!("Flushing {} query entries to {}", buffer.len(), path);

    // Ensure parent directory exists (in case it was deleted during runtime)
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        let _ = std::fs::create_dir_all(parent);
    }

    // Check if rotation needed
    if let Ok(metadata) = std::fs::metadata(path)
        && metadata.len() >= max_file_size
    {
        rotate_log_file(path, max_file_size, max_files);
    }

    // Open file for append
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => {
            debug!("Opened query log file: {}", path);
            f
        }
        Err(e) => {
            error!(path = %path, error = %e, "Failed to open query log file");
            buffer.clear();
            return;
        }
    };

    let mut writer = std::io::BufWriter::new(file);

    let mut written = 0;
    for entry in buffer.drain(..) {
        let line = if use_json {
            match entry.to_json() {
                Ok(json) => json,
                Err(e) => {
                    error!(error = %e, "Failed to serialize query log entry");
                    continue;
                }
            }
        } else {
            entry.to_text()
        };

        if let Err(e) = writeln!(writer, "{}", line) {
            error!(error = %e, "Failed to write query log entry");
        } else {
            written += 1;
        }
    }

    debug!("Wrote {} entries to buffer", written);

    if let Err(e) = writer.flush() {
        error!(error = %e, "Failed to flush query log");
    } else {
        debug!("Query log buffer flushed successfully");
    }
}

/// Background task for writing security logs
async fn security_log_writer(
    mut rx: mpsc::UnboundedReceiver<AuditEvent>,
    path: String,
    buffer_size: usize,
    max_file_size: u64,
    max_files: u32,
) {
    let mut buffer = Vec::with_capacity(buffer_size);
    let mut accumulated_size: u64 = 0;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                if let Ok(json) = event.to_json() {
                    let event_size = json.len() as u64 + 1; // +1 for newline
                    buffer.push(json);
                    accumulated_size += event_size;

                    // Flush if buffer reaches size limit
                    if buffer.len() >= buffer_size {
                        flush_security_buffer(&path, &mut buffer, max_file_size, max_files, &mut accumulated_size);
                    }
                } else {
                    error!("Failed to serialize security event");
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                // Periodic flush
                if !buffer.is_empty() {
                    flush_security_buffer(&path, &mut buffer, max_file_size, max_files, &mut accumulated_size);
                }
            }
        }
    }
}

/// Flush security event buffer to file
fn flush_security_buffer(
    path: &str,
    buffer: &mut Vec<String>,
    max_file_size: u64,
    max_files: u32,
    accumulated_size: &mut u64,
) {
    if buffer.is_empty() {
        return;
    }

    // Check file size before writing
    if let Ok(metadata) = std::fs::metadata(path) {
        let current_size = metadata.len();
        if current_size + *accumulated_size > max_file_size && current_size > 0 {
            // Need to rotate
            rotate_log_file(path, max_file_size, max_files);
            *accumulated_size = 0;
        }
    }

    // Ensure parent directory exists
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        let _ = std::fs::create_dir_all(parent);
    }

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            error!(path = %path, error = %e, "Failed to open security log file");
            buffer.clear();
            *accumulated_size = 0;
            return;
        }
    };

    let mut writer = std::io::BufWriter::new(file);
    for json in buffer.drain(..) {
        if let Err(e) = writeln!(writer, "{}", json) {
            error!(error = %e, "Failed to write security event");
        }
    }

    *accumulated_size = 0;
}

/// Rotate log files (simple numbered rotation)
/// Checks file size and rotates if needed
fn rotate_log_file(path: &str, _max_file_size: u64, max_files: u32) {
    // Delete oldest file if at limit
    let oldest = format!("{}.{}", path, max_files);
    let _ = std::fs::remove_file(&oldest);

    // Shift existing files
    for i in (1..max_files).rev() {
        let from = format!("{}.{}", path, i);
        let to = format!("{}.{}", path, i + 1);
        let _ = std::fs::rename(&from, &to);
    }

    // Rename current file to .1
    let first = format!("{}.1", path);
    if let Err(e) = std::fs::rename(path, &first) {
        warn!(path = %path, error = %e, "Failed to rotate log file");
    } else {
        info!(path = %path, "Rotated log file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_audit_logger_new() {
        let logger = AuditLogger::new();
        let stats = logger.stats();
        assert_eq!(stats.queries_logged, 0);
        assert_eq!(stats.security_events_logged, 0);
    }

    #[test]
    fn test_should_sample_100_percent() {
        let logger = AuditLogger::new();
        // Default is 100% sampling
        for _ in 0..100 {
            assert!(logger.should_sample());
        }
    }

    #[test]
    fn test_should_sample_0_percent() {
        let logger = AuditLogger::new();
        logger.sampling_threshold.store(0, Ordering::Relaxed);
        for _ in 0..100 {
            assert!(!logger.should_sample());
        }
    }

    #[tokio::test]
    async fn test_audit_logger_disabled() {
        let logger = AuditLogger::new();
        let config = AuditConfig::default();
        logger.init(config).await.unwrap();
        assert!(!logger.is_enabled().await);
    }

    #[tokio::test]
    async fn test_audit_logger_query_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("queries.log");

        let logger = AuditLogger::new();
        let config = AuditConfig {
            enabled: true,
            buffer_size: 100,
            max_file_size: 100 * 1024 * 1024,
            max_files: 10,
            query_log: Some(QueryLogConfig {
                path: path.to_string_lossy().to_string(),
                format: "json".into(),
                sampling_rate: 1.0,
                ..Default::default()
            }),
            security_events: None,
        };

        logger.init(config).await.unwrap();
        assert!(logger.is_query_log_enabled().await);

        // Log a query
        let entry = QueryLogEntry::new(1234, "udp", "example.com".into(), "A".into(), "IN".into());
        logger.log_query(entry).await;

        // Give writer time to flush
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let stats = logger.stats();
        assert_eq!(stats.queries_logged, 1);

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn test_audit_logger_security_event() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("security.log");

        let logger = AuditLogger::new();
        let config = AuditConfig {
            enabled: true,
            buffer_size: 100,
            max_file_size: 100 * 1024 * 1024,
            max_files: 10,
            query_log: None,
            security_events: Some(SecurityEventConfig {
                enabled: true,
                path: path.to_string_lossy().to_string(),
                events: vec![], // all events
                ..Default::default()
            }),
        };

        logger.init(config).await.unwrap();

        // Log a security event
        logger
            .log_security_event(
                SecurityEventType::RateLimitExceeded,
                "Test rate limit",
                None,
                Some("example.com".into()),
            )
            .await;

        // Give writer time
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let stats = logger.stats();
        assert_eq!(stats.security_events_logged, 1);

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn test_audit_logger_filtered_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("security.log");

        let logger = AuditLogger::new();
        let config = AuditConfig {
            enabled: true,
            buffer_size: 100,
            max_file_size: 100 * 1024 * 1024,
            max_files: 10,
            query_log: None,
            security_events: Some(SecurityEventConfig {
                enabled: true,
                path: path.to_string_lossy().to_string(),
                events: vec!["rate_limit_exceeded".into()], // only this event
                ..Default::default()
            }),
        };

        logger.init(config).await.unwrap();

        // Log allowed event
        logger
            .log_security_event(SecurityEventType::RateLimitExceeded, "Test", None, None)
            .await;

        // Log filtered event (should be ignored)
        logger
            .log_security_event(SecurityEventType::BlockedDomainQuery, "Test", None, None)
            .await;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let stats = logger.stats();
        assert_eq!(stats.security_events_logged, 1);

        logger.shutdown().await;
    }
}
