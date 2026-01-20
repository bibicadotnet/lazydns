//! Unified audit plugin module
//!
//! Consolidates DNS query logging and security event auditing into a single plugin.
//!
//! # Features
//!
//! - **Query Logging**: Record DNS queries with optional response details
//! - **Sampling**: Reduce I/O by logging only a percentage of queries
//! - **Security Events**: Track rate limiting, blocked domains, upstream failures
//! - **Structured Output**: JSON format for SIEM integration
//! - **Async File I/O**: Non-blocking writes using tokio
//! - **Three Execution Modes**: QueryLog, Security, or Full
//!
//! # Configuration
//!
//! ```yaml
//! plugins:
//!   - tag: audit
//!     type: audit
//!     args:
//!       query_log:
//!         path: /var/log/lazydns/queries.log
//!         format: json
//!         sampling_rate: 1.0
//!       security_events:
//!         path: /var/log/lazydns/security.log
//!         enabled: true
//! ```

pub mod config;
pub mod event;
pub mod logger;
pub mod plugin;

// Public re-exports
pub use config::{AuditConfig, QueryLogConfig, SecurityEventConfig};
pub use event::{AuditEvent, QueryLogEntry, SecurityEventType};
pub use logger::{AUDIT_LOGGER, AuditLogger};
pub use plugin::AuditPlugin;
