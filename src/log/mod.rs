//! Log module with rotation support.
//!
//! This module provides logging infrastructure with flexible rotation strategies:
//! - **Time-based**: Rotate daily or hourly with local timezone support
//! - **Size-based**: Rotate when file exceeds a size limit with numbered backups
//! - **Hybrid**: Rotate on whichever trigger fires first
//!
//! The module is designed to be potentially extractable as a standalone crate
//! (e.g., `lazylog`) for reuse in other projects.
//!
//! # Features
//!
//! - Local timezone support for time-based rotation
//! - Size tracking without syscall overhead
//! - Configurable file retention (max_files)
//! - Non-blocking async support via `tracing_appender`
//! - Serde-compatible configuration types
//!
//! # Example Configuration (YAML)
//!
//! ```yaml
//! logging:
//!   level: info
//!   console: true
//!   file:
//!     enabled: true
//!     path: /var/log/app/app.log
//!     rotation:
//!       type: both
//!       period: daily
//!       max_size: 10485760  # 10MB
//!       max_files: 5
//!       compress: false
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use lazydns::log::{init_logging, RotatingWriter, RotationTrigger, RotationPeriod};
//!
//! // Initialize logging from config
//! init_logging(&config.logging, None)?;
//!
//! // Or create a writer manually
//! let writer = RotatingWriter::new(
//!     "/var/log/app.log",
//!     RotationTrigger::both(RotationPeriod::Daily, 10 * 1024 * 1024, 5),
//! )?;
//! ```

mod rotation;
mod writer;

pub use rotation::{RotationPeriod, RotationTrigger};
pub use writer::RotatingWriter;

use crate::config::LogConfig;
use anyhow::Result;

#[cfg(feature = "tracing-subscriber")]
use tracing_subscriber::{
    EnvFilter, fmt::time::OffsetTime, layer::SubscriberExt, util::SubscriberInitExt,
};

/// Custom RFC3339 format with 3-digit subseconds (milliseconds).
#[cfg(feature = "tracing-subscriber")]
const RFC3339_MS: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3][offset_hour sign:mandatory]:[offset_minute]"
);

/// Guard to hold the background log file worker alive for the lifetime of the
/// process. The worker guard is stored in a `OnceCell` so it can be initialized
/// once during `init_logging` and retained to prevent log loss on shutdown.
#[cfg(feature = "log-file")]
static FILE_GUARD: once_cell::sync::OnceCell<tracing_appender::non_blocking::WorkerGuard> =
    once_cell::sync::OnceCell::new();

/// Compute the effective RUST_LOG-like spec string using precedence:
/// RUST_LOG (env) > CLI verbosity > config.level
///
/// Behavior:
/// - If RUST_LOG env var is present and non-empty, return it unchanged.
/// - If `cli_verbose` is Some(n):
///     * 0: return `warn,lazydns=<cfg_level>` (default suppress external crates)
///     * 1: return `warn,lazydns=debug`
///     * 2: return `warn,lazydns=trace`
///     * >=3: return `trace` (global trace -- include external crates)
/// - If no CLI override, default to `warn,lazydns=<cfg_level>` so external crates are quiet.
#[allow(dead_code)]
pub(crate) fn effective_log_spec(cfg: &LogConfig, cli_verbose: Option<u8>) -> String {
    // RUST_LOG always wins
    match std::env::var("RUST_LOG") {
        Ok(v) if !v.is_empty() => return v,
        _ => {}
    }

    if let Some(v) = cli_verbose {
        match v {
            0 => format!("warn,lazydns={}", cfg.level),
            1 => "warn,lazydns=debug".to_string(),
            2 => "warn,lazydns=trace".to_string(),
            _ => "trace".to_string(),
        }
    } else {
        // No CLI override: use config-level for lazydns but keep externals quiet
        format!("warn,lazydns={}", cfg.level)
    }
}

/// Create a local timezone timer for tracing-subscriber.
#[cfg(feature = "tracing-subscriber")]
fn create_timer() -> OffsetTime<&'static [time::format_description::FormatItem<'static>]> {
    match time::UtcOffset::current_local_offset() {
        Ok(offset) => OffsetTime::new(offset, RFC3339_MS),
        Err(_) => OffsetTime::new(time::UtcOffset::UTC, RFC3339_MS),
    }
}

/// Initialize global logging according to the provided `LogConfig`.
///
/// This configures `tracing_subscriber` with an `EnvFilter` derived from
/// `effective_log_spec`, applies either JSON or human-readable formatting,
/// and optionally routes logs to a rotating file.
///
/// # Arguments
///
/// * `cfg` - Logging configuration
/// * `cli_verbose` - Optional CLI verbosity level (from -v flags)
///
/// # Rotation Behavior
///
/// The new configuration format supports:
/// - `file.enabled`: Whether to enable file logging
/// - `file.path`: Path to the log file
/// - `file.rotation.type`: `time`, `size`, or `both`
/// - `file.rotation.period`: `daily` or `hourly` (for time-based)
/// - `file.rotation.max_size`: Maximum file size in bytes (for size-based)
/// - `file.rotation.max_files`: Number of rotated files to keep
///
/// # Legacy Support
///
/// For backward compatibility, the old `file` and `rotate` fields are still supported.
#[cfg(feature = "tracing-subscriber")]
pub fn init_logging(cfg: &LogConfig, cli_verbose: Option<u8>) -> Result<()> {
    // Build EnvFilter from effective spec
    let spec = effective_log_spec(cfg, cli_verbose);
    let filter = match EnvFilter::try_new(spec.clone()) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, spec = %spec, "invalid log spec; falling back to config level");
            EnvFilter::new(format!("warn,lazydns={}", cfg.level))
        }
    };

    let registry = tracing_subscriber::registry().with(filter);
    let timer = create_timer();

    // Determine if console output is enabled (default true)
    let console_enabled = cfg.console;

    // Determine file configuration
    let file_config = cfg.file.as_ref().filter(|f| f.enabled);

    // Build layers based on configuration
    if cfg.format == "json" {
        init_json_logging(registry, timer, console_enabled, file_config)?;
    } else {
        init_text_logging(registry, timer, console_enabled, file_config)?;
    }

    Ok(())
}

#[cfg(feature = "tracing-subscriber")]
fn init_json_logging<S>(
    registry: S,
    timer: OffsetTime<&'static [time::format_description::FormatItem<'static>]>,
    console_enabled: bool,
    file_config: Option<&crate::config::FileLogConfig>,
) -> Result<()>
where
    S: tracing::Subscriber
        + for<'span> tracing_subscriber::registry::LookupSpan<'span>
        + Send
        + Sync,
{
    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_timer(timer.clone());

    if let Some(file_cfg) = file_config {
        #[cfg(feature = "log-file")]
        {
            let trigger = file_cfg.rotation.clone();
            let writer = RotatingWriter::new(&file_cfg.path, trigger)?;
            let (non_blocking, guard) = tracing_appender::non_blocking(writer);
            let _ = FILE_GUARD.set(guard);

            let file_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_timer(timer.clone())
                .with_ansi(false)
                .with_writer(non_blocking);

            if console_enabled {
                let console_layer = tracing_subscriber::fmt::layer()
                    .json()
                    .with_timer(timer.clone())
                    .with_writer(std::io::stdout);
                let _ = registry.with(file_layer).with(console_layer).try_init();
            } else {
                let _ = registry.with(file_layer).try_init();
            }
        }

        #[cfg(not(feature = "log-file"))]
        {
            tracing::warn!(
                file = %file_cfg.path,
                "'log-file' feature not enabled; ignoring file logging configuration"
            );
            if console_enabled {
                let _ = registry.with(json_layer).try_init();
            } else {
                let _ = registry
                    .with(json_layer.with_writer(std::io::sink))
                    .try_init();
            }
        }
    } else if console_enabled {
        let _ = registry.with(json_layer).try_init();
    } else {
        // No console, no file - use sink
        let _ = registry
            .with(json_layer.with_writer(std::io::sink))
            .try_init();
    }

    Ok(())
}

#[cfg(feature = "tracing-subscriber")]
fn init_text_logging<S>(
    registry: S,
    timer: OffsetTime<&'static [time::format_description::FormatItem<'static>]>,
    console_enabled: bool,
    file_config: Option<&crate::config::FileLogConfig>,
) -> Result<()>
where
    S: tracing::Subscriber
        + for<'span> tracing_subscriber::registry::LookupSpan<'span>
        + Send
        + Sync,
{
    let text_layer = tracing_subscriber::fmt::layer().with_timer(timer.clone());

    if let Some(file_cfg) = file_config {
        #[cfg(feature = "log-file")]
        {
            let trigger = file_cfg.rotation.clone();
            let writer = RotatingWriter::new(&file_cfg.path, trigger)?;
            let (non_blocking, guard) = tracing_appender::non_blocking(writer);
            let _ = FILE_GUARD.set(guard);

            let file_layer = tracing_subscriber::fmt::layer()
                .with_timer(timer.clone())
                .with_ansi(false)
                .with_writer(non_blocking);

            if console_enabled {
                let console_layer = tracing_subscriber::fmt::layer()
                    .with_timer(timer.clone())
                    .with_writer(std::io::stdout);
                let _ = registry.with(file_layer).with(console_layer).try_init();
            } else {
                let _ = registry.with(file_layer).try_init();
            }
        }

        #[cfg(not(feature = "log-file"))]
        {
            tracing::warn!(
                file = %file_cfg.path,
                "'log-file' feature not enabled; ignoring file logging configuration"
            );
            if console_enabled {
                let _ = registry.with(text_layer).try_init();
            } else {
                let _ = registry
                    .with(text_layer.with_writer(std::io::sink))
                    .try_init();
            }
        }
    } else if console_enabled {
        let _ = registry.with(text_layer).try_init();
    } else {
        // No console, no file - use sink
        let _ = registry
            .with(text_layer.with_writer(std::io::sink))
            .try_init();
    }

    Ok(())
}

#[cfg(not(feature = "tracing-subscriber"))]
pub fn init_logging(_cfg: &LogConfig, _cli_verbose: Option<u8>) -> Result<()> {
    tracing::warn!("tracing-subscriber not enabled: logging initialization is a no-op");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogConfig;

    #[test]
    fn rust_log_overrides_config_level() {
        let prev = std::env::var_os("RUST_LOG");
        unsafe {
            std::env::set_var("RUST_LOG", "trace");
        }
        let cfg = LogConfig {
            level: "info".to_string(),
            ..Default::default()
        };

        assert_eq!(effective_log_spec(&cfg, None), "trace");

        unsafe {
            match prev {
                Some(v) => std::env::set_var("RUST_LOG", v),
                None => std::env::remove_var("RUST_LOG"),
            }
        }
    }

    #[test]
    fn cfg_level_used_when_no_rust_log() {
        let prev = std::env::var("RUST_LOG").ok();
        unsafe {
            std::env::set_var("RUST_LOG", "");
        }
        let cfg = LogConfig {
            level: "warn".to_string(),
            ..Default::default()
        };

        assert_eq!(effective_log_spec(&cfg, None), "warn,lazydns=warn");
        assert_eq!(effective_log_spec(&cfg, Some(1)), "warn,lazydns=debug");
        assert_eq!(effective_log_spec(&cfg, Some(2)), "warn,lazydns=trace");
        assert_eq!(effective_log_spec(&cfg, Some(3)), "trace");

        unsafe {
            if let Some(v) = prev {
                std::env::set_var("RUST_LOG", v);
            }
        }
    }

    #[test]
    fn init_logging_succeeds_with_defaults() {
        let cfg = LogConfig::default();
        // This may fail if logging is already initialized, but should not panic
        let _ = init_logging(&cfg, None);
    }
}
