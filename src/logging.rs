//! Logging utilities and initialization helpers.
//!
//! This module provides helpers to initialize the global `tracing` subscriber
//! according to the application's `LogConfig`. It supports JSON and plain
//! text output, optional file output with rotation, and configurable
//! timestamp formats (including custom `time` crate format descriptions).

use crate::config::LogConfig;
use anyhow::Result;
use once_cell::sync::OnceCell;
use std::fmt;
use time::{
    format_description::parse as parse_format, format_description::well_known::Rfc3339,
    OffsetDateTime,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Guard to hold the background log file worker alive for the lifetime of the
/// process. The worker guard is stored in a `OnceCell` so it can be initialized
/// once during `init_logging` and retained to prevent log loss on shutdown.
static FILE_GUARD: OnceCell<tracing_appender::non_blocking::WorkerGuard> = OnceCell::new();

/// Formatter used to render timestamps according to the configured
/// `time_format` value in `LogConfig`.
///
/// Supported formats:
/// - `iso8601`: UTC RFC3339 timestamps
/// - `timestamp`: unix seconds (UTC)
/// - `local`: local time in RFC3339
/// - `custom:<fmt>`: custom UTC format using `time` crate's format descriptions
/// - `custom_local:<fmt>`: custom local time format
struct TimeFormatter {
    fmt: String,
}

impl TimeFormatter {
    /// Create a new `TimeFormatter` with the given format string.
    ///
    /// The format value is interpreted as described on [`TimeFormatter`]:
    /// see module-level documentation for supported values.
    fn new(fmt: impl Into<String>) -> Self {
        Self { fmt: fmt.into() }
    }
}

/// Implementation of `tracing_subscriber`'s `FormatTime` trait.
///
/// Chooses the correct timestamp representation based on the configured
/// format string and emits a normalized timestamp to the provided writer.
impl tracing_subscriber::fmt::time::FormatTime for TimeFormatter {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        let now_utc = OffsetDateTime::now_utc();

        // Helper to format an OffsetDateTime with RFC3339
        let fmt_rfc3339 = |dt: &OffsetDateTime| match dt.format(&Rfc3339) {
            Ok(s) => s,
            Err(_) => "".to_string(),
        };

        // Support local timezone formats:
        // - "local" -> local time in iso8601 with offset
        // - "custom_local:<fmt>" -> custom fmt applied to local time
        let mut s = if self.fmt == "iso8601" {
            fmt_rfc3339(&now_utc)
        } else if self.fmt == "timestamp" {
            now_utc.unix_timestamp().to_string()
        } else if self.fmt == "local" {
            match OffsetDateTime::now_local() {
                Ok(local) => fmt_rfc3339(&local),
                Err(_) => fmt_rfc3339(&now_utc),
            }
        } else if let Some(rest) = self.fmt.strip_prefix("custom_local:") {
            match OffsetDateTime::now_local() {
                Ok(local) => match parse_format(rest) {
                    Ok(desc) => match local.format(&desc) {
                        Ok(s) => s,
                        Err(_) => fmt_rfc3339(&local),
                    },
                    Err(_) => fmt_rfc3339(&local),
                },
                Err(_) => fmt_rfc3339(&now_utc),
            }
        } else if let Some(rest) = self.fmt.strip_prefix("custom:") {
            match parse_format(rest) {
                Ok(desc) => match now_utc.format(&desc) {
                    Ok(s) => s,
                    Err(_) => fmt_rfc3339(&now_utc),
                },
                Err(_) => fmt_rfc3339(&now_utc),
            }
        } else {
            match OffsetDateTime::now_local() {
                Ok(local) => fmt_rfc3339(&local),
                Err(_) => fmt_rfc3339(&now_utc),
            }
        };

        // Normalize fractional seconds to fixed width (milliseconds, 3 digits)
        // by delegating to the module-level helper `normalize_subsec`.
        s = normalize_subsec(&s, 3);
        w.write_str(&s)
    }
}

/// Normalize fractional seconds in an RFC3339-like timestamp string to `digits`
/// precision (truncating or padding as necessary). If no fractional part is
/// present it will insert `.000...` with `digits` zeros. This helper is
/// extracted to make the behavior testable.
///
/// # Examples
/// ```rust,no_run
/// // Truncate to 3 digits
/// assert_eq!(lazydns::logging::normalize_subsec("2025-12-16T22:39:35.926487+08:00", 3),
///            "2025-12-16T22:39:35.926+08:00");
/// ```
/// Normalize fractional seconds in an RFC3339-like timestamp string to `digits`
/// precision (truncating or padding as necessary). If no fractional part is
/// present it will insert `.000...` with `digits` zeros. This helper is
/// extracted to make the behavior testable and is public so it can be used by
/// documentation tests and external tooling.
///
/// # Examples
/// ```rust
/// assert_eq!(lazydns::logging::normalize_subsec("2025-12-16T22:39:35.926487+08:00", 3),
///            "2025-12-16T22:39:35.926+08:00");
/// ```
pub fn normalize_subsec(s: &str, digits: usize) -> String {
    let mut s = s.to_string();

    // Find 'T' to locate time part
    if let Some(tpos) = s.find('T') {
        // Search for timezone indicator ('+' or '-' or 'Z') after the 'T'
        let rest = &s[tpos..];
        let tz_rel = rest
            .find('+')
            .or_else(|| rest.find('-'))
            .or_else(|| rest.find('Z'));
        if let Some(tz_rel) = tz_rel {
            let tz_idx = tpos + tz_rel;
            if let Some(dot_rel) = s[tpos..tz_idx].find('.') {
                let dot_idx = tpos + dot_rel;
                let frac = &s[dot_idx + 1..tz_idx];
                let mut frac_owned = frac.to_string();
                if frac_owned.len() > digits {
                    frac_owned.truncate(digits);
                } else {
                    while frac_owned.len() < digits {
                        frac_owned.push('0');
                    }
                }
                s.replace_range(dot_idx + 1..tz_idx, &frac_owned);
            } else {
                // No fractional part: insert .000... before tz
                let zeros = "0".repeat(digits);
                s.insert_str(tz_idx, &format!(".{}", zeros));
            }
        }
    }

    s
}

/// Determine the effective log specification string used to build an `EnvFilter`.
///
/// The environment variable `RUST_LOG`, when set and non-empty, takes
/// precedence over the configured `cfg.level`. This allows runtime
/// overrides without changing configuration files.
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

/// Initialize global logging according to the provided `LogConfig`.
///
/// This configures `tracing_subscriber` with an `EnvFilter` derived from
/// `effective_log_spec`, applies either JSON or human-readable formatting,
/// configures timestamp formatting via `TimeFormatter`, and optionally
/// routes logs to a rotating file. When a file writer is created a
/// background worker guard is stored in a global `OnceCell` to keep the
/// file appender alive for the process lifetime.
///
/// Returns `anyhow::Result<()>` to make initialization errors easy to
/// propagate from application startup.
pub fn init_logging(cfg: &LogConfig, cli_verbose: Option<u8>) -> Result<()> {
    // Build EnvFilter from effective spec
    let filter = EnvFilter::try_new(effective_log_spec(cfg, cli_verbose))?;

    let registry = tracing_subscriber::registry().with(filter);

    if cfg.format == "json" {
        let mut layer = tracing_subscriber::fmt::layer()
            .json()
            .with_timer(TimeFormatter::new(cfg.time_format.clone()));

        // When writing to a file, disable ANSI color codes
        if cfg.file.is_some() {
            layer = layer.with_ansi(false);
        }

        if let Some(path) = &cfg.file {
            match cfg.rotate.as_str() {
                "daily" | "hourly" => {
                    let rotation_dir = cfg
                        .rotate_dir
                        .as_deref()
                        .or_else(|| std::path::Path::new(path).parent().and_then(|p| p.to_str()))
                        .unwrap_or(".");

                    let file_name = std::path::Path::new(path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("log");

                    let rolling = if cfg.rotate == "daily" {
                        tracing_appender::rolling::daily(rotation_dir, file_name)
                    } else {
                        tracing_appender::rolling::hourly(rotation_dir, file_name)
                    };

                    let (non_blocking, guard) = tracing_appender::non_blocking(rolling);

                    let _ = FILE_GUARD.set(guard);
                    let _ = registry.with(layer.with_writer(non_blocking)).try_init();
                }
                _ => {
                    let file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?;

                    let (non_blocking, guard) = tracing_appender::non_blocking(file);
                    let _ = FILE_GUARD.set(guard);

                    let _ = registry.with(layer.with_writer(non_blocking)).try_init();
                }
            }
        } else {
            let _ = registry.with(layer).try_init();
        }
    } else {
        let mut layer = tracing_subscriber::fmt::layer()
            .with_timer(TimeFormatter::new(cfg.time_format.clone()));

        // When writing to a file, disable ANSI color codes
        if cfg.file.is_some() {
            layer = layer.with_ansi(false);
        }

        if let Some(path) = &cfg.file {
            match cfg.rotate.as_str() {
                "daily" | "hourly" => {
                    let rotation_dir = cfg
                        .rotate_dir
                        .as_deref()
                        .or_else(|| std::path::Path::new(path).parent().and_then(|p| p.to_str()))
                        .unwrap_or(".");

                    let file_name = std::path::Path::new(path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("log");

                    let rolling = if cfg.rotate == "daily" {
                        tracing_appender::rolling::daily(rotation_dir, file_name)
                    } else {
                        tracing_appender::rolling::hourly(rotation_dir, file_name)
                    };

                    let (non_blocking, guard) = tracing_appender::non_blocking(rolling);

                    let _ = FILE_GUARD.set(guard);
                    let _ = registry.with(layer.with_writer(non_blocking)).try_init();
                }
                _ => {
                    let file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?;

                    let (non_blocking, guard) = tracing_appender::non_blocking(file);
                    let _ = FILE_GUARD.set(guard);

                    let _ = registry.with(layer.with_writer(non_blocking)).try_init();
                }
            }
        } else {
            let _ = registry.with(layer).try_init();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogConfig;

    #[test]
    fn rust_log_overrides_config_level() {
        // Preserve existing RUST_LOG and restore at the end to avoid
        // interfering with other tests running in parallel.
        let prev = std::env::var_os("RUST_LOG");
        std::env::set_var("RUST_LOG", "trace");
        let cfg = LogConfig {
            level: "info".to_string(),
            ..Default::default()
        };

        assert_eq!(effective_log_spec(&cfg, None), "trace");

        // Restore previous value
        match prev {
            Some(v) => std::env::set_var("RUST_LOG", v),
            None => std::env::remove_var("RUST_LOG"),
        }
    }

    #[test]
    fn cfg_level_used_when_no_rust_log() {
        // Preserve and remove RUST_LOG to ensure the default is used.
        let prev = std::env::var_os("RUST_LOG");
        std::env::remove_var("RUST_LOG");
        let cfg = LogConfig {
            level: "warn".to_string(),
            ..Default::default()
        };

        assert_eq!(effective_log_spec(&cfg, None), "warn,lazydns=warn");

        // CLI verbosity 1 -> debug for lazydns with externals suppressed
        assert_eq!(effective_log_spec(&cfg, Some(1)), "warn,lazydns=debug");
        // CLI verbosity 2 -> trace for lazydns
        assert_eq!(effective_log_spec(&cfg, Some(2)), "warn,lazydns=trace");
        // CLI verbosity >=3 -> global trace (include external crates)
        assert_eq!(effective_log_spec(&cfg, Some(3)), "trace");

        // Restore previous value
        match prev {
            Some(v) => std::env::set_var("RUST_LOG", v),
            None => std::env::remove_var("RUST_LOG"),
        }
    }

    #[test]
    fn normalize_subsec_truncates_and_pads() {
        // Truncate to 3 digits
        let s = "2025-12-16T22:39:35.926487+08:00";
        assert_eq!(normalize_subsec(s, 3), "2025-12-16T22:39:35.926+08:00");

        // Truncate shorter fractional part
        let s2 = "2025-12-16T22:39:35.9266+08:00";
        assert_eq!(normalize_subsec(s2, 3), "2025-12-16T22:39:35.926+08:00");

        // Pad when too short
        let s3 = "2025-12-16T22:39:35.9+08:00";
        assert_eq!(normalize_subsec(s3, 3), "2025-12-16T22:39:35.900+08:00");

        // Insert when no fractional part
        let s4 = "2025-12-16T22:39:35+08:00";
        assert_eq!(normalize_subsec(s4, 3), "2025-12-16T22:39:35.000+08:00");

        // Works with 'Z' timezone
        let s5 = "2025-12-16T22:39:35.9Z";
        assert_eq!(normalize_subsec(s5, 3), "2025-12-16T22:39:35.900Z");

        // Unchanged if no 'T' time separator
        let s6 = "not-a-timestamp";
        assert_eq!(normalize_subsec(s6, 3), "not-a-timestamp");
    }
}
