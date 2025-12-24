//! Logging utilities and initialization helpers.
//!
//! This module provides helpers to initialize the global `tracing` subscriber
//! according to the application's `LogConfig`. It supports JSON and plain
//! text output, optional file output with rotation, and timestamps via
//! `tracing-subscriber`'s `local-time` feature.

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

/// Initialize global logging according to the provided `LogConfig`.
///
/// This configures `tracing_subscriber` with an `EnvFilter` derived from
/// `effective_log_spec`, applies either JSON or human-readable formatting,
/// and optionally routes logs to a rotating file via `tracing-appender`.
/// Timestamps are handled by `tracing-subscriber`'s `local-time` feature.
/// When a file writer is created a background worker guard is stored in a
/// global `OnceCell` to keep the file appender alive for the process lifetime.
///
/// Returns `anyhow::Result<()>` to make initialization errors easy to
/// propagate from application startup.
#[cfg(feature = "tracing-subscriber")]
pub fn init_logging(cfg: &LogConfig, cli_verbose: Option<u8>) -> Result<()> {
    // Build EnvFilter from effective spec. If parsing fails (e.g., invalid RUST_LOG),
    // fall back to a conservative filter based on the configured level and log a warning.
    let spec = effective_log_spec(cfg, cli_verbose);
    let filter = match EnvFilter::try_new(spec.clone()) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, spec = %spec, "invalid log spec; falling back to config level");
            EnvFilter::new(format!("warn,lazydns={}", cfg.level))
        }
    };

    let registry = tracing_subscriber::registry().with(filter);

    if cfg.format == "json" {
        let mut layer = tracing_subscriber::fmt::layer().json();

        // When writing to a file, disable ANSI color codes
        if cfg.file.is_some() {
            layer = layer.with_ansi(false);
        }

        // Use local timezone formatter when possible; fall back to UTC if local offset unavailable
        let layer = match time::UtcOffset::current_local_offset() {
            Ok(offset) => {
                let timer = OffsetTime::new(offset, RFC3339_MS);
                layer.with_timer(timer)
            }
            Err(_) => {
                // Construct an explicit UTC rfc3339 OffsetTime fallback
                let fallback = OffsetTime::new(time::UtcOffset::UTC, RFC3339_MS);
                layer.with_timer(fallback)
            }
        };

        if let Some(path) = &cfg.file {
            #[cfg(feature = "log-file")]
            {
                match cfg.rotate.as_str() {
                    "daily" | "hourly" => {
                        let rotation_dir = cfg
                            .rotate_dir
                            .as_deref()
                            .or_else(|| {
                                std::path::Path::new(path).parent().and_then(|p| p.to_str())
                            })
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
            }

            #[cfg(not(feature = "log-file"))]
            {
                tracing::warn!(file = %path, "'log-file' feature not enabled; ignoring file logging configuration");
                let _ = registry.with(layer).try_init();
            }
        } else {
            let _ = registry.with(layer).try_init();
        }
    } else {
        let mut layer = tracing_subscriber::fmt::layer();

        // When writing to a file, disable ANSI color codes
        if cfg.file.is_some() {
            layer = layer.with_ansi(false);
        }

        // Use local timezone formatter when possible; fall back to UTC if local offset unavailable
        let layer = match time::UtcOffset::current_local_offset() {
            Ok(offset) => {
                let timer = OffsetTime::new(offset, RFC3339_MS);
                layer.with_timer(timer)
            }
            Err(_) => {
                // Construct an explicit UTC rfc3339 OffsetTime fallback
                let fallback = OffsetTime::new(time::UtcOffset::UTC, RFC3339_MS);
                layer.with_timer(fallback)
            }
        };

        if let Some(path) = &cfg.file {
            #[cfg(feature = "log-file")]
            {
                match cfg.rotate.as_str() {
                    "daily" | "hourly" => {
                        let rotation_dir = cfg
                            .rotate_dir
                            .as_deref()
                            .or_else(|| {
                                std::path::Path::new(path).parent().and_then(|p| p.to_str())
                            })
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
            }

            #[cfg(not(feature = "log-file"))]
            {
                tracing::warn!(file = %path, "'log-file' feature not enabled; ignoring file logging configuration");
                let _ = registry.with(layer).try_init();
            }
        } else {
            let _ = registry.with(layer).try_init();
        }
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
        // Preserve existing RUST_LOG and restore at the end to avoid
        // interfering with other tests running in parallel.
        let prev = std::env::var_os("RUST_LOG");
        unsafe {
            std::env::set_var("RUST_LOG", "trace");
        }
        let cfg = LogConfig {
            level: "info".to_string(),
            ..Default::default()
        };

        assert_eq!(effective_log_spec(&cfg, None), "trace");

        // Restore previous value
        unsafe {
            match prev {
                Some(v) => std::env::set_var("RUST_LOG", v),
                None => std::env::remove_var("RUST_LOG"),
            }
        }
    }

    #[test]
    fn cfg_level_used_when_no_rust_log() {
        // Preserve and remove RUST_LOG to ensure the default is used.
        let prev = std::env::var("RUST_LOG").ok();
        unsafe {
            std::env::set_var("RUST_LOG", "");
        }
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
        unsafe {
            match prev {
                Some(v) => std::env::set_var("RUST_LOG", v),
                None => std::env::remove_var("RUST_LOG"),
            }
        }
    }

    #[test]
    fn init_logging_ignores_file_when_feature_disabled() {
        // This test compiles and runs with default features (which do not include
        // `log-file`). When `cfg.file` is set but the feature is disabled, we
        // should not attempt to open files and initialization should succeed.
        let tmp_path = std::env::temp_dir().join("should_not_be_opened.log");
        let cfg = LogConfig {
            file: Some(tmp_path.to_string_lossy().to_string()),
            ..Default::default()
        };

        // If the feature is disabled this should return Ok without touching the filesystem.
        assert!(init_logging(&cfg, None).is_ok());
    }
}
