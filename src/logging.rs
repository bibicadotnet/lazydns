use crate::config::LogConfig;
use anyhow::Result;
use time::{format_description::well_known::Rfc3339, format_description::parse as parse_format, OffsetDateTime};
use once_cell::sync::OnceCell;
use std::fmt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static FILE_GUARD: OnceCell<tracing_appender::non_blocking::WorkerGuard> = OnceCell::new();

/// Custom formatter for time using `time_format` from config.
struct TimeFormatter {
    fmt: String,
}

impl TimeFormatter {
    fn new(fmt: impl Into<String>) -> Self {
        Self { fmt: fmt.into() }
    }
}

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

        // Normalize fractional seconds to fixed width (milliseconds, 3 digits) so logs
        // have consistent subsecond precision, e.g. ".926487" -> ".926" and
        // ".9266" -> ".926", while no fractional part becomes ".000".
        fn normalize_subsec(mut s: String, digits: usize) -> String {
            // Find 'T' to locate time part
            if let Some(tpos) = s.find('T') {
                // Search for timezone indicator ('+' or '-' or 'Z') after the 'T'
                let rest = &s[tpos..];
                let tz_rel = rest.find('+').or_else(|| rest.find('-')).or_else(|| rest.find('Z'));
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

        s = normalize_subsec(s, 3);
        w.write_str(&s)
    }
}

/// Initialize tracing/logging according to `LogConfig`.
/// Determine the effective log spec string used to build an `EnvFilter`.
///
/// Precedence: `RUST_LOG` env var (when set and non-empty) overrides the
/// provided `cfg.level` (which may already reflect a CLI `--log-level`).
pub(crate) fn effective_log_spec(cfg: &LogConfig) -> String {
    match std::env::var("RUST_LOG") {
        Ok(v) if !v.is_empty() => v,
        _ => cfg.level.clone(),
    }
}

pub fn init_logging(cfg: &LogConfig) -> Result<()> {
    // Build EnvFilter from effective spec
    let filter = EnvFilter::try_new(effective_log_spec(cfg))?;

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
        std::env::set_var("RUST_LOG", "trace");
        let cfg = LogConfig {
            level: "info".to_string(),
            ..Default::default()
        };

        assert_eq!(effective_log_spec(&cfg), "trace");

        std::env::remove_var("RUST_LOG");
    }

    #[test]
    fn cfg_level_used_when_no_rust_log() {
        std::env::remove_var("RUST_LOG");
        let cfg = LogConfig {
            level: "warn".to_string(),
            ..Default::default()
        };

        assert_eq!(effective_log_spec(&cfg), "warn");
    }
}
