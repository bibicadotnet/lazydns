use crate::config::LogConfig;
use anyhow::Result;
use chrono::{DateTime, Local, Utc};
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
        let now: DateTime<Utc> = Utc::now();

        // Support local timezone formats:
        // - "local" -> local time in iso8601 with offset
        // - "custom_local:<fmt>" -> custom fmt applied to local time
        let s = if self.fmt == "iso8601" {
            now.to_rfc3339()
        } else if self.fmt == "timestamp" {
            now.timestamp().to_string()
        } else if self.fmt == "local" {
            // Use local timezone iso8601 representation
            Local::now().to_rfc3339()
        } else if let Some(rest) = self.fmt.strip_prefix("custom_local:") {
            Local::now().format(rest).to_string()
        } else if let Some(rest) = self.fmt.strip_prefix("custom:") {
            now.format(rest).to_string()
        } else {
            Local::now().to_rfc3339()
        };

        w.write_str(&s)
    }
}

/// Initialize tracing/logging according to `LogConfig`.
pub fn init_logging(cfg: &LogConfig) -> Result<()> {
    // EnvFilter: set from cfg.level
    let filter = EnvFilter::try_new(cfg.level.clone())?;

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
                        .as_ref()
                        .map(|s| s.as_str())
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
                        .as_ref()
                        .map(|s| s.as_str())
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
