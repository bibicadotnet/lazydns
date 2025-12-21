#![cfg(feature = "log-file")]

use lazydns::config::LogConfig;
use std::io::Read;
use std::time::Duration;

#[test]
fn test_file_logging_disables_ansi_text() {
    let tmp = tempfile::NamedTempFile::new().expect("temp file");
    let path = tmp.path().to_str().unwrap().to_string();

    let cfg = LogConfig {
        level: "info".to_string(),
        file: Some(path.clone()),
        format: "text".to_string(),
        time_format: "iso8601".to_string(),
        rotate: "never".to_string(),
        rotate_dir: None,
    };

    let filter = tracing_subscriber::EnvFilter::try_new(cfg.level.clone()).unwrap();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open file");

    let (non_blocking, guard) = tracing_appender::non_blocking(file);
    let mut builder = tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(non_blocking);
    if cfg.file.is_some() {
        builder = builder.with_ansi(false);
    }
    let subscriber = builder.finish();
    let boxed: Box<dyn tracing::Subscriber + Send + Sync> = Box::new(subscriber);
    let dispatch = tracing::Dispatch::new(boxed);

    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info!("file-logging-test: no-ansi");
    });

    // Give background worker a moment to write and flush
    std::thread::sleep(Duration::from_millis(200));
    drop(guard);

    let mut s = String::new();
    std::fs::File::open(&path)
        .expect("open log file")
        .read_to_string(&mut s)
        .expect("read log file");

    assert!(s.contains("file-logging-test: no-ansi"));
    assert!(!s.contains("\x1b"), "ANSI escape found in log file");
}

#[test]
fn test_file_logging_disables_ansi_json() {
    let tmp = tempfile::NamedTempFile::new().expect("temp file");
    let path = tmp.path().to_str().unwrap().to_string();

    let cfg = LogConfig {
        level: "info".to_string(),
        file: Some(path.clone()),
        format: "json".to_string(),
        time_format: "iso8601".to_string(),
        rotate: "never".to_string(),
        rotate_dir: None,
    };

    let filter = tracing_subscriber::EnvFilter::try_new(cfg.level.clone()).unwrap();

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open file");

    let (non_blocking, guard) = tracing_appender::non_blocking(file);
    let mut builder = tracing_subscriber::fmt::Subscriber::builder()
        .json()
        .with_env_filter(filter)
        .with_writer(non_blocking);
    if cfg.file.is_some() {
        builder = builder.with_ansi(false);
    }
    let subscriber = builder.finish();
    let boxed: Box<dyn tracing::Subscriber + Send + Sync> = Box::new(subscriber);
    let dispatch = tracing::Dispatch::new(boxed);

    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info!("file-logging-test-json: no-ansi-json");
    });

    std::thread::sleep(Duration::from_millis(200));
    drop(guard);

    let mut s = String::new();
    std::fs::File::open(&path)
        .expect("open log file")
        .read_to_string(&mut s)
        .expect("read log file");

    assert!(s.contains("file-logging-test-json: no-ansi-json"));
    assert!(!s.contains("\x1b"), "ANSI escape found in JSON log file");
}

#[test]
fn test_rolling_daily_creates_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_str = dir.path().to_str().unwrap().to_string();

    let cfg = LogConfig {
        level: "info".to_string(),
        file: Some("app.log".to_string()),
        format: "text".to_string(),
        time_format: "iso8601".to_string(),
        rotate: "daily".to_string(),
        rotate_dir: Some(dir_str.clone()),
    };

    let filter = tracing_subscriber::EnvFilter::try_new(cfg.level.clone()).unwrap();

    let rolling = tracing_appender::rolling::daily(&dir_str, "app.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(rolling);

    let mut builder = tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(non_blocking);

    if cfg.file.is_some() {
        builder = builder.with_ansi(false);
    }

    let subscriber = builder.finish();
    let boxed: Box<dyn tracing::Subscriber + Send + Sync> = Box::new(subscriber);
    let dispatch = tracing::Dispatch::new(boxed);

    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info!("rolling-test: hello");
    });

    std::thread::sleep(Duration::from_millis(200));
    drop(guard);

    // Look for files starting with `app.log` in the rotate dir
    let mut found = false;
    for entry in std::fs::read_dir(dir.path()).expect("read dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().into_string().unwrap_or_default();
        if name.starts_with("app.log") {
            let mut s = String::new();
            std::fs::File::open(entry.path())
                .expect("open rolling file")
                .read_to_string(&mut s)
                .expect("read rolling file");
            if s.contains("rolling-test: hello") {
                assert!(!s.contains("\x1b"));
                found = true;
                break;
            }
        }
    }

    assert!(found, "No rolling file with log content found");
}
