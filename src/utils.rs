use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Spawn a generic file watcher task.
///
/// - `name`: optional name used in logs
/// - `files`: list of files (PathBuf) to watch
/// - `debounce_ms`: debounce window in milliseconds to coalesce rapid events
/// - `on_reload`: callback invoked when a file change should trigger a reload; it receives the event path and the full files list
pub fn spawn_file_watcher<F>(
    name: impl Into<String>,
    files: Vec<PathBuf>,
    debounce_ms: u64,
    mut on_reload: F,
) where
    F: FnMut(&PathBuf, &Vec<PathBuf>) + Send + 'static,
{
    let name = name.into();

    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel(100);

        // Create watcher
        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<Event>| match res {
                Ok(event) => {
                    if matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                    ) {
                        let _ = tx.blocking_send(event);
                    }
                }
                Err(e) => {
                    error!("file watcher error: {:?}", e);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    error!(name = %name, error = %e, "failed to create file watcher");
                    return;
                }
            };

        // Canonicalize file paths for accurate comparison with event paths
        let canonical_files: Vec<PathBuf> =
            files.iter().filter_map(|p| p.canonicalize().ok()).collect();

        // Debounce state
        let mut last_reload: HashMap<PathBuf, Instant> = HashMap::new();

        // Watch provided files
        for file_path in &files {
            debug!(name = %name, file = ?file_path, "start watching file");
            if let Err(e) = watcher.watch(file_path, RecursiveMode::NonRecursive) {
                warn!(name = %name, file = ?file_path, error = %e, "failed to watch file");
            }
        }

        info!(name = %name, "file watcher started successfully");
        debug!(name = %name, "file watcher loop started");

        while let Some(event) = rx.recv().await {
            for path in &event.paths {
                let canonical_path = path.canonicalize().ok();
                if canonical_path
                    .as_ref()
                    .is_some_and(|cp| canonical_files.contains(cp))
                {
                    let file_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    // Debounce rapid reloads per-file
                    let now = Instant::now();
                    if let Some(cp) = canonical_path.as_ref() {
                        if let Some(prev) = last_reload.get(cp)
                            && now.duration_since(*prev) < Duration::from_millis(debounce_ms)
                        {
                            debug!(name = %name, file = file_name, "skipping reload due to debounce");
                            continue;
                        }
                        last_reload.insert(cp.clone(), now);
                    }

                    // Handle file removal/rename: attempt to re-watch
                    if matches!(event.kind, EventKind::Remove(_)) {
                        info!(name = %name, file = file_name, "file removed or renamed, attempting to re-watch");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if path.exists() {
                            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                                warn!(name = %name, file = file_name, error = %e, "failed to re-watch file");
                            } else {
                                info!(name = %name, file = file_name, "successfully re-added file to watch list");
                            }
                        }
                    }

                    // Notify caller to perform reload
                    info!(name = %name, file = file_name, "scheduled reload: invoking callback");
                    (on_reload)(path, &files);

                    // Only reload once per event batch
                    break;
                }
            }
        }

        debug!(name = %name, "file watcher closed, exiting loop");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::NamedTempFile;
    use tokio::sync::Notify;
    use tokio::time::{Duration, timeout};

    // Exposed for unit testing debounce logic without relying on filesystem events
    fn should_reload(
        last_reload: &mut HashMap<PathBuf, Instant>,
        cp: &PathBuf,
        debounce_ms: u64,
    ) -> bool {
        let now = Instant::now();
        if let Some(prev) = last_reload.get(cp)
            && now.duration_since(*prev) < Duration::from_millis(debounce_ms)
        {
            return false;
        }
        last_reload.insert(cp.clone(), now);
        true
    }

    #[tokio::test]
    async fn test_spawn_file_watcher_detects_change() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let counter = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());

        let c = Arc::clone(&counter);
        let n = Arc::clone(&notify);

        spawn_file_watcher("test-basic", vec![path.clone()], 100, move |_p, _files| {
            c.fetch_add(1, Ordering::SeqCst);
            n.notify_one();
        });

        // Give watcher a short moment to start watching; avoids races on CI
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Trigger a change by writing and syncing to ensure the event is emitted reliably
        {
            use std::fs::OpenOptions;
            use std::io::Write;

            let mut f = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&path)
                .unwrap();
            f.write_all(b"hello\n").unwrap();
            f.sync_all().unwrap();
        }

        // Wait for callback (increase timeout to accommodate slower CI / coverage runners)
        let res = timeout(Duration::from_secs(15), notify.notified()).await;
        assert!(res.is_ok(), "timeout waiting for file watcher callback");
        assert!(counter.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn test_spawn_file_watcher_debounce() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let counter = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());

        let c = Arc::clone(&counter);
        let n = Arc::clone(&notify);

        // Use debounce window 200ms
        spawn_file_watcher(
            "test-debounce",
            vec![path.clone()],
            200,
            move |_p, _files| {
                c.fetch_add(1, Ordering::SeqCst);
                n.notify_one();
            },
        );

        // Give watcher a short moment to start watching
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Trigger two quick successive changes by writing (replace content)
        std::fs::write(&path, b"one\n").unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&path, b"two\n").unwrap();

        // Wait for callback
        let res = timeout(Duration::from_secs(3), notify.notified()).await;
        assert!(res.is_ok(), "timeout waiting for debounce callback");

        // Allow some time for any additional callbacks (should be debounced)
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Counter should be 1 (or at least not >1 if debounce works)
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_should_reload_debounce_logic() {
        let mut last_reload: HashMap<PathBuf, Instant> = HashMap::new();
        let tmp = NamedTempFile::new().unwrap();
        let cp = tmp.path().to_path_buf();

        // First time should permit reload
        assert!(should_reload(&mut last_reload, &cp, 200));

        // Immediately should be debounced
        assert!(!should_reload(&mut last_reload, &cp, 200));

        // After waiting beyond debounce window, should permit reload again
        std::thread::sleep(Duration::from_millis(250));
        assert!(should_reload(&mut last_reload, &cp, 200));
    }
}
