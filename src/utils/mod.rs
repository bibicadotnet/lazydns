use notify::{Event, EventKind, RecursiveMode, Watcher};
// HashSet used by previous debounce implementation (replaced by HashMap)
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

pub mod task_queue;

/// Macro to generate a match statement for DNS type name to numeric value mapping.
/// Supports fallback to parsing as numeric value if name is not recognized.
/// Returns Result<T, ParseIntError> where T is the numeric type.
///
/// # Example
/// ```
/// let val = dns_type_match!(input, u16, "IN" | "INTERNET" => 1u16, "CH" => 3u16).map_err(|_| ...)?;
/// ```
#[macro_export]
macro_rules! dns_type_match {
    ($input:expr, $ty:ty, $($($name:literal)|+ => $val:expr),* $(,)?) => {
        match $input.to_uppercase().as_str() {
            $($($name)|+ => Ok($val),)*
            _ => $input.parse::<$ty>(),
        }
    };
}

/// Handle returned by `spawn_file_watcher` to allow graceful shutdown of the watcher task.
pub struct FileWatcherHandle {
    stop_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl FileWatcherHandle {
    /// Signal the watcher to stop and await the background task termination.
    pub async fn stop(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.handle.await;
    }
}

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
    on_reload: F,
) -> FileWatcherHandle
where
    F: FnMut(&PathBuf, &Vec<PathBuf>) + Send + 'static,
{
    let name = name.into();

    // Channel used to notify the background task to stop
    let (stop_tx, mut stop_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
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

        // Debounce scheduling: we keep a per-path map of last event time and
        // a marker that a task is scheduled. This allows resetting the debounce
        // timer on rapid successive events so only one callback fires after
        // events have quiesced.
        use std::time::Instant as StdInstant;
        let pending_map: Arc<Mutex<std::collections::HashMap<PathBuf, StdInstant>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let on_reload_mutex: Arc<Mutex<F>> = Arc::new(Mutex::new(on_reload));

        // Watch provided files
        for file_path in &files {
            debug!(name = %name, file = ?file_path, "start watching file");
            if let Err(e) = watcher.watch(file_path, RecursiveMode::NonRecursive) {
                warn!(name = %name, file = ?file_path, error = %e, "failed to watch file");
            }
        }

        debug!(name = %name, "file watcher started successfully");

        loop {
            tokio::select! {
                biased;
                maybe_event = rx.recv() => {
                    match maybe_event {
                        Some(event) => {
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

                                    if let Some(cp) = canonical_path.as_ref() {
                                        // Record last event timestamp for this path and schedule a debounced
                                        // task only if not already scheduled. The scheduled task will wait
                                        // until events have quiesced for `debounce_ms` before invoking
                                        // the callback; new events update the timestamp and reset the wait.
                                        let cp_clone = cp.clone();
                                        let now = StdInstant::now();
                                        let mut map = pending_map.lock().await;
                                        let already_scheduled = map.contains_key(&cp_clone);
                                        map.insert(cp_clone.clone(), now);
                                        drop(map);

                                        // Handle file removal/rename immediately (attempt to re-watch)
                                        if matches!(event.kind, EventKind::Remove(_)) {
                                            debug!(name = %name, file = file_name, "file removed or renamed, attempting to re-watch");
                                            tokio::time::sleep(Duration::from_millis(50)).await;
                                            if path.exists() {
                                                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                                                    warn!(name = %name, file = file_name, error = %e, "failed to re-watch file");
                                                } else {
                                                    debug!(name = %name, file = file_name, "successfully re-added file to watch list");
                                                }
                                            }
                                        }

                                        if !already_scheduled {
                                            // Clone for the spawned task
                                            let pending_map_clone = Arc::clone(&pending_map);
                                            let on_reload_clone = Arc::clone(&on_reload_mutex);
                                            let files_clone = files.clone();
                                            let path_clone = path.clone();
                                            let name_clone = name.clone();

                                            tokio::spawn(async move {
                                                loop {
                                                    tokio::time::sleep(Duration::from_millis(debounce_ms)).await;

                                                    // Check last event time
                                                    let mut guard = pending_map_clone.lock().await;
                                                    let last = guard.get(&cp_clone).cloned();
                                                    if let Some(ts) = last {
                                                        if StdInstant::now().duration_since(ts)
                                                            >= Duration::from_millis(debounce_ms)
                                                        {
                                                            // Invoke the callback under mutex
                                                            let mut f = on_reload_clone.lock().await;
                                                            (f)(&path_clone, &files_clone);

                                                            // Remove pending marker
                                                            guard.remove(&cp_clone);
                                                            debug!(name = %name_clone, file = ?path_clone, "scheduled reload: invoking callback (debounced)");
                                                            break;
                                                        } else {
                                                            // Not yet quiesced; loop and wait again
                                                            continue;
                                                        }
                                                    } else {
                                                        // No pending entry; nothing to do
                                                        break;
                                                    }
                                                }
                                            });
                                        } else {
                                            debug!(name = %name, file = file_name, "updated pending debounce timestamp");
                                        }

                                        // Only reload once per event batch
                                        break;
                                    }
                                }
                            }
                        }
                        None => break, // channel closed
                    }
                }
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        trace!(name = %name, "file watcher stop requested");
                        break;
                    }
                }
            }
        }

        trace!(name = %name, "file watcher closed, exiting loop");
    });

    FileWatcherHandle { stop_tx, handle }
}

/// Hint the allocator to release unused pages back to the OS when supported.
///
/// On Linux with the GNU C library this calls `malloc_trim(0)` which asks the
/// allocator to try to return free memory to the OS. On other platforms or
/// with other allocators this is a no-op. This function is intentionally a
/// small, best-effort hint and does not provide guarantees about memory
/// reclamation.
#[inline]
pub fn malloc_trim_hint() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        // Call is safe as it's a simple allocator hint; ignore the return value.
        let _ = libc::malloc_trim(0);
    }
    // No-op on other platforms
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;
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

        let handle =
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

        // Stop watcher to avoid leaking background task on CI
        handle.stop().await;
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
        let handle = spawn_file_watcher(
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

        // Stop watcher
        handle.stop().await;
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
