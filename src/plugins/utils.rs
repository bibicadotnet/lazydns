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
                        if let Some(prev) = last_reload.get(cp) {
                            if now.duration_since(*prev) < Duration::from_millis(debounce_ms) {
                                debug!(name = %name, file = file_name, "skipping reload due to debounce");
                                continue;
                            }
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
