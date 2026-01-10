//! Log file writers with rotation support.
//!
//! This module provides writers that implement `std::io::Write` and support
//! various rotation strategies: time-based, size-based, or hybrid (both).
//!
//! The writers are designed to be used with `tracing_appender::non_blocking`
//! for high-performance async logging.

use super::rotation::{RotationPeriod, RotationTrigger};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Internal state for the current log file.
#[derive(Debug)]
struct FileState {
    /// The open file handle.
    file: File,
    /// Current file size in bytes (tracked to avoid metadata() calls).
    size: u64,
    /// Current time suffix (for time-based rotation detection).
    time_suffix: String,
}

/// A rotating log file writer supporting time, size, or hybrid rotation.
///
/// This writer implements `std::io::Write` and can be used with
/// `tracing_appender::non_blocking` for async logging.
///
/// # Rotation Behavior
///
/// - **Time-based**: Rotates to `{base}.YYYY-MM-DD` or `{base}.YYYY-MM-DD-HH`
/// - **Size-based**: Rotates to `{base}.1`, `{base}.2`, etc. with rename chain
/// - **Hybrid**: Rotates on whichever trigger fires first
///
/// # Example
///
/// ```ignore
/// use lazydns::log::{RotatingWriter, RotationTrigger, RotationPeriod};
///
/// let writer = RotatingWriter::new(
///     "/var/log/app.log",
///     RotationTrigger::both(RotationPeriod::Daily, 10 * 1024 * 1024, 5),
/// )?;
/// ```
pub struct RotatingWriter {
    /// Base path for the log file (without rotation suffix).
    base_path: PathBuf,
    /// Rotation trigger configuration.
    trigger: RotationTrigger,
    /// Current file state (file handle, size, time suffix).
    state: Arc<Mutex<Option<FileState>>>,
    /// Whether to compress rotated files (reserved for future use).
    #[allow(dead_code)]
    compress: bool,
}

impl RotatingWriter {
    /// Create a new rotating writer.
    ///
    /// # Arguments
    ///
    /// * `path` - Base path for the log file
    /// * `trigger` - Rotation trigger configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created.
    pub fn new(path: impl AsRef<Path>, trigger: RotationTrigger) -> io::Result<Self> {
        let base_path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = base_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
        }

        Ok(Self {
            base_path,
            trigger,
            state: Arc::new(Mutex::new(None)),
            compress: false,
        })
    }

    /// Create a new rotating writer with compression enabled.
    ///
    /// TODO: Compression is a placeholder for future implementation.
    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Get the current time suffix based on the rotation period.
    fn current_time_suffix(&self) -> String {
        match self.trigger.period() {
            Some(period) => period.get_suffix(),
            None => String::new(),
        }
    }

    /// Determine the actual file path for the current rotation.
    fn current_file_path(&self) -> PathBuf {
        let suffix = self.current_time_suffix();
        if suffix.is_empty() {
            self.base_path.clone()
        } else {
            // Time-based: append suffix like .2026-01-09
            let path_str = self.base_path.to_string_lossy();
            PathBuf::from(format!("{}.{}", path_str, suffix))
        }
    }

    /// Check if rotation is needed based on current state and buffer size.
    fn needs_rotation(&self, state: &FileState, buf_len: usize) -> bool {
        match &self.trigger {
            RotationTrigger::Never => false,
            RotationTrigger::Time { period } => {
                if *period == RotationPeriod::Never {
                    return false;
                }
                let current_suffix = period.get_suffix();
                current_suffix != state.time_suffix
            }
            RotationTrigger::Size { max_size, .. } => state.size + buf_len as u64 > *max_size,
            RotationTrigger::Both {
                period, max_size, ..
            } => {
                let time_trigger = if *period != RotationPeriod::Never {
                    period.get_suffix() != state.time_suffix
                } else {
                    false
                };
                let size_trigger = state.size + buf_len as u64 > *max_size;
                time_trigger || size_trigger
            }
        }
    }

    /// Perform size-based rotation with rename chain.
    ///
    /// Renames: base.log -> base.log.1 -> base.log.2 -> ... -> base.log.N (deleted)
    fn rotate_by_size(&self) -> io::Result<()> {
        let max_files = self.trigger.max_files().unwrap_or(5);
        let base = &self.base_path;

        // Delete the oldest file if it exists
        let oldest = PathBuf::from(format!("{}.{}", base.display(), max_files));
        if oldest.exists() {
            std::fs::remove_file(&oldest)?;
        }

        // Shift files: .N-1 -> .N, .N-2 -> .N-1, ..., .1 -> .2
        for i in (1..max_files).rev() {
            let from = PathBuf::from(format!("{}.{}", base.display(), i));
            let to = PathBuf::from(format!("{}.{}", base.display(), i + 1));
            if from.exists() {
                std::fs::rename(&from, &to)?;
            }
        }

        // Rename current file to .1
        if base.exists() {
            let first = PathBuf::from(format!("{}.1", base.display()));
            std::fs::rename(base, first)?;
        }

        Ok(())
    }

    /// Perform rotation and create a new file.
    fn rotate(&self) -> io::Result<FileState> {
        // For size-based rotation, perform the rename chain
        if self.trigger.has_size_rotation() {
            // Use base_path for size rotation (not time-suffixed path)
            self.rotate_by_size()?;
        }

        // Open/create the new file
        let file_path = self.current_file_path();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(FileState {
            file,
            size,
            time_suffix: self.current_time_suffix(),
        })
    }

    /// Get or create the current file, rotating if necessary.
    fn get_or_rotate(&self, buf_len: usize) -> io::Result<Arc<Mutex<Option<FileState>>>> {
        let mut guard = self.state.lock().unwrap();

        let needs_rotation = match &*guard {
            None => true,
            Some(state) => self.needs_rotation(state, buf_len),
        };

        if needs_rotation {
            // Close current file (drop it)
            *guard = None;

            // Perform rotation and create new file
            let new_state = self.rotate()?;
            *guard = Some(new_state);
        }

        Ok(Arc::clone(&self.state))
    }
}

impl Write for RotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let state_arc = self.get_or_rotate(buf.len())?;
        let mut guard = state_arc.lock().unwrap();

        if let Some(state) = guard.as_mut() {
            let written = state.file.write(buf)?;
            state.size += written as u64;
            Ok(written)
        } else {
            Err(io::Error::other("Failed to open log file"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let guard = self.state.lock().unwrap();
        if let Some(state) = guard.as_ref() {
            // We need interior mutability for flush, so we use a trick:
            // File::flush takes &mut self, but we can sync_all() on &File
            state.file.sync_all()
        } else {
            Ok(())
        }
    }
}

// Implement Send for use with non_blocking
unsafe impl Send for RotatingWriter {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(prefix: &str) -> PathBuf {
        let unique = format!(
            "{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(format!("lazydns_log_test_{}_{}", prefix, unique))
    }

    fn cleanup_dir(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_rotating_writer_creates_file() {
        let dir = unique_test_dir("create");
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("test.log");
        let mut writer =
            RotatingWriter::new(&log_path, RotationTrigger::Never).expect("create writer");

        writer.write_all(b"hello world\n").unwrap();
        writer.flush().unwrap();

        assert!(log_path.exists());
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("hello world"));

        cleanup_dir(&dir);
    }

    #[test]
    fn test_rotating_writer_size_rotation() {
        let dir = unique_test_dir("size");
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("test.log");
        // Very small max_size to trigger rotation quickly
        let mut writer =
            RotatingWriter::new(&log_path, RotationTrigger::size(50, 3)).expect("create writer");

        // Write enough to trigger rotation
        for i in 0..5 {
            writer
                .write_all(format!("line {} - some padding text here\n", i).as_bytes())
                .unwrap();
        }
        writer.flush().unwrap();

        // Check that rotated files exist
        assert!(log_path.exists(), "base log file should exist");
        let rotated_1 = dir.join("test.log.1");
        assert!(rotated_1.exists(), "test.log.1 should exist");

        cleanup_dir(&dir);
    }

    #[cfg(feature = "log")]
    #[test]
    fn test_rotating_writer_time_suffix() {
        let dir = unique_test_dir("time");
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("test.log");
        let mut writer = RotatingWriter::new(
            &log_path,
            RotationTrigger::Time {
                period: RotationPeriod::Daily,
            },
        )
        .expect("create writer");

        writer.write_all(b"hello\n").unwrap();
        writer.flush().unwrap();

        // Find the time-suffixed file
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();

        assert!(!entries.is_empty(), "should have created a log file");

        // Check that filename has date suffix
        let first = &entries[0];
        let name = first.file_name().to_string_lossy().to_string();
        assert!(
            name.starts_with("test.log."),
            "filename should have date suffix"
        );
        assert!(name.contains('-'), "filename should contain date separator");

        cleanup_dir(&dir);
    }

    #[test]
    fn test_rotating_writer_max_files_limit() {
        let dir = unique_test_dir("maxfiles");
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("test.log");
        // Very small size and only 2 max files
        let mut writer =
            RotatingWriter::new(&log_path, RotationTrigger::size(20, 2)).expect("create writer");

        // Write multiple times to trigger multiple rotations
        for i in 0..10 {
            writer
                .write_all(format!("line number {}\n", i).as_bytes())
                .unwrap();
        }
        writer.flush().unwrap();

        // Count log files
        let log_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("test.log"))
            .collect();

        // Should have at most max_files + 1 (current + rotated)
        assert!(
            log_files.len() <= 3,
            "should not exceed max_files limit, found {}",
            log_files.len()
        );

        cleanup_dir(&dir);
    }

    #[test]
    fn test_rotating_writer_hybrid() {
        let dir = unique_test_dir("hybrid");
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("test.log");
        let mut writer = RotatingWriter::new(
            &log_path,
            RotationTrigger::both(RotationPeriod::Daily, 50, 3),
        )
        .expect("create writer");

        // Write enough to trigger size rotation
        for i in 0..5 {
            writer
                .write_all(format!("line {} padding\n", i).as_bytes())
                .unwrap();
        }
        writer.flush().unwrap();

        // Should have created files
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();

        assert!(!entries.is_empty(), "should have created log files");

        cleanup_dir(&dir);
    }
}
