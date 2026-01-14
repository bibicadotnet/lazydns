//! cgroup memory reader for container-aware metrics
//!
//! Detects and reads cgroup v2 and v1 memory statistics for container environments.

use std::fs;
use std::io;
use std::path::Path;

/// cgroup memory statistics
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupMemoryStats {
    /// Current memory usage in bytes
    pub usage_bytes: u64,
    /// Memory limit in bytes (if set)
    pub limit_bytes: Option<u64>,
}

/// cgroup version detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    /// cgroup v2 (unified hierarchy)
    V2,
    /// cgroup v1 (legacy)
    V1,
}

/// Detect cgroup version and read memory statistics
///
/// Tries to detect cgroup v2 first (modern containers), then falls back to v1.
/// Returns None if not running in a cgroup or if reading fails.
///
/// # Example
///
/// ```no_run
/// # use lazydns::metrics::memory::cgroup_reader::read_cgroup_memory;
/// if let Some(stats) = read_cgroup_memory() {
///     println!("cgroup memory usage: {} bytes", stats.usage_bytes);
///     if let Some(limit) = stats.limit_bytes {
///         println!("cgroup memory limit: {} bytes", limit);
///     }
/// }
/// ```
pub fn read_cgroup_memory() -> Option<CgroupMemoryStats> {
    // Try cgroup v2 first (modern)
    if let Ok(stats) = read_cgroup_v2_memory() {
        return Some(stats);
    }

    // Fall back to cgroup v1
    read_cgroup_v1_memory().ok()
}

/// Read cgroup v2 memory statistics
///
/// Reads from /sys/fs/cgroup/memory.current and /sys/fs/cgroup/memory.max
fn read_cgroup_v2_memory() -> io::Result<CgroupMemoryStats> {
    let usage_bytes = fs::read_to_string("/sys/fs/cgroup/memory.current")?
        .trim()
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let limit_bytes = fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|content| {
            let trimmed = content.trim();
            // "max" means unlimited
            if trimmed == "max" {
                None
            } else {
                trimmed.parse::<u64>().ok()
            }
        });

    Ok(CgroupMemoryStats {
        usage_bytes,
        limit_bytes,
    })
}

/// Read cgroup v1 memory statistics
///
/// Reads from /sys/fs/cgroup/memory/memory.usage_in_bytes and
/// /sys/fs/cgroup/memory/memory.limit_in_bytes
fn read_cgroup_v1_memory() -> io::Result<CgroupMemoryStats> {
    let usage_bytes = fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")?
        .trim()
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let limit_bytes = fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        .ok()
        .and_then(|content| {
            let limit = content.trim().parse::<u64>().ok()?;
            // Very large values (near u64::MAX) typically mean unlimited
            // Common unlimited sentinel: 9223372036854771712 (0x7FFFFFFFFFFFF000)
            if limit > (1u64 << 60) {
                None
            } else {
                Some(limit)
            }
        });

    Ok(CgroupMemoryStats {
        usage_bytes,
        limit_bytes,
    })
}

/// Detect which cgroup version is in use
///
/// Returns V2 if /sys/fs/cgroup/memory.current exists (cgroup v2),
/// V1 if /sys/fs/cgroup/memory exists (cgroup v1),
/// or None if neither is detected.
pub fn detect_cgroup_version() -> Option<CgroupVersion> {
    if Path::new("/sys/fs/cgroup/memory.current").exists() {
        Some(CgroupVersion::V2)
    } else if Path::new("/sys/fs/cgroup/memory").exists() {
        Some(CgroupVersion::V1)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_version_enum() {
        // Basic enum test
        let v2 = CgroupVersion::V2;
        let v1 = CgroupVersion::V1;
        assert_ne!(v2, v1);
    }

    #[test]
    fn test_cgroup_memory_stats_default() {
        let stats = CgroupMemoryStats::default();
        assert_eq!(stats.usage_bytes, 0);
        assert_eq!(stats.limit_bytes, None);
    }

    // Integration tests only run on Linux with cgroups available
    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_cgroup_version_integration() {
        // This test may pass or fail depending on the environment
        // Just ensure it doesn't panic
        let version = detect_cgroup_version();
        if let Some(v) = version {
            println!("Detected cgroup version: {:?}", v);
        } else {
            println!("No cgroup detected (not running in container)");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_cgroup_memory_integration() {
        // This test attempts to read cgroup memory if available
        if let Some(stats) = read_cgroup_memory() {
            println!("cgroup memory usage: {} bytes", stats.usage_bytes);
            if let Some(limit) = stats.limit_bytes {
                println!("cgroup memory limit: {} bytes", limit);
            }
            // Basic sanity check
            assert!(stats.usage_bytes > 0, "Usage should be > 0 in container");
        } else {
            println!("Not running in cgroup, skipping test");
        }
    }
}
