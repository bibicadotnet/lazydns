//! Rotation trigger types and configuration.
//!
//! This module defines the rotation policy types used by log writers.
//! It is designed to be reusable and could be extracted into a standalone crate.

use serde::{Deserialize, Serialize};

/// Time-based rotation period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RotationPeriod {
    /// Rotate logs daily (at midnight local time).
    #[default]
    Daily,
    /// Rotate logs hourly.
    Hourly,
    /// Never rotate based on time.
    Never,
}

impl RotationPeriod {
    /// Returns the time suffix format for the current period.
    #[cfg(feature = "log")]
    pub fn get_suffix(&self) -> String {
        let now =
            time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());

        match self {
            RotationPeriod::Daily => {
                format!(
                    "{:04}-{:02}-{:02}",
                    now.year(),
                    now.month() as u8,
                    now.day()
                )
            }
            RotationPeriod::Hourly => {
                format!(
                    "{:04}-{:02}-{:02}-{:02}",
                    now.year(),
                    now.month() as u8,
                    now.day(),
                    now.hour()
                )
            }
            RotationPeriod::Never => String::new(),
        }
    }

    /// Fallback implementation when `log` feature (and the `time` crate) is not enabled.
    /// Returns an empty string since time-based rotation is unavailable.
    #[cfg(not(feature = "log"))]
    pub fn get_suffix(&self) -> String {
        String::new()
    }
}

/// Rotation trigger policy.
///
/// Determines when log files should be rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RotationTrigger {
    /// Rotate based on time period only.
    Time {
        /// The time period for rotation.
        #[serde(default)]
        period: RotationPeriod,
    },
    /// Rotate based on file size only.
    Size {
        /// Maximum file size in bytes before rotation.
        #[serde(default = "default_max_size")]
        max_size: u64,
        /// Maximum number of rotated files to keep.
        #[serde(default = "default_max_files")]
        max_files: usize,
    },
    /// Rotate based on both time and size (whichever triggers first).
    Both {
        /// The time period for rotation.
        #[serde(default)]
        period: RotationPeriod,
        /// Maximum file size in bytes before rotation.
        #[serde(default = "default_max_size")]
        max_size: u64,
        /// Maximum number of rotated files to keep.
        #[serde(default = "default_max_files")]
        max_files: usize,
    },
    /// Never rotate logs.
    Never,
}

fn default_max_size() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

fn default_max_files() -> usize {
    5
}

impl Default for RotationTrigger {
    fn default() -> Self {
        RotationTrigger::Time {
            period: RotationPeriod::Daily,
        }
    }
}

impl RotationTrigger {
    /// Create a time-based rotation trigger.
    pub fn time(period: RotationPeriod) -> Self {
        RotationTrigger::Time { period }
    }

    /// Create a size-based rotation trigger.
    pub fn size(max_size: u64, max_files: usize) -> Self {
        RotationTrigger::Size {
            max_size,
            max_files,
        }
    }

    /// Create a hybrid rotation trigger (time + size).
    pub fn both(period: RotationPeriod, max_size: u64, max_files: usize) -> Self {
        RotationTrigger::Both {
            period,
            max_size,
            max_files,
        }
    }

    /// Get the maximum file size if configured.
    pub fn max_size(&self) -> Option<u64> {
        match self {
            RotationTrigger::Size { max_size, .. } | RotationTrigger::Both { max_size, .. } => {
                Some(*max_size)
            }
            _ => None,
        }
    }

    /// Get the maximum number of rotated files if configured.
    pub fn max_files(&self) -> Option<usize> {
        match self {
            RotationTrigger::Size { max_files, .. } | RotationTrigger::Both { max_files, .. } => {
                Some(*max_files)
            }
            _ => None,
        }
    }

    /// Get the rotation period if configured.
    pub fn period(&self) -> Option<RotationPeriod> {
        match self {
            RotationTrigger::Time { period } | RotationTrigger::Both { period, .. } => {
                Some(*period)
            }
            _ => None,
        }
    }

    /// Check if size-based rotation is enabled.
    pub fn has_size_rotation(&self) -> bool {
        matches!(
            self,
            RotationTrigger::Size { .. } | RotationTrigger::Both { .. }
        )
    }

    /// Check if time-based rotation is enabled.
    pub fn has_time_rotation(&self) -> bool {
        matches!(
            self,
            RotationTrigger::Time { period, .. } | RotationTrigger::Both { period, .. }
            if *period != RotationPeriod::Never
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "log")]
    #[test]
    fn test_rotation_period_suffix_daily() {
        let suffix = RotationPeriod::Daily.get_suffix();
        let parts: Vec<_> = suffix.split('-').collect();
        assert_eq!(parts.len(), 3);
        let year: i32 = parts[0].parse().unwrap();
        let month: u8 = parts[1].parse().unwrap();
        let day: u8 = parts[2].parse().unwrap();
        assert!(year >= 2000);
        assert!((1..=12).contains(&month));
        assert!((1..=31).contains(&day));
    }

    #[cfg(feature = "log")]
    #[test]
    fn test_rotation_period_suffix_hourly() {
        let suffix = RotationPeriod::Hourly.get_suffix();
        let parts: Vec<_> = suffix.split('-').collect();
        assert_eq!(parts.len(), 4);
        let hour: u8 = parts[3].parse().unwrap();
        assert!((0..=23).contains(&hour));
    }

    #[test]
    fn test_rotation_period_suffix_never() {
        let suffix = RotationPeriod::Never.get_suffix();
        assert!(suffix.is_empty());
    }

    #[test]
    fn test_rotation_trigger_defaults() {
        let trigger = RotationTrigger::default();
        assert!(trigger.has_time_rotation());
        assert!(!trigger.has_size_rotation());
    }

    #[test]
    fn test_rotation_trigger_size() {
        let trigger = RotationTrigger::size(1024 * 1024, 3);
        assert!(trigger.has_size_rotation());
        assert!(!trigger.has_time_rotation());
        assert_eq!(trigger.max_size(), Some(1024 * 1024));
        assert_eq!(trigger.max_files(), Some(3));
    }

    #[test]
    fn test_rotation_trigger_both() {
        let trigger = RotationTrigger::both(RotationPeriod::Hourly, 5 * 1024 * 1024, 10);
        assert!(trigger.has_size_rotation());
        assert!(trigger.has_time_rotation());
        assert_eq!(trigger.period(), Some(RotationPeriod::Hourly));
        assert_eq!(trigger.max_size(), Some(5 * 1024 * 1024));
        assert_eq!(trigger.max_files(), Some(10));
    }

    #[test]
    fn test_rotation_trigger_serde_time() {
        let yaml = r#"
type: time
period: daily
"#;
        let trigger: RotationTrigger = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            trigger,
            RotationTrigger::Time {
                period: RotationPeriod::Daily
            }
        ));
    }

    #[test]
    fn test_rotation_trigger_serde_size() {
        let yaml = r#"
type: size
max_size: 10485760
max_files: 5
"#;
        let trigger: RotationTrigger = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            trigger,
            RotationTrigger::Size {
                max_size: 10485760,
                max_files: 5
            }
        ));
    }

    #[test]
    fn test_rotation_trigger_serde_both() {
        let yaml = r#"
type: both
period: hourly
max_size: 5242880
max_files: 3
"#;
        let trigger: RotationTrigger = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            trigger,
            RotationTrigger::Both {
                period: RotationPeriod::Hourly,
                max_size: 5242880,
                max_files: 3
            }
        ));
    }
}
