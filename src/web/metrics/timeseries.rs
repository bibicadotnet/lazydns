//! Time series data structures for metrics aggregation
//!
//! Provides sliding window time series with configurable granularity.

use parking_lot::RwLock;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A single point in a time series
#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesPoint {
    /// Timestamp (seconds since start of collection)
    pub timestamp: u64,
    /// Value at this point
    pub value: f64,
}

/// Sliding window time series
#[derive(Debug)]
pub struct TimeSeries {
    /// Window duration
    window: Duration,
    /// Bucket duration (granularity)
    bucket_duration: Duration,
    /// Data points
    buckets: RwLock<VecDeque<Bucket>>,
    /// Start time
    start_time: Instant,
}

#[derive(Debug, Clone)]
struct Bucket {
    /// Bucket start time (relative to start_time)
    timestamp: u64,
    /// Sum of values in this bucket
    sum: f64,
    /// Count of values in this bucket
    count: u64,
    /// Minimum value
    min: f64,
    /// Maximum value
    max: f64,
}

impl Bucket {
    fn new(timestamp: u64) -> Self {
        Self {
            timestamp,
            sum: 0.0,
            count: 0,
            min: f64::MAX,
            max: f64::MIN,
        }
    }

    fn add(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    fn average(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }
}

impl TimeSeries {
    /// Create a new time series with window and bucket duration
    pub fn new(window: Duration, bucket_duration: Duration) -> Self {
        Self {
            window,
            bucket_duration,
            buckets: RwLock::new(VecDeque::new()),
            start_time: Instant::now(),
        }
    }

    /// Create with default 5-minute window and 1-second buckets
    pub fn default_qps() -> Self {
        Self::new(Duration::from_secs(300), Duration::from_secs(1))
    }

    /// Create with 1-hour window and 1-minute buckets
    pub fn hourly() -> Self {
        Self::new(Duration::from_secs(3600), Duration::from_secs(60))
    }

    /// Add a value to the current bucket
    pub fn add(&self, value: f64) {
        let now = self.current_bucket_timestamp();
        let mut buckets = self.buckets.write();

        // Clean up old buckets
        self.cleanup_locked(&mut buckets, now);

        // Find or create current bucket
        if let Some(last) = buckets.back_mut()
            && last.timestamp == now
        {
            last.add(value);
            return;
        }

        // Create new bucket
        let mut bucket = Bucket::new(now);
        bucket.add(value);
        buckets.push_back(bucket);
    }

    /// Increment the current bucket by 1
    pub fn increment(&self) {
        self.add(1.0);
    }

    /// Get current bucket timestamp
    fn current_bucket_timestamp(&self) -> u64 {
        let elapsed = self.start_time.elapsed();
        let bucket_secs = self.bucket_duration.as_secs();
        (elapsed.as_secs() / bucket_secs) * bucket_secs
    }

    /// Clean up old buckets (requires write lock)
    fn cleanup_locked(&self, buckets: &mut VecDeque<Bucket>, current_timestamp: u64) {
        let window_secs = self.window.as_secs();
        let cutoff = current_timestamp.saturating_sub(window_secs);

        while let Some(front) = buckets.front() {
            if front.timestamp < cutoff {
                buckets.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get all data points in the window
    pub fn points(&self) -> Vec<TimeSeriesPoint> {
        let now = self.current_bucket_timestamp();
        let buckets = self.buckets.read();

        buckets
            .iter()
            .filter(|b| b.timestamp <= now)
            .map(|b| TimeSeriesPoint {
                timestamp: b.timestamp,
                value: b.sum,
            })
            .collect()
    }

    /// Get average values for each bucket
    pub fn averages(&self) -> Vec<TimeSeriesPoint> {
        let now = self.current_bucket_timestamp();
        let buckets = self.buckets.read();

        buckets
            .iter()
            .filter(|b| b.timestamp <= now)
            .map(|b| TimeSeriesPoint {
                timestamp: b.timestamp,
                value: b.average(),
            })
            .collect()
    }

    /// Get the sum of all values in the window
    pub fn sum(&self) -> f64 {
        self.buckets.read().iter().map(|b| b.sum).sum()
    }

    /// Get the count of all values in the window
    pub fn count(&self) -> u64 {
        self.buckets.read().iter().map(|b| b.count).sum()
    }

    /// Get the current rate (sum per second over window)
    pub fn rate(&self) -> f64 {
        let sum = self.sum();
        let window_secs = self.window.as_secs() as f64;
        if window_secs > 0.0 {
            sum / window_secs
        } else {
            0.0
        }
    }

    /// Get min, max, and average over the window
    pub fn stats(&self) -> TimeSeriesStats {
        let buckets = self.buckets.read();

        if buckets.is_empty() {
            return TimeSeriesStats {
                min: 0.0,
                max: 0.0,
                avg: 0.0,
                sum: 0.0,
                count: 0,
            };
        }

        let mut total_sum = 0.0;
        let mut total_count = 0u64;
        let mut overall_min = f64::MAX;
        let mut overall_max = f64::MIN;

        for bucket in buckets.iter() {
            total_sum += bucket.sum;
            total_count += bucket.count;
            if bucket.count > 0 {
                overall_min = overall_min.min(bucket.min);
                overall_max = overall_max.max(bucket.max);
            }
        }

        TimeSeriesStats {
            min: if overall_min == f64::MAX {
                0.0
            } else {
                overall_min
            },
            max: if overall_max == f64::MIN {
                0.0
            } else {
                overall_max
            },
            avg: if total_count > 0 {
                total_sum / total_count as f64
            } else {
                0.0
            },
            sum: total_sum,
            count: total_count,
        }
    }

    /// Clear all data
    pub fn clear(&self) {
        self.buckets.write().clear();
    }
}

/// Statistics for a time series
#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesStats {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub sum: f64,
    pub count: u64,
}

/// Latency distribution buckets
#[derive(Debug)]
pub struct LatencyDistribution {
    /// Buckets: <1ms, 1-10ms, 10-50ms, 50-100ms, 100-500ms, 500ms-1s, >1s
    buckets: RwLock<[u64; 7]>,
}

impl LatencyDistribution {
    pub fn new() -> Self {
        Self {
            buckets: RwLock::new([0; 7]),
        }
    }

    /// Add a latency measurement in milliseconds
    pub fn add(&self, latency_ms: f64) {
        let bucket_idx = if latency_ms < 1.0 {
            0
        } else if latency_ms < 10.0 {
            1
        } else if latency_ms < 50.0 {
            2
        } else if latency_ms < 100.0 {
            3
        } else if latency_ms < 500.0 {
            4
        } else if latency_ms < 1000.0 {
            5
        } else {
            6
        };

        self.buckets.write()[bucket_idx] += 1;
    }

    /// Get distribution as labeled buckets
    pub fn distribution(&self) -> LatencyDistributionSnapshot {
        let buckets = *self.buckets.read();
        let total: u64 = buckets.iter().sum();

        LatencyDistributionSnapshot {
            buckets: vec![
                LatencyBucket {
                    label: "<1ms".to_string(),
                    count: buckets[0],
                    percentage: Self::pct(buckets[0], total),
                },
                LatencyBucket {
                    label: "1-10ms".to_string(),
                    count: buckets[1],
                    percentage: Self::pct(buckets[1], total),
                },
                LatencyBucket {
                    label: "10-50ms".to_string(),
                    count: buckets[2],
                    percentage: Self::pct(buckets[2], total),
                },
                LatencyBucket {
                    label: "50-100ms".to_string(),
                    count: buckets[3],
                    percentage: Self::pct(buckets[3], total),
                },
                LatencyBucket {
                    label: "100-500ms".to_string(),
                    count: buckets[4],
                    percentage: Self::pct(buckets[4], total),
                },
                LatencyBucket {
                    label: "500ms-1s".to_string(),
                    count: buckets[5],
                    percentage: Self::pct(buckets[5], total),
                },
                LatencyBucket {
                    label: ">1s".to_string(),
                    count: buckets[6],
                    percentage: Self::pct(buckets[6], total),
                },
            ],
            total,
        }
    }

    fn pct(count: u64, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            (count as f64 / total as f64) * 100.0
        }
    }

    /// Clear all data
    pub fn clear(&self) {
        *self.buckets.write() = [0; 7];
    }
}

impl Default for LatencyDistribution {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of latency distribution
#[derive(Debug, Clone, Serialize)]
pub struct LatencyDistributionSnapshot {
    pub buckets: Vec<LatencyBucket>,
    pub total: u64,
}

/// A single latency bucket
#[derive(Debug, Clone, Serialize)]
pub struct LatencyBucket {
    pub label: String,
    pub count: u64,
    pub percentage: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_series_add() {
        let ts = TimeSeries::new(Duration::from_secs(60), Duration::from_secs(1));
        ts.add(1.0);
        ts.add(2.0);
        ts.add(3.0);

        assert_eq!(ts.count(), 3);
        assert_eq!(ts.sum(), 6.0);
    }

    #[test]
    fn test_time_series_rate() {
        let ts = TimeSeries::new(Duration::from_secs(10), Duration::from_secs(1));
        for _ in 0..100 {
            ts.increment();
        }

        let rate = ts.rate();
        assert!((rate - 10.0).abs() < 0.1); // ~10 per second
    }

    #[test]
    fn test_latency_distribution() {
        let dist = LatencyDistribution::new();
        dist.add(0.5); // <1ms
        dist.add(5.0); // 1-10ms
        dist.add(25.0); // 10-50ms
        dist.add(75.0); // 50-100ms
        dist.add(200.0); // 100-500ms
        dist.add(750.0); // 500ms-1s
        dist.add(2000.0); // >1s

        let snapshot = dist.distribution();
        assert_eq!(snapshot.total, 7);
        assert_eq!(snapshot.buckets[0].count, 1);
        assert_eq!(snapshot.buckets[6].count, 1);
    }
}
