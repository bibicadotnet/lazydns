//! Statistics tracking for refresh coordinator

use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics for refresh task processing
#[derive(Debug, Default)]
pub struct RefreshStats {
    /// Total tasks enqueued successfully
    pub enqueued: AtomicU64,
    /// Total tasks processed to completion
    pub processed: AtomicU64,
    /// Tasks rejected due to full queue
    pub rejected: AtomicU64,
    /// Tasks skipped due to deduplication (already processing)
    pub dedup_skipped: AtomicU64,
    /// Tasks that succeeded
    pub success: AtomicU64,
    /// Tasks that failed
    pub failed: AtomicU64,
    /// Tasks that timed out
    pub timeout: AtomicU64,
}

impl RefreshStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record task enqueued
    pub fn record_enqueued(&self) {
        self.enqueued.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task rejected
    pub fn record_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task skipped due to deduplication
    pub fn record_dedup_skipped(&self) {
        self.dedup_skipped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task processed
    pub fn record_processed(&self) {
        self.processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task success
    pub fn record_success(&self) {
        self.success.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task failure
    pub fn record_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task timeout
    pub fn record_timeout(&self) {
        self.timeout.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total enqueued count
    pub fn total_enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    /// Get total processed count
    pub fn total_processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    /// Get total rejected count
    pub fn total_rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Get total skipped count
    pub fn total_dedup_skipped(&self) -> u64 {
        self.dedup_skipped.load(Ordering::Relaxed)
    }

    /// Get success count
    pub fn total_success(&self) -> u64 {
        self.success.load(Ordering::Relaxed)
    }

    /// Get failed count
    pub fn total_failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    /// Get timeout count
    pub fn total_timeout(&self) -> u64 {
        self.timeout.load(Ordering::Relaxed)
    }

    /// Calculate success rate (0.0 to 1.0)
    pub fn success_rate(&self) -> f64 {
        let processed = self.total_processed();
        if processed == 0 {
            0.0
        } else {
            self.total_success() as f64 / processed as f64
        }
    }

    /// Get queue depth (pending tasks)
    pub fn queue_depth(&self) -> u64 {
        let enqueued = self.total_enqueued();
        let processed = self.total_processed();
        let rejected = self.total_rejected();
        let skipped = self.total_dedup_skipped();

        enqueued.saturating_sub(processed + rejected + skipped)
    }
}
