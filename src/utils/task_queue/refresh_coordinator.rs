//! Refresh coordinator for background cache refresh operations
//!
//! Manages a worker pool to execute cache refresh tasks with:
//! - Deduplication (same key won't refresh twice concurrently)
//! - Bounded queue with backpressure
//! - Timeout protection
//! - Comprehensive statistics

use crate::dns::Message;
use crate::plugin::PluginHandler;
use crate::server::{Protocol, RequestContext, RequestHandler};
use dashmap::DashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use super::stats::RefreshStats;

/// Task to refresh a cache entry in the background
#[derive(Clone)]
pub struct RefreshTask {
    /// Cache key being refreshed
    pub key: String,
    /// DNS query message
    pub message: Message,
    /// Plugin handler to execute the query
    pub handler: Arc<PluginHandler>,
    /// Entry name for the handler
    pub entry_name: String,
    /// When this task was created
    pub created_at: Instant,
}

/// Coordinator for cache refresh operations
///
/// Design goals:
/// - Replace unbounded tokio::spawn with bounded worker pool
/// - Deduplicate concurrent refreshes for same key
/// - Provide backpressure when queue is full
/// - Track comprehensive statistics
///
/// Future extensibility:
/// - Can be generalized to handle file reload tasks
/// - Can support priority queues
/// - Can add adaptive worker scaling
pub struct RefreshCoordinator {
    /// Channel sender for enqueueing tasks
    tx: mpsc::Sender<RefreshTask>,
    /// Set of keys currently being processed (for deduplication)
    processing: Arc<DashSet<String>>,
    /// Statistics tracker
    stats: Arc<RefreshStats>,
}

impl RefreshCoordinator {
    /// Create a new refresh coordinator with worker pool
    ///
    /// # Arguments
    /// * `worker_count` - Number of background workers
    /// * `queue_capacity` - Maximum pending tasks in queue
    ///
    /// # Returns
    /// Self with running worker pool
    pub fn new(worker_count: usize, queue_capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(queue_capacity);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let processing = Arc::new(DashSet::new());
        let stats = Arc::new(RefreshStats::new());

        debug!(
            worker_count = worker_count,
            queue_capacity = queue_capacity,
            "Starting refresh coordinator worker pool"
        );

        // Spawn worker pool
        for worker_id in 0..worker_count {
            let rx_clone = Arc::clone(&rx);
            let processing_clone = Arc::clone(&processing);
            let stats_clone = Arc::clone(&stats);

            tokio::spawn(async move {
                Self::worker_loop(worker_id, rx_clone, processing_clone, stats_clone).await;
            });
        }

        Self {
            tx,
            processing,
            stats,
        }
    }

    /// Try to enqueue a refresh task
    ///
    /// # Deduplication
    /// If the same key is already being processed, the task is rejected with
    /// dedup_skipped counter incremented.
    ///
    /// # Backpressure
    /// If the queue is full, the task is rejected with rejected counter incremented.
    ///
    /// # Arguments
    /// * `task` - Refresh task to enqueue
    ///
    /// # Returns
    /// Ok(()) if enqueued successfully, Err if rejected
    pub async fn enqueue(&self, task: RefreshTask) -> Result<(), EnqueueError> {
        // Check if already processing this key
        if !self.processing.insert(task.key.clone()) {
            trace!(key = %task.key, "Refresh already in progress, skipping duplicate");
            self.stats.record_dedup_skipped();
            return Err(EnqueueError::AlreadyProcessing);
        }

        // Try to send to queue (non-blocking)
        let key_for_cleanup = task.key.clone();
        match self.tx.try_send(task) {
            Ok(_) => {
                self.stats.record_enqueued();
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Queue full, remove from processing set
                self.processing.remove(&key_for_cleanup);
                self.stats.record_rejected();
                warn!(
                    key = %key_for_cleanup,
                    queue_depth = self.stats.queue_depth(),
                    "Refresh queue full, rejecting task"
                );
                Err(EnqueueError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Channel closed (should not happen in normal operation)
                self.processing.remove(&key_for_cleanup);
                warn!("Refresh coordinator channel closed");
                Err(EnqueueError::Closed)
            }
        }
    }

    /// Get statistics reference
    pub fn stats(&self) -> Arc<RefreshStats> {
        Arc::clone(&self.stats)
    }

    /// Worker loop - processes tasks from queue
    async fn worker_loop(
        worker_id: usize,
        rx: Arc<tokio::sync::Mutex<mpsc::Receiver<RefreshTask>>>,
        processing: Arc<DashSet<String>>,
        stats: Arc<RefreshStats>,
    ) {
        trace!(worker_id = worker_id, "Refresh worker started");

        loop {
            // Lock receiver and wait for next task
            let task = {
                let mut rx_guard = rx.lock().await;
                rx_guard.recv().await
            };

            match task {
                Some(task) => {
                    let start = Instant::now();
                    let key = task.key.clone();
                    let queued_duration = start.duration_since(task.created_at);

                    trace!(
                        worker_id = worker_id,
                        key = %key,
                        queued_ms = queued_duration.as_millis(),
                        "Processing refresh task"
                    );

                    // Execute task with timeout
                    const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
                    let result =
                        tokio::time::timeout(REFRESH_TIMEOUT, Self::execute_task(&task)).await;

                    let duration = start.elapsed();
                    stats.record_processed();

                    match result {
                        Ok(Ok(_)) => {
                            stats.record_success();
                            debug!(
                                worker_id = worker_id,
                                key = %key,
                                duration_ms = duration.as_millis(),
                                "Refresh succeeded"
                            );
                        }
                        Ok(Err(e)) => {
                            stats.record_failed();
                            debug!(
                                worker_id = worker_id,
                                key = %key,
                                duration_ms = duration.as_millis(),
                                error = %e,
                                "Refresh failed"
                            );
                        }
                        Err(_) => {
                            stats.record_timeout();
                            warn!(
                                worker_id = worker_id,
                                key = %key,
                                timeout_secs = REFRESH_TIMEOUT.as_secs(),
                                "Refresh timeout"
                            );
                        }
                    }

                    // Remove from processing set
                    processing.remove(&key);
                }
                None => {
                    // Channel closed, worker exits
                    debug!(
                        worker_id = worker_id,
                        "Refresh worker stopping (channel closed)"
                    );
                    break;
                }
            }
        }

        trace!(worker_id = worker_id, "Refresh worker stopped");
    }

    /// Execute a single refresh task
    async fn execute_task(task: &RefreshTask) -> Result<(), String> {
        trace!(key = %task.key, "Executing refresh query");

        let ctx = RequestContext::new(task.message.clone(), Protocol::Udp);

        match task.handler.handle(ctx).await {
            Ok(response) => {
                if response.response_code() == crate::dns::ResponseCode::NoError {
                    trace!(key = %task.key, "Refresh query returned NoError");
                    Ok(())
                } else {
                    trace!(
                        key = %task.key,
                        rcode = ?response.response_code(),
                        "Refresh query returned error response"
                    );
                    Err(format!("Response code: {:?}", response.response_code()))
                }
            }
            Err(e) => {
                trace!(key = %task.key, error = %e, "Refresh query failed");
                Err(e.to_string())
            }
        }
    }
}

/// Errors that can occur when enqueueing a refresh task
#[derive(Debug)]
pub enum EnqueueError {
    /// Task for this key is already being processed
    AlreadyProcessing,
    /// Queue is full (backpressure)
    QueueFull,
    /// Coordinator channel closed (should not happen)
    Closed,
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnqueueError::AlreadyProcessing => write!(f, "Already processing"),
            EnqueueError::QueueFull => write!(f, "Queue full"),
            EnqueueError::Closed => write!(f, "Coordinator closed"),
        }
    }
}

impl std::error::Error for EnqueueError {}
