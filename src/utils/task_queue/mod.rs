//! Task queue system for background operations
//!
//! Provides a coordinated worker pool for handling background tasks with deduplication
//! and backpressure. Currently used for cache refresh operations, with design allowing
//! future extension to file reload and other asynchronous operations.

mod refresh_coordinator;
mod stats;
use crate::error::Error;
pub use refresh_coordinator::{RefreshCoordinator, RefreshTask};
pub use stats::RefreshStats;
use std::fmt::Display;

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

impl Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnqueueError::AlreadyProcessing => write!(f, "Already processing"),
            EnqueueError::QueueFull => write!(f, "Queue full"),
            EnqueueError::Closed => write!(f, "Coordinator closed"),
        }
    }
}

impl std::error::Error for EnqueueError {}

impl From<EnqueueError> for Error {
    fn from(e: EnqueueError) -> Self {
        match e {
            EnqueueError::AlreadyProcessing => {
                Error::Plugin("Refresh already in progress".to_string())
            }
            EnqueueError::QueueFull => Error::Plugin("Refresh queue full".to_string()),
            EnqueueError::Closed => Error::Plugin("Refresh coordinator closed".to_string()),
        }
    }
}
