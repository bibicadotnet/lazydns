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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enqueue_error_display() {
        let already_processing = EnqueueError::AlreadyProcessing;
        assert_eq!(format!("{}", already_processing), "Already processing");

        let queue_full = EnqueueError::QueueFull;
        assert_eq!(format!("{}", queue_full), "Queue full");

        let closed = EnqueueError::Closed;
        assert_eq!(format!("{}", closed), "Coordinator closed");
    }

    #[test]
    fn test_enqueue_error_debug() {
        let error = EnqueueError::AlreadyProcessing;
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("AlreadyProcessing"));
    }

    #[test]
    fn test_enqueue_error_to_lazydns_error() {
        let error: Error = EnqueueError::AlreadyProcessing.into();
        assert!(matches!(error, Error::Plugin(_)));

        let error: Error = EnqueueError::QueueFull.into();
        assert!(matches!(error, Error::Plugin(_)));

        let error: Error = EnqueueError::Closed.into();
        assert!(matches!(error, Error::Plugin(_)));
    }

    #[test]
    fn test_enqueue_error_std_error() {
        use std::error::Error as StdError;

        let error = EnqueueError::AlreadyProcessing;
        // Ensure it implements std::error::Error
        let _: &dyn StdError = &error;
    }
}
