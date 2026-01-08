//! Task queue system for background operations
//!
//! Provides a coordinated worker pool for handling background tasks with deduplication
//! and backpressure. Currently used for cache refresh operations, with design allowing
//! future extension to file reload and other asynchronous operations.

mod refresh_coordinator;
mod stats;

pub use refresh_coordinator::{RefreshCoordinator, RefreshTask};
pub use stats::RefreshStats;
