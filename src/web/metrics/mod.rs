//! Metrics collection and aggregation
//!
//! Collects and aggregates DNS query metrics for the WebUI dashboard.

pub mod collector;
pub mod timeseries;
pub mod top_n;

pub use collector::MetricsCollector;
pub use timeseries::{TimeSeries, TimeSeriesPoint};
pub use top_n::TopN;
