//! Executable plugins for DNS query processing
//!
//! This module contains plugins that perform actions on DNS queries and responses.

pub mod arbitrary;
pub mod black_hole;
pub mod collector;
pub mod debug_print;
pub mod downloader;
pub mod drop_resp;
pub mod dual_selector;
pub mod ecs;
pub mod edns0opt;
pub mod fallback;
pub mod ipset;
pub mod nftset;
pub mod query_summary;
pub mod ratelimit;
pub mod redirect;
pub mod reverse_lookup;
pub mod ros_addrlist;
pub mod sequence;
pub mod sleep;
pub mod ttl;

pub use arbitrary::ArbitraryPlugin;
pub use black_hole::BlackholePlugin;
pub use collector::MetricsCollectorPlugin;
#[cfg(feature = "metrics")]
pub use collector::PromMetricsCollectorPlugin;
pub use debug_print::DebugPrintPlugin;
pub use downloader::DownloaderPlugin;
pub use drop_resp::DropRespPlugin;
pub use dual_selector::{DualSelectorPlugin, IpPreference};
pub use ecs::EcsPlugin;
pub use edns0opt::{Edns0OptPlugin, Edns0Option};
pub use fallback::FallbackPlugin;
pub use ipset::IpSetPlugin;
pub use nftset::NftSetPlugin;
pub use query_summary::QuerySummaryPlugin;
pub use ratelimit::RateLimitPlugin;
pub use redirect::RedirectPlugin;
pub use reverse_lookup::ReverseLookupPlugin;
pub use ros_addrlist::RosAddrlistPlugin;
pub use sequence::SequencePlugin;
pub use sequence::SequenceStep;
pub use sleep::SleepPlugin;
pub use ttl::TtlPlugin;

// Re-export builder initialization statics
#[allow(unused_imports)]
pub(crate) use crate::plugins::forward::FORWARD_PLUGIN_FACTORY;
