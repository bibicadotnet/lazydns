//! Executable plugins for DNS query processing
//!
//! This module contains plugins that perform actions on DNS queries and responses.

pub mod arbitrary;
pub mod black_hole;
pub mod cache;
pub mod debug_print;
pub mod drop_resp;
pub mod dual_selector;
pub mod ecs_handler;
pub mod fallback;
pub mod forward_edns0opt;
pub mod ipset;
pub mod nftset;
pub mod query_summary;
pub mod redirect;
pub mod reverse_lookup;
pub mod ros_addrlist;
pub mod sequence;
pub mod sleep;
pub mod ttl;

pub use arbitrary::ArbitraryPlugin;
pub use black_hole::BlackholePlugin;
pub use cache::{ExecCache, ExecCacheStore};
pub use debug_print::DebugPrintPlugin;
pub use drop_resp::DropRespPlugin;
pub use dual_selector::{DualSelectorPlugin, IpPreference};
pub use ecs_handler::EcsHandler;
pub use fallback::FallbackPlugin;
pub use forward_edns0opt::{Edns0Option, ForwardEdns0OptPlugin};
pub use ipset::IpSetPlugin;
pub use nftset::NftSetPlugin;
pub use query_summary::QuerySummaryPlugin;
pub use redirect::RedirectPlugin;
pub use reverse_lookup::ReverseLookup;
pub use ros_addrlist::RosAddrListPlugin;
pub use sequence::SequencePlugin;
pub use sequence::SequenceStep;
pub use sleep::SleepPlugin;
pub use ttl::TtlPlugin;

pub mod hosts;
pub use hosts::HostsPlugin;
pub mod forward;
pub use forward::{ForwardPlugin, ForwardPluginBuilder};
