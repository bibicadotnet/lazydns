//! Control flow plugins collection (split files)
//!
//! This module contains control-flow related plugins split into separate files.

pub mod accept;
pub mod goto;
pub mod if_plugin;
pub mod jump;
pub mod parallel;
pub mod prefer_ipv4;
pub mod prefer_ipv6;
pub mod reject;
pub mod return_plugin;

pub use accept::AcceptPlugin;
pub use goto::GotoPlugin;
pub use if_plugin::IfPlugin;
pub use jump::JumpPlugin;
pub use parallel::ParallelPlugin;
pub use prefer_ipv4::PreferIpv4Plugin;
pub use prefer_ipv6::PreferIpv6Plugin;
pub use reject::RejectPlugin;
pub use return_plugin::ReturnPlugin;
