//! Matcher plugins for conditional query processing
//!
//! This module contains plugins that match various aspects of DNS queries
//! and responses. Matchers set metadata in the context that can be used by
//! other plugins for decision making.

pub mod base_int;
pub mod client_ip;
pub mod cname;
pub mod env;
pub mod has_resp;
pub mod has_wanted_ans;
pub mod ptr_ip;
pub mod qclass;
pub mod qname;
pub mod qtype;
pub mod random;
pub mod rcode;
pub mod string_exp;

pub use base_int::{BaseIntMatcherPlugin, IntComparison};
pub use client_ip::ClientIpMatcherPlugin;
pub use cname::CnameMatcherPlugin;
pub use env::EnvMatcherPlugin;
pub use has_resp::HasRespMatcherPlugin;
pub use has_wanted_ans::HasWantedAnsMatcherPlugin;
pub use ptr_ip::PtrIpMatcherPlugin;
pub use qclass::QClassMatcherPlugin;
pub use qname::QNameMatcherPlugin;
pub use qtype::QTypeMatcherPlugin;
pub use random::RandomMatcherPlugin;
pub use rcode::RCodeMatcherPlugin;
pub use string_exp::{StringExpMatcherPlugin, StringExpression};
