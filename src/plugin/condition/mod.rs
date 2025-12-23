//! Built-in condition builder implementations
//!
//! This module contains all the default condition builders for common DNS query conditions.
//! Each builder implements the ConditionBuilder trait and is registered in the global registry.

pub mod builder;
pub mod has_cname;
pub mod has_resp;
pub mod qclass;
pub mod qname;
pub mod qname_neg;
pub mod qtype;
pub mod rcode;
pub mod resp_ip;
pub mod resp_ip_neg;

pub use has_cname::HasCnameBuilder;
pub use has_resp::HasRespBuilder;
pub use qclass::QclassBuilder;
pub use qname::QnameBuilder;
pub use qname_neg::QnameNegBuilder;
pub use qtype::QtypeBuilder;
pub use rcode::RcodeBuilder;
pub use resp_ip::RespIpBuilder;
pub use resp_ip_neg::RespIpNegBuilder;
