//! DNS protocol implementation module
//!
//! This module provides comprehensive DNS protocol support including:
//! - DNS message parsing and serialization (RFC 1035)
//! - Support for all common DNS record types
//! - EDNS0 support (RFC 6891)
//! - DNS message validation and error handling
//!
//! # Example
//!
//! ```rust,no_run
//! use lazydns::dns::{Message, Question, RecordType, RecordClass};
//!
//! // Create a DNS query message
//! let mut message = Message::new();
//! message.set_query(true);
//! message.add_question(Question::new(
//!     "example.com",
//!     RecordType::A,
//!     RecordClass::IN,
//! ));
//! ```

pub mod message;
pub mod question;
pub mod rdata;
pub mod record;
pub mod types;
pub mod wire;

// Re-export commonly used types
pub use message::Message;
pub use question::Question;
pub use rdata::RData;
pub use record::{Record, ResourceRecord};
pub use types::{OpCode, RecordClass, RecordType, ResponseCode};
pub use wire::{parse_message, serialize_message};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_types_reexports() {
        // Verify all re-exported types are accessible
        let _msg = Message::new();
        let _question = Question::new("example.com", RecordType::A, RecordClass::IN);
        let _opcode = OpCode::Query;
        let _rcode = ResponseCode::NoError;
    }

    #[test]
    fn test_record_types_accessible() {
        // Verify RecordType enum variants are accessible
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
        assert_eq!(RecordType::CNAME.to_u16(), 5);
    }

    #[test]
    fn test_record_classes_accessible() {
        // Verify RecordClass enum variants are accessible
        assert_eq!(RecordClass::IN.to_u16(), 1);
        assert_eq!(RecordClass::CH.to_u16(), 3);
    }

    #[test]
    fn test_message_serialization() {
        // Verify wire format functions are accessible
        let message = Message::new();
        let serialized = serialize_message(&message);
        assert!(serialized.is_ok());

        let wire_data = serialized.unwrap();
        let parsed = parse_message(&wire_data);
        assert!(parsed.is_ok());
    }
}
