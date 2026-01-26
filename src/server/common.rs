//! Common utilities shared across DNS server implementations
//!
//! This module provides common helper functions used by multiple server
//! implementations (TCP, DoT, etc.) to avoid code duplication.

use crate::Result;
use crate::dns::Message;

/// Parse DNS request from wire format
///
/// Thin wrapper around `dns::wire::parse_message` that converts a byte
/// slice into a `Message` structure. Returns an error on invalid input.
///
/// # Arguments
///
/// * `data` - Raw DNS wire format bytes
///
/// # Returns
///
/// Parsed DNS `Message` or error if the data is malformed
pub fn parse_dns_request(data: &[u8]) -> Result<Message> {
    crate::dns::wire::parse_message(data)
}

/// Serialize DNS response to wire format
///
/// Converts a `Message` into DNS wire-format byte vector suitable for
/// sending over TCP/TLS connections.
///
/// # Arguments
///
/// * `message` - DNS message to serialize
///
/// # Returns
///
/// Serialized bytes or error if serialization fails
pub fn serialize_dns_response(message: &Message) -> Result<Vec<u8>> {
    crate::dns::wire::serialize_message(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_request_minimal_header() {
        // Minimal valid DNS header (12 bytes of zeros)
        let data = vec![0u8; 12];
        let result = parse_dns_request(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_dns_request_empty_fails() {
        let data: Vec<u8> = vec![];
        let result = parse_dns_request(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_dns_response() {
        let message = Message::new();
        let result = serialize_dns_response(&message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 12); // Minimal DNS header
    }
}
