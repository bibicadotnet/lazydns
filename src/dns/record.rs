//! DNS resource record implementation
//!
//! This module defines DNS resource records, which contain the actual
//! data returned in DNS responses.

use super::rdata::RData;
use super::types::{RecordClass, RecordType};
use std::fmt;
use std::sync::Arc;

/// DNS resource record
///
/// Represents a complete DNS resource record including name, type, class,
/// TTL, and data. Resource records appear in the answer, authority, and
/// additional sections of DNS messages.
///
/// # Example
///
/// ```
/// use lazydns::dns::{ResourceRecord, RecordType, RecordClass, RData};
/// use std::net::Ipv4Addr;
///
/// let record = ResourceRecord::new(
///     "example.com",
///     RecordType::A,
///     RecordClass::IN,
///     3600,
///     RData::A(Ipv4Addr::new(192, 0, 2, 1)),
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Domain name (shared via Arc for efficient cloning)
    name: Arc<str>,
    /// Record type
    rtype: RecordType,
    /// Record class
    rclass: RecordClass,
    /// Time to live (seconds)
    ttl: u32,
    /// Resource data
    rdata: RData,
}

impl ResourceRecord {
    /// Create a new resource record
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name for this record
    /// * `rtype` - Type of the record
    /// * `rclass` - Class of the record
    /// * `ttl` - Time to live in seconds
    /// * `rdata` - The resource data
    pub fn new(
        name: impl AsRef<str>,
        rtype: RecordType,
        rclass: RecordClass,
        ttl: u32,
        rdata: RData,
    ) -> Self {
        Self {
            name: Arc::from(name.as_ref()),
            rtype,
            rclass,
            ttl,
            rdata,
        }
    }

    /// Create a new resource record with a pre-allocated Arc<str>
    ///
    /// This is more efficient when you already have an Arc<str> as it avoids
    /// an additional allocation.
    pub fn with_arc(
        name: Arc<str>,
        rtype: RecordType,
        rclass: RecordClass,
        ttl: u32,
        rdata: RData,
    ) -> Self {
        Self {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        }
    }

    /// Get the domain name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the record type
    pub fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// Get the record class
    pub fn rclass(&self) -> RecordClass {
        self.rclass
    }

    /// Get the TTL
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Get the resource data
    pub fn rdata(&self) -> &RData {
        &self.rdata
    }

    /// Set the domain name
    pub fn set_name(&mut self, name: impl AsRef<str>) {
        self.name = Arc::from(name.as_ref());
    }

    /// Set the domain name with a pre-allocated Arc<str>
    pub fn set_name_arc(&mut self, name: Arc<str>) {
        self.name = name;
    }

    /// Get a clone of the Arc<str> for the domain name
    ///
    /// This is useful for sharing the domain name without string allocation.
    pub fn name_arc(&self) -> Arc<str> {
        Arc::clone(&self.name)
    }

    /// Set the record type
    pub fn set_rtype(&mut self, rtype: RecordType) {
        self.rtype = rtype;
    }

    /// Set the record class
    pub fn set_rclass(&mut self, rclass: RecordClass) {
        self.rclass = rclass;
    }

    /// Set the TTL
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// Set the resource data
    pub fn set_rdata(&mut self, rdata: RData) {
        self.rdata = rdata;
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}",
            self.name, self.ttl, self.rclass, self.rtype, self.rdata
        )
    }
}

/// Type alias for ResourceRecord for convenience
pub type Record = ResourceRecord;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_resource_record_creation() {
        let record = ResourceRecord::new(
            "example.com",
            RecordType::A,
            RecordClass::IN,
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );

        assert_eq!(record.name(), "example.com");
        assert_eq!(record.rtype(), RecordType::A);
        assert_eq!(record.rclass(), RecordClass::IN);
        assert_eq!(record.ttl(), 3600);
    }

    #[test]
    fn test_resource_record_setters() {
        let mut record = ResourceRecord::new(
            "example.com",
            RecordType::A,
            RecordClass::IN,
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );

        record.set_name("test.com");
        record.set_rtype(RecordType::AAAA);
        record.set_rclass(RecordClass::CH);
        record.set_ttl(7200);

        assert_eq!(record.name(), "test.com");
        assert_eq!(record.rtype(), RecordType::AAAA);
        assert_eq!(record.rclass(), RecordClass::CH);
        assert_eq!(record.ttl(), 7200);
    }

    #[test]
    fn test_resource_record_display() {
        let record = ResourceRecord::new(
            "example.com",
            RecordType::A,
            RecordClass::IN,
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );

        let display = format!("{}", record);
        assert!(display.contains("example.com"));
        assert!(display.contains("3600"));
        assert!(display.contains("IN"));
        assert!(display.contains("A"));
        assert!(display.contains("192.0.2.1"));
    }

    #[test]
    fn test_record_equality() {
        let r1 = ResourceRecord::new(
            "example.com",
            RecordType::A,
            RecordClass::IN,
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );
        let r2 = ResourceRecord::new(
            "example.com",
            RecordType::A,
            RecordClass::IN,
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );
        let r3 = ResourceRecord::new(
            "other.com",
            RecordType::A,
            RecordClass::IN,
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );

        assert_eq!(r1, r2);
        assert_ne!(r1, r3);
    }

    #[test]
    fn test_different_record_types() {
        use std::net::Ipv6Addr;

        // Test AAAA record
        let aaaa = ResourceRecord::new(
            "example.com",
            RecordType::AAAA,
            RecordClass::IN,
            3600,
            RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        assert_eq!(aaaa.rtype(), RecordType::AAAA);

        // Test CNAME record
        let cname = ResourceRecord::new(
            "www.example.com",
            RecordType::CNAME,
            RecordClass::IN,
            3600,
            RData::CNAME("example.com".to_string()),
        );
        assert_eq!(cname.rtype(), RecordType::CNAME);

        // Test MX record
        let mx = ResourceRecord::new(
            "example.com",
            RecordType::MX,
            RecordClass::IN,
            3600,
            RData::mx(10, "mail.example.com".to_string()),
        );
        assert_eq!(mx.rtype(), RecordType::MX);
    }
}
