//! DNS protocol type definitions
//!
//! This module defines the core DNS types including:
//! - Record types (A, AAAA, CNAME, etc.)
//! - Record classes (IN, CH, etc.)
//! - Operation codes
//! - Response codes

use std::fmt;

/// DNS record type
///
/// Represents the type of DNS record (A, AAAA, CNAME, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    /// IPv4 address record
    A = 1,
    /// Name server record
    NS = 2,
    /// Canonical name record
    CNAME = 5,
    /// Start of authority record
    SOA = 6,
    /// Pointer record
    PTR = 12,
    /// Mail exchange record
    MX = 15,
    /// Text record
    TXT = 16,
    /// IPv6 address record
    AAAA = 28,
    /// Service record
    SRV = 33,
    /// OPT pseudo-record for EDNS(0) (RFC 6891)
    OPT = 41,
    /// DNSSEC delegation signer (RFC 4034)
    DS = 43,
    /// DNSSEC signature (RFC 4034)
    RRSIG = 46,
    /// Next secure record (RFC 4034)
    NSEC = 47,
    /// DNSSEC key record (RFC 4034)
    DNSKEY = 48,
    /// Next secure record v3 (RFC 5155)
    NSEC3 = 50,
    /// NSEC3 parameters (RFC 5155)
    NSEC3PARAM = 51,
    /// Service binding record (RFC 9460)
    SVCB = 64,
    /// HTTPS service binding (RFC 9460)
    HTTPS = 65,
    /// Certificate authority authorization
    CAA = 257,
    /// Unknown or unsupported record type
    Unknown(u16),
}

impl RecordType {
    /// Create a RecordType from a u16 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::RecordType;
    ///
    /// let a_record = RecordType::from_u16(1);
    /// assert_eq!(a_record, RecordType::A);
    ///
    /// let aaaa_record = RecordType::from_u16(28);
    /// assert_eq!(aaaa_record, RecordType::AAAA);
    ///
    /// let unknown = RecordType::from_u16(9999);
    /// assert_eq!(unknown, RecordType::Unknown(9999));
    /// ```
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            41 => RecordType::OPT,
            43 => RecordType::DS,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            64 => RecordType::SVCB,
            65 => RecordType::HTTPS,
            257 => RecordType::CAA,
            _ => RecordType::Unknown(value),
        }
    }

    /// Convert RecordType to u16 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::RecordType;
    ///
    /// assert_eq!(RecordType::A.to_u16(), 1);
    /// assert_eq!(RecordType::AAAA.to_u16(), 28);
    /// assert_eq!(RecordType::HTTPS.to_u16(), 65);
    /// assert_eq!(RecordType::Unknown(9999).to_u16(), 9999);
    /// ```
    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::DS => 43,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::CAA => 257,
            RecordType::Unknown(v) => v,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::NS => write!(f, "NS"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::OPT => write!(f, "OPT"),
            RecordType::DS => write!(f, "DS"),
            RecordType::RRSIG => write!(f, "RRSIG"),
            RecordType::NSEC => write!(f, "NSEC"),
            RecordType::DNSKEY => write!(f, "DNSKEY"),
            RecordType::NSEC3 => write!(f, "NSEC3"),
            RecordType::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            RecordType::SVCB => write!(f, "SVCB"),
            RecordType::HTTPS => write!(f, "HTTPS"),
            RecordType::CAA => write!(f, "CAA"),
            RecordType::Unknown(v) => write!(f, "TYPE{}", v),
        }
    }
}

/// DNS record class
///
/// Represents the class of DNS record (usually IN for Internet)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordClass {
    /// Internet class
    IN = 1,
    /// Chaos class
    CH = 3,
    /// Hesiod class
    HS = 4,
    /// Unknown or unsupported class
    Unknown(u16),
}

impl RecordClass {
    /// Create a RecordClass from a u16 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::RecordClass;
    ///
    /// let internet = RecordClass::from_u16(1);
    /// assert_eq!(internet, RecordClass::IN);
    ///
    /// let unknown = RecordClass::from_u16(255);
    /// assert_eq!(unknown, RecordClass::Unknown(255));
    /// ```
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordClass::IN,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => RecordClass::Unknown(value),
        }
    }

    /// Convert RecordClass to u16 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::RecordClass;
    ///
    /// assert_eq!(RecordClass::IN.to_u16(), 1);
    /// assert_eq!(RecordClass::CH.to_u16(), 3);
    /// assert_eq!(RecordClass::Unknown(255).to_u16(), 255);
    /// ```
    pub fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::Unknown(v) => v,
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordClass::IN => write!(f, "IN"),
            RecordClass::CH => write!(f, "CH"),
            RecordClass::HS => write!(f, "HS"),
            RecordClass::Unknown(v) => write!(f, "CLASS{}", v),
        }
    }
}

/// DNS operation code
///
/// Specifies the kind of query in a DNS message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    /// Standard query
    Query = 0,
    /// Inverse query (obsolete)
    IQuery = 1,
    /// Server status request
    Status = 2,
    /// Notify
    Notify = 4,
    /// Update
    Update = 5,
    /// Unknown operation code
    Unknown(u8),
}

impl OpCode {
    /// Create an OpCode from a u8 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::OpCode;
    ///
    /// let query = OpCode::from_u8(0);
    /// assert_eq!(query, OpCode::Query);
    ///
    /// let update = OpCode::from_u8(5);
    /// assert_eq!(update, OpCode::Update);
    /// ```
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            _ => OpCode::Unknown(value),
        }
    }

    /// Convert OpCode to u8 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::OpCode;
    ///
    /// assert_eq!(OpCode::Query.to_u8(), 0);
    /// assert_eq!(OpCode::Update.to_u8(), 5);
    /// ```
    pub fn to_u8(self) -> u8 {
        match self {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Notify => 4,
            OpCode::Update => 5,
            OpCode::Unknown(v) => v,
        }
    }
}

/// DNS response code
///
/// Indicates the status of a DNS response
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    /// No error
    NoError = 0,
    /// Format error
    FormErr = 1,
    /// Server failure
    ServFail = 2,
    /// Non-existent domain
    NXDomain = 3,
    /// Not implemented
    NotImp = 4,
    /// Query refused
    Refused = 5,
    /// Name exists when it should not
    YXDomain = 6,
    /// RR set exists when it should not
    YXRRSet = 7,
    /// RR set that should exist does not
    NXRRSet = 8,
    /// Server not authoritative for zone / Not authorized
    NotAuth = 9,
    /// Name not contained in zone
    NotZone = 10,
    /// Unknown response code
    Unknown(u8),
}

impl ResponseCode {
    /// Create a ResponseCode from a u8 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::ResponseCode;
    ///
    /// let noerror = ResponseCode::from_u8(0);
    /// assert_eq!(noerror, ResponseCode::NoError);
    ///
    /// let nxdomain = ResponseCode::from_u8(3);
    /// assert_eq!(nxdomain, ResponseCode::NXDomain);
    /// ```
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            6 => ResponseCode::YXDomain,
            7 => ResponseCode::YXRRSet,
            8 => ResponseCode::NXRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
            _ => ResponseCode::Unknown(value),
        }
    }

    /// Convert ResponseCode to u8 value
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::ResponseCode;
    ///
    /// assert_eq!(ResponseCode::NoError.to_u8(), 0);
    /// assert_eq!(ResponseCode::NXDomain.to_u8(), 3);
    /// assert_eq!(ResponseCode::ServFail.to_u8(), 2);
    /// ```
    pub fn to_u8(self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormErr => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NXDomain => 3,
            ResponseCode::NotImp => 4,
            ResponseCode::Refused => 5,
            ResponseCode::YXDomain => 6,
            ResponseCode::YXRRSet => 7,
            ResponseCode::NXRRSet => 8,
            ResponseCode::NotAuth => 9,
            ResponseCode::NotZone => 10,
            ResponseCode::Unknown(v) => v,
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseCode::NoError => write!(f, "NOERROR"),
            ResponseCode::FormErr => write!(f, "FORMERR"),
            ResponseCode::ServFail => write!(f, "SERVFAIL"),
            ResponseCode::NXDomain => write!(f, "NXDOMAIN"),
            ResponseCode::NotImp => write!(f, "NOTIMP"),
            ResponseCode::Refused => write!(f, "REFUSED"),
            ResponseCode::YXDomain => write!(f, "YXDOMAIN"),
            ResponseCode::YXRRSet => write!(f, "YXRRSET"),
            ResponseCode::NXRRSet => write!(f, "NXRRSET"),
            ResponseCode::NotAuth => write!(f, "NOTAUTH"),
            ResponseCode::NotZone => write!(f, "NOTZONE"),
            ResponseCode::Unknown(v) => write!(f, "RCODE{}", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_conversions() {
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::from_u16(28), RecordType::AAAA);
        assert_eq!(RecordType::from_u16(64), RecordType::SVCB);
        assert_eq!(RecordType::from_u16(65), RecordType::HTTPS);
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
        assert_eq!(RecordType::SVCB.to_u16(), 64);
        assert_eq!(RecordType::HTTPS.to_u16(), 65);

        // Test unknown type
        let unknown = RecordType::from_u16(9999);
        assert_eq!(unknown, RecordType::Unknown(9999));
        assert_eq!(unknown.to_u16(), 9999);
    }

    #[test]
    fn test_record_type_display() {
        assert_eq!(format!("{}", RecordType::SVCB), "SVCB");
        assert_eq!(format!("{}", RecordType::HTTPS), "HTTPS");
    }

    #[test]
    fn test_record_class_conversions() {
        assert_eq!(RecordClass::from_u16(1), RecordClass::IN);
        assert_eq!(RecordClass::IN.to_u16(), 1);

        // Test unknown class
        let unknown = RecordClass::from_u16(255);
        assert_eq!(unknown, RecordClass::Unknown(255));
        assert_eq!(unknown.to_u16(), 255);
    }

    #[test]
    fn test_opcode_conversions() {
        assert_eq!(OpCode::from_u8(0), OpCode::Query);
        assert_eq!(OpCode::from_u8(5), OpCode::Update);
        assert_eq!(OpCode::Query.to_u8(), 0);
        assert_eq!(OpCode::Update.to_u8(), 5);
    }

    #[test]
    fn test_response_code_conversions() {
        assert_eq!(ResponseCode::from_u8(0), ResponseCode::NoError);
        assert_eq!(ResponseCode::from_u8(3), ResponseCode::NXDomain);
        assert_eq!(ResponseCode::NoError.to_u8(), 0);
        assert_eq!(ResponseCode::NXDomain.to_u8(), 3);
    }

    #[test]
    fn test_display_formats() {
        assert_eq!(RecordType::A.to_string(), "A");
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(RecordClass::IN.to_string(), "IN");
        assert_eq!(ResponseCode::NoError.to_string(), "NOERROR");
        assert_eq!(ResponseCode::NXDomain.to_string(), "NXDOMAIN");
    }
}
