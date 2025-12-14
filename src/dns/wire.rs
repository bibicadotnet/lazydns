//! DNS wire format parsing and serialization
//!
//! This module provides DNS message wire format (RFC 1035) conversion
//! using the hickory-proto library for production-grade implementation.

use crate::dns::{Message, Question, RecordClass, RecordType, ResourceRecord};
use crate::{Error, Result};
use hickory_proto::serialize::binary::BinEncodable;

/// Parse DNS message from wire format bytes
///
/// # Arguments
///
/// * `data` - Wire format DNS message bytes
///
/// # Returns
///
/// Parsed DNS Message or error
///
/// # Example
///
/// ```no_run
/// use lazydns::dns::wire::parse_message;
///
/// let wire_data = vec![/* DNS wire format bytes */];
/// let message = parse_message(&wire_data)?;
/// # Ok::<(), lazydns::Error>(())
/// ```
pub fn parse_message(data: &[u8]) -> Result<Message> {
    // Use hickory-proto for parsing
    use hickory_proto::op::Message as HickoryMessage;
    use hickory_proto::serialize::binary::BinDecodable;

    let hickory_msg = HickoryMessage::from_bytes(data)
        .map_err(|e| Error::DnsProtocol(format!("Failed to parse DNS message: {}", e)))?;

    // Convert hickory message to our message type
    convert_from_hickory(hickory_msg)
}

/// Serialize DNS message to wire format bytes
///
/// # Arguments
///
/// * `message` - DNS Message to serialize
///
/// # Returns
///
/// Wire format bytes or error
///
/// # Example
///
/// ```no_run
/// use lazydns::dns::{Message, wire::serialize_message};
///
/// let message = Message::new();
/// let wire_data = serialize_message(&message)?;
/// # Ok::<(), lazydns::Error>(())
/// ```
pub fn serialize_message(message: &Message) -> Result<Vec<u8>> {
    // Convert to hickory message
    let hickory_msg = convert_to_hickory(message)?;

    // Use hickory-proto for serialization
    use hickory_proto::serialize::binary::BinEncoder;

    let mut buffer = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buffer);

    hickory_msg
        .emit(&mut encoder)
        .map_err(|e| Error::DnsProtocol(format!("Failed to serialize DNS message: {}", e)))?;

    Ok(buffer)
}

/// Convert hickory-proto message to our message type
fn convert_from_hickory(hickory_msg: hickory_proto::op::Message) -> Result<Message> {
    use hickory_proto::op::OpCode as HickoryOpCode;
    use hickory_proto::op::ResponseCode as HickoryRCode;

    let mut message = Message::new();

    // Set header fields
    message.set_id(hickory_msg.id());
    message.set_query(hickory_msg.message_type() == hickory_proto::op::MessageType::Query);
    message.set_authoritative(hickory_msg.authoritative());
    message.set_truncated(hickory_msg.truncated());
    message.set_recursion_desired(hickory_msg.recursion_desired());
    message.set_recursion_available(hickory_msg.recursion_available());

    // Convert opcode
    let opcode = match hickory_msg.op_code() {
        HickoryOpCode::Query => crate::dns::OpCode::Query,
        HickoryOpCode::Status => crate::dns::OpCode::Status,
        HickoryOpCode::Notify => crate::dns::OpCode::Notify,
        HickoryOpCode::Update => crate::dns::OpCode::Update,
    };
    message.set_opcode(opcode);

    // Convert response code
    let rcode = match hickory_msg.response_code() {
        HickoryRCode::NoError => crate::dns::ResponseCode::NoError,
        HickoryRCode::FormErr => crate::dns::ResponseCode::FormErr,
        HickoryRCode::ServFail => crate::dns::ResponseCode::ServFail,
        HickoryRCode::NXDomain => crate::dns::ResponseCode::NXDomain,
        HickoryRCode::NotImp => crate::dns::ResponseCode::NotImp,
        HickoryRCode::Refused => crate::dns::ResponseCode::Refused,
        HickoryRCode::YXDomain => crate::dns::ResponseCode::ServFail, // Map to ServFail
        HickoryRCode::YXRRSet => crate::dns::ResponseCode::ServFail,
        HickoryRCode::NXRRSet => crate::dns::ResponseCode::ServFail,
        HickoryRCode::NotAuth => crate::dns::ResponseCode::Refused,
        HickoryRCode::NotZone => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADVERS => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADSIG => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADKEY => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADTIME => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADMODE => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADNAME => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADALG => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADTRUNC => crate::dns::ResponseCode::ServFail,
        HickoryRCode::BADCOOKIE => crate::dns::ResponseCode::ServFail,
        _ => crate::dns::ResponseCode::ServFail,
    };
    message.set_response_code(rcode);

    // Convert questions
    for q in hickory_msg.queries() {
        let qname = q.name().to_utf8();
        let qtype = RecordType::from_u16(q.query_type().into());
        let qclass = RecordClass::from_u16(q.query_class().into());

        message.add_question(Question::new(qname, qtype, qclass));
    }

    // Convert answer records
    for record in hickory_msg.answers() {
        if let Some(rr) = convert_hickory_record(record) {
            message.add_answer(rr);
        }
    }

    // Convert authority records
    for record in hickory_msg.name_servers() {
        if let Some(rr) = convert_hickory_record(record) {
            message.add_authority(rr);
        }
    }

    // Convert additional records
    for record in hickory_msg.additionals() {
        if let Some(rr) = convert_hickory_record(record) {
            message.add_additional(rr);
        }
    }

    Ok(message)
}

/// Convert a hickory-proto record to our ResourceRecord type
fn convert_hickory_record(record: &hickory_proto::rr::Record) -> Option<ResourceRecord> {
    use hickory_proto::rr::RData as HickoryRData;

    let name = record.name().to_utf8();
    let rtype = RecordType::from_u16(record.record_type().into());
    let rclass = RecordClass::from_u16(record.dns_class().into());
    let ttl = record.ttl();

    let rdata = match record.data() {
        Some(HickoryRData::A(ipv4)) => crate::dns::RData::A(ipv4.0),
        Some(HickoryRData::AAAA(ipv6)) => crate::dns::RData::AAAA(ipv6.0),
        Some(HickoryRData::CNAME(name)) => crate::dns::RData::CNAME(name.to_utf8()),
        Some(HickoryRData::MX(mx)) => crate::dns::RData::MX {
            preference: mx.preference(),
            exchange: mx.exchange().to_utf8(),
        },
        Some(HickoryRData::NS(ns)) => crate::dns::RData::NS(ns.to_utf8()),
        Some(HickoryRData::PTR(ptr)) => crate::dns::RData::PTR(ptr.to_utf8()),
        Some(HickoryRData::TXT(txt)) => {
            let text_data: Vec<String> = txt
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect();
            crate::dns::RData::TXT(text_data)
        }
        Some(HickoryRData::SOA(soa)) => crate::dns::RData::SOA {
            mname: soa.mname().to_utf8(),
            rname: soa.rname().to_utf8(),
            serial: soa.serial(),
            refresh: soa.refresh() as u32,
            retry: soa.retry() as u32,
            expire: soa.expire() as u32,
            minimum: soa.minimum(),
        },
        _ => return None, // Unsupported record type
    };

    Some(ResourceRecord::new(name, rtype, rclass, ttl, rdata))
}

/// Convert our message type to hickory-proto message
fn convert_to_hickory(message: &Message) -> Result<hickory_proto::op::Message> {
    use hickory_proto::op::{Message as HickoryMessage, OpCode as HickoryOpCode, Query};
    use hickory_proto::rr::{Name, RecordType as HickoryRecordType};

    let mut hickory_msg = HickoryMessage::new();

    // Set header fields
    hickory_msg.set_id(message.id());
    hickory_msg.set_message_type(if message.is_response() {
        hickory_proto::op::MessageType::Response
    } else {
        hickory_proto::op::MessageType::Query
    });
    hickory_msg.set_authoritative(message.is_authoritative());
    hickory_msg.set_truncated(message.is_truncated());
    hickory_msg.set_recursion_desired(message.recursion_desired());
    hickory_msg.set_recursion_available(message.recursion_available());

    // Convert opcode
    let opcode = match message.opcode() {
        crate::dns::OpCode::Query => HickoryOpCode::Query,
        crate::dns::OpCode::Status => HickoryOpCode::Status,
        crate::dns::OpCode::Notify => HickoryOpCode::Notify,
        crate::dns::OpCode::Update => HickoryOpCode::Update,
        crate::dns::OpCode::IQuery | crate::dns::OpCode::Unknown(_) => HickoryOpCode::Query,
    };
    hickory_msg.set_op_code(opcode);

    // Convert response code
    let rcode = match message.response_code() {
        crate::dns::ResponseCode::NoError => hickory_proto::op::ResponseCode::NoError,
        crate::dns::ResponseCode::FormErr => hickory_proto::op::ResponseCode::FormErr,
        crate::dns::ResponseCode::ServFail => hickory_proto::op::ResponseCode::ServFail,
        crate::dns::ResponseCode::NXDomain => hickory_proto::op::ResponseCode::NXDomain,
        crate::dns::ResponseCode::NotImp => hickory_proto::op::ResponseCode::NotImp,
        crate::dns::ResponseCode::Refused => hickory_proto::op::ResponseCode::Refused,
        crate::dns::ResponseCode::YXDomain => hickory_proto::op::ResponseCode::YXDomain,
        crate::dns::ResponseCode::YXRRSet => hickory_proto::op::ResponseCode::YXRRSet,
        crate::dns::ResponseCode::NXRRSet => hickory_proto::op::ResponseCode::NXRRSet,
        crate::dns::ResponseCode::NotAuth => hickory_proto::op::ResponseCode::NotAuth,
        crate::dns::ResponseCode::NotZone => hickory_proto::op::ResponseCode::NotZone,
        crate::dns::ResponseCode::Unknown(code) => {
            // Map unknown codes to the closest match
            match code {
                0 => hickory_proto::op::ResponseCode::NoError,
                1 => hickory_proto::op::ResponseCode::FormErr,
                2 => hickory_proto::op::ResponseCode::ServFail,
                3 => hickory_proto::op::ResponseCode::NXDomain,
                4 => hickory_proto::op::ResponseCode::NotImp,
                5 => hickory_proto::op::ResponseCode::Refused,
                _ => hickory_proto::op::ResponseCode::ServFail,
            }
        }
    };
    hickory_msg.set_response_code(rcode);

    // Convert questions
    for q in message.questions() {
        let name = Name::from_utf8(q.qname())
            .map_err(|e| Error::DnsProtocol(format!("Invalid domain name: {}", e)))?;

        let rtype: HickoryRecordType = q.qtype().to_u16().into();

        let query = Query::query(name, rtype);
        hickory_msg.add_query(query);
    }

    // Convert answer records
    for rr in message.answers() {
        if let Some(record) = convert_to_hickory_record(rr)? {
            hickory_msg.add_answer(record);
        }
    }

    // Convert authority records
    for rr in message.authority() {
        if let Some(record) = convert_to_hickory_record(rr)? {
            hickory_msg.add_name_server(record);
        }
    }

    // Convert additional records
    for rr in message.additional() {
        if let Some(record) = convert_to_hickory_record(rr)? {
            hickory_msg.add_additional(record);
        }
    }

    Ok(hickory_msg)
}

/// Convert our ResourceRecord to hickory-proto Record type
fn convert_to_hickory_record(rr: &ResourceRecord) -> Result<Option<hickory_proto::rr::Record>> {
    use hickory_proto::rr::{Name, RData as HickoryRData, Record, RecordType as HickoryRecordType};

    let name = Name::from_utf8(rr.name())
        .map_err(|e| Error::DnsProtocol(format!("Invalid domain name: {}", e)))?;

    let rtype: HickoryRecordType = rr.rtype().to_u16().into();
    let ttl = rr.ttl();

    let rdata = match rr.rdata() {
        crate::dns::RData::A(ipv4) => HickoryRData::A(hickory_proto::rr::rdata::A(*ipv4)),
        crate::dns::RData::AAAA(ipv6) => HickoryRData::AAAA(hickory_proto::rr::rdata::AAAA(*ipv6)),
        crate::dns::RData::CNAME(name_str) => {
            let cname = Name::from_utf8(name_str)
                .map_err(|e| Error::DnsProtocol(format!("Invalid CNAME: {}", e)))?;
            HickoryRData::CNAME(hickory_proto::rr::rdata::CNAME(cname))
        }
        crate::dns::RData::MX {
            preference,
            exchange,
        } => {
            let mx_name = Name::from_utf8(exchange)
                .map_err(|e| Error::DnsProtocol(format!("Invalid MX exchange: {}", e)))?;
            HickoryRData::MX(hickory_proto::rr::rdata::MX::new(*preference, mx_name))
        }
        crate::dns::RData::NS(ns_str) => {
            let ns_name = Name::from_utf8(ns_str)
                .map_err(|e| Error::DnsProtocol(format!("Invalid NS: {}", e)))?;
            HickoryRData::NS(hickory_proto::rr::rdata::NS(ns_name))
        }
        crate::dns::RData::PTR(ptr_str) => {
            let ptr_name = Name::from_utf8(ptr_str)
                .map_err(|e| Error::DnsProtocol(format!("Invalid PTR: {}", e)))?;
            HickoryRData::PTR(hickory_proto::rr::rdata::PTR(ptr_name))
        }
        crate::dns::RData::TXT(text_vec) => {
            let txt_data: Vec<String> = text_vec.to_vec();
            HickoryRData::TXT(hickory_proto::rr::rdata::TXT::new(txt_data))
        }
        crate::dns::RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            let mname_name = Name::from_utf8(mname)
                .map_err(|e| Error::DnsProtocol(format!("Invalid SOA mname: {}", e)))?;
            let rname_name = Name::from_utf8(rname)
                .map_err(|e| Error::DnsProtocol(format!("Invalid SOA rname: {}", e)))?;
            HickoryRData::SOA(hickory_proto::rr::rdata::SOA::new(
                mname_name,
                rname_name,
                *serial,
                *refresh as i32,
                *retry as i32,
                *expire as i32,
                *minimum,
            ))
        }
        _ => return Ok(None), // Unsupported record type, skip it
    };

    let mut record = Record::new();
    record.set_name(name);
    record.set_record_type(rtype);
    record.set_dns_class(hickory_proto::rr::DNSClass::from(rr.rclass().to_u16()));
    record.set_ttl(ttl);
    record.set_data(Some(rdata));

    Ok(Some(record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_and_parse_query() {
        let mut message = Message::new();
        message.set_id(1234);
        message.set_query(true);
        message.set_recursion_desired(true);
        message.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        // Serialize
        let wire_data = serialize_message(&message).unwrap();
        assert!(!wire_data.is_empty());

        // Parse back
        let parsed = parse_message(&wire_data).unwrap();
        assert_eq!(parsed.id(), message.id());
        assert!(!parsed.is_response()); // is_query is the inverse of is_response
        assert!(parsed.recursion_desired());
        assert_eq!(parsed.question_count(), 1);
    }

    #[test]
    fn test_parse_invalid_data() {
        let invalid_data = vec![0x00, 0x01, 0x02]; // Too short
        let result = parse_message(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_response() {
        let mut message = Message::new();
        message.set_id(5678);
        message.set_response(true);
        message.set_recursion_available(true);
        message.set_response_code(crate::dns::ResponseCode::NoError);

        let wire_data = serialize_message(&message).unwrap();
        let parsed = parse_message(&wire_data).unwrap();

        assert_eq!(parsed.id(), 5678);
        assert!(parsed.is_response());
        assert!(parsed.recursion_available());
    }
}
