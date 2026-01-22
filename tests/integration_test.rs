//! Integration tests for DNS server
//!
//! Tests full DNS query/response functionality with wire format parsing

use lazydns::dns::wire::{parse_message, serialize_message};
use lazydns::dns::{Message, Question, RData, RecordClass, RecordType, ResourceRecord};
use std::net::Ipv4Addr;

#[test]
fn test_wire_format_roundtrip_query() {
    // Create a DNS query
    let mut query = Message::new();
    query.set_id(1234);
    query.set_query(true);
    query.set_recursion_desired(true);
    query.add_question(Question::new("example.com", RecordType::A, RecordClass::IN));

    // Serialize to wire format
    let wire_data = serialize_message(&query).expect("Failed to serialize query");

    // Verify wire format is valid (at least header size)
    assert!(
        wire_data.len() >= 12,
        "Wire format should be at least 12 bytes for header"
    );

    // Parse back from wire format
    let parsed = parse_message(&wire_data).expect("Failed to parse wire format");

    // Verify all fields match
    assert_eq!(parsed.id(), query.id());
    assert_eq!(parsed.is_response(), query.is_response());
    assert_eq!(parsed.recursion_desired(), query.recursion_desired());
    assert_eq!(parsed.question_count(), query.question_count());

    // Verify question details
    let qname = parsed.questions()[0].qname();
    assert!(
        qname == "example.com" || qname == "example.com.",
        "Question name should match"
    );
    assert_eq!(parsed.questions()[0].qtype(), RecordType::A);
    assert_eq!(parsed.questions()[0].qclass(), RecordClass::IN);
}

#[test]
fn test_wire_format_roundtrip_response() {
    // Create a DNS response
    let mut response = Message::new();
    response.set_id(5678);
    response.set_response(true);
    response.set_recursion_available(true);
    response.set_authoritative(false);

    // Add question section (copied from query)
    response.add_question(Question::new("example.com", RecordType::A, RecordClass::IN));

    // Add answer section
    response.add_answer(ResourceRecord::new(
        "example.com",
        RecordType::A,
        RecordClass::IN,
        300,
        RData::A(Ipv4Addr::new(93, 184, 216, 34)),
    ));

    // Serialize to wire format
    let wire_data = serialize_message(&response).expect("Failed to serialize response");

    // Parse back from wire format
    let parsed = parse_message(&wire_data).expect("Failed to parse wire format");

    // Verify all fields match
    assert_eq!(parsed.id(), response.id());
    assert!(parsed.is_response());
    assert!(parsed.recursion_available());
    assert_eq!(parsed.question_count(), 1);
    assert_eq!(parsed.answer_count(), 1);

    // Verify answer
    let answer = &parsed.answers()[0];
    let answer_name = answer.name();
    assert!(
        answer_name == "example.com" || answer_name == "example.com.",
        "Answer name should match"
    );
    assert_eq!(answer.rtype(), RecordType::A);
    match answer.rdata() {
        RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        _ => panic!("Expected A record"),
    }
}

#[test]
fn test_wire_format_with_multiple_answers() {
    // Create a response with multiple answers
    let mut response = Message::new();
    response.set_id(9999);
    response.set_response(true);
    response.set_recursion_available(true);

    response.add_question(Question::new("example.com", RecordType::A, RecordClass::IN));

    // Add multiple A records
    response.add_answer(ResourceRecord::new(
        "example.com",
        RecordType::A,
        RecordClass::IN,
        300,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));

    response.add_answer(ResourceRecord::new(
        "example.com",
        RecordType::A,
        RecordClass::IN,
        300,
        RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    ));

    // Serialize and parse
    let wire_data = serialize_message(&response).expect("Failed to serialize");
    let parsed = parse_message(&wire_data).expect("Failed to parse");

    assert_eq!(parsed.answer_count(), 2);
    let name1 = parsed.answers()[0].name();
    let name2 = parsed.answers()[1].name();
    assert!(
        name1 == "example.com" || name1 == "example.com.",
        "Answer 1 name should match"
    );
    assert!(
        name2 == "example.com" || name2 == "example.com.",
        "Answer 2 name should match"
    );
}

#[test]
fn test_wire_format_with_cname() {
    let mut response = Message::new();
    response.set_id(1111);
    response.set_response(true);

    response.add_question(Question::new(
        "www.example.com",
        RecordType::A,
        RecordClass::IN,
    ));

    // Add CNAME record
    response.add_answer(ResourceRecord::new(
        "www.example.com",
        RecordType::CNAME,
        RecordClass::IN,
        300,
        RData::CNAME("example.com".to_string()),
    ));

    // Add A record for the target
    response.add_answer(ResourceRecord::new(
        "example.com",
        RecordType::A,
        RecordClass::IN,
        300,
        RData::A(Ipv4Addr::new(93, 184, 216, 34)),
    ));

    // Serialize and parse
    let wire_data = serialize_message(&response).expect("Failed to serialize");
    let parsed = parse_message(&wire_data).expect("Failed to parse");

    assert_eq!(parsed.answer_count(), 2);

    // Verify CNAME
    match parsed.answers()[0].rdata() {
        RData::CNAME(target) => {
            assert!(
                target == "example.com" || target == "example.com.",
                "CNAME target should match"
            );
        }
        _ => panic!("Expected CNAME record"),
    }

    // Verify A record
    match parsed.answers()[1].rdata() {
        RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        _ => panic!("Expected A record"),
    }
}

#[test]
fn test_wire_format_error_response() {
    use lazydns::dns::ResponseCode;

    let mut response = Message::new();
    response.set_id(2222);
    response.set_response(true);
    response.set_response_code(ResponseCode::NXDomain);

    response.add_question(Question::new(
        "nonexistent.example.com",
        RecordType::A,
        RecordClass::IN,
    ));

    // Serialize and parse
    let wire_data = serialize_message(&response).expect("Failed to serialize");
    let parsed = parse_message(&wire_data).expect("Failed to parse");

    assert_eq!(parsed.response_code(), ResponseCode::NXDomain);
    assert_eq!(parsed.answer_count(), 0);
}
