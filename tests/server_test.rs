//! Server integration tests
//!
//! Tests the DNS server with real UDP queries

use async_trait::async_trait;
use lazydns::dns::wire::{parse_message, serialize_message};
use lazydns::dns::{Message, Question, RData, RecordClass, RecordType, ResourceRecord};
use lazydns::server::{RequestHandler, ServerConfig, UdpServer};
use lazydns::Result;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

/// A simple test handler that returns a fixed response
struct TestHandler;

#[async_trait]
impl RequestHandler for TestHandler {
    async fn handle(&self, mut request: Message) -> Result<Message> {
        // Convert query to response
        request.set_response(true);
        request.set_recursion_available(true);

        // Add an answer for any A query
        if !request.questions().is_empty() {
            let question = &request.questions()[0];
            if question.qtype() == RecordType::A {
                request.add_answer(ResourceRecord::new(
                    question.qname().trim_end_matches('.').to_string(),
                    RecordType::A,
                    RecordClass::IN,
                    300,
                    RData::A(Ipv4Addr::new(93, 184, 216, 34)),
                ));
            }
        }

        Ok(request)
    }
}

#[tokio::test]
async fn test_udp_server_query_response() {
    // Start server on a random port
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = ServerConfig::default().with_udp_addr(server_addr);
    let handler = Arc::new(TestHandler);

    let server = UdpServer::new(config, handler)
        .await
        .expect("Failed to create server");
    let actual_addr = server.local_addr().expect("Failed to get server address");

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Create a DNS query
    let mut query = Message::new();
    query.set_id(12345);
    query.set_query(true);
    query.set_recursion_desired(true);
    query.add_question(Question::new(
        "test.example.com".to_string(),
        RecordType::A,
        RecordClass::IN,
    ));

    // Serialize query
    let query_bytes = serialize_message(&query).expect("Failed to serialize query");

    // Send query to server
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");
    client_socket
        .send_to(&query_bytes, actual_addr)
        .await
        .expect("Failed to send query");

    // Receive response with timeout
    let mut buf = vec![0u8; 512];
    let (len, _) = timeout(Duration::from_secs(5), client_socket.recv_from(&mut buf))
        .await
        .expect("Timeout waiting for response")
        .expect("Failed to receive response");

    // Parse response
    let response = parse_message(&buf[..len]).expect("Failed to parse response");

    // Verify response
    assert_eq!(response.id(), query.id());
    assert!(response.is_response());
    assert!(response.recursion_available());
    assert_eq!(response.question_count(), 1);
    assert_eq!(response.answer_count(), 1);

    // Verify the answer
    let answer = &response.answers()[0];
    assert_eq!(answer.rtype(), RecordType::A);
    match answer.rdata() {
        RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        _ => panic!("Expected A record"),
    }

    // Clean up
    server_handle.abort();
}

#[tokio::test]
async fn test_multiple_sequential_queries() {
    // Start server
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = ServerConfig::default().with_udp_addr(server_addr);
    let handler = Arc::new(TestHandler);

    let server = UdpServer::new(config, handler)
        .await
        .expect("Failed to create server");
    let actual_addr = server.local_addr().expect("Failed to get server address");

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(100)).await;

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");

    // Send multiple queries
    for i in 0..5 {
        let mut query = Message::new();
        query.set_id(1000 + i);
        query.set_query(true);
        query.set_recursion_desired(true);
        query.add_question(Question::new(
            format!("test{}.example.com", i),
            RecordType::A,
            RecordClass::IN,
        ));

        let query_bytes = serialize_message(&query).expect("Failed to serialize query");
        client_socket
            .send_to(&query_bytes, actual_addr)
            .await
            .expect("Failed to send query");

        let mut buf = vec![0u8; 512];
        let (len, _) = timeout(Duration::from_secs(5), client_socket.recv_from(&mut buf))
            .await
            .expect("Timeout waiting for response")
            .expect("Failed to receive response");

        let response = parse_message(&buf[..len]).expect("Failed to parse response");
        assert_eq!(response.id(), 1000 + i);
        assert!(response.is_response());
        assert_eq!(response.answer_count(), 1);
    }

    server_handle.abort();
}
