//! Simple test server for manual testing with dig/nslookup
//!
//! Run this with: cargo run --example test_server
//! Then test with: dig @127.0.0.1 -p 5353 example.com

use async_trait::async_trait;
use lazydns::Result;
use lazydns::dns::{Message, RData, RecordClass, RecordType, ResourceRecord};
use lazydns::server::{RequestContext, RequestHandler, ServerConfig, UdpServer};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// A simple handler that returns a fixed IP for any A query
struct SimpleHandler;

#[async_trait]
impl RequestHandler for SimpleHandler {
    async fn handle(&self, ctx: RequestContext) -> Result<Message> {
        let mut request = ctx.into_message();
        println!("Received query:");
        println!("  ID: {}", request.id());
        println!("  Questions: {}", request.question_count());

        if !request.questions().is_empty() {
            let q = &request.questions()[0];
            println!("  Query: {} {} {}", q.qname(), q.qtype(), q.qclass());
        }

        // Convert query to response
        request.set_response(true);
        request.set_recursion_available(true);
        request.set_authoritative(false);

        // Add an answer for any A query
        if !request.questions().is_empty() {
            let question = &request.questions()[0];
            if question.qtype() == RecordType::A {
                let qname = question.qname().trim_end_matches('.').to_string();
                request.add_answer(ResourceRecord::new(
                    qname.clone(),
                    RecordType::A,
                    RecordClass::IN,
                    300,
                    RData::A(Ipv4Addr::new(93, 184, 216, 34)),
                ));
                println!("  Response: {} A 93.184.216.34", qname);
            } else if question.qtype() == RecordType::AAAA {
                let qname = question.qname().trim_end_matches('.').to_string();
                use std::net::Ipv6Addr;
                request.add_answer(ResourceRecord::new(
                    qname.clone(),
                    RecordType::AAAA,
                    RecordClass::IN,
                    300,
                    RData::AAAA(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    )),
                ));
                println!(
                    "  Response: {} AAAA 2606:2800:220:1:248:1893:25c8:1946",
                    qname
                );
            }
        }

        Ok(request)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    #[cfg(feature = "tracing-subscriber")]
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("Starting DNS test server on 127.0.0.1:5353");
    println!("Test with: dig @127.0.0.1 -p 5353 example.com");
    println!("Or: dig @127.0.0.1 -p 5353 example.com AAAA");
    println!();

    let config = ServerConfig::default().with_udp_addr("127.0.0.1:5353".parse().unwrap());

    let handler = Arc::new(SimpleHandler);
    let server = UdpServer::new(config, handler).await?;

    server.run().await
}
