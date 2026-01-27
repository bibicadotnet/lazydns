//! SSE (Server-Sent Events) routes for real-time audit streaming

use crate::plugins::audit::event_bus;
use crate::web::state::WebState;
use axum::{
    extract::State,
    response::sse::{Event, Sse},
};
use futures_util::stream::Stream;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, trace};

/// GET /api/audit/query-logs/stream
///
/// SSE endpoint for streaming query logs in real-time
pub async fn query_logs_stream(
    State(state): State<Arc<WebState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let keepalive_secs = state.config().sse.keepalive_secs;

    let stream = async_stream::stream! {
        let bus = match event_bus() {
            Some(bus) => bus,
            None => {
                yield Ok(Event::default()
                    .event("error")
                    .data("Event bus not available"));
                return;
            }
        };

        let mut subscriber = bus.subscribe_queries();
        debug!("New SSE subscriber for query logs");

        // Send initial connection event
        yield Ok(Event::default()
            .event("connected")
            .data(r#"{"status":"connected","stream":"query-logs"}"#));

        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(keepalive_secs));

        loop {
            tokio::select! {
                entry = subscriber.recv() => {
                    match entry {
                        Some(entry) => {
                            match serde_json::to_string(&entry) {
                                Ok(json) => {
                                    trace!(qname = %entry.qname, "Sending query log via SSE");
                                    yield Ok(Event::default()
                                        .event("query")
                                        .data(json));
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to serialize query log entry");
                                }
                            }
                        }
                        None => {
                            debug!("Query log channel closed");
                            yield Ok(Event::default()
                                .event("closed")
                                .data(r#"{"reason":"channel_closed"}"#));
                            break;
                        }
                    }
                }
                _ = keepalive_interval.tick() => {
                    // Send keepalive comment
                    yield Ok(Event::default().comment("keepalive"));
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keepalive"),
    )
}

/// GET /api/audit/security-events/stream
///
/// SSE endpoint for streaming security events in real-time
pub async fn security_events_stream(
    State(state): State<Arc<WebState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let keepalive_secs = state.config().sse.keepalive_secs;

    let stream = async_stream::stream! {
        let bus = match event_bus() {
            Some(bus) => bus,
            None => {
                yield Ok(Event::default()
                    .event("error")
                    .data("Event bus not available"));
                return;
            }
        };

        let mut subscriber = bus.subscribe_security();
        debug!("New SSE subscriber for security events");

        // Send initial connection event
        yield Ok(Event::default()
            .event("connected")
            .data(r#"{"status":"connected","stream":"security-events"}"#));

        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(keepalive_secs));

        loop {
            tokio::select! {
                event = subscriber.recv() => {
                    match event {
                        Some(event) => {
                            match serde_json::to_string(&event) {
                                Ok(json) => {
                                    trace!("Sending security event via SSE");
                                    yield Ok(Event::default()
                                        .event("security")
                                        .data(json));
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to serialize security event");
                                }
                            }
                        }
                        None => {
                            debug!("Security event channel closed");
                            yield Ok(Event::default()
                                .event("closed")
                                .data(r#"{"reason":"channel_closed"}"#));
                            break;
                        }
                    }
                }
                _ = keepalive_interval.tick() => {
                    yield Ok(Event::default().comment("keepalive"));
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keepalive"),
    )
}
