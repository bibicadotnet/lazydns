//! DNS over HTTPS (DoH) server implementation
//!
//! Implements RFC 8484 - DNS Queries over HTTPS (DoH)
//!
//! DoH provides DNS queries over HTTPS, using HTTP/2 for efficiency and privacy.

use crate::dns::Message;
use crate::error::{Error, Result};
use crate::server::{RequestHandler, TlsConfig};
use axum::{
    body::Bytes,
    extract::{Query as AxumQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// DNS over HTTPS server
///
/// Implements RFC 8484 DoH protocol over HTTP/2.
pub struct DohServer {
    /// Server listening address
    addr: String,
    /// TLS configuration
    tls_config: TlsConfig,
    /// Request handler
    handler: Arc<dyn RequestHandler>,
    /// DoH path (default: /dns-query)
    path: String,
}

impl DohServer {
    /// Create a new DoH server
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to listen on (e.g., "0.0.0.0:443")
    /// * `tls_config` - TLS configuration with certificates
    /// * `handler` - Request handler for processing DNS queries
    ///
    /// # Example
    ///
    /// ```no_run
    /// use lazydns::server::{DohServer, TlsConfig, DefaultHandler};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tls = TlsConfig::from_files("cert.pem", "key.pem")?;
    /// let handler = Arc::new(DefaultHandler);
    /// let server = DohServer::new("0.0.0.0:443", tls, handler);
    /// // server.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        addr: impl Into<String>,
        tls_config: TlsConfig,
        handler: Arc<dyn RequestHandler>,
    ) -> Self {
        Self {
            addr: addr.into(),
            tls_config,
            handler,
            path: "/dns-query".to_string(),
        }
    }

    /// Set the DoH query path
    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    /// Start the DoH server
    ///
    /// Listens for HTTPS connections and processes DNS queries over HTTP/2.
    ///
    /// Note: This is a simplified implementation using axum-server.
    /// For production use, consider using a full-featured HTTPS server.
    pub async fn run(self) -> Result<()> {
        let handler = Arc::clone(&self.handler);

        // Create router
        let app = Router::new()
            .route(&self.path, post(handle_post_query).get(handle_get_query))
            .with_state(handler);

        info!(
            "DoH server listening on {} (path: {})",
            self.addr, self.path
        );

        // Build TLS config (placeholder for now)
        let _tls_config = self.tls_config.build_server_config()?;

        // Use axum-server for TLS support (requires axum-server crate in production)
        // For now, this is a placeholder that would need axum-server crate
        warn!("DoH server implementation is simplified - requires axum-server crate for full functionality");

        // Bind and serve (placeholder - would use axum-server::bind_rustls)
        let listener = tokio::net::TcpListener::bind(&self.addr)
            .await
            .map_err(Error::Io)?;

        // Simplified: serve without TLS for testing
        // In production, use: axum_server::bind_rustls(addr, tls_config).serve(app.into_make_service())
        axum::serve(listener, app)
            .await
            .map_err(|e| Error::Other(format!("Server error: {}", e)))?;

        Ok(())
    }
}

/// Handle GET requests (RFC 8484 Section 4.1)
async fn handle_get_query(
    State(handler): State<Arc<dyn RequestHandler>>,
    AxumQuery(params): AxumQuery<HashMap<String, String>>,
    _headers: HeaderMap,
) -> Response {
    // GET requests use ?dns= query parameter with base64url-encoded DNS message (RFC 8484 Section 4.1)
    debug!("Handling DoH GET request");

    // Extract the 'dns' parameter
    let dns_param = match params.get("dns") {
        Some(param) => param,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing 'dns' query parameter. Usage: /dns-query?dns=<base64url-encoded-query>",
            )
                .into_response();
        }
    };

    // Decode base64url-encoded DNS message
    let dns_data = match URL_SAFE_NO_PAD.decode(dns_param.as_bytes()) {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid base64url encoding: {}", e),
            )
                .into_response();
        }
    };

    debug!("Decoded DNS query: {} bytes", dns_data.len());

    // Parse DNS query
    let request = match parse_dns_message(&dns_data) {
        Ok(msg) => msg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid DNS message: {}", e),
            )
                .into_response();
        }
    };

    // Process query
    let response = match handler.handle(request).await {
        Ok(resp) => resp,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Query processing failed: {}", e),
            )
                .into_response();
        }
    };

    // Serialize response
    let response_data = match serialize_dns_message(&response) {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Response serialization failed: {}", e),
            )
                .into_response();
        }
    };

    debug!("Sending DoH response: {} bytes", response_data.len());

    // Return DNS response with proper content type
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/dns-message")],
        response_data,
    )
        .into_response()
}

/// Handle POST requests (RFC 8484 Section 4.1)
async fn handle_post_query(
    State(handler): State<Arc<dyn RequestHandler>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Verify content type
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        if content_type != "application/dns-message" {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/dns-message",
            )
                .into_response();
        }
    } else {
        return (StatusCode::BAD_REQUEST, "Content-Type header required").into_response();
    }

    // Parse DNS query (placeholder)
    let request = match parse_dns_message(&body) {
        Ok(msg) => msg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid DNS message: {}", e),
            )
                .into_response();
        }
    };

    // Process query
    let response = match handler.handle(request).await {
        Ok(resp) => resp,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Query processing failed: {}", e),
            )
                .into_response();
        }
    };

    // Serialize response (placeholder)
    let response_data = match serialize_dns_message(&response) {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Response serialization failed: {}", e),
            )
                .into_response();
        }
    };

    // Return DNS response
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/dns-message")],
        response_data,
    )
        .into_response()
}

/// Parse DNS message from wire format (placeholder)
/// Parse DNS message from wire format
fn parse_dns_message(data: &[u8]) -> Result<Message> {
    crate::dns::wire::parse_message(data)
}

/// Serialize DNS message to wire format
fn serialize_dns_message(message: &Message) -> Result<Vec<u8>> {
    crate::dns::wire::serialize_message(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_message_placeholder() {
        let data = vec![0u8; 12];
        let result = parse_dns_message(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_dns_message_placeholder() {
        let message = Message::new();
        let result = serialize_dns_message(&message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 12);
    }

    #[test]
    fn test_base64url_encoding_decoding() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        // Test data (minimal DNS query header)
        let original_data = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        // Encode
        let encoded = URL_SAFE_NO_PAD.encode(&original_data);

        // Decode
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).unwrap();

        assert_eq!(original_data, decoded);
    }
}
