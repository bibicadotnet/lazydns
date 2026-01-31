//! Embedded WebUI assets module
//!
//! This module provides embedded static assets for the WebUI when compiled
//! with the `web-embed` feature. Assets are embedded at compile time from
//! the `webui/dist` directory.
//!
//! # Usage
//!
//! Build with embedded assets:
//! ```bash
//! # First build the frontend
//! cd webui && npm run build
//!
//! # Then build with web-embed feature
//! cargo build --release --features web-embed
//! ```
//!
//! The resulting binary will contain all WebUI assets and can be deployed
//! as a single executable without needing external static files.

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Response, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use rust_embed::Embed;

/// Embedded WebUI assets from webui/dist directory
#[derive(Embed)]
#[folder = "webui/dist"]
#[prefix = ""]
pub struct Assets;

/// Serve an embedded asset by path
async fn serve_asset(Path(path): Path<String>) -> impl IntoResponse {
    serve_embedded_file(&path)
}

/// Serve the index.html for SPA routing
async fn serve_index() -> impl IntoResponse {
    serve_embedded_file("index.html")
}

/// Helper function to serve an embedded file
fn serve_embedded_file(path: &str) -> Response<Body> {
    // Try to get the file from embedded assets
    match Assets::get(path) {
        Some(content) => {
            // Determine content type from file extension
            let mime_type = content.metadata.mimetype();

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime_type)
                .header(header::CACHE_CONTROL, cache_control_header(path))
                .body(Body::from(content.data.into_owned()))
                .unwrap()
        }
        None => {
            // For SPA routing, serve index.html for non-asset paths
            if (!path.contains('.') || path.ends_with(".html"))
                && let Some(content) = Assets::get("index.html")
            {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from(content.data.into_owned()))
                    .unwrap();
            }

            // Return 404 for truly missing files
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("Not Found"))
                .unwrap()
        }
    }
}

/// Get appropriate cache control header based on file type
fn cache_control_header(path: &str) -> &'static str {
    if path.ends_with(".html") {
        // HTML files should not be cached to ensure fresh content
        "no-cache"
    } else if path.ends_with(".js") || path.ends_with(".css") {
        // JS and CSS with hashes can be cached for a long time
        "public, max-age=31536000, immutable"
    } else if path.ends_with(".woff2")
        || path.ends_with(".woff")
        || path.ends_with(".ttf")
        || path.ends_with(".eot")
    {
        // Fonts can be cached for a long time
        "public, max-age=31536000, immutable"
    } else if path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".gif")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
    {
        // Images can be cached for a moderate time
        "public, max-age=86400"
    } else {
        // Default: short cache for other assets
        "public, max-age=3600"
    }
}

/// Create a router that serves embedded assets
///
/// This router handles:
/// - Exact file paths from the embedded assets
/// - SPA fallback to index.html for client-side routing
///
/// # Example
///
/// ```ignore
/// use lazydns::web::embedded::embedded_assets_router;
///
/// let app = Router::new()
///     .nest("/api", api_router)
///     .merge(embedded_assets_router());
/// ```
pub fn embedded_assets_router() -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/{*path}", get(serve_asset))
}

/// Check if embedded assets are available
///
/// Returns true if the webui/dist was present at compile time and
/// contains at least an index.html file.
pub fn has_embedded_assets() -> bool {
    Assets::get("index.html").is_some()
}

/// List all embedded asset paths (useful for debugging)
#[allow(dead_code)]
pub fn list_assets() -> Vec<String> {
    Assets::iter().map(|s| s.into_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_control_header() {
        assert_eq!(cache_control_header("index.html"), "no-cache");
        assert_eq!(
            cache_control_header("assets/main.abc123.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_control_header("assets/style.def456.css"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control_header("favicon.ico"), "public, max-age=86400");
        assert_eq!(
            cache_control_header("fonts/inter.woff2"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control_header("data.json"), "public, max-age=3600");
    }

    #[test]
    fn test_has_embedded_assets() {
        // This will be false in tests unless webui/dist exists
        // Just ensure the function doesn't panic
        let _ = has_embedded_assets();
    }

    #[test]
    fn test_list_assets() {
        // Ensure list_assets doesn't panic
        let assets = list_assets();
        // Assets may or may not be present depending on build
        // Just verify we get a vector (length could be 0 if no assets)
        assert!(assets.is_empty() || !assets.is_empty());
    }
}
