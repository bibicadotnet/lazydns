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
use tracing::{debug, warn};

#[cfg(all(feature = "web-embed", webui_dist))]
use rust_embed::Embed;

/// Embedded WebUI assets from webui/dist directory
#[cfg(all(feature = "web-embed", webui_dist))]
#[derive(Embed)]
#[folder = "webui/dist"]
#[prefix = ""]
pub struct Assets;

// Helper to fetch asset data and mime type in a unified format
#[allow(dead_code)]
fn assets_get(path: &str) -> Option<(Vec<u8>, String)> {
    #[cfg(all(feature = "web-embed", webui_dist))]
    {
        Assets::get(path).map(|content| {
            (
                content.data.into_owned(),
                content.metadata.mimetype().to_string(),
            )
        })
    }

    #[cfg(not(all(feature = "web-embed", webui_dist)))]
    {
        let _ = path; // silence unused variable warning
        None
    }
}

// Unified asset iterator
#[allow(dead_code)]
fn assets_list() -> Vec<String> {
    #[cfg(all(feature = "web-embed", webui_dist))]
    {
        Assets::iter().map(|s| s.into_owned()).collect()
    }

    #[cfg(not(all(feature = "web-embed", webui_dist)))]
    {
        Vec::new()
    }
}

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
    debug!("Attempting to serve embedded file: {}", path);

    // Try to get the file from embedded assets
    match assets_get(path) {
        Some((data, mime_type)) => {
            debug!("Found embedded file: {} ({})", path, mime_type);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime_type)
                .header(header::CACHE_CONTROL, cache_control_header(path))
                .body(Body::from(data))
                .unwrap()
        }
        None => {
            debug!("File not found in embedded assets: {}", path);

            // For SPA routing, serve index.html for non-asset paths
            if (!path.contains('.') || path.ends_with(".html"))
                && let Some((data, _mime)) = assets_get("index.html")
            {
                debug!("Serving index.html for SPA route: {}", path);
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from(data))
                    .unwrap();
            }

            // Return 404 for truly missing files
            warn!("Embedded asset not found: {}", path);
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
    // Debug: log all embedded assets on startup
    let assets = list_assets();
    if !assets.is_empty() {
        debug!("Embedded assets available (total: {})", assets.len());
        for asset in assets.iter().take(10) {
            debug!("  - {}", asset);
        }
        if assets.len() > 10 {
            debug!("  ... and {} more", assets.len() - 10);
        }
    } else {
        warn!("No embedded assets found!");
    }

    Router::new()
        .route("/", get(serve_index))
        .route("/{*path}", get(serve_asset))
}

/// Check if embedded assets are available
///
/// Returns true if the webui/dist was present at compile time and
/// contains at least an index.html file.
pub fn has_embedded_assets() -> bool {
    assets_get("index.html").is_some()
}

/// List all embedded asset paths (useful for debugging)
#[allow(dead_code)]
pub fn list_assets() -> Vec<String> {
    assets_list()
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
