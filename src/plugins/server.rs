//! DNS server plugins
//!
//! Plugins that start DNS servers (UDP, TCP) and handle incoming queries.

use crate::Result;
use crate::dns::Message;
use crate::plugin::{Context, Plugin, Registry};
use crate::server::{RequestContext, RequestHandler, ServerConfig, TcpServer, UdpServer};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info};

// Auto-register using the register macro
crate::register_plugin_builder!(UdpServerPlugin);
crate::register_plugin_builder!(TcpServerPlugin);

/// UDP server plugin
///
/// Starts a UDP DNS server that listens for queries and processes them
/// through a plugin chain.
pub struct UdpServerPlugin {
    /// Address to listen on
    listen_addr: SocketAddr,
    /// Entry point plugin/sequence to execute for each query
    entry_plugin: String,
    /// Shutdown channel sender
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl UdpServerPlugin {
    /// Create a new UDP server plugin
    pub fn new(listen_addr: SocketAddr, entry_plugin: String) -> Self {
        Self {
            listen_addr,
            entry_plugin,
            shutdown_tx: None,
        }
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get the entry plugin name
    pub fn entry_plugin(&self) -> &str {
        &self.entry_plugin
    }

    /// Start the server (called during plugin initialization)
    pub async fn start(&mut self, registry: Arc<Registry>) -> Result<()> {
        let config = ServerConfig {
            udp_addr: Some(self.listen_addr),
            ..Default::default()
        };

        let handler = Arc::new(PluginRequestHandler {
            registry,
            entry_plugin: self.entry_plugin.clone(),
        });

        let server = UdpServer::new(config, handler).await?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn server in background task
        tokio::spawn(async move {
            tokio::select! {
                result = server.run() => {
                    if let Err(e) = result {
                            error!("UDP server error: {}", e);
                        }
                }
                _ = &mut shutdown_rx => {
                    info!("UDP server shutting down");
                }
            }
        });

        info!("udp_server started on {}", self.listen_addr);
        Ok(())
    }
}

impl std::fmt::Debug for UdpServerPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpServerPlugin")
            .field("listen_addr", &self.listen_addr)
            .field("entry_plugin", &self.entry_plugin)
            .finish()
    }
}

#[async_trait]
impl Plugin for UdpServerPlugin {
    fn name(&self) -> &str {
        "udp_server"
    }

    fn init(config: &crate::config::types::PluginConfig) -> Result<Arc<dyn Plugin>> {
        use std::sync::Arc;

        let args = config.effective_args();
        let listen = args
            .get("listen")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0:53");
        let entry = args
            .get("entry")
            .and_then(|v| v.as_str())
            .unwrap_or("main_sequence");
        // Accept shorthand like ":5353" and normalize to "0.0.0.0:5353"
        let listen_parse_str = if listen.starts_with(':') {
            format!("0.0.0.0{}", listen)
        } else {
            listen.to_string()
        };
        let addr = listen_parse_str.parse().map_err(|e| {
            crate::Error::Config(format!("Invalid listen address '{}': {}", listen, e))
        })?;
        Ok(Arc::new(UdpServerPlugin::new(addr, entry.to_string())))
    }

    async fn execute(&self, _ctx: &mut Context) -> Result<()> {
        // Server plugins don't process individual queries through execute()
        Ok(())
    }
}

/// TCP server plugin
///
/// Starts a TCP DNS server that listens for queries and processes them
/// through a plugin chain.
pub struct TcpServerPlugin {
    /// Address to listen on
    listen_addr: SocketAddr,
    /// Entry point plugin/sequence to execute for each query
    entry_plugin: String,
    /// Shutdown channel sender
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TcpServerPlugin {
    /// Create a new TCP server plugin
    pub fn new(listen_addr: SocketAddr, entry_plugin: String) -> Self {
        Self {
            listen_addr,
            entry_plugin,
            shutdown_tx: None,
        }
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get the entry plugin name
    pub fn entry_plugin(&self) -> &str {
        &self.entry_plugin
    }

    /// Start the server (called during plugin initialization)
    pub async fn start(&mut self, registry: Arc<Registry>) -> Result<()> {
        let config = ServerConfig {
            tcp_addr: Some(self.listen_addr),
            ..Default::default()
        };

        let handler = Arc::new(PluginRequestHandler {
            registry,
            entry_plugin: self.entry_plugin.clone(),
        });

        let server = TcpServer::new(config, handler).await?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn server in background task
        tokio::spawn(async move {
            tokio::select! {
                result = server.run() => {
                    if let Err(e) = result {
                            error!("TCP server error: {}", e);
                        }
                }
                _ = &mut shutdown_rx => {
                    info!("TCP server shutting down");
                }
            }
        });

        info!("tcp_server started on {}", self.listen_addr);
        Ok(())
    }
}

impl std::fmt::Debug for TcpServerPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpServerPlugin")
            .field("listen_addr", &self.listen_addr)
            .field("entry_plugin", &self.entry_plugin)
            .finish()
    }
}

#[async_trait]
impl Plugin for TcpServerPlugin {
    fn name(&self) -> &str {
        "tcp_server"
    }

    fn init(config: &crate::config::types::PluginConfig) -> Result<Arc<dyn Plugin>> {
        use std::sync::Arc;

        let args = config.effective_args();
        let listen = args
            .get("listen")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0:53");
        let entry = args
            .get("entry")
            .and_then(|v| v.as_str())
            .unwrap_or("main_sequence");
        // Accept shorthand like ":5353" and normalize to "0.0.0.0:5353"
        let listen_parse_str = if listen.starts_with(':') {
            format!("0.0.0.0{}", listen)
        } else {
            listen.to_string()
        };
        let addr = listen_parse_str.parse().map_err(|e| {
            crate::Error::Config(format!("Invalid listen address '{}': {}", listen, e))
        })?;
        Ok(Arc::new(TcpServerPlugin::new(addr, entry.to_string())))
    }

    async fn execute(&self, _ctx: &mut Context) -> Result<()> {
        // Server plugins don't process individual queries through execute()
        Ok(())
    }
}

/// Request handler that executes plugin chains
struct PluginRequestHandler {
    registry: Arc<Registry>,
    entry_plugin: String,
}

#[async_trait]
impl RequestHandler for PluginRequestHandler {
    async fn handle(&self, ctx: RequestContext) -> Result<Message> {
        let request = ctx.into_message();
        // Save request ID for response
        let request_id = request.id();
        error!("Request ID in handler: {}", request_id);

        // Create context for this request
        let mut ctx = Context::new(request);

        // Execute the entry plugin/sequence
        if let Some(plugin) = self.registry.get(&self.entry_plugin) {
            plugin.execute(&mut ctx).await?;
        }

        // Return the response or an error response
        let mut response = ctx.take_response().unwrap_or_else(|| {
            let mut msg = Message::new();
            msg.set_response_code(crate::dns::ResponseCode::ServFail);
            msg
        });

        error!("Response ID before setting: {}", response.id());

        // Ensure response has correct ID and flags
        response.set_id(request_id);
        response.set_response(true);
        response.set_recursion_available(true);

        error!("Response ID after setting: {}", response.id());

        Ok(response)
    }
}
