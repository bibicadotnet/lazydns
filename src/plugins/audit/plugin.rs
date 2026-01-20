//! Unified audit plugin
//!
//! This plugin consolidates query logging and security event tracking
//! into a single plugin that can be configured under the plugins section.

use super::config::AuditConfig;
use super::logger::AUDIT_LOGGER;
use crate::RegisterPlugin;
use crate::Result;
use crate::config::types::PluginConfig;
use crate::plugin::{Context, Plugin};
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Unified audit plugin that handles both query logging and security events
///
/// Behavior is controlled through configuration:
/// - If `query_log` is configured, queries are logged
/// - If `security_events` is configured and enabled, security events are logged
/// - Multiple audit plugin invocations can be added at different points in the sequence
#[derive(Debug, Clone, RegisterPlugin)]
pub struct AuditPlugin {
    /// Whether query logging is enabled
    query_log_enabled: bool,
    /// Whether to include response details in query logs
    include_response: bool,
    /// Whether to include client IP in query logs
    include_client_ip: bool,
    /// Whether security event logging is enabled
    security_events_enabled: bool,
}

impl AuditPlugin {
    /// Create a new audit plugin from configuration
    pub fn from_config(config: &AuditConfig) -> Self {
        let query_log_enabled = config.query_log.is_some();
        let include_response = config
            .query_log
            .as_ref()
            .map(|q| q.include_response)
            .unwrap_or(true);

        let include_client_ip = config
            .query_log
            .as_ref()
            .map(|q| q.include_client_ip)
            .unwrap_or(true);

        let security_events_enabled = config
            .security_events
            .as_ref()
            .map(|s| s.enabled)
            .unwrap_or(false);

        Self {
            query_log_enabled,
            include_response,
            include_client_ip,
            security_events_enabled,
        }
    }

    /// Initialize the audit logger from configuration
    pub async fn init_from_config(&self, config: AuditConfig) -> Result<()> {
        info!(
            query_log_enabled = self.query_log_enabled,
            security_events_enabled = self.security_events_enabled,
            "Initializing audit plugin"
        );
        AUDIT_LOGGER.init(config).await
    }

    /// Log a query entry
    async fn log_query(&self, ctx: &Context, start_time: Option<Instant>) {
        // Skip if query logging is not enabled
        if !self.query_log_enabled {
            return;
        }

        // Get first question from request
        let request = ctx.request();
        let question = match request.questions().first() {
            Some(q) => q,
            None => {
                tracing::debug!("No question to log");
                return; // No question to log
            }
        };

        tracing::debug!(qname = %question.qname(), "Audit plugin logging query");

        // Get protocol from metadata
        let protocol = ctx
            .get_metadata::<String>("protocol")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        // Build log entry
        let mut entry = super::event::QueryLogEntry::new(
            request.id(),
            protocol,
            question.qname().to_string(),
            format!("{:?}", question.qtype()),
            format!("{:?}", question.qclass()),
        );

        // Add client IP if available and configured
        if self.include_client_ip
            && let Some(ip) = ctx.get_metadata::<IpAddr>("client_ip")
        {
            entry = entry.with_client_ip(*ip);
        }

        // Add response details if available and configured
        if self.include_response
            && let Some(response) = ctx.response()
        {
            let response_time = start_time
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);

            entry = entry.with_response(
                &format!("{:?}", response.response_code()),
                response.answers().len(),
                response_time,
            );

            // Check if cached
            if let Some(cached) = ctx.get_metadata::<bool>("cached") {
                entry = entry.with_cached(*cached);
            }

            // Add answer IPs for A/AAAA queries
            let answers: Vec<String> = response
                .answers()
                .iter()
                .filter_map(|a| match a.rdata() {
                    crate::dns::RData::A(ip) => Some(ip.to_string()),
                    crate::dns::RData::AAAA(ip) => Some(ip.to_string()),
                    _ => None,
                })
                .collect();

            if !answers.is_empty() {
                entry = entry.with_answers(answers);
            }
        }

        // Log the entry
        AUDIT_LOGGER.log_query(entry).await;
    }
}

impl Default for AuditPlugin {
    fn default() -> Self {
        // Default: enable query logging with response details
        Self {
            query_log_enabled: true,
            include_response: true,
            include_client_ip: true,
            security_events_enabled: false,
        }
    }
}

#[async_trait]
impl Plugin for AuditPlugin {
    fn name(&self) -> &str {
        "audit"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        tracing::trace!("Audit plugin execute called");
        // Get start time from metadata if available
        let start_time = ctx.get_metadata::<Instant>("request_start_time").copied();

        // Log query if applicable
        self.log_query(ctx, start_time).await;

        Ok(())
    }

    fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> {
        // Extract audit config from plugin args
        let audit_config: AuditConfig = serde_yaml::from_value(config.args.clone())
            .map_err(|e| crate::Error::Config(format!("Failed to parse audit config: {}", e)))?;

        // Create plugin with configuration-based settings
        let plugin = Arc::new(AuditPlugin::from_config(&audit_config));

        // Initialize the audit logger in background
        let plugin_clone = Arc::clone(&plugin);

        // Use block_in_place for the async init to ensure completion before returning
        if tokio::runtime::Handle::try_current().is_ok() {
            // We're in a tokio runtime
            tokio::spawn(async move {
                if let Err(e) = plugin_clone.init_from_config(audit_config).await {
                    tracing::error!("Failed to initialize audit logger: {}", e);
                }
            });
        } else {
            // Fallback for non-async context (shouldn't happen in practice)
            tracing::warn!("Not in tokio runtime context for audit plugin initialization");
        }

        Ok(plugin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Message, Question, RecordClass, RecordType};

    #[test]
    fn test_audit_plugin_default() {
        let plugin = AuditPlugin::default();
        assert!(plugin.query_log_enabled);
        assert!(plugin.include_response);
        assert!(!plugin.security_events_enabled);
        assert_eq!(plugin.name(), "audit");
    }

    #[test]
    fn test_audit_plugin_from_config_query_log_only() {
        let config = AuditConfig {
            enabled: true,
            query_log: Some(Default::default()),
            security_events: None,
        };
        let plugin = AuditPlugin::from_config(&config);
        assert!(plugin.query_log_enabled);
        assert!(!plugin.security_events_enabled);
    }

    #[test]
    fn test_audit_plugin_from_config_include_response_false() {
        use super::super::config::QueryLogConfig;
        let config = AuditConfig {
            enabled: true,
            query_log: Some(QueryLogConfig {
                include_response: false,
                ..Default::default()
            }),
            security_events: None,
        };
        let plugin = AuditPlugin::from_config(&config);
        assert!(plugin.query_log_enabled);
        assert!(!plugin.include_response);
    }

    #[tokio::test]
    async fn test_audit_plugin_execute() {
        let plugin = AuditPlugin::default();

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".into(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(request);
        ctx.set_metadata("protocol".to_string(), "udp".to_string());

        // Should not fail
        let result = plugin.execute(&mut ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_plugin_execute_with_response() {
        let plugin = AuditPlugin::default();

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".into(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(request);
        ctx.set_metadata("protocol".to_string(), "tcp".to_string());

        // Create a response
        let mut response = Message::new();
        response.set_response(true);
        ctx.set_response(Some(response));

        let result = plugin.execute(&mut ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_plugin_disabled_query_log() {
        let plugin = AuditPlugin {
            query_log_enabled: false,
            include_response: true,
            security_events_enabled: false,
            include_client_ip: true,
        };

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".into(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(request);
        ctx.set_metadata("protocol".to_string(), "udp".to_string());

        // Should execute but not log anything
        let result = plugin.execute(&mut ctx).await;
        assert!(result.is_ok());
    }
}
