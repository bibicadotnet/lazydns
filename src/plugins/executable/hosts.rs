//! Executable hosts plugin wrapper
//!
//! This file provides the plugin wrapper that implements the `Plugin` trait,
//! starts file watchers for auto-reload, and converts host lookups into DNS
//! `Message` responses. The parsing and lookup core is implemented in
//! `crate::plugins::hosts::Hosts` (kept lightweight and testable).

use crate::dns::{Message, Question, RData, RecordType, ResourceRecord};
use crate::error::Error;
use crate::plugin::{Context, Plugin};
use crate::plugins::hosts::Hosts;
use async_trait::async_trait;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Hosts plugin wrapper: lifecycle, file watching and Plugin impl
pub struct HostsPlugin {
    hosts: Arc<Hosts>,
    files: Vec<PathBuf>,
    auto_reload: bool,
}

impl HostsPlugin {
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(Hosts::new()),
            files: Vec::new(),
            auto_reload: false,
        }
    }

    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = files.into_iter().map(PathBuf::from).collect();
        self
    }

    pub fn with_auto_reload(mut self, enabled: bool) -> Self {
        self.auto_reload = enabled;
        self
    }

    pub fn add_host(&self, domain: String, ip: IpAddr) {
        self.hosts.add_host(domain, ip);
    }

    pub fn remove_host(&self, domain: &str) -> bool {
        self.hosts.remove_host(domain)
    }

    pub fn get_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        self.hosts.get_ips(domain)
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn clear(&self) {
        self.hosts.clear();
    }

    /// Load hosts from configured files (aggregated)
    pub fn load_hosts(&self) -> Result<(), Error> {
        let mut combined = String::new();
        for file_path in &self.files {
            match std::fs::read_to_string(file_path) {
                Ok(c) => {
                    combined.push_str(&c);
                    combined.push('\n');
                }
                Err(e) => warn!(file = ?file_path, error = %e, "Failed to read hosts file"),
            }
        }

        if !combined.is_empty() {
            self.hosts.load_from_string(&combined)?;
        }

        info!(
            entries = self.len(),
            files = self.files.len(),
            "Hosts loaded (wrapper)"
        );
        Ok(())
    }

    /// Start file watcher if auto-reload is enabled
    pub fn start_file_watcher(&self) {
        if !self.auto_reload || self.files.is_empty() {
            return;
        }

        let files = self.files.clone();
        let hosts = Arc::clone(&self.hosts);

        info!(auto_reload = true, files = ?files, "file auto-reload status");

        const DEBOUNCE_MS: u64 = 200;

        crate::utils::spawn_file_watcher(
            "hosts",
            files.clone(),
            DEBOUNCE_MS,
            move |_path, files| {
                let file_name = files
                    .first()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                // Aggregate file contents and reload using core parser
                let start = std::time::Instant::now();
                let mut combined = String::new();

                for file_path in files {
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        combined.push_str(&content);
                        combined.push('\n');
                    } else {
                        warn!(file = ?file_path, "Failed to read hosts file");
                    }
                }

                if !combined.is_empty() {
                    if let Err(e) = hosts.load_from_string(&combined) {
                        warn!(error = %e, "Failed to parse hosts file during auto-reload");
                    }
                }

                let duration = start.elapsed();
                info!(filename = file_name, duration = ?duration, "scheduled auto-reload completed");
            },
        );
    }

    /// Build a DNS response for the provided question and IPs
    fn create_response(&self, question: &Question, ips: &[IpAddr]) -> Message {
        let mut response = Message::new();
        response.set_response(true);
        response.set_authoritative(true);
        response.set_recursion_available(false);

        response.add_question(question.clone());

        let qtype = question.qtype();
        let qname = question.qname().to_string();
        let qclass = question.qclass();

        for ip in ips {
            let record = match (ip, qtype) {
                (IpAddr::V4(ipv4), RecordType::A) => Some(ResourceRecord::new(
                    qname.clone(),
                    RecordType::A,
                    qclass,
                    3600,
                    RData::A(*ipv4),
                )),
                (IpAddr::V6(ipv6), RecordType::AAAA) => Some(ResourceRecord::new(
                    qname.clone(),
                    RecordType::AAAA,
                    qclass,
                    3600,
                    RData::AAAA(*ipv6),
                )),
                _ => None,
            };

            if let Some(r) = record {
                response.add_answer(r);
            }
        }

        response
    }
}

impl Default for HostsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HostsPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostsPlugin")
            .field("entries", &self.hosts.len())
            .finish()
    }
}

#[async_trait]
impl Plugin for HostsPlugin {
    async fn execute(&self, context: &mut Context) -> Result<(), Error> {
        if context.response().is_some() {
            return Ok(());
        }

        let question = match context.request().questions().first() {
            Some(q) => q,
            None => return Ok(()),
        };

        let qtype = question.qtype();
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return Ok(());
        }

        let domain = question.qname();
        if let Some(ips) = self.get_ips(domain) {
            debug!("Hosts plugin: Found {} IPs for {}", ips.len(), domain);

            let mut response = self.create_response(question, &ips);
            response.set_id(context.request().id());
            response.set_response_code(crate::dns::ResponseCode::NoError);

            context.set_response(Some(response));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "hosts"
    }

    fn priority(&self) -> i32 {
        100
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordClass;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_hosts_plugin_a_query() {
        let plugin = HostsPlugin::new();
        plugin.add_host(
            "example.com".to_string(),
            Ipv4Addr::new(93, 184, 216, 34).into(),
        );

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        let response = context.response();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rtype(), RecordType::A);
    }

    #[tokio::test]
    async fn test_hosts_plugin_aaaa_query() {
        let plugin = HostsPlugin::new();
        plugin.add_host(
            "example.com".to_string(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
        );

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        let response = context.response();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rtype(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_hosts_plugin_hostname_first_ipv4_and_ipv6() {
        let plugin = HostsPlugin::new();
        let content = "media.githubusercontent.com 185.199.108.133 2606:50c0:8001::154";
        plugin.load_hosts().unwrap();
        // load_hosts() uses configured files; instead parse directly
        plugin.hosts.load_from_string(content).unwrap();

        // A query
        let mut request_a = Message::new();
        request_a.add_question(Question::new(
            "media.githubusercontent.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx_a = Context::new(request_a);
        plugin.execute(&mut ctx_a).await.unwrap();
        let resp_a = ctx_a.response().unwrap();
        assert_eq!(resp_a.answers().len(), 1);
        assert_eq!(resp_a.answers()[0].rtype(), RecordType::A);

        // AAAA query
        let mut request_aaaa = Message::new();
        request_aaaa.add_question(Question::new(
            "media.githubusercontent.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));
        let mut ctx_aaaa = Context::new(request_aaaa);
        plugin.execute(&mut ctx_aaaa).await.unwrap();
        let resp_aaaa = ctx_aaaa.response().unwrap();
        assert_eq!(resp_aaaa.answers().len(), 1);
        assert_eq!(resp_aaaa.answers()[0].rtype(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_hosts_plugin_no_match() {
        let plugin = HostsPlugin::new();
        plugin.add_host(
            "example.com".to_string(),
            Ipv4Addr::new(93, 184, 216, 34).into(),
        );

        let mut request = Message::new();
        request.add_question(Question::new(
            "notfound.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        // Should not set a response
        assert!(context.response().is_none());
    }

    #[tokio::test]
    async fn test_hosts_plugin_wrong_type() {
        let plugin = HostsPlugin::new();
        // Add IPv4 address
        plugin.add_host(
            "example.com".to_string(),
            Ipv4Addr::new(93, 184, 216, 34).into(),
        );

        // Query for AAAA (IPv6)
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);
        plugin.execute(&mut context).await.unwrap();

        // Should set response but with no answers
        let response = context.response();
        assert!(response.is_some());
        assert_eq!(response.unwrap().answers().len(), 0);
    }

    #[tokio::test]
    async fn test_hosts_plugin_skips_if_response_set() {
        let plugin = HostsPlugin::new();
        plugin.add_host("example.com".to_string(), Ipv4Addr::new(1, 2, 3, 4).into());

        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut context = Context::new(request);

        // Pre-set a response
        let mut pre_response = Message::new();
        pre_response.set_id(999);
        context.set_response(Some(pre_response));

        plugin.execute(&mut context).await.unwrap();

        // Should not modify the pre-set response
        assert_eq!(context.response().unwrap().id(), 999);
    }
}
