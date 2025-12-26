use crate::Result;
use crate::plugin::{Context, ExecPlugin, Plugin};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::info;

crate::register_exec_plugin_builder!(QuerySummaryPlugin);

/// Query summary plugin that records a concise summary of the request
/// questions into the request `Context` metadata and emits a short
/// informational log entry.
///
/// Behavior
/// - For each question in the incoming request this plugin formats a
///   short fragment `"<qname> <qclass> <qtype>"` and joins fragments with
///   `"; "` into one summary string.
/// - The summary string is stored in the request metadata under the
///   user-provided `metadata_key` (so downstream plugins can read it).
/// - An `info`-level tracing event is also emitted with the same summary.
///
/// Example
/// ```rust
/// use lazydns::plugins::executable::QuerySummaryPlugin;
/// use lazydns::plugin::Context;
/// use lazydns::dns::{Message, Question, RecordType, RecordClass};
///
/// // Create plugin that stores summary under "summary" key
/// let plugin = QuerySummaryPlugin::new("summary");
///
/// // Build a request message with one question
/// let mut req = Message::new();
/// req.add_question(Question::new("example.com".into(), RecordType::A, RecordClass::IN));
/// let mut ctx = Context::new(req);
///
/// // Execute plugin (async context omitted for brevity)
/// // plugin.execute(&mut ctx).await?;
/// // let s = ctx.get_metadata::<String>("summary").unwrap();
/// ```
///
/// Notes
/// - This plugin is lightweight and side-effect free (it only writes to
///   in-memory request metadata and logs); it is suitable for inclusion
///   in both production and test executor graphs.
/// - Use a descriptive `metadata_key` when composing larger executor
///   pipelines to avoid metadata name collisions.
#[derive(Debug, Clone)]
pub struct QuerySummaryPlugin {
    /// Metadata key used to store the generated summary string.
    metadata_key: String,
}

impl QuerySummaryPlugin {
    /// Create a new `QuerySummaryPlugin` which stores the generated summary
    /// under `metadata_key` in the request `Context`.
    pub fn new(metadata_key: impl Into<String>) -> Self {
        Self {
            metadata_key: metadata_key.into(),
        }
    }

    /// Convenience constructor kept for API compatibility with older
    /// helper names; equivalent to `QuerySummaryPlugin::new`.
    pub fn quick_setup(s: &str) -> Self {
        Self::new(s)
    }
}

#[async_trait]
impl Plugin for QuerySummaryPlugin {
    fn name(&self) -> &str {
        "query_summary"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let summary: Vec<String> = ctx
            .request()
            .questions()
            .iter()
            .map(|q| format!("{} {} {}", q.qname(), q.qclass(), q.qtype()))
            .collect();

        let joined = summary.join("; ");
        // store in metadata and also log a concise info entry
        ctx.set_metadata(self.metadata_key.clone(), joined.clone());
        info!(key = %self.metadata_key, summary = %joined, "query summary");
        Ok(())
    }
}

impl ExecPlugin for QuerySummaryPlugin {
    /// Parse a quick configuration string for query_summary plugin.
    ///
    /// The exec_str should be the metadata key to use for storing the summary.
    /// Example: "summary" or "query_info"
    fn quick_setup(prefix: &str, exec_str: &str) -> Result<Arc<dyn Plugin>> {
        if prefix != "query_summary" {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected 'query_summary'",
                prefix
            )));
        }

        let metadata_key = exec_str.trim();
        if metadata_key.is_empty() {
            return Err(crate::Error::Config(
                "query_summary requires a metadata key (e.g., 'query_summary summary')".to_string(),
            ));
        }

        let plugin = QuerySummaryPlugin::new(metadata_key);
        Ok(Arc::new(plugin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question};

    #[tokio::test]
    async fn test_query_summary_basic() {
        let plugin = QuerySummaryPlugin::new("summary");
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = crate::plugin::Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();

        let s = ctx
            .get_metadata::<String>("summary")
            .expect("summary metadata");
        assert!(s.contains("example.com"));
    }

    #[tokio::test]
    async fn test_query_summary_sets_metadata() {
        let mut request = Message::new();
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::AAAA,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(request);
        let plugin = QuerySummaryPlugin::new("summary");

        plugin.execute(&mut ctx).await.unwrap();
        let summary = ctx.get_metadata::<String>("summary").unwrap();

        assert!(summary.contains("example.com"));
        assert!(summary.contains("A"));
        assert!(summary.contains("AAAA"));
    }
}
