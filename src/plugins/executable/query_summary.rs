use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use tracing::info;

/// Simple query summary logger plugin
pub struct QuerySummary {
    msg: String,
}

impl QuerySummary {
    pub fn new(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        let msg = if msg.is_empty() {
            "query summary".to_string()
        } else {
            msg
        };
        Self { msg }
    }

    pub fn quick_setup(s: &str) -> Self {
        Self::new(s)
    }
}

impl fmt::Debug for QuerySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuerySummary")
            .field("msg", &self.msg)
            .finish()
    }
}

#[async_trait]
impl Plugin for QuerySummary {
    fn name(&self) -> &str {
        "query_summary"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Log a concise summary using tracing
        let req = ctx.request();
        let qcount = req.question_count();
        info!(message = %self.msg, questions = qcount, "query summary");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, Question};

    #[tokio::test]
    async fn test_query_summary_basic() {
        let plugin = QuerySummary::new("test");
        let mut req = Message::new();
        req.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = crate::plugin::Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
    }
}
