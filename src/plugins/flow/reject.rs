use crate::RegisterExecPlugin;
use crate::Result;
use crate::dns::{Message, ResponseCode};
use crate::plugin::{Context, ExecPlugin, Plugin};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, RegisterExecPlugin)]
pub struct RejectPlugin {
    rcode: u8,
}

impl RejectPlugin {
    pub fn new(rcode: u8) -> Self {
        Self { rcode }
    }

    pub fn nxdomain() -> Self {
        Self::new(3)
    }

    pub fn refused() -> Self {
        Self::new(5)
    }

    pub fn servfail() -> Self {
        Self::new(2)
    }
}

#[async_trait]
impl Plugin for RejectPlugin {
    fn name(&self) -> &str {
        "reject"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let mut response = Message::new();
        response.set_id(ctx.request().id());
        response.set_response_code(ResponseCode::from_u8(self.rcode));
        response.set_response(true);

        for question in ctx.request().questions() {
            response.add_question(question.clone());
        }

        ctx.set_response(Some(response));
        ctx.set_metadata(crate::plugin::RETURN_FLAG, true);
        Ok(())
    }
}

impl ExecPlugin for RejectPlugin {
    fn quick_setup(prefix: &str, exec_str: &str) -> Result<Arc<dyn Plugin>> {
        if prefix != "reject" {
            return Err(crate::Error::Config(format!(
                "ExecPlugin quick_setup: unsupported prefix '{}', expected 'reject'",
                prefix
            )));
        }

        // allow forms like "nxdomain"/"refused"/"servfail" or numeric codes
        let s = exec_str.trim();
        if s.is_empty() {
            // default to NXDOMAIN
            return Ok(Arc::new(RejectPlugin::nxdomain()));
        }

        let lower = s.to_lowercase();
        match lower.as_str() {
            "nxdomain" | "nx" => Ok(Arc::new(RejectPlugin::nxdomain())),
            "refused" | "ref" => Ok(Arc::new(RejectPlugin::refused())),
            "servfail" | "serv" => Ok(Arc::new(RejectPlugin::servfail())),
            _ => {
                // Try parse numeric
                if let Ok(num) = s.parse::<u8>() {
                    Ok(Arc::new(RejectPlugin::new(num)))
                } else {
                    Err(crate::Error::Config(format!(
                        "reject exec invalid argument: {}",
                        exec_str
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_reject_plugin() {
        let plugin = RejectPlugin::new(3);
        assert_eq!(plugin.name(), "reject");

        let mut request = Message::new();
        request.set_id(12345);
        let mut ctx = Context::new(request);

        plugin.execute(&mut ctx).await.unwrap();

        assert!(ctx.has_response());
        let response = ctx.response().unwrap();
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(response.is_response());
        assert_eq!(response.id(), 12345);

        assert_eq!(
            ctx.get_metadata::<bool>(crate::plugin::RETURN_FLAG),
            Some(&true)
        );
    }

    #[tokio::test]
    async fn test_reject_helpers() {
        let nxdomain = RejectPlugin::nxdomain();
        let refused = RejectPlugin::refused();
        let servfail = RejectPlugin::servfail();

        assert_eq!(nxdomain.rcode, 3);
        assert_eq!(refused.rcode, 5);
        assert_eq!(servfail.rcode, 2);
    }

    #[test]
    fn test_reject_debug() {
        let plugin = RejectPlugin::new(3);
        let debug_str = format!("{:?}", plugin);
        assert!(debug_str.contains("RejectPlugin"));
    }

    #[test]
    fn test_reject_quick_setup_default() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_nxdomain() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "nxdomain").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_nx() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "nx").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_refused() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "refused").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_ref() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "ref").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_servfail() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "servfail").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_serv() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "serv").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_numeric() {
        let plugin = <RejectPlugin as ExecPlugin>::quick_setup("reject", "4").unwrap();
        assert_eq!(plugin.name(), "reject");
    }

    #[test]
    fn test_reject_quick_setup_wrong_prefix() {
        let result = <RejectPlugin as ExecPlugin>::quick_setup("wrong", "nxdomain");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_quick_setup_invalid_arg() {
        let result = <RejectPlugin as ExecPlugin>::quick_setup("reject", "invalid");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reject_copies_questions() {
        use crate::dns::{Question, RecordClass, RecordType};
        let plugin = RejectPlugin::nxdomain();

        let mut request = Message::new();
        request.set_id(100);
        request.add_question(Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));

        let mut ctx = Context::new(request);
        plugin.execute(&mut ctx).await.unwrap();

        let response = ctx.response().unwrap();
        assert_eq!(response.question_count(), 1);
        assert_eq!(response.questions()[0].qname(), "example.com");
    }
}
