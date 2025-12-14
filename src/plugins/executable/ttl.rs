use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;

/// TTL plugin: fix or clamp TTLs on responses
pub struct TtlPlugin {
    fix: u32,
    min: u32,
    max: u32,
}

impl TtlPlugin {
    pub fn new(fix: u32, min: u32, max: u32) -> Self {
        Self { fix, min, max }
    }

    /// Quick setup: accept either "min-max" or a fixed value string
    pub fn quick_setup(s: &str) -> Result<Self> {
        if s.contains('-') {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            let l = parts[0].parse::<u32>().unwrap_or(0);
            let u = parts[1].parse::<u32>().unwrap_or(0);
            Ok(Self::new(0, l, u))
        } else {
            let f = s.parse::<u32>().unwrap_or(0);
            Ok(Self::new(f, 0, 0))
        }
    }

    fn apply(&self, ctx: &mut Context) {
        if let Some(resp) = ctx.response_mut() {
            if self.fix > 0 {
                for rr in resp.answers_mut().iter_mut() {
                    rr.set_ttl(self.fix);
                }
                for rr in resp.authority_mut().iter_mut() {
                    rr.set_ttl(self.fix);
                }
                for rr in resp.additional_mut().iter_mut() {
                    rr.set_ttl(self.fix);
                }
            } else {
                if self.min > 0 {
                    for rr in resp.answers_mut().iter_mut() {
                        if rr.ttl() < self.min {
                            rr.set_ttl(self.min);
                        }
                    }
                    for rr in resp.authority_mut().iter_mut() {
                        if rr.ttl() < self.min {
                            rr.set_ttl(self.min);
                        }
                    }
                    for rr in resp.additional_mut().iter_mut() {
                        if rr.ttl() < self.min {
                            rr.set_ttl(self.min);
                        }
                    }
                }
                if self.max > 0 {
                    for rr in resp.answers_mut().iter_mut() {
                        if rr.ttl() > self.max {
                            rr.set_ttl(self.max);
                        }
                    }
                    for rr in resp.authority_mut().iter_mut() {
                        if rr.ttl() > self.max {
                            rr.set_ttl(self.max);
                        }
                    }
                    for rr in resp.additional_mut().iter_mut() {
                        if rr.ttl() > self.max {
                            rr.set_ttl(self.max);
                        }
                    }
                }
            }
        }
    }
}

impl fmt::Debug for TtlPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TtlPlugin").finish()
    }
}

#[async_trait]
impl Plugin for TtlPlugin {
    fn name(&self) -> &str {
        "ttl"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        self.apply(ctx);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, ResourceRecord};

    #[tokio::test]
    async fn test_ttl_fix() {
        let plugin = TtlPlugin::new(10, 0, 0);
        let mut msg = Message::new();
        msg.add_answer(ResourceRecord::new(
            "a".into(),
            RecordType::A,
            RecordClass::IN,
            300,
            crate::dns::RData::A(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        ));
        let mut ctx = crate::plugin::Context::new(crate::dns::Message::new());
        ctx.set_response(Some(msg));
        plugin.execute(&mut ctx).await.unwrap();
        let resp = ctx.response().unwrap();
        assert_eq!(resp.answers()[0].ttl(), 10);
    }
}
