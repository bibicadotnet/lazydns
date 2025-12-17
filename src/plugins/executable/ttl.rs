/// TTL plugin: fix or clamp TTLs on responses.
///
/// This plugin can either set a fixed TTL for all response records,
/// or enforce a minimum/maximum TTL range. Use `fix` to set all TTLs to
/// an exact value (>0); otherwise `min` and/or `max` are applied.
///
/// Quick setup strings are supported via `quick_setup`, e.g. "60" (fix=60)
/// or "30-300" (min=30, max=300).
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;

/// TTL plugin: fix or clamp TTLs on responses
/// TTL plugin configuration.
///
/// Fields:
/// - `fix`: If >0, all record TTLs will be set to this value.
/// - `min`: Minimum TTL to enforce when `fix == 0`.
/// - `max`: Maximum TTL to enforce when `fix == 0`.
pub struct TtlPlugin {
    fix: u32,
    min: u32,
    max: u32,
}

impl TtlPlugin {
    /// Create a new `TtlPlugin`.
    ///
    /// - `fix`: if non-zero, sets all TTLs to this value.
    /// - `min`: minimum TTL to clamp to when `fix` is zero.
    /// - `max`: maximum TTL to clamp to when `fix` is zero.
    pub fn new(fix: u32, min: u32, max: u32) -> Self {
        Self { fix, min, max }
    }

    /// Parse a quick configuration string.
    ///
    /// Accepts either a range `"min-max"` or a single fixed value.
    /// Returns a `TtlPlugin` configured accordingly.
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

    /// Apply TTL rules to the response contained in `ctx`.
    ///
    /// If `fix` > 0, all records have their TTL replaced with `fix`.
    /// Otherwise `min` and `max` are enforced where set (>0).
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
    /// Return the plugin name used in configuration.
    fn name(&self) -> &str {
        "ttl"
    }

    /// Execute the plugin for a given request context.
    ///
    /// This will modify any response in the context to adjust TTLs.
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
