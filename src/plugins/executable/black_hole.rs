use crate::dns::{Message, RData, ResourceRecord};
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Black hole plugin: returns configured A/AAAA answers for a query
pub struct BlackHolePlugin {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

impl BlackHolePlugin {
    /// Create from iterator of address strings
    pub fn new_from_strs<I, S>(ips: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for s in ips {
            let s = s.as_ref();
            if let Ok(a4) = s.parse::<Ipv4Addr>() {
                ipv4.push(a4);
            } else if let Ok(a6) = s.parse::<Ipv6Addr>() {
                ipv6.push(a6);
            } else {
                return Err(crate::Error::Other(format!("invalid ip: {}", s)));
            }
        }
        Ok(Self { ipv4, ipv6 })
    }

    fn make_response_for_a(&self, req: &Message) -> Option<Message> {
        if req.question_count() != 1 || self.ipv4.is_empty() {
            return None;
        }
        let q = &req.questions()[0];
        if q.qtype() != crate::dns::types::RecordType::A {
            return None;
        }
        let mut r = Message::new();
        r.set_id(req.id());
        r.set_response(true);
        r.add_question(q.clone());
        for ip in &self.ipv4 {
            r.add_answer(ResourceRecord::new(
                q.qname().to_string(),
                crate::dns::types::RecordType::A,
                crate::dns::types::RecordClass::IN,
                300,
                RData::A(*ip),
            ));
        }
        Some(r)
    }

    fn make_response_for_aaaa(&self, req: &Message) -> Option<Message> {
        if req.question_count() != 1 || self.ipv6.is_empty() {
            return None;
        }
        let q = &req.questions()[0];
        if q.qtype() != crate::dns::types::RecordType::AAAA {
            return None;
        }
        let mut r = Message::new();
        r.set_id(req.id());
        r.set_response(true);
        r.add_question(q.clone());
        for ip in &self.ipv6 {
            r.add_answer(ResourceRecord::new(
                q.qname().to_string(),
                crate::dns::types::RecordType::AAAA,
                crate::dns::types::RecordClass::IN,
                300,
                RData::AAAA(*ip),
            ));
        }
        Some(r)
    }
}

impl fmt::Debug for BlackHolePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlackHolePlugin")
            .field("ipv4_count", &self.ipv4.len())
            .field("ipv6_count", &self.ipv6.len())
            .finish()
    }
}

#[async_trait]
impl Plugin for BlackHolePlugin {
    fn name(&self) -> &str {
        "black_hole"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let req = ctx.request();
        if let Some(resp) = self
            .make_response_for_a(req)
            .or_else(|| self.make_response_for_aaaa(req))
        {
            ctx.set_response(Some(resp));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};

    #[tokio::test]
    async fn test_black_hole_a() {
        let plugin = BlackHolePlugin::new_from_strs(["192.0.2.1"]).unwrap();
        let mut req = Message::new();
        req.add_question(crate::dns::question::Question::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        ));
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        let resp = ctx.response().unwrap();
        assert_eq!(resp.answer_count(), 1);
        if let RData::A(ip) = resp.answers()[0].rdata() {
            assert_eq!(*ip, Ipv4Addr::new(192, 0, 2, 1));
        } else {
            panic!("expected A");
        }
    }
}
