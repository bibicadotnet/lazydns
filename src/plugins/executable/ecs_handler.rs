use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::fmt;
use std::net::IpAddr;

/// Arguments for the ECS handler.
///
/// Port the upstream `ecs_handler` executable plugin options.
/// - `forward`: when true, copy client-provided EDNS0 options to the outgoing query
/// - `send`: when true, derive ECS from client address metadata and attach it
/// - `preset`: optional preset address to use as ECS
/// - `mask4` / `mask6`: source prefix lengths for IPv4/IPv6
#[derive(Deserialize, Clone)]
pub struct EcsArgs {
    pub forward: Option<bool>,
    pub send: Option<bool>,
    pub preset: Option<String>,
    pub mask4: Option<u8>,
    pub mask6: Option<u8>,
}

/// Runtime ECS handler.
///
/// This plugin prepares EDNS0 CLIENT-SUBNET options and writes them into
/// context metadata (`edns0_options` and `edns0_preserve_existing`) so that
/// downstream forwarding logic can include them in upstream queries.
#[derive(Clone)]
pub struct EcsHandler {
    forward: bool,
    send: bool,
    preset: Option<IpAddr>,
    mask4: u8,
    mask6: u8,
}

impl EcsHandler {
    pub fn new(args: EcsArgs) -> Result<Self> {
        let forward = args.forward.unwrap_or(false);
        let send = args.send.unwrap_or(false);
        let mask4 = args.mask4.unwrap_or(24);
        let mask6 = args.mask6.unwrap_or(48);
        if mask4 > 32 || mask6 > 128 {
            return Err(crate::Error::Other("invalid mask".into()));
        }
        let preset = if let Some(p) = args.preset {
            match p.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(e) => return Err(crate::Error::Other(format!("invalid preset addr: {}", e))),
            }
        } else {
            None
        };
        Ok(Self {
            forward,
            send,
            preset,
            mask4,
            mask6,
        })
    }

    #[allow(clippy::manual_div_ceil)]
    /// Build a single EDNS0 CLIENT-SUBNET option tuple `(code, data)` for `ip`.
    ///
    /// The returned `Vec<u8>` follows the format: FAMILY(2) | SOURCE_PREFIX(1) |
    /// SCOPE_PREFIX(1) | ADDRESS (variable). Returns `None` only in impossible
    /// cases — callers can rely on `Some((8, data))` for valid inputs.
    fn make_ecs_option(ip: IpAddr, mask4: u8, mask6: u8) -> Option<(u16, Vec<u8>)> {
        // EDNS Client Subnet option code = 8
        let code = 8u16;
        match ip {
            IpAddr::V4(v4) => {
                let family = 1u16.to_be_bytes();
                let src_mask = mask4.min(32);
                let scope = 0u8;
                let octets = v4.octets();
                let nbytes = ((src_mask as usize) + 7) / 8;
                let mut data = Vec::with_capacity(4 + nbytes);
                data.extend_from_slice(&family);
                data.push(src_mask);
                data.push(scope);
                data.extend_from_slice(&octets[..nbytes]);
                Some((code, data))
            }
            IpAddr::V6(v6) => {
                let family = 2u16.to_be_bytes();
                let src_mask = mask6.min(128);
                let scope = 0u8;
                let octets = v6.octets();
                let nbytes = ((src_mask as usize) + 7) / 8;
                let mut data = Vec::with_capacity(4 + nbytes);
                data.extend_from_slice(&family);
                data.push(src_mask);
                data.push(scope);
                data.extend_from_slice(&octets[..nbytes]);
                Some((code, data))
            }
        }
    }
}

impl fmt::Debug for EcsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcsHandler")
            .field("forward", &self.forward)
            .field("send", &self.send)
            .field("preset", &self.preset)
            .finish()
    }
}

#[async_trait]
impl Plugin for EcsHandler {
    fn name(&self) -> &str {
        "ecs_handler"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // If forward mode, attempt to copy client EDNS0 options from metadata `client_edns0_options`.
        if self.forward {
            if let Some(options) = ctx.get_metadata::<Vec<(u16, Vec<u8>)>>("client_edns0_options") {
                ctx.set_metadata("edns0_options", options.clone());
                ctx.set_metadata("edns0_preserve_existing", true);
                return Ok(());
            }
        }

        // If preset is configured, add ECS option derived from preset
        if let Some(ip) = &self.preset {
            if let Some((code, data)) = EcsHandler::make_ecs_option(*ip, self.mask4, self.mask6) {
                let opt = vec![(code, data)];
                ctx.set_metadata("edns0_options", opt);
                ctx.set_metadata("edns0_preserve_existing", true);
            }
            return Ok(());
        }

        // If send: try to derive client IP from metadata `client_addr` (string)
        if self.send {
            if let Some(addr) = ctx.get_metadata::<String>("client_addr") {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    if let Some((code, data)) =
                        EcsHandler::make_ecs_option(ip, self.mask4, self.mask6)
                    {
                        let opt = vec![(code, data)];
                        ctx.set_metadata("edns0_options", opt);
                        ctx.set_metadata("edns0_preserve_existing", true);
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;
    use std::net::Ipv6Addr;

    #[tokio::test]
    async fn test_ecs_preset_v4() {
        let args = EcsArgs {
            forward: None,
            send: None,
            preset: Some("192.0.2.5".to_string()),
            mask4: Some(24),
            mask6: None,
        };
        let plugin = EcsHandler::new(args).unwrap();
        let req = Message::new();
        let mut ctx = Context::new(req);
        plugin.execute(&mut ctx).await.unwrap();
        let opts = ctx.get_metadata::<Vec<(u16, Vec<u8>)>>("edns0_options");
        assert!(opts.is_some());
    }

    #[tokio::test]
    async fn test_ecs_forward_copies_client_options() {
        let args = EcsArgs {
            forward: Some(true),
            send: None,
            preset: None,
            mask4: None,
            mask6: None,
        };
        let plugin = EcsHandler::new(args).unwrap();
        let req = Message::new();
        let mut ctx = Context::new(req);
        // prepare client_edns0_options metadata and ensure it's copied
        let client_opts: Vec<(u16, Vec<u8>)> = vec![(8u16, vec![0, 1, 24, 0, 192, 0, 2])];
        ctx.set_metadata("client_edns0_options", client_opts.clone());
        plugin.execute(&mut ctx).await.unwrap();
        let got = ctx.get_metadata::<Vec<(u16, Vec<u8>)>>("edns0_options");
        assert!(got.is_some());
        assert_eq!(got.unwrap(), &client_opts);
    }

    #[tokio::test]
    async fn test_ecs_send_derives_from_client_addr() {
        let args = EcsArgs {
            forward: None,
            send: Some(true),
            preset: None,
            mask4: Some(24),
            mask6: Some(56),
        };
        let plugin = EcsHandler::new(args).unwrap();
        let req = Message::new();
        let mut ctx = Context::new(req);
        ctx.set_metadata("client_addr", "192.0.2.7".to_string());
        plugin.execute(&mut ctx).await.unwrap();
        let got = ctx.get_metadata::<Vec<(u16, Vec<u8>)>>("edns0_options");
        assert!(got.is_some());
        // also verify preset/IPv6 path doesn't panic: call make_ecs_option directly
        let _ = EcsHandler::make_ecs_option(IpAddr::V6(Ipv6Addr::LOCALHOST), 24, 56);
    }
}
