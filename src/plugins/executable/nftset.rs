//! NftSet executable plugin.
//!
//! This plugin inspects DNS response answers and emits nftables set
//! entries (CIDR prefixes) for A/AAAA records. On Linux it will try to
//! call the `nft` command to add elements to the configured set; on
//! non-Linux platforms it records additions in the request `Context`
//! metadata under `"nftset_added_v4"` and `"nftset_added_v6"`.
//!
//! Quick-setup accepts a compact shorthand used by some configurations:
//! `"<family>,<table>,<set>,<addr_type>,<mask> ..."` (max two fields).
//! Example: `"inet,my_table,my_set,ipv4_addr,24"`.
//!
//! Note: `SetArgs` contains optional table family and table names which
//! are used when attempting to run `nft` with the configured parameters.
use crate::dns::RData;
use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::info;

#[derive(Debug, Deserialize, Clone)]
pub struct NftSetArgs {
    /// Optional configuration for IPv4 elements (table, set and mask).
    pub ipv4: Option<SetArgs>,
    /// Optional configuration for IPv6 elements (table, set and mask).
    pub ipv6: Option<SetArgs>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SetArgs {
    /// Optional nftables table family (e.g. `inet`).
    pub table_family: Option<String>,
    /// Optional nftables table name.
    pub table: Option<String>,
    /// Optional nftables set name.
    pub set: Option<String>,
    /// Prefix length mask to apply when synthesizing CIDRs.
    pub mask: Option<u8>,
}

pub struct NftSetPlugin {
    args: NftSetArgs,
}

impl NftSetPlugin {
    pub fn new(args: NftSetArgs) -> Self {
        NftSetPlugin { args }
    }

    /// QuickSetup format: [{ip|ip6|inet},table_name,set_name,{ipv4_addr|ipv6_addr},mask] *2
    /// e.g. "inet,my_table,my_set,ipv4_addr,24 inet,my_table,my_set,ipv6_addr,48"
    pub fn quick_setup(s: &str) -> Result<Self> {
        let fs: Vec<&str> = s.split_whitespace().collect();
        if fs.len() > 2 {
            return Err(crate::Error::Other(format!(
                "expect no more than 2 fields, got {}",
                fs.len()
            )));
        }
        let mut args = NftSetArgs {
            ipv4: None,
            ipv6: None,
        };
        for args_str in fs {
            let ss: Vec<&str> = args_str.split(',').collect();
            if ss.len() != 5 {
                return Err(crate::Error::Other(format!(
                    "invalid args, expect 5 fields, got {}",
                    ss.len()
                )));
            }
            let m: i32 = ss[4]
                .parse()
                .map_err(|e| crate::Error::Other(format!("invalid mask, {}", e)))?;
            let sa = SetArgs {
                table_family: Some(ss[0].to_string()),
                table: Some(ss[1].to_string()),
                set: Some(ss[2].to_string()),
                mask: Some(m as u8),
            };
            match ss[3] {
                "ipv4_addr" => args.ipv4 = Some(sa),
                "ipv6_addr" => args.ipv6 = Some(sa),
                other => return Err(crate::Error::Other(format!("invalid ip type, {}", other))),
            }
        }
        Ok(NftSetPlugin::new(args))
    }

    fn make_v4_prefix(ip: &Ipv4Addr, mask: u8) -> String {
        let mask = mask.min(32);
        let ip_u32 = u32::from_be_bytes(ip.octets());
        let net = ip_u32 & (!0u32 << (32 - mask as u32));
        let bytes = net.to_be_bytes();
        // Return canonical CIDR like "192.0.2.0/24" (no spaces).
        format!(
            "{}.{}.{}.{} /{}",
            bytes[0], bytes[1], bytes[2], bytes[3], mask
        )
        .replace(' ', "")
    }

    fn make_v6_prefix(ip: &Ipv6Addr, mask: u8) -> String {
        let mask = mask.min(128);
        let mut bytes = ip.octets();
        let mut bits = mask as usize;
        for b in bytes.iter_mut() {
            if bits >= 8 {
                bits -= 8;
                continue;
            }
            if bits == 0 {
                *b = 0;
            } else {
                let keep = (!0u8) << (8 - bits);
                *b &= keep;
                bits = 0;
            }
        }
        use std::net::Ipv6Addr;
        let addr = Ipv6Addr::from(bytes);
        // Return canonical IPv6 CIDR like "2001:db8::/48".
        format!("{}/{}", addr, mask)
    }
}

impl fmt::Debug for NftSetPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NftSetPlugin").finish()
    }
}

#[async_trait]
impl Plugin for NftSetPlugin {
    fn name(&self) -> &str {
        "nftset"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        if let Some(resp) = ctx.response() {
            let mut added_v4 = Vec::new();
            let mut added_v6 = Vec::new();
            for rr in resp.answers() {
                match rr.rdata() {
                    RData::A(ipv4) => {
                        if let Some(sa) = &self.args.ipv4 {
                            if let Some(set_name) = &sa.set {
                                let mask = sa.mask.unwrap_or(24);
                                let prefix = Self::make_v4_prefix(ipv4, mask);
                                info!(set = %set_name, cidr = %prefix, "nftset add");
                                added_v4.push((set_name.clone(), prefix));
                            }
                        }
                    }
                    RData::AAAA(ipv6) => {
                        if let Some(sa) = &self.args.ipv6 {
                            if let Some(set_name) = &sa.set {
                                let mask = sa.mask.unwrap_or(48);
                                let prefix = Self::make_v6_prefix(ipv6, mask);
                                info!(set = %set_name, cidr = %prefix, "nftset add");
                                added_v6.push((set_name.clone(), prefix));
                            }
                        }
                    }
                    _ => {}
                }
            }
            // On Linux, try to apply to system nftables; otherwise keep metadata.
            #[cfg(target_os = "linux")]
            {
                use std::process::Command;
                for (set_name, prefix) in &added_v4 {
                    if let Some(sa) = &self.args.ipv4 {
                        if let (Some(table_family), Some(table)) = (&sa.table_family, &sa.table) {
                            let status = Command::new("nft")
                                .args([
                                    "add",
                                    "element",
                                    table_family.as_str(),
                                    table.as_str(),
                                    set_name.as_str(),
                                    "{",
                                    prefix.as_str(),
                                    "}",
                                ])
                                .status();
                            match status {
                                Ok(s) if s.success() => {}
                                Ok(s) => {
                                    tracing::warn!(table = %table, set = %set_name, prefix = %prefix, status = ?s, "nft command returned non-zero exit status, continuing");
                                }
                                Err(e) => {
                                    tracing::warn!(table = %table, set = %set_name, prefix = %prefix, error = %e, "failed to spawn nft command, continuing");
                                }
                            }
                        }
                    }
                }
                for (set_name, prefix) in &added_v6 {
                    if let Some(sa) = &self.args.ipv6 {
                        if let (Some(table_family), Some(table)) = (&sa.table_family, &sa.table) {
                            let status = Command::new("nft")
                                .args([
                                    "add",
                                    "element",
                                    table_family.as_str(),
                                    table.as_str(),
                                    set_name.as_str(),
                                    "{",
                                    prefix.as_str(),
                                    "}",
                                ])
                                .status();
                            match status {
                                Ok(s) if s.success() => {}
                                Ok(s) => {
                                    tracing::warn!(table = %table, set = %set_name, prefix = %prefix, status = ?s, "nft command returned non-zero exit status, continuing");
                                }
                                Err(e) => {
                                    tracing::warn!(table = %table, set = %set_name, prefix = %prefix, error = %e, "failed to spawn nft command, continuing");
                                }
                            }
                        }
                    }
                }
            }

            if !added_v4.is_empty() {
                ctx.set_metadata("nftset_added_v4", added_v4);
            }
            if !added_v6.is_empty() {
                ctx.set_metadata("nftset_added_v6", added_v6);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::types::{RecordClass, RecordType};
    use crate::dns::{Message, ResourceRecord};

    #[tokio::test]
    async fn test_nftset_v4_add() {
        let sa = SetArgs {
            table_family: Some("inet".into()),
            table: Some("t".into()),
            set: Some("s".into()),
            mask: Some(24),
        };
        let args = NftSetArgs {
            ipv4: Some(sa),
            ipv6: None,
        };
        let plugin = NftSetPlugin::new(args);
        let mut msg = Message::new();
        msg.add_answer(ResourceRecord::new(
            "example.com".into(),
            RecordType::A,
            RecordClass::IN,
            300,
            crate::dns::RData::A("192.0.2.5".parse().unwrap()),
        ));
        let mut ctx = crate::plugin::Context::new(crate::dns::Message::new());
        ctx.set_response(Some(msg));
        plugin.execute(&mut ctx).await.unwrap();
        let added = ctx
            .get_metadata::<Vec<(String, String)>>("nftset_added_v4")
            .unwrap();
        assert_eq!(added.len(), 1);
    }
}
