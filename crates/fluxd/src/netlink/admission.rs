//! Interface admission predicates (blueprint §3.3, §8.5, §16.9.5).

use std::io;

use flux_core::control_wire::IfaceStatus;

use super::attr::{find_attr, nested_attrs};
use super::consts::{IFINFOMSG_LEN, IFLA_INFO_KIND, IFLA_LINKINFO};
use super::rt_socket::{build_msg, dump, link_flags, link_ifindex, link_ifname, open_route_socket};
use super::tc;

const RTM_GETLINK: u16 = 18;
const RTM_GETADDR: u16 = 22;

/// Hard limit on candidate interfaces (blueprint §8.5).
pub const MAX_CANDIDATES: usize = 64;

#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    pub name: String,
    pub ifindex: i32,
    pub flags: u32,
    pub kind: Option<String>,
    pub has_global_addr: bool,
    pub has_clsact: bool,
    pub clsact_foreign: bool,
}

/// Enumerates links and evaluates admission for capture candidates.
pub fn evaluate_interfaces(seq: u32) -> io::Result<Vec<(LinkSnapshot, IfaceStatus)>> {
    let links = dump_links(seq)?;
    let globals = dump_global_addrs(seq)?;
    let mut out = Vec::new();
    for link in links {
        if out.len() >= MAX_CANDIDATES {
            break;
        }
        let has_global = globals.contains(&link.ifindex);
        let has_clsact = tc::has_clsact(seq + 1, link.ifindex).unwrap_or(false);
        let clsact_foreign = if has_clsact {
            tc::dump_clsact_attrs(seq + 2, link.ifindex)
                .map(|a| a.is_foreign())
                .unwrap_or(true)
        } else {
            false
        };
        let snap = LinkSnapshot {
            name: link.name.clone(),
            ifindex: link.ifindex,
            flags: link.flags,
            kind: link.kind.clone(),
            has_global_addr: has_global,
            has_clsact,
            clsact_foreign,
        };
        let status = classify(&snap);
        if status.status != "excluded" || status.reason.as_deref() != Some("not_candidate") {
            out.push((snap, status));
        }
    }
    Ok(out)
}

fn classify(snap: &LinkSnapshot) -> IfaceStatus {
    let mut status = IfaceStatus {
        name: snap.name.clone(),
        ifindex: snap.ifindex as u32,
        arphrd: snap.kind.clone(),
        entry: None,
        status: "excluded".to_string(),
        prog_id: None,
        prog_tag: None,
        first_applicable: None,
        reason: Some("not_candidate".to_string()),
    };

    if snap.name.starts_with("flxrs") || snap.name == "lo" {
        status.reason = Some("flux_owned".to_string());
        return status;
    }

    if (snap.flags & libc::IFF_UP as u32) == 0 {
        status.reason = Some("iface_down".to_string());
        return status;
    }

    if !snap.has_global_addr {
        status.reason = Some("no_global_addr".to_string());
        return status;
    }

    if !snap.has_clsact {
        status.reason = Some("no_clsact".to_string());
        return status;
    }

    if snap.clsact_foreign {
        status.reason = Some("clsact_foreign".to_string());
        return status;
    }

    status.status = "pending".to_string();
    status.reason = None;
    status
}

struct RawLink {
    name: String,
    ifindex: i32,
    flags: u32,
    kind: Option<String>,
}

fn dump_links(seq: u32) -> io::Result<Vec<RawLink>> {
    let sock = open_route_socket()?;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let hdr = [0u8; IFINFOMSG_LEN];
    let msg = build_msg(RTM_GETLINK, flags, seq, &hdr, &[]);
    let entries = dump(&sock, &msg)?;
    let mut out = Vec::new();
    for payload in entries {
        if let Some(name) = link_ifname(&payload) {
            let ifindex = link_ifindex(&payload).unwrap_or(0) as i32;
            let flags = link_flags(&payload);
            let kind = link_kind(&payload);
            out.push(RawLink {
                name,
                ifindex,
                flags,
                kind,
            });
        }
    }
    Ok(out)
}

fn link_kind(payload: &[u8]) -> Option<String> {
    if payload.len() < IFINFOMSG_LEN {
        return None;
    }
    let attrs = &payload[IFINFOMSG_LEN..];
    let linkinfo = find_attr(attrs, IFLA_LINKINFO)?;
    for (kind, data) in nested_attrs(linkinfo).flatten() {
        if kind == IFLA_INFO_KIND {
            return Some(String::from_utf8_lossy(data).into_owned());
        }
    }
    None
}

fn dump_global_addrs(seq: u32) -> io::Result<Vec<i32>> {
    let sock = open_route_socket()?;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let hdr = [0u8; 8]; // ifaddrmsg
    let msg = build_msg(RTM_GETADDR, flags, seq, &hdr, &[]);
    let entries = dump(&sock, &msg)?;
    let mut out = Vec::new();
    for payload in entries {
        if payload.len() < 8 {
            continue;
        }
        // ifaddrmsg: family, prefixlen, flags, scope at offset 2
        let scope = payload[5];
        if scope != libc::RT_SCOPE_UNIVERSE {
            continue;
        }
        let ifindex = u32::from_ne_bytes(payload[4..8].try_into().unwrap_or([0, 0, 0, 0])) as i32;
        out.push(ifindex);
    }
    Ok(out)
}
