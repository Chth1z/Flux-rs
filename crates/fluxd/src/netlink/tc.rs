//! TC clsact qdisc and filter ownership (blueprint §8.5, §8.9.4–8.9.5).

use std::io;

use super::attr::{find_attr, nested_attrs, AttrIter};
use super::consts::{
    TCA_BPF_ID, TCA_BPF_TAG, TCA_EGRESS_BLOCK, TCA_INGRESS_BLOCK, TCA_KIND, TCA_OPTIONS, TCMSG_LEN,
    TC_H_CLSACT_HANDLE, TC_H_CLSACT_PARENT, TC_H_MIN_EGRESS_PARENT, TC_H_MIN_INGRESS_PARENT,
};
use super::rt_socket::{build_msg, dump, open_route_socket, request_ack};

const RTM_NEWQDISC: u16 = 36;
const RTM_GETQDISC: u16 = 38;
const RTM_GETTFILTER: u16 = 46;

fn tcmsg_header(ifindex: i32, handle: u32, parent: u32, info: u32) -> [u8; TCMSG_LEN] {
    let mut h = [0u8; TCMSG_LEN];
    h[0] = libc::AF_UNSPEC as u8;
    h[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    h[8..12].copy_from_slice(&handle.to_ne_bytes());
    h[12..16].copy_from_slice(&parent.to_ne_bytes());
    h[16..20].copy_from_slice(&info.to_ne_bytes());
    h
}

/// Creates clsact on `ifindex` with `NLM_F_EXCL`. `EEXIST` is non-fatal.
pub fn ensure_clsact(seq: u32, ifindex: i32) -> io::Result<ClsactState> {
    let sock = open_route_socket()?;
    let mut attrs = AttrBuilder::new();
    attrs.push_str(TCA_KIND, "clsact");
    let flags =
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    let hdr = tcmsg_header(ifindex, TC_H_CLSACT_HANDLE, TC_H_CLSACT_PARENT, 0);
    let msg = build_msg(RTM_NEWQDISC, flags, seq, &hdr, attrs.as_slice());
    match request_ack(&sock, &msg) {
        Ok(()) => Ok(ClsactState::Created),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => classify_existing_clsact(seq, ifindex),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClsactState {
    Created,
    Foreign,
    Present,
}

fn classify_existing_clsact(seq: u32, ifindex: i32) -> io::Result<ClsactState> {
    if dump_clsact_attrs(seq, ifindex)?.is_foreign() {
        Ok(ClsactState::Foreign)
    } else {
        Ok(ClsactState::Present)
    }
}

#[derive(Debug, Default)]
pub struct ClsactAttrs {
    pub ingress_block: bool,
    pub egress_block: bool,
    pub options_nonempty: bool,
}

impl ClsactAttrs {
    pub fn is_foreign(&self) -> bool {
        self.ingress_block || self.egress_block || self.options_nonempty
    }
}

pub fn dump_clsact_attrs(seq: u32, ifindex: i32) -> io::Result<ClsactAttrs> {
    let sock = open_route_socket()?;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let hdr = tcmsg_header(ifindex, 0, TC_H_CLSACT_PARENT, 0);
    let msg = build_msg(RTM_GETQDISC, flags, seq, &hdr, &[]);
    let entries = dump(&sock, &msg)?;
    let mut out = ClsactAttrs::default();
    for payload in entries {
        if payload.len() < TCMSG_LEN {
            continue;
        }
        let attrs = &payload[TCMSG_LEN..];
        for (kind, data) in AttrIter::new(attrs).flatten() {
            match kind {
                TCA_INGRESS_BLOCK => out.ingress_block = true,
                TCA_EGRESS_BLOCK => out.egress_block = true,
                TCA_OPTIONS => {
                    if !data.is_empty() {
                        out.options_nonempty = true;
                    }
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Whether clsact exists on the interface (any qdisc dump returns clsact).
pub fn has_clsact(seq: u32, ifindex: i32) -> io::Result<bool> {
    let sock = open_route_socket()?;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let hdr = tcmsg_header(ifindex, 0, TC_H_CLSACT_PARENT, 0);
    let msg = build_msg(RTM_GETQDISC, flags, seq, &hdr, &[]);
    let entries = dump(&sock, &msg)?;
    Ok(!entries.is_empty())
}

/// One BPF filter entry from a TC dump.
#[derive(Debug, Clone)]
pub struct TcFilterInfo {
    pub parent: u32,
    pub handle: u32,
    pub info: u32,
    pub prog_id: Option<u32>,
    pub prog_tag: Option<[u8; 8]>,
    pub kind: Option<String>,
}

pub fn dump_filters(seq: u32, ifindex: i32, parent: u32) -> io::Result<Vec<TcFilterInfo>> {
    let sock = open_route_socket()?;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let hdr = tcmsg_header(ifindex, 0, parent, 0);
    let msg = build_msg(RTM_GETTFILTER, flags, seq, &hdr, &[]);
    let entries = dump(&sock, &msg)?;
    let mut out = Vec::new();
    for payload in entries {
        if payload.len() < TCMSG_LEN {
            continue;
        }
        let parent = u32::from_ne_bytes(payload[12..16].try_into().unwrap());
        let handle = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
        let info = u32::from_ne_bytes(payload[16..20].try_into().unwrap());
        let attrs = &payload[TCMSG_LEN..];
        let kind = find_attr(attrs, TCA_KIND).map(|b| String::from_utf8_lossy(b).into_owned());
        let mut prog_id = None;
        let mut prog_tag = None;
        if let Some(opts) = find_attr(attrs, TCA_OPTIONS) {
            for (k, d) in nested_attrs(opts).flatten() {
                if k == TCA_BPF_ID && d.len() >= 4 {
                    prog_id = Some(u32::from_ne_bytes(d[0..4].try_into().unwrap()));
                }
                if k == TCA_BPF_TAG && d.len() >= 8 {
                    prog_tag = Some(d[0..8].try_into().unwrap());
                }
            }
        }
        out.push(TcFilterInfo {
            parent,
            handle,
            info,
            prog_id,
            prog_tag,
            kind,
        });
    }
    Ok(out)
}

use super::attr::AttrBuilder;

pub const EGRESS_PARENT: u32 = TC_H_MIN_EGRESS_PARENT;
pub const INGRESS_PARENT: u32 = TC_H_MIN_INGRESS_PARENT;
