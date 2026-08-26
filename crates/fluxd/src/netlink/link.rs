//! Link operations: veth pair lifecycle (blueprint §8.9.1).

use std::io;

use flux_core::abi;

use super::attr::AttrBuilder;
use super::consts::{
    IFINFOMSG_LEN, IFLA_IFALIAS, IFLA_INFO_DATA, IFLA_INFO_KIND, IFLA_LINKINFO, IFLA_MTU,
    VETH_INFO_PEER,
};
use super::rt_socket::{build_msg, dump, open_route_socket, request_ack};

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;

fn ifinfomsg_header(index: i32, flags: u32, change: u32) -> [u8; IFINFOMSG_LEN] {
    let mut h = [0u8; IFINFOMSG_LEN];
    h[0] = libc::AF_UNSPEC as u8;
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h[0..4].copy_from_slice(&index.to_ne_bytes());
    h
}

/// Creates the Flux veth pair with `NLM_F_CREATE|NLM_F_EXCL`.
pub fn create_veth_pair(seq: u32) -> io::Result<()> {
    let sock = open_route_socket()?;
    let mut peer_attrs = AttrBuilder::new();
    peer_attrs.push_str(libc::IFLA_IFNAME, abi::VETH_PEER);
    peer_attrs.push_u32(IFLA_MTU, abi::VETH_MTU);

    let mut peer_blob = Vec::new();
    peer_blob.extend_from_slice(&ifinfomsg_header(0, 0, 0));
    peer_blob.extend_from_slice(peer_attrs.as_slice());

    let mut veth_data = AttrBuilder::new();
    veth_data.push_bytes(VETH_INFO_PEER, &peer_blob);

    let mut linkinfo = AttrBuilder::new();
    linkinfo.push_str(IFLA_INFO_KIND, "veth");
    linkinfo.push_nested(IFLA_INFO_DATA, &veth_data);

    let mut attrs = AttrBuilder::new();
    attrs.push_str(libc::IFLA_IFNAME, abi::VETH_HOST);
    attrs.push_u32(IFLA_MTU, abi::VETH_MTU);
    attrs.push_nested(IFLA_LINKINFO, &linkinfo);

    let flags =
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    let hdr = ifinfomsg_header(0, 0, 0);
    let msg = build_msg(RTM_NEWLINK, flags, seq, &hdr, attrs.as_slice());
    request_ack(&sock, &msg)?;
    Ok(())
}

pub fn set_alias(seq: u32, ifindex: i32, alias: &str) -> io::Result<()> {
    let sock = open_route_socket()?;
    let mut attrs = AttrBuilder::new();
    attrs.push_str(IFLA_IFALIAS, alias);
    let hdr = ifinfomsg_header(ifindex, 0, 0);
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    let msg = build_msg(RTM_NEWLINK, flags, seq, &hdr, attrs.as_slice());
    request_ack(&sock, &msg)
}

pub fn set_link_up(seq: u32, ifindex: i32) -> io::Result<()> {
    let sock = open_route_socket()?;
    let flags = libc::IFF_UP as u32;
    let hdr = ifinfomsg_header(ifindex, flags, flags);
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    let msg = build_msg(RTM_NEWLINK, flags, seq, &hdr, &[]);
    request_ack(&sock, &msg)
}

pub fn delete_link(seq: u32, ifindex: i32) -> io::Result<()> {
    let sock = open_route_socket()?;
    let hdr = ifinfomsg_header(ifindex, 0, 0);
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    let msg = build_msg(RTM_DELLINK, flags, seq, &hdr, &[]);
    request_ack(&sock, &msg)
}

/// Returns `(host_index, peer_index)` when both ends exist.
pub fn find_veth_indices(seq: u32) -> io::Result<Option<(i32, i32)>> {
    let sock = open_route_socket()?;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let hdr = ifinfomsg_header(0, 0, 0);
    let msg = build_msg(RTM_GETLINK, flags, seq, &hdr, &[]);
    let entries = dump(&sock, &msg)?;
    let mut host = None;
    let mut peer = None;
    for payload in entries {
        if let Some(name) = super::rt_socket::link_ifname(&payload) {
            match name.as_str() {
                abi::VETH_HOST => host = super::rt_socket::link_ifindex(&payload).map(|v| v as i32),
                abi::VETH_PEER => peer = super::rt_socket::link_ifindex(&payload).map(|v| v as i32),
                _ => {}
            }
        }
    }
    match (host, peer) {
        (Some(h), Some(p)) => Ok(Some((h, p))),
        _ => Ok(None),
    }
}

pub fn if_nametoindex(name: &str) -> io::Result<i32> {
    // SAFETY: libc if_nametoindex.
    let idx = unsafe {
        let cname = std::ffi::CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        libc::if_nametoindex(cname.as_ptr())
    };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx as i32)
}
