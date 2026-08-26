//! Route table 20260 local entries (blueprint §8.9.2).

use std::io;

use flux_core::abi;

use super::attr::AttrBuilder;
use super::consts::{RTA_OIF, RTA_TABLE, RTMSG_LEN, RTN_LOCAL, RT_SCOPE_HOST, RT_TABLE_UNSPEC};
use super::link;
use super::rt_socket::{build_msg, open_route_socket, request_ack};

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

fn rtmsg_header(family: u8) -> [u8; RTMSG_LEN] {
    let mut h = [0u8; RTMSG_LEN];
    h[0] = family;
    h[6] = RT_TABLE_UNSPEC;
    h[7] = abi::ROUTE_PROTO;
    h[8] = RT_SCOPE_HOST;
    h[9] = RTN_LOCAL;
    h
}

pub fn add_local_route(seq: u32, family: u8, lo_ifindex: i32) -> io::Result<()> {
    let sock = open_route_socket()?;
    let mut attrs = AttrBuilder::new();
    attrs.push_u32(RTA_TABLE, abi::ROUTE_TABLE);
    attrs.push_u32(RTA_OIF, lo_ifindex as u32);
    let flags =
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    let hdr = rtmsg_header(family);
    let msg = build_msg(RTM_NEWROUTE, flags, seq, &hdr, attrs.as_slice());
    request_ack(&sock, &msg)
}

pub fn del_local_route(seq: u32, family: u8, lo_ifindex: i32) -> io::Result<()> {
    let sock = open_route_socket()?;
    let mut attrs = AttrBuilder::new();
    attrs.push_u32(RTA_TABLE, abi::ROUTE_TABLE);
    attrs.push_u32(RTA_OIF, lo_ifindex as u32);
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    let hdr = rtmsg_header(family);
    let msg = build_msg(RTM_DELROUTE, flags, seq, &hdr, attrs.as_slice());
    request_ack(&sock, &msg)
}

pub fn lo_ifindex() -> io::Result<i32> {
    link::if_nametoindex("lo")
}

pub fn install_table_routes(seq: u32) -> io::Result<()> {
    let lo = lo_ifindex()?;
    add_local_route(seq, libc::AF_INET as u8, lo)?;
    add_local_route(seq, libc::AF_INET6 as u8, lo)?;
    Ok(())
}

pub fn remove_table_routes(seq: u32) -> io::Result<()> {
    let lo = lo_ifindex()?;
    let _ = del_local_route(seq, libc::AF_INET as u8, lo);
    let _ = del_local_route(seq, libc::AF_INET6 as u8, lo);
    Ok(())
}
