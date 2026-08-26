//! RPDB rules scoped to `iif flxrs1` (blueprint §8.9.3).

use std::io;

use flux_core::abi;

use super::attr::AttrBuilder;
use super::consts::{
    FIB_RULE_HDR_LEN, FRA_IIFNAME, FRA_PRIORITY, FRA_TABLE, FR_ACT_TO_TBL, RT_TABLE_UNSPEC,
};
use super::rt_socket::{build_msg, open_route_socket, request_ack};

const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

fn fib_rule_hdr(family: u8) -> [u8; FIB_RULE_HDR_LEN] {
    let mut h = [0u8; FIB_RULE_HDR_LEN];
    h[0] = family;
    h[4] = RT_TABLE_UNSPEC;
    h[5] = FR_ACT_TO_TBL;
    h
}

pub fn add_rpdb_rule(seq: u32, family: u8) -> io::Result<()> {
    let sock = open_route_socket()?;
    let mut attrs = AttrBuilder::new();
    attrs.push_u32(FRA_PRIORITY, abi::RULE_PRIORITY);
    attrs.push_u32(FRA_TABLE, abi::ROUTE_TABLE);
    attrs.push_str(FRA_IIFNAME, abi::VETH_PEER);
    let flags =
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    let hdr = fib_rule_hdr(family);
    let msg = build_msg(RTM_NEWRULE, flags, seq, &hdr, attrs.as_slice());
    request_ack(&sock, &msg)
}

pub fn del_rpdb_rule(seq: u32, family: u8) -> io::Result<()> {
    let sock = open_route_socket()?;
    let mut attrs = AttrBuilder::new();
    attrs.push_u32(FRA_PRIORITY, abi::RULE_PRIORITY);
    attrs.push_u32(FRA_TABLE, abi::ROUTE_TABLE);
    attrs.push_str(FRA_IIFNAME, abi::VETH_PEER);
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    let hdr = fib_rule_hdr(family);
    let msg = build_msg(RTM_DELRULE, flags, seq, &hdr, attrs.as_slice());
    request_ack(&sock, &msg)
}

pub fn install_rules(seq: u32) -> io::Result<()> {
    add_rpdb_rule(seq, libc::AF_INET as u8)?;
    add_rpdb_rule(seq, libc::AF_INET6 as u8)?;
    Ok(())
}

pub fn remove_rules(seq: u32) -> io::Result<()> {
    let _ = del_rpdb_rule(seq, libc::AF_INET as u8);
    let _ = del_rpdb_rule(seq, libc::AF_INET6 as u8);
    Ok(())
}
