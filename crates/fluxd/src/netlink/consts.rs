//! Linux rtnetlink / TC constants not exposed by `libc`.

/// `IFLA_LINKINFO`
pub const IFLA_LINKINFO: u16 = 18;
/// `IFLA_INFO_KIND`
pub const IFLA_INFO_KIND: u16 = 1;
/// `IFLA_INFO_DATA`
pub const IFLA_INFO_DATA: u16 = 2;
/// `VETH_INFO_PEER`
pub const VETH_INFO_PEER: u16 = 1;
/// `IFLA_IFALIAS`
pub const IFLA_IFALIAS: u16 = 17;
/// `IFLA_MTU`
pub const IFLA_MTU: u16 = 4;

/// `RTA_TABLE`
pub const RTA_TABLE: u16 = 15;
/// `RTA_OIF`
pub const RTA_OIF: u16 = 4;
/// `RT_TABLE_UNSPEC`
pub const RT_TABLE_UNSPEC: u8 = 0;
/// `RT_SCOPE_HOST`
pub const RT_SCOPE_HOST: u8 = 254;
/// `RTN_LOCAL`
pub const RTN_LOCAL: u8 = 2;

/// `FRA_PRIORITY`
pub const FRA_PRIORITY: u16 = 6;
/// `FRA_TABLE`
pub const FRA_TABLE: u16 = 15;
/// `FRA_IIFNAME`
pub const FRA_IIFNAME: u16 = 8;
/// `FR_ACT_TO_TBL`
pub const FR_ACT_TO_TBL: u8 = 1;

/// `TCA_KIND`
pub const TCA_KIND: u16 = 1;
/// `TCA_OPTIONS`
pub const TCA_OPTIONS: u16 = 2;
/// `TCA_INGRESS_BLOCK`
pub const TCA_INGRESS_BLOCK: u16 = 13;
/// `TCA_EGRESS_BLOCK`
pub const TCA_EGRESS_BLOCK: u16 = 14;
/// `TCA_BPF_FD`
pub const TCA_BPF_FD: u16 = 6;
/// `TCA_BPF_NAME`
pub const TCA_BPF_NAME: u16 = 7;
/// `TCA_BPF_FLAGS`
pub const TCA_BPF_FLAGS: u16 = 8;
/// `TCA_BPF_ID`
pub const TCA_BPF_ID: u16 = 11;
/// `TCA_BPF_TAG`
pub const TCA_BPF_TAG: u16 = 10;
/// `TCA_BPF_FLAG_ACT_DIRECT`
pub const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;

/// `TC_H_MAJ` mask for clsact major handle.
pub const TC_H_MAJ_MASK: u32 = 0xFFFF_0000;
/// clsact qdisc handle `TC_H_MAKE(TC_H_CLSACT, 0)`.
pub const TC_H_CLSACT_HANDLE: u32 = 0xFFFF_0000;
/// clsact parent `TC_H_CLSACT`.
pub const TC_H_CLSACT_PARENT: u32 = 0xFFFF_FFF1;
/// egress minor parent `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)`.
pub const TC_H_MIN_EGRESS_PARENT: u32 = 0xFFFF_FFF3;
/// ingress minor parent `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)`.
pub const TC_H_MIN_INGRESS_PARENT: u32 = 0xFFFF_FFF2;

/// `ETH_P_ALL` in network byte order for `tcm_info` low 16 bits.
pub const ETH_P_ALL_BE: u16 = 0x0003;
/// `ETH_P_IP`
pub const ETH_P_IP: u16 = 0x0800;

/// `struct ifinfomsg` length after `nlmsghdr`.
pub const IFINFOMSG_LEN: usize = 16;
/// `struct rtmsg` length.
pub const RTMSG_LEN: usize = 12;
/// `struct fib_rule_hdr` length.
pub const FIB_RULE_HDR_LEN: usize = 16;
/// `struct tcmsg` length.
pub const TCMSG_LEN: usize = 20;
