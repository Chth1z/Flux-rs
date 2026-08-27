use std::collections::BTreeSet;
use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::os::fd::RawFd;

#[cfg(test)]
use super::wire::NdMsg;
use super::wire::{
    as_bytes, attr_cstr, attr_u32, attrs, read_struct, DrainResult, FibRuleHdr, IfAddrMsg,
    IfInfoMsg, MessageBuilder, NonblockingSocket, RequestSocket, RtMsg, TcMsg, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
#[cfg(test)]
const RTM_NEWNEIGH: u16 = 28;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;
const RTM_NEWQDISC: u16 = 36;
const RTM_GETQDISC: u16 = 38;
const RTM_NEWTFILTER: u16 = 44;
#[allow(dead_code)] // The Phase 5 attachment consumer is not present yet.
const RTM_DELTFILTER: u16 = 45;
const RTM_GETTFILTER: u16 = 46;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_IFALIAS: u16 = 20;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

#[cfg(test)]
const NDA_DST: u16 = 1;
#[cfg(test)]
const NDA_LLADDR: u16 = 2;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_PRIORITY: u16 = 6;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_PREF: u16 = 20;

const FRA_IIFNAME: u16 = 3;
const FRA_PRIORITY: u16 = 6;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_PROTOCOL: u16 = 21;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_CHAIN: u16 = 11;
const TCA_INGRESS_BLOCK: u16 = 13;
const TCA_EGRESS_BLOCK: u16 = 14;
#[allow(dead_code)] // The Phase 5 attachment consumer is not present yet.
const TCA_BPF_FD: u16 = 6;
const TCA_BPF_NAME: u16 = 7;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_FLAGS_GEN: u16 = 9;
const TCA_BPF_TAG: u16 = 10;
const TCA_BPF_ID: u16 = 11;
const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;

pub const IFF_UP: u32 = 1;
pub const IFF_LOOPBACK: u32 = 1 << 3;
pub const TC_H_CLSACT: u32 = 0xffff_fff1;
#[allow(dead_code)] // Used when Phase 5 attaches flx_in to the owned peer.
pub const TC_H_INGRESS: u32 = 0xffff_fff2;
pub const TC_H_EGRESS: u32 = 0xffff_fff3;
pub const TC_CLSACT_HANDLE: u32 = 0xffff_0000;
#[allow(dead_code)] // Used by the typed Phase 5 filter attachment call.
pub const ETH_P_ALL: u16 = 0x0003;

const RT_TABLE_UNSPEC: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;
const RTN_LOCAL: u8 = 2;
#[cfg(test)]
const NUD_PERMANENT: u16 = 0x80;
#[cfg(test)]
const RT_SCOPE_UNIVERSE: u8 = 0;
#[cfg(test)]
const RTN_UNICAST: u8 = 1;
const FR_ACT_TO_TBL: u8 = 1;

const EVENT_GROUPS: u32 = 1 // RTNLGRP_LINK
    | (1 << 3) // RTNLGRP_TC
    | (1 << 4) // RTNLGRP_IPV4_IFADDR
    | (1 << 6) // RTNLGRP_IPV4_ROUTE
    | (1 << 7) // RTNLGRP_IPV4_RULE
    | (1 << 8) // RTNLGRP_IPV6_IFADDR
    | (1 << 10) // RTNLGRP_IPV6_ROUTE
    | (1 << 18); // RTNLGRP_IPV6_RULE

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub ifindex: u32,
    pub name: String,
    pub alias: Option<String>,
    pub kind: Option<String>,
    pub peer_ifindex: Option<u32>,
    pub master_ifindex: Option<u32>,
    pub arphrd: u16,
    pub flags: u32,
    pub mtu: u32,
    pub address: Vec<u8>,
    pub unknown_attrs: bool,
    pub duplicate_attrs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub ifindex: u32,
    pub family: u8,
    pub prefix_len: u8,
    pub scope: u8,
    /// Full 32-bit IFA flag set. `IFA_FLAGS` overrides the legacy 8-bit
    /// header field when present.
    pub flags: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub family: u8,
    pub dst_len: u8,
    pub table: u32,
    pub protocol: u8,
    pub scope: u8,
    pub kind: u8,
    pub oif: Option<u32>,
    pub has_dst: bool,
    pub metric: Option<u32>,
    pub preference: Option<u8>,
    pub extra_attrs: bool,
    pub extra_attr_kinds: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub table: u32,
    pub action: u8,
    pub priority: Option<u32>,
    pub iif_name: Option<String>,
    pub suppress_prefix_len: Option<u32>,
    pub protocol: Option<u8>,
    pub extra_attrs: bool,
    /// Attribute type ids excluded from the exact ownership contract. Values
    /// are intentionally not retained because a foreign rule may contain
    /// addresses or marks that do not belong in diagnostics.
    pub extra_attr_kinds: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qdisc {
    pub ifindex: u32,
    pub handle: u32,
    pub parent: u32,
    pub kind: Option<String>,
    pub options_nonempty: bool,
    pub ingress_block: bool,
    pub egress_block: bool,
    pub unknown_attrs: bool,
    pub duplicate_attrs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub ifindex: u32,
    pub parent: u32,
    pub handle: u32,
    pub chain: u32,
    pub priority: u16,
    pub protocol: u16,
    pub kind: Option<String>,
    pub direct_action: bool,
    pub bpf_flags: Option<u32>,
    pub prog_id: Option<u32>,
    pub prog_tag: Option<[u8; 8]>,
    pub prog_name: Option<String>,
    pub flags_gen: Option<u32>,
    pub unknown_attrs: bool,
    pub duplicate_attrs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Phase 5 supplies program/map identity after BPF load.
pub struct FilterIdentity {
    pub ifindex: u32,
    pub parent: u32,
    pub handle: u32,
    pub chain: u32,
    pub priority: u16,
    pub protocol: u16,
    pub prog_id: u32,
    pub prog_tag: [u8; 8],
    pub prog_name: String,
    pub flags_gen: u32,
}

#[allow(dead_code)] // Phase 5 supplies program/map identity after BPF load.
impl FilterIdentity {
    pub fn matches(&self, filter: &Filter) -> bool {
        !filter.unknown_attrs
            && !filter.duplicate_attrs
            && filter.ifindex == self.ifindex
            && filter.parent == self.parent
            && filter.handle == self.handle
            && filter.chain == self.chain
            && filter.priority == self.priority
            && filter.protocol == self.protocol
            && filter.kind.as_deref() == Some("bpf")
            && filter.direct_action
            && filter.bpf_flags == Some(TCA_BPF_FLAG_ACT_DIRECT)
            && filter.flags_gen == Some(self.flags_gen)
            && filter.prog_id == Some(self.prog_id)
            && filter.prog_tag == Some(self.prog_tag)
            && filter.prog_name.as_deref() == Some(self.prog_name.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Phase 5 supplies a verified program fd.
pub struct TcAttach<'a> {
    pub ifindex: u32,
    pub parent: u32,
    pub handle: u32,
    pub chain: u32,
    pub priority: u16,
    pub protocol: u16,
    pub program_fd: RawFd,
    pub program_name: &'a str,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkSnapshot {
    pub links: Vec<Link>,
    pub addresses: Vec<Address>,
    pub routes: Vec<Route>,
    pub rules: Vec<Rule>,
    pub qdiscs: Vec<Qdisc>,
}

pub struct EventSocket {
    socket: NonblockingSocket,
}

impl EventSocket {
    pub fn open() -> io::Result<Self> {
        NonblockingSocket::open(EVENT_GROUPS).map(|socket| Self { socket })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    pub fn drain(&self) -> io::Result<DrainResult> {
        self.socket.drain()
    }
}

pub struct RouteNetlink {
    socket: RequestSocket,
}

impl RouteNetlink {
    pub fn open() -> io::Result<Self> {
        RequestSocket::open().map(|socket| Self { socket })
    }

    pub fn snapshot(&mut self) -> io::Result<NetworkSnapshot> {
        Ok(NetworkSnapshot {
            links: self.dump_links()?,
            addresses: self.dump_addresses()?,
            routes: self.dump_routes()?,
            rules: self.dump_rules()?,
            qdiscs: self.dump_qdiscs()?,
        })
    }

    pub fn dump_links(&mut self) -> io::Result<Vec<Link>> {
        let body = IfInfoMsg::default();
        let messages = self.dump(RTM_GETLINK, as_bytes(&body))?;
        messages
            .into_iter()
            .filter(|message| message.kind == RTM_NEWLINK)
            .map(|message| parse_link(&message.payload))
            .collect()
    }

    pub fn dump_addresses(&mut self) -> io::Result<Vec<Address>> {
        let body = IfAddrMsg::default();
        let messages = self.dump(RTM_GETADDR, as_bytes(&body))?;
        messages
            .into_iter()
            .filter(|message| message.kind == RTM_NEWADDR)
            .map(|message| parse_address(&message.payload))
            .collect()
    }

    pub fn dump_routes(&mut self) -> io::Result<Vec<Route>> {
        let body = RtMsg::default();
        let messages = self.dump(RTM_GETROUTE, as_bytes(&body))?;
        messages
            .into_iter()
            .filter(|message| message.kind == RTM_NEWROUTE)
            .map(|message| parse_route(&message.payload))
            .collect()
    }

    pub fn dump_rules(&mut self) -> io::Result<Vec<Rule>> {
        let body = FibRuleHdr::default();
        let messages = self.dump(RTM_GETRULE, as_bytes(&body))?;
        messages
            .into_iter()
            .filter(|message| message.kind == RTM_NEWRULE)
            .map(|message| parse_rule(&message.payload))
            .collect()
    }

    pub fn dump_qdiscs(&mut self) -> io::Result<Vec<Qdisc>> {
        let body = TcMsg::default();
        let messages = self.dump(RTM_GETQDISC, as_bytes(&body))?;
        messages
            .into_iter()
            .filter(|message| message.kind == RTM_NEWQDISC)
            .map(|message| parse_qdisc(&message.payload))
            .collect()
    }

    pub fn dump_filters(&mut self, ifindex: u32, parent: u32) -> io::Result<Vec<Filter>> {
        let body = TcMsg {
            family: libc::AF_UNSPEC as u8,
            ifindex: ifindex as i32,
            parent,
            ..TcMsg::default()
        };
        let messages = self.dump(RTM_GETTFILTER, as_bytes(&body))?;
        messages
            .into_iter()
            .filter(|message| message.kind == RTM_NEWTFILTER)
            .map(|message| parse_filter(&message.payload))
            .collect()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn add_ipv4_address(
        &mut self,
        ifindex: u32,
        address: [u8; 4],
        prefix_len: u8,
    ) -> io::Result<()> {
        let body = IfAddrMsg {
            family: libc::AF_INET as u8,
            prefix_len,
            scope: RT_SCOPE_UNIVERSE,
            index: ifindex,
            ..IfAddrMsg::default()
        };
        self.mutate_flags_with_attrs(RTM_NEWADDR, true, as_bytes(&body), |request| {
            request.attr(IFA_LOCAL, &address);
            request.attr(IFA_ADDRESS, &address);
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn add_ipv4_neighbor(
        &mut self,
        ifindex: u32,
        address: [u8; 4],
        lladdr: &[u8],
    ) -> io::Result<()> {
        let body = NdMsg {
            family: libc::AF_INET as u8,
            ifindex: ifindex as i32,
            state: NUD_PERMANENT,
            kind: RTN_UNICAST,
            ..NdMsg::default()
        };
        self.mutate_flags_with_attrs(RTM_NEWNEIGH, true, as_bytes(&body), |request| {
            request.attr(NDA_DST, &address);
            request.attr(NDA_LLADDR, lladdr);
        })
    }

    pub fn create_veth(&mut self, host: &str, peer: &str, mtu: u32) -> io::Result<()> {
        let seq = self.socket.next_seq();
        let body = IfInfoMsg::default();
        let mut request = MessageBuilder::new(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            seq,
            as_bytes(&body),
        );
        request.attr_cstr(IFLA_IFNAME, host);
        request.attr_u32(IFLA_MTU, mtu);
        request.begin_nested(IFLA_LINKINFO);
        request.attr_cstr(IFLA_INFO_KIND, "veth");
        request.begin_nested(IFLA_INFO_DATA);
        request.begin_nested(VETH_INFO_PEER);
        request.nested_payload(as_bytes(&IfInfoMsg::default()));
        request.attr_cstr(IFLA_IFNAME, peer);
        request.attr_u32(IFLA_MTU, mtu);
        request.end_nested();
        request.end_nested();
        request.end_nested();
        self.socket.ack(request.finish(), seq)
    }

    pub fn set_link_alias(&mut self, ifindex: u32, alias: &str) -> io::Result<()> {
        let body = IfInfoMsg {
            family: libc::AF_UNSPEC as u8,
            index: ifindex as i32,
            ..IfInfoMsg::default()
        };
        self.mutate_with_attrs(RTM_NEWLINK, as_bytes(&body), |request| {
            request.attr_cstr(IFLA_IFALIAS, alias);
        })
    }

    pub fn set_link_up(&mut self, ifindex: u32) -> io::Result<()> {
        let body = IfInfoMsg {
            family: libc::AF_UNSPEC as u8,
            index: ifindex as i32,
            flags: IFF_UP,
            change: IFF_UP,
            ..IfInfoMsg::default()
        };
        self.mutate(RTM_NEWLINK, as_bytes(&body))
    }

    pub fn delete_link(&mut self, ifindex: u32) -> io::Result<()> {
        let body = IfInfoMsg {
            family: libc::AF_UNSPEC as u8,
            index: ifindex as i32,
            ..IfInfoMsg::default()
        };
        self.mutate(RTM_DELLINK, as_bytes(&body))
    }

    pub fn add_local_route(
        &mut self,
        family: u8,
        table: u32,
        protocol: u8,
        lo_ifindex: u32,
    ) -> io::Result<()> {
        self.local_route(RTM_NEWROUTE, true, family, table, protocol, lo_ifindex)
    }

    pub fn delete_local_route(
        &mut self,
        family: u8,
        table: u32,
        protocol: u8,
        lo_ifindex: u32,
    ) -> io::Result<()> {
        self.local_route(RTM_DELROUTE, false, family, table, protocol, lo_ifindex)
    }

    fn local_route(
        &mut self,
        kind: u16,
        create: bool,
        family: u8,
        table: u32,
        protocol: u8,
        lo_ifindex: u32,
    ) -> io::Result<()> {
        let body = RtMsg {
            family,
            table: RT_TABLE_UNSPEC,
            protocol,
            scope: RT_SCOPE_HOST,
            kind: RTN_LOCAL,
            ..RtMsg::default()
        };
        self.mutate_flags_with_attrs(kind, create, as_bytes(&body), |request| {
            request.attr_u32(RTA_TABLE, table);
            request.attr_u32(RTA_OIF, lo_ifindex);
        })
    }

    pub fn add_rule(&mut self, family: u8, priority: u32, table: u32, iif: &str) -> io::Result<()> {
        self.rule(RTM_NEWRULE, true, family, priority, table, iif)
    }

    pub fn delete_rule(
        &mut self,
        family: u8,
        priority: u32,
        table: u32,
        iif: &str,
    ) -> io::Result<()> {
        self.rule(RTM_DELRULE, false, family, priority, table, iif)
    }

    fn rule(
        &mut self,
        kind: u16,
        create: bool,
        family: u8,
        priority: u32,
        table: u32,
        iif: &str,
    ) -> io::Result<()> {
        let body = FibRuleHdr {
            family,
            table: RT_TABLE_UNSPEC,
            action: FR_ACT_TO_TBL,
            ..FibRuleHdr::default()
        };
        self.mutate_flags_with_attrs(kind, create, as_bytes(&body), |request| {
            request.attr_u32(FRA_PRIORITY, priority);
            request.attr_u32(FRA_TABLE, table);
            request.attr_cstr(FRA_IIFNAME, iif);
        })
    }

    pub fn create_clsact(&mut self, ifindex: u32) -> io::Result<()> {
        let body = TcMsg {
            family: libc::AF_UNSPEC as u8,
            ifindex: ifindex as i32,
            handle: TC_CLSACT_HANDLE,
            parent: TC_H_CLSACT,
            ..TcMsg::default()
        };
        self.mutate_flags_with_attrs(RTM_NEWQDISC, true, as_bytes(&body), |request| {
            request.attr_cstr(TCA_KIND, "clsact");
        })
    }

    #[allow(dead_code)] // Phase 3 owns the encoder; Phase 5 supplies program fds.
    pub fn attach_filter(&mut self, attach: TcAttach<'_>) -> io::Result<()> {
        let body = TcMsg {
            family: libc::AF_UNSPEC as u8,
            ifindex: attach.ifindex as i32,
            handle: attach.handle,
            parent: attach.parent,
            info: tc_info(attach.priority, attach.protocol),
            ..TcMsg::default()
        };
        self.mutate_flags_with_attrs(RTM_NEWTFILTER, true, as_bytes(&body), |request| {
            request.attr_cstr(TCA_KIND, "bpf");
            request.attr_u32(TCA_CHAIN, attach.chain);
            request.begin_nested(TCA_OPTIONS);
            request.attr_u32(TCA_BPF_FD, attach.program_fd as u32);
            request.attr_cstr(TCA_BPF_NAME, attach.program_name);
            request.attr_u32(TCA_BPF_FLAGS, TCA_BPF_FLAG_ACT_DIRECT);
            request.end_nested();
        })
    }

    #[allow(dead_code)] // Phase 3 owns the encoder; Phase 5 supplies identities.
    pub fn detach_filter(
        &mut self,
        ifindex: u32,
        parent: u32,
        handle: u32,
        chain: u32,
        priority: u16,
        protocol: u16,
    ) -> io::Result<()> {
        let body = TcMsg {
            family: libc::AF_UNSPEC as u8,
            ifindex: ifindex as i32,
            handle,
            parent,
            info: tc_info(priority, protocol),
            ..TcMsg::default()
        };
        self.mutate_with_attrs(RTM_DELTFILTER, as_bytes(&body), |request| {
            request.attr_cstr(TCA_KIND, "bpf");
            request.attr_u32(TCA_CHAIN, chain);
        })
    }

    pub fn if_nametoindex(name: &str) -> io::Result<u32> {
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has NUL"))?;
        // SAFETY: name is a valid NUL-terminated C string.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(index)
        }
    }

    fn dump(&mut self, kind: u16, body: &[u8]) -> io::Result<Vec<super::wire::RawMessage>> {
        let seq = self.socket.next_seq();
        let request =
            MessageBuilder::new(kind, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, seq, body).finish();
        self.socket.dump(request, seq)
    }

    fn mutate(&mut self, kind: u16, body: &[u8]) -> io::Result<()> {
        self.mutate_with_attrs(kind, body, |_| {})
    }

    fn mutate_with_attrs(
        &mut self,
        kind: u16,
        body: &[u8],
        attrs: impl FnOnce(&mut MessageBuilder),
    ) -> io::Result<()> {
        self.mutate_flags_with_attrs(kind, false, body, attrs)
    }

    fn mutate_flags_with_attrs(
        &mut self,
        kind: u16,
        create: bool,
        body: &[u8],
        attrs: impl FnOnce(&mut MessageBuilder),
    ) -> io::Result<()> {
        let seq = self.socket.next_seq();
        let mut flags = NLM_F_REQUEST | NLM_F_ACK;
        if create {
            flags |= NLM_F_CREATE | NLM_F_EXCL;
        }
        let mut request = MessageBuilder::new(kind, flags, seq, body);
        attrs(&mut request);
        self.socket.ack(request.finish(), seq)
    }
}

#[allow(dead_code)] // Used by the dormant typed filter mutation methods above.
fn tc_info(priority: u16, protocol: u16) -> u32 {
    (u32::from(priority) << 16) | u32::from(protocol.to_be())
}

fn parse_link(payload: &[u8]) -> io::Result<Link> {
    let header: IfInfoMsg = read_struct(payload)?;
    let mut name = None;
    let mut alias = None;
    let mut kind = None;
    let mut peer_ifindex = None;
    let mut master_ifindex = None;
    let mut mtu = None;
    let mut address = None;
    let mut seen = BTreeSet::new();
    let mut unknown = false;
    let mut duplicate = false;
    for attr in attrs(&payload[size_of::<IfInfoMsg>()..])? {
        if !seen.insert(attr.kind) {
            duplicate = true;
        }
        match attr.kind {
            IFLA_IFNAME => name = Some(attr_cstr(attr)?),
            IFLA_IFALIAS => alias = Some(attr_cstr(attr)?),
            IFLA_MTU => mtu = Some(attr_u32(attr)?),
            IFLA_LINK => peer_ifindex = Some(attr_u32(attr)?),
            IFLA_MASTER => master_ifindex = Some(attr_u32(attr)?),
            IFLA_ADDRESS => address = Some(attr.payload.to_vec()),
            IFLA_LINKINFO => {
                if !attr.nested {
                    unknown = true;
                }
                for info in attrs(attr.payload)? {
                    match info.kind {
                        IFLA_INFO_KIND => kind = Some(attr_cstr(info)?),
                        IFLA_INFO_DATA => {}
                        _ => unknown = true,
                    }
                }
            }
            // The link dump contains many observational attributes. They are
            // allowed but do not enter Flux's ownership predicate.
            2 | 6..=9 | 11..=17 | 19 | 21..=64 => {}
            _ => unknown = true,
        }
    }
    Ok(Link {
        ifindex: positive_index(header.index)?,
        name: name.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "link has no name"))?,
        alias,
        kind,
        peer_ifindex,
        master_ifindex,
        arphrd: header.arphrd,
        flags: header.flags,
        mtu: mtu.unwrap_or_default(),
        address: address.unwrap_or_default(),
        unknown_attrs: unknown,
        duplicate_attrs: duplicate,
    })
}

fn parse_address(payload: &[u8]) -> io::Result<Address> {
    let header: IfAddrMsg = read_struct(payload)?;
    let mut address = None;
    let mut flags = u32::from(header.flags);
    for attr in attrs(&payload[size_of::<IfAddrMsg>()..])? {
        match attr.kind {
            IFA_LOCAL => address = Some(attr.payload.to_vec()),
            IFA_ADDRESS if address.is_none() => address = Some(attr.payload.to_vec()),
            IFA_FLAGS => flags = attr_u32(attr)?,
            _ => {}
        }
    }
    Ok(Address {
        ifindex: header.index,
        family: header.family,
        prefix_len: header.prefix_len,
        scope: header.scope,
        flags,
        bytes: address
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "address has no bytes"))?,
    })
}

fn parse_route(payload: &[u8]) -> io::Result<Route> {
    let header: RtMsg = read_struct(payload)?;
    let mut table = u32::from(header.table);
    let mut oif = None;
    let mut has_dst = false;
    let mut metric = None;
    let mut preference = None;
    let mut extra = header.src_len != 0 || header.tos != 0 || header.flags != 0;
    let mut extra_attr_kinds = Vec::new();
    let mut seen = BTreeSet::new();
    for attr in attrs(&payload[size_of::<RtMsg>()..])? {
        if !seen.insert(attr.kind) {
            extra = true;
            extra_attr_kinds.push(attr.kind);
        }
        match attr.kind {
            RTA_TABLE => table = attr_u32(attr)?,
            RTA_OIF => oif = Some(attr_u32(attr)?),
            RTA_DST => has_dst = true,
            RTA_PRIORITY => metric = Some(attr_u32(attr)?),
            // Kernel-generated route diagnostics. The fixed-size cacheinfo
            // does not alter lookup semantics and its counters/timestamps are
            // deliberately not part of ownership.
            RTA_CACHEINFO if attr.payload.len() == 32 => {}
            RTA_PREF => {
                preference = match attr.payload {
                    [value] => Some(*value),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "route preference attribute has the wrong size",
                        ));
                    }
                }
            }
            _ => {
                extra = true;
                extra_attr_kinds.push(attr.kind);
            }
        }
    }
    Ok(Route {
        family: header.family,
        dst_len: header.dst_len,
        table,
        protocol: header.protocol,
        scope: header.scope,
        kind: header.kind,
        oif,
        has_dst,
        metric,
        preference,
        extra_attrs: extra,
        extra_attr_kinds,
    })
}

fn parse_rule(payload: &[u8]) -> io::Result<Rule> {
    let header: FibRuleHdr = read_struct(payload)?;
    let mut table = u32::from(header.table);
    let mut priority = None;
    let mut iif_name = None;
    let mut suppress_prefix_len = None;
    let mut protocol = None;
    let mut extra = header.tos != 0 || header.flags != 0;
    let mut extra_attr_kinds = Vec::new();
    let mut seen = BTreeSet::new();
    for attr in attrs(&payload[size_of::<FibRuleHdr>()..])? {
        if !seen.insert(attr.kind) {
            extra = true;
            extra_attr_kinds.push(attr.kind);
        }
        match attr.kind {
            FRA_TABLE => table = attr_u32(attr)?,
            FRA_PRIORITY => priority = Some(attr_u32(attr)?),
            FRA_IIFNAME => iif_name = Some(attr_cstr(attr)?),
            FRA_SUPPRESS_PREFIXLEN => {
                suppress_prefix_len = Some(attr_u32(attr)?);
            }
            FRA_PROTOCOL => {
                protocol = match attr.payload {
                    [value] => Some(*value),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "rule protocol attribute has the wrong size",
                        ));
                    }
                };
            }
            _ => {
                extra = true;
                extra_attr_kinds.push(attr.kind);
            }
        }
    }
    Ok(Rule {
        family: header.family,
        dst_len: header.dst_len,
        src_len: header.src_len,
        table,
        action: header.action,
        priority,
        iif_name,
        suppress_prefix_len,
        protocol,
        extra_attrs: extra,
        extra_attr_kinds,
    })
}

fn parse_qdisc(payload: &[u8]) -> io::Result<Qdisc> {
    let header: TcMsg = read_struct(payload)?;
    let mut kind = None;
    let mut options_nonempty = false;
    let mut ingress_block = false;
    let mut egress_block = false;
    let mut unknown = false;
    let mut duplicate = false;
    let mut seen = BTreeSet::new();
    for attr in attrs(&payload[size_of::<TcMsg>()..])? {
        if !seen.insert(attr.kind) {
            duplicate = true;
        }
        match attr.kind {
            TCA_KIND => kind = Some(attr_cstr(attr)?),
            TCA_OPTIONS => options_nonempty = !attr.payload.is_empty(),
            TCA_INGRESS_BLOCK => ingress_block = true,
            TCA_EGRESS_BLOCK => egress_block = true,
            3..=12 => {}
            _ => unknown = true,
        }
    }
    Ok(Qdisc {
        ifindex: positive_index(header.ifindex)?,
        handle: header.handle,
        parent: header.parent,
        kind,
        options_nonempty,
        ingress_block,
        egress_block,
        unknown_attrs: unknown,
        duplicate_attrs: duplicate,
    })
}

fn parse_filter(payload: &[u8]) -> io::Result<Filter> {
    let header: TcMsg = read_struct(payload)?;
    let mut kind = None;
    let mut chain = 0;
    let mut direct_action = false;
    let mut bpf_flags = None;
    let mut prog_id = None;
    let mut prog_tag = None;
    let mut prog_name = None;
    let mut flags_gen = None;
    let mut unknown = false;
    let mut duplicate = false;
    let mut seen = BTreeSet::new();
    for attr in attrs(&payload[size_of::<TcMsg>()..])? {
        if !seen.insert(attr.kind) {
            duplicate = true;
        }
        match attr.kind {
            TCA_KIND => kind = Some(attr_cstr(attr)?),
            TCA_CHAIN => chain = attr_u32(attr)?,
            TCA_OPTIONS => {
                let mut option_seen = BTreeSet::new();
                for option in attrs(attr.payload)? {
                    if !option_seen.insert(option.kind) {
                        duplicate = true;
                    }
                    match option.kind {
                        TCA_BPF_FLAGS => {
                            let flags = attr_u32(option)?;
                            direct_action = flags & TCA_BPF_FLAG_ACT_DIRECT != 0;
                            bpf_flags = Some(flags);
                        }
                        TCA_BPF_FLAGS_GEN => flags_gen = Some(attr_u32(option)?),
                        TCA_BPF_TAG => {
                            if option.payload.len() == 8 {
                                prog_tag = Some(option.payload.try_into().expect("size checked"));
                            } else {
                                unknown = true;
                            }
                        }
                        TCA_BPF_ID => prog_id = Some(attr_u32(option)?),
                        TCA_BPF_NAME => prog_name = Some(attr_cstr(option)?),
                        // ACT/POLICE/CLASSID/OPS/FD change identity or are not
                        // expected in a dump of a direct-action Flux filter.
                        _ => unknown = true,
                    }
                }
            }
            // Stats and hardware-offload diagnostics are allowed but never
            // treated as ownership evidence.
            3..=10 | 12 => {}
            _ => unknown = true,
        }
    }
    Ok(Filter {
        ifindex: positive_index(header.ifindex)?,
        parent: header.parent,
        handle: header.handle,
        chain,
        priority: (header.info >> 16) as u16,
        protocol: u16::from_be(header.info as u16),
        kind,
        direct_action,
        bpf_flags,
        prog_id,
        prog_tag,
        prog_name,
        flags_gen,
        unknown_attrs: unknown,
        duplicate_attrs: duplicate,
    })
}

fn positive_index(index: i32) -> io::Result<u32> {
    u32::try_from(index)
        .ok()
        .filter(|index| *index != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid interface index"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_info_keeps_priority_host_order_and_protocol_network_order() {
        let info = tc_info(2, ETH_P_ALL);
        assert_eq!(info >> 16, 2);
        assert_eq!(u16::from_be(info as u16), ETH_P_ALL);
    }

    #[test]
    fn filter_identity_is_fail_closed() {
        let filter = Filter {
            ifindex: 7,
            parent: TC_H_EGRESS,
            handle: 1,
            chain: 0,
            priority: 2,
            protocol: ETH_P_ALL,
            kind: Some("bpf".to_string()),
            direct_action: true,
            bpf_flags: Some(TCA_BPF_FLAG_ACT_DIRECT),
            prog_id: Some(42),
            prog_tag: Some([1; 8]),
            prog_name: Some("flx_cap_l2".to_string()),
            flags_gen: Some(0),
            unknown_attrs: false,
            duplicate_attrs: false,
        };
        let identity = FilterIdentity {
            ifindex: 7,
            parent: TC_H_EGRESS,
            handle: 1,
            chain: 0,
            priority: 2,
            protocol: ETH_P_ALL,
            prog_id: 42,
            prog_tag: [1; 8],
            prog_name: "flx_cap_l2".to_string(),
            flags_gen: 0,
        };
        assert!(identity.matches(&filter));
        let mut foreign = filter.clone();
        foreign.chain = 7;
        assert!(!identity.matches(&foreign));
        let mut foreign = filter.clone();
        foreign.flags_gen = Some(8);
        assert!(!identity.matches(&foreign));
        let mut foreign = filter;
        foreign.unknown_attrs = true;
        assert!(!identity.matches(&foreign));
    }
}
