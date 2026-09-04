//! Generic-netlink transport for the nl80211 SSID activation input (§29.2).
//!
//! Events are only invalidation triggers. The SSID bytes used for a decision
//! always come from a fresh `GET_INTERFACE` dump and are never formatted.

use std::io;
use std::mem::size_of;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::RawFd;

use super::wire::{
    as_bytes, attr_cstr, attr_u16, attr_u32, attrs, read_struct, Attr, MessageBuilder,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use super::wire::{DrainResult, RequestSocket, NLMSG_ERROR, NLM_F_DUMP, NLM_F_REQUEST};

// Values below are derived from
// clone/kernel-src/v5.15/include/uapi/linux/genetlink.h.
const GENL_ID_CTRL: u16 = 0x10; // GENL_ID_CTRL = NLMSG_MIN_TYPE
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

// Values below are counted from the enums in
// clone/kernel-src/v5.15/include/uapi/linux/nl80211.h. Command aliases such as
// NEW_BEACON = START_AP do not advance the enum value.
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEAUTHENTICATE: u8 = 39;
const NL80211_CMD_DISASSOCIATE: u8 = 40;
const NL80211_CMD_CONNECT: u8 = 46;
const NL80211_CMD_ROAM: u8 = 47;
const NL80211_CMD_DISCONNECT: u8 = 48;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_SSID: u16 = 52;
pub const NL80211_IFTYPE_STATION: u32 = 2;

#[cfg(any(target_os = "linux", target_os = "android"))]
const CHANGE_COMMANDS: [u8; 5] = [
    NL80211_CMD_DEAUTHENTICATE,
    NL80211_CMD_DISASSOCIATE,
    NL80211_CMD_CONNECT,
    NL80211_CMD_ROAM,
    NL80211_CMD_DISCONNECT,
];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GenlMsgHdr {
    cmd: u8,
    version: u8,
    reserved: u16,
}

/// The dynamic nl80211 family and its `mlme` multicast group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nl80211Family {
    pub id: u16,
    pub mlme_group: u32,
}

/// One interface record from `NL80211_CMD_GET_INTERFACE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirelessInterface {
    pub ifindex: u32,
    pub iftype: u32,
    /// Raw 802.11 SSID bytes. `None` means the interface is not associated.
    pub ssid: Option<Vec<u8>>,
}

/// One non-blocking `NETLINK_GENERIC` socket used for resolution, dumps, and events.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct GenlSocket {
    socket: RequestSocket,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl GenlSocket {
    /// Opens exactly `NETLINK_GENERIC | SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC`.
    pub fn open() -> io::Result<Self> {
        RequestSocket::open_nonblocking(libc::NETLINK_GENERIC).map(|socket| Self { socket })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Resolves nl80211 and its `mlme` group through the controller family.
    /// `ENOENT` is the normal "cfg80211 absent" result.
    pub fn resolve_nl80211(&mut self) -> io::Result<Option<Nl80211Family>> {
        let seq = self.socket.next_seq();
        let header = GenlMsgHdr {
            cmd: CTRL_CMD_GETFAMILY,
            version: 2,
            reserved: 0,
        };
        let mut request = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST, seq, as_bytes(&header));
        request.attr_cstr(CTRL_ATTR_FAMILY_NAME, "nl80211");
        let response = match self.socket.request(request.finish(), seq) {
            Ok(response) => response,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(error) => return Err(error),
        };
        if response.kind != GENL_ID_CTRL {
            return Err(invalid_data("GETFAMILY replied with the wrong family id"));
        }
        parse_family(&response.payload).map(Some)
    }

    /// Joins a generic-netlink multicast group before the first state dump.
    pub fn join(&self, group: u32) -> io::Result<()> {
        let group = libc::c_int::try_from(group)
            .map_err(|_| invalid_data("generic-netlink multicast group id exceeds c_int"))?;
        // SAFETY: group points to one initialized c_int of the stated size,
        // and the descriptor is this socket for the duration of the call.
        let rc = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                (&group as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Takes the authoritative interface snapshot after multicast is joined.
    pub fn dump_interfaces(&mut self, family: u16) -> io::Result<Vec<WirelessInterface>> {
        let seq = self.socket.next_seq();
        let header = GenlMsgHdr {
            cmd: NL80211_CMD_GET_INTERFACE,
            version: 1,
            reserved: 0,
        };
        let request =
            MessageBuilder::new(family, NLM_F_REQUEST | NLM_F_DUMP, seq, as_bytes(&header))
                .finish();
        self.socket
            .dump(request, seq)?
            .into_iter()
            .map(|message| {
                if message.kind != family {
                    return Err(invalid_data(
                        "interface dump replied with the wrong family id",
                    ));
                }
                parse_interface(&message.payload)
            })
            .collect()
    }

    /// Drains all pending multicast records and reports only invalidation or overflow.
    pub fn drain(&mut self, family: u16) -> io::Result<DrainResult> {
        let (messages, resync) = self.socket.drain_messages()?;
        if resync {
            return Ok(DrainResult::Resync);
        }
        let mut result = DrainResult::Quiet;
        for message in messages {
            if message.kind == NLMSG_ERROR {
                return Ok(DrainResult::Resync);
            }
            if message.kind != family {
                continue;
            }
            let header: GenlMsgHdr = read_struct(&message.payload)?;
            if CHANGE_COMMANDS.contains(&header.cmd) {
                result = DrainResult::Changed;
            }
        }
        Ok(result)
    }
}

fn parse_family(payload: &[u8]) -> io::Result<Nl80211Family> {
    let (header, top) = genl_attrs(payload)?;
    if header.cmd != CTRL_CMD_NEWFAMILY {
        return Err(invalid_data("GETFAMILY reply has an unexpected command"));
    }

    let mut family_id = None;
    let mut mlme_group = None;
    for attr in top {
        match attr.kind {
            CTRL_ATTR_FAMILY_ID => set_once(&mut family_id, attr_u16(attr), "family id")?,
            CTRL_ATTR_MCAST_GROUPS => {
                for group in attrs(attr.payload)? {
                    let mut name = None;
                    let mut id = None;
                    for field in attrs(group.payload)? {
                        match field.kind {
                            CTRL_ATTR_MCAST_GRP_NAME => {
                                set_once(&mut name, attr_cstr(field), "multicast group name")?
                            }
                            CTRL_ATTR_MCAST_GRP_ID => {
                                set_once(&mut id, attr_u32(field), "multicast group id")?
                            }
                            _ => {}
                        }
                    }
                    let name = name.ok_or_else(|| invalid_data("multicast group has no name"))?;
                    let id = id.ok_or_else(|| invalid_data("multicast group has no id"))?;
                    if name == "mlme" && mlme_group.replace(id).is_some() {
                        return Err(invalid_data("duplicate mlme multicast group"));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(Nl80211Family {
        id: family_id.ok_or_else(|| invalid_data("GETFAMILY reply has no family id"))?,
        mlme_group: mlme_group
            .ok_or_else(|| invalid_data("GETFAMILY reply has no mlme multicast group"))?,
    })
}

fn parse_interface(payload: &[u8]) -> io::Result<WirelessInterface> {
    let (header, fields) = genl_attrs(payload)?;
    if header.cmd != NL80211_CMD_NEW_INTERFACE {
        return Err(invalid_data("interface dump has an unexpected command"));
    }

    let mut ifindex = None;
    let mut iftype = None;
    let mut ssid = None;
    for attr in fields {
        match attr.kind {
            NL80211_ATTR_IFINDEX => set_once(&mut ifindex, attr_u32(attr), "interface index")?,
            NL80211_ATTR_IFTYPE => set_once(&mut iftype, attr_u32(attr), "interface type")?,
            NL80211_ATTR_SSID => {
                if attr.payload.len() > 32 {
                    return Err(invalid_data("SSID attribute exceeds 32 bytes"));
                }
                set_once(&mut ssid, Ok(attr.payload.to_vec()), "SSID")?;
            }
            _ => {}
        }
    }

    Ok(WirelessInterface {
        ifindex: ifindex.ok_or_else(|| invalid_data("interface dump has no ifindex"))?,
        iftype: iftype.ok_or_else(|| invalid_data("interface dump has no iftype"))?,
        ssid,
    })
}

fn genl_attrs(payload: &[u8]) -> io::Result<(GenlMsgHdr, Vec<Attr<'_>>)> {
    let header: GenlMsgHdr = read_struct(payload)?;
    let fields = attrs(&payload[size_of::<GenlMsgHdr>()..])?;
    Ok((header, fields))
}

fn set_once<T>(slot: &mut Option<T>, value: io::Result<T>, name: &str) -> io::Result<()> {
    if slot.is_some() {
        return Err(invalid_data(&format!("duplicate {name} attribute")));
    }
    *slot = Some(value?);
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::super::wire::NlMsgHdr;
    use super::*;

    fn payload(cmd: u8, fill: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let header = GenlMsgHdr {
            cmd,
            version: 1,
            reserved: 0,
        };
        let mut message = MessageBuilder::new(0x20, 0, 1, as_bytes(&header));
        fill(&mut message);
        message.finish()[size_of::<NlMsgHdr>()..].to_vec()
    }

    #[test]
    fn getfamily_reply_decodes_family_and_mlme_group() {
        let bytes = payload(CTRL_CMD_NEWFAMILY, |message| {
            message.attr(CTRL_ATTR_FAMILY_ID, &0x31u16.to_ne_bytes());
            message.begin_nested(CTRL_ATTR_MCAST_GROUPS);
            message.begin_nested(1);
            message.attr_cstr(CTRL_ATTR_MCAST_GRP_NAME, "scan");
            message.attr_u32(CTRL_ATTR_MCAST_GRP_ID, 9);
            message.end_nested();
            message.begin_nested(2);
            message.attr_cstr(CTRL_ATTR_MCAST_GRP_NAME, "mlme");
            message.attr_u32(CTRL_ATTR_MCAST_GRP_ID, 17);
            message.end_nested();
            message.end_nested();
        });
        assert_eq!(
            parse_family(&bytes).unwrap(),
            Nl80211Family {
                id: 0x31,
                mlme_group: 17,
            }
        );
    }

    #[test]
    fn interface_reply_preserves_raw_ssid_bytes() {
        let bytes = payload(NL80211_CMD_NEW_INTERFACE, |message| {
            message.attr_u32(NL80211_ATTR_IFINDEX, 24);
            message.attr_u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
            message.attr(NL80211_ATTR_SSID, &[0xff, b'x']);
        });
        assert_eq!(
            parse_interface(&bytes).unwrap(),
            WirelessInterface {
                ifindex: 24,
                iftype: NL80211_IFTYPE_STATION,
                ssid: Some(vec![0xff, b'x']),
            }
        );
    }

    #[test]
    fn interface_without_ssid_is_not_associated() {
        let bytes = payload(NL80211_CMD_NEW_INTERFACE, |message| {
            message.attr_u32(NL80211_ATTR_IFINDEX, 25);
            message.attr_u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
        });
        assert_eq!(parse_interface(&bytes).unwrap().ssid, None);
    }

    #[test]
    fn unknown_attributes_are_skipped() {
        let bytes = payload(NL80211_CMD_NEW_INTERFACE, |message| {
            message.attr(777, &[1, 2, 3]);
            message.attr_u32(NL80211_ATTR_IFINDEX, 26);
            message.attr_u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
        });
        let interface = parse_interface(&bytes).unwrap();
        assert_eq!(interface.ifindex, 26);
        assert_eq!(interface.ssid, None);
    }

    #[test]
    fn truncated_attribute_rejects_the_whole_message() {
        let header = GenlMsgHdr {
            cmd: NL80211_CMD_NEW_INTERFACE,
            version: 1,
            reserved: 0,
        };
        let mut bytes = as_bytes(&header).to_vec();
        bytes.extend_from_slice(&8u16.to_ne_bytes());
        bytes.extend_from_slice(&NL80211_ATTR_IFINDEX.to_ne_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        assert!(parse_interface(&bytes).is_err());
    }
}
