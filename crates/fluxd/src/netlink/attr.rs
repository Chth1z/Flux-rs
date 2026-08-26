//! `nlattr` TLV encode/decode (blueprint §8.9).

use std::io;

/// Netlink attribute header length.
pub const NLA_HDRLEN: usize = 4;

/// Align a length to `NLA_ALIGNTO` (4).
pub fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Builder for nested netlink attributes.
#[derive(Debug, Default)]
pub struct AttrBuilder {
    buf: Vec<u8>,
}

impl AttrBuilder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn push_u8(&mut self, kind: u16, value: u8) {
        self.push_raw(kind, &[value]);
    }

    pub fn push_u32(&mut self, kind: u16, value: u32) {
        self.push_raw(kind, &value.to_ne_bytes());
    }

    pub fn push_str(&mut self, kind: u16, value: &str) {
        self.push_raw(kind, value.as_bytes());
    }

    pub fn push_bytes(&mut self, kind: u16, value: &[u8]) {
        self.push_raw(kind, value);
    }

    pub fn push_nested(&mut self, kind: u16, nested: &AttrBuilder) {
        self.push_raw(kind, nested.as_slice());
    }

    fn push_raw(&mut self, kind: u16, payload: &[u8]) {
        let nla_len = NLA_HDRLEN + payload.len();
        let aligned = nla_align(nla_len);
        self.buf.extend_from_slice(&(nla_len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        if aligned > nla_len {
            self.buf.resize(self.buf.len() + (aligned - nla_len), 0);
        }
    }
}

/// Iterator over attributes inside a netlink message payload.
pub struct AttrIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> AttrIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<(u16, &'a [u8]), io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + NLA_HDRLEN > self.data.len() {
            return None;
        }
        let nla_len =
            u16::from_ne_bytes(self.data[self.offset..self.offset + 2].try_into().unwrap())
                as usize;
        if nla_len < NLA_HDRLEN {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid nla_len",
            )));
        }
        let kind = u16::from_ne_bytes(
            self.data[self.offset + 2..self.offset + 4]
                .try_into()
                .unwrap(),
        );
        let payload_len = nla_len - NLA_HDRLEN;
        let end = self.offset + NLA_HDRLEN + payload_len;
        if end > self.data.len() {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated nla",
            )));
        }
        let payload = &self.data[self.offset + NLA_HDRLEN..end];
        self.offset += nla_align(nla_len);
        Some(Ok((kind, payload)))
    }
}

/// Find the first attribute with `kind` in `data`.
pub fn find_attr(data: &[u8], kind: u16) -> Option<&[u8]> {
    for (k, payload) in AttrIter::new(data).flatten() {
        if k == kind {
            return Some(payload);
        }
    }
    None
}

/// Parse nested attributes from a nested attribute payload.
pub fn nested_attrs(payload: &[u8]) -> AttrIter<'_> {
    AttrIter::new(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::consts;

    #[test]
    fn builder_round_trip() {
        let mut inner = AttrBuilder::new();
        inner.push_str(libc::IFLA_IFNAME, "flxrs1");
        let mut outer = AttrBuilder::new();
        outer.push_nested(consts::VETH_INFO_PEER, &inner);
        let name = find_attr(outer.as_slice(), consts::VETH_INFO_PEER).unwrap();
        let peer_name = find_attr(name, libc::IFLA_IFNAME).unwrap();
        assert_eq!(peer_name, b"flxrs1");
    }
}
