//! Length arithmetic for `parse_pkt` (blueprint §7.2).
//!
//! The BPF helper is the only decoder. These predicates pin the bound rules so
//! a second C parser is not required on the host. Device Phase 6 still has to
//! load the four entries on 5.15; this table does not replace that gate.

/// Whether a header at `start` of `len` bytes sits inside both protocol and
/// memory bounds. Overflowing addition is out of scope.
pub fn header_fits(start: u32, len: u32, l3_end: u32, data_end: u32) -> bool {
    match start.checked_add(len) {
        Some(end) => end <= l3_end && end <= data_end,
        None => false,
    }
}

/// IPv4 `tot_len` versus ihl and `skb->len`. GSO may have tot_len larger than
/// the current linear head; it must still fit the buffer.
pub fn ipv4_length_ok(nh_off: u32, tot_len: u32, ihl_bytes: u32, skb_len: u32) -> bool {
    tot_len >= ihl_bytes && nh_off.saturating_add(tot_len) <= skb_len
}

/// IPv6 `payload_len` of 0 is a jumbogram and is out of scope.
pub fn ipv6_length_ok(nh_off: u32, payload_len: u32, skb_len: u32) -> bool {
    payload_len != 0 && nh_off.saturating_add(40).saturating_add(payload_len) <= skb_len
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETH: u32 = 14;
    const IPV4: u32 = 20;
    const IPV6: u32 = 40;
    const FRAG: u32 = 8;
    const TCP: u32 = 20;
    const UDP: u32 = 8;

    #[test]
    fn ipv4_padding_after_tot_len_is_not_an_l4_header() {
        let tot_len = IPV4;
        let l3_end = ETH + tot_len;
        let data_end = ETH + IPV4 + TCP;
        assert!(ipv4_length_ok(ETH, tot_len, IPV4, data_end));
        assert!(!header_fits(ETH + IPV4, TCP, l3_end, data_end));
    }

    #[test]
    fn ipv4_l4_inside_tot_len_accepts_trailing_padding() {
        let tot_len = IPV4 + TCP;
        let l3_end = ETH + tot_len;
        let data_end = l3_end + 20;
        assert!(ipv4_length_ok(ETH, tot_len, IPV4, data_end));
        assert!(header_fits(ETH + IPV4, TCP, l3_end, data_end));
        assert!(header_fits(ETH + IPV4, UDP, l3_end, data_end));
    }

    #[test]
    fn ipv4_tot_len_shorter_than_ihl_is_malformed() {
        assert!(!ipv4_length_ok(ETH, 10, IPV4, 60));
    }

    #[test]
    fn ipv4_tot_len_past_skb_len_is_malformed() {
        assert!(!ipv4_length_ok(ETH, 1500, IPV4, 60));
    }

    #[test]
    fn ipv4_min_header_fits_before_the_fragment_branch() {
        let l3_end = ETH + 80;
        let data_end = ETH + IPV4;
        assert!(header_fits(ETH, IPV4, l3_end, data_end));
    }

    #[test]
    fn ipv6_jumbogram_is_out_of_scope() {
        assert!(!ipv6_length_ok(ETH, 0, 1500));
    }

    #[test]
    fn ipv6_fragment_requires_eight_bytes_in_both_bounds() {
        let payload_len = 4;
        let l3_end = ETH + IPV6 + payload_len;
        let data_end = ETH + IPV6 + FRAG;
        assert!(ipv6_length_ok(ETH, payload_len, data_end));
        assert!(!header_fits(ETH + IPV6, FRAG, l3_end, data_end));

        let payload_len = FRAG;
        let l3_end = ETH + IPV6 + payload_len;
        let data_end = ETH + IPV6 + 4;
        assert!(ipv6_length_ok(ETH, payload_len, ETH + IPV6 + FRAG));
        assert!(!header_fits(ETH + IPV6, FRAG, l3_end, data_end));

        let data_end = ETH + IPV6 + FRAG;
        assert!(header_fits(ETH + IPV6, FRAG, l3_end, data_end));
    }
}
