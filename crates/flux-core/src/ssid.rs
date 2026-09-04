//! Pure SSID matching for the conditional-activation dimension (blueprint §29.1).

use crate::config::ListMode;

/// The activation decision made from the currently connected station SSIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsidVerdict {
    /// Whether the `[ssid]` dimension holds Flux inactive.
    pub paused: bool,
    /// One-based expanded-list position that caused a blacklist pause.
    pub matched_entry: Option<usize>,
}

/// Applies the `[ssid]` list to the raw SSID bytes of associated station interfaces.
///
/// List entries are compared as UTF-8 bytes without case folding or pattern
/// matching. An empty `connected` set means that Wi-Fi has nothing to say and
/// therefore never pauses either list mode.
pub fn ssid_verdict(mode: ListMode, list: &[String], connected: &[Vec<u8>]) -> SsidVerdict {
    if connected.is_empty() {
        return SsidVerdict {
            paused: false,
            matched_entry: None,
        };
    }

    let matched_entry = list.iter().position(|entry| {
        connected
            .iter()
            .any(|ssid| entry.as_bytes() == ssid.as_slice())
    });

    match mode {
        ListMode::Blacklist => SsidVerdict {
            paused: matched_entry.is_some(),
            matched_entry: matched_entry.map(|index| index + 1),
        },
        ListMode::Whitelist => SsidVerdict {
            paused: matched_entry.is_none(),
            matched_entry: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_string()).collect()
    }

    fn connected(entries: &[&[u8]]) -> Vec<Vec<u8>> {
        entries.iter().map(|entry| entry.to_vec()).collect()
    }

    #[test]
    fn no_wifi_never_pauses_either_mode() {
        let list = strings(&["Home"]);
        for mode in [ListMode::Blacklist, ListMode::Whitelist] {
            assert_eq!(
                ssid_verdict(mode, &list, &[]),
                SsidVerdict {
                    paused: false,
                    matched_entry: None,
                }
            );
        }
    }

    #[test]
    fn blacklist_pauses_on_the_first_matching_list_entry() {
        let verdict = ssid_verdict(
            ListMode::Blacklist,
            &strings(&["Office", "Home", "Cafe"]),
            &connected(&[b"Home"]),
        );
        assert_eq!(
            verdict,
            SsidVerdict {
                paused: true,
                matched_entry: Some(2),
            }
        );
    }

    #[test]
    fn blacklist_does_not_pause_without_a_match() {
        let verdict = ssid_verdict(
            ListMode::Blacklist,
            &strings(&["Office"]),
            &connected(&[b"Home"]),
        );
        assert_eq!(
            verdict,
            SsidVerdict {
                paused: false,
                matched_entry: None,
            }
        );
    }

    #[test]
    fn whitelist_pauses_only_when_connected_without_a_match() {
        let list = strings(&["Office"]);
        assert_eq!(
            ssid_verdict(ListMode::Whitelist, &list, &connected(&[b"Home"])),
            SsidVerdict {
                paused: true,
                matched_entry: None,
            }
        );
        assert_eq!(
            ssid_verdict(ListMode::Whitelist, &list, &connected(&[b"Office"])),
            SsidVerdict {
                paused: false,
                matched_entry: None,
            }
        );
    }

    #[test]
    fn any_matching_station_wins_across_multiple_interfaces() {
        let verdict = ssid_verdict(
            ListMode::Blacklist,
            &strings(&["Home"]),
            &connected(&[b"Cafe", b"Home"]),
        );
        assert_eq!(verdict.matched_entry, Some(1));
        assert!(verdict.paused);
    }

    #[test]
    fn non_utf8_ssid_cannot_match_a_utf8_list_entry() {
        let verdict = ssid_verdict(
            ListMode::Blacklist,
            &strings(&["Home", "\u{00ff}"]),
            &connected(&[&[0xff, 0xfe]]),
        );
        assert_eq!(
            verdict,
            SsidVerdict {
                paused: false,
                matched_entry: None,
            }
        );
    }
}
