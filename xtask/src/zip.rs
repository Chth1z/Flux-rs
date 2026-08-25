//! Deterministic ZIP writer.
//!
//! Blueprint §13.4 step 6: fixed entry order, `SOURCE_DATE_EPOCH`, no extra
//! attributes. Two packaging runs over identical inputs must produce
//! byte-identical archives, so this writer emits exactly the fields below and
//! nothing else — no extra fields, no comments, no data descriptors.
//!
//! Entries are STORED, not deflated. Compression is not a packaging
//! requirement, ~97% of the payload is two already-dense binaries, and a
//! deflate implementation would either be a new dependency (governance §1.2)
//! or several hundred lines of hand-rolled bit-fiddling nobody asked for.

/// One file to archive. Directories are not stored: every extractor creates
/// parents, and omitting them removes an ordering degree of freedom.
pub struct Entry {
    /// Forward-slash path inside the archive.
    pub name: String,
    /// Unix permission bits, e.g. `0o755`.
    pub mode: u32,
    pub data: Vec<u8>,
}

/// Build the archive in memory, all entries stamped with one DOS timestamp.
pub fn build(entries: &[Entry], dos_date: u16, dos_time: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();

    for entry in entries {
        let crc = crc32(&entry.data);
        let name = entry.name.as_bytes();
        let size = entry.data.len() as u32;
        let offset = out.len() as u32;

        // Local file header.
        out.extend_from_slice(&0x04034b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: STORE
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(&entry.data);

        // Central directory record.
        central.extend_from_slice(&0x02014b50u32.to_le_bytes());
        central.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes()); // made by: unix
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&dos_time.to_le_bytes());
        central.extend_from_slice(&dos_date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        let external = (0o100000u32 | (entry.mode & 0o7777)) << 16;
        central.extend_from_slice(&external.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory.
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    out
}

/// `SOURCE_DATE_EPOCH` -> DOS (date, time), UTC. DOS timestamps start at
/// 1980-01-01, so anything earlier — including the unset default of 0 —
/// clamps there, which is itself deterministic.
pub fn dos_datetime(epoch_secs: i64) -> (u16, u16) {
    const DOS_EPOCH: i64 = 315_532_800; // 1980-01-01T00:00:00Z
    let secs = epoch_secs.max(DOS_EPOCH);

    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    let date = (((year - 1980) as u16) << 9) | ((month as u16) << 5) | day as u16;
    let time =
        (((tod / 3600) as u16) << 11) | ((((tod / 60) % 60) as u16) << 5) | ((tod % 60) / 2) as u16;
    (date, time)
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's
/// `civil_from_days`, exact over the full DOS range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe as i64 + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// CRC-32 (IEEE 802.3), the ZIP checksum.
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        // The standard CRC-32 check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn dos_time_clamps_and_converts() {
        // Pre-1980 clamps to the DOS epoch.
        assert_eq!(dos_datetime(0), dos_datetime(315_532_800));
        let (date, time) = dos_datetime(0);
        // Year bits are zero at the 1980 floor: month 1, day 1.
        assert_eq!(date, (1 << 5) | 1);
        assert_eq!(time, 0);

        // 2026-08-17T09:47:06Z (the engine release timestamp).
        let (date, time) = dos_datetime(1_786_960_026);
        assert_eq!(date, ((2026 - 1980) << 9) | (8 << 5) | 17);
        assert_eq!(time, (9 << 11) | (47 << 5) | (6 / 2));
    }

    #[test]
    fn archive_is_deterministic_and_well_formed() {
        let entries = vec![
            Entry {
                name: "a.txt".into(),
                mode: 0o644,
                data: b"hello\n".to_vec(),
            },
            Entry {
                name: "bin/b".into(),
                mode: 0o755,
                data: vec![0u8; 100],
            },
        ];
        let one = build(&entries, 0x21, 0);
        let two = build(&entries, 0x21, 0);
        assert_eq!(one, two);
        assert_eq!(&one[0..4], &0x04034b50u32.to_le_bytes());
        // EOCD is the last 22 bytes of an archive without a comment.
        assert_eq!(
            &one[one.len() - 22..one.len() - 18],
            &0x06054b50u32.to_le_bytes()
        );
    }
}
