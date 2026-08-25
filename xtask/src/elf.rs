//! Just enough ELF64 to read `PT_LOAD` alignments.
//!
//! Packaging needs two facts (blueprint §13.4): every `LOAD` segment of
//! `fluxd` has `p_align >= 0x4000` (16 KiB base-page devices), and the pinned
//! official sing-box is still exactly `0x1000` as recorded in `engine.lock`.

const PT_LOAD: u32 = 1;

fn u16le(b: &[u8], off: usize) -> u64 {
    u64::from(u16::from_le_bytes([b[off], b[off + 1]]))
}

fn u64le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(
        b[off..off + 8]
            .try_into()
            .expect("bounds checked by caller"),
    )
}

/// `p_align` of every `PT_LOAD` program header, in file order.
pub fn load_aligns(elf: &[u8]) -> Result<Vec<u64>, String> {
    if elf.len() < 64 {
        return Err("file too short to be an ELF".into());
    }
    if &elf[0..4] != b"\x7fELF" {
        return Err("bad ELF magic".into());
    }
    if elf[4] != 2 {
        return Err("not a 64-bit ELF".into());
    }
    if elf[5] != 1 {
        return Err("not a little-endian ELF".into());
    }

    let phoff = u64le(elf, 0x20) as usize;
    let phentsize = u16le(elf, 0x36) as usize;
    let phnum = u16le(elf, 0x38) as usize;
    if phentsize < 0x38 {
        return Err(format!("implausible e_phentsize {phentsize}"));
    }

    let mut aligns = Vec::new();
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let Some(ph) = elf.get(base..base + phentsize) else {
            return Err(format!("program header {i} out of bounds"));
        };
        let p_type = u32::from_le_bytes(ph[0..4].try_into().expect("slice is long enough"));
        if p_type == PT_LOAD {
            aligns.push(u64le(ph, 0x30));
        }
    }
    if aligns.is_empty() {
        return Err("no PT_LOAD segments".into());
    }
    Ok(aligns)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal synthetic ELF64 with two PT_LOAD headers.
    fn sample(align_a: u64, align_b: u64) -> Vec<u8> {
        let mut elf = vec![0u8; 64 + 2 * 0x38];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // little-endian
        elf[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes()); // e_phentsize
        elf[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
        for (i, align) in [align_a, align_b].into_iter().enumerate() {
            let base = 64 + i * 0x38;
            elf[base..base + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            elf[base + 0x30..base + 0x38].copy_from_slice(&align.to_le_bytes());
        }
        elf
    }

    #[test]
    fn reads_load_aligns() {
        assert_eq!(
            load_aligns(&sample(0x1000, 0x4000)).unwrap(),
            vec![0x1000, 0x4000]
        );
    }

    #[test]
    fn rejects_non_elf() {
        assert!(load_aligns(b"not an elf at all, sorry").is_err());
    }
}
