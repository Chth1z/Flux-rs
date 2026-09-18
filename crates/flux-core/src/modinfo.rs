//! ELF `.modinfo` vermagic for a GKI-line `fluxrs.ko`.
//!
//! Admission is still `finit_module` succeeding (`docs/plan/rc4.md` §4.1).
//! The strings here exist so `fluxd check` and an `lkm_finit` detail can name
//! both the module and the running kernel instead of a bare `EINVAL`.

use crate::gki_line;

/// How a module's vermagic relates to `uname -r`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VermagicRelation {
    /// Byte-for-byte equal to the running release (rare on GKI).
    Equal,
    /// Same `androidN-X.Y` line; patch / build suffix differs.
    SameLine,
    /// Different generation, or one side did not map to a GKI line.
    Different,
}

/// `vermagic=` payload from a NUL-separated `.modinfo` blob.
pub fn vermagic_from_modinfo(modinfo: &[u8]) -> Option<&str> {
    for record in modinfo.split(|byte| *byte == 0) {
        let record = core::str::from_utf8(record).ok()?;
        if let Some(value) = record.strip_prefix("vermagic=") {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// First whitespace-separated token of a vermagic string (the UTS release).
pub fn vermagic_release(vermagic: &str) -> &str {
    vermagic.split_whitespace().next().unwrap_or(vermagic)
}

/// Reads `vermagic=` from a little-endian ELF64 `.modinfo` section.
pub fn vermagic_from_elf(elf: &[u8]) -> Result<&str, &'static str> {
    let modinfo = elf64_section(elf, ".modinfo")?;
    vermagic_from_modinfo(modinfo).ok_or("ELF .modinfo has no vermagic=")
}

/// Compare a module vermagic string with `uname -r`.
pub fn relate(vermagic: &str, kernel_release: &str) -> VermagicRelation {
    let module_release = vermagic_release(vermagic);
    if module_release == kernel_release {
        return VermagicRelation::Equal;
    }
    match (
        gki_line::from_uname_release(module_release),
        gki_line::from_uname_release(kernel_release),
    ) {
        (Some(left), Some(right)) if left == right => VermagicRelation::SameLine,
        _ => VermagicRelation::Different,
    }
}

/// Minimal `ET_REL` AArch64 ELF whose only payload is `.modinfo`.
///
/// Used by packaging stubs and host tests. Not a loadable kernel module.
pub fn reloc_elf_with_modinfo(modinfo: &[u8]) -> Vec<u8> {
    const EHSIZE: usize = 64;
    const SHENTSIZE: usize = 64;
    const SHNUM: usize = 3;
    let headers = EHSIZE + SHNUM * SHENTSIZE;
    let shstrtab: &[u8] = b"\0.modinfo\0.shstrtab\0";
    let shstrtab_off = headers;
    let modinfo_off = shstrtab_off + shstrtab.len();
    let mut elf = vec![0u8; modinfo_off + modinfo.len()];

    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&1u16.to_le_bytes());
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[40..48].copy_from_slice(&(EHSIZE as u64).to_le_bytes());
    elf[52..54].copy_from_slice(&(EHSIZE as u16).to_le_bytes());
    elf[58..60].copy_from_slice(&(SHENTSIZE as u16).to_le_bytes());
    elf[60..62].copy_from_slice(&(SHNUM as u16).to_le_bytes());
    elf[62..64].copy_from_slice(&2u16.to_le_bytes());

    write_section_header(
        &mut elf[EHSIZE + SHENTSIZE..EHSIZE + 2 * SHENTSIZE],
        1,
        1,
        modinfo_off as u64,
        modinfo.len() as u64,
    );
    write_section_header(
        &mut elf[EHSIZE + 2 * SHENTSIZE..EHSIZE + 3 * SHENTSIZE],
        10,
        3,
        shstrtab_off as u64,
        shstrtab.len() as u64,
    );
    elf[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(shstrtab);
    elf[modinfo_off..].copy_from_slice(modinfo);
    elf
}

/// Deterministic envelope stub: `fluxrs-android13-5.15.ko` bytes.
pub fn stub_android13_5_15() -> Vec<u8> {
    reloc_elf_with_modinfo(b"vermagic=5.15.0-android13-stub SMP preempt aarch64\0")
}

fn write_section_header(slot: &mut [u8], name: u32, sh_type: u32, offset: u64, size: u64) {
    slot[0..4].copy_from_slice(&name.to_le_bytes());
    slot[4..8].copy_from_slice(&sh_type.to_le_bytes());
    slot[0x18..0x20].copy_from_slice(&offset.to_le_bytes());
    slot[0x20..0x28].copy_from_slice(&size.to_le_bytes());
}

fn elf64_section<'a>(elf: &'a [u8], wanted: &str) -> Result<&'a [u8], &'static str> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return Err("not a little-endian ELF64 file");
    }
    let shoff = u64_le(elf, 0x28)? as usize;
    let shentsize = u16_le(elf, 0x3a)? as usize;
    let shnum = u16_le(elf, 0x3c)? as usize;
    let shstrndx = u16_le(elf, 0x3e)? as usize;
    if shentsize < 64 || shstrndx >= shnum {
        return Err("invalid ELF section-header table");
    }
    let header = |index: usize| -> Result<&[u8], &'static str> {
        let start = shoff
            .checked_mul(1)
            .and_then(|_| index.checked_mul(shentsize))
            .and_then(|off| shoff.checked_add(off))
            .ok_or("section offset overflow")?;
        elf.get(start..start + shentsize)
            .ok_or("section header is out of bounds")
    };
    let strings_header = header(shstrndx)?;
    let strings_offset = u64_le(strings_header, 0x18)? as usize;
    let strings_size = u64_le(strings_header, 0x20)? as usize;
    let strings = elf
        .get(strings_offset..strings_offset.checked_add(strings_size).ok_or("overflow")?)
        .ok_or("section-name string table is out of bounds")?;
    for index in 0..shnum {
        let sh = header(index)?;
        let name_offset = u32_le(sh, 0)? as usize;
        let tail = strings.get(name_offset..).ok_or("invalid section name")?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(tail.len());
        let name = core::str::from_utf8(&tail[..end]).map_err(|_| "section name is not UTF-8")?;
        if name == wanted {
            let offset = u64_le(sh, 0x18)? as usize;
            let size = u64_le(sh, 0x20)? as usize;
            return elf
                .get(offset..offset.checked_add(size).ok_or("overflow")?)
                .ok_or("section payload is out of bounds");
        }
    }
    Err("ELF section is missing")
}

fn u16_le(bytes: &[u8], off: usize) -> Result<u16, &'static str> {
    bytes
        .get(off..off + 2)
        .and_then(|slice| slice.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or("truncated ELF field")
}

fn u32_le(bytes: &[u8], off: usize) -> Result<u32, &'static str> {
    bytes
        .get(off..off + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("truncated ELF field")
}

fn u64_le(bytes: &[u8], off: usize) -> Result<u64, &'static str> {
    bytes
        .get(off..off + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or("truncated ELF field")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vermagic_parses_nul_records() {
        let blob = b"license=GPL\0vermagic=5.15.202-android13-x SMP\0depends=\0";
        assert_eq!(
            vermagic_from_modinfo(blob),
            Some("5.15.202-android13-x SMP")
        );
        assert_eq!(
            vermagic_release("5.15.202-android13-x SMP preempt"),
            "5.15.202-android13-x"
        );
    }

    #[test]
    fn stub_elf_round_trips() {
        let elf = stub_android13_5_15();
        let magic = vermagic_from_elf(&elf).expect("stub vermagic");
        assert!(magic.starts_with("5.15.0-android13-stub"));
        assert_eq!(
            relate(magic, "5.15.211-Qkernel-g7a72da9438"),
            VermagicRelation::SameLine
        );
        assert_eq!(
            relate(magic, "6.1.75-something"),
            VermagicRelation::Different
        );
        assert_eq!(
            relate(magic, "5.15.0-android13-stub"),
            VermagicRelation::Equal
        );
    }

    #[test]
    fn ddk_vermagic_and_qkernel_share_a_gki_line() {
        assert_eq!(
            relate(
                "5.15.202-android13-5.15.202_r00-dirty SMP",
                "5.15.211-Qkernel-g7a72da9438"
            ),
            VermagicRelation::SameLine
        );
    }
}
