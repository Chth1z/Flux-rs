//! Strict ELF64 parser for the embedded BPF object.
//!
//! Supported input is intentionally tiny: little-endian `ET_REL`/`EM_BPF`,
//! one symbol table, one program per configured executable section and
//! `SHT_REL` map relocations of type `R_BPF_64_64`.

use std::collections::BTreeSet;
use std::os::fd::RawFd;

const ELF_HEADER_SIZE: usize = 64;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_SIZE: usize = 24;
const REL_SIZE: usize = 16;
const BPF_INSN_SIZE: usize = 8;
const MAX_OBJECT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SECTIONS: usize = 256;
const MAX_SYMBOLS: usize = 4096;

const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHF_EXECINSTR: u64 = 4;
const STB_GLOBAL: u8 = 1;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const R_BPF_64_64: u32 = 1;
const BPF_LD_IMM64: u8 = 0x18;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const ABI_SECTION: &str = "flux_abi";

#[derive(Debug, Clone)]
struct Section {
    name: String,
    section_type: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: usize,
    info: usize,
    entsize: usize,
}

#[derive(Debug, Clone)]
struct Symbol {
    name: String,
    info: u8,
    shndx: usize,
    value: usize,
    size: usize,
}

impl Symbol {
    fn binding(&self) -> u8 {
        self.info >> 4
    }

    fn symbol_type(&self) -> u8 {
        self.info & 0x0f
    }
}

#[derive(Debug)]
pub struct Object<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    symtab_index: usize,
    abi_magic: u32,
}

pub struct ProgramImage {
    pub instructions: Vec<u8>,
    pub insn_count: u32,
}

impl<'a> Object<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("embedded BPF object is empty; rebuild with FLUX_BUILD_BPF=1".into());
        }
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(format!(
                "embedded BPF object exceeds {MAX_OBJECT_BYTES} bytes"
            ));
        }
        if bytes.len() < ELF_HEADER_SIZE || &bytes[..4] != b"\x7fELF" {
            return Err("bad ELF magic or truncated ELF header".into());
        }
        if bytes[4] != 2 {
            return Err("BPF object is not ELFCLASS64".into());
        }
        if bytes[5] != 1 {
            return Err("BPF object is not ELFDATA2LSB".into());
        }
        if bytes[6] != 1 {
            return Err("BPF object has an unsupported ELF version".into());
        }
        if read_u16(bytes, 0x10)? != ET_REL {
            return Err("BPF object is not ET_REL".into());
        }
        if read_u16(bytes, 0x12)? != EM_BPF {
            return Err("ELF e_machine is not EM_BPF".into());
        }
        if read_u32(bytes, 0x14)? != 1 {
            return Err("BPF object has an unsupported ELF header version".into());
        }
        if read_u16(bytes, 0x34)? as usize != ELF_HEADER_SIZE {
            return Err("ELF header size is not 64".into());
        }
        let shoff = to_usize(read_u64(bytes, 0x28)?, "section table offset")?;
        let shentsize = read_u16(bytes, 0x3a)? as usize;
        let shnum = read_u16(bytes, 0x3c)? as usize;
        let shstrndx = read_u16(bytes, 0x3e)? as usize;
        if shentsize != SECTION_HEADER_SIZE || shnum == 0 || shnum > MAX_SECTIONS {
            return Err("invalid ELF section table shape".into());
        }
        if shstrndx >= shnum {
            return Err("section-name table index is out of range".into());
        }
        checked_range(
            shoff,
            shnum
                .checked_mul(shentsize)
                .ok_or("section table size overflow")?,
            bytes.len(),
            "section table",
        )?;

        let raw_section = |index: usize| -> Result<&[u8], String> {
            let start = shoff
                .checked_add(
                    index
                        .checked_mul(shentsize)
                        .ok_or("section offset overflow")?,
                )
                .ok_or("section offset overflow")?;
            slice(bytes, start, shentsize, "section header")
        };
        let names_header = raw_section(shstrndx)?;
        if read_u32(names_header, 4)? != SHT_STRTAB {
            return Err("section-name table is not SHT_STRTAB".into());
        }
        let names = section_payload(bytes, names_header, "section-name table")?;

        let mut sections = Vec::with_capacity(shnum);
        for index in 0..shnum {
            let raw = raw_section(index)?;
            let name = elf_string(names, read_u32(raw, 0)? as usize, "section name")?;
            let section_type = read_u32(raw, 4)?;
            let offset = to_usize(read_u64(raw, 24)?, "section offset")?;
            let size = to_usize(read_u64(raw, 32)?, "section size")?;
            if section_type != SHT_NOBITS {
                checked_range(offset, size, bytes.len(), &format!("section `{name}`"))?;
            }
            sections.push(Section {
                name,
                section_type,
                flags: read_u64(raw, 8)?,
                offset,
                size,
                link: read_u32(raw, 40)? as usize,
                info: read_u32(raw, 44)? as usize,
                entsize: to_usize(read_u64(raw, 56)?, "section entsize")?,
            });
        }

        let symtabs = sections
            .iter()
            .enumerate()
            .filter(|(_, section)| section.section_type == SHT_SYMTAB)
            .collect::<Vec<_>>();
        if symtabs.len() != 1 {
            return Err(format!("expected one SHT_SYMTAB, found {}", symtabs.len()));
        }
        let (symtab_index, symtab) = symtabs[0];
        if symtab.entsize != SYMBOL_SIZE || !symtab.size.is_multiple_of(SYMBOL_SIZE) {
            return Err("symbol table has an invalid entry size".into());
        }
        let symbol_count = symtab.size / SYMBOL_SIZE;
        if symbol_count == 0 || symbol_count > MAX_SYMBOLS || symtab.link >= sections.len() {
            return Err("symbol table shape or string-table link is invalid".into());
        }
        let strings_section = &sections[symtab.link];
        if strings_section.section_type != SHT_STRTAB {
            return Err("symbol names are not in SHT_STRTAB".into());
        }
        let strings = slice(
            bytes,
            strings_section.offset,
            strings_section.size,
            "symbol strings",
        )?;
        let symbol_bytes = slice(bytes, symtab.offset, symtab.size, "symbol table")?;
        let mut symbols = Vec::with_capacity(symbol_count);
        for index in 0..symbol_count {
            let raw = slice(
                symbol_bytes,
                index * SYMBOL_SIZE,
                SYMBOL_SIZE,
                "symbol entry",
            )?;
            symbols.push(Symbol {
                name: elf_string(strings, read_u32(raw, 0)? as usize, "symbol name")?,
                info: raw[4],
                shndx: read_u16(raw, 6)? as usize,
                value: to_usize(read_u64(raw, 8)?, "symbol value")?,
                size: to_usize(read_u64(raw, 16)?, "symbol size")?,
            });
        }

        let abi = unique_section(&sections, ABI_SECTION)?;
        if abi.section_type != SHT_PROGBITS || abi.size != 4 {
            return Err("flux_abi section must contain exactly one u32".into());
        }
        let abi_magic = read_u32(slice(bytes, abi.offset, abi.size, ABI_SECTION)?, 0)?;

        Ok(Self {
            bytes,
            sections,
            symbols,
            symtab_index,
            abi_magic,
        })
    }

    pub fn abi_magic(&self) -> u32 {
        self.abi_magic
    }

    pub fn program(
        &self,
        expected_name: &str,
        expected_section: &str,
        mut resolve_map: impl FnMut(&str) -> Option<RawFd>,
    ) -> Result<ProgramImage, String> {
        let (section_index, section) = self
            .sections
            .iter()
            .enumerate()
            .find(|(_, section)| section.name == expected_section)
            .ok_or_else(|| format!("program section `{expected_section}` is missing"))?;
        if self
            .sections
            .iter()
            .filter(|section| section.name == expected_section)
            .count()
            != 1
        {
            return Err(format!(
                "program section `{expected_section}` is duplicated"
            ));
        }
        if section.section_type != SHT_PROGBITS
            || section.flags & SHF_EXECINSTR == 0
            || section.size == 0
            || !section.size.is_multiple_of(BPF_INSN_SIZE)
        {
            return Err(format!(
                "program section `{expected_section}` has invalid flags/size"
            ));
        }
        let functions = self
            .symbols
            .iter()
            .filter(|symbol| {
                symbol.name == expected_name
                    && symbol.shndx == section_index
                    && symbol.binding() == STB_GLOBAL
                    && symbol.symbol_type() == STT_FUNC
            })
            .collect::<Vec<_>>();
        if functions.len() != 1 || functions[0].value != 0 || functions[0].size != section.size {
            return Err(format!(
                "program `{expected_name}` is not the single whole-section function"
            ));
        }

        let mut instructions =
            slice(self.bytes, section.offset, section.size, expected_section)?.to_vec();
        let relocations = self
            .sections
            .iter()
            .filter(|candidate| {
                candidate.section_type == SHT_REL && candidate.info == section_index
            })
            .collect::<Vec<_>>();
        if relocations.len() != 1 {
            return Err(format!(
                "program `{expected_name}` needs exactly one SHT_REL section, found {}",
                relocations.len()
            ));
        }
        let relocations = relocations[0];
        if relocations.link != self.symtab_index
            || relocations.entsize != REL_SIZE
            || !relocations.size.is_multiple_of(REL_SIZE)
        {
            return Err(format!(
                "relocations for `{expected_name}` have invalid metadata"
            ));
        }
        let entries = slice(
            self.bytes,
            relocations.offset,
            relocations.size,
            "program relocations",
        )?;
        let mut patched = BTreeSet::new();
        for index in 0..entries.len() / REL_SIZE {
            let relocation = slice(entries, index * REL_SIZE, REL_SIZE, "relocation")?;
            let offset = to_usize(read_u64(relocation, 0)?, "relocation offset")?;
            let info = read_u64(relocation, 8)?;
            let symbol_index = (info >> 32) as usize;
            let relocation_type = info as u32;
            if relocation_type != R_BPF_64_64 {
                return Err(format!("unsupported BPF relocation type {relocation_type}"));
            }
            if symbol_index >= self.symbols.len()
                || !offset.is_multiple_of(BPF_INSN_SIZE)
                || !patched.insert(offset)
            {
                return Err("relocation symbol/offset is invalid or duplicated".into());
            }
            checked_range(
                offset,
                2 * BPF_INSN_SIZE,
                instructions.len(),
                "LD_IMM64 relocation",
            )?;
            let symbol = &self.symbols[symbol_index];
            if symbol.binding() != STB_GLOBAL
                || symbol.symbol_type() != STT_OBJECT
                || symbol.shndx >= self.sections.len()
                || self.sections[symbol.shndx].name != ".maps"
            {
                return Err(format!("relocation `{}` is not a map symbol", symbol.name));
            }
            let fd = resolve_map(&symbol.name)
                .ok_or_else(|| format!("map relocation `{}` has no FD binding", symbol.name))?;
            if fd < 0 {
                return Err(format!(
                    "map relocation `{}` has a negative FD",
                    symbol.name
                ));
            }
            if instructions[offset] != BPF_LD_IMM64
                || instructions[offset + BPF_INSN_SIZE..offset + 2 * BPF_INSN_SIZE]
                    != [0; BPF_INSN_SIZE]
            {
                return Err(format!(
                    "relocation `{}` does not target LD_IMM64",
                    symbol.name
                ));
            }
            instructions[offset + 1] = (instructions[offset + 1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
            instructions[offset + 4..offset + 8].copy_from_slice(&fd.to_le_bytes());
            instructions[offset + 12..offset + 16].fill(0);
        }

        Ok(ProgramImage {
            insn_count: u32::try_from(instructions.len() / BPF_INSN_SIZE)
                .map_err(|_| "program instruction count exceeds u32")?,
            instructions,
        })
    }
}

fn unique_section<'a>(sections: &'a [Section], name: &str) -> Result<&'a Section, String> {
    let found = sections
        .iter()
        .filter(|section| section.name == name)
        .collect::<Vec<_>>();
    match found.as_slice() {
        [section] => Ok(section),
        _ => Err(format!(
            "expected one `{name}` section, found {}",
            found.len()
        )),
    }
}

fn section_payload<'a>(bytes: &'a [u8], header: &[u8], label: &str) -> Result<&'a [u8], String> {
    let offset = to_usize(read_u64(header, 24)?, "section payload offset")?;
    let size = to_usize(read_u64(header, 32)?, "section payload size")?;
    slice(bytes, offset, size, label)
}

fn elf_string(bytes: &[u8], offset: usize, label: &str) -> Result<String, String> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| format!("{label} offset is out of bounds"))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("{label} is not NUL terminated"))?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_string)
        .map_err(|_| format!("{label} is not UTF-8"))
}

fn checked_range(offset: usize, size: usize, total: usize, label: &str) -> Result<(), String> {
    if offset <= total && size <= total - offset {
        Ok(())
    } else {
        Err(format!("{label} is out of bounds"))
    }
}

fn slice<'a>(bytes: &'a [u8], offset: usize, size: usize, label: &str) -> Result<&'a [u8], String> {
    checked_range(offset, size, bytes.len(), label)?;
    Ok(&bytes[offset..offset + size])
}

fn to_usize(value: u64, label: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{label} does not fit usize"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        slice(bytes, offset, 2, "u16")?
            .try_into()
            .expect("length checked"),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        slice(bytes, offset, 4, "u32")?
            .try_into()
            .expect("length checked"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        slice(bytes, offset, 8, "u64")?
            .try_into()
            .expect("length checked"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn align8(value: usize) -> usize {
        (value + 7) & !7
    }

    fn sample() -> Vec<u8> {
        let sh_names = b"\0.shstrtab\0tc\0.reltc\0.maps\0.strtab\0.symtab\0flux_abi\0";
        let strings = b"\0flx_test\0counters\0";
        let mut program = vec![0u8; 16];
        program[0] = BPF_LD_IMM64;
        let mut reloc = vec![0u8; REL_SIZE];
        put64(&mut reloc, 0, 0);
        put64(&mut reloc, 8, (2u64 << 32) | u64::from(R_BPF_64_64));
        let maps = vec![0u8; 8];
        let mut symbols = vec![0u8; 3 * SYMBOL_SIZE];
        // [1] flx_test: GLOBAL FUNC, whole section 2.
        put32(&mut symbols, SYMBOL_SIZE, 1);
        symbols[SYMBOL_SIZE + 4] = 0x12;
        put16(&mut symbols, SYMBOL_SIZE + 6, 2);
        put64(&mut symbols, SYMBOL_SIZE + 16, program.len() as u64);
        // [2] counters: GLOBAL OBJECT in .maps section 4.
        put32(&mut symbols, 2 * SYMBOL_SIZE, 10);
        symbols[2 * SYMBOL_SIZE + 4] = 0x11;
        put16(&mut symbols, 2 * SYMBOL_SIZE + 6, 4);
        put64(&mut symbols, 2 * SYMBOL_SIZE + 16, 8);
        let abi = 0xF10C_0903u32.to_le_bytes().to_vec();

        let payloads: [&[u8]; 7] = [sh_names, &program, &reloc, &maps, strings, &symbols, &abi];
        let mut offsets = Vec::new();
        let mut cursor = ELF_HEADER_SIZE;
        let mut elf = vec![0u8; ELF_HEADER_SIZE];
        for payload in payloads {
            cursor = align8(cursor);
            elf.resize(cursor, 0);
            offsets.push(cursor);
            elf.extend_from_slice(payload);
            cursor += payload.len();
        }
        let shoff = align8(elf.len());
        elf.resize(shoff + 8 * SECTION_HEADER_SIZE, 0);
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        put16(&mut elf, 0x10, ET_REL);
        put16(&mut elf, 0x12, EM_BPF);
        put32(&mut elf, 0x14, 1);
        put16(&mut elf, 0x34, ELF_HEADER_SIZE as u16);
        put64(&mut elf, 0x28, shoff as u64);
        put16(&mut elf, 0x3a, SECTION_HEADER_SIZE as u16);
        put16(&mut elf, 0x3c, 8);
        put16(&mut elf, 0x3e, 1);

        let names = [0u32, 1, 11, 14, 21, 27, 35, 43];
        let types = [
            0,
            SHT_STRTAB,
            SHT_PROGBITS,
            SHT_REL,
            SHT_PROGBITS,
            SHT_STRTAB,
            SHT_SYMTAB,
            SHT_PROGBITS,
        ];
        let sizes = [
            0usize,
            sh_names.len(),
            program.len(),
            reloc.len(),
            maps.len(),
            strings.len(),
            symbols.len(),
            abi.len(),
        ];
        for index in 1..8 {
            let base = shoff + index * SECTION_HEADER_SIZE;
            put32(&mut elf, base, names[index]);
            put32(&mut elf, base + 4, types[index]);
            put64(&mut elf, base + 24, offsets[index - 1] as u64);
            put64(&mut elf, base + 32, sizes[index] as u64);
            put64(&mut elf, base + 48, 8);
        }
        // tc executable.
        put64(&mut elf, shoff + 2 * SECTION_HEADER_SIZE + 8, SHF_EXECINSTR);
        // .reltc links symtab, applies to tc, entry size 16.
        put32(&mut elf, shoff + 3 * SECTION_HEADER_SIZE + 40, 6);
        put32(&mut elf, shoff + 3 * SECTION_HEADER_SIZE + 44, 2);
        put64(
            &mut elf,
            shoff + 3 * SECTION_HEADER_SIZE + 56,
            REL_SIZE as u64,
        );
        // symtab links strtab, entry size 24.
        put32(&mut elf, shoff + 6 * SECTION_HEADER_SIZE + 40, 5);
        put64(
            &mut elf,
            shoff + 6 * SECTION_HEADER_SIZE + 56,
            SYMBOL_SIZE as u64,
        );
        elf
    }

    #[test]
    fn parses_and_relocates_the_supported_subset() {
        let elf = sample();
        let object = Object::parse(&elf).unwrap();
        assert_eq!(object.abi_magic(), 0xF10C_0903);
        let image = object
            .program("flx_test", "tc", |name| (name == "counters").then_some(42))
            .unwrap();
        assert_eq!(image.insn_count, 2);
        assert_eq!(image.instructions[1] >> 4, BPF_PSEUDO_MAP_FD);
        assert_eq!(
            i32::from_le_bytes(image.instructions[4..8].try_into().unwrap()),
            42
        );
    }

    #[test]
    fn rejects_wrong_machine_and_wrong_relocation_type() {
        let mut elf = sample();
        put16(&mut elf, 0x12, 62);
        assert!(Object::parse(&elf).unwrap_err().contains("EM_BPF"));

        let mut elf = sample();
        // Locate .reltc through the known sample payload alignment.
        let reloc_offset = read_u64(
            &elf,
            read_u64(&elf, 0x28).unwrap() as usize + 3 * SECTION_HEADER_SIZE + 24,
        )
        .unwrap() as usize;
        put64(&mut elf, reloc_offset + 8, (2u64 << 32) | 2);
        let object = Object::parse(&elf).unwrap();
        assert!(object.program("flx_test", "tc", |_| Some(1)).is_err());
    }
}
