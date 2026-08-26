//! Cross-check the hand-written SK_STORAGE BTF against clang's `.BTF`.

#[derive(Debug)]
struct TypeRecord {
    name: String,
    kind: u32,
    kind_flag: bool,
    size_or_type: u32,
    data: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct StructLayout {
    size: u32,
    /// (field name, bit offset, byte size)
    members: Vec<(String, u32, u64)>,
}

fn le16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    bytes
        .get(offset..offset + 2)
        .ok_or("truncated BTF u16".to_string())?
        .try_into()
        .map(u16::from_le_bytes)
        .map_err(|_| "truncated BTF u16".to_string())
}

fn le32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    bytes
        .get(offset..offset + 4)
        .ok_or("truncated BTF u32".to_string())?
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| "truncated BTF u32".to_string())
}

fn string_at(strings: &[u8], offset: u32) -> Result<String, String> {
    let tail = strings
        .get(offset as usize..)
        .ok_or_else(|| format!("BTF string offset {offset} is out of bounds"))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("BTF string at {offset} is unterminated"))?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_string)
        .map_err(|_| format!("BTF string at {offset} is not UTF-8"))
}

fn extra_words(kind: u32, vlen: usize) -> Result<usize, String> {
    match kind {
        1 => Ok(1),                    // INT
        2 | 7..=12 | 16 | 18 => Ok(0), // PTR/FWD/modifiers/FUNC/FLOAT/TYPE_TAG
        3 => Ok(3),                    // ARRAY
        4 | 5 => Ok(vlen * 3),         // STRUCT/UNION members
        6 | 13 => Ok(vlen * 2),        // ENUM/FUNC_PROTO
        14 | 17 => Ok(1),              // VAR/DECL_TAG
        15 | 19 => Ok(vlen * 3),       // DATASEC/ENUM64
        _ => Err(format!("unsupported BTF kind {kind}")),
    }
}

fn parse(blob: &[u8]) -> Result<Vec<TypeRecord>, String> {
    if le16(blob, 0)? != 0xeb9f || blob.get(2) != Some(&1) {
        return Err("invalid BTF header magic/version".into());
    }
    let header_len = le32(blob, 4)? as usize;
    let type_offset = header_len + le32(blob, 8)? as usize;
    let type_len = le32(blob, 12)? as usize;
    let string_offset = header_len + le32(blob, 16)? as usize;
    let string_len = le32(blob, 20)? as usize;
    let types = blob
        .get(type_offset..type_offset + type_len)
        .ok_or("BTF type section is out of bounds")?;
    let strings = blob
        .get(string_offset..string_offset + string_len)
        .ok_or("BTF string section is out of bounds")?;

    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < types.len() {
        let name_offset = le32(types, offset)?;
        let info = le32(types, offset + 4)?;
        let size_or_type = le32(types, offset + 8)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let words = extra_words(kind, vlen)?;
        let end = offset
            .checked_add(12 + words * 4)
            .ok_or("BTF type length overflow")?;
        if end > types.len() {
            return Err(format!("BTF type {} is truncated", records.len() + 1));
        }
        let mut data = Vec::with_capacity(words);
        for word in 0..words {
            data.push(le32(types, offset + 12 + word * 4)?);
        }
        records.push(TypeRecord {
            name: string_at(strings, name_offset)?,
            kind,
            kind_flag: info >> 31 != 0,
            size_or_type,
            data,
        });
        offset = end;
    }
    Ok(records)
}

fn type_size(records: &[TypeRecord], id: u32, depth: usize) -> Result<u64, String> {
    if depth > 32 || id == 0 {
        return Err(format!("invalid or recursive BTF type id {id}"));
    }
    let record = records
        .get(id as usize - 1)
        .ok_or_else(|| format!("BTF type id {id} is out of bounds"))?;
    match record.kind {
        1 | 4 | 5 | 6 | 16 => Ok(u64::from(record.size_or_type)),
        3 => {
            let element = *record.data.first().ok_or("truncated BTF array")?;
            let count = *record.data.get(2).ok_or("truncated BTF array")?;
            type_size(records, element, depth + 1)?
                .checked_mul(u64::from(count))
                .ok_or("BTF array size overflow".into())
        }
        8..=11 | 18 => type_size(records, record.size_or_type, depth + 1),
        other => Err(format!("BTF kind {other} has no value size")),
    }
}

fn decision_layout(blob: &[u8]) -> Result<StructLayout, String> {
    let records = parse(blob)?;
    let record = records
        .iter()
        .find(|record| record.kind == 4 && record.name == "flux_decision")
        .ok_or("BTF has no `struct flux_decision`")?;
    let mut members = Vec::new();
    for member in record.data.chunks_exact(3) {
        let name = {
            // Reparse just the string table through the member's name offset.
            let header_len = le32(blob, 4)? as usize;
            let string_offset = header_len + le32(blob, 16)? as usize;
            let string_len = le32(blob, 20)? as usize;
            string_at(
                blob.get(string_offset..string_offset + string_len)
                    .ok_or("BTF string section is out of bounds")?,
                member[0],
            )?
        };
        let offset = if record.kind_flag {
            member[2] & 0x00ff_ffff
        } else {
            member[2]
        };
        members.push((name, offset, type_size(&records, member[1], 0)?));
    }
    Ok(StructLayout {
        size: record.size_or_type,
        members,
    })
}

pub fn run() -> Result<(), String> {
    crate::package::build_bpf()?;
    let object_path = crate::util::repo_root().join("target/xtask/flux.bpf.o");
    let object =
        std::fs::read(&object_path).map_err(|e| format!("read {}: {e}", object_path.display()))?;
    let clang_btf = crate::elf::section(&object, ".BTF")?;
    let clang = decision_layout(clang_btf)?;
    let handwritten = decision_layout(&flux_core::btf::flux_decision_btf())?;
    if clang != handwritten {
        return Err(format!(
            "hand-written BTF disagrees with clang .BTF\n  clang: {clang:?}\n  hand:  {handwritten:?}"
        ));
    }
    println!(
        "btf-check: OK — flux_decision size {}, members {:?}",
        clang.size, clang.members
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_handwritten_decision_layout() {
        let layout = decision_layout(&flux_core::btf::flux_decision_btf()).unwrap();
        assert_eq!(layout.size, 16);
        assert_eq!(
            layout.members,
            vec![
                ("magic".into(), 0, 4),
                ("mode".into(), 32, 1),
                ("reserved".into(), 40, 3),
                ("generation".into(), 64, 8),
            ]
        );
    }
}
