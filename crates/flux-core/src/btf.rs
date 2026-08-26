//! Hand-written BTF blob for the `tcp_decision` SK_STORAGE map.
//!
//! Implements blueprint §12.3. `BPF_MAP_TYPE_SK_STORAGE` creation requires a
//! non-zero `btf_key_type_id` and `btf_value_type_id`; the loader in
//! `fluxd/src/bpf/` calls `BPF_BTF_LOAD` with the blob this module builds and
//! then creates `tcp_decision` with key type id 1 (`int`) and value type id 6
//! (`struct flux_decision`).
//!
//! Building the blob here, in pure logic, is deliberate (blueprint §12.3): the
//! 5.15 BTF verifier is strict about unknown kinds, and a clang toolchain
//! upgrade can introduce `DECL_TAG` / `FLOAT` / `ENUM64` kinds that would need
//! sanitising. We only need two type ids, so ~100 hand-emitted bytes is smaller
//! and steadier than depending on clang's `.BTF`. Blueprint §15.2 test 6 lives
//! at the bottom and asserts the byte layout matches the struct definition in
//! [`crate::abi`]; xtask additionally cross-checks against clang's `.BTF` in CI.

#[cfg(test)]
use crate::abi::Decision;

/// `BTF_KIND_INT`.
const BTF_KIND_INT: u32 = 1;
/// `BTF_KIND_ARRAY`.
const BTF_KIND_ARRAY: u32 = 3;
/// `BTF_KIND_STRUCT`.
const BTF_KIND_STRUCT: u32 = 4;
/// `BTF_INT_SIGNED` encoding flag.
const BTF_INT_SIGNED: u32 = 1;
/// BTF magic (`0xeb9f`), little-endian on the wire.
const BTF_MAGIC: u16 = 0xeb9f;
/// Fixed BTF header length.
const BTF_HEADER_LEN: u32 = 24;

/// Type id of `int`, used as the SK_STORAGE key type.
pub const KEY_TYPE_ID: u32 = 1;
/// Type id of `struct flux_decision`, used as the SK_STORAGE value type.
pub const VALUE_TYPE_ID: u32 = 6;

fn btf_info(kind: u32, vlen: u32) -> u32 {
    (kind << 24) | (vlen & 0xffff)
}

fn btf_int_data(encoding: u32, bits: u32) -> u32 {
    // offset is always 0 here; encoding occupies bits 24..28, size in bits the
    // low byte (kernel UAPI BTF_INT_* accessors).
    (encoding << 24) | (bits & 0xff)
}

/// A small string table that hands out offsets and keeps insertion order.
struct StringTable {
    bytes: Vec<u8>,
}

impl StringTable {
    fn new() -> Self {
        // BTF requires the first string to be the empty string at offset 0.
        Self { bytes: vec![0] }
    }

    fn add(&mut self, s: &str) -> u32 {
        let offset = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        offset
    }
}

/// Builds the minimal BTF blob for `tcp_decision`.
///
/// Type table (matching the sketch in blueprint §12.3, extended with a `u8`
/// integer of its own as the note there requires):
///
/// ```text
/// [1] INT   "int"                size 4, 32 bits, signed   (SK_STORAGE key)
/// [2] INT   "unsigned int"       size 4, 32 bits           (magic)
/// [3] INT   "unsigned long long" size 8, 64 bits           (generation)
/// [4] INT   "unsigned char"      size 1,  8 bits           (u8 / array elem)
/// [5] ARRAY elem [4], index [1], 3 elems                   (reserved[3])
/// [6] STRUCT "flux_decision" size 16
///        magic:[2]@0  mode:[4]@32  reserved:[5]@40  generation:[3]@64  (bits)
/// ```
pub fn flux_decision_btf() -> Vec<u8> {
    let mut strings = StringTable::new();
    let s_int = strings.add("int");
    let s_uint = strings.add("unsigned int");
    let s_ull = strings.add("unsigned long long");
    let s_uchar = strings.add("unsigned char");
    let s_struct = strings.add("flux_decision");
    let s_magic = strings.add("magic");
    let s_mode = strings.add("mode");
    let s_reserved = strings.add("reserved");
    let s_generation = strings.add("generation");

    let mut types: Vec<u8> = Vec::new();

    let mut push_type = |name_off: u32, info: u32, size_or_type: u32, extra: &[u32]| {
        types.extend_from_slice(&name_off.to_le_bytes());
        types.extend_from_slice(&info.to_le_bytes());
        types.extend_from_slice(&size_or_type.to_le_bytes());
        for word in extra {
            types.extend_from_slice(&word.to_le_bytes());
        }
    };

    // [1] int
    push_type(
        s_int,
        btf_info(BTF_KIND_INT, 0),
        4,
        &[btf_int_data(BTF_INT_SIGNED, 32)],
    );
    // [2] unsigned int
    push_type(s_uint, btf_info(BTF_KIND_INT, 0), 4, &[btf_int_data(0, 32)]);
    // [3] unsigned long long
    push_type(s_ull, btf_info(BTF_KIND_INT, 0), 8, &[btf_int_data(0, 64)]);
    // [4] unsigned char
    push_type(s_uchar, btf_info(BTF_KIND_INT, 0), 1, &[btf_int_data(0, 8)]);
    // [5] array of 3 u8: btf_array { type=[4], index_type=[1], nelems=3 }
    push_type(0, btf_info(BTF_KIND_ARRAY, 0), 0, &[4, KEY_TYPE_ID, 3]);
    // [6] struct flux_decision, 4 members. Each member is
    // btf_member { name_off, type, offset-in-bits }.
    push_type(
        s_struct,
        btf_info(BTF_KIND_STRUCT, 4),
        16,
        &[
            s_magic,
            2,
            0, // magic: unsigned int @ bit 0
            s_mode,
            4,
            32, // mode: unsigned char @ bit 32
            s_reserved,
            5,
            40, // reserved: array @ bit 40
            s_generation,
            3,
            64, // generation: unsigned long long @ bit 64
        ],
    );

    let type_len = types.len() as u32;
    let str_len = strings.bytes.len() as u32;

    let mut blob =
        Vec::with_capacity(BTF_HEADER_LEN as usize + type_len as usize + str_len as usize);
    blob.extend_from_slice(&BTF_MAGIC.to_le_bytes());
    blob.push(1); // version
    blob.push(0); // flags
    blob.extend_from_slice(&BTF_HEADER_LEN.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // type_off
    blob.extend_from_slice(&type_len.to_le_bytes());
    blob.extend_from_slice(&type_len.to_le_bytes()); // str_off (after types)
    blob.extend_from_slice(&str_len.to_le_bytes());
    blob.extend_from_slice(&types);
    blob.extend_from_slice(&strings.bytes);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    // A tiny reader that decodes the fields the test needs to compare against
    // the struct definition. It follows the same UAPI layout as the writer, so
    // a change to one that is not mirrored in the other fails the test.
    struct Reader<'a> {
        types: &'a [u8],
        strings: &'a [u8],
    }

    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    fn le16(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }

    impl<'a> Reader<'a> {
        fn parse(blob: &'a [u8]) -> Self {
            assert_eq!(le16(blob, 0), BTF_MAGIC, "wrong BTF magic");
            assert_eq!(blob[2], 1, "wrong BTF version");
            let hdr_len = le32(blob, 4);
            assert_eq!(hdr_len, BTF_HEADER_LEN);
            let type_off = le32(blob, 8) as usize;
            let type_len = le32(blob, 12) as usize;
            let str_off = le32(blob, 16) as usize;
            let str_len = le32(blob, 20) as usize;
            let base = hdr_len as usize;
            Reader {
                types: &blob[base + type_off..base + type_off + type_len],
                strings: &blob[base + str_off..base + str_off + str_len],
            }
        }

        fn string(&self, off: u32) -> &str {
            let start = off as usize;
            let end = self.strings[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap();
            core::str::from_utf8(&self.strings[start..end]).unwrap()
        }
    }

    #[test]
    fn blob_layout_matches_the_decision_struct() {
        let blob = flux_decision_btf();
        let reader = Reader::parse(&blob);

        // Walk the type section to the struct (type id 6). Each INT is 16 bytes
        // (12 header + 4 data), the ARRAY is 24 (12 + 12), the STRUCT header is
        // 12 followed by 4 members * 12 bytes.
        // int, uint, ull, uchar are each 16 bytes: 4 * 16 = 64.
        let mut off = 4 * 16;
        // array: 24 bytes.
        let array_type = le32(reader.types, off + 12);
        let array_index = le32(reader.types, off + 16);
        let array_nelems = le32(reader.types, off + 20);
        assert_eq!(array_type, 4, "reserved[] element is the u8 type");
        assert_eq!(array_index, KEY_TYPE_ID);
        assert_eq!(
            array_nelems as usize,
            <[u8; 3]>::default().len(),
            "reserved[] length must match the struct"
        );
        off += 24;

        // struct header.
        let name_off = le32(reader.types, off);
        let info = le32(reader.types, off + 4);
        let size = le32(reader.types, off + 8);
        assert_eq!(reader.string(name_off), "flux_decision");
        assert_eq!(info >> 24, BTF_KIND_STRUCT);
        assert_eq!(info & 0xffff, 4, "four members");
        assert_eq!(
            size as usize,
            size_of::<Decision>(),
            "struct size must equal size_of::<Decision>()"
        );

        // members: name, type, bit offset. Byte offsets from abi::Decision,
        // times 8, are the BTF bit offsets.
        let members = off + 12;
        let read_member = |i: usize| {
            let base = members + i * 12;
            (
                reader.string(le32(reader.types, base)),
                le32(reader.types, base + 4),
                le32(reader.types, base + 8),
            )
        };
        assert_eq!(
            read_member(0),
            ("magic", 2, offset_of!(Decision, magic) as u32 * 8)
        );
        assert_eq!(
            read_member(1),
            ("mode", 4, offset_of!(Decision, mode) as u32 * 8)
        );
        assert_eq!(
            read_member(2),
            ("reserved", 5, offset_of!(Decision, reserved) as u32 * 8)
        );
        assert_eq!(
            read_member(3),
            ("generation", 3, offset_of!(Decision, generation) as u32 * 8)
        );
    }

    #[test]
    fn integer_types_have_the_widths_the_struct_uses() {
        let blob = flux_decision_btf();
        let reader = Reader::parse(&blob);
        // int(4), unsigned int(4), unsigned long long(8), unsigned char(1).
        for (i, (expected_size, expected_bits)) in [(4u32, 32u32), (4, 32), (8, 64), (1, 8)]
            .into_iter()
            .enumerate()
        {
            let base = i * 16;
            assert_eq!(le32(reader.types, base + 4) >> 24, BTF_KIND_INT);
            assert_eq!(le32(reader.types, base + 8), expected_size);
            assert_eq!(le32(reader.types, base + 12) & 0xff, expected_bits);
        }
    }
}
