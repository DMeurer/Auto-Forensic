//! Partition tables (pieces I7–I10): MBR with extended partitions, GPT (primary or backup
//! header), and no table at all, where the volume starts at offset 0.
//!
//! Odd tables are listed as found, with notes, never silently fixed: a CRC mismatch, a hybrid
//! MBR, a partition past the end of the disk.

use std::io;

/// How a disk is divided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// No partition table: one volume from offset 0.
    None,
    Mbr,
    Gpt,
}

impl Scheme {
    pub fn name(self) -> &'static str {
        match self {
            Scheme::None => "none",
            Scheme::Mbr => "mbr",
            Scheme::Gpt => "gpt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// Numbered like Linux: MBR primaries 1–4 by slot, logicals from 5; GPT by entry, from 1.
    pub number: u32,
    /// Bytes from the start of the disk.
    pub start: u64,
    pub len: u64,
    /// `0x83` for MBR, the type GUID for GPT.
    pub kind: String,
    /// The type's common name and, for GPT, the partition's own name.
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub scheme: Scheme,
    pub sector_size: u64,
    /// In table order.
    pub partitions: Vec<Partition>,
    /// Anything odd: checksum mismatches, hybrid MBRs, partitions past the end, broken chains.
    pub notes: Vec<String>,
}

/// Reads exactly `buf.len()` bytes at an offset of the disk.
pub type ReadAt<'a> = dyn FnMut(u64, &mut [u8]) -> io::Result<()> + 'a;

struct Disk<'a, 'b> {
    read: &'a mut ReadAt<'b>,
    len: u64,
}

impl Disk<'_, '_> {
    /// `n` bytes at `off`, or `None` if they lie past the end. Read errors are errors.
    fn get(&mut self, off: u64, n: usize) -> io::Result<Option<Vec<u8>>> {
        if off.checked_add(n as u64).is_none_or(|end| end > self.len) {
            return Ok(None);
        }
        let mut b = vec![0u8; n];
        (self.read)(off, &mut b)?;
        Ok(Some(b))
    }
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap_or_default())
}

fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default())
}

/// Finds the partition table of a disk `len` bytes long.
pub fn read_table(read: &mut ReadAt<'_>, len: u64) -> io::Result<Table> {
    let mut d = Disk { read, len };
    let mut notes = Vec::new();
    let mbr = d.get(0, 512)?;
    // GPT first: its header is unmistakable, and its protective MBR is not a real table.
    for ss in [512u64, 4096] {
        if let Some(parts) = gpt(&mut d, ss, &mut notes)? {
            if let Some(m) = &mbr {
                let others: Vec<String> = mbr_entries(m)
                    .filter(|e| e.1 != 0xee)
                    .map(|e| format!("{:#04x}", e.1))
                    .collect();
                if !others.is_empty() {
                    notes.push(format!(
                        "hybrid MBR: besides the GPT it lists type(s) {}",
                        others.join(", ")
                    ));
                }
            }
            return Ok(table(Scheme::Gpt, ss, parts, notes, len));
        }
    }
    let Some(m) = mbr else {
        return Ok(table(Scheme::None, 512, vec![], notes, len));
    };
    let head_len = (crate::HEAD_LEN as u64).min(len) as usize;
    let head = d.get(0, head_len)?.unwrap_or_default();
    let mbr_like =
        m[510..512] == [0x55, 0xaa] && (0..4).all(|i| matches!(m[446 + i * 16], 0 | 0x80));
    if crate::detect(&head) != crate::Content::Unknown || !mbr_like {
        return Ok(table(Scheme::None, 512, vec![], notes, len));
    }
    let parts = mbr_parts(&mut d, &m, &mut notes)?;
    if parts.is_empty() {
        notes.push("the MBR partition table is empty".into());
    }
    if mbr_entries(&m).any(|e| e.1 == 0xee) {
        notes.push("protective MBR, but no valid GPT header".into());
    }
    Ok(table(Scheme::Mbr, 512, parts, notes, len))
}

/// Adds the notes every scheme shares: partitions past the end, and overlaps.
fn table(
    scheme: Scheme,
    sector_size: u64,
    partitions: Vec<Partition>,
    mut notes: Vec<String>,
    len: u64,
) -> Table {
    for p in &partitions {
        if p.start.saturating_add(p.len) > len {
            notes.push(format!(
                "partition {} runs past the end of the disk ({} bytes beyond)",
                p.number,
                p.start.saturating_add(p.len) - len
            ));
        }
    }
    let mut sorted: Vec<&Partition> = partitions.iter().collect();
    sorted.sort_by_key(|p| p.start);
    for w in sorted.windows(2) {
        if w[0].start + w[0].len > w[1].start {
            notes.push(format!(
                "partitions {} and {} overlap",
                w[0].number, w[1].number
            ));
        }
    }
    Table {
        scheme,
        sector_size,
        partitions,
        notes,
    }
}

/// The used slots of an MBR sector: (slot, type, first LBA, sector count).
fn mbr_entries(m: &[u8]) -> impl Iterator<Item = (usize, u8, u64, u64)> + '_ {
    (0..4).filter_map(move |i| {
        let e = &m[446 + i * 16..462 + i * 16];
        let (kind, lba, count) = (e[4], u64::from(u32le(e, 8)), u64::from(u32le(e, 12)));
        (kind != 0 && count > 0).then_some((i, kind, lba, count))
    })
}

fn is_extended(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0f | 0x85)
}

// shortcut: MBR sectors are taken as 512 bytes; 4Kn disks with an MBR would list wrong offsets, upgrade when one turns up.
fn mbr_parts(
    d: &mut Disk<'_, '_>,
    m: &[u8],
    notes: &mut Vec<String>,
) -> io::Result<Vec<Partition>> {
    let mut parts = Vec::new();
    let mut logical = 5;
    for (slot, kind, lba, count) in mbr_entries(m) {
        if !is_extended(kind) {
            parts.push(mbr_part(slot as u32 + 1, kind, lba, count));
            continue;
        }
        // The chain of extended boot records: each holds one logical partition and a link.
        let (base, mut ebr, mut seen) = (lba, lba, Vec::new());
        loop {
            if seen.contains(&ebr) || seen.len() >= 128 {
                notes.push(format!(
                    "the extended partition chain loops at sector {ebr}"
                ));
                break;
            }
            seen.push(ebr);
            let Some(s) = d.get(ebr * 512, 512)? else {
                notes.push(format!(
                    "extended boot record at sector {ebr} is past the end"
                ));
                break;
            };
            if s[510..512] != [0x55, 0xaa] {
                notes.push(format!(
                    "extended boot record at sector {ebr} has no signature"
                ));
                break;
            }
            let entries: Vec<_> = mbr_entries(&s).collect();
            if let Some(&(_, k, rel, n)) = entries.iter().find(|e| e.0 == 0) {
                parts.push(mbr_part(logical, k, ebr + rel, n));
                logical += 1;
            }
            match entries.iter().find(|e| e.0 == 1 && is_extended(e.1)) {
                Some(&(_, _, rel, _)) => ebr = base + rel,
                None => break,
            }
        }
    }
    Ok(parts)
}

fn mbr_part(number: u32, kind: u8, lba: u64, count: u64) -> Partition {
    let name = match kind {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0e => "FAT16",
        0x07 => "NTFS/exFAT",
        0x0b | 0x0c => "FAT32",
        0x27 => "Windows recovery",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8e => "Linux LVM",
        0xa5 => "FreeBSD",
        0xaf => "HFS/HFS+",
        0xee => "GPT protective",
        0xef => "EFI system",
        0xfd => "Linux RAID",
        _ => "",
    };
    Partition {
        number,
        start: lba * 512,
        len: count * 512,
        kind: format!("{kind:#04x}"),
        description: name.into(),
    }
}

/// The GPT with sectors of `ss` bytes, from the primary header or else the backup one.
fn gpt(
    d: &mut Disk<'_, '_>,
    ss: u64,
    notes: &mut Vec<String>,
) -> io::Result<Option<Vec<Partition>>> {
    let primary = d
        .get(ss, ss as usize)?
        .filter(|h| h.starts_with(b"EFI PART"));
    let Some(primary) = primary else {
        return Ok(None);
    };
    let mut header = primary;
    if !header_crc_ok(&header) {
        let backup = match d.len.checked_sub(ss) {
            Some(at) => d
                .get(at, ss as usize)?
                .filter(|h| h.starts_with(b"EFI PART") && header_crc_ok(h)),
            None => None,
        };
        match backup {
            Some(b) => {
                notes.push("GPT header checksum mismatch: the backup header is used".into());
                header = b;
            }
            None => {
                notes.push("GPT header checksum mismatch, and no good backup: read anyway".into())
            }
        }
    }
    let (lba, n, size) = (
        u64le(&header, 72),
        u32le(&header, 80) as usize,
        u32le(&header, 84) as usize,
    );
    if size < 128 || size % 8 != 0 || n.saturating_mul(size) > 4 << 20 {
        notes.push(format!(
            "GPT entry array is implausible: {n} entries of {size} bytes"
        ));
        return Ok(Some(vec![]));
    }
    let Some(array) = lba
        .checked_mul(ss)
        .map(|at| d.get(at, n * size))
        .transpose()?
        .flatten()
    else {
        notes.push(format!("GPT entry array at sector {lba} is past the end"));
        return Ok(Some(vec![]));
    };
    if crc32(&array) != u32le(&header, 88) {
        notes.push("GPT entry array checksum mismatch".into());
    }
    let mut parts = Vec::new();
    for (i, e) in array.chunks_exact(size).enumerate() {
        if e[..16] == [0; 16] {
            continue;
        }
        let (first, last) = (u64le(e, 32), u64le(e, 40));
        let range = (last >= first)
            .then(|| {
                first
                    .checked_mul(ss)
                    .zip((last - first + 1).checked_mul(ss))
            })
            .flatten();
        let Some((start, len)) = range else {
            notes.push(format!(
                "GPT entry {} has an impossible range {first}..{last}",
                i + 1
            ));
            continue;
        };
        let name: Vec<u16> = e[56..128]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let kind = guid(&e[..16]);
        let (type_name, own) = (gpt_type_name(&kind), String::from_utf16_lossy(&name));
        let description = match (type_name, own.as_str()) {
            (t, "") => t.to_string(),
            ("", o) => o.to_string(),
            (t, o) if t == o => t.to_string(),
            (t, o) => format!("{t}: {o}"),
        };
        parts.push(Partition {
            number: i as u32 + 1,
            start,
            len,
            kind,
            description,
        });
    }
    Ok(Some(parts))
}

fn header_crc_ok(h: &[u8]) -> bool {
    let size = u32le(h, 12) as usize;
    if !(92..=h.len()).contains(&size) {
        return false;
    }
    let mut copy = h[..size].to_vec();
    copy[16..20].fill(0);
    crc32(&copy) == u32le(h, 16)
}

/// A GUID as text, from its mixed-endian on-disk form.
fn guid(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32le(b, 0),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

fn gpt_type_name(guid: &str) -> &'static str {
    match guid {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI system",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft reserved",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Basic data",
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Windows recovery",
        "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" => "LDM metadata",
        "af9b60a0-1431-4f62-bc68-3311714a69ad" => "LDM data",
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux filesystem",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux swap",
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => "Linux LVM",
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" => "Linux root (x86-64)",
        "48465300-0000-11aa-aa11-00306543ecac" => "Apple HFS+",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "Apple APFS",
        "21686148-6449-6e6f-744e-656564454649" => "BIOS boot",
        _ => "",
    }
}

/// CRC-32 (IEEE), as GPT uses it.
fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = (c >> 1) ^ (0xedb8_8320 & (c & 1).wrapping_neg());
        }
    }
    !c
}

/// The stretches of a disk `len` bytes long that no partition covers, as (start, len).
pub fn gaps(partitions: &[Partition], len: u64) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = partitions
        .iter()
        .map(|p| (p.start, p.start.saturating_add(p.len)))
        .collect();
    spans.sort_unstable();
    let (mut out, mut at) = (Vec::new(), 0u64);
    for (s, e) in spans {
        if s > at {
            out.push((at, s.min(len) - at));
        }
        at = at.max(e);
        if at >= len {
            return out;
        }
    }
    if at < len {
        out.push((at, len - at));
    }
    out.retain(|g| g.1 > 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(disk: &[u8]) -> Table {
        let mut r = |off: u64, buf: &mut [u8]| {
            buf.copy_from_slice(&disk[off as usize..off as usize + buf.len()]);
            Ok(())
        };
        read_table(&mut r, disk.len() as u64).unwrap()
    }

    fn entry(s: &mut [u8], at: usize, slot: usize, kind: u8, lba: u32, count: u32) {
        let e = &mut s[at + 446 + slot * 16..];
        e[4] = kind;
        e[8..12].copy_from_slice(&lba.to_le_bytes());
        e[12..16].copy_from_slice(&count.to_le_bytes());
        s[at + 510] = 0x55;
        s[at + 511] = 0xaa;
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn mbr_with_a_logical_partition_numbers_like_linux() {
        let mut d = vec![0u8; 512 * 400];
        entry(&mut d, 0, 0, 0x83, 1, 129);
        entry(&mut d, 0, 1, 0x05, 130, 270);
        entry(&mut d, 130 * 512, 0, 0x07, 1, 100); // logical 5 at 131
        entry(&mut d, 130 * 512, 1, 0x05, 110, 50); // next EBR at 240
        entry(&mut d, 240 * 512, 0, 0x0c, 1, 20); // logical 6 at 241
        let t = read(&d);
        assert_eq!(t.scheme, Scheme::Mbr);
        let got: Vec<_> = t
            .partitions
            .iter()
            .map(|p| (p.number, p.start / 512, p.len / 512))
            .collect();
        assert_eq!(got, [(1, 1, 129), (5, 131, 100), (6, 241, 20)]);
        assert!(t.notes.is_empty(), "{:?}", t.notes);
        let g = gaps(&t.partitions, d.len() as u64);
        assert_eq!(
            g,
            [
                (0, 512),
                (130 * 512, 512),
                (231 * 512, 10 * 512),
                (261 * 512, 139 * 512)
            ]
        );
    }

    #[test]
    fn a_looping_chain_and_an_empty_table_are_reported() {
        let mut d = vec![0u8; 512 * 64];
        entry(&mut d, 0, 0, 0x05, 10, 50);
        entry(&mut d, 10 * 512, 1, 0x05, 0, 50); // links back to itself
        let t = read(&d);
        assert!(t.notes.iter().any(|n| n.contains("loops")), "{:?}", t.notes);
        let mut e = vec![0u8; 512 * 64];
        e[510] = 0x55;
        e[511] = 0xaa;
        let t = read(&e);
        assert_eq!((t.scheme, t.partitions.len()), (Scheme::Mbr, 0));
        assert!(t.notes[0].contains("empty"));
    }

    #[test]
    fn a_file_system_at_offset_0_is_no_table() {
        let t = read(&crate::build_test_fat(4_000, 1, 12, 512).repeat(70));
        assert_eq!((t.scheme, t.partitions.len()), (Scheme::None, 0));
        assert_eq!(
            read(&[0u8; 100]).scheme,
            Scheme::None,
            "too short is no panic"
        );
    }

    #[test]
    fn partitions_past_the_end_are_noted() {
        let mut d = vec![0u8; 512 * 64];
        entry(&mut d, 0, 0, 0x83, 1, 1000);
        let t = read(&d);
        assert!(
            t.notes.iter().any(|n| n.contains("past the end")),
            "{:?}",
            t.notes
        );
    }
}
