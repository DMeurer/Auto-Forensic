//! NTFS `$MFT` records from bytes (piece M1), on the `mft` crate (T2: on four images it matched
//! MFTECmd on every record and every `$SI` time).
//!
//! The bytes are a loose `$MFT` or the `$MFT` read from an image; this crate doesn't care which.
//! `mft` reads the records, applies fixups, walks attributes, follows `$ATTRIBUTE_LIST` into
//! extension records and builds paths. The `$STANDARD_INFORMATION` and `$FILE_NAME` contents are
//! read here from the attributes' raw bytes, so every time keeps its FILETIME as stored: `mft`
//! turns times into `jiff` timestamps, which can't hold a FILETIME past the year 9999 (a
//! timestomped value can be one).

use mft::MftParser;
use mft::attribute::MftAttributeType;
use mft::attribute::header::ResidentialHeader;
use mft::entry::MftEntry;

/// One file record (a base record; extension records only add attributes to theirs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub number: u64,
    pub sequence: u16,
    /// The record is in use; a deleted file's record is not, until it is reused.
    pub in_use: bool,
    pub is_dir: bool,
    pub link_count: u16,
    pub info: Option<StandardInfo>,
    /// Every `$FILE_NAME`: a hard link or DOS short name each has its own.
    pub names: Vec<FileName>,
    /// The path from the root, `\` between names, as `mft` builds it (`[Orphaned]\...` when a
    /// parent is gone).
    pub path: Option<String>,
    /// The size of the unnamed `$DATA` stream.
    pub size: Option<u64>,
}

/// `$STANDARD_INFORMATION`: the times Windows shows, FILETIME ticks as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardInfo {
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
    pub flags: u32,
    /// The file's last USN journal entry (NTFS 3.0 on).
    pub usn: Option<u64>,
}

/// One `$FILE_NAME`: its own four times, FILETIME ticks as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    pub parent: u64,
    pub parent_sequence: u16,
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
    pub size: u64,
    pub flags: u32,
    /// 0 POSIX, 1 Win32, 2 DOS, 3 Win32 and DOS.
    pub namespace: u8,
    pub name: String,
}

/// What [`read`] went through.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    /// Base records given to the caller.
    pub records: u64,
    /// Records that failed to read, in the crate's words.
    pub errors: Vec<String>,
}

/// Reads every record of an `$MFT` and gives each base record to `visit`, in record order.
/// Never-used records (no `FILE` signature) are skipped; a record that fails to read is an entry
/// in [`Summary::errors`], next to the records that did read.
pub fn read(mft: Vec<u8>, mut visit: impl FnMut(Record)) -> Result<Summary, String> {
    let mut parser = MftParser::from_buffer(mft).map_err(|e| e.to_string())?;
    let mut summary = Summary::default();
    for i in 0..parser.get_entry_count() {
        let entry = match parser.get_entry(i) {
            Ok(e) => e,
            Err(e) => {
                summary.errors.push(format!("record {i}: {e}"));
                continue;
            }
        };
        if !entry.header.is_valid() || !entry.header.is_base_record() {
            continue;
        }
        let mut found = Found::default();
        found.add(&entry);
        if found.has_list {
            for ext in parser.get_extension_entries(&entry) {
                found.add(&ext);
            }
        }
        // `mft` builds a PathBuf, whose separator depends on the OS this runs on.
        let path = parser
            .get_full_path_for_entry(&entry)
            .ok()
            .flatten()
            .map(|p| {
                p.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("\\")
            });
        visit(Record {
            number: entry.header.record_number,
            sequence: entry.header.sequence,
            in_use: entry.is_allocated(),
            is_dir: entry.is_dir(),
            link_count: entry.header.hard_link_count,
            info: found.info,
            names: found.names,
            path,
            size: found.size,
        });
        summary.records += 1;
    }
    Ok(summary)
}

/// The attributes collected from a base record and its extension records.
#[derive(Default)]
struct Found {
    info: Option<StandardInfo>,
    names: Vec<FileName>,
    size: Option<u64>,
    has_list: bool,
}

impl Found {
    fn add(&mut self, entry: &MftEntry) {
        let wanted = vec![
            MftAttributeType::StandardInformation,
            MftAttributeType::AttributeList,
            MftAttributeType::FileName,
            MftAttributeType::DATA,
        ];
        for (header, record) in entry
            .iter_attribute_records_matching(Some(wanted))
            .flatten()
        {
            let content = match &header.residential_header {
                ResidentialHeader::Resident(r) => {
                    let at = usize::from(r.data_offset);
                    record.get(at..at.saturating_add(r.data_size as usize))
                }
                ResidentialHeader::NonResident(_) => None,
            };
            match header.type_code {
                MftAttributeType::StandardInformation if self.info.is_none() => {
                    self.info = content.and_then(standard_info);
                }
                MftAttributeType::AttributeList => self.has_list = true,
                MftAttributeType::FileName => self.names.extend(content.and_then(file_name)),
                MftAttributeType::DATA if header.name_size == 0 => {
                    self.size = self.size.or(match &header.residential_header {
                        ResidentialHeader::Resident(r) => Some(u64::from(r.data_size)),
                        ResidentialHeader::NonResident(n) if n.vnc_first == 0 => Some(n.file_size),
                        ResidentialHeader::NonResident(_) => None,
                    });
                }
                _ => {}
            }
        }
    }
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// `$STANDARD_INFORMATION`: four FILETIMEs, the flags at 0x20, the USN at 0x40.
fn standard_info(b: &[u8]) -> Option<StandardInfo> {
    Some(StandardInfo {
        created: u64_at(b, 0x00)?,
        modified: u64_at(b, 0x08)?,
        mft_modified: u64_at(b, 0x10)?,
        accessed: u64_at(b, 0x18)?,
        flags: u32_at(b, 0x20)?,
        usn: u64_at(b, 0x40),
    })
}

/// `$FILE_NAME`: the parent reference, four FILETIMEs, sizes, flags, then the name.
fn file_name(b: &[u8]) -> Option<FileName> {
    let parent = u64_at(b, 0x00)?;
    let len = usize::from(*b.get(0x40)?);
    let units: Vec<u16> = b
        .get(0x42..0x42 + 2 * len)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Some(FileName {
        parent: parent & 0x0000_FFFF_FFFF_FFFF,
        parent_sequence: (parent >> 48) as u16,
        created: u64_at(b, 0x08)?,
        modified: u64_at(b, 0x10)?,
        mft_modified: u64_at(b, 0x18)?,
        accessed: u64_at(b, 0x20)?,
        size: u64_at(b, 0x30)?,
        flags: u32_at(b, 0x38)?,
        namespace: *b.get(0x41)?,
        name: String::from_utf16_lossy(&units),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: usize = 1024;

    /// A resident attribute: header (0x18 bytes, no name), then `content`, 8-byte aligned.
    fn attribute(type_code: u32, id: u16, content: &[u8]) -> Vec<u8> {
        let len = (0x18 + content.len()).next_multiple_of(8);
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&type_code.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[0x0E..0x10].copy_from_slice(&id.to_le_bytes());
        a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
        a[0x14..0x16].copy_from_slice(&0x18u16.to_le_bytes());
        a[0x18..0x18 + content.len()].copy_from_slice(content);
        a
    }

    /// A `FILE` record with fixups, in use, holding `attributes`.
    fn record(number: u32, sequence: u16, is_dir: bool, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut e = vec![0u8; SIZE];
        e[0..4].copy_from_slice(b"FILE");
        e[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        e[6..8].copy_from_slice(&3u16.to_le_bytes());
        e[0x10..0x12].copy_from_slice(&sequence.to_le_bytes());
        e[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
        e[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
        e[0x16..0x18].copy_from_slice(&(1u16 | if is_dir { 2 } else { 0 }).to_le_bytes());
        e[0x1C..0x20].copy_from_slice(&(SIZE as u32).to_le_bytes());
        e[0x2C..0x30].copy_from_slice(&number.to_le_bytes());
        let mut at = 0x38;
        for a in attributes {
            e[at..at + a.len()].copy_from_slice(a);
            at += a.len();
        }
        e[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        e[0x18..0x1C].copy_from_slice(&((at + 8) as u32).to_le_bytes());
        // Fixups: the update sequence number at the end of each 512-byte sector.
        let usn = 7u16.to_le_bytes();
        e[0x30..0x32].copy_from_slice(&usn);
        for s in 0..2 {
            let end = 512 * (s + 1) - 2;
            let (keep0, keep1) = (e[end], e[end + 1]);
            e[0x32 + 2 * s] = keep0;
            e[0x33 + 2 * s] = keep1;
            e[end..end + 2].copy_from_slice(&usn);
        }
        e
    }

    fn si(times: [u64; 4]) -> Vec<u8> {
        let mut b = vec![0u8; 0x48];
        for (i, t) in times.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        b[0x20..0x24].copy_from_slice(&0x20u32.to_le_bytes());
        b[0x40..0x48].copy_from_slice(&4711u64.to_le_bytes());
        b
    }

    fn fname(parent: u64, parent_seq: u16, t: u64, size: u64, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut b = vec![0u8; 0x42 + 2 * units.len()];
        b[0..8].copy_from_slice(&(parent | u64::from(parent_seq) << 48).to_le_bytes());
        for i in 0..4 {
            b[8 + i * 8..16 + i * 8].copy_from_slice(&t.to_le_bytes());
        }
        b[0x30..0x38].copy_from_slice(&size.to_le_bytes());
        b[0x40] = units.len() as u8;
        b[0x41] = 1;
        for (i, u) in units.iter().enumerate() {
            b[0x42 + 2 * i..0x44 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        b
    }

    /// Records 0 to 4 unused, 5 the root, 6 a folder, 7 a file in it whose `$SI` created time
    /// is past the year 9999 (a FILETIME `mft` can't turn into a timestamp), 8 never used.
    #[test]
    fn times_as_stored_names_and_paths() {
        let t = 132_000_000_000_000_000u64; // 2019-04-15
        let far = 2_650_467_743_990_000_000u64; // the year 10000
        let mut mft = vec![0u8; 5 * SIZE];
        mft.extend(record(
            5,
            5,
            true,
            &[
                attribute(0x10, 0, &si([t; 4])),
                attribute(0x30, 1, &fname(5, 5, t, 0, ".")),
            ],
        ));
        mft.extend(record(
            6,
            1,
            true,
            &[
                attribute(0x10, 0, &si([t; 4])),
                attribute(0x30, 1, &fname(5, 5, t, 0, "Users")),
            ],
        ));
        mft.extend(record(
            7,
            3,
            false,
            &[
                attribute(0x10, 0, &si([far, t + 1, t + 2, t + 3])),
                attribute(0x30, 1, &fname(6, 1, t, 12, "a.txt")),
                attribute(0x80, 2, b"hello world!"),
            ],
        ));
        mft.extend(vec![0u8; SIZE]);
        let mut seen = vec![];
        let s = read(mft, |r| seen.push(r)).unwrap();
        assert_eq!(
            s,
            Summary {
                records: 3,
                errors: vec![]
            }
        );
        let file = &seen[2];
        assert_eq!(
            (file.number, file.sequence, file.in_use, file.is_dir),
            (7, 3, true, false)
        );
        let info = file.info.as_ref().unwrap();
        assert_eq!(
            (info.created, info.modified, info.flags, info.usn),
            (far, t + 1, 0x20, Some(4711))
        );
        let n = &file.names[0];
        assert_eq!(
            (
                n.parent,
                n.parent_sequence,
                n.created,
                n.size,
                n.namespace,
                n.name.as_str()
            ),
            (6, 1, t, 12, 1, "a.txt")
        );
        assert_eq!(file.size, Some(12));
        assert_eq!(file.path.as_deref(), Some("Users\\a.txt"));
        assert!(seen[1].is_dir);
    }

    #[test]
    fn not_an_mft_is_an_error() {
        assert!(read(vec![], |_| ()).is_err());
        assert!(
            read(vec![0u8; 4 * SIZE], |_| ()).is_err(),
            "no record says its size"
        );
    }
}
