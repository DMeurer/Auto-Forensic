//! NTFS change journal records from bytes (piece M5), on our `ntfs-core` fork: the `$J` stream of
//! `$Extend\$UsnJrnl`, read with `ntfs-core`'s streaming reader (it skips the zeroed and sparse
//! ranges), and the folder path of every record as it was when the record was written.
//!
//! Paths are rewound through the journal, as MFTECmd does: start from the names the `$MFT` holds
//! now and walk the journal from its newest record back. Each record's parent path is read from
//! the names at that point; then the record's own name and parent become the names for the
//! records before it. A folder renamed, moved, deleted or whose MFT record was reused since
//! keeps the name it had then: a rename writes its old name just before its new one.

use ntfs_core::UsnJournalReader;
use std::collections::HashMap;
use std::io::{Read, Seek};

/// FILETIME ticks from 1601 to 1970.
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// A file reference: MFT record number and sequence number.
pub type FileRef = (u64, u16);

/// One change journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub file: FileRef,
    pub parent: FileRef,
    /// The update sequence number: the record's offset in `$J`.
    pub usn: i64,
    /// When the change was written, in FILETIME ticks; `None` when the stored time is zero,
    /// negative or before 1970 (`ntfs-core` keeps no such time).
    pub ticks: Option<u64>,
    /// `USN_REASON_*` flags.
    pub reasons: u32,
    /// `FILE_ATTRIBUTE_*` flags.
    pub attributes: u32,
    pub name: String,
    /// 2 (NTFS) or 3 (128-bit references, ReFS; cut to 64 bits by `ntfs-core`).
    pub version: u16,
}

/// Every record of a `$J` stream, in journal order. An `Err` item is a read error of the
/// source; the reader stops after it. Bytes that hold no record are skipped.
pub fn read<R: Read + Seek>(j: R) -> Result<impl Iterator<Item = Result<Record, String>>, String> {
    let reader = UsnJournalReader::new(j).map_err(|e| e.to_string())?;
    Ok(reader.map(|r| {
        let r = r.map_err(|e| e.to_string())?;
        let (secs, nanos) = (
            r.timestamp.timestamp(),
            r.timestamp.timestamp_subsec_nanos(),
        );
        // ntfs-core turns a time it can't keep into the Unix epoch.
        let ticks = (secs > 0 || nanos > 0)
            .then(|| UNIX_EPOCH_TICKS + secs.unsigned_abs() * 10_000_000 + u64::from(nanos / 100));
        Ok(Record {
            file: (r.mft_entry, r.mft_sequence),
            parent: (r.parent_mft_entry, r.parent_mft_sequence),
            usn: r.usn,
            ticks,
            reasons: r.reason.bits(),
            attributes: r.file_attributes.bits(),
            name: r.filename,
            version: r.major_version,
        })
    }))
}

/// Folder names by file reference, to build paths from.
#[derive(Debug, Clone, Default)]
pub struct Names {
    root: FileRef,
    names: HashMap<FileRef, (String, FileRef)>,
}

/// Folder chains longer than this are taken as loops.
const MAX_DEPTH: usize = 4096;

impl Names {
    /// No names yet; `root` is the root folder's reference (`(5, 5)` on NTFS).
    pub fn new(root: FileRef) -> Self {
        Self {
            root,
            names: HashMap::new(),
        }
    }

    /// `file` is named `name` in folder `parent`.
    pub fn insert(&mut self, file: FileRef, name: String, parent: FileRef) {
        self.names.insert(file, (name, parent));
    }

    /// The path of `file` from the root, `/` between names (the root is `/`); `None` when a
    /// folder on the way has no name or the chain loops.
    pub fn path(&self, file: FileRef) -> Option<String> {
        let (mut parts, mut at) = (vec![], file);
        while at != self.root {
            if parts.len() > MAX_DEPTH {
                return None;
            }
            let (name, parent) = self.names.get(&at)?;
            parts.push(name.as_str());
            at = *parent;
        }
        parts.reverse();
        Some(format!("/{}", parts.join("/")))
    }
}

/// The parent folder path of each record when it was written, rewound from `now` (the names
/// the `$MFT` holds now) through `records` in journal order; `None` where a folder on the way
/// is unknown.
pub fn parent_paths(records: &[Record], mut now: Names) -> Vec<Option<String>> {
    let mut out = vec![None; records.len()];
    for (i, r) in records.iter().enumerate().rev() {
        out[i] = now.path(r.parent);
        now.insert(r.file, r.name.clone(), r.parent);
    }
    out
}

/// Builds a `USN_RECORD_V2` for tests of this crate and others, 8-byte aligned.
pub fn build_test_record(r: &Record) -> Vec<u8> {
    let name: Vec<u8> = r.name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let len = 0x3C + name.len();
    let mut b = vec![0u8; len.next_multiple_of(8)];
    let reference = |(n, s): FileRef| n | (u64::from(s) << 48);
    b[0..4].copy_from_slice(&(len as u32).to_le_bytes());
    b[4..6].copy_from_slice(&2u16.to_le_bytes());
    b[0x08..0x10].copy_from_slice(&reference(r.file).to_le_bytes());
    b[0x10..0x18].copy_from_slice(&reference(r.parent).to_le_bytes());
    b[0x18..0x20].copy_from_slice(&r.usn.to_le_bytes());
    b[0x20..0x28].copy_from_slice(&r.ticks.unwrap_or(0).to_le_bytes());
    b[0x28..0x2C].copy_from_slice(&r.reasons.to_le_bytes());
    b[0x34..0x38].copy_from_slice(&r.attributes.to_le_bytes());
    b[0x38..0x3A].copy_from_slice(&(name.len() as u16).to_le_bytes());
    b[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
    b[0x3C..len].copy_from_slice(&name);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: FileRef = (5, 5);
    const RENAME_OLD: u32 = 0x1000;
    const RENAME_NEW: u32 = 0x2000;

    fn rec(file: FileRef, parent: FileRef, reasons: u32, name: &str) -> Record {
        Record {
            file,
            parent,
            usn: 0,
            ticks: Some(131_674_911_875_724_698),
            reasons,
            attributes: 0x20,
            name: name.into(),
            version: 2,
        }
    }

    /// Records between zeroed ranges read back as written, times to the tick.
    #[test]
    fn reads_records_between_zeros() {
        let mut j = vec![0u8; 4096];
        let mut want = vec![];
        for (i, name) in ["a.txt", "longer name.docx"].into_iter().enumerate() {
            let mut r = rec((100 + i as u64, 1), ROOT, 0x100, name);
            r.usn = j.len() as i64;
            j.extend(build_test_record(&r));
            want.push(r);
        }
        j.extend([0u8; 100]);
        let got: Vec<Record> = read(std::io::Cursor::new(j))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(got, want);
    }

    /// Folder 100 was `Old`, then renamed `New`; folder record 300 held `Gone` (sequence 1),
    /// was deleted and is now `Other` (sequence 2). The `$MFT` knows only the names of now.
    #[test]
    fn paths_rewind_renames_and_reused_records() {
        let records = [
            rec((100, 1), ROOT, 0x100, "Old"),
            rec((200, 1), (100, 1), 0x100, "a"),
            rec((210, 1), (300, 1), 0x100, "b"),
            rec((100, 1), ROOT, RENAME_OLD, "Old"),
            rec((100, 1), ROOT, RENAME_NEW, "New"),
            rec((201, 1), (100, 1), 0x100, "c"),
            rec((300, 1), ROOT, 0x200, "Gone"),
        ];
        let mut now = Names::new(ROOT);
        now.insert((100, 1), "New".into(), ROOT);
        now.insert((300, 2), "Other".into(), ROOT);
        let paths = parent_paths(&records, now);
        let paths: Vec<&str> = paths.iter().map(|p| p.as_deref().unwrap()).collect();
        assert_eq!(paths, ["/", "/Old", "/Gone", "/", "/", "/New", "/"]);
    }

    #[test]
    fn unknown_folders_and_loops_give_no_path() {
        let mut names = Names::new(ROOT);
        assert_eq!(names.path((9, 1)), None);
        names.insert((10, 1), "x".into(), (11, 1));
        names.insert((11, 1), "y".into(), (10, 1));
        assert_eq!(names.path((10, 1)), None);
    }
}
