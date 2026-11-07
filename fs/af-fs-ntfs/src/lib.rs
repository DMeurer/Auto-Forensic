//! NTFS as an [`af_core::fs::FileSystem`] (piece I13), on our fork of `ntfs-core`.
//!
//! Entries are MFT records; a [`FileId`] is the NTFS file reference (`ntfs.file_ref`: record
//! number in the low 48 bits, sequence number in the high 16), so a reused record never answers
//! for its old file. `all()` walks every record in MFT order, in use or not.
//!
//! Plain non-resident data opens as an [`ExtentSource`] over the volume: reads go straight to
//! the data runs (not through `ntfs-core`'s `read_at`, which re-reads from the start on every
//! call), and offsets map back to the image. Resident and compressed data is read whole.

use af_core::bytes::{ByteSource, DecodedSource, Extent, ExtentSource, ExtentTarget};
use af_core::fs::{
    Entry, EntryKind, EntryName, FileSystem, FsInfo, StreamInfo, StreamName, TimeName, TimeRole,
};
use af_core::ids::FileId;
use af_core::names::Kind;
use af_core::path::{CasePolicy, Name, NameKind};
use af_core::time::{Precision, Time, Zone};
use ntfs_core::{
    Attribute, AttributeBody, FileName, FileReference, MftRecordHeader, NtfsError, NtfsFs,
    StandardInformation, parse_attributes, runlist::Run,
};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

const STANDARD_INFORMATION: u32 = 0x10;
const FILE_NAME: u32 = 0x30;
const DATA: u32 = 0x80;
const ROOT_RECORD: u64 = 5;

/// An NTFS volume.
pub struct Ntfs {
    fs: NtfsFs<SourceReader>,
    volume: Arc<dyn ByteSource>,
    info: FsInfo,
    records: u64,
    /// The `$MFT`'s own runs, to look at a record's raw bytes when `ntfs-core` can't read it.
    mft_runs: Vec<ntfs_core::Run>,
}

/// A byte source as `Read + Seek`, which `ntfs-core` reads through.
struct SourceReader {
    src: Arc<dyn ByteSource>,
    pos: u64,
}

impl Read for SourceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.src.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SourceReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let (base, delta) = match to {
            SeekFrom::Start(n) => (0, n as i128),
            SeekFrom::End(d) => (self.src.len(), d as i128),
            SeekFrom::Current(d) => (self.pos, d as i128),
        };
        let at = u64::try_from(base as i128 + delta)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        self.pos = at;
        Ok(at)
    }
}

fn err(e: NtfsError) -> io::Error {
    match e {
        NtfsError::Io(e) => e,
        e => io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
    }
}

fn kind(name: &str) -> Kind {
    Kind::new(name).expect("a valid built-in name")
}

/// The time names NTFS has: the $STANDARD_INFORMATION set and the $FILE_NAME set.
const TIMES: [(&str, TimeRole); 8] = [
    ("ntfs.si.created", TimeRole::Created),
    ("ntfs.si.modified", TimeRole::Modified),
    ("ntfs.si.changed", TimeRole::Changed),
    ("ntfs.si.accessed", TimeRole::Accessed),
    ("ntfs.fn.created", TimeRole::Created),
    ("ntfs.fn.modified", TimeRole::Modified),
    ("ntfs.fn.changed", TimeRole::Changed),
    ("ntfs.fn.accessed", TimeRole::Accessed),
];

fn file_id(r: FileReference) -> FileId {
    FileId {
        scheme: kind("ntfs.file_ref"),
        value: (r.record_number | (u64::from(r.sequence) << 48))
            .to_le_bytes()
            .to_vec(),
    }
}

fn reference(id: &FileId) -> Option<FileReference> {
    if id.scheme.as_str() != "ntfs.file_ref" {
        return None;
    }
    let raw: [u8; 8] = id.value.as_slice().try_into().ok()?;
    Some(FileReference::from_u64(u64::from_le_bytes(raw)))
}

impl Ntfs {
    /// Opens the NTFS volume in `volume`, such as a partition view.
    pub fn open(volume: Arc<dyn ByteSource>) -> io::Result<Self> {
        let fs = NtfsFs::open(SourceReader {
            src: volume.clone(),
            pos: 0,
        })
        .map_err(err)?;
        let rec0 = fs.read_record(0).map_err(err)?;
        let mft_size = attributes(&rec0)?
            .iter()
            .find_map(|a| match a.body {
                AttributeBody::NonResident {
                    real_size,
                    start_vcn: 0,
                    ..
                } if a.type_code == DATA && a.name.is_none() => Some(real_size),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "$MFT has no $DATA"))?;
        let records = mft_size / fs.boot().mft_record_size.max(1);
        let info = FsInfo {
            kind: kind("fs.ntfs"),
            case: CasePolicy::Insensitive,
            label: None,
            serial: Some(format!("{:016X}", fs.boot().volume_serial)),
            time_names: TIMES
                .iter()
                .map(|(n, role)| TimeName {
                    name: kind(n),
                    role: *role,
                    precision: Precision::TICK,
                    zone: Zone::Utc,
                })
                .collect(),
            finds_deleted: true,
        };
        let mft_runs = fs.runs_by_record(0, None).map_err(err)?;
        Ok(Self {
            fs,
            volume,
            info,
            records,
            mft_runs,
        })
    }

    /// The base record `n` with its extension records, or `None` if it isn't a base record
    /// in use or not (an extension record, a never-used one, a broken signature).
    fn record(&self, n: u64) -> io::Result<Option<(MftRecordHeader, Vec<Vec<u8>>)>> {
        if n >= self.records {
            return Ok(None);
        }
        let rec = match self.fs.read_record(n) {
            Ok(r) => r,
            // A record never written is all zeros, which fails the fixup: no entry, no error.
            Err(_) if self.never_written(n)? => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        let h = MftRecordHeader::parse(&rec).map_err(err)?;
        if &h.signature != b"FILE" || h.base_record != 0 {
            return Ok(None);
        }
        let all = if h.is_in_use() {
            self.fs.gather_records(n, &rec).map_err(err)?
        } else {
            // shortcut: a deleted record's extension records may be reused already, so only the base record is read; upgrade with I20.
            vec![rec]
        };
        Ok(Some((h, all)))
    }

    /// Whether MFT record `n` is all zeros on the volume.
    fn never_written(&self, n: u64) -> io::Result<bool> {
        let (size, cluster) = (
            self.fs.boot().mft_record_size,
            self.fs.boot().cluster_size(),
        );
        let mut vcn_byte = n.saturating_mul(size);
        let mut buf = vec![0u8; size as usize];
        let mut got = 0usize;
        for run in &self.mft_runs {
            let run_len = run.length.saturating_mul(cluster);
            if vcn_byte >= run_len {
                vcn_byte -= run_len;
                continue;
            }
            let take = (run_len - vcn_byte).min((buf.len() - got) as u64) as usize;
            if let Some(lcn) = run.lcn {
                let at = lcn.saturating_mul(cluster) + vcn_byte;
                self.volume.read_exact_at(at, &mut buf[got..got + take])?;
            }
            got += take;
            vcn_byte = 0;
            if got == buf.len() {
                break;
            }
        }
        Ok(got == buf.len() && buf.iter().all(|&b| b == 0))
    }

    /// The entry of a base record, or `None` for a record without a name that isn't the root:
    /// the reserved records 12 to 15 are in use but hold no file.
    fn build(&self, n: u64, h: &MftRecordHeader, records: &[Vec<u8>]) -> io::Result<Option<Entry>> {
        let id = file_id(FileReference {
            record_number: n,
            sequence: h.sequence_number,
        });
        let (mut names, mut times, mut streams) = (Vec::new(), Vec::new(), Vec::new());
        let mut fn_times = None;
        for rec in records {
            for a in attributes(rec)? {
                match a.type_code {
                    STANDARD_INFORMATION => {
                        let si = a
                            .resident_content(rec)
                            .map(StandardInformation::parse)
                            .transpose()
                            .map_err(err)?;
                        if let Some(si) = si {
                            for (name, t) in [
                                ("ntfs.si.created", si.created),
                                ("ntfs.si.modified", si.modified),
                                ("ntfs.si.changed", si.mft_modified),
                                ("ntfs.si.accessed", si.accessed),
                            ] {
                                times.push((kind(name), Time::from_ticks_1601(t.0)));
                            }
                        }
                    }
                    FILE_NAME => {
                        let Some(f) = a
                            .resident_content(rec)
                            .map(FileName::parse)
                            .transpose()
                            .map_err(err)?
                        else {
                            continue;
                        };
                        let ns = match f.namespace {
                            0 => "ntfs.name.posix",
                            2 => "ntfs.name.dos",
                            3 => "ntfs.name.win32_dos",
                            _ => "ntfs.name.win32",
                        };
                        // The long name's times; the DOS name's copy is normally the same.
                        if f.namespace != 2 || fn_times.is_none() {
                            fn_times = Some([f.created, f.modified, f.mft_modified, f.accessed]);
                        }
                        // The root names itself "." in its own folder.
                        if n != ROOT_RECORD {
                            names.push(EntryName {
                                parent: file_id(f.parent),
                                // shortcut: ntfs-core decodes names to String, so an unpaired surrogate is lost; keep raw UTF-16 in the fork when a case needs it.
                                name: Name::from_text(&f.name, NameKind::Utf16),
                                kind: kind(ns),
                                alias: f.namespace == 2,
                            });
                        }
                    }
                    DATA => {
                        let (size, stale) = match a.body {
                            AttributeBody::Resident { content_length, .. } => {
                                (u64::from(content_length), 0)
                            }
                            AttributeBody::NonResident {
                                start_vcn: 0,
                                real_size,
                                initialized_size,
                                ..
                            } if !a.is_compressed() => {
                                (real_size, real_size.saturating_sub(initialized_size))
                            }
                            AttributeBody::NonResident {
                                start_vcn: 0,
                                real_size,
                                ..
                            } => (real_size, 0),
                            AttributeBody::NonResident { .. } => continue, // a later fragment
                        };
                        let n = a.name.as_ref().map(|s| Name::from_text(s, NameKind::Utf16));
                        let (name, k) = match &n {
                            None => (StreamName::Default, "fs.data"),
                            Some(n) => (StreamName::Named(n.clone()), "ntfs.ads"),
                        };
                        streams.push(StreamInfo {
                            name,
                            kind: kind(k),
                            size,
                        });
                        if stale > 0 {
                            streams.push(StreamInfo {
                                name: StreamName::Stale(n),
                                kind: kind("ntfs.stale_bytes"),
                                size: stale,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(ft) = fn_times {
            for (name, t) in [
                "ntfs.fn.created",
                "ntfs.fn.modified",
                "ntfs.fn.changed",
                "ntfs.fn.accessed",
            ]
            .iter()
            .zip(ft)
            {
                times.push((kind(name), Time::from_ticks_1601(t.0)));
            }
        }
        let allocated = h.is_in_use();
        Ok(Some(Entry {
            id,
            kind: if h.is_directory() {
                EntryKind::Folder
            } else {
                EntryKind::File
            },
            names,
            times,
            allocated,
            recovered: (!allocated).then(|| kind("ntfs.mft.unused_record")),
            streams,
            attrs: vec![],
        })
        .filter(|e| n == ROOT_RECORD || !e.names.is_empty()))
    }

    /// The `$DATA` attributes of a stream, in VCN order.
    fn data_attributes(
        records: &[Vec<u8>],
        stream: Option<&str>,
    ) -> io::Result<Vec<(usize, Attribute)>> {
        let mut out = Vec::new();
        for (i, rec) in records.iter().enumerate() {
            for a in attributes(rec)? {
                if a.type_code == DATA && a.name.as_deref() == stream {
                    out.push((i, a));
                }
            }
        }
        out.sort_by_key(|(_, a)| match a.body {
            AttributeBody::NonResident { start_vcn, .. } => start_vcn,
            AttributeBody::Resident { .. } => 0,
        });
        Ok(out)
    }
}

fn attributes(rec: &[u8]) -> io::Result<Vec<Attribute>> {
    let h = MftRecordHeader::parse(rec).map_err(err)?;
    parse_attributes(rec, usize::from(h.first_attribute_offset)).map_err(err)
}

impl FileSystem for Ntfs {
    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn root(&self) -> FileId {
        // The root's sequence number is 5 on every NTFS volume Windows formats; read it anyway.
        let seq = self
            .fs
            .read_record(ROOT_RECORD)
            .ok()
            .and_then(|r| MftRecordHeader::parse(&r).ok())
            .map_or(ROOT_RECORD as u16, |h| h.sequence_number);
        file_id(FileReference {
            record_number: ROOT_RECORD,
            sequence: seq,
        })
    }

    fn entry(&self, id: &FileId) -> io::Result<Option<Entry>> {
        let Some(r) = reference(id) else {
            return Ok(None);
        };
        match self.record(r.record_number)? {
            Some((h, recs)) if h.sequence_number == r.sequence => {
                self.build(r.record_number, &h, &recs)
            }
            _ => Ok(None),
        }
    }

    fn list(&self, dir: &FileId) -> io::Result<Vec<(Name, FileId)>> {
        let Some(r) = reference(dir) else {
            return Ok(vec![]);
        };
        let rec = self.fs.read_record(r.record_number).map_err(err)?;
        let h = MftRecordHeader::parse(&rec).map_err(err)?;
        if h.sequence_number != r.sequence || !h.is_in_use() || !h.is_directory() {
            return Ok(vec![]);
        }
        Ok(self
            .fs
            .directory_entries_by_record(r.record_number)
            .map_err(err)?
            .into_iter()
            .filter(|e| e.file_reference.record_number != r.record_number)
            .filter_map(|e| {
                let f = e.file_name?;
                Some((
                    Name::from_text(&f.name, NameKind::Utf16),
                    file_id(e.file_reference),
                ))
            })
            .collect())
    }

    fn all(&self) -> Box<dyn Iterator<Item = io::Result<Entry>> + '_> {
        Box::new((0..self.records).filter_map(move |n| match self.record(n) {
            Ok(Some((h, recs))) => self.build(n, &h, &recs).transpose(),
            Ok(None) => None,
            Err(e) => Some(Err(io::Error::new(e.kind(), format!("record {n}: {e}")))),
        }))
    }

    fn open(&self, id: &FileId, stream: &StreamName) -> io::Result<Option<Arc<dyn ByteSource>>> {
        let Some(r) = reference(id) else {
            return Ok(None);
        };
        let Some((h, recs)) = self.record(r.record_number)? else {
            return Ok(None);
        };
        if h.sequence_number != r.sequence {
            return Ok(None);
        }
        let (name, stale) = match stream {
            StreamName::Default => (None, false),
            StreamName::Named(n) => (Some(n.display()), false),
            StreamName::Stale(n) => (n.as_ref().map(Name::display), true),
        };
        let attrs = Self::data_attributes(&recs, name.as_deref())?;
        let Some((_, first)) = attrs.first() else {
            return Ok(None);
        };
        let tag = format!("ntfs.file_ref={}-{}", r.record_number, r.sequence);
        let tag = match &name {
            Some(s) => format!("{tag}:{s}"),
            None => tag,
        };
        let loc = self
            .volume
            .locator()
            .child(if stale { "fs.stale_bytes" } else { "fs.file" }, &tag);
        let (real_size, initialized) = match first.body {
            AttributeBody::NonResident {
                real_size,
                initialized_size,
                ..
            } if !first.is_compressed() => (real_size, initialized_size.min(real_size)),
            _ if stale => return Ok(None),
            _ => {
                // Resident or compressed: no one-to-one place on the volume, so read it whole.
                let data = self
                    .fs
                    .read_data_by_record(r.record_number, name.as_deref(), u64::MAX)
                    .map_err(err)?;
                return Ok(Some(Arc::new(DecodedSource::new(
                    self.volume.clone(),
                    data,
                    loc,
                ))));
            }
        };
        if stale && initialized >= real_size {
            return Ok(None);
        }
        let cluster = self.fs.boot().cluster_size();
        let runs = self
            .fs
            .runs_by_record(r.record_number, name.as_deref())
            .map_err(err)?;
        let extents = if stale {
            extents(&runs, cluster, initialized, real_size)
        } else {
            // Past the initialized size Windows reads zeros, whatever the clusters still hold.
            let mut x = extents(&runs, cluster, 0, initialized);
            if x.last().map_or(0, |e| e.start + e.len) == initialized {
                x.push(Extent {
                    start: initialized,
                    len: real_size - initialized,
                    target: ExtentTarget::Sparse,
                });
            }
            x
        };
        Ok(Some(Arc::new(ExtentSource::new(
            self.volume.clone(),
            extents,
            loc,
        )?)))
    }
}

/// Bytes `from..to` of a stream with these data runs, as extents starting at 0. Holes stay
/// sparse; runs that end early give a shorter stream.
fn extents(runs: &[Run], cluster: u64, from: u64, to: u64) -> Vec<Extent> {
    let (mut out, mut at) = (Vec::new(), 0u64);
    for run in runs {
        let end = at.saturating_add(run.length.saturating_mul(cluster));
        let (lo, hi) = (at.max(from), end.min(to));
        if lo < hi {
            out.push(Extent {
                start: lo - from,
                len: hi - lo,
                target: match run.lcn {
                    Some(lcn) => ExtentTarget::Parent(lcn.saturating_mul(cluster) + (lo - at)),
                    None => ExtentTarget::Sparse,
                },
            });
        }
        at = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_range_maps_across_runs_and_holes() {
        // 2 clusters at 10, a hole of 1, 2 clusters at 50; clusters of 100 bytes.
        let runs = [
            Run {
                length: 2,
                lcn: Some(10),
            },
            Run {
                length: 1,
                lcn: None,
            },
            Run {
                length: 2,
                lcn: Some(50),
            },
        ];
        let x = extents(&runs, 100, 150, 420);
        let got: Vec<_> = x.iter().map(|e| (e.start, e.len, e.target)).collect();
        assert_eq!(
            got,
            [
                (0, 50, ExtentTarget::Parent(1150)),
                (50, 100, ExtentTarget::Sparse),
                (150, 120, ExtentTarget::Parent(5000)),
            ]
        );
    }
}
