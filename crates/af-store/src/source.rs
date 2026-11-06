//! Sources of a project (piece F20): add, list, remove and relink.
//!
//! - **Images** (`.E01` sets, `.dd`, `.raw`, `.img`, `.001` sets, `.vmdk`, `.vhd`, `.vhdx`) are
//!   referenced where they lie and never written to. A segment set (`x.E01`, `x.E02`, ...) is one
//!   source; its hash covers the segment files in order (the media hash inside an E01 comes with
//!   the E01 reader, I5).
//! - **Folders** are referenced like images (C0a): a hand-built root or an exported profile,
//!   read in place. Their hash covers every file's path and content, the fingerprint every
//!   file's path and size.
//! - **Loose files** (anything else) are copied into `sources/<id>/` inside the project, and the
//!   copy is checked against the original by hash.
//!
//! Adding stores the SHA-256 of every byte and a quick fingerprint: SHA-256 over the size and
//! the first, middle and last MiB. Relinking a moved image checks the fingerprint (seconds), or
//! with `verify` the full hash (minutes). Removing a source deletes its records, events,
//! entities, artifacts and systems, and a loose file's copy; an image itself is never touched.

use crate::project::{Project, ProjectError};
use af_core::ids::SourceId;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MIB: u64 = 1 << 20;
/// What a device source holds where others hold their hash and fingerprint.
pub const LIVE: &str = "live, not hashed";

const IMAGE_EXTENSIONS: &[&str] = &[
    "e01", "dd", "raw", "img", "000", "001", "vmdk", "vhd", "vhdx",
];

/// When a source's evidence was captured, and how that is known (F31). Facts read from a source
/// are true as of this time, which matters because they have no time of their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsOf {
    /// Seconds since 1970, UTC; `None` when unknown.
    pub unix: Option<i64>,
    /// `acquisition` (from the image's metadata), `last_shutdown` (from the system), `entered`
    /// (typed in when adding loose files) or `unknown`.
    pub basis: String,
}

impl AsOf {
    pub const BASES: [&str; 4] = ["acquisition", "last_shutdown", "entered", "unknown"];

    /// "as of 2026-04-26 10:00:00 UTC (entered)" or "as of unknown".
    pub fn display(&self) -> String {
        match self.unix {
            Some(t) => format!(
                "as of {} ({})",
                af_core::time::Time::from_unix_seconds(t).display(),
                self.basis
            ),
            None => "as of unknown".into(),
        }
    }
}

/// A source as the project lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    pub id: SourceId,
    /// `image`, `folder`, `device` or `loose`.
    pub kind: String,
    pub label: String,
    pub size: u64,
    pub sha256: String,
    pub fingerprint: String,
    /// Image segments where they lie, or the loose file's copy inside the project.
    pub files: Vec<PathBuf>,
}

impl Project {
    /// Adds a source: an image by reference, anything else as a copy. Hashes it fully.
    pub fn add_source(&mut self, path: &Path) -> Result<SourceInfo, ProjectError> {
        let path = std::fs::canonicalize(path)?;
        let id = SourceId::new_random();
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (kind, files, stored) = if af_host::device::is_block_device(&path) {
            let stored = vec![path.to_string_lossy().into_owned()];
            ("device", vec![path.clone()], stored)
        } else if path.is_dir() {
            let stored = vec![path.to_string_lossy().into_owned()];
            ("folder", vec![path.clone()], stored)
        } else if is_image(&path) {
            let files = segments(&path);
            let stored: Vec<String> = files
                .iter()
                .map(|f| f.to_string_lossy().into_owned())
                .collect();
            ("image", files, stored)
        } else {
            let rel = PathBuf::from("sources").join(id.to_string()).join(&label);
            let copy = self.dir.join(&rel);
            std::fs::create_dir_all(copy.parent().expect("has a parent"))?;
            std::fs::copy(&path, &copy)?;
            if full_hash(std::slice::from_ref(&path))? != full_hash(std::slice::from_ref(&copy))? {
                std::fs::remove_dir_all(copy.parent().expect("has a parent"))?;
                return Err(ProjectError::Io(std::io::Error::other(
                    "the copy doesn't match the original",
                )));
            }
            (
                "loose",
                vec![copy],
                vec![rel.to_string_lossy().into_owned()],
            )
        };
        let (size, sha256, fingerprint) = if kind == "device" {
            // A live device can change under us, so a hash would prove nothing later (I28).
            let img = af_host::raw::RawImage::open(&files, af_core::bytes::Locator::default())
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::PermissionDenied => std::io::Error::new(
                        e.kind(),
                        if cfg!(windows) {
                            format!("{}: reading a physical drive needs af run as administrator", path.display())
                        } else {
                            format!(
                                "{}: reading a device needs root or the disk group, or read access just for it (`sudo setfacl -m u:$USER:r {}`)",
                                path.display(),
                                path.display()
                            )
                        },
                    ),
                    _ => e,
                })?;
            (
                af_core::bytes::ByteSource::len(&img),
                LIVE.into(),
                LIVE.into(),
            )
        } else if kind == "folder" {
            let (size, fp, sha) = folder_measure(&path, true)?;
            (size, sha.expect("asked for the full hash"), fp)
        } else {
            (
                total_size(&files)?,
                full_hash(&files)?,
                fingerprint(&files)?,
            )
        };
        let check = if kind == "image" {
            image_check(&files)?
        } else {
            None
        };
        let (volumes, notes) = if kind == "image" || kind == "device" {
            list_volumes(&files)
        } else {
            (vec![], vec![])
        };
        let added = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let tx = self.store.conn.transaction()?;
        tx.execute(
            "INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'unknown')",
            duckdb::params![id.0, kind, label, size, sha256, fingerprint, added],
        )?;
        for (seq, (f, s)) in files.iter().zip(&stored).enumerate() {
            let len = if kind == "folder" || kind == "device" {
                size
            } else {
                std::fs::metadata(f)?.len()
            };
            tx.execute(
                "INSERT INTO source_files VALUES (?, ?, ?, ?)",
                duckdb::params![id.0, seq as i32, s, len],
            )?;
        }
        if let Some(c) = &check {
            tx.execute(
                "INSERT INTO image_checks VALUES (?, ?, ?, ?, ?, ?, ?)",
                duckdb::params![
                    id.0,
                    c.stored_md5,
                    c.stored_sha1,
                    c.computed_md5,
                    c.result,
                    c.acquisition_errors,
                    c.acquired
                ],
            )?;
        }
        for v in &volumes {
            tx.execute(
                "INSERT INTO volumes VALUES (?, ?, ?, ?, ?, ?)",
                duckdb::params![id.0, v.id, v.start, v.len, v.description, v.content],
            )?;
        }
        for n in &notes {
            tx.execute(
                "INSERT INTO volume_notes VALUES (?, ?)",
                duckdb::params![id.0, n],
            )?;
        }
        tx.commit()?;
        Ok(SourceInfo {
            id,
            kind: kind.into(),
            label,
            size,
            sha256,
            fingerprint,
            files,
        })
    }

    /// The volumes found when the source was added, by start, and the notes on its tables.
    pub fn volumes(&self, id: SourceId) -> Result<(Vec<VolumeRow>, Vec<String>), ProjectError> {
        let mut stmt = self.store.conn.prepare(
            "SELECT id, start, len, description, content FROM volumes WHERE source = ? ORDER BY start, id",
        )?;
        let rows = stmt
            .query_map([id.0], |r| {
                Ok(VolumeRow {
                    id: r.get(0)?,
                    start: r.get(1)?,
                    len: r.get(2)?,
                    description: r.get(3)?,
                    content: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut stmt = self
            .store
            .conn
            .prepare("SELECT note FROM volume_notes WHERE source = ?")?;
        let notes = stmt
            .query_map([id.0], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok((rows, notes))
    }

    /// The E01 check made when the source was added, if it is an E01.
    pub fn image_check(&self, id: SourceId) -> Result<Option<ImageCheck>, ProjectError> {
        let mut stmt = self.store.conn.prepare(
            "SELECT stored_md5, stored_sha1, computed_md5, result, acquisition_errors, acquired \
             FROM image_checks WHERE source = ?",
        )?;
        let mut rows = stmt.query_map([id.0], |r| {
            Ok(ImageCheck {
                stored_md5: r.get(0)?,
                stored_sha1: r.get(1)?,
                computed_md5: r.get(2)?,
                result: r.get(3)?,
                acquisition_errors: r.get(4)?,
                acquired: r.get(5)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Sets when a source's evidence was captured. `basis` is one of [`AsOf::BASES`].
    pub fn set_as_of(
        &mut self,
        id: SourceId,
        unix: Option<i64>,
        basis: &str,
    ) -> Result<(), ProjectError> {
        if !AsOf::BASES.contains(&basis) || (unix.is_none() != (basis == "unknown")) {
            return Err(ProjectError::Mismatch(format!(
                "an as-of time needs a basis of acquisition, last_shutdown or entered, and \
                 'unknown' needs no time (got {basis})"
            )));
        }
        let n = self.store.conn.execute(
            "UPDATE sources SET as_of_unix = ?, as_of_basis = ? WHERE id = ?",
            duckdb::params![unix, basis, id.0],
        )?;
        if n == 0 {
            return Err(ProjectError::NoSource(id.to_string()));
        }
        Ok(())
    }

    /// When a source's evidence was captured.
    pub fn as_of(&self, id: SourceId) -> Result<AsOf, ProjectError> {
        self.store
            .conn
            .query_row(
                "SELECT as_of_unix, as_of_basis FROM sources WHERE id = ?",
                [id.0],
                |r| {
                    Ok(AsOf {
                        unix: r.get(0)?,
                        basis: r.get(1)?,
                    })
                },
            )
            .map_err(|e| match e {
                duckdb::Error::QueryReturnedNoRows => ProjectError::NoSource(id.to_string()),
                other => ProjectError::Db(other),
            })
    }

    /// When a fact is true: the as-of time of the source it was read from.
    pub fn fact_as_of(&self, fact: u128) -> Result<AsOf, ProjectError> {
        let source: u128 =
            self.store
                .conn
                .query_row("SELECT source FROM facts WHERE id = ?", [fact], |r| {
                    r.get(0)
                })?;
        self.as_of(SourceId(source))
    }

    /// All sources, in the order they were added.
    pub fn sources(&self) -> Result<Vec<SourceInfo>, ProjectError> {
        let conn = &self.store.conn;
        let mut stmt = conn.prepare(
            "SELECT id, kind, label, size, sha256, fingerprint FROM sources ORDER BY added_unix, id",
        )?;
        let mut list: Vec<SourceInfo> = stmt
            .query_map([], |r| {
                Ok(SourceInfo {
                    id: SourceId(r.get(0)?),
                    kind: r.get(1)?,
                    label: r.get(2)?,
                    size: r.get(3)?,
                    sha256: r.get(4)?,
                    fingerprint: r.get(5)?,
                    files: Vec::new(),
                })
            })?
            .collect::<Result<_, _>>()?;
        let mut files =
            conn.prepare("SELECT path FROM source_files WHERE source = ? ORDER BY seq")?;
        for s in &mut list {
            let stored: Vec<String> = files
                .query_map([s.id.0], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            s.files = stored
                .into_iter()
                .map(|p| match s.kind.as_str() {
                    "loose" => self.dir.join(p),
                    _ => PathBuf::from(p),
                })
                .collect();
        }
        Ok(list)
    }

    fn source(&self, id: SourceId) -> Result<SourceInfo, ProjectError> {
        self.sources()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| ProjectError::NoSource(id.to_string()))
    }

    /// Removes a source with its records, events and entities. A loose file's copy goes too;
    /// an image is never touched.
    pub fn remove_source(&mut self, id: SourceId) -> Result<(), ProjectError> {
        let s = self.source(id)?;
        let tx = self.store.conn.transaction()?;
        for table in ["system_facts", "run_log", "outcomes"] {
            tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE system IN (SELECT id FROM systems WHERE source = ?)"
                ),
                [id.0],
            )?;
        }
        for table in [
            "events",
            "records",
            "entities",
            "facts",
            "artifacts",
            "systems",
            "source_files",
            "image_checks",
            "volumes",
            "volume_notes",
        ] {
            tx.execute(&format!("DELETE FROM {table} WHERE source = ?"), [id.0])?;
        }
        tx.execute("DELETE FROM sources WHERE id = ?", [id.0])?;
        tx.commit()?;
        if s.kind == "loose" {
            let own = self.dir.join("sources").join(id.to_string());
            if own.is_dir() {
                std::fs::remove_dir_all(own)?;
            }
        }
        Ok(())
    }

    /// Points an image source at its new place. The new files must have the same size and
    /// fingerprint, and with `verify` the same full hash.
    pub fn relink_source(
        &mut self,
        id: SourceId,
        new_path: &Path,
        verify: bool,
    ) -> Result<SourceInfo, ProjectError> {
        let s = self.source(id)?;
        if s.kind == "loose" {
            return Err(ProjectError::Mismatch(
                "only images and folders are referenced; a loose file's copy lives in the project"
                    .into(),
            ));
        }
        if s.kind == "device" {
            // Without a hash there is nothing to prove the new device is the same one.
            return Err(ProjectError::Mismatch(
                "a live device has no hash to check a new path against; add it as a new source"
                    .into(),
            ));
        }
        let new_path = std::fs::canonicalize(new_path)?;
        let (files, size, fp, full) = if s.kind == "folder" {
            let (size, fp, sha) = folder_measure(&new_path, verify)?;
            (vec![new_path.clone()], size, fp, sha)
        } else {
            let files = segments(&new_path);
            let full = if verify {
                Some(full_hash(&files)?)
            } else {
                None
            };
            let (size, fp) = (total_size(&files)?, fingerprint(&files)?);
            (files, size, fp, full)
        };
        if size != s.size || fp != s.fingerprint {
            return Err(ProjectError::Mismatch(format!(
                "{} is not the same {} (size or fingerprint differs)",
                new_path.display(),
                s.kind
            )));
        }
        if full.is_some_and(|h| h != s.sha256) {
            return Err(ProjectError::Mismatch(format!(
                "{} has another SHA-256",
                new_path.display()
            )));
        }
        let tx = self.store.conn.transaction()?;
        tx.execute("DELETE FROM source_files WHERE source = ?", [id.0])?;
        for (seq, f) in files.iter().enumerate() {
            let len = if s.kind == "folder" {
                size
            } else {
                std::fs::metadata(f)?.len()
            };
            tx.execute(
                "INSERT INTO source_files VALUES (?, ?, ?, ?)",
                duckdb::params![id.0, seq as i32, f.to_string_lossy().into_owned(), len],
            )?;
        }
        tx.commit()?;
        self.source(id)
    }
}

/// What an E01 says about itself, and whether its media still hash to what it stored (I6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageCheck {
    pub stored_md5: Option<String>,
    pub stored_sha1: Option<String>,
    pub computed_md5: String,
    /// `verified`, `MISMATCH`, `no stored hash` or `unreadable: <why>`.
    pub result: String,
    /// Sector ranges the imager couldn't read, as `first+count` separated by commas; empty if none.
    pub acquisition_errors: String,
    /// The acquisition date as the imager wrote it: local time of that machine, zone unknown.
    pub acquired: Option<String>,
}

impl ImageCheck {
    /// One line for `af status` and `af source add`.
    pub fn display(&self) -> String {
        let stored = match (&self.stored_md5, &self.stored_sha1) {
            (Some(m), Some(s)) => format!("stored MD5 {m}, SHA-1 {s}"),
            (Some(m), None) => format!("stored MD5 {m}"),
            _ => "no stored hash".into(),
        };
        let errors = if self.acquisition_errors.is_empty() {
            "no acquisition errors".to_string()
        } else {
            format!("acquisition errors at sectors {}", self.acquisition_errors)
        };
        format!("E01 {}: {stored}; {errors}", self.result)
    }
}

/// One volume of an image or device, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRow {
    /// `whole`, a partition number (`1`, `1/1` nested), or `gap1`, ...
    pub id: String,
    pub start: u64,
    pub len: u64,
    pub description: String,
    pub content: String,
}

impl VolumeRow {
    pub fn display(&self) -> String {
        format!(
            "volume {}: {} at byte {}, {} bytes ({})",
            self.id, self.content, self.start, self.len, self.description
        )
    }
}

/// The volumes of an image or device. One that can't be read is still added, with a note.
fn list_volumes(files: &[PathBuf]) -> (Vec<VolumeRow>, Vec<String>) {
    let listing = af_host::ewf::open_image(files, af_core::bytes::Locator::default())
        .and_then(|src| af_host::volumes::list(std::sync::Arc::from(src)));
    match listing {
        Ok(l) => (
            l.volumes
                .iter()
                .map(|v| VolumeRow {
                    id: v.id.clone(),
                    start: v.start,
                    len: v.len,
                    description: v.description.clone(),
                    content: v.content.name().into(),
                })
                .collect(),
            l.notes,
        ),
        Err(e) => (vec![], vec![format!("volumes not listed: {e}")]),
    }
}

/// The verdict from the two hash comparisons: any mismatch wins, then any match.
fn verdict(md5: Option<bool>, sha1: Option<bool>) -> &'static str {
    match (md5, sha1) {
        (Some(false), _) | (_, Some(false)) => "MISMATCH",
        (None, None) => "no stored hash",
        _ => "verified",
    }
}

/// Reads a whole E01 set to recompute its media hash. `None` for images that aren't E01s.
fn image_check(files: &[PathBuf]) -> std::io::Result<Option<ImageCheck>> {
    let is_e01 = files
        .first()
        .and_then(|f| f.extension())
        .is_some_and(|e| e.eq_ignore_ascii_case("e01"));
    if !is_e01 {
        return Ok(None);
    }
    // A damaged E01 is still evidence: it is added, and the check says what's wrong with it.
    let unreadable = |e: &dyn std::fmt::Display| ImageCheck {
        stored_md5: None,
        stored_sha1: None,
        computed_md5: String::new(),
        result: format!("unreadable: {e}"),
        acquisition_errors: String::new(),
        acquired: None,
    };
    let img = match af_host::ewf::EwfImage::open(files, af_core::bytes::Locator::default()) {
        Ok(i) => i,
        Err(e) => return Ok(Some(unreadable(&e))),
    };
    let r = img.reader();
    let v = match r.verify() {
        Ok(v) => v,
        Err(e) => return Ok(Some(unreadable(&e))),
    };
    let stored = r.stored_hashes();
    Ok(Some(ImageCheck {
        stored_md5: stored.md5.map(|h| hex(&h)),
        stored_sha1: stored.sha1.map(|h| hex(&h)),
        computed_md5: hex(&v.computed_md5),
        result: verdict(v.md5_match, v.sha1_match).into(),
        acquisition_errors: r
            .acquisition_errors()
            .iter()
            .map(|e| format!("{}+{}", e.first_sector, e.sector_count))
            .collect::<Vec<_>>()
            .join(","),
        acquired: r.metadata().acquiry_date.clone(),
    }))
}

fn is_image(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| IMAGE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// The segment files of an image: `x.E01`, `x.E02`, ... or `x.001`, `x.002`, ..., counting up
/// from the given one while the next file exists, in the same letter case. Other images are one
/// file.
// shortcut: two-digit E01-E99 and three-digit 001-999 only; EAA-style segments after E99 come with I5.
fn segments(path: &Path) -> Vec<PathBuf> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let (prefix, digits) = match ext.as_bytes() {
        [p, a, b] if p.eq_ignore_ascii_case(&b'e') && a.is_ascii_digit() && b.is_ascii_digit() => {
            (&ext[..1], &ext[1..])
        }
        [a, b, c] if a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit() => ("", ext),
        _ => return vec![path.to_path_buf()],
    };
    let width = digits.len();
    let mut n: u32 = digits.parse().unwrap_or(1);
    let mut out = vec![path.to_path_buf()];
    loop {
        n += 1;
        let next = path.with_extension(format!("{prefix}{n:0width$}"));
        if n >= 10u32.pow(width as u32) || !next.is_file() {
            break;
        }
        out.push(next);
    }
    out
}

/// A folder's total size, its fingerprint (SHA-256 over every file's path and size) and, with
/// `full`, its hash (SHA-256 over every file's path and content hash). Paths are taken below the
/// folder, in their escaped form, so the folder can move.
fn folder_measure(dir: &Path, full: bool) -> std::io::Result<(u64, String, Option<String>)> {
    let vol = af_host::folder::FolderVolume::new(af_core::system::VolumeId(0), dir);
    let style = af_core::path::PathStyle {
        separator: '/',
        case: af_core::path::CasePolicy::Exact,
    };
    let (mut fp, mut sha) = (Sha256::new(), Sha256::new());
    let mut size = 0u64;
    for f in vol.files()? {
        let rel = f.path.display(style);
        size += f.size;
        fp.update((rel.len() as u64).to_le_bytes());
        fp.update(rel.as_bytes());
        fp.update(f.size.to_le_bytes());
        if full {
            sha.update((rel.len() as u64).to_le_bytes());
            sha.update(rel.as_bytes());
            sha.update(full_hash(std::slice::from_ref(&f.on_disk))?.as_bytes());
        }
    }
    Ok((
        size,
        hex(&fp.finalize()),
        full.then(|| hex(&sha.finalize())),
    ))
}

fn total_size(files: &[PathBuf]) -> std::io::Result<u64> {
    files
        .iter()
        .map(|f| std::fs::metadata(f).map(|m| m.len()))
        .sum()
}

pub(crate) fn full_hash(files: &[PathBuf]) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; MIB as usize];
    for f in files {
        let mut file = File::open(f)?;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
    }
    Ok(hex(&h.finalize()))
}

/// SHA-256 over the total size and the first, middle and last MiB of the files read as one.
fn fingerprint(files: &[PathBuf]) -> std::io::Result<String> {
    let size = total_size(files)?;
    let mut h = Sha256::new();
    h.update(size.to_le_bytes());
    let len = MIB.min(size);
    for start in [0, (size - len) / 2, size - len] {
        h.update(read_virtual(files, start, len)?);
    }
    Ok(hex(&h.finalize()))
}

/// `len` bytes at `offset` of the files read as one stream.
fn read_virtual(files: &[PathBuf], mut offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len as usize);
    for f in files {
        if out.len() as u64 == len {
            break;
        }
        let flen = std::fs::metadata(f)?.len();
        if offset >= flen {
            offset -= flen;
            continue;
        }
        let mut file = File::open(f)?;
        file.seek(SeekFrom::Start(offset))?;
        let want = (len - out.len() as u64).min(flen - offset);
        let mut part = vec![0u8; want as usize];
        file.read_exact(&mut part)?;
        out.extend_from_slice(&part);
        offset = 0;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_mismatch_wins_over_a_match() {
        assert_eq!(verdict(Some(true), Some(false)), "MISMATCH");
        assert_eq!(verdict(Some(true), None), "verified");
        assert_eq!(verdict(None, None), "no stored hash");
    }

    /// I6 on a real E01, where the dfVFS samples are fetched: stored and recomputed MD5 agree.
    #[test]
    fn an_added_e01_is_verified() {
        let e01 = PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("af-stage3/evidence/dfvfs/ext2.E01");
        if !e01.is_file() {
            return;
        }
        let root = scratch("e01");
        let mut p = Project::create(&root.join("case"), "t").unwrap();
        let s = p.add_source(&e01).unwrap();
        let c = p.image_check(s.id).unwrap().expect("an E01 gets a check");
        assert_eq!(c.result, "verified", "{c:?}");
        assert_eq!(c.stored_md5.as_deref(), Some(c.computed_md5.as_str()));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_image_s_volumes_are_stored_and_removed_with_it() {
        let root = scratch("volumes");
        let mut disk = vec![0u8; 64 * 512];
        disk[446 + 4] = 0x0c; // FAT32, sectors 1..=40
        disk[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&40u32.to_le_bytes());
        disk[510..512].copy_from_slice(&[0x55, 0xaa]);
        let img = root.join("disk.dd");
        std::fs::write(&img, &disk).unwrap();
        let mut p = Project::create(&root.join("case"), "t").unwrap();
        let s = p.add_source(&img).unwrap();
        let (v, notes) = p.volumes(s.id).unwrap();
        let got: Vec<_> = v
            .iter()
            .map(|v| (v.id.as_str(), v.start / 512, v.len / 512))
            .collect();
        assert_eq!(got, [("gap1", 0, 1), ("1", 1, 40), ("gap2", 41, 23)]);
        assert_eq!(v[1].description, "mbr 0x0c FAT32");
        assert!(notes.is_empty(), "{notes:?}");
        assert!(
            p.status()
                .unwrap()
                .contains("volume 1: unknown at byte 512, 20480 bytes")
        );
        p.remove_source(s.id).unwrap();
        assert_eq!(p.volumes(s.id).unwrap(), (vec![], vec![]));
        std::fs::remove_dir_all(&root).unwrap();
    }
    use super::*;
    use crate::EventRow;
    use af_core::time::Time;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "af-source-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A 3.5 MiB "image" split into two segments, so the fingerprint reads across both.
    fn image(dir: &Path) -> (PathBuf, Vec<u8>) {
        let data: Vec<u8> = (0..(3 * MIB + MIB / 2))
            .map(|i| (i * 7 % 256) as u8)
            .collect();
        std::fs::write(dir.join("disk.E01"), &data[..2 * MIB as usize]).unwrap();
        std::fs::write(dir.join("disk.E02"), &data[2 * MIB as usize..]).unwrap();
        (dir.join("disk.E01"), data)
    }

    fn event(id: u128, source: SourceId) -> EventRow {
        EventRow {
            id,
            source: source.0,
            record: id,
            system: 1,
            kind: "test.event".into(),
            meaning: "test.written".into(),
            time: Time::from_unix_seconds(id as i64).to_columns(),
            clock_domain: "wall".into(),
            seq_domain: None,
            seq_no: None,
            created_by: "test.plugin".into(),
        }
    }

    #[test]
    fn image_is_referenced_and_hashed_over_its_segments() {
        let root = scratch("image");
        let (e01, data) = image(&root);
        let mut p = Project::create(&root.join("case"), "case").unwrap();
        let s = p.add_source(&e01).unwrap();
        assert_eq!(s.kind, "image");
        assert_eq!(s.files.len(), 2, "both segments");
        assert_eq!(s.size, data.len() as u64);
        assert_eq!(s.sha256, hex(&Sha256::digest(&data)));
        assert!(!root.join("case/sources").exists(), "images aren't copied");
        assert_eq!(p.sources().unwrap(), [s]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn removing_a_source_removes_its_events() {
        let root = scratch("remove");
        let (e01, _) = image(&root);
        let loose = root.join("SYSTEM");
        std::fs::write(&loose, b"regf...").unwrap();
        let mut p = Project::create(&root.join("case"), "case").unwrap();
        let img = p.add_source(&e01).unwrap();
        let hive = p.add_source(&loose).unwrap();
        assert_eq!(hive.kind, "loose");
        assert!(hive.files[0].starts_with(root.join("case/sources")));
        p.store
            .insert_events(&[event(1, img.id), event(2, img.id), event(3, hive.id)])
            .unwrap();

        p.remove_source(hive.id).unwrap();
        let left: Vec<u128> = p.store.events().unwrap().iter().map(|e| e.id).collect();
        assert_eq!(left, [1, 2]);
        assert!(!hive.files[0].exists(), "the copy is gone");
        assert!(loose.exists(), "the original is untouched");

        p.remove_source(img.id).unwrap();
        assert!(p.store.events().unwrap().is_empty());
        assert!(e01.exists(), "an image is never touched");
        assert!(p.sources().unwrap().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_moved_image_relinks() {
        let root = scratch("relink");
        let (e01, data) = image(&root);
        let mut p = Project::create(&root.join("case"), "case").unwrap();
        let s = p.add_source(&e01).unwrap();
        let moved = root.join("moved");
        std::fs::create_dir_all(&moved).unwrap();
        for seg in ["disk.E01", "disk.E02"] {
            std::fs::rename(root.join(seg), moved.join(seg)).unwrap();
        }
        let r = p
            .relink_source(s.id, &moved.join("disk.E01"), true)
            .unwrap();
        assert_eq!(
            r.files[0],
            std::fs::canonicalize(moved.join("disk.E01")).unwrap()
        );
        assert_eq!(r.sha256, s.sha256);

        // Same size, one byte different in the middle MiB: refused.
        let mut other = data.clone();
        other[(data.len() / 2) + 10] ^= 1;
        let wrong = root.join("wrong");
        std::fs::create_dir_all(&wrong).unwrap();
        std::fs::write(wrong.join("disk.E01"), &other).unwrap();
        assert!(matches!(
            p.relink_source(s.id, &wrong.join("disk.E01"), false),
            Err(ProjectError::Mismatch(_))
        ));
        // A byte outside the fingerprinted parts passes the quick check, but not `verify`.
        let mut sneaky = data.clone();
        sneaky[(MIB + MIB / 10) as usize] ^= 1; // between the first and the middle MiB
        std::fs::write(wrong.join("disk.E01"), &sneaky).unwrap();
        assert!(
            p.relink_source(s.id, &wrong.join("disk.E01"), true)
                .is_err()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn segments_count_up_in_the_same_case() {
        let root = scratch("seg");
        for f in ["x.e01", "x.e02", "x.e03", "y.001", "y.002"] {
            std::fs::write(root.join(f), b"").unwrap();
        }
        assert_eq!(segments(&root.join("x.e01")).len(), 3);
        assert_eq!(segments(&root.join("y.001")).len(), 2);
        assert_eq!(
            segments(&root.join("x.e02")).len(),
            2,
            "from the given one upward"
        );
        assert!(is_image(&root.join("a.VMDK")));
        assert!(!is_image(&root.join("NTUSER.DAT")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_loose_hive_without_a_capture_date_shows_its_facts_as_of_unknown() {
        let root = scratch("asof");
        let hive = root.join("SAM");
        std::fs::write(&hive, b"regf...").unwrap();
        let mut p = Project::create(&root.join("case"), "case").unwrap();
        let s = p.add_source(&hive).unwrap();
        p.store
            .insert_facts(&[crate::facts::FactRow {
                id: 77,
                source: s.id.0,
                system: 1,
                kind: "windows.account".into(),
                subject: "S-1-5-21-1-2-3-1001".into(),
                attrs: None,
                created_by: "windows.registry.sam".into(),
            }])
            .unwrap();
        assert_eq!(p.fact_as_of(77).unwrap().display(), "as of unknown");
        p.set_as_of(s.id, Some(1_777_190_400), "entered").unwrap();
        assert_eq!(
            p.fact_as_of(77).unwrap().display(),
            "as of 2026-04-26 08:00:00 UTC (entered)"
        );
        // A time needs a basis, and "unknown" takes no time.
        assert!(p.set_as_of(s.id, Some(1), "unknown").is_err());
        assert!(p.set_as_of(s.id, None, "entered").is_err());
        assert!(p.set_as_of(s.id, Some(1), "guessed").is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_folder_is_referenced_hashed_and_relinked() {
        let root = scratch("folder");
        let linux = root.join("linux-root");
        for (p, data) in [
            ("etc/hostname", &b"logserver\n"[..]),
            ("var/log/wtmp", &[0u8; 384][..]),
        ] {
            std::fs::create_dir_all(linux.join(p).parent().unwrap()).unwrap();
            std::fs::write(linux.join(p), data).unwrap();
        }
        let mut p = Project::create(&root.join("case"), "case").unwrap();
        let s = p.add_source(&linux).unwrap();
        assert_eq!(s.kind, "folder");
        assert_eq!(s.size, 10 + 384);
        assert!(!root.join("case/sources").exists(), "folders aren't copied");
        // Moved: relinks; with one file changed: refused.
        let moved = root.join("moved-root");
        std::fs::rename(&linux, &moved).unwrap();
        assert!(p.relink_source(s.id, &moved, true).is_ok());
        std::fs::write(moved.join("etc/hostname"), b"otherhost\n").unwrap();
        assert!(
            p.relink_source(s.id, &moved, true).is_err(),
            "same size, other content"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
