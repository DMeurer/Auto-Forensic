//! Sources of a project (piece F20): add, list, remove and relink.
//!
//! - **Images** (`.E01` sets, `.dd`, `.raw`, `.img`, `.001` sets, `.vmdk`, `.vhd`, `.vhdx`) are
//!   referenced where they lie and never written to. A segment set (`x.E01`, `x.E02`, ...) is one
//!   source; its hash covers the segment files in order (the media hash inside an E01 comes with
//!   the E01 reader, I5).
//! - **Loose files** (anything else) are copied into `sources/<id>/` inside the project, and the
//!   copy is checked against the original by hash.
//!
//! Adding stores the SHA-256 of every byte and a quick fingerprint: SHA-256 over the size and
//! the first, middle and last MiB. Relinking a moved image checks the fingerprint (seconds), or
//! with `verify` the full hash (minutes). Removing a source deletes its records, events and
//! entities, and a loose file's copy; an image itself is never touched.

use crate::project::{Project, ProjectError};
use af_core::ids::SourceId;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MIB: u64 = 1 << 20;
const IMAGE_EXTENSIONS: &[&str] = &["e01", "dd", "raw", "img", "001", "vmdk", "vhd", "vhdx"];

/// A source as the project lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    pub id: SourceId,
    /// `image` or `loose`.
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
        let (kind, files, stored) = if is_image(&path) {
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
        let size = total_size(&files)?;
        let sha256 = full_hash(&files)?;
        let fingerprint = fingerprint(&files)?;
        let added = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let tx = self.store.conn.transaction()?;
        tx.execute(
            "INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![id.0, kind, label, size, sha256, fingerprint, added],
        )?;
        for (seq, (f, s)) in files.iter().zip(&stored).enumerate() {
            tx.execute(
                "INSERT INTO source_files VALUES (?, ?, ?, ?)",
                duckdb::params![id.0, seq as i32, s, std::fs::metadata(f)?.len()],
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
        for table in ["events", "records", "entities", "source_files"] {
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
        if s.kind != "image" {
            return Err(ProjectError::Mismatch(
                "only images are referenced; a loose file's copy lives in the project".into(),
            ));
        }
        let new_path = std::fs::canonicalize(new_path)?;
        let files = segments(&new_path);
        if total_size(&files)? != s.size || fingerprint(&files)? != s.fingerprint {
            return Err(ProjectError::Mismatch(format!(
                "{} is not the same image (size or fingerprint differs)",
                new_path.display()
            )));
        }
        if verify && full_hash(&files)? != s.sha256 {
            return Err(ProjectError::Mismatch(format!(
                "{} has another SHA-256",
                new_path.display()
            )));
        }
        let tx = self.store.conn.transaction()?;
        tx.execute("DELETE FROM source_files WHERE source = ?", [id.0])?;
        for (seq, f) in files.iter().enumerate() {
            tx.execute(
                "INSERT INTO source_files VALUES (?, ?, ?, ?)",
                duckdb::params![
                    id.0,
                    seq as i32,
                    f.to_string_lossy().into_owned(),
                    std::fs::metadata(f)?.len()
                ],
            )?;
        }
        tx.commit()?;
        self.source(id)
    }
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

fn total_size(files: &[PathBuf]) -> std::io::Result<u64> {
    files
        .iter()
        .map(|f| std::fs::metadata(f).map(|m| m.len()))
        .sum()
}

fn full_hash(files: &[PathBuf]) -> std::io::Result<String> {
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
}
