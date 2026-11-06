//! The volumes of an image or device (pieces I7–I10): partitions, the stretches between them,
//! or the whole disk when it has no table (I9). Each is a view of the source, readable like it.
//!
//! A partition whose content is unknown is searched for a table of its own, so a GPT inside an
//! MBR partition (dfVFS `gpt_in_mbr.raw`) lists its partitions as `1/1`.

use af_core::bytes::{ByteSource, ExtentSource};
use af_fmt_volume::partition::{Scheme, gaps, read_table};
use af_fmt_volume::{Content, HEAD_LEN, detect};
use std::io;
use std::sync::Arc;

pub struct Volume {
    /// `whole` without a table; else the partition number (`1`, `5`), `gap1`, ..., with the
    /// containing partition first for nested tables (`1/1`).
    pub id: String,
    /// Bytes from the start of the source.
    pub start: u64,
    pub len: u64,
    /// The table entry, such as `mbr 0x0c FAT32`, or `unallocated`.
    pub description: String,
    pub content: Content,
    pub view: Arc<dyn ByteSource>,
}

#[derive(Default)]
pub struct Listing {
    /// Ordered by start.
    pub volumes: Vec<Volume>,
    /// What was odd about the tables.
    pub notes: Vec<String>,
}

/// Lists the volumes of a source.
pub fn list(src: Arc<dyn ByteSource>) -> io::Result<Listing> {
    let mut out = Listing::default();
    walk(&src, 0, "", &mut out)?;
    out.volumes.sort_by_key(|v| v.start);
    Ok(out)
}

fn walk(src: &Arc<dyn ByteSource>, base: u64, prefix: &str, out: &mut Listing) -> io::Result<()> {
    let len = src.len();
    let mut read = |off: u64, buf: &mut [u8]| src.read_exact_at(off, buf);
    let t = read_table(&mut read, len)?;
    let name = |n: String| {
        if prefix.is_empty() {
            n
        } else {
            format!("{prefix}/{n}")
        }
    };
    out.notes.extend(t.notes.iter().map(|n| {
        if prefix.is_empty() {
            n.clone()
        } else {
            format!("in {prefix}: {n}")
        }
    }));
    if t.scheme == Scheme::None {
        if prefix.is_empty() {
            out.volumes.push(Volume {
                id: "whole".into(),
                start: 0,
                len,
                description: "no partition table".into(),
                content: content_of(&**src)?,
                view: src.clone(),
            });
        }
        return Ok(());
    }
    let mut cut = |kind: &str, id: String, start: u64, plen: u64, description: String| {
        let step = id.rsplit('/').next().unwrap_or(&id).to_string();
        let plen = plen.min(len.saturating_sub(start));
        let view: Arc<dyn ByteSource> = Arc::new(ExtentSource::slice(
            src.clone(),
            start,
            plen,
            src.locator().child(kind, &step),
        )?);
        let content = content_of(&*view)?;
        out.volumes.push(Volume {
            id,
            start: base + start,
            len: plen,
            description,
            content,
            view: view.clone(),
        });
        io::Result::Ok((view, content))
    };
    let mut nested = Vec::new();
    for p in &t.partitions {
        let id = name(p.number.to_string());
        let desc = format!("{} {} {}", t.scheme.name(), p.kind, p.description);
        let (view, content) = cut(
            "volume.partition",
            id.clone(),
            p.start,
            p.len,
            desc.trim_end().into(),
        )?;
        // Two levels at most: a table pointing at itself would otherwise recurse for ever.
        if content == Content::Unknown && prefix.is_empty() && !view.is_empty() {
            nested.push((view, base + p.start, id));
        }
    }
    for (i, (s, l)) in gaps(&t.partitions, len).into_iter().enumerate() {
        cut(
            "volume.gap",
            name(format!("gap{}", i + 1)),
            s,
            l,
            "unallocated".into(),
        )?;
    }
    for (view, at, id) in nested {
        walk(&view, at, &id, out)?;
    }
    Ok(())
}

fn content_of(src: &dyn ByteSource) -> io::Result<Content> {
    let mut head = vec![0u8; (HEAD_LEN as u64).min(src.len()) as usize];
    src.read_exact_at(0, &mut head)?;
    Ok(detect(&head))
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::bytes::Locator;
    use std::path::PathBuf;

    fn home(rel: &str) -> PathBuf {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }

    fn open(path: PathBuf) -> Option<Arc<dyn ByteSource>> {
        path.is_file().then(|| {
            Arc::from(crate::ewf::open_image(&[path], Locator::root("source.image", "t")).unwrap())
        })
    }

    fn ids(l: &Listing) -> Vec<(String, u64, u64, Content)> {
        l.volumes
            .iter()
            .map(|v| (v.id.clone(), v.start / 512, v.len / 512, v.content))
            .collect()
    }

    /// I10: the GPT inside MBR partition 1 is listed as 1/1, at its place on the whole disk.
    #[test]
    fn a_gpt_inside_an_mbr_partition_is_listed_nested() {
        let Some(src) = open(home("af-stage3/evidence/dfvfs/gpt_in_mbr.raw")) else {
            return;
        };
        let l = list(src.clone()).unwrap();
        let v = ids(&l);
        assert!(
            v.contains(&("1".into(), 128, 8192, Content::Unknown)),
            "{v:?}"
        );
        let inner = l
            .volumes
            .iter()
            .find(|v| v.id == "1/1")
            .expect("nested partition");
        assert_eq!((inner.start / 512, inner.len / 512), (128 + 2048, 128));
        // The view reads the disk's bytes at that place.
        let (mut a, mut b) = (vec![0u8; 4096], vec![0u8; 4096]);
        inner.view.read_exact_at(0, &mut a).unwrap();
        src.read_exact_at(inner.start, &mut b).unwrap();
        assert_eq!(a, b);
        assert!(l.notes.is_empty(), "{:?}", l.notes);
    }

    /// I9: a stick without a table is one volume at offset 0.
    #[test]
    fn a_bare_stick_opens_at_offset_0() {
        let Some(src) = open(home("af-stage3/fixtures/fat32.img")) else {
            return;
        };
        let v = ids(&list(src.clone()).unwrap());
        assert_eq!(v, [("whole".into(), 0, src.len() / 512, Content::Fat32)]);
    }

    /// I9: the Windows-made stick has an MBR with one FAT32 partition at sector 63 (`mmls`).
    #[test]
    fn the_windows_stick_has_fat32_behind_an_mbr() {
        let Some(src) = open(PathBuf::from(
            "/mnt/hgfs/VM_sharedFolder/DF/various/USB-Stick images/FAT32-Win.E01",
        )) else {
            return;
        };
        let v = ids(&list(src).unwrap());
        assert_eq!(
            v,
            [
                ("gap1".into(), 0, 63, Content::Unknown),
                ("1".into(), 63, 3_932_097, Content::Fat32)
            ]
        );
    }
}
