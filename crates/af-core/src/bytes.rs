//! Byte sources and locators (piece F12).
//!
//! Everything the tool reads is a [`ByteSource`]: an image, a partition inside it, a file inside
//! the partition, a stream inside the file. Each source reads by offset ([`ByteSource::read_at`]),
//! knows its parent, and can say where one of its offsets lies in the parent
//! ([`ByteSource::map_back`]). Chained to the top ([`map_to_root`]), a hit at offset 10 of a file
//! becomes "byte 1,050,634 of the image", which links search hits back to evidence.
//!
//! Not every offset maps back: sparse runs have no bytes on disk, and compressed or decrypted
//! data has no one-to-one position. Those say so instead of guessing.
//!
//! A [`Locator`] names a source as a chain of namespaced steps from the top, such as
//! `source.image:exam.E01/volume.partition:2/fs.file:ntfs.file_ref=1234-5`.

use crate::names::Kind;
use std::fmt;
use std::io;
use std::sync::Arc;

/// One step of a locator: what kind of thing, and which one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocatorStep {
    pub kind: Kind,
    pub id: String,
}

/// Where a byte source sits, from the top of the evidence down.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Locator(pub Vec<LocatorStep>);

impl Locator {
    pub fn root(kind: &str, id: &str) -> Self {
        Self(vec![LocatorStep::new(kind, id)])
    }

    /// This locator with one more step.
    pub fn child(&self, kind: &str, id: &str) -> Self {
        let mut steps = self.0.clone();
        steps.push(LocatorStep::new(kind, id));
        Self(steps)
    }

    pub fn steps(&self) -> &[LocatorStep] {
        &self.0
    }
}

impl LocatorStep {
    /// A step. Panics on an invalid kind, which is a programming error, not bad evidence.
    pub fn new(kind: &str, id: &str) -> Self {
        Self {
            kind: Kind::new(kind).expect("locator kind is a namespaced name"),
            id: id.to_string(),
        }
    }
}

impl Locator {
    /// Back from the text form [`Display`](fmt::Display) writes. `None` if it isn't one.
    pub fn parse(text: &str) -> Option<Self> {
        let steps = text
            .split('/')
            .map(|step| {
                let (kind, id) = step.split_once(':')?;
                Some(LocatorStep {
                    kind: Kind::new(kind).ok()?,
                    id: id.replace("%2F", "/").replace("%25", "%"),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self(steps))
    }
}

impl fmt::Display for Locator {
    /// `kind:id` steps joined by `/`. A `/` or `%` inside an ID is written as `%2F` or `%25`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            write!(
                f,
                "{}:{}",
                s.kind,
                s.id.replace('%', "%25").replace('/', "%2F")
            )?;
        }
        Ok(())
    }
}

/// Where an offset of a source lies in its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapBack {
    /// At this offset of the parent.
    Parent(u64),
    /// This source is the top; the offset is already an evidence offset.
    Root,
    /// Beyond the end of the source.
    OutOfRange,
    /// No bytes stand for it in the parent: a sparse run reads as zeros.
    Sparse,
    /// The bytes exist in the parent, but not one to one (compressed, encrypted, decoded).
    Transformed,
}

/// Bytes that can be read by offset, with a parent to map back to.
pub trait ByteSource: Send + Sync {
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads up to `buf.len()` bytes at `offset`. Returns fewer near the end, and 0 at or past it.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    fn locator(&self) -> &Locator;

    /// The source this one was cut from, if any.
    fn parent(&self) -> Option<&Arc<dyn ByteSource>>;

    /// Where `offset` lies in the parent.
    fn map_back(&self, offset: u64) -> MapBack;

    /// Reads exactly `buf.len()` bytes at `offset`, or fails with `UnexpectedEof`.
    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.read_at(offset, buf)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            offset += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    }
}

/// Where an offset ends up after mapping back as far as possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOffset {
    /// The source the mapping stopped at: the top, or the last one before a step that can't map.
    pub locator: Locator,
    pub offset: u64,
    /// `None` if it reached the top; otherwise why it stopped.
    pub stopped: Option<MapBack>,
}

/// Maps `offset` of `source` back through every parent, as far as it goes.
pub fn map_to_root(source: &dyn ByteSource, offset: u64) -> RootOffset {
    let mut current: &dyn ByteSource = source;
    let mut offset = offset;
    loop {
        match current.map_back(offset) {
            MapBack::Parent(o) => match current.parent() {
                Some(p) => {
                    current = p.as_ref();
                    offset = o;
                }
                None => {
                    return RootOffset {
                        locator: current.locator().clone(),
                        offset,
                        stopped: Some(MapBack::Root),
                    };
                }
            },
            MapBack::Root => {
                return RootOffset {
                    locator: current.locator().clone(),
                    offset,
                    stopped: None,
                };
            }
            other => {
                return RootOffset {
                    locator: current.locator().clone(),
                    offset,
                    stopped: Some(other),
                };
            }
        }
    }
}

/// Bytes in memory, as a top-level source. For tests, fixtures and small loose files.
pub struct MemSource {
    data: Vec<u8>,
    locator: Locator,
}

impl MemSource {
    pub fn new(data: Vec<u8>, locator: Locator) -> Self {
        Self { data, locator }
    }
}

impl ByteSource for MemSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        Ok(copy_from(&self.data, offset, buf))
    }
    fn locator(&self) -> &Locator {
        &self.locator
    }
    fn parent(&self) -> Option<&Arc<dyn ByteSource>> {
        None
    }
    fn map_back(&self, offset: u64) -> MapBack {
        if offset < self.len() {
            MapBack::Root
        } else {
            MapBack::OutOfRange
        }
    }
}

fn copy_from(data: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let Ok(start) = usize::try_from(offset) else {
        return 0;
    };
    if start >= data.len() {
        return 0;
    }
    let n = buf.len().min(data.len() - start);
    buf[..n].copy_from_slice(&data[start..start + n]);
    n
}

/// One run of an [`ExtentSource`]: `len` bytes from `start` of the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub start: u64,
    pub len: u64,
    pub target: ExtentTarget,
}

/// Where a run's bytes come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentTarget {
    /// At this offset of the parent.
    Parent(u64),
    /// No bytes on disk: reads as zeros.
    Sparse,
}

/// A source made of runs of its parent: a file's data runs, or one partition (a single run).
pub struct ExtentSource {
    parent: Arc<dyn ByteSource>,
    extents: Vec<Extent>,
    len: u64,
    locator: Locator,
}

impl ExtentSource {
    /// Runs must be in order, without gaps or overlaps, starting at 0. A gap or overlap is an
    /// error, because it would make offsets ambiguous.
    pub fn new(
        parent: Arc<dyn ByteSource>,
        mut extents: Vec<Extent>,
        locator: Locator,
    ) -> io::Result<Self> {
        extents.retain(|e| e.len > 0);
        let mut next = 0u64;
        for e in &extents {
            if e.start != next {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "extent at {} doesn't follow the previous one at {next}",
                        e.start
                    ),
                ));
            }
            next = e
                .start
                .checked_add(e.len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "extent too long"))?;
        }
        Ok(Self {
            parent,
            extents,
            len: next,
            locator,
        })
    }

    /// A window `[offset, offset + len)` of the parent, such as a partition.
    pub fn slice(
        parent: Arc<dyn ByteSource>,
        offset: u64,
        len: u64,
        locator: Locator,
    ) -> io::Result<Self> {
        Self::new(
            parent,
            vec![Extent {
                start: 0,
                len,
                target: ExtentTarget::Parent(offset),
            }],
            locator,
        )
    }

    fn extent_at(&self, offset: u64) -> Option<&Extent> {
        let i = self.extents.partition_point(|e| e.start + e.len <= offset);
        self.extents.get(i).filter(|e| e.start <= offset)
    }
}

impl ByteSource for ExtentSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(e) = self.extent_at(offset) else {
            return Ok(0);
        };
        let within = offset - e.start;
        let n = buf
            .len()
            .min(usize::try_from(e.len - within).unwrap_or(usize::MAX));
        match e.target {
            ExtentTarget::Sparse => {
                buf[..n].fill(0);
                Ok(n)
            }
            ExtentTarget::Parent(p) => self.parent.read_at(p + within, &mut buf[..n]),
        }
    }

    fn locator(&self) -> &Locator {
        &self.locator
    }

    fn parent(&self) -> Option<&Arc<dyn ByteSource>> {
        Some(&self.parent)
    }

    fn map_back(&self, offset: u64) -> MapBack {
        match self.extent_at(offset) {
            None => MapBack::OutOfRange,
            Some(Extent {
                target: ExtentTarget::Sparse,
                ..
            }) => MapBack::Sparse,
            Some(
                e @ Extent {
                    target: ExtentTarget::Parent(p),
                    ..
                },
            ) => MapBack::Parent(p + (offset - e.start)),
        }
    }
}

/// Bytes decoded from a parent (decompressed, decrypted), held in memory. Offsets can't map back
/// one to one, so [`map_back`](ByteSource::map_back) says [`MapBack::Transformed`].
pub struct DecodedSource {
    parent: Arc<dyn ByteSource>,
    data: Vec<u8>,
    locator: Locator,
}

impl DecodedSource {
    pub fn new(parent: Arc<dyn ByteSource>, data: Vec<u8>, locator: Locator) -> Self {
        Self {
            parent,
            data,
            locator,
        }
    }
}

impl ByteSource for DecodedSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        Ok(copy_from(&self.data, offset, buf))
    }
    fn locator(&self) -> &Locator {
        &self.locator
    }
    fn parent(&self) -> Option<&Arc<dyn ByteSource>> {
        Some(&self.parent)
    }
    fn map_back(&self, offset: u64) -> MapBack {
        if offset < self.len() {
            MapBack::Transformed
        } else {
            MapBack::OutOfRange
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4 MiB image whose byte at offset `o` is `o % 251`, so every read is checkable.
    fn image() -> Arc<dyn ByteSource> {
        let data: Vec<u8> = (0..4u64 << 20).map(|o| (o % 251) as u8).collect();
        Arc::new(MemSource::new(
            data,
            Locator::root("source.image", "exam.E01"),
        ))
    }

    fn at(o: u64) -> u8 {
        (o % 251) as u8
    }

    const PART: u64 = 1 << 20; // the partition starts at 1 MiB

    /// image → partition at 1 MiB → a file in three runs: 4 KiB at partition 8 KiB, a sparse
    /// 4 KiB run, 2 KiB at partition 64 KiB.
    fn file(image: &Arc<dyn ByteSource>) -> (Arc<dyn ByteSource>, ExtentSource) {
        let part: Arc<dyn ByteSource> = Arc::new(
            ExtentSource::slice(
                image.clone(),
                PART,
                2 << 20,
                image.locator().child("volume.partition", "2"),
            )
            .unwrap(),
        );
        let f = ExtentSource::new(
            part.clone(),
            vec![
                Extent {
                    start: 0,
                    len: 4096,
                    target: ExtentTarget::Parent(8192),
                },
                Extent {
                    start: 4096,
                    len: 4096,
                    target: ExtentTarget::Sparse,
                },
                Extent {
                    start: 8192,
                    len: 2048,
                    target: ExtentTarget::Parent(65536),
                },
            ],
            part.locator().child("fs.file", "ntfs.file_ref=1234-5"),
        )
        .unwrap();
        (part, f)
    }

    #[test]
    fn nested_read_maps_back_to_the_outer_offset() {
        let img = image();
        let (_part, f) = file(&img);
        // Offset 10 of the file is partition offset 8202, image offset 1 MiB + 8202.
        let r = map_to_root(&f, 10);
        assert_eq!(r.stopped, None);
        assert_eq!(r.offset, PART + 8192 + 10);
        assert_eq!(r.locator.to_string(), "source.image:exam.E01");
        // And the bytes agree with the image at that offset.
        let mut b = [0u8; 1];
        f.read_exact_at(10, &mut b).unwrap();
        assert_eq!(b[0], at(r.offset));
        // In the third run.
        let r = map_to_root(&f, 8192 + 100);
        assert_eq!(r.offset, PART + 65536 + 100);
    }

    #[test]
    fn reads_cross_runs_and_sparse_reads_zeros() {
        let img = image();
        let (_part, f) = file(&img);
        assert_eq!(f.len(), 10240);
        let mut buf = vec![0xaa; 10240];
        f.read_exact_at(0, &mut buf).unwrap();
        assert!((0..4096).all(|i| buf[i] == at(PART + 8192 + i as u64)));
        assert!(buf[4096..8192].iter().all(|&b| b == 0));
        assert!((0..2048).all(|i| buf[8192 + i] == at(PART + 65536 + i as u64)));
        // Short read at the end, nothing past it.
        let mut tail = [0u8; 100];
        assert_eq!(f.read_at(10200, &mut tail).unwrap(), 40);
        assert_eq!(f.read_at(10240, &mut tail).unwrap(), 0);
        assert!(f.read_exact_at(10200, &mut tail).is_err());
    }

    #[test]
    fn mapping_stops_where_it_must() {
        let img = image();
        let (_part, f) = file(&img);
        let r = map_to_root(&f, 5000);
        assert_eq!(r.stopped, Some(MapBack::Sparse));
        assert!(
            r.locator
                .to_string()
                .ends_with("fs.file:ntfs.file_ref=1234-5")
        );
        assert_eq!(map_to_root(&f, 1 << 30).stopped, Some(MapBack::OutOfRange));

        let f: Arc<dyn ByteSource> = Arc::new(f);
        let zip = DecodedSource::new(
            f.clone(),
            b"inflated bytes".to_vec(),
            f.locator().child("decode.deflate", "member=report.txt"),
        );
        let r = map_to_root(&zip, 3);
        assert_eq!(r.stopped, Some(MapBack::Transformed));
        assert_eq!(r.offset, 3);
    }

    #[test]
    fn gaps_and_overlaps_are_refused() {
        let img = image();
        let loc = Locator::root("fs.file", "x");
        let gap = ExtentSource::new(
            img.clone(),
            vec![
                Extent {
                    start: 0,
                    len: 10,
                    target: ExtentTarget::Parent(0),
                },
                Extent {
                    start: 20,
                    len: 10,
                    target: ExtentTarget::Parent(0),
                },
            ],
            loc.clone(),
        );
        assert!(gap.is_err());
        let overlap = ExtentSource::new(
            img,
            vec![
                Extent {
                    start: 0,
                    len: 10,
                    target: ExtentTarget::Parent(0),
                },
                Extent {
                    start: 5,
                    len: 10,
                    target: ExtentTarget::Parent(0),
                },
            ],
            loc,
        );
        assert!(overlap.is_err());
    }

    #[test]
    fn locator_text_escapes_slashes() {
        let l = Locator::root("source.folder", "/home/don/case").child("fs.file", "50%/x");
        assert_eq!(
            l.to_string(),
            "source.folder:%2Fhome%2Fdon%2Fcase/fs.file:50%25%2Fx"
        );
        assert_eq!(l.steps().len(), 2);
        assert_eq!(Locator::parse(&l.to_string()), Some(l));
        // `%2F` written as text inside an ID survives: its `%` is escaped first.
        let tricky = Locator::root("fs.path", "a%2Fb:c");
        assert_eq!(Locator::parse(&tricky.to_string()), Some(tricky));
        assert_eq!(Locator::parse("no-colon"), None);
    }
}
