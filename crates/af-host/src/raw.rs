//! Raw and split raw images (piece I4): one file, or segment files read as one stream.

use af_core::bytes::{ByteSource, Locator, MapBack};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A raw image made of segment files in order (`x.001`, `x.002`, ... or just `x.dd`).
pub struct RawImage {
    /// Each segment with the image offset it starts at.
    segments: Vec<(u64, Mutex<File>)>,
    len: u64,
    locator: Locator,
}

impl RawImage {
    pub fn open(files: &[PathBuf], locator: Locator) -> io::Result<Self> {
        if files.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an image needs a file",
            ));
        }
        let mut segments = Vec::with_capacity(files.len());
        let mut len = 0u64;
        for f in files {
            let mut file = File::open(f)?;
            // Block devices report 0 in their metadata; the end offset works for both.
            let n = file.seek(SeekFrom::End(0))?;
            segments.push((len, Mutex::new(file)));
            len += n;
        }
        Ok(Self {
            segments,
            len,
            locator,
        })
    }
}

impl ByteSource for RawImage {
    fn len(&self) -> u64 {
        self.len
    }

    /// Reads within one segment, so a read across a boundary returns short; the caller reads on.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let i = self.segments.partition_point(|(start, _)| *start <= offset) - 1;
        let (start, file) = &self.segments[i];
        let end = self.segments.get(i + 1).map_or(self.len, |(s, _)| *s);
        let want = buf
            .len()
            .min(usize::try_from(end - offset).unwrap_or(usize::MAX));
        let mut f = file
            .lock()
            .map_err(|_| io::Error::other("file lock poisoned"))?;
        f.seek(SeekFrom::Start(offset - start))?;
        f.read(&mut buf[..want])
    }

    fn locator(&self) -> &Locator {
        &self.locator
    }

    fn parent(&self) -> Option<&Arc<dyn ByteSource>> {
        None
    }

    fn map_back(&self, offset: u64) -> MapBack {
        if offset < self.len {
            MapBack::Root
        } else {
            MapBack::OutOfRange
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(src: &dyn ByteSource, step: usize) -> Vec<u8> {
        let (mut out, mut buf) = (Vec::new(), vec![0u8; step]);
        loop {
            let n = src.read_at(out.len() as u64, &mut buf).unwrap();
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    #[test]
    fn segments_read_as_one_stream() {
        let d = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let parts = [&data[..300], &data[300..301], &data[301..]];
        let files: Vec<PathBuf> = parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let f = d.path().join(format!("x.{:03}", i + 1));
                std::fs::write(&f, p).unwrap();
                f
            })
            .collect();
        let img = RawImage::open(&files, Locator::root("source.image", "x")).unwrap();
        assert_eq!(img.len(), 1000);
        for step in [1, 7, 299, 4096] {
            assert_eq!(read_all(&img, step), data, "step {step}");
        }
        let mut b = [0u8; 4];
        assert_eq!(
            img.read_at(299, &mut b).unwrap(),
            1,
            "stops at the segment end"
        );
        assert_eq!(img.read_at(1000, &mut b).unwrap(), 0);
    }

    /// The dfVFS split raw sample reads the same as its unsplit original, by the pinned hash.
    /// Runs when `cargo xtask evidence fetch dfvfs` has put the samples in place.
    #[test]
    fn dfvfs_split_raw_matches_the_reference() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        let dir = PathBuf::from(home).join("af-stage3/evidence/dfvfs");
        let files = [dir.join("ext2.splitraw.000"), dir.join("ext2.splitraw.001")];
        if !files.iter().all(|f| f.is_file()) {
            return;
        }
        use sha2::{Digest, Sha256};
        let img = RawImage::open(&files, Locator::root("source.image", "ext2")).unwrap();
        let hash: String = Sha256::digest(read_all(&img, 1 << 20))
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // ext2.raw's pin in xtask/evidence.tsv.
        assert_eq!(
            hash,
            "a6c2f0e39afe6c6ab432ca5465349fcefe8dc944398e97b2d957d3f89dbb5d80"
        );
    }
}
