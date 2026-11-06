//! E01 images (piece I5), read through the `ewf` crate. The segment set is opened as found by
//! the project (`x.E01`, `x.E02`, ...); reads give the media's bytes, decompressed.

use af_core::bytes::{ByteSource, Locator, MapBack};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

pub struct EwfImage {
    reader: ewf::EwfReader,
    locator: Locator,
}

impl EwfImage {
    pub fn open(segments: &[PathBuf], locator: Locator) -> io::Result<Self> {
        let reader = ewf::EwfReader::open_segments(segments).map_err(io::Error::other)?;
        Ok(Self { reader, locator })
    }

    /// The crate's reader, for the stored hashes, metadata and acquisition errors (I6).
    pub fn reader(&self) -> &ewf::EwfReader {
        &self.reader
    }
}

impl ByteSource for EwfImage {
    fn len(&self) -> u64 {
        self.reader.total_size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len() {
            return Ok(0);
        }
        self.reader.read_at(buf, offset).map_err(io::Error::other)
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

/// Opens an image's files as one source: E01 sets through `ewf`, everything else as raw.
pub fn open_image(files: &[PathBuf], locator: Locator) -> io::Result<Box<dyn ByteSource>> {
    let is_ewf = files.first().and_then(|f| f.extension()).is_some_and(|e| {
        let e = e.to_string_lossy();
        e.len() == 3
            && e[..1].eq_ignore_ascii_case("e")
            && e[1..].bytes().all(|b| b.is_ascii_digit())
    });
    Ok(if is_ewf {
        Box::new(EwfImage::open(files, locator)?)
    } else {
        Box::new(crate::raw::RawImage::open(files, locator)?)
    })
}

/// SHA-256 over all of a source's bytes, read in 1 MiB steps. For tests and checks.
pub fn sha256_of(src: &dyn ByteSource) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let (mut h, mut buf, mut at) = (Sha256::new(), vec![0u8; 1 << 20], 0u64);
    while at < src.len() {
        let n = src.read_at(at, &mut buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("source ends early at {at}"),
            ));
        }
        h.update(&buf[..n]);
        at += n as u64;
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The reference checks below need files outside the repository; they skip where those are missing.
#[cfg(test)]
fn present(paths: &[&std::path::Path]) -> bool {
    paths.iter().all(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> PathBuf {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }

    fn loc() -> Locator {
        Locator::root("source.image", "test")
    }

    /// I5's check: the generated FAT32 stick reads the same from its E01 as from its raw image.
    #[test]
    fn fat32_stick_e01_reads_like_raw() {
        let (e01, img) = (
            home("af-stage3/fixtures/fat32.E01"),
            home("af-stage3/fixtures/fat32.img"),
        );
        if !present(&[&e01, &img]) {
            return;
        }
        let e = open_image(&[e01], loc()).unwrap();
        let r = open_image(&[img], loc()).unwrap();
        assert_eq!(e.len(), r.len());
        // Byte for byte, at unaligned offsets that cross EWF chunk borders (32 KiB).
        let (mut a, mut b) = (vec![0u8; 100_003], vec![0u8; 100_003]);
        let mut at = 0;
        while at < r.len() {
            let n = e.read_at(at, &mut a).unwrap();
            assert!(n > 0, "E01 read stops at {at}");
            assert_eq!(r.read_at(at, &mut b[..n]).unwrap(), n);
            assert_eq!(a[..n], b[..n], "differs near {at}");
            at += n as u64;
        }
    }

    /// dfVFS: one E01 and a two-segment E01 of ext2.raw both hash like the raw file's pin.
    #[test]
    fn dfvfs_e01_sets_hash_like_the_raw_image() {
        let d = home("af-stage3/evidence/dfvfs");
        let one = [d.join("ext2.E01")];
        let two = [d.join("ext2.split.E01"), d.join("ext2.split.E02")];
        let raw = [d.join("ext2.raw")];
        if !present(&[&one[0], &two[0], &two[1], &raw[0]]) {
            return;
        }
        let want = sha256_of(&*open_image(&raw, loc()).unwrap()).unwrap();
        assert_eq!(
            want,
            "a6c2f0e39afe6c6ab432ca5465349fcefe8dc944398e97b2d957d3f89dbb5d80"
        );
        assert_eq!(sha256_of(&*open_image(&one, loc()).unwrap()).unwrap(), want);
        assert_eq!(sha256_of(&*open_image(&two, loc()).unwrap()).unwrap(), want);
    }

    /// The Windows-made stick of stage 1: its E01 data hashes like the deleted raw image did.
    #[test]
    #[ignore = "reads two 2 GB sticks (minutes in a debug build); run with --ignored"]
    fn windows_stick_e01_hashes_like_its_raw_image() {
        let dir = PathBuf::from("/mnt/hgfs/VM_sharedFolder/DF/various/USB-Stick images");
        for name in ["FAT32-Win", "ExFAT-Win"] {
            let (e01, sum) = (
                dir.join(format!("{name}.E01")),
                dir.join(format!("{name}.img.sha256")),
            );
            if !present(&[&e01, &sum]) {
                continue;
            }
            let want = std::fs::read_to_string(&sum).unwrap();
            let want = want.split_whitespace().next().unwrap();
            let got = sha256_of(&*open_image(&[e01], loc()).unwrap()).unwrap();
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn extensions_pick_the_reader() {
        let d = tempfile::tempdir().unwrap();
        let raw = d.path().join("x.dd");
        std::fs::write(&raw, [1u8, 2, 3]).unwrap();
        assert_eq!(open_image(&[raw], loc()).unwrap().len(), 3);
        let fake = d.path().join("x.E01");
        std::fs::write(&fake, [0u8; 64]).unwrap();
        assert!(
            open_image(&[fake], loc()).is_err(),
            "not an EWF file: an error, not a panic"
        );
    }
}
