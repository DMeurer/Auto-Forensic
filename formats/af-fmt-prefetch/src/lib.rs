//! Windows Prefetch files from bytes (piece X1), on our `frnsc-prefetch` fork (X0): versions 17
//! (XP), 23 (Vista and 7), 26 (8), 30 and 31 (10 and 11, compressed with Xpress Huffman, which
//! the fork decompresses itself, so it works on any system).
//!
//! T4 matched the crate with PECmd on four images, value for value. A file of only zeros is a
//! file Windows created but never wrote (the exam image's `GETHELP.EXE-40796CE6.pf`, whose NTFS
//! data is uninitialised, and LoneWolf's `CHROME.EXE-CCF9F3F5.pf`, whose zeros are on disk):
//! [`Error::NeverWritten`], not a parse error.

use forensic_rs::traits::vfs::{VFileType, VMetadata, VirtualFile};
use std::io::{Cursor, Read, Seek, SeekFrom};

/// One Prefetch file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefetch {
    /// 17, 23, 26, 30 or 31.
    pub version: u32,
    /// The executable's name as stored (`CMD.EXE`).
    pub name: String,
    pub run_count: u32,
    /// The stored run times (up to 8) as FILETIME ticks, in stored order. Windows doesn't keep
    /// them sorted, so the latest isn't always the first (stage 1, X2).
    pub run_times: Vec<u64>,
    /// The files the program loaded, as stored (`\VOLUME{...}\WINDOWS\SYSTEM32\NTDLL.DLL`).
    pub files: Vec<String>,
    pub volumes: Vec<Volume>,
}

/// A volume the program used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// `\DEVICE\HARDDISKVOLUME2` and the like.
    pub device_path: String,
    pub serial: u32,
    /// When the volume was created, in FILETIME ticks.
    pub created: u64,
    pub directories: Vec<String>,
}

/// Why a file gave no Prefetch data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Empty or only zeros: Windows created the file but never wrote its content.
    NeverWritten,
    /// Not a Prefetch file, or a damaged one, in the parser's words.
    Bad(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NeverWritten => write!(f, "never written (empty or only zeros)"),
            Error::Bad(e) => write!(f, "{e}"),
        }
    }
}

/// Reads a Prefetch file. `file_name` is its name on disk (`CMD.EXE-087B4001.pf`); the parser
/// compares it with the stored name and hash.
pub fn read(file_name: &str, data: &[u8]) -> Result<Prefetch, Error> {
    if data.iter().all(|&b| b == 0) {
        return Err(Error::NeverWritten);
    }
    let file = Box::new(Bytes(Cursor::new(data.to_vec())));
    let pf = frnsc_prefetch::prelude::read_prefetch_file(file_name, file)
        .map_err(|e| Error::Bad(e.to_string()))?;
    Ok(Prefetch {
        version: pf.version,
        name: pf.name,
        run_count: pf.run_count,
        run_times: pf.last_run_times.iter().map(|t| t.filetime()).collect(),
        files: pf.metrics.into_iter().map(|m| m.file).collect(),
        volumes: pf
            .volume
            .into_iter()
            .map(|v| Volume {
                device_path: v.device_path,
                serial: v.serial_number,
                created: v.creation_time,
                directories: v.directory_strings,
            })
            .collect(),
    })
}

/// Bytes as the file the parser reads from.
struct Bytes(Cursor<Vec<u8>>);

impl Read for Bytes {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for Bytes {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(to)
    }
}

impl VirtualFile for Bytes {
    fn metadata(&self) -> forensic_rs::err::ForensicResult<VMetadata> {
        Ok(VMetadata {
            created: None,
            accessed: None,
            modified: None,
            file_type: VFileType::File,
            size: self.0.get_ref().len() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_and_empty_files_were_never_written() {
        assert_eq!(
            read("GETHELP.EXE-40796CE6.pf", &[0; 9036]),
            Err(Error::NeverWritten)
        );
        assert_eq!(read("X.EXE-00000000.pf", &[]), Err(Error::NeverWritten));
    }

    #[test]
    fn other_bytes_fail_loudly() {
        let Err(Error::Bad(e)) = read("X.EXE-00000000.pf", &[0x41; 300]) else {
            panic!("not a Prefetch file")
        };
        assert!(e.contains("signature"), "{e}");
        // Shorter than the 64-byte header the parser reads first.
        assert!(matches!(
            read("X.EXE-00000000.pf", b"MAM\x04"),
            Err(Error::Bad(_))
        ));
    }
}
