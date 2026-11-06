//! Folders on this machine as evidence (piece C0a): a hand-built Linux root, an exported
//! user profile, or loose files in a tree.
//!
//! A [`FolderVolume`] reads a folder in place, never copying or writing it. Names keep their raw
//! form: bytes on Linux and macOS, UTF-16 on Windows, so `Foo` and `foo` stay two files where
//! the file system keeps them apart, and a name that isn't valid UTF-8 round-trips to the same
//! bytes. Each file is a [`FileSource`], read by offset.

use af_core::bytes::{ByteSource, Locator, MapBack};
use af_core::path::{CasePolicy, Name, ViewPath};
use af_core::system::{VolumeId, VolumeProbe};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A folder read as a volume.
#[derive(Debug, Clone)]
pub struct FolderVolume {
    pub id: VolumeId,
    pub root: PathBuf,
}

/// One file found in a folder: its path below the root and where it lies on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderFile {
    pub path: ViewPath,
    pub on_disk: PathBuf,
    pub size: u64,
}

impl FolderVolume {
    pub fn new(id: VolumeId, root: &Path) -> Self {
        Self {
            id,
            root: root.to_path_buf(),
        }
    }

    /// Every regular file below the root, sorted by path. Symbolic links are listed as links
    /// would be on the evidence, not followed, so a link can't lead outside the folder.
    pub fn files(&self) -> io::Result<Vec<FolderFile>> {
        let mut out = Vec::new();
        let mut stack = vec![(self.root.clone(), ViewPath::default())];
        while let Some((dir, path)) = stack.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                let child = path.join(name_of(&entry.file_name()));
                if kind.is_dir() {
                    stack.push((entry.path(), child));
                } else if kind.is_file() {
                    out.push(FolderFile {
                        path: child,
                        on_disk: entry.path(),
                        size: entry.metadata()?.len(),
                    });
                }
            }
        }
        out.sort_by(|a, b| a.on_disk.cmp(&b.on_disk));
        Ok(out)
    }

    /// The path on this machine for a path below the root.
    pub fn on_disk(&self, path: &ViewPath) -> Option<PathBuf> {
        let mut p = self.root.clone();
        for n in path.names() {
            p.push(os_name(n)?);
        }
        Some(p)
    }

    /// A file below the root as a byte source.
    pub fn open(&self, path: &ViewPath, locator: Locator) -> io::Result<FileSource> {
        let p = self
            .on_disk(path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name not usable here"))?;
        FileSource::open(&p, locator)
    }
}

impl VolumeProbe for FolderVolume {
    fn id(&self) -> VolumeId {
        self.id
    }
    fn exists(&self, path: &ViewPath) -> bool {
        // The host file system decides about case, as it would for the original system.
        self.on_disk(path)
            .is_some_and(|p| p.symlink_metadata().is_ok())
    }
    fn label(&self) -> Option<String> {
        self.root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
    }
    fn read(&self, path: &ViewPath) -> Option<Vec<u8>> {
        self.on_disk(path).and_then(|p| std::fs::read(p).ok())
    }
    fn case(&self) -> CasePolicy {
        if cfg!(any(windows, target_os = "macos")) {
            CasePolicy::Insensitive
        } else {
            CasePolicy::Exact
        }
    }
}

#[cfg(unix)]
fn name_of(n: &std::ffi::OsStr) -> Name {
    use std::os::unix::ffi::OsStrExt;
    Name::from_bytes(n.as_bytes())
}

#[cfg(windows)]
fn name_of(n: &std::ffi::OsStr) -> Name {
    use std::os::windows::ffi::OsStrExt;
    Name::Utf16(n.encode_wide().collect())
}

/// A name as this host's file system wants it, if it can hold it.
#[cfg(unix)]
fn os_name(n: &Name) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;
    match n {
        Name::Bytes(b) => Some(std::ffi::OsString::from_vec(b.clone())),
        Name::Utf16(u) => String::from_utf16(u).ok().map(Into::into),
    }
}

#[cfg(windows)]
fn os_name(n: &Name) -> Option<std::ffi::OsString> {
    use std::os::windows::ffi::OsStringExt;
    match n {
        Name::Utf16(u) => Some(std::ffi::OsString::from_wide(u)),
        Name::Bytes(b) => std::str::from_utf8(b).ok().map(Into::into),
    }
}

/// A file on this machine as a top-level byte source.
pub struct FileSource {
    file: Mutex<File>,
    len: u64,
    locator: Locator,
}

impl FileSource {
    pub fn open(path: &Path, locator: Locator) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            len,
            locator,
        })
    }
}

impl ByteSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let mut f = self
            .file
            .lock()
            .map_err(|_| io::Error::other("file lock poisoned"))?;
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
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
    use af_core::path::NameKind;

    /// A hand-built Linux root, as the canary uses.
    fn linux_root() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        for (p, data) in [
            (
                "etc/os-release",
                &b"NAME=\"Debian GNU/Linux\"\nID=debian\n"[..],
            ),
            ("etc/hostname", b"logserver\n"),
            ("etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n"),
            ("var/log/wtmp", &[0u8; 384][..]),
            ("home/Foo", b"upper"),
        ] {
            std::fs::create_dir_all(r.join(p).parent().unwrap()).unwrap();
            std::fs::write(r.join(p), data).unwrap();
        }
        d
    }

    fn vp(text: &str) -> ViewPath {
        ViewPath::new(
            text.split('/')
                .map(|n| Name::from_text(n, native()))
                .collect(),
        )
    }

    fn native() -> NameKind {
        if cfg!(windows) {
            NameKind::Utf16
        } else {
            NameKind::Bytes
        }
    }

    #[test]
    fn lists_and_reads_a_folder_in_place() {
        let root = linux_root();
        let vol = FolderVolume::new(VolumeId(1), root.path());
        let files = vol.files().unwrap();
        let paths: Vec<String> = files
            .iter()
            .map(|f| {
                f.path.display(af_core::path::PathStyle {
                    separator: '/',
                    case: CasePolicy::Exact,
                })
            })
            .collect();
        assert_eq!(
            paths,
            [
                "/etc/hostname",
                "/etc/os-release",
                "/etc/passwd",
                "/home/Foo",
                "/var/log/wtmp"
            ]
        );
        assert!(vol.exists(&vp("etc/os-release")));
        let src = vol
            .open(&vp("etc/hostname"), Locator::root("source.folder", "test"))
            .unwrap();
        let mut buf = vec![0; src.len() as usize];
        src.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(buf, b"logserver\n");
        assert_eq!(
            files
                .iter()
                .find(|f| f.path == vp("var/log/wtmp"))
                .unwrap()
                .size,
            384
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn foo_and_foo_stay_two_files_and_raw_names_round_trip() {
        use std::os::unix::ffi::OsStrExt;
        let root = linux_root();
        std::fs::write(root.path().join("home/foo"), b"lower").unwrap();
        let weird = std::ffi::OsStr::from_bytes(b"caf\xe9.txt");
        std::fs::write(root.path().join("home").join(weird), b"latin-1 name").unwrap();
        let vol = FolderVolume::new(VolumeId(1), root.path());
        assert_eq!(vol.case(), CasePolicy::Exact);
        let files = vol.files().unwrap();
        let home: Vec<&FolderFile> = files
            .iter()
            .filter(|f| f.path.names()[0] == Name::from_bytes(b"home"))
            .collect();
        assert_eq!(home.len(), 3);
        // The non-UTF-8 name comes back as the same bytes, and opens.
        let latin = home
            .iter()
            .find(|f| f.path.names()[1] == Name::from_bytes(b"caf\xe9.txt"))
            .unwrap();
        assert_eq!(latin.path.names()[1].display(), "caf\\xe9.txt");
        let src = vol
            .open(&latin.path, Locator::root("source.folder", "t"))
            .unwrap();
        assert_eq!(src.len(), 12);
        // Foo and foo are two files with their own content.
        for (name, data) in [("Foo", &b"upper"[..]), ("foo", b"lower")] {
            let p = vp(&format!("home/{name}"));
            let s = vol.open(&p, Locator::root("source.folder", "t")).unwrap();
            let mut b = vec![0; s.len() as usize];
            s.read_exact_at(0, &mut b).unwrap();
            assert_eq!(b, data);
        }
    }
}
