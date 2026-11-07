//! Archives made by real tools (Python's `zipfile`, the system `tar`) read back with the same
//! bytes, and passing the file system check. Each test skips when its tool is missing.

use af_core::bytes::{ByteSource, Locator, MemSource};
use af_core::fs::{FileSystem, FsVolume, StreamName, check};
use af_core::path::{Name, ViewPath};
use af_core::system::VolumeId;
use af_fs_archive::Archive;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

/// Files of a small Windows-like tree: compressible, incompressible, empty, a path over tar's
/// 100-byte name field, and (with `wide`) a name that isn't ASCII.
fn sample(wide: bool) -> Vec<(String, Vec<u8>)> {
    let mut noise = Vec::new();
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..70_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        noise.push(x as u8);
    }
    let mut files = vec![
        (
            "Windows/System32/config/SYSTEM".to_string(),
            b"regf".repeat(25_000),
        ),
        ("Users/admin/NTUSER.DAT".to_string(), noise),
        ("empty.txt".to_string(), vec![]),
        (
            format!("{}/{}/deep.txt", "a".repeat(60), "b".repeat(60)),
            b"long path".to_vec(),
        ),
    ];
    if wide {
        files.push(("Users/admin/café.txt".to_string(), b"not ascii".to_vec()));
    }
    files
}

fn write_tree(root: &Path, files: &[(String, Vec<u8>)]) {
    for (p, data) in files {
        std::fs::create_dir_all(root.join(p).parent().unwrap()).unwrap();
        std::fs::write(root.join(p), data).unwrap();
    }
}

fn read_back(archive: &Path, files: &[(String, Vec<u8>)], want_kind: &str) {
    let src: Arc<dyn ByteSource> = Arc::new(MemSource::new(
        std::fs::read(archive).unwrap(),
        Locator::root("source.archive", "t"),
    ));
    let fs = Archive::open(src).unwrap();
    assert_eq!(fs.info().kind.as_str(), want_kind);
    let report = check(&fs).unwrap();
    assert!(report.problems.is_empty(), "{:#?}", report.problems);
    let vol = FsVolume {
        id: VolumeId(1),
        fs: &fs,
    };
    for (p, data) in files {
        let path = ViewPath::new(
            p.split('/')
                .map(|n| Name::from_bytes(n.as_bytes()))
                .collect(),
        );
        let id = vol.lookup(&path).unwrap_or_else(|| panic!("{p} not found"));
        let s = fs.open(&id, &StreamName::Default).unwrap().expect("data");
        let mut got = vec![0; s.len() as usize];
        s.read_exact_at(0, &mut got).unwrap();
        assert!(got == *data, "{p}: other bytes");
    }
}

fn python() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|p| {
        Command::new(p)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// Deflated and stored members, an explicit folder entry, and ZIP64 records forced by lowering
/// the module's limit, so the 64-bit fields are read without a 4 GiB file.
const MAKE_ZIP: &str = r#"
import os, sys, zipfile
zipfile.ZIP64_LIMIT = 10
out, root = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w") as z:
    z.writestr(zipfile.ZipInfo("Windows/"), b"")
    for d, _, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            arc = os.path.relpath(p, root).replace(os.sep, "/")
            info = zipfile.ZipInfo(arc)
            info.compress_type = zipfile.ZIP_STORED if n == "NTUSER.DAT" else zipfile.ZIP_DEFLATED
            with open(p, "rb") as src, z.open(info, "w", force_zip64=True) as dst:
                dst.write(src.read())
"#;

#[test]
fn a_python_zip_with_zip64_reads_back() {
    let Some(py) = python() else { return };
    let d = tempfile::tempdir().unwrap();
    let files = sample(true);
    write_tree(&d.path().join("tree"), &files);
    let zip = d.path().join("t.zip");
    let ok = Command::new(py)
        .args(["-I", "-c", MAKE_ZIP])
        .arg(&zip)
        .arg(d.path().join("tree"))
        .status()
        .unwrap();
    assert!(ok.success());
    read_back(&zip, &files, "fs.zip");
}

#[test]
fn tars_in_gnu_and_pax_format_read_back() {
    let d = tempfile::tempdir().unwrap();
    // The non-ASCII name only where tar keeps names as bytes.
    let files = sample(cfg!(unix));
    write_tree(&d.path().join("tree"), &files);
    for format in ["gnu", "pax"] {
        let tar = d.path().join(format!("{format}.tar"));
        let Ok(st) = Command::new("tar")
            .arg(format!("--format={format}"))
            .arg("-cf")
            .arg(&tar)
            .arg("-C")
            .arg(d.path().join("tree"))
            .arg(".")
            .status()
        else {
            return;
        };
        assert!(st.success(), "tar --format={format}");
        read_back(&tar, &files, "fs.tar");
    }
}

#[test]
fn other_bytes_are_neither() {
    let src: Arc<dyn ByteSource> = Arc::new(MemSource::new(
        vec![7; 4096],
        Locator::root("source.archive", "t"),
    ));
    assert!(Archive::open(src).is_err());
}
