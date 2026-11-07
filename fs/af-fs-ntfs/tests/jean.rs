//! I13's check on Jean (M57, `cargo xtask evidence fetch jean`): five files hash as TSK's
//! `icat` gives them, and the whole volume passes af-core's file system check. Skips when the
//! image is missing.

use af_core::bytes::{ByteSource, Locator};
use af_core::fs::{FileSystem, FsVolume, StreamName, check, paths};
use af_core::path::{Name, NameKind};
use af_core::system::{VolumeId, VolumeProbe};
use af_fs_ntfs::Ntfs;
use std::path::PathBuf;
use std::sync::Arc;

fn jean() -> Option<Ntfs> {
    let dir =
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("af-stage3/evidence/jean");
    let files = vec![dir.join("nps-2008-jean.E01"), dir.join("nps-2008-jean.E02")];
    if !files.iter().all(|f| f.is_file()) {
        return None;
    }
    let img: Arc<dyn ByteSource> =
        Arc::from(af_host::ewf::open_image(&files, Locator::root("source.image", "jean")).unwrap());
    let vol = af_host::volumes::list(img).unwrap();
    let ntfs = vol.volumes.iter().find(|v| v.id == "1").unwrap();
    Some(Ntfs::open(ntfs.view.clone()).unwrap())
}

fn sha256(src: &dyn ByteSource) -> String {
    af_host::ewf::sha256_of(src).unwrap()
}

/// Expected hashes from `icat -i ewf -o 63 nps-2008-jean.E01 <inode>-128-<id> | sha256sum`.
#[test]
fn five_files_hash_like_tsk() {
    let Some(fs) = jean() else { return };
    let v = FsVolume {
        id: VolumeId(1),
        fs: &fs,
    };
    let p = |s: &str| {
        af_core::path::ViewPath::new(
            s.split('/')
                .map(|n| Name::from_text(n, NameKind::Utf16))
                .collect(),
        )
    };
    for (path, stream, want) in [
        // A hive whose initialized size (3,874,816) is below its size (3,932,160).
        (
            "WINDOWS/system32/config/system",
            None,
            "d7e65edc2e6cceab2a00dbb4ab994f6ffec47b50295c4bc1e23bb0fa75bd28b3",
        ),
        (
            "Documents and Settings/Jean/NTUSER.DAT",
            None,
            "2fc68060b97f4c67d1c668cf3af97543fc32c1226cfacbac9fe1260728b409e4",
        ),
        (
            "Documents and Settings/Jean/Desktop/m57biz.xls",
            None,
            "34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f",
        ),
        // Resident data.
        (
            "Documents and Settings/Jean/Application Data/desktop.ini",
            None,
            "ec097199b6931ee3facc515eba14be947cb78b98bccef84c57cc6c4cc85419db",
        ),
        // An alternate data stream.
        (
            "Documents and Settings/Administrator/Desktop/install_flash_player.exe",
            Some("Zone.Identifier"),
            "eacd09517ce90d34ba562171d15ac40d302f0e691b439f91be1b6406e25f5913",
        ),
    ] {
        let id = v
            .lookup(&p(path))
            .unwrap_or_else(|| panic!("{path} not found"));
        let s = match stream {
            None => StreamName::Default,
            Some(n) => StreamName::Named(Name::from_text(n, NameKind::Utf16)),
        };
        let src = fs.open(&id, &s).unwrap().expect("stream opens");
        assert_eq!(sha256(&*src), want, "{path}");
        let e = fs.entry(&id).unwrap().unwrap();
        let shown: Vec<String> = paths(&fs, &e)
            .unwrap()
            .iter()
            .map(|p| p.display())
            .collect();
        assert!(
            shown
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&format!("/{path}"))),
            "{shown:?}"
        );
    }
    assert!(
        v.exists(&p("windows/SYSTEM32/config/SOFTWARE")),
        "case-insensitive"
    );
}

/// The whole volume keeps the interface's promises. Slow in a debug build; run with --ignored.
#[test]
#[ignore = "walks all of Jean's MFT"]
fn jean_passes_the_file_system_check() {
    let Some(fs) = jean() else { return };
    let r = check(&fs).unwrap();
    eprintln!(
        "{} entries, {} deleted, {} unreadable",
        r.entries,
        r.deleted,
        r.unreadable.len()
    );
    for u in &r.unreadable {
        eprintln!("unreadable: {u}");
    }
    assert!(
        r.problems.is_empty(),
        "{:#?}",
        &r.problems[..r.problems.len().min(20)]
    );
}
