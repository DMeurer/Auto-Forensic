//! I14's check on LoneWolf (the shared-folder copy, see `xtask/evidence.tsv`): the SYSTEM hive,
//! whose initialized size is below its size, hashes as TSK's `icat` gives it, and the bytes the
//! disk still holds past the initialized size are reachable as a stream of their own. Skips when
//! the image is missing.

use af_core::bytes::{ByteSource, Locator};
use af_core::fs::{FileSystem, FsVolume, StreamName, paths};
use af_core::path::{Name, NameKind, ViewPath};
use af_core::system::VolumeId;
use af_fs_ntfs::Ntfs;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

fn lonewolf() -> Option<Ntfs> {
    let dir = PathBuf::from("/mnt/hgfs/VM_sharedFolder/DF/various/LoneWolf");
    let files: Vec<_> = (1..=9)
        .map(|i| dir.join(format!("LoneWolf.E{i:02}")))
        .collect();
    if !files.iter().all(|f| f.is_file()) {
        return None;
    }
    let img: Arc<dyn ByteSource> = Arc::from(
        af_host::ewf::open_image(&files, Locator::root("source.image", "lonewolf")).unwrap(),
    );
    let vol = af_host::volumes::list(img).unwrap();
    let ntfs = vol.volumes.iter().find(|v| v.id == "4").unwrap();
    Some(Ntfs::open(ntfs.view.clone()).unwrap())
}

/// `icat -o 1259520 LoneWolf.E0? 89229 | sha256sum` for the hive. For the stale bytes,
/// `istat -r` gives runs of 3,072 clusters at 1432898 and 64 at 5385156, size 12,845,056 and
/// initialized size 12,402,688, so they are `blkcat … 1435926 44` then `blkcat … 5385156 64`.
#[test]
fn system_hashes_like_tsk_and_its_stale_bytes_stay_reachable() {
    let Some(fs) = lonewolf() else { return };
    let v = FsVolume {
        id: VolumeId(4),
        fs: &fs,
    };
    let path = ViewPath::new(
        ["Windows", "System32", "config", "SYSTEM"]
            .map(|n| Name::from_text(n, NameKind::Utf16))
            .to_vec(),
    );
    let id = v.lookup(&path).expect("SYSTEM found");
    let hash = |s: &StreamName| {
        let src = fs.open(&id, s).unwrap().expect("stream opens");
        (src.len(), af_host::ewf::sha256_of(&*src).unwrap())
    };
    assert_eq!(
        hash(&StreamName::Default),
        (
            12_845_056,
            "9154e260abdc4ac206ef9d872dd4e1add0150b869bda5b112944af2ff5ec39b4".into()
        )
    );
    assert_eq!(
        hash(&StreamName::Stale(None)),
        (
            442_368,
            "aff97a00a7ed0eb4fd05ebb19be04077d320afbecf488e64d88651ac1800e4c0".into()
        )
    );
    let e = fs.entry(&id).unwrap().unwrap();
    let stale = e
        .streams
        .iter()
        .find(|s| s.name == StreamName::Stale(None))
        .expect("listed");
    assert_eq!(
        (stale.kind.as_str(), stale.size),
        ("ntfs.stale_bytes", 442_368)
    );
}

/// I15: every in-use path matches TSK's `fls -r -p` listing, so no 8.3 name stands in for a
/// long one. The listing was saved in stage 1 to `~/af-stage1/lonewolf/fls.txt` (course data,
/// kept out of the repository). Slow: a full MFT walk.
#[test]
#[ignore]
fn in_use_paths_match_fls() {
    let Some(fs) = lonewolf() else { return };
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let Ok(text) = std::fs::read_to_string(home.join("af-stage1/lonewolf/fls.txt")) else {
        return;
    };
    let mut tsk = BTreeSet::new();
    for line in text.lines() {
        let Some((head, path)) = line.split_once(":\t") else {
            continue;
        };
        // Deleted names and TSK's orphan folder belong to I20. So do `r/-` lines, with no
        // attribute id: a live folder index entry whose record now holds another file.
        let addr = head.rsplit(' ').next().unwrap();
        if head.contains(" * ") || path.starts_with("$OrphanFiles") || !addr.contains('-') {
            continue;
        }
        // `file:stream` lines also vouch for the file: `$Secure` has only named streams.
        let path = match path.rsplit_once('/') {
            Some((dir, last)) => format!("{dir}/{}", last.split(':').next().unwrap()),
            None => path.split(':').next().unwrap().to_string(),
        };
        if path.ends_with("/.") {
            continue; // TSK lists a folder's streams a second time under its own `.` entry
        }
        let rec = addr.split('-').next().unwrap();
        tsk.insert((rec.parse::<u64>().unwrap(), format!("/{path}")));
    }
    let mut ours = BTreeSet::new();
    for e in fs.all() {
        let Ok(e) = e else { continue };
        if !e.allocated {
            continue;
        }
        let rec = u64::from_le_bytes(e.id.value[..8].try_into().unwrap()) & ((1 << 48) - 1);
        for p in paths(&fs, &e).unwrap() {
            let shown = p.display();
            if !p.orphan && shown != "/" {
                ours.insert((rec, shown));
            }
        }
    }
    let missing: Vec<_> = tsk.difference(&ours).collect();
    let extra: Vec<_> = ours.difference(&tsk).collect();
    // Folder 102511's index still points TransportSecurity at record 141267 with sequence 6,
    // but the record is now at sequence 11 and names that folder itself. TSK lists the stale
    // index entry (`r/-`); paths here come from the record. Stale index entries are I20.
    let known = (
        141_267,
        "/Users/jcloudy/AppData/Local/Google/Chrome/User Data/Default/TransportSecurity"
            .to_string(),
    );
    assert!(
        missing.is_empty() && extra == [&known],
        "{} of {} TSK paths missing, e.g. {:?}\n{} extra of {}, e.g. {:?}",
        missing.len(),
        tsk.len(),
        &missing[..missing.len().min(10)],
        extra.len(),
        ours.len(),
        &extra[..extra.len().min(10)],
    );
}

/// I18: compressed and sparse files, and data spread over extension records through
/// `$ATTRIBUTE_LIST`, hash as `icat -o 1259520 LoneWolf.E0? <record>` gives them.
#[test]
fn compressed_sparse_and_split_files_hash_like_tsk() {
    let Some(fs) = lonewolf() else { return };
    let v = FsVolume {
        id: VolumeId(4),
        fs: &fs,
    };
    for (path, size, want) in [
        // Compressed, data in 21 records (119439).
        (
            "Windows/System32/MRT-KB890830.exe",
            130_364_688,
            "3b13eb5aaaf0c00a51fa15f00c0b9f26cf647e1a56149054a718088d13484b74",
        ),
        // Compressed, data in 13 records (140400).
        (
            "ProgramData/Microsoft/Windows Defender/Scans/mpcache-A7681A9F04346C1C183D81FD7DB04EEFC86EC685.bin.79",
            64_765_952,
            "36ecefa0d316a86d7acf4034ef5627516999df5b23135f50952a8c2cf81536c8",
        ),
        // Compressed, one record (34964).
        (
            "Windows/Logs/CBS/CBS.log",
            7_742_753,
            "eecf0971ca30510899414eb0153ec41a08852e3af6768d42a0136e1d04ac9b2c",
        ),
        // Sparse, data in 2 records (92983).
        (
            "Windows/SoftwareDistribution/Download/c72d407696aad956229131246b7fc10a7c23905a",
            301_324_075,
            "a821fd8d64e13be1b507e8a5d3d1dcabf9a914e32f90bf46e7fbd6c5df770af3",
        ),
        // Sparse, data in 2 records (111776).
        (
            "Program Files (x86)/Microsoft Office/root/vfs/ProgramFilesCommonX86/Microsoft Shared/OFFICE16/MSORES.DLL",
            71_208_128,
            "b6392a4e6cd9db960e2f1113ca1f51778f667014d666dc37af47f4d47c98fe78",
        ),
        // Sparse and small (22238).
        (
            "Program Files (x86)/Microsoft Office/root/Templates/1033/TimeCard.xltx",
            17_663,
            "8d4ca2d0ed920ee81d6f102091edd06e9fe01f194c2942df25d91eb2c6fa96b9",
        ),
    ] {
        let p = ViewPath::new(
            path.split('/')
                .map(|n| Name::from_text(n, NameKind::Utf16))
                .collect(),
        );
        let id = v.lookup(&p).unwrap_or_else(|| panic!("{path} not found"));
        let src = fs.open(&id, &StreamName::Default).unwrap().expect("opens");
        assert_eq!(
            (src.len(), af_host::ewf::sha256_of(&*src).unwrap()),
            (size, want.to_string()),
            "{path}"
        );
    }
}
