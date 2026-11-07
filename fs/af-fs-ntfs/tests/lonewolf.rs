//! I14's check on LoneWolf (the shared-folder copy, see `xtask/evidence.tsv`): the SYSTEM hive,
//! whose initialized size is below its size, hashes as TSK's `icat` gives it, and the bytes the
//! disk still holds past the initialized size are reachable as a stream of their own. Skips when
//! the image is missing.

use af_core::bytes::{ByteSource, Locator};
use af_core::fs::{FileSystem, FsVolume, StreamName};
use af_core::path::{Name, NameKind, ViewPath};
use af_core::system::VolumeId;
use af_fs_ntfs::Ntfs;
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
