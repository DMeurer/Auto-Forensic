//! I20's check on the generated NTFS stick (`cargo xtask fixtures ~/af-stage3/fixtures`, I2):
//! the two deleted files from its truth file are found through the MFT, unallocated. The Linux
//! driver that made the stick clears a deleted record's `$FILE_NAME`, so they have no name or
//! path left, and TSK lists neither name. Skips when the fixture is missing.

use af_core::bytes::{ByteSource, Locator};
use af_core::fs::{FileSystem, StreamName, paths};
use af_fs_ntfs::Ntfs;
use std::path::PathBuf;
use std::sync::Arc;

fn stick() -> Option<Ntfs> {
    let img = PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("af-stage3/fixtures/ntfs.img");
    if !img.is_file() {
        return None;
    }
    let src: Arc<dyn ByteSource> =
        Arc::from(af_host::ewf::open_image(&[img], Locator::root("source.image", "ntfs")).unwrap());
    let vol = af_host::volumes::list(src).unwrap();
    let whole = vol.volumes.iter().find(|v| v.id == "whole").unwrap();
    Some(Ntfs::open(whole.view.clone()).unwrap())
}

#[test]
fn the_known_deletions_appear_unallocated() {
    let Some(fs) = stick() else { return };
    let mut deleted = vec![];
    for e in fs.all() {
        let e = e.unwrap();
        if e.allocated {
            assert!(e.recovered.is_none());
            continue;
        }
        let p: Vec<String> = paths(&fs, &e)
            .unwrap()
            .iter()
            .map(|p| p.display())
            .collect();
        let src = fs.open(&e.id, &StreamName::Default).unwrap().expect("data");
        let hash = af_host::ewf::sha256_of(&*src).unwrap();
        deleted.push((
            p,
            e.recovered.map(|k| k.as_str().to_string()),
            src.len(),
            hash,
        ));
    }
    deleted.sort();
    let found = |size: u64| {
        deleted
            .iter()
            .find(|d| d.0.is_empty() && d.2 == size)
            .unwrap_or_else(|| panic!("no {size}-byte deleted file among {deleted:#?}"))
    };
    let unused = Some("ntfs.mft.unused_record".to_string());
    // Deleted, clusters not reused: the content is still the truth file's.
    let intact = found(200_000); // Geburtstag.jpg
    assert_eq!(
        (&intact.1, intact.2, intact.3.as_str()),
        (
            &unused,
            200_000,
            "9301ce18588cd797a861aa65703512608d82c8489d1e657b56f7ce4d80463f48"
        )
    );
    // Deleted, then its clusters went to `neu/später geschrieben.bin`: found, but the bytes
    // are no longer the photo.
    let gone = found(300_000); // Urlaub Foto am Strand.jpg
    assert_eq!((&gone.1, gone.2), (&unused, 300_000));
    assert_ne!(
        gone.3,
        "b467a5356681ee0e5ce95af8c97ccaa312652ecd38cb55c1e7800fc3baaf76b9"
    );
    assert_eq!(deleted.len(), 2, "{deleted:#?}");
}
