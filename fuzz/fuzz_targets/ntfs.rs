#![no_main]
//! NTFS: the boot sector, the MFT and every record, then a walk.
#[path = "common.rs"]
mod common;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(fs) = af_fs_ntfs::Ntfs::open(common::source(data)) {
        common::walk(&fs);
    }
});
