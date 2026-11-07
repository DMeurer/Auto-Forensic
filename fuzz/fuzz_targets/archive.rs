#![no_main]
//! Zip and tar parsing, then a walk of what was found.
#[path = "common.rs"]
mod common;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(fs) = af_fs_archive::Archive::open(common::source(data)) {
        common::walk(&fs);
    }
});
