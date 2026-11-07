#![no_main]
//! Partition tables (MBR, GPT, nested) and content detection.
#[path = "common.rs"]
mod common;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = af_host::volumes::list(common::source(data));
});
