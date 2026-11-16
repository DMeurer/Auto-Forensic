#![no_main]
//! Event logs: the `evtx` crate through our wrapper, and the own record-offset walk (O4).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = af_fmt_evtx::read(data.to_vec());
});
