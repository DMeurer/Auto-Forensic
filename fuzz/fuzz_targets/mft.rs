#![no_main]
//! A loose `$MFT`: the `mft` crate through our wrapper, paths included (O4).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = af_fmt_mft::read(data.to_vec(), |_| {});
});
