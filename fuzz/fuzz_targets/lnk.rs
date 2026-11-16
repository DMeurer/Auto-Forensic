#![no_main]
//! Shortcuts: the own MS-SHLLINK reader (O4).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = af_fmt_lnk::read(data);
});
