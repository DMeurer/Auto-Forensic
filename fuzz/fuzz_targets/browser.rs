#![no_main]
//! Browser databases: SQLite from bytes, Chromium and Firefox (O4).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = af_fmt_browser::chromium(data);
    let _ = af_fmt_browser::firefox(data);
});
