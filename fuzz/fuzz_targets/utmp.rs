#![no_main]
//! Linux login records (O4).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Some(size) = af_fmt_utmp::detect_size(data) {
        let _ = af_fmt_utmp::records(data, size);
    }
    let _ = af_fmt_utmp::records(data, 384);
});
