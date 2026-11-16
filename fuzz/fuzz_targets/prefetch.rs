#![no_main]
//! Prefetch files: the wrapper on our frnsc-prefetch fork (O4), with and without MAM compression.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = af_fmt_prefetch::read("CMD.EXE-6D6290C5.pf", data);
});
