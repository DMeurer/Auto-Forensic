#![no_main]
//! The change journal: `ntfs-core`'s reader through our wrapper, then the path rewind (O4).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(records) = af_fmt_usn::read(std::io::Cursor::new(data)) else { return };
    let records: Vec<_> = records.take(10_000).filter_map(Result::ok).collect();
    let _ = af_fmt_usn::parent_paths(&records, af_fmt_usn::Names::new((5, 5)));
});
