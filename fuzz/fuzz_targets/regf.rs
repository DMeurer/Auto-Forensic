#![no_main]
//! Hives: the own root-key reader and the notatin reader, walked a few levels deep.

fn walk(h: &mut af_fmt_regf::hive::Hive, path: String, depth: u32, budget: &mut u32) {
    let Some(k) = h.key(&path) else { return };
    for s in k.subkeys {
        if depth == 0 || *budget == 0 {
            return;
        }
        *budget -= 1;
        let p = if path.is_empty() { s } else { format!("{path}\\{s}") };
        walk(h, p, depth - 1, budget);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = af_fmt_regf::root_subkey_names(data);
    let _ = af_fmt_regf::root_last_written(data);
    if let Ok(mut h) = af_fmt_regf::hive::Hive::open(data.to_vec(), vec![]) {
        walk(&mut h, String::new(), 4, &mut 500);
    }
});
