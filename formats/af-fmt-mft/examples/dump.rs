//! Every base record of an `$MFT` as tab-separated lines, for comparing with MFTECmd (M1, M4).
//! Usage: `cargo run --release -p af-fmt-mft --example dump MFT > out.tsv`

#![allow(clippy::print_stdout)]

fn main() {
    let file = std::env::args().nth(1).expect("an $MFT file");
    let bytes = std::fs::read(&file).unwrap_or_else(|e| panic!("{file}: {e}"));
    let summary = af_fmt_mft::read(bytes, |r| {
        let si = r.info.as_ref();
        let t = |f: fn(&af_fmt_mft::StandardInfo) -> u64| {
            si.map_or(String::new(), |s| f(s).to_string())
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.number,
            r.sequence,
            r.in_use,
            r.is_dir,
            r.path.as_deref().unwrap_or(""),
            r.size.map_or(String::new(), |s| s.to_string()),
            t(|s| s.created),
            t(|s| s.modified),
            t(|s| s.mft_modified),
            t(|s| s.accessed),
        );
    })
    .unwrap_or_else(|e| panic!("{file}: {e}"));
    eprintln!(
        "{} records, {} errors",
        summary.records,
        summary.errors.len()
    );
    for e in summary.errors.iter().take(20) {
        eprintln!("{e}");
    }
}
