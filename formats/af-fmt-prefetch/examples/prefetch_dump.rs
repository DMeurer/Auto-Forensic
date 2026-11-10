//! X1: one JSON line per Prefetch file, in the form of stage 1's `pf_dump`, for comparison with
//! PECmd (`t4_prefetch_compare.py`). Usage: `cargo run --release -p af-fmt-prefetch --example
//! prefetch_dump FILE.pf... > out.jsonl`

use std::io::Write;

fn main() {
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for path in std::env::args().skip(1) {
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let line = match af_fmt_prefetch::read(&name, &data) {
            Ok(pf) => serde_json::json!({
                "file": name, "ok": true, "version": pf.version, "name": pf.name,
                "run_count": pf.run_count, "last_run_filetimes": pf.run_times,
                "files_loaded": pf.files,
                "volumes": pf.volumes.iter().map(|v| serde_json::json!({
                    "device": v.device_path, "serial": format!("{:08X}", v.serial),
                    "created_filetime": v.created, "directories": v.directories.len()})).collect::<Vec<_>>(),
            }),
            Err(e) => serde_json::json!({"file": name, "ok": false, "error": e.to_string(),
                "never_written": e == af_fmt_prefetch::Error::NeverWritten}),
        };
        writeln!(out, "{line}").unwrap();
    }
}
