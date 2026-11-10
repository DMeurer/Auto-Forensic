//! X3: one JSON line per shortcut file, for comparison with LECmd (`x3_compare.py`).
//! Usage: `cargo run --release -p af-fmt-lnk --example lnk_dump FILE.lnk... > out.jsonl`

use std::io::Write;

fn main() {
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let line = match af_fmt_lnk::read(&data) {
            Ok(l) => serde_json::json!({
                "file": path, "ok": true, "created": l.created, "accessed": l.accessed,
                "modified": l.modified, "size": l.size, "attributes": l.attributes,
                "drive_type": l.volume.as_ref().map(|v| v.drive_type),
                "serial": l.volume.as_ref().map(|v| format!("{:08X}", v.serial)),
                "label": l.volume.as_ref().and_then(|v| v.label.clone()),
                "local_path": l.local_path, "common_path": l.common_path,
                "net_name": l.network.as_ref().and_then(|n| n.net_name.clone()),
                "device_name": l.network.as_ref().and_then(|n| n.device_name.clone()),
                "name": l.name, "relative_path": l.relative_path, "working_dir": l.working_dir,
                "arguments": l.arguments, "icon_location": l.icon_location,
                "target_mft": l.target_mft, "environment": l.environment,
                "machine_id": l.tracker.as_ref().map(|t| t.machine_id.clone()),
                "mac": l.tracker.as_ref().and_then(|t| t.mac.clone()),
                "droid_created": l.tracker.as_ref().and_then(|t| t.droid_created),
                "volume_droid": l.tracker.as_ref().map(|t| t.volume_droid.clone()),
                "file_droid": l.tracker.as_ref().map(|t| t.file_droid.clone()),
                "volume_droid_birth": l.tracker.as_ref().map(|t| t.volume_droid_birth.clone()),
                "file_droid_birth": l.tracker.as_ref().map(|t| t.file_droid_birth.clone()),
            }),
            Err(e) => serde_json::json!({"file": path, "ok": false, "error": e}),
        };
        writeln!(out, "{line}").unwrap();
    }
}
