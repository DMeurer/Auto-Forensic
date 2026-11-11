//! B1: one JSON line per row of a Chromium `History` or Firefox `places.sqlite`, for comparison
//! with SQLECmd (`b1_compare.py`). Usage: `cargo run --release -p af-fmt-browser --example
//! browser_dump DB... > out.jsonl`

use std::io::Write;

fn main() {
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut line = |kind: &str, v: serde_json::Value| {
            writeln!(
                out,
                "{}",
                serde_json::json!({"file": path, "kind": kind, "row": v})
            )
            .unwrap();
        };
        if path.ends_with("places.sqlite") {
            let f = af_fmt_browser::firefox(&data).unwrap_or_else(|e| panic!("{path}: {e}"));
            for v in f.visits {
                line(
                    "visit",
                    serde_json::json!({"id": v.visit_id, "time": v.time, "url": v.url}),
                );
            }
            for b in f.bookmarks {
                line(
                    "bookmark",
                    serde_json::json!({"id": b.id, "parent": b.parent, "type": b.kind,
                    "title": b.title, "url": b.url, "added": b.added, "modified": b.modified,
                    "position": b.position, "fk": b.place_id}),
                );
            }
            for g in f.gaps {
                line(
                    "gap",
                    serde_json::json!({"table": g.table, "from": g.from, "to": g.to}),
                );
            }
        } else {
            let h = af_fmt_browser::chromium(&data).unwrap_or_else(|e| panic!("{path}: {e}"));
            for v in h.visits {
                line(
                    "visit",
                    serde_json::json!({"id": v.visit_id, "time": v.time,
                    "from": v.from_visit, "duration_us": v.duration_us, "url_id": v.url_id,
                    "url": v.url, "title": v.title, "visit_count": v.visit_count,
                    "typed_count": v.typed_count, "hidden": v.hidden, "last_visit": v.last_visit}),
                );
            }
            for d in h.downloads {
                line(
                    "download",
                    serde_json::json!({"id": d.id, "guid": d.guid,
                    "current_path": d.current_path, "target_path": d.target_path,
                    "received": d.received_bytes, "total": d.total_bytes, "start": d.start,
                    "end": d.end, "state": d.state, "url_chain": d.url_chain, "referrer": d.referrer,
                    "tab_url": d.tab_url, "mime": d.mime_type}),
                );
            }
            for s in h.searches {
                line(
                    "search",
                    serde_json::json!({"keyword_id": s.keyword_id, "url_id": s.url_id,
                    "term": s.term, "url": s.url, "title": s.title, "last_visit": s.last_visit}),
                );
            }
            for g in h.gaps {
                line(
                    "gap",
                    serde_json::json!({"table": g.table, "from": g.from, "to": g.to}),
                );
            }
        }
    }
}
