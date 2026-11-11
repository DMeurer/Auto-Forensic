//! B1 on the exam image's browser databases, copied out in stage 0 (`~/af-stage0/extract`):
//! its SYSTEM hive and the `Users` folders with Chrome, Edge, WebView2 and Tor Browser, laid out
//! as a Windows folder, so the Windows profile finds them. Skipped where the copies aren't.
//! SQLECmd agrees with every visit, download, search and bookmark
//! (`~/af-stage3/scripts/b1_compare.py`).

use std::path::Path;
use std::process::Command;

fn af(args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_af"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "af {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().map(Result::unwrap) {
        let (f, t) = (e.path(), to.join(e.file_name()));
        if f.is_dir() {
            copy(&f, &t);
        } else {
            std::fs::copy(&f, &t).unwrap();
        }
    }
}

#[test]
fn exam_browser_history() {
    let stage0 = Path::new(&std::env::var_os("HOME").unwrap_or_default()).join("af-stage0/extract");
    let (users, system) = (stage0.join("browser/Users"), stage0.join("hives/SYSTEM"));
    if !users.is_dir() || !system.is_file() {
        return;
    }
    let parent = std::env::temp_dir().join(format!("af-exam-browser-{}", std::process::id()));
    let disk = parent.join("disk");
    copy(&users, &disk.join("Users"));
    let config = disk.join("Windows/System32/config");
    std::fs::create_dir_all(&config).unwrap();
    for f in ["SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2"] {
        std::fs::copy(stage0.join("hives").join(f), config.join(f)).unwrap();
    }
    let case = parent.join("case");
    let c = case.to_str().unwrap();
    af(&["project", "new", c]);
    af(&["source", "add", c, disk.to_str().unwrap()]);
    af(&["run", c]);
    let status = af(&["status", c]);

    let db = duckdb::Connection::open_with_flags(
        case.join("project.duckdb"),
        duckdb::Config::default()
            .access_mode(duckdb::AccessMode::ReadOnly)
            .unwrap(),
    )
    .unwrap();
    let kinds: Vec<(String, i64)> = db
        .prepare(
            "SELECT kind, count(*) FROM events WHERE created_by = 'browser.history' \
             GROUP BY 1 ORDER BY 1",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let want = [
        ("browser.bookmark.added", 15),
        ("browser.bookmark.modified", 15),
        ("browser.download.finished", 2),
        ("browser.download.started", 2),
        ("browser.search", 2),
        // 25 Chrome, 8 Edge, 5 WebView2; Tor Browser kept none.
        ("browser.visit", 38),
    ];
    assert_eq!(kinds, want.map(|(k, n)| (k.to_string(), n)), "{status}");
    // The three Chromium journals hold pages not merged in; the Tor WAL is empty.
    assert_eq!(
        status
            .lines()
            .filter(|l| l.contains("not merged into its database"))
            .count(),
        3,
        "{status}"
    );
    // Edge's URL rows 1 to 13 and visit rows 1 to 20 expired.
    let gaps: Vec<String> = db
        .prepare("SELECT subject FROM facts WHERE kind = 'browser.history.gap' ORDER BY 1")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(gaps, ["urls 1-13", "visits 1-20"]);
    // Stage 0's "what was the machine used for": the searches and the DocForge24 visits.
    let (term, docforge): (String, i64) = db
        .query_row(
            "SELECT (SELECT max(json_extract_string(attrs, '$.term')) FROM records \
                 WHERE kind = 'browser.search'), \
             (SELECT count(*) FROM records WHERE kind = 'browser.visit' \
                 AND (attrs LIKE '%192.168.2.57%' OR lower(attrs) LIKE '%docforge%'))",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((term.as_str(), docforge), ("dokumentenfälschung strafe", 9));
    std::fs::remove_dir_all(&parent).unwrap();
}
