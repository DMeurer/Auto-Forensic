//! L4 on the exam image's event logs and SYSTEM hive, copied out in stage 0
//! (`~/af-stage0/extract`), laid out as a Windows folder. Skipped where the copies aren't.

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
fn exam_sessions() {
    let stage0 = Path::new(&std::env::var_os("HOME").unwrap_or_default()).join("af-stage0/extract");
    let (logs, system) = (stage0.join("evtx"), stage0.join("hives/SYSTEM"));
    if !logs.is_dir() || !system.is_file() {
        return;
    }
    let parent = std::env::temp_dir().join(format!("af-exam-sessions-{}", std::process::id()));
    let disk = parent.join("disk");
    copy(&logs, &disk.join("Windows/System32/winevt/Logs"));
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

    let db = duckdb::Connection::open_with_flags(
        case.join("project.duckdb"),
        duckdb::Config::default()
            .access_mode(duckdb::AccessMode::ReadOnly)
            .unwrap(),
    )
    .unwrap();
    // Every one of the 21 logged-off sessions pairs with its logon; the only disconnect (24)
    // comes a second after a logoff. The last ends at the 09:10:03 logoff stage 0 found.
    let sessions: Vec<(String, String, String)> = db
        .prepare(
            "SELECT l.label, l.key, \
             strftime(make_timestamp(((a.ts - 116444736000000000) // 10)::BIGINT), '%m-%d %H:%M:%S') \
             || '-' || strftime(make_timestamp(((b.ts - 116444736000000000) // 10)::BIGINT), '%H:%M:%S') \
             FROM links l JOIN events a ON a.id = l.from_id JOIN events b ON b.id = l.to_id \
             WHERE l.created_by = 'windows.sessions' ORDER BY a.ts",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(sessions.len(), 21, "{sessions:#?}");
    assert!(sessions.iter().all(|s| s.0 == "session logged off"));
    assert_eq!(
        (&*sessions[0].1, &*sessions[0].2),
        (
            "session 1, DESKTOP-G2LNLED\\defaultuser0",
            "04-18 08:48:56-08:51:59"
        )
    );
    assert_eq!(
        (&*sessions[20].1, &*sessions[20].2),
        ("session 1, DESKTOP-G2LNLED\\ich", "09-08 09:08:05-09:10:03")
    );
    // The 309 process starts are SYSTEM's, at boot: no user logon has any.
    let groups: i64 = db
        .query_row(
            "SELECT count(*) FROM groups WHERE kind = 'windows.logon.processes'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(groups, 0);
    std::fs::remove_dir_all(&parent).unwrap();
}
