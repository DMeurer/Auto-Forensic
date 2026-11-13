//! L4, L8 and L10 on the exam image's event logs and SYSTEM and SAM hives, copied out in stage 0
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
    for hive in ["SYSTEM", "SAM"] {
        for f in [
            hive.to_string(),
            format!("{hive}.LOG1"),
            format!("{hive}.LOG2"),
        ] {
            std::fs::copy(stage0.join("hives").join(&f), config.join(&f)).unwrap();
        }
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

    // L10: stage 0's r3. The four failed logons each followed by a success, both SAM values on
    // their events, 23 logoffs of logons that lasted longer than 10 s, the 38 that didn't in one
    // group per boot, and the 45 normal-and-elevated token pairs.
    let logons: Vec<(String, String, String)> = db
        .prepare(
            "SELECT l.label, \
             strftime(make_timestamp(((a.ts - 116444736000000000) // 10)::BIGINT), '%m-%d %H:%M:%S') \
             || '-' || strftime(make_timestamp(((b.ts - 116444736000000000) // 10)::BIGINT), '%H:%M:%S'), \
             coalesce(l.description, '') FROM links l JOIN events a ON a.id = l.from_id \
             JOIN events b ON b.id = l.to_id WHERE l.created_by = 'windows.logons' \
             AND l.label NOT IN ('user logged off', 'session ended') ORDER BY a.ts, l.label",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let want = [
        (
            "then logged on",
            "04-18 09:06:29-09:06:34",
            "5 s after the failed attempt",
        ),
        (
            "then logged on",
            "04-18 09:24:38-09:24:43",
            "5 s after the failed attempt",
        ),
        (
            "then logged on",
            "09-08 08:13:33-08:13:37",
            "4 s after the failed attempt",
        ),
        (
            "is SAM's last wrong password",
            "09-08 09:09:42-09:09:42",
            "SAM 09:09:42.573, event 09:09:42.641",
        ),
        (
            "then logged on",
            "09-08 09:09:42-09:09:48",
            "5 s after the failed attempt",
        ),
        (
            "is SAM's last logon",
            "09-08 09:09:48-09:09:48",
            "SAM 09:09:48.584, event 09:09:48.628",
        ),
    ];
    assert_eq!(
        logons,
        want.map(|(l, t, d)| (l.to_string(), t.to_string(), d.to_string()))
    );
    let counts: Vec<(String, i64, i64)> = db
        .prepare(
            "SELECT 'link ' || label, count(*), 0 FROM links WHERE created_by = 'windows.logons' \
             AND label IN ('user logged off', 'session ended') GROUP BY label \
             UNION ALL SELECT 'group ' || g.kind, count(DISTINCT g.id), count(*) FROM groups g \
             JOIN group_members m ON m.grp = g.id WHERE g.created_by = 'windows.logons' \
             GROUP BY g.kind ORDER BY 1",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let want = [
        ("group windows.logon.short", 18, 76),
        ("group windows.logon.tokens", 45, 90),
        ("link session ended", 2, 0),
        ("link user logged off", 21, 0),
    ];
    assert_eq!(counts, want.map(|(k, n, m)| (k.to_string(), n, m)));

    // L8: the stick (stage 0's rule r2). Its USB device and disk each link to their registry
    // times and to every log entry that names them: all 16 that mention it, one naming both.
    let (usb, disk) = (
        r"VID_ABCD&PID_1234\5&12c8f4c0&0&2",
        r"Disk&Ven_General&Prod_UDisk&Rev_5.00\6&1526ad36&0&_&0",
    );
    let stick: Vec<(String, String, i64)> = db
        .prepare(
            "SELECT f.kind, l.label, count(*) FROM links l JOIN facts f ON f.id = l.from_id \
             WHERE f.subject IN (?, ?) GROUP BY ALL ORDER BY 1, 2",
        )
        .unwrap()
        .query_map([usb, disk], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let want = [
        ("windows.usb_device", "first installed", 1),
        ("windows.usb_device", "installed", 1),
        ("windows.usb_device", "is storage of", 1),
        ("windows.usb_device", "last connected", 1),
        ("windows.usb_device", "named in log", 7),
        ("windows.usb_storage", "first installed", 1),
        ("windows.usb_storage", "installed", 1),
        ("windows.usb_storage", "last connected", 1),
        ("windows.usb_storage", "mounted as", 2),
        ("windows.usb_storage", "named in log", 10),
    ];
    assert_eq!(
        stick,
        want.map(|(k, l, n)| (k.to_string(), l.to_string(), n))
    );
    // The disk fact lists its connections, and a connection points back.
    let (fact, event): (u128, u128) = db
        .query_row(
            "SELECT l.from_id, l.to_id FROM links l JOIN facts f ON f.id = l.from_id \
             JOIN events e ON e.id = l.to_id WHERE f.subject = ? AND l.label = 'named in log' \
             ORDER BY e.ts LIMIT 1",
            [disk],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let explained = af(&["explain", c, &format!("{fact:x}")]);
    assert!(
        explained.starts_with(&format!(
            "fact windows.usb_storage  {fact:032x}\n  {disk}\n"
        )),
        "{explained}"
    );
    assert_eq!(
        explained.matches("\nnamed in log  -> ").count(),
        10,
        "{explained}"
    );
    assert!(
        explained.contains(&format!(
            "\nis storage of  <- fact windows.usb_device: {usb}  "
        )),
        "{explained}"
    );
    assert!(
        explained.contains("\nmounted as  -> fact windows.mounted_device: \\DosDevices\\F:  "),
        "{explained}"
    );
    let explained = af(&["explain", c, &format!("{event:x}")]);
    assert!(
        explained.contains(&format!(
            "\nnamed in log  <- fact windows.usb_storage: {disk}  {fact:032x}  [strong]"
        )),
        "{explained}"
    );
    std::fs::remove_dir_all(&parent).unwrap();
}
