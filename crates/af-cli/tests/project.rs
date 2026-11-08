//! `af project new` and `af project info`, run as the real binary (F19).

use std::process::Command;

fn af(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_af"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn project_new_then_info() {
    let parent = std::env::temp_dir().join(format!("af-cli-test-{}", std::process::id()));
    let dir = parent.join("case-7");
    let d = dir.to_str().unwrap();
    let (ok, out, err) = af(&["project", "new", d, "--name", "Case 7"]);
    assert!(ok, "{err}");
    assert!(out.contains("Case 7"));
    let (ok, out, err) = af(&["project", "info", d]);
    assert!(ok, "{err}");
    assert!(out.contains("name:     Case 7"), "{out}");
    assert!(out.contains(" UTC"), "{out}");
    // A second `new` into the same folder is refused.
    let (ok, _, err) = af(&["project", "new", d]);
    assert!(!ok);
    assert!(err.contains("isn't empty"), "{err}");
    std::fs::remove_dir_all(&parent).unwrap();
}

/// F22's "done when": SYSTEM, SOFTWARE and NTUSER.DAT are identified with their names removed.
#[test]
fn renamed_hives_are_identified() {
    let parent = std::env::temp_dir().join(format!("af-cli-hives-{}", std::process::id()));
    let case = parent.join("case");
    std::fs::create_dir_all(&parent).unwrap();
    let hives: [(&str, &[&str]); 3] = [
        (
            "file1",
            &["ControlSet001", "MountedDevices", "Select", "Setup"],
        ),
        (
            "file2",
            &["Classes", "Microsoft", "Policies", "Setup", "WOW6432Node"],
        ),
        (
            "file3",
            &["AppEvents", "Control Panel", "Environment", "Software"],
        ),
    ];
    for (name, roots) in hives {
        std::fs::write(parent.join(name), af_fmt_regf::build_test_hive(roots, "lh")).unwrap();
    }
    std::fs::write(parent.join("notes.txt"), b"plain text").unwrap();
    let c = case.to_str().unwrap();
    assert!(af(&["project", "new", c]).0);
    let mut kinds = Vec::new();
    for name in ["file1", "file2", "file3"] {
        let (ok, out, err) = af(&["source", "add", c, parent.join(name).to_str().unwrap()]);
        assert!(ok, "{err}");
        kinds.push(
            out.lines()
                .find(|l| l.starts_with("kind"))
                .unwrap()
                .to_string(),
        );
    }
    assert_eq!(
        kinds,
        [
            "kind   windows.hive.system",
            "kind   windows.hive.software",
            "kind   windows.hive.ntuser"
        ]
    );
    // An entered capture date shows up; without one it's unknown.
    let (ok, out, err) = af(&[
        "source",
        "add",
        c,
        parent.join("file1").to_str().unwrap(),
        "--as-of",
        "2026-04-26 10:00",
    ]);
    assert!(
        ok && out.contains("as of 2026-04-26 10:00:00 UTC (entered)"),
        "{out}{err}"
    );
    let (ok, _, err) = af(&[
        "source",
        "add",
        c,
        parent.join("file1").to_str().unwrap(),
        "--as-of",
        "2026-13-01",
    ]);
    assert!(!ok && err.contains("not a UTC time"), "{err}");
    // Not a hive: no kind, unless named with --as.
    let notes = parent.join("notes.txt");
    let (_, out, _) = af(&["source", "add", c, notes.to_str().unwrap()]);
    assert!(out.contains("kind   unknown"), "{out}");
    let (ok, out, _) = af(&[
        "source",
        "add",
        c,
        notes.to_str().unwrap(),
        "--as",
        "user.notes",
    ]);
    assert!(ok && out.contains("kind   user.notes"), "{out}");
    let (ok, _, err) = af(&[
        "source",
        "add",
        c,
        notes.to_str().unwrap(),
        "--as",
        "Bad Kind",
    ]);
    assert!(!ok && err.contains("namespaced"), "{err}");
    let (_, list, _) = af(&["source", "list", c]);
    assert_eq!(list.matches("kind: windows.hive.").count(), 4, "{list}");
    assert!(list.contains("as of unknown"), "{list}");
    // Each import is its own system (F23): three hives give Windows systems, the two text
    // imports (unknown, then --as user.notes) none.
    let (ok, systems, err) = af(&["system", "list", c]);
    assert!(ok, "{err}");
    assert_eq!(systems.matches(" windows ").count(), 4, "{systems}");
    assert_eq!(systems.matches(" none ").count(), 2, "{systems}");
    // af status lists the artifact kinds and says no plugin ran yet.
    let (ok, status, err) = af(&["status", c]);
    assert!(ok, "{err}");
    assert!(status.contains("windows.hive.system: 2"), "{status}");
    assert!(status.contains("no plugin has run on it yet"), "{status}");
    // C0c: af run reads the hives' root keys into facts, plus one last-written event per hive
    // and one link per root key from Correlate (SYSTEM: 4 + 1 + 4, SOFTWARE: 5 + 1 + 5).
    let (ok, out, err) = af(&["run", c]);
    assert!(ok, "{err}{out}");
    let (_, status, _) = af(&["status", c]);
    assert!(
        status.contains("windows.hive.root_keys v1: read, 9 items"),
        "{status}"
    );
    assert!(
        status.contains("windows.hive.root_keys v1: read, 11 items"),
        "{status}"
    );
    // A second run extracts nothing.
    let (_, out, _) = af(&["run", c]);
    assert!(out.contains(": 0 extracted, 0 events loaded"), "{out}");
    // R6: the run gives each system with a registry its identity; without SYSTEM (the NTUSER)
    // the time zone is unknown, and these test hives' SYSTEM has no control set to read it from.
    let (_, systems, _) = af(&["system", "list", c]);
    assert!(
        systems.contains("    windows.time_zone: unknown (no SYSTEM hive)"),
        "{systems}"
    );
    assert!(
        systems.contains("    windows.time_zone: unknown (SYSTEM has no current control set)"),
        "{systems}"
    );
    std::fs::remove_dir_all(&parent).unwrap();
}

/// F32: read-only commands wait while a run writes the project, then say so; afterwards they work.
#[test]
fn reading_waits_for_a_writing_run() {
    let parent = std::env::temp_dir().join(format!("af-cli-lock-{}", std::process::id()));
    let dir = parent.join("case");
    let d = dir.to_str().unwrap();
    assert!(af(&["project", "new", d]).0);
    // Stand-in for a run's final load: hold the project open for writing.
    let writer = af_store::Store::open(&dir.join("project.duckdb"), 256).unwrap();
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_af"))
        .args(["status", d])
        .env("AF_LOCK_WAIT_SECS", "1")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        !o.status.success() && err.contains("being written by a run"),
        "{err}"
    );
    drop(writer);
    let (ok, out, err) = af(&["status", d]);
    assert!(ok, "{err}");
    assert!(out.contains("sources: 0"), "{out}");
    std::fs::remove_dir_all(&parent).unwrap();
}

/// C0a: a folder is added in place, listed, and gets a system of its own.
#[test]
fn a_folder_is_added_in_place() {
    let parent = std::env::temp_dir().join(format!("af-cli-folder-{}", std::process::id()));
    let root = parent.join("linux-root");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/hostname"), b"logserver\n").unwrap();
    let case = parent.join("case");
    let c = case.to_str().unwrap();
    assert!(af(&["project", "new", c]).0);
    let (ok, out, err) = af(&["source", "add", c, root.to_str().unwrap()]);
    assert!(ok, "{err}");
    assert!(
        out.contains("added folder") && out.contains("system "),
        "{out}"
    );
    assert!(!case.join("sources").exists(), "a folder isn't copied");
    // Nothing claims a lone hostname file: one `none` system, named after the folder.
    let (_, systems, _) = af(&["system", "list", c]);
    assert!(
        systems.contains(" none ") && systems.contains("linux-root"),
        "{systems}"
    );
    // af run works on any project, even with no plugin compiled in yet.
    let (ok, out, err) = af(&["run", c]);
    assert!(ok, "{err}");
    assert!(out.contains("events loaded"), "{out}");
    let (_, list, _) = af(&["source", "list", c]);
    assert!(
        list.contains(" folder ") && list.contains("linux-root"),
        "{list}"
    );
    std::fs::remove_dir_all(&parent).unwrap();
}

/// C1: a hand-built Linux root added as a folder is detected, and af run reads its wtmp (the
/// 400-byte layout here; both layouts are tested in af-fmt-utmp) and passwd.
#[test]
fn a_linux_root_is_detected_and_read() {
    let parent = std::env::temp_dir().join(format!("af-cli-linux-{}", std::process::id()));
    let root = parent.join("rootfs");
    let wtmp = af_fmt_utmp::build_test_file(
        400,
        &[
            (2, "reboot", "~", "4.15.0-29-generic", 1_531_143_874, 0),
            (7, "admin", "pts/0", "192.168.2.57", 1_531_143_900, 123_456),
            (8, "", "pts/0", "", 1_531_147_500, 0),
        ],
    );
    for (p, data) in [
        (
            "etc/os-release",
            &b"PRETTY_NAME=\"Debian GNU/Linux 9 (stretch)\"\n"[..],
        ),
        ("etc/hostname", b"logserver\n"),
        (
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n",
        ),
        ("var/log/wtmp", &wtmp),
    ] {
        std::fs::create_dir_all(root.join(p).parent().unwrap()).unwrap();
        std::fs::write(root.join(p), data).unwrap();
    }
    let case = parent.join("case");
    let c = case.to_str().unwrap();
    assert!(af(&["project", "new", c]).0);
    let (ok, _, err) = af(&["source", "add", c, root.to_str().unwrap()]);
    assert!(ok, "{err}");
    let (_, systems, _) = af(&["system", "list", c]);
    assert!(
        systems.contains(" linux ") && systems.contains("logserver"),
        "{systems}"
    );
    assert!(
        systems.contains("linux.os_release: Debian GNU/Linux 9 (stretch)"),
        "{systems}"
    );
    let (ok, out, err) = af(&["run", c]);
    assert!(ok, "{err}{out}");
    let (_, status, _) = af(&["status", c]);
    assert!(status.contains("linux.wtmp v1: read, 3 items"), "{status}");
    assert!(
        status.contains("linux.passwd v1: read, 2 items"),
        "{status}"
    );
    std::fs::remove_dir_all(&parent).unwrap();
}

/// R3: a Windows folder whose SYSTEM hive is dirty and has no logs; `af status` says so after a
/// run, and SOFTWARE, closed cleanly, gets no note. E2: an event log that isn't one is a note
/// too, and it stays after a second run, which doesn't extract again.
#[test]
fn a_dirty_hive_without_logs_is_reported() {
    let parent = std::env::temp_dir().join(format!("af-cli-dirty-{}", std::process::id()));
    let config = parent.join("pc/Windows/System32/config");
    std::fs::create_dir_all(&config).unwrap();
    let mut system = af_fmt_regf::build_test_hive(&["Select"], "lh");
    system[4] = 7; // primary sequence number ahead of the secondary: not closed cleanly
    let sum = af_fmt_regf::hive::header_checksum(&system);
    system[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
    std::fs::write(config.join("SYSTEM"), system).unwrap();
    std::fs::write(
        config.join("SOFTWARE"),
        af_fmt_regf::build_test_hive(&["Microsoft"], "lh"),
    )
    .unwrap();
    let logs = parent.join("pc/Windows/System32/winevt/Logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("Broken.evtx"), b"not an event log").unwrap();
    let case = parent.join("case");
    let c = case.to_str().unwrap();
    assert!(af(&["project", "new", c]).0);
    let (ok, _, err) = af(&["source", "add", c, parent.join("pc").to_str().unwrap()]);
    assert!(ok, "{err}");
    for _ in 0..2 {
        let (ok, _, err) = af(&["run", c]);
        assert!(ok, "{err}");
    }
    let (_, status, _) = af(&["status", c]);
    assert!(
        status
            .contains("    note: event log Windows/System32/winevt/Logs/Broken.evtx wasn't read: "),
        "{status}"
    );
    assert!(
        status.contains(
            "    note: hive Windows/System32/config/SYSTEM is dirty and its transaction logs \
             are missing: read as it is, recent changes may be missing"
        ),
        "{status}"
    );
    assert!(!status.contains("config/SOFTWARE is dirty"), "{status}");
    std::fs::remove_dir_all(&parent).unwrap();
}

/// E3: a map in the project's `maps` folder changes `af events` output with no rebuild, ahead of
/// the compiled-in 4624 map (E4); a broken map is skipped with a message.
#[test]
fn a_project_map_changes_af_events_output() {
    use af_core::time::Time;
    use af_store::{EventRow, RecordRow};
    let case = tempfile::tempdir().unwrap();
    let mut p = af_store::project::Project::create(case.path(), "maps").unwrap();
    let event = r##"{"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},
        "EventID":4624,"Channel":"Security"},
        "EventData":{"SubjectUserName":"me","SubjectDomainName":"PC","TargetUserName":"jcloudy",
        "TargetDomainName":"DESKTOP","LogonType":2}}"##;
    p.store
        .insert_records(&[RecordRow {
            id: 7,
            source: 1,
            system: 1,
            kind: "windows.evtx.record".into(),
            locator: "source.loose:1/evtx.record:42".into(),
            attrs: Some(event.into()),
            created_by: "windows.evtx.events".into(),
        }])
        .unwrap();
    p.store
        .insert_events(&[EventRow {
            id: 1,
            source: 1,
            record: 7,
            system: 1,
            kind: "windows.evtx.4624".into(),
            meaning: "evtx.time_created".into(),
            time: Time::from_ticks_1601(131_666_157_609_012_671).to_columns(),
            clock_domain: "wall".into(),
            seq_domain: Some("source.loose:1".into()),
            seq_no: Some(42),
            created_by: "windows.evtx.events".into(),
        }])
        .unwrap();
    drop(p);
    let c = case.path().to_str().unwrap();
    let row = |out: &str| {
        out.lines()
            .find(|l| l.contains("windows.evtx.4624"))
            .unwrap()
            .to_string()
    };

    let (ok, out, err) = af(&["events", c]);
    assert!(ok, "{err}");
    let line = row(&out);
    let fields: Vec<&str> = line.split('\t').collect();
    assert_eq!(fields[0], "2018-03-27 09:16:00.9012671 UTC");
    assert_eq!(
        &fields[3..8],
        [
            "Successful logon",
            "PC\\me",
            " ()",
            "",
            "Target: DESKTOP\\jcloudy"
        ]
    );
    assert_eq!(fields[13], "source.loose:1/evtx.record:42");

    let maps = case.path().join("maps");
    std::fs::create_dir(&maps).unwrap();
    std::fs::write(
        maps.join("mine.map"),
        "EventId: 4624\nChannel: Security\nProvider: Microsoft-Windows-Security-Auditing\n\
         Description: My logon\nMaps:\n  - Property: PayloadData1\n    PropertyValue: \"who: %u%\"\n    \
         Values:\n      - Name: u\n        Value: \"/Event/EventData/Data[@Name='TargetUserName']\"\n",
    )
    .unwrap();
    std::fs::write(maps.join("broken.map"), "EventId: [").unwrap();
    let (ok, out, err) = af(&["events", c]);
    assert!(ok, "{err}");
    assert!(err.contains("broken.map skipped"), "{err}");
    let line = row(&out);
    let fields: Vec<&str> = line.split('\t').collect();
    assert_eq!(fields[3], "My logon");
    assert_eq!(fields[7], "who: jcloudy");
}
