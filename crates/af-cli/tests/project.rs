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
