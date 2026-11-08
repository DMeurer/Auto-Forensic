//! The project canary (C3), from the report: an empty project, add a SYSTEM hive and an
//! NTUSER.DAT as loose files, run, add one more hive, run again. Passes when plugins with absent
//! inputs say so, tags survive the re-run, unchanged inputs aren't extracted again, links are
//! rebuilt, and no plugin assumes an image path (the hives here are loose files, found by kind).
//! The last step (C3b, moved to the end of stage 3 on 2026-11-06) adds a stick image from the
//! shared folder and runs again: the stick is its own `none` system and nothing else changes. It
//! is skipped when the image is missing, since course images never go into the repository.

use af_core::ids::{Endpoint, EventId};
use af_store::Store;
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

fn hive(dir: &Path, name: &str, roots: &[&str], ticks: u64) -> String {
    let mut h = af_fmt_regf::build_test_hive(roots, "lh");
    let root = u32::from_le_bytes(h[0x24..0x28].try_into().unwrap()) as usize;
    let at = 0x1000 + root + 4 + 0x04;
    h[at..at + 8].copy_from_slice(&ticks.to_le_bytes());
    let p = dir.join(name);
    std::fs::write(&p, h).unwrap();
    p.to_str().unwrap().to_string()
}

fn links(db: &Path) -> Vec<(u128, String)> {
    let s = Store::open_read_only(db).unwrap();
    s.links().unwrap()
}

/// Each system of `af status`: its line and its outcome lines.
fn system_blocks(status: &str) -> Vec<String> {
    let mut blocks: Vec<String> = Vec::new();
    for l in status.split_once("\nsystems: ").unwrap().1.lines().skip(1) {
        if l.starts_with("    ") {
            blocks.last_mut().unwrap().push_str(&format!("\n{l}"));
        } else if l.starts_with("  ") {
            blocks.push(l.to_string());
        } else {
            break;
        }
    }
    blocks
}

#[test]
fn project_canary() {
    let parent = std::env::temp_dir().join(format!("af-project-canary-{}", std::process::id()));
    std::fs::create_dir_all(&parent).unwrap();
    let t = 131_759_000_000_000_000; // 2018-07-09, in 100 ns ticks since 1601
    let system = hive(
        &parent,
        "SYSTEM",
        &["ControlSet001", "MountedDevices", "Select"],
        t,
    );
    let ntuser = hive(
        &parent,
        "NTUSER.DAT",
        &["Control Panel", "Environment", "Software"],
        t + 1,
    );
    let software = hive(
        &parent,
        "SOFTWARE",
        &["Classes", "Microsoft", "Policies"],
        t + 2,
    );
    let case = parent.join("case");
    let c = case.to_str().unwrap();
    let db = case.join("project.duckdb");

    af(&["project", "new", c]);
    af(&["source", "add", c, &system]);
    af(&["source", "add", c, &ntuser]);
    let first = af(&["run", c]);
    // The hive, key-time, host, network, Run key and service plugins on both systems, and the
    // profile plugin where an NTUSER.DAT is.
    assert!(first.contains("13 extracted"), "{first}");

    // Absent inputs are reported clearly, and told apart from inputs with nothing in them.
    let status = af(&["status", c]);
    assert!(
        status.contains("windows.user_profiles v3: not in this project"),
        "{status}"
    );
    assert!(
        status.contains("windows.services v1: present, nothing relevant"),
        "{status}"
    );
    // R12: the loose NTUSER.DAT is a user without a SID.
    assert!(
        status.contains("windows.user_profiles v3: read, 1 items"),
        "{status}"
    );
    let users = af(&["users", c]);
    assert!(
        users.contains("  unknown user 1      (loose hive, no SID known)"),
        "{users}"
    );
    let links_before = links(&db);
    assert_eq!(
        links_before.len(),
        6,
        "3 root keys per hive, linked to the hive's time"
    );

    // The analyst tags an event.
    let tagged = {
        let mut s = Store::open(&db, 256).unwrap();
        let id = s.events().unwrap()[0].id;
        s.add_tag(&Endpoint::Event(EventId(id)), "suspicious")
            .unwrap();
        id
    };

    // One more hive, and run again.
    af(&["source", "add", c, &software]);
    let second = af(&["run", c]);
    assert!(
        second.contains("6 extracted"),
        "only the new hive is read, by the six registry plugins: {second}"
    );

    let s = Store::open_read_only(&db).unwrap();
    assert_eq!(
        s.tags_of(&Endpoint::Event(EventId(tagged))).unwrap(),
        ["suspicious"]
    );
    let events = s.events().unwrap();
    let root_times = events
        .iter()
        .filter(|e| e.kind == "windows.hive.root_written")
        .count();
    assert_eq!(root_times, 3, "one root time event per hive, none twice");
    assert_eq!(events.len(), 15, "and R7's key times: 4 keys in each hive");
    drop(s);
    let links_after = links(&db);
    assert_eq!(links_after.len(), 9, "links rebuilt for all three hives");
    for l in &links_before {
        assert!(links_after.contains(l), "rebuilt links keep their IDs");
    }

    // C3b: a stick image becomes its own `none` system, and the hive systems stay as they were.
    let stick = Path::new("/mnt/hgfs/VM_sharedFolder/DF/various/USB-Stick images/FAT32-Win.E01");
    if stick.is_file() {
        let before = af(&["status", c]);
        af(&["source", "add", c, stick.to_str().unwrap()]);
        af(&["run", c]);
        let after = af(&["status", c]);
        eprintln!("{after}");
        let mut before = system_blocks(&before);
        let mut after = system_blocks(&after);
        let stick_at = after
            .iter()
            .position(|b| b.ends_with(" FAT32-Win.E01\n    no plugin has run on it yet"))
            .unwrap_or_else(|| panic!("the stick isn't a system no plugin ran on: {after:?}"));
        assert!(after.remove(stick_at).contains(" none "));
        before.sort();
        after.sort();
        assert_eq!(after, before, "the hive systems' outcomes are unchanged");
        let s = Store::open_read_only(&db).unwrap();
        assert_eq!(
            s.tags_of(&Endpoint::Event(EventId(tagged))).unwrap(),
            ["suspicious"]
        );
        assert_eq!(s.events().unwrap().len(), 15, "the stick adds no events");
    }
    std::fs::remove_dir_all(&parent).unwrap();
}
