//! The project canary (C3), from the report: an empty project, add a SYSTEM hive and an
//! NTUSER.DAT as loose files, run, add one more hive, run again. Passes when plugins with absent
//! inputs say so, tags survive the re-run, unchanged inputs aren't extracted again, links are
//! rebuilt, and no plugin assumes an image path (the hives here are loose files, found by kind).
//! The last step, adding a stick image, moved to the end of stage 3 (decision of 2026-11-06).

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
    // The hive plugin on both systems, and the profile plugin where an NTUSER.DAT is.
    assert!(first.contains("3 extracted"), "{first}");

    // Absent inputs are reported clearly, and told apart from inputs with nothing in them.
    let status = af(&["status", c]);
    assert!(
        status.contains("windows.user_profiles v1: not in this project"),
        "{status}"
    );
    assert!(
        status.contains("windows.user_profiles v1: present, nothing relevant"),
        "{status}"
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
        second.contains("1 extracted"),
        "only the new hive is read: {second}"
    );

    let s = Store::open_read_only(&db).unwrap();
    assert_eq!(
        s.tags_of(&Endpoint::Event(EventId(tagged))).unwrap(),
        ["suspicious"]
    );
    assert_eq!(
        s.events().unwrap().len(),
        3,
        "one time event per hive, none twice"
    );
    drop(s);
    let links_after = links(&db);
    assert_eq!(links_after.len(), 9, "links rebuilt for all three hives");
    for l in &links_before {
        assert!(links_after.contains(l), "rebuilt links keep their IDs");
    }
    std::fs::remove_dir_all(&parent).unwrap();
}
