//! I23 and I24 on LoneWolf (the shared-folder copy, see `xtask/evidence.tsv`): the image gives
//! its Windows system, every hive, event log and Prefetch file is indexed, as many as the stage-1
//! `fls` listing (`~/af-stage1/lonewolf/fls.txt`) shows, and after a run `af users` lists the
//! ProfileList users with their hives. The source goes in through the store, because
//! `af source add` hashes and verifies all 13.5 GB first. Skips when the image is missing.

use af_core::ids::SourceId;
use af_core::profile::{NoneProfile, OsProfile};
use af_store::project::Project;
use af_store::source::SourceInfo;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn lonewolf_gives_its_windows_system_with_hives_event_logs_and_prefetch() {
    let dir = PathBuf::from("/mnt/hgfs/VM_sharedFolder/DF/various/LoneWolf");
    let files: Vec<PathBuf> = (1..=9)
        .map(|i| dir.join(format!("LoneWolf.E{i:02}")))
        .collect();
    if !files.iter().all(|f| f.is_file()) {
        return;
    }
    let case = tempfile::tempdir().unwrap();
    let mut p = Project::create(case.path(), "lonewolf").unwrap();
    let source = SourceInfo {
        id: SourceId::new_random(),
        kind: "image".into(),
        label: "LoneWolf.E01".into(),
        size: 0,
        sha256: String::new(),
        fingerprint: String::new(),
        files,
    };
    let profiles: [&dyn OsProfile; 3] = [
        &af_windows::WindowsProfile,
        &af_linux::LinuxProfile,
        &NoneProfile,
    ];
    p.add_systems(&source, &profiles).unwrap();
    // The source row `af source add` would write, without its hash.
    let db = p.store.connection();
    db.execute(
        "INSERT INTO sources VALUES (?, 'image', 'LoneWolf.E01', 0, '', '', 0, NULL, 'unknown')",
        duckdb::params![source.id.0],
    )
    .unwrap();
    for (seq, f) in source.files.iter().enumerate() {
        db.execute(
            "INSERT INTO source_files VALUES (?, ?, ?, 0)",
            duckdb::params![source.id.0, seq as i32, f.to_str().unwrap()],
        )
        .unwrap();
    }

    let mut families: Vec<String> = p.systems().unwrap().into_iter().map(|s| s.family).collect();
    families.sort();
    // Partition 1, the recovery partition (`Recovery/WindowsRE`), belongs to the Windows system.
    assert_eq!(families, ["windows"]);

    let index = p.store.artifacts().unwrap();
    let mut kinds: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for a in index.all() {
        let steps = a.locator.steps();
        assert_eq!(steps[1].id, "4", "on the Windows partition");
        assert_eq!(a.sha256.len(), 64);
        kinds
            .entry(a.kind.as_str().to_string())
            .or_default()
            .push(steps.last().unwrap().id.clone());
    }
    let count = |k: &str| kinds.get(k).map_or(0, Vec::len);
    assert_eq!(count("windows.evtx"), 146);
    assert_eq!(
        count("windows.hive.log"),
        22,
        "LOG1 and LOG2 of eleven hives"
    );
    assert_eq!(count("windows.prefetch"), 161);
    for (k, n) in [
        ("windows.hive.system", 1),
        ("windows.hive.software", 1),
        ("windows.hive.sam", 1),
        ("windows.hive.security", 1),
        ("windows.hive.default", 1),
        ("windows.hive.amcache", 1),
        ("windows.hive.ntuser", 4),
        ("windows.hive.usrclass", 1),
    ] {
        assert_eq!(count(k), n, "{k}: {:?}", kinds.get(k));
    }
    // The locator holds the folder as the disk stores it, as in TSK's `fls`.
    assert_eq!(
        kinds["windows.hive.amcache"],
        ["Windows/appcompat/Programs/Amcache.hve"]
    );
    let ntuser = &kinds["windows.hive.ntuser"];
    assert!(
        ntuser.contains(&"Users/jcloudy/NTUSER.DAT".to_string()),
        "{ntuser:?}"
    );

    // I24: a run, then `af users`.
    drop(p);
    af_store::run::run_project(
        case.path(),
        &[
            &af_windows::plugins::HiveRootKeys,
            &af_windows::plugins::UserProfiles,
            &af_windows::evtx::EventLogs,
        ],
        &profiles,
    )
    .unwrap();
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_af"))
        .arg("users")
        .arg(case.path())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let users = String::from_utf8_lossy(&o.stdout);
    eprintln!("{users}");
    let has = |line: &str| users.lines().any(|l| l.trim_start().starts_with(line));
    assert!(
        users.lines().any(
            |l| l.trim_start().starts_with("S-1-5-21-") && l.contains("jcloudy  Users/jcloudy")
        ),
        "{users}"
    );
    assert!(
        has("windows.hive.ntuser  Users/jcloudy/NTUSER.DAT"),
        "{users}"
    );
    assert!(
        has("windows.hive.usrclass  Users/jcloudy/AppData/Local/Microsoft/Windows/UsrClass.dat"),
        "{users}"
    );
    for sid in ["S-1-5-18 ", "S-1-5-19 ", "S-1-5-20 "] {
        assert!(has(sid), "{sid} in {users}");
    }
    assert!(
        has("windows.hive.ntuser  Windows/ServiceProfiles/LocalService/NTUSER.DAT"),
        "{users}"
    );
    assert!(
        !users.contains("Users/Default"),
        "the template isn't a user: {users}"
    );

    // I26: the kinds no plugin reads yet are marked, the hives aren't.
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_af"))
        .arg("status")
        .arg(case.path())
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&o.stdout);
    // R3: SYSTEM, SOFTWARE, DEFAULT, Amcache and jcloudy's NTUSER.DAT are dirty, and all
    // replay from their logs, so no hive gets a note.
    assert!(!status.contains("note: hive"), "{status}");
    // E1: every log reads, so no event log gets a note either.
    assert!(!status.contains("note:"), "{status}");
    for line in [
        "  windows.evtx: 146",
        "    windows.evtx.events v1: read, 55638 items",
        "  windows.prefetch: 161 (no plugin reads this kind yet)",
        "  windows.hive.log: 22 (no plugin reads this kind yet)",
        "  windows.hive.system: 1",
        "  windows.hive.ntuser: 4",
    ] {
        assert!(status.lines().any(|l| l == line), "{line} in {status}");
    }

    // E2: Security's 4624 events, as EvtxECmd lists them (827, the earliest record 406).
    let p = Project::open(case.path()).unwrap();
    let db = p.store.connection();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE kind = 'windows.evtx.4624'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 827);
    let (seq_domain, raw, attrs): (String, i64, String) = db
        .query_row(
            "SELECT e.seq_domain, e.raw_i64, r.attrs FROM events e JOIN records r \
             ON r.id = e.record WHERE e.kind = 'windows.evtx.4624' AND e.seq_no = 406",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(
        seq_domain.ends_with("/fs.path:Windows%2FSystem32%2Fwinevt%2FLogs%2FSecurity.evtx"),
        "the record number counts within its log: {seq_domain}"
    );
    assert_eq!(
        raw, 131_666_157_609_012_671,
        "2018-03-27 09:16:00.9012671 UTC"
    );
    assert!(attrs.contains("\"EventData\""), "{attrs}");

    // R6: the run gives the system its identity from SYSTEM.
    drop(p);
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_af"))
        .args(["system", "list"])
        .arg(case.path())
        .output()
        .unwrap();
    let systems = String::from_utf8_lossy(&o.stdout);
    assert!(systems.contains(" windows  DESKTOP-PM6C56D "), "{systems}");
    for fact in [
        "    windows.computer_name: DESKTOP-PM6C56D",
        "    windows.control_set: ControlSet001",
        "    windows.time_zone: Eastern Standard Time",
        "    windows.time_zone_offset: UTC-05:00",
    ] {
        assert!(systems.lines().any(|l| l == fact), "{fact} in {systems}");
    }
}
