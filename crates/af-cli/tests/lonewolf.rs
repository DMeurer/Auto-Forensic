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
            &af_windows::registry_timeline::KeyTimes,
            &af_windows::host::Host,
            &af_windows::network::Network,
            &af_windows::autoruns::RunKeys,
            &af_windows::autoruns::Services,
            &af_windows::bam::Bam,
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
    // E1: every log reads, so no event log gets a note either. R9's only note: the Wi-Fi
    // adapter's lease times are no calendar times.
    let notes: Vec<&str> = status.lines().filter(|l| l.contains("note:")).collect();
    assert_eq!(notes.len(), 1, "{status}");
    assert!(
        notes[0].contains("interface Wi-Fi: DHCP lease times"),
        "{status}"
    );
    for line in [
        "  windows.evtx: 146",
        "    windows.evtx.events v1: read, 55638 items",
        "  windows.prefetch: 161 (no plugin reads this kind yet)",
        "  windows.hive.log: 22",
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

    // R7: one last-written event per key, as many per hive as yarp counts keys in TSK's copies
    // of the same hives with their logs (~/af-stage3/r5, 2026-11-08).
    let p = Project::open(case.path()).unwrap();
    let db = p.store.connection();
    let mut stmt = db
        .prepare(
            "SELECT json_extract_string(r.attrs, '$.hive'), \
             coalesce(json_extract_string(r.attrs, '$.owner'), '-'), count(*) \
             FROM events e JOIN records r ON r.id = e.record \
             WHERE e.kind = 'windows.registry.key_written' GROUP BY ALL ORDER BY ALL",
        )
        .unwrap();
    let counts: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let jc = "S-1-5-21-2734969515-1644526556-1039763013-1001";
    let want: Vec<(String, String, i64)> = [
        ("windows.amcache", "-", 1058),
        ("windows.default", "-", 641),
        ("windows.ntuser", "S-1-5-19", 695),
        ("windows.ntuser", "S-1-5-20", 695),
        ("windows.ntuser", jc, 5292),
        ("windows.ntuser", "default profile", 630),
        ("windows.sam", "-", 78),
        ("windows.security", "-", 92),
        ("windows.software", "-", 311_797),
        ("windows.system", "-", 35_595),
        ("windows.usrclass", jc, 6238),
    ]
    .into_iter()
    .map(|(h, o, n)| (h.to_string(), o.to_string(), n))
    .collect();
    assert_eq!(counts, want);

    // R8: as RECmd's Kroll batch reads TSK's copies (~/af-stage3/r8): Windows 10 Education,
    // build 16299, installed 2018-03-27 12:13:27.5286063, shut down 21:45:28.0567018 (UTC).
    let os: String = db
        .query_row(
            "SELECT subject || ' ' || attrs FROM facts WHERE kind = 'windows.os'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        os.starts_with("Windows 10 Education ") && os.contains(r#""build":"16299""#),
        "{os}"
    );
    for (kind, ticks, key) in [
        (
            "windows.os.installed",
            131_666_264_075_286_063_i64,
            "Microsoft\\Windows NT\\CurrentVersion",
        ),
        (
            "windows.os.shutdown",
            131_666_607_280_567_018,
            "ControlSet001\\Control\\Windows",
        ),
    ] {
        let (raw, path): (i64, String) = db
            .query_row(
                "SELECT e.raw_i64, json_extract_string(r.attrs, '$.path') FROM events e \
                 JOIN records r ON r.id = e.record WHERE e.kind = ?",
                [kind],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(raw, ticks, "{kind}");
        assert_eq!(
            path,
            format!("\\{key}"),
            "{kind} points at its key's record"
        );
    }

    // R9: the Wi-Fi adapter's gateway MAC, and profile "Net 2.4" last connected at 08:26:14.496
    // local, in Eastern daylight time by the hive's rules. Lease times are no calendar times.
    let wifi: String = db
        .query_row(
            "SELECT attrs FROM facts WHERE kind = 'windows.network.interface' AND subject = 'Wi-Fi'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        wifi.contains(r#""gateway_mac":"5C-8F-E0-2A-1C-68""#)
            && wifi.contains(r#""lease_obtained_raw":830452"#),
        "{wifi}"
    );
    let (ts, offset): (i64, i16) = db
        .query_row(
            "SELECT ts, tz_offset_min FROM events WHERE kind = 'windows.network.last_connected'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (ts, offset),
        (131_674_911_744_960_000, -240),
        "2018-04-06 12:26:14.496 UTC"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE kind LIKE 'windows.network.lease%'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );

    // R10: RECmd's Kroll batch on the machine and user hives (~/af-stage3/r8, r10): 11 Run
    // entries, and the 656 services of ControlSet001.
    let mut runs: Vec<(String, String)> = db
        .prepare(
            "SELECT subject, coalesce(json_extract_string(attrs, '$.owner'), '-') \
             FROM facts WHERE kind = 'windows.autorun'",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    runs.sort();
    let user = |n: &str| (n.to_string(), jc.to_string());
    let machine = |n: &str| (n.to_string(), "-".to_string());
    let mut want = vec![
        machine("Apoint"),
        machine("BoxSync"),
        machine("SecurityHealth"),
        machine("application"),
        user("GoogleDriveSync"),
        user("OneDrive"),
        user("Uninstall 18.025.0204.0009"),
        user("Uninstall 18.025.0204.0009\\amd64"),
        ("OneDriveSetup".into(), "S-1-5-19".into()),
        ("OneDriveSetup".into(), "S-1-5-20".into()),
        ("OneDriveSetup".into(), "default profile".into()),
    ];
    want.sort();
    assert_eq!(runs, want);
    let services: i64 = db
        .query_row(
            "SELECT count(*) FROM facts WHERE kind = 'windows.service'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(services, 656);

    // R13: RECmd's Bam plugin on LoneWolf's SYSTEM (~/af-stage3/r13): 31 entries in the 1709
    // layout, csrss.exe last run by SYSTEM at 2018-04-06 12:40:38.8104203 UTC.
    let (bam, csrss): (i64, i64) = db
        .query_row(
            "SELECT count(*), max(e.ts) FILTER (WHERE r.attrs LIKE '%csrss.exe%' \
             AND r.attrs LIKE '%\"S-1-5-18\"%') FROM events e JOIN records r ON r.id = e.record \
             WHERE e.kind = 'windows.bam.last_run'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((bam, csrss), (31, 131_674_920_388_104_203));
}
