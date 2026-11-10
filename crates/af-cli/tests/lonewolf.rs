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
    let mut file_systems = vec![];
    for a in index.all() {
        let steps = a.locator.steps();
        // M3: the NTFS file systems of the system's partitions, for fs.timeline.
        if a.kind.as_str() == "fs.ntfs" {
            file_systems.push(steps[1].id.clone());
            continue;
        }
        assert_eq!(steps[1].id, "4", "on the Windows partition");
        assert_eq!(a.sha256.len(), 64);
        kinds
            .entry(a.kind.as_str().to_string())
            .or_default()
            .push(steps.last().unwrap().id.clone());
    }
    file_systems.sort();
    assert_eq!(file_systems, ["1", "4"]);
    let count = |k: &str| kinds.get(k).map_or(0, Vec::len);
    assert_eq!(count("windows.evtx"), 146);
    // X3: shortcuts below the user profiles and in the shared Start Menu.
    assert_eq!(count("windows.lnk"), 198);
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
            &af_windows::prefetch::Prefetch,
            &af_windows::lnk::Shortcuts,
            &af_windows::registry_timeline::KeyTimes,
            &af_windows::host::Host,
            &af_windows::network::Network,
            &af_windows::autoruns::RunKeys,
            &af_windows::autoruns::Services,
            &af_windows::bam::Bam,
            &af_windows::sam::Sam,
            &af_windows::usb::Usb,
            &af_core::fs_timeline::Timeline,
            &af_windows::usn::Journal,
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
    // E1: every log reads, so no event log gets a note either. R9's note: the Wi-Fi adapter's
    // lease times are no calendar times. X2's: CHROME.EXE's Prefetch file is only zeros.
    let notes: Vec<&str> = status.lines().filter(|l| l.contains("note:")).collect();
    assert_eq!(notes.len(), 2, "{status}");
    assert!(
        notes
            .iter()
            .any(|n| n.contains("interface Wi-Fi: DHCP lease times")),
        "{status}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.contains("CHROME.EXE-CCF9F3F5.pf was never written (only zeros)")),
        "{status}"
    );
    for line in [
        "  windows.evtx: 146",
        "    windows.evtx.events v1: read, 55638 items",
        "  windows.prefetch: 161",
        "    windows.prefetch v1: read, 695 items",
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

    // R14: RECmd's UserAccounts plugin (~/af-stage3/r8): 5 accounts; jcloudy logged in 23 times,
    // last at 2018-04-06 12:26:27.5724698 UTC.
    let (accounts, logins, last): (i64, String, i64) = db
        .query_row(
            "SELECT count(*), max(json_extract_string(f.attrs, '$.login_count')) \
             FILTER (WHERE f.subject = 'jcloudy'), \
             (SELECT ts FROM events WHERE kind = 'windows.account.last_login') \
             FROM facts f WHERE f.kind = 'windows.account'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (accounts, logins.as_str(), last),
        (5, "23", 131_674_911_875_724_698)
    );

    // R11: RECmd's USB, USBSTOR and MountedDevices plugins (~/af-stage3/r11): 11 USB devices, 2
    // SanDisk disks, 7 mounted devices and 41 device times. The disk mounted as D: has its own
    // DiskId (RECmd repeats the other disk's).
    let (devices, disks, mounted, times, d): (i64, i64, i64, i64, String) = db
        .query_row(
            "SELECT count(*) FILTER (WHERE kind = 'windows.usb_device'), \
             count(*) FILTER (WHERE kind = 'windows.usb_storage'), \
             count(*) FILTER (WHERE kind = 'windows.mounted_device'), \
             (SELECT count(*) FROM events WHERE kind LIKE 'windows.usb.%'), \
             max(json_extract_string(attrs, '$.disk_id') || ' ' || \
                 json_extract_string(attrs, '$.usb_device')) \
             FILTER (WHERE attrs LIKE '%DosDevices%D:%') FROM facts",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(
        (devices, disks, mounted, times, d.as_str()),
        (
            11,
            2,
            7,
            41,
            "{3869c279-31b8-11e8-9b12-ecf4bb487fed} VID_0781&PID_5580\\AA010603160707470215"
        )
    );

    // M3: fs.timeline on both NTFS partitions (~/af-stage3/m3): the Windows partition's 142,956
    // entries (as MFTECmd) with the $SI times of the loose $MFT plugin, and the recovery
    // partition's 31.
    let parts: Vec<(String, i64, i64)> = db
        .prepare(
            "SELECT split_part(r.locator, '/', 2), count(DISTINCT r.id), count(*) FROM events e \
             JOIN records r ON r.id = e.record WHERE e.created_by = 'fs.timeline' \
             GROUP BY 1 ORDER BY 1",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        parts,
        [
            ("volume.partition:1".to_string(), 31, 248),
            ("volume.partition:4".to_string(), 142_956, 1_143_648)
        ]
    );

    // M6: the Windows partition's change journal (~/af-stage3/m6), equal to MFTECmd: 352,849
    // records, one event per change flag (681,177), each linked to its file. jcloudy deleted
    // "Cloudy thoughts (4apr).docx" from the desktop at 2018-04-05 02:39:29.7499774 UTC.
    let (records, events, links, deleted): (i64, i64, i64, String) = db
        .query_row(
            "SELECT (SELECT count(*) FROM records WHERE kind = 'ntfs.usn.record'), \
             (SELECT count(*) FROM events WHERE created_by = 'windows.usn'), \
             (SELECT count(*) FROM links WHERE created_by = 'windows.usn'), \
             (SELECT string_agg(e.ts || ' ' || json_extract_string(r.attrs, '$.parent_path') \
                 || ' ' || json_extract_string(r.attrs, '$.entry'), ';') \
              FROM events e JOIN records r ON r.id = e.record \
              WHERE e.kind = 'ntfs.usn.file_delete' \
              AND json_extract_string(r.attrs, '$.name') = 'Cloudy thoughts (4apr).docx')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (records, events, links, deleted.as_str()),
        (
            352_849,
            681_177,
            681_177,
            "131673695697499774 /Users/jcloudy/Desktop 131041"
        )
    );

    // X2: 695 run times in 160 Prefetch files, as PECmd's timeline (~/af-stage3/x2). Last run is
    // the latest stored time: OFFICECLICKTORUN.EXE's first slot holds 12:29:29, which PECmd calls
    // LastRun, but it also ran at 12:29:30.
    let (files, runs, office): (i64, i64, String) = db
        .query_row(
            "SELECT (SELECT count(*) FROM records WHERE kind = 'windows.prefetch.file'), \
             (SELECT count(*) FROM events WHERE kind = 'windows.prefetch.run'), \
             (SELECT json_extract_string(attrs, '$.last_run') FROM records \
              WHERE kind = 'windows.prefetch.file' \
              AND json_extract_string(attrs, '$.name') = 'OFFICECLICKTORUN.EXE')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (files, runs, office.as_str()),
        (160, 695, "2018-04-06 12:29:30.3456068 UTC")
    );

    // X3: the 198 shortcuts below the profiles and in the Start Menu, read as LECmd reads them
    // (~/af-stage3/x3): 298 stored times. jcloudy's Recent/key.lnk points to key.txt on a
    // removable volume "CloudLog" (its full path is checked in af-fmt-lnk's tests).
    let (links, times, key): (i64, i64, String) = db
        .query_row(
            "SELECT (SELECT count(*) FROM records WHERE kind = 'windows.lnk.file'), \
             (SELECT count(*) FROM events WHERE created_by = 'windows.lnk'), \
             (SELECT concat_ws(' ', json_extract_string(attrs, '$.target') LIKE '%key.txt', \
                 json_extract_string(attrs, '$.drive_type'), \
                 json_extract_string(attrs, '$.volume_serial'), \
                 json_extract_string(attrs, '$.volume_label')) \
              FROM records WHERE kind = 'windows.lnk.file' AND locator LIKE '%Recent%2Fkey.lnk')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (links, times, key.as_str()),
        (198, 298, "true removable 4C36F4AC CloudLog")
    );
}
