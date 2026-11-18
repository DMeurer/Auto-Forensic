//! G1 to G3 on the exam image (`unlocker.E01`, see `exam_moves.rs`): file groups, deleted-file
//! groups and program runs. The source goes in through the store, because `af source add` would
//! hash all 12 GB first. Skips when the image is missing. `AF_KEEP=<folder>` keeps the project
//! there for a look with `af`.

use af_core::ids::SourceId;
use af_core::profile::{NoneProfile, OsProfile};
use af_store::project::Project;
use af_store::source::SourceInfo;
use std::path::PathBuf;

#[test]
fn exam_groups() {
    let image = PathBuf::from("/mnt/hgfs/VM_sharedFolder/DF/prufung/unlocker.E01");
    if !image.is_file() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let case = std::env::var_os("AF_KEEP").map_or(temp.path().to_path_buf(), PathBuf::from);
    let mut p = Project::create(&case, "exam").unwrap();
    let source = SourceInfo {
        id: SourceId::new_random(),
        kind: "image".into(),
        label: "unlocker.E01".into(),
        size: 0,
        sha256: String::new(),
        fingerprint: String::new(),
        files: vec![image.clone()],
    };
    let profiles: [&dyn OsProfile; 2] = [&af_windows::WindowsProfile, &NoneProfile];
    p.add_systems(&source, &profiles).unwrap();
    let db = p.store.connection();
    db.execute(
        "INSERT INTO sources VALUES (?, 'image', 'unlocker.E01', 0, '', '', 0, NULL, 'unknown')",
        duckdb::params![source.id.0],
    )
    .unwrap();
    db.execute(
        "INSERT INTO source_files VALUES (?, 0, ?, 0)",
        duckdb::params![source.id.0, image.to_str().unwrap()],
    )
    .unwrap();
    drop(p);
    af_store::run::run_project(
        &case,
        &[
            &af_core::fs_timeline::Timeline,
            &af_windows::usn::Journal,
            &af_windows::prefetch::Prefetch,
            &af_windows::bam::Bam,
            &af_windows::file_groups::FileGroups,
            &af_windows::program_runs::ProgramRuns,
        ],
        &profiles,
    )
    .unwrap();

    // G3 (stage 0, Task 5): on 2026-04-26 (UTC) a file's `$MFT` and journal events fold into one
    // line: 350,728 events (each USN reason and `$MFT` time one) become 35,857 file lines, the
    // files (entry and sequence) with a time that day in MFTECmd's `$MFT` and `$J` output
    // (~/af-stage0/csv/mft), and 358 Prefetch runs.
    let day = |args: &[&str]| -> (usize, usize) {
        let o = std::process::Command::new(env!("CARGO_BIN_EXE_af"))
            .arg("events")
            .args(args)
            .arg(&case)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let out = String::from_utf8_lossy(&o.stdout);
        let lines: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("2026-04-26 "))
            .collect();
        let files = lines
            .iter()
            .filter(|l| l.split('\t').nth(1) == Some("windows.file"))
            .count();
        (lines.len(), files)
    };
    assert_eq!(day(&["--expand"]), (350_728, 0));
    assert_eq!(day(&[]), (36_215, 35_857));

    let db = duckdb::Connection::open_with_flags(
        case.join("project.duckdb"),
        duckdb::Config::default()
            .access_mode(duckdb::AccessMode::ReadOnly)
            .unwrap(),
    )
    .unwrap();
    let count = |sql: &str| -> i64 { db.query_row(sql, [], |r| r.get(0)).unwrap() };
    let groups = |kind: &str| {
        count(&format!(
            "SELECT count(*) FROM groups WHERE kind = '{kind}'"
        ))
    };
    // G2: as MFTECmd's `$J` and `$MFT` give them (~/af-stage0/csv/mft, its reasons read as flags
    // where it prints a number): a deletion with the same entry and sequence's creation, or with
    // the entry left unused at sequence + 1 under its last name.
    assert_eq!(groups("windows.deleted_file"), 13_795);
    // G1: one per run time, as PECmd lists them (~/af-stage0/csv/pf/pf.csv); the journal holds
    // the Prefetch write of all but one.
    assert_eq!(groups("windows.program_run"), 1_155);
    assert_eq!(
        count(
            "SELECT count(*) FROM groups WHERE kind = 'windows.program_run' \
             AND reason LIKE '%no Prefetch write%'"
        ),
        1
    );
    // Tor's first run on 2026-04-26: its `state` and `control_auth_cookie`, in its Prefetch list,
    // written until the Prefetch write 35 s later.
    let tor = count(
        "SELECT count(*) FROM group_members m JOIN groups g ON g.id = m.grp \
         WHERE g.reason LIKE 'run of TOR.EXE at 2026-04-26 07:37:19.3356395 UTC%'",
    );
    assert_eq!(tor, 31);
}
