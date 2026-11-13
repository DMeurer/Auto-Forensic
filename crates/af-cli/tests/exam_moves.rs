//! L11 on the exam image: `unlocker.E01`, which stage 0 made from the BitLocker image and
//! checked against it decrypted with its key (`dislocker -K vmk.dat`, same files and contents).
//! Only the journal and the moved-to rule run. The source goes in through the store, as in the
//! LoneWolf test, because `af source add` would hash all 12 GB first. Skips when the image is
//! missing.

use af_core::ids::SourceId;
use af_core::profile::{NoneProfile, OsProfile};
use af_store::project::Project;
use af_store::source::SourceInfo;
use std::path::PathBuf;

#[test]
fn exam_moves_link_old_names_to_new() {
    let image = PathBuf::from("/mnt/hgfs/VM_sharedFolder/DF/prufung/unlocker.E01");
    if !image.is_file() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path();
    let mut p = Project::create(case, "exam").unwrap();
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
        case,
        &[&af_windows::usn::Journal, &af_windows::moved::MovedTo],
        &profiles,
    )
    .unwrap();

    let db = duckdb::Connection::open_with_flags(
        case.join("project.duckdb"),
        duckdb::Config::default()
            .access_mode(duckdb::AccessMode::ReadOnly)
            .unwrap(),
    )
    .unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM links WHERE created_by = 'windows.moved_to'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // MFTECmd's journal output (~/af-stage0/csv/mft/usn.csv) has 1,189 renames into another
    // folder that aren't Windows deleting a file (into `$Extend\$Deleted`); 9 of them are within
    // WinSxS.
    assert_eq!(count, 1180);
    // The user's own: two files into the Recycle Bin, three phone videos into Music and a photo
    // into Pictures.
    let user: Vec<String> = db
        .prepare(
            "SELECT l.reason FROM links l JOIN events e ON e.id = l.from_id \
             WHERE l.created_by = 'windows.moved_to' AND l.reason LIKE '%from /Users/ich/%' \
             AND l.reason NOT LIKE '%/AppData/%' AND l.reason NOT LIKE '%/Tor Browser/%' \
             ORDER BY e.ts",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .map(|r: String| r.split(") from ").nth(1).unwrap().to_string())
        .collect();
    let bin = "/$Recycle.Bin/S-1-5-21-2238723211-971586207-103896696-1001";
    let want = [
        format!("/Users/ich/Desktop/crypto.txt to {bin}/$RKU2ADN.txt"),
        "/Users/ich/Downloads/PXL_20260720_190701472.TS.mp4 to /Users/ich/Music/PXL_20260720_190701472.TS.mp4".into(),
        "/Users/ich/Pictures/PXL_20260720_161853925.TS.mp4 to /Users/ich/Music/PXL_20260720_161853925.TS.mp4".into(),
        "/Users/ich/Pictures/PXL_20260720_154824613.mp4 to /Users/ich/Music/PXL_20260720_154824613.mp4".into(),
        format!("/Users/ich/Pictures/IMG_8008.HEIC to {bin}/$R2Y3FNX.HEIC"),
        "/Users/ich/Downloads/PXL_20260713_104809495.MP.jpg to /Users/ich/Pictures/PXL_20260713_104809495.MP.jpg".into(),
    ];
    assert_eq!(user, want);
}
