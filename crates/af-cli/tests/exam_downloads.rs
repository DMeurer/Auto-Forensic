//! L9 on the exam image's data copied out in stage 0 (`~/af-stage0/extract`): its `$MFT`,
//! Prefetch files, browser databases, SYSTEM and SOFTWARE, laid out as a Windows folder with the
//! `$MFT` at its root, as triage tools copy it. Skipped where the copies aren't.

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
fn exam_download_to_use() {
    let stage0 = Path::new(&std::env::var_os("HOME").unwrap_or_default()).join("af-stage0/extract");
    let mft = stage0.join("ntfs/$MFT");
    if !mft.is_file() || !stage0.join("hives/SOFTWARE").is_file() {
        return;
    }
    let parent = std::env::temp_dir().join(format!("af-exam-downloads-{}", std::process::id()));
    let disk = parent.join("disk");
    copy(&stage0.join("browser/Users"), &disk.join("Users"));
    copy(&stage0.join("prefetch"), &disk.join("Windows/Prefetch"));
    let config = disk.join("Windows/System32/config");
    std::fs::create_dir_all(&config).unwrap();
    for hive in ["SYSTEM", "SOFTWARE"] {
        for f in [
            hive.to_string(),
            format!("{hive}.LOG1"),
            format!("{hive}.LOG2"),
        ] {
            std::fs::copy(stage0.join("hives").join(&f), config.join(&f)).unwrap();
        }
    }
    std::fs::copy(&mft, disk.join("$MFT")).unwrap();
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
    // Stage 0's eight links, and nothing else: the Tor chain of Training cases (Edge download,
    // the installer and its run, the folder it made, FIREFOX.EXE and TOR.EXE in it, the cookies
    // database FIREFOX loaded) and the ChromeSetup download and its run. Times are UTC.
    let links: Vec<(String, String, String, String)> = db
        .prepare(
            "SELECT l.tier, l.label, regexp_replace(l.key, '^[A-Z]:', ''), \
             strftime(make_timestamp(((a.ts - 116444736000000000) // 10)::BIGINT), '%H:%M:%S') \
             || '-' || strftime(make_timestamp(((b.ts - 116444736000000000) // 10)::BIGINT), '%H:%M:%S') \
             FROM links l JOIN events a ON a.id = l.from_id JOIN events b ON b.id = l.to_id \
             WHERE l.created_by = 'windows.download_to_use' ORDER BY a.ts, l.label",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let tor = "/Users/ich/Desktop/Tor Browser";
    let want = [
        (
            "strong",
            "saved as file",
            "\\Users\\ich\\Downloads\\tor-browser-windows-x86_64-portable-15.0.10.exe \
             (113409064 bytes)"
                .to_string(),
            "07:34:07-07:34:08",
        ),
        (
            "strong",
            "run",
            "/Users/ich/Downloads/tor-browser-windows-x86_64-portable-15.0.10.exe".into(),
            "07:34:08-07:35:01",
        ),
        (
            "possible",
            "probably installed to",
            tor.into(),
            "07:35:01-07:35:12",
        ),
        (
            "strong",
            "contains program that ran",
            format!("{tor}/Browser/TorBrowser/Tor/tor.exe"),
            "07:35:12-07:37:19",
        ),
        (
            "strong",
            "contains program that ran",
            format!("{tor}/Browser/firefox.exe"),
            "07:35:12-07:37:38",
        ),
        (
            "strong",
            "used database",
            format!("{tor}/Browser/TorBrowser/Data/Browser/profile.default/cookies.sqlite"),
            "07:37:38-07:36:50",
        ),
        (
            "strong",
            "run",
            "/Users/ich/Downloads/ChromeSetup.exe".into(),
            "07:40:58-07:41:43",
        ),
        (
            "strong",
            "saved as file",
            "\\Users\\ich\\Downloads\\ChromeSetup.exe (11487160 bytes)".into(),
            "07:40:59-07:40:58",
        ),
    ];
    assert_eq!(
        links,
        want.map(|(t, l, k, w)| (t.to_string(), l.to_string(), k, w.to_string()))
    );
    std::fs::remove_dir_all(&parent).unwrap();
}
