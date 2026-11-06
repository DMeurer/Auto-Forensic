//! The Linux canary (C2): one project with a Windows sample system and a hand-built Linux root,
//! checked against the report's six pass criteria.
//!
//! 1. *Zero edits in core*: shown by commit `185eb92`, which added Linux with two new crates
//!    and one line each in `PROFILES` and `PLUGINS`, touching no file in `af-core`, `af-store`
//!    or `af-host`. A diff can't be a test; it's recorded in the plan.
//! 2. Both systems detected, with correct and filterable system IDs.
//! 3. `Foo` and `foo` stay distinct on Linux; Windows lookups ignore case.
//! 4. A non-UTF-8 name round-trips through the stored form to the same bytes.
//! 5. One SQL query returns user keys from both systems without treating them as equal.
//! 6. One timeline query mixes both systems, sorted by `ts`, with raw values preserved.

use af_core::path::{CasePolicy, Name, NameKind, PathIndex, PathStyle, ViewPath};
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

const TICKS_PER_SEC: i64 = 10_000_000;
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// A synthetic hive with these root keys and this root last-written time (Unix seconds).
fn hive(roots: &[&str], unix: i64) -> Vec<u8> {
    let mut h = af_fmt_regf::build_test_hive(roots, "lh");
    let root = u32::from_le_bytes(h[0x24..0x28].try_into().unwrap()) as usize;
    let at = 0x1000 + root + 4 + 0x04;
    let ticks = (unix * TICKS_PER_SEC + UNIX_EPOCH_TICKS) as u64;
    h[at..at + 8].copy_from_slice(&ticks.to_le_bytes());
    h
}

fn write(base: &Path, path: &str, data: &[u8]) {
    std::fs::create_dir_all(base.join(path).parent().unwrap()).unwrap();
    std::fs::write(base.join(path), data).unwrap();
}

// 2018-07-09 13:00, 13:30, 14:00 and 14:30 UTC, alternating Windows and Linux.
const W1: i64 = 1_531_141_200;
const L1: i64 = 1_531_143_000;
const W2: i64 = 1_531_144_800;
const L2: i64 = 1_531_146_600;

#[test]
fn linux_canary() {
    let parent = std::env::temp_dir().join(format!("af-canary-{}", std::process::id()));
    let win = parent.join("win-sample");
    let lin = parent.join("rootfs");
    write(
        &win,
        "Windows/System32/config/SYSTEM",
        &hive(&["MountedDevices", "Select"], W1),
    );
    write(
        &win,
        "Users/admin/NTUSER.DAT",
        &hive(&["Control Panel", "Environment", "Software"], W2),
    );
    write(
        &lin,
        "etc/os-release",
        b"PRETTY_NAME=\"Debian GNU/Linux 9 (stretch)\"\n",
    );
    write(&lin, "etc/hostname", b"logserver\n");
    write(
        &lin,
        "etc/passwd",
        b"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n",
    );
    write(
        &lin,
        "var/log/wtmp",
        &af_fmt_utmp::build_test_file(
            400,
            &[
                (7, "admin", "pts/0", "192.168.2.57", L1, 500_000),
                (8, "", "pts/0", "", L2, 0),
            ],
        ),
    );
    write(&lin, "home/Foo", b"upper");
    let case = parent.join("case");
    let c = case.to_str().unwrap();
    af(&["project", "new", c]);
    af(&["source", "add", c, win.to_str().unwrap()]);
    af(&["source", "add", c, lin.to_str().unwrap()]);
    af(&["run", c]);
    let db = Store::open_read_only(&case.join("project.duckdb")).unwrap();
    let q = |sql: &str| -> Vec<Vec<String>> {
        let mut stmt = db.connection().prepare(sql).unwrap();
        let n = stmt.column_count();
        stmt.query_map([], |r| {
            (0..n)
                .map(|i| {
                    r.get::<_, duckdb::types::Value>(i)
                        .map(|v| format!("{v:?}"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    };

    // 2. Both systems, with their IDs filterable.
    let systems = q("SELECT family, label, id::VARCHAR FROM systems ORDER BY family");
    assert_eq!(systems.len(), 2, "{systems:?}");
    assert!(systems[0][0].contains("linux") && systems[0][1].contains("logserver"));
    assert!(systems[1][0].contains("windows"));
    let per_system = q(
        "SELECT s.family, count(e.id) FROM systems s LEFT JOIN events e ON e.system = s.id \
         GROUP BY s.family ORDER BY s.family",
    );
    assert_eq!(
        per_system[0][1], "BigInt(2)",
        "linux: two login records, {per_system:?}"
    );
    assert_eq!(
        per_system[1][1], "BigInt(2)",
        "windows: two hive times, {per_system:?}"
    );

    // 3. Foo and foo: two files on the Linux root (on a Linux host), one name on Windows.
    if cfg!(target_os = "linux") {
        write(&lin, "home/foo", b"lower");
        let vol = af_host::folder::FolderVolume::new(af_core::system::VolumeId(1), &lin);
        let home: Vec<_> = vol
            .files()
            .unwrap()
            .into_iter()
            .filter(|f| f.path.names()[0] == Name::from_bytes(b"home"))
            .collect();
        assert_eq!(home.len(), 2, "Foo and foo stay two files");
    }
    let windows = |text: &str| {
        ViewPath::parse(
            text,
            PathStyle {
                separator: '\\',
                case: CasePolicy::Insensitive,
            },
            NameKind::Utf16,
        )
        .unwrap()
    };
    let mut idx = PathIndex::new(CasePolicy::Insensitive);
    idx.insert(windows("\\Users\\admin\\NTUSER.DAT"), ());
    assert_eq!(idx.get(&windows("\\USERS\\Admin\\ntuser.dat")).len(), 1);
    let mut exact = PathIndex::new(CasePolicy::Exact);
    let linux = |t: &str| {
        ViewPath::parse(
            t,
            PathStyle {
                separator: '/',
                case: CasePolicy::Exact,
            },
            NameKind::Bytes,
        )
        .unwrap()
    };
    exact.insert(linux("/home/Foo"), ());
    assert!(exact.get(&linux("/home/foo")).is_empty());

    // 4. A non-UTF-8 name through the stored form: the locator text in the artifacts table.
    let raw = ViewPath::new(vec![
        Name::from_bytes(b"home"),
        Name::from_bytes(b"caf\xe9.txt"),
    ]);
    let stored = af_store::run::folder_locator_path(&raw);
    assert_eq!(stored, "home/caf\\xe9.txt");
    let back = ViewPath::parse(
        &stored,
        PathStyle {
            separator: '/',
            case: CasePolicy::Exact,
        },
        NameKind::Bytes,
    )
    .unwrap();
    assert_eq!(
        back.names()[1],
        Name::from_bytes(b"caf\xe9.txt"),
        "same bytes"
    );

    // 5. User keys from both systems in one query, kept apart by system and scheme.
    let keys = q(
        "SELECT s.family, f.kind, f.subject FROM facts f JOIN systems s ON s.id = f.system \
         WHERE f.kind IN ('unix.user', 'windows.user_profile') ORDER BY 1, 2, 3",
    );
    let flat: Vec<String> = keys.iter().map(|r| r.join(" ")).collect();
    assert_eq!(keys.len(), 3, "{flat:?}");
    assert!(
        flat[0].contains("linux") && flat[0].contains("unix.user") && flat[0].contains("\"0\"")
    );
    assert!(flat[1].contains("linux") && flat[1].contains("\"1000\""));
    assert!(
        flat[2].contains("windows")
            && flat[2].contains("windows.user_profile")
            && flat[2].contains("\"admin\"")
    );
    // Linux user 1000 is called admin, as is the Windows profile; they stay two user keys.
    let joined = q(
        "SELECT count(*) FROM facts a JOIN facts b ON a.subject = b.subject AND a.system = b.system \
         AND a.kind = b.kind WHERE a.kind IN ('unix.user', 'windows.user_profile') AND a.id <> b.id",
    );
    assert_eq!(joined[0][0], "BigInt(0)");

    // 6. One timeline across both systems, sorted by ts, raw values as stored in the evidence.
    let timeline = q(
        "SELECT s.family, e.raw_encoding, e.raw_i64 FROM events e JOIN systems s ON s.id = e.system \
         ORDER BY e.ts NULLS LAST, e.id",
    );
    let fams: Vec<&str> = timeline
        .iter()
        .map(|r| if r[0].contains("windows") { "W" } else { "L" })
        .collect();
    assert_eq!(fams, ["W", "L", "W", "L"], "{timeline:?}");
    let w1 = format!("BigInt({})", W1 * TICKS_PER_SEC + UNIX_EPOCH_TICKS);
    let l1 = format!("BigInt({})", L1 * 1_000_000_000 + 500_000_000);
    assert!(
        timeline[0][1].contains("ticks_1601") && timeline[0][2] == w1,
        "{timeline:?}"
    );
    assert!(
        timeline[1][1].contains("unix_ns") && timeline[1][2] == l1,
        "{timeline:?}"
    );

    drop(db);
    std::fs::remove_dir_all(&parent).unwrap();
}
