//! I22: one Windows tree added as a folder, a zip and a tar gives the same system, the same
//! indexed hives (kind, path and SHA-256) and the same events. The zip is made by Python's
//! `zipfile`, the tar by the system `tar`; each is skipped when its tool is missing.

use af_store::Store;
use std::collections::BTreeSet;
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

fn write(base: &Path, path: &str, data: &[u8]) {
    std::fs::create_dir_all(base.join(path).parent().unwrap()).unwrap();
    std::fs::write(base.join(path), data).unwrap();
}

/// (kind, path below the source, SHA-256) of every indexed artifact, and the number of events.
fn added(parent: &Path, name: &str, source: &Path) -> (BTreeSet<(String, String, String)>, i64) {
    let case = parent.join(name);
    let c = case.to_str().unwrap();
    af(&["project", "new", c]);
    let out = af(&["source", "add", c, source.to_str().unwrap()]);
    assert!(out.contains("system "), "{out}");
    af(&["run", c]);
    let p = af_store::project::Project::open_read_only(&case, std::time::Duration::from_secs(5))
        .unwrap();
    let hives = p
        .store
        .artifacts()
        .unwrap()
        .all()
        .map(|a| {
            (
                a.kind.as_str().to_string(),
                a.locator.steps().last().unwrap().id.clone(),
                a.sha256.clone(),
            )
        })
        .collect();
    drop(p);
    let db = Store::open_read_only(&case.join("project.duckdb")).unwrap();
    let events: i64 = db
        .connection()
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    (hives, events)
}

fn tool(names: &[&'static str]) -> Option<&'static str> {
    names.iter().copied().find(|p| {
        Command::new(p)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

#[test]
fn a_zip_and_a_tar_give_the_same_hives_as_the_folder() {
    let parent = std::env::temp_dir().join(format!("af-archive-{}", std::process::id()));
    let tree = parent.join("collection");
    write(
        &tree,
        "Windows/System32/config/SYSTEM",
        &af_fmt_regf::build_test_hive(&["MountedDevices", "Select"], "lh"),
    );
    write(
        &tree,
        "Windows/System32/config/SOFTWARE",
        &af_fmt_regf::build_test_hive(&["Microsoft"], "lh"),
    );
    write(
        &tree,
        "Users/admin/NTUSER.DAT",
        &af_fmt_regf::build_test_hive(&["Control Panel", "Software"], "lh"),
    );
    let folder = added(&parent, "from-folder", &tree);
    assert_eq!(folder.0.len(), 3, "{:?}", folder.0);
    assert!(folder.1 > 0);

    if let Some(py) = tool(&["python3", "python"]) {
        let zip = parent.join("collection.zip");
        let ok = Command::new(py)
            .current_dir(&tree)
            .args(["-I", "-m", "zipfile", "-c"])
            .arg(&zip)
            .args(["Windows", "Users"])
            .status()
            .unwrap();
        assert!(ok.success());
        assert_eq!(added(&parent, "from-zip", &zip), folder, "zip");
    }
    if tool(&["tar"]).is_some() {
        let tar = parent.join("collection.tar");
        let ok = Command::new("tar")
            .arg("-cf")
            .arg(&tar)
            .arg("-C")
            .arg(&tree)
            .arg(".")
            .status()
            .unwrap();
        assert!(ok.success());
        assert_eq!(added(&parent, "from-tar", &tar), folder, "tar");
    }
    std::fs::remove_dir_all(&parent).ok();
}
