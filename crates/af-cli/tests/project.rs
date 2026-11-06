//! `af project new` and `af project info`, run as the real binary (F19).

use std::process::Command;

fn af(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_af"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn project_new_then_info() {
    let parent = std::env::temp_dir().join(format!("af-cli-test-{}", std::process::id()));
    let dir = parent.join("case-7");
    let d = dir.to_str().unwrap();
    let (ok, out, err) = af(&["project", "new", d, "--name", "Case 7"]);
    assert!(ok, "{err}");
    assert!(out.contains("Case 7"));
    let (ok, out, err) = af(&["project", "info", d]);
    assert!(ok, "{err}");
    assert!(out.contains("name:     Case 7"), "{out}");
    assert!(out.contains(" UTC"), "{out}");
    // A second `new` into the same folder is refused.
    let (ok, _, err) = af(&["project", "new", d]);
    assert!(!ok);
    assert!(err.contains("isn't empty"), "{err}");
    std::fs::remove_dir_all(&parent).unwrap();
}
