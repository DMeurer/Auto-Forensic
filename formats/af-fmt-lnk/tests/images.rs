//! X3 on shortcut files copied out of the test images (`~/af-stage0/extract/lnk`, the exam
//! image's 108; `~/af-stage3/x3/lonewolf`, LoneWolf's 389 allocated ones); each check is
//! skipped where its copy isn't. LECmd agrees on every field it shows, except one LoneWolf
//! file whose MFT reference has sequence 0, which LECmd prints without a sequence
//! (`~/af-stage3/scripts/x3_compare.py`).

use std::path::{Path, PathBuf};

fn links(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().map(Result::unwrap) {
        let p = e.path();
        if p.is_dir() {
            links(&p, out);
        } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
            out.push(p);
        }
    }
}

fn all(rel: &str) -> Option<Vec<PathBuf>> {
    let d = PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel);
    let mut out = vec![];
    d.is_dir().then(|| links(&d, &mut out))?;
    Some(out)
}

#[test]
fn every_link_reads() {
    for (rel, count) in [
        ("af-stage0/extract/lnk", 108),
        ("af-stage3/x3/lonewolf", 389),
    ] {
        let Some(files) = all(rel) else { continue };
        assert_eq!(files.len(), count, "{rel}");
        for f in files {
            af_fmt_lnk::read(&std::fs::read(&f).unwrap()).unwrap_or_else(|e| panic!("{f:?}: {e}"));
        }
    }
}

#[test]
fn lonewolf_key_on_the_stick() {
    let Some(files) = all("af-stage3/x3/lonewolf") else {
        return;
    };
    let key = files
        .iter()
        .find(|f| f.ends_with("Recent/key.lnk"))
        .unwrap();
    let l = af_fmt_lnk::read(&std::fs::read(key).unwrap()).unwrap();
    assert_eq!(l.local_path.as_deref(), Some("D:\\key.txt"));
    let v = l.volume.unwrap();
    assert_eq!(
        (v.drive_type, v.serial, v.label.as_deref()),
        (2, 0x4C36_F4AC, Some("CloudLog")),
        "a removable volume"
    );
    assert_eq!(l.target_mft, Some((0x31_8200, 0)));
}
