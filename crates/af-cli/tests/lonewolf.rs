//! I23 on LoneWolf (the shared-folder copy, see `xtask/evidence.tsv`): the image gives its
//! Windows system, and every hive, event log and Prefetch file is indexed, as many as the
//! stage-1 `fls` listing (`~/af-stage1/lonewolf/fls.txt`) shows. The source goes in through the
//! store, because `af source add` hashes and verifies all 13.5 GB first. Skips when the image
//! is missing.

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
    assert_eq!(count("windows.prefetch"), 161);
    for (k, n) in [
        ("windows.hive.system", 1),
        ("windows.hive.software", 1),
        ("windows.hive.sam", 1),
        ("windows.hive.security", 1),
        ("windows.hive.default", 1),
        ("windows.hive.amcache", 1),
        ("windows.hive.ntuser", 2),
        ("windows.hive.usrclass", 1),
    ] {
        assert_eq!(count(k), n, "{k}: {:?}", kinds.get(k));
    }
    let ntuser = &kinds["windows.hive.ntuser"];
    assert!(
        ntuser.contains(&"Users/jcloudy/NTUSER.DAT".to_string()),
        "{ntuser:?}"
    );
}
