//! The Windows profile, a stub so far (piece F10).
//!
//! - **Detect:** a volume with `Windows\System32\config\SYSTEM` holds a Windows system, which
//!   claims that volume, and every recovery partition of the same source (a volume with
//!   `Recovery\WindowsRE`), so the recovery files stay with their system (I23). Claiming its
//!   other partitions needs `MountedDevices` from the SYSTEM hive, which comes with the registry
//!   capability (F11) and the registry plugins.
//! - **Views:** one view with backslashes that ignores case. The system volume is `C:`; any
//!   further claimed volumes follow as `D:`, `E:` and so on, until the real drive letters can be
//!   read from the registry.
//! - **Identity:** the computer name from the SYSTEM hive, through the registry capability
//!   (F11). Without a registry, or without the value, it says so.

use crate::registry::{computer_name, current_control_set, time_zone};
use af_core::capability::Capabilities;
use af_core::names::Kind;
use af_core::path::ViewPath;
use af_core::path::{CasePolicy, PathStyle};
use af_core::profile::{Identity, OsProfile, system_volumes};
use af_core::system::{
    Detected, Detector, Family, MemVolume, Mount, System, View, ViewId, VolumeId, VolumeProbe,
};

/// The file whose presence marks a Windows system volume.
pub const MARKER: &str = "Windows/System32/config/SYSTEM";

/// The Windows profile.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsProfile;

impl Detector for WindowsProfile {
    fn detect(&self, volumes: &[&dyn VolumeProbe]) -> Vec<Detected> {
        let marker = MemVolume::path(MARKER);
        let recovery = MemVolume::path("Recovery/WindowsRE");
        let recoveries: Vec<VolumeId> = volumes
            .iter()
            .filter(|v| v.exists(&recovery) && !v.exists(&marker))
            .map(|v| v.id())
            .collect();
        volumes
            .iter()
            .filter(|v| v.exists(&marker))
            .map(|v| Detected {
                family: Family::Windows,
                volumes: [v.id()]
                    .into_iter()
                    .chain(recoveries.iter().copied())
                    .collect(),
                label: None,
                parent_volume: None,
                reason: "Windows\\System32\\config\\SYSTEM exists".into(),
            })
            .collect()
    }
}

/// `rest` (names with `/` between) below `base`.
fn below(base: &ViewPath, rest: &str) -> ViewPath {
    ViewPath::new(
        base.names()
            .iter()
            .chain(MemVolume::path(rest).names())
            .cloned()
            .collect(),
    )
}

impl OsProfile for WindowsProfile {
    fn family(&self) -> Family {
        Family::Windows
    }

    fn build_views(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
        new_id: &mut dyn FnMut() -> ViewId,
    ) -> Vec<View> {
        let mounts = system_volumes(system, volumes)
            .iter()
            .zip('C'..='Z')
            .map(|(v, letter)| Mount {
                point: format!("{letter}:"),
                volume: v.id(),
            })
            .collect();
        vec![View {
            id: new_id(),
            system: system.id,
            style: PathStyle {
                separator: '\\',
                case: CasePolicy::Insensitive,
            },
            mounts,
        }]
    }

    /// On the system volume: the config hives, Amcache, each user's NTUSER.DAT and UsrClass.dat
    /// (also of the service profiles), every hive's transaction logs, the event logs and the
    /// Prefetch files. Names match by the volume's case rules.
    fn index(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
    ) -> Vec<(VolumeId, ViewPath, Kind)> {
        let Some(vol) = system_volumes(system, volumes).into_iter().next() else {
            return Vec::new();
        };
        let kind = |k: &str| Kind::new(k).expect("valid kind");
        let mut found = Vec::new();
        // A hive and its transaction logs: `<name>.LOG1` and `.LOG2` beside it, in any letter
        // case (LoneWolf has `ntuser.dat.LOG1` beside `NTUSER.DAT`).
        let mut known = |path: ViewPath, k: &str| {
            if !vol.exists(&path) {
                return;
            }
            if let (Some(dir), Some(name)) = (path.parent(), path.names().last()) {
                let base = name.display().to_lowercase();
                for n in vol.list(&dir) {
                    let l = n.display().to_lowercase();
                    if l == format!("{base}.log1") || l == format!("{base}.log2") {
                        found.push((vol.id(), dir.join(n), kind("windows.hive.log")));
                    }
                }
            }
            found.push((vol.id(), path, kind(k)));
        };
        for (file, k) in [
            ("SYSTEM", "windows.hive.system"),
            ("SOFTWARE", "windows.hive.software"),
            ("SAM", "windows.hive.sam"),
            ("SECURITY", "windows.hive.security"),
            ("DEFAULT", "windows.hive.default"),
        ] {
            known(
                MemVolume::path(&format!("Windows/System32/config/{file}")),
                k,
            );
        }
        known(
            MemVolume::path("Windows/AppCompat/Programs/Amcache.hve"),
            "windows.hive.amcache",
        );
        let users = MemVolume::path("Users");
        for user in vol.list(&users) {
            let home = users.join(user);
            known(below(&home, "NTUSER.DAT"), "windows.hive.ntuser");
            known(
                below(&home, "AppData/Local/Microsoft/Windows/UsrClass.dat"),
                "windows.hive.usrclass",
            );
        }
        for home in [
            "Windows/System32/config/systemprofile",
            "Windows/ServiceProfiles/LocalService",
            "Windows/ServiceProfiles/NetworkService",
        ] {
            known(
                below(&MemVolume::path(home), "NTUSER.DAT"),
                "windows.hive.ntuser",
            );
        }
        // X3, the user's choice: shortcuts in the places users make and use them, anywhere
        // below each profile folder and in the shared Start Menu.
        let mut tops: Vec<ViewPath> = vol
            .list(&users)
            .into_iter()
            .map(|u| users.join(u))
            .collect();
        tops.push(MemVolume::path("ProgramData/Microsoft/Windows/Start Menu"));
        let is_link = |n: &str| n.to_lowercase().ends_with(".lnk");
        for top in tops {
            files_below(vol, top, 0, &is_link, &mut |p| {
                found.push((vol.id(), p, kind("windows.lnk")))
            });
        }
        // X4: scheduled tasks, one XML file per task, in folders by task path.
        files_below(
            vol,
            MemVolume::path("Windows/System32/Tasks"),
            0,
            &|_| true,
            &mut |p| found.push((vol.id(), p, kind("windows.task"))),
        );
        // X4: the Recycle Bin's `$I` files, one folder per user SID.
        let bin = MemVolume::path("$Recycle.Bin");
        for sid in vol.list(&bin) {
            let dir = bin.join(sid);
            for name in vol.list(&dir) {
                if name.display().to_lowercase().starts_with("$i") {
                    found.push((vol.id(), dir.join(name), kind("windows.recyclebin.info")));
                }
            }
        }
        // Listed names exist, so they skip the lookup.
        for (dir, ext, k) in [
            ("Windows/System32/winevt/Logs", ".evtx", "windows.evtx"),
            ("Windows/Prefetch", ".pf", "windows.prefetch"),
        ] {
            let dir = MemVolume::path(dir);
            for name in vol.list(&dir) {
                if name.display().to_lowercase().ends_with(ext) {
                    found.push((vol.id(), dir.join(name), kind(k)));
                }
            }
        }
        found
    }

    /// The machine hives, with their logs replayed.
    fn registry(
        &self,
        artifacts: &[af_core::artifact::Artifact],
        opener: &dyn af_core::runner::Opener,
    ) -> (Option<Box<dyn af_core::capability::Registry>>, Vec<String>) {
        let (reg, notes) = crate::registry::HiveRegistry::from_artifacts(artifacts, opener);
        (
            reg.map(|r| Box::new(r) as Box<dyn af_core::capability::Registry>),
            notes,
        )
    }

    fn identity(
        &self,
        _system: &System,
        _volumes: &[&dyn VolumeProbe],
        caps: &Capabilities<'_>,
    ) -> Identity {
        let fact = |k: &str, v: String| (Kind::new(k).expect("valid kind"), v);
        // R6: the zone says so when it can't be known, so a local time is never read as UTC.
        let unknown_zone = |why: &str| fact("windows.time_zone", format!("unknown ({why})"));
        let Some(reg) = caps.registry else {
            return Identity {
                facts: vec![unknown_zone("no SYSTEM hive")],
                note: Some("no registry: the computer name is in the SYSTEM hive".into()),
                ..Identity::default()
            };
        };
        let mut facts = vec![];
        let name = computer_name(reg);
        if let Some(n) = &name {
            facts.push(fact("windows.computer_name", n.clone()));
        }
        match current_control_set(reg) {
            Some(set) => facts.push(fact("windows.control_set", set)),
            None if reg.hives().contains(&crate::registry::system_hive()) => {
                facts.push(unknown_zone("SYSTEM has no current control set"))
            }
            None => facts.push(unknown_zone("no SYSTEM hive")),
        }
        if let Some(tz) = time_zone(reg) {
            facts.push(fact(
                "windows.time_zone",
                tz.name.clone().unwrap_or_else(|| "unnamed".into()),
            ));
            if let Some(off) = tz.offset() {
                facts.push(fact("windows.time_zone_offset", off));
            }
        } else if current_control_set(reg).is_some() {
            facts.push(unknown_zone("SYSTEM has no TimeZoneInformation"));
        }
        Identity {
            note: name
                .is_none()
                .then(|| "the SYSTEM hive has no computer name in its current control set".into()),
            label: name,
            facts,
        }
    }
}

/// Folder depth past which a walk stops: deeper means a loop (a junction a folder copy followed).
const MAX_WALK_DEPTH: usize = 32;

/// Every file below `dir` whose name `keep` accepts. A volume lists a file as an empty folder,
/// so a name with nothing below it is taken as a file; a path that doesn't open as one (an
/// empty folder) is dropped when the artifact is hashed.
fn files_below(
    vol: &dyn VolumeProbe,
    dir: ViewPath,
    depth: usize,
    keep: &dyn Fn(&str) -> bool,
    found: &mut dyn FnMut(ViewPath),
) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    for name in vol.list(&dir) {
        let text = name.display();
        let path = dir.join(name);
        if vol.list(&path).is_empty() {
            if keep(&text) {
                found(path);
            }
        } else {
            files_below(vol, path, depth + 1, keep, found);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::system_with_name;
    use af_core::ids::SystemId;
    use af_core::path::CasePolicy;
    use af_core::profile::{NoneProfile, build_systems};

    fn counters() -> (impl FnMut() -> SystemId, impl FnMut() -> ViewId) {
        let (mut s, mut v) = (0, 0);
        (
            move || {
                s += 1;
                SystemId(s)
            },
            move || {
                v += 1;
                ViewId(v)
            },
        )
    }

    fn profiles() -> [&'static dyn OsProfile; 2] {
        [&WindowsProfile, &NoneProfile]
    }

    #[test]
    fn windows_disk_with_a_data_partition() {
        // The marker in another letter case still counts: NTFS ignores case.
        let os = MemVolume::new(1, &["WINDOWS/system32/Config/SYSTEM", "Users"]);
        let data = MemVolume::new(2, &["Projects"]).with_label("DATA");
        let (sid, vid) = counters();
        let (systems, identities) = build_systems(
            &[&os, &data],
            &profiles(),
            &Capabilities::default(),
            sid,
            vid,
        );
        let fams: Vec<&Family> = systems.iter().map(|s| &s.family).collect();
        assert_eq!(fams, [&Family::None, &Family::Windows]);

        let win = &systems[1];
        let view = &win.views[0];
        assert_eq!(view.style.separator, '\\');
        assert_eq!(view.style.case, CasePolicy::Insensitive);
        assert_eq!(view.mounts[0].point, "C:");
        assert_eq!(view.mounts[0].volume, os.id);
        assert!(
            identities[1]
                .note
                .as_deref()
                .unwrap()
                .contains("no registry")
        );
        // The data partition isn't claimed yet, so it is its own none system.
        assert_eq!(systems[0].label.as_deref(), Some("DATA"));
    }

    #[test]
    fn stick_without_windows_gives_only_none() {
        let stick = MemVolume::new(9, &["DCIM/100CANON/IMG_0001.JPG"]);
        let (sid, vid) = counters();
        let (systems, _) =
            build_systems(&[&stick], &profiles(), &Capabilities::default(), sid, vid);
        assert_eq!(systems.len(), 1);
        assert_eq!(systems[0].family, Family::None);
        assert_eq!(systems[0].views[0].style.separator, '/');
    }

    #[test]
    fn two_windows_volumes_give_two_systems_each_with_c() {
        let a = MemVolume::new(1, &[MARKER]);
        let b = MemVolume::new(2, &[MARKER]);
        let (sid, vid) = counters();
        let (systems, _) =
            build_systems(&[&a, &b], &profiles(), &Capabilities::default(), sid, vid);
        assert_eq!(systems.len(), 2);
        for s in &systems {
            assert_eq!(s.family, Family::Windows);
            assert_eq!(s.views[0].mounts[0].point, "C:");
        }
    }

    #[test]
    fn a_recovery_partition_belongs_to_the_windows_system() {
        let re = MemVolume::new(1, &["Recovery/WindowsRE", "Recovery/WindowsRE/Winre.wim"]);
        let os = MemVolume::new(2, &["Windows/System32/config/SYSTEM"]);
        let (sid, vid) = counters();
        let (systems, _) =
            build_systems(&[&re, &os], &profiles(), &Capabilities::default(), sid, vid);
        assert_eq!(systems.len(), 1, "{systems:?}");
        assert_eq!(systems[0].family, Family::Windows);
        assert_eq!(
            systems[0].volumes,
            [os.id, re.id],
            "the system volume first"
        );
        // Without Windows on the source, a recovery partition is just a volume.
        let (sid, vid) = counters();
        let (alone, _) = build_systems(&[&re], &profiles(), &Capabilities::default(), sid, vid);
        assert_eq!(alone[0].family, Family::None);
    }

    #[test]
    fn indexes_hives_event_logs_prefetch_and_shortcuts() {
        let os = MemVolume::new(
            1,
            &[
                "Windows/System32/config/SYSTEM",
                "Windows/System32/config/SYSTEM.LOG1",
                "Windows/System32/config/DEFAULT",
                "Windows/AppCompat/Programs/Amcache.hve",
                "Windows/System32/winevt/Logs/Security.evtx",
                "Windows/System32/winevt/Logs/System.EVTX",
                "Windows/Prefetch/CMD.EXE-0BD30981.pf",
                "Windows/Prefetch/Layout.ini",
                "Users/admin/NTUSER.DAT",
                "Users/admin/ntuser.dat.LOG2",
                "Users/admin/AppData/Local/Microsoft/Windows/UsrClass.dat",
                "Users/Public/Desktop/Edge.LNK",
                "Windows/ServiceProfiles/LocalService/NTUSER.DAT",
                "Users/admin/AppData/Roaming/Microsoft/Windows/Recent/key.lnk",
                "ProgramData/Microsoft/Windows/Start Menu/Programs/Paint.lnk",
                // Not where users make or use shortcuts (X3, the user's choice).
                "Windows/WinSxS/amd64_explorer-shortcuts/Paint.lnk",
                "Windows/ServiceProfiles/LocalService/Desktop/x.lnk",
                "$Recycle.Bin/S-1-5-21-1-1001/$I23A30B.docx",
                "$Recycle.Bin/S-1-5-21-1-1001/$R23A30B.docx",
                "$Recycle.Bin/S-1-5-21-1-1001/desktop.ini",
                "Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag",
                "Windows/System32/Tasks/Updater",
            ],
        );
        let (sid, vid) = counters();
        let (systems, _) = build_systems(&[&os], &profiles(), &Capabilities::default(), sid, vid);
        let mut got: Vec<(String, String)> = WindowsProfile
            .index(&systems[0], &[&os])
            .into_iter()
            .map(|(_, p, k)| {
                let style = PathStyle {
                    separator: '/',
                    case: CasePolicy::Exact,
                };
                let p = p.display(style).trim_start_matches('/').to_string();
                (k.as_str().to_string(), p)
            })
            .collect();
        got.sort();
        let want = [
            ("windows.evtx", "Windows/System32/winevt/Logs/Security.evtx"),
            ("windows.evtx", "Windows/System32/winevt/Logs/System.EVTX"),
            (
                "windows.hive.amcache",
                "Windows/AppCompat/Programs/Amcache.hve",
            ),
            ("windows.hive.default", "Windows/System32/config/DEFAULT"),
            ("windows.hive.log", "Users/admin/ntuser.dat.LOG2"),
            ("windows.hive.log", "Windows/System32/config/SYSTEM.LOG1"),
            ("windows.hive.ntuser", "Users/admin/NTUSER.DAT"),
            (
                "windows.hive.ntuser",
                "Windows/ServiceProfiles/LocalService/NTUSER.DAT",
            ),
            ("windows.hive.system", "Windows/System32/config/SYSTEM"),
            (
                "windows.hive.usrclass",
                "Users/admin/AppData/Local/Microsoft/Windows/UsrClass.dat",
            ),
            (
                "windows.lnk",
                "ProgramData/Microsoft/Windows/Start Menu/Programs/Paint.lnk",
            ),
            ("windows.lnk", "Users/Public/Desktop/Edge.LNK"),
            (
                "windows.lnk",
                "Users/admin/AppData/Roaming/Microsoft/Windows/Recent/key.lnk",
            ),
            ("windows.prefetch", "Windows/Prefetch/CMD.EXE-0BD30981.pf"),
            (
                "windows.recyclebin.info",
                "$Recycle.Bin/S-1-5-21-1-1001/$I23A30B.docx",
            ),
            (
                "windows.task",
                "Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag",
            ),
            ("windows.task", "Windows/System32/Tasks/Updater"),
        ];
        assert_eq!(got, want.map(|(k, p)| (k.to_string(), p.to_string())));
    }

    #[test]
    fn identity_from_the_registry() {
        let os = MemVolume::new(1, &[MARKER]);
        let reg = system_with_name("DESKTOP-ICH");
        let caps = Capabilities {
            registry: Some(&reg),
        };
        let (sid, vid) = counters();
        let (systems, identities) = build_systems(&[&os], &profiles(), &caps, sid, vid);
        assert_eq!(systems[0].label.as_deref(), Some("DESKTOP-ICH"));
        assert_eq!(identities[0].facts[0].0.as_str(), "windows.computer_name");
    }
}
