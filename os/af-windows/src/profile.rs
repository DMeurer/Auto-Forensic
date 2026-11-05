//! The Windows profile, a stub so far (piece F10).
//!
//! - **Detect:** a volume with `Windows\System32\config\SYSTEM` holds a Windows system, which
//!   claims that volume. Claiming its other partitions needs `MountedDevices` from the SYSTEM
//!   hive, which comes with the registry capability (F11) and the registry plugins.
//! - **Views:** one view with backslashes that ignores case. The system volume is `C:`; any
//!   further claimed volumes follow as `D:`, `E:` and so on, until the real drive letters can be
//!   read from the registry.
//! - **Identity:** the computer name lives in the SYSTEM hive, so the stub reports that it
//!   can't tell yet.

use af_core::path::{CasePolicy, PathStyle};
use af_core::profile::{Identity, OsProfile, system_volumes};
use af_core::system::{
    Detected, Detector, Family, MemVolume, Mount, System, View, ViewId, VolumeProbe,
};

/// The file whose presence marks a Windows system volume.
pub const MARKER: &str = "Windows/System32/config/SYSTEM";

/// The Windows profile.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsProfile;

impl Detector for WindowsProfile {
    fn detect(&self, volumes: &[&dyn VolumeProbe]) -> Vec<Detected> {
        let marker = MemVolume::path(MARKER);
        volumes
            .iter()
            .filter(|v| v.exists(&marker))
            .map(|v| Detected {
                family: Family::Windows,
                volumes: vec![v.id()],
                label: None,
                parent_volume: None,
                reason: "Windows\\System32\\config\\SYSTEM exists".into(),
            })
            .collect()
    }
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

    fn identity(&self, _system: &System, _volumes: &[&dyn VolumeProbe]) -> Identity {
        Identity {
            note: Some(
                "the computer name is in the SYSTEM hive; it needs the registry capability (F11)"
                    .into(),
            ),
            ..Identity::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let (systems, identities) = build_systems(&[&os, &data], &profiles(), sid, vid);
        let fams: Vec<&Family> = systems.iter().map(|s| &s.family).collect();
        assert_eq!(fams, [&Family::None, &Family::Windows]);

        let win = &systems[1];
        let view = &win.views[0];
        assert_eq!(view.style.separator, '\\');
        assert_eq!(view.style.case, CasePolicy::Insensitive);
        assert_eq!(view.mounts[0].point, "C:");
        assert_eq!(view.mounts[0].volume, os.id);
        assert!(identities[1].note.as_deref().unwrap().contains("F11"));
        // The data partition isn't claimed yet, so it is its own none system.
        assert_eq!(systems[0].label.as_deref(), Some("DATA"));
    }

    #[test]
    fn stick_without_windows_gives_only_none() {
        let stick = MemVolume::new(9, &["DCIM/100CANON/IMG_0001.JPG"]);
        let (sid, vid) = counters();
        let (systems, _) = build_systems(&[&stick], &profiles(), sid, vid);
        assert_eq!(systems.len(), 1);
        assert_eq!(systems[0].family, Family::None);
        assert_eq!(systems[0].views[0].style.separator, '/');
    }

    #[test]
    fn two_windows_volumes_give_two_systems_each_with_c() {
        let a = MemVolume::new(1, &[MARKER]);
        let b = MemVolume::new(2, &[MARKER]);
        let (sid, vid) = counters();
        let (systems, _) = build_systems(&[&a, &b], &profiles(), sid, vid);
        assert_eq!(systems.len(), 2);
        for s in &systems {
            assert_eq!(s.family, Family::Windows);
            assert_eq!(s.views[0].mounts[0].point, "C:");
        }
    }
}
