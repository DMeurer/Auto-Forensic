//! The Windows profile, a stub so far (piece F10).
//!
//! - **Detect:** a volume with `Windows\System32\config\SYSTEM` holds a Windows system, which
//!   claims that volume. Claiming its other partitions needs `MountedDevices` from the SYSTEM
//!   hive, which comes with the registry capability (F11) and the registry plugins.
//! - **Views:** one view with backslashes that ignores case. The system volume is `C:`; any
//!   further claimed volumes follow as `D:`, `E:` and so on, until the real drive letters can be
//!   read from the registry.
//! - **Identity:** the computer name from the SYSTEM hive, through the registry capability
//!   (F11). Without a registry, or without the value, it says so.

use crate::registry::computer_name;
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

    /// The config hives on the system volume.
    fn index(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
    ) -> Vec<(VolumeId, ViewPath, Kind)> {
        let Some(vol) = system_volumes(system, volumes).into_iter().next() else {
            return Vec::new();
        };
        [
            ("SYSTEM", "windows.hive.system"),
            ("SOFTWARE", "windows.hive.software"),
            ("SAM", "windows.hive.sam"),
            ("SECURITY", "windows.hive.security"),
        ]
        .into_iter()
        .map(|(file, kind)| {
            (
                MemVolume::path(&format!("Windows/System32/config/{file}")),
                kind,
            )
        })
        .filter(|(p, _)| vol.exists(p))
        .map(|(p, kind)| (vol.id(), p, Kind::new(kind).expect("valid kind")))
        .collect()
    }

    fn identity(
        &self,
        _system: &System,
        _volumes: &[&dyn VolumeProbe],
        caps: &Capabilities<'_>,
    ) -> Identity {
        let Some(reg) = caps.registry else {
            return Identity {
                note: Some("no registry: the computer name is in the SYSTEM hive".into()),
                ..Identity::default()
            };
        };
        match computer_name(reg) {
            Some(name) => Identity {
                label: Some(name.clone()),
                facts: vec![(
                    Kind::new("windows.computer_name").expect("valid kind"),
                    name,
                )],
                note: None,
            },
            None => Identity {
                note: Some(
                    "the SYSTEM hive has no computer name in its current control set".into(),
                ),
                ..Identity::default()
            },
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
