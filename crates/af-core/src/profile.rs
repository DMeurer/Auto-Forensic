//! OS profiles (piece F10): what core needs from each operating system family.
//!
//! A profile detects its systems on a source's volumes, builds the views of a system (path
//! style and where each volume appears), and finds the system's identity (a name for people
//! and identifying facts). Core ships only the `none` profile, for volumes without an operating
//! system. The Windows profile lives in `os/af-windows`.

use crate::ids::SystemId;
use crate::names::Kind;
use crate::path::{CasePolicy, PathStyle};
use crate::system::{
    Detected, Detector, Family, Mount, System, View, ViewId, VolumeProbe, detect_systems,
    to_systems,
};

/// Who a system is, as far as its profile can tell.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    /// A name for people, such as the computer name or a volume label.
    pub label: Option<String>,
    /// Identifying values, such as `windows.computer_name` or `volume.label`.
    pub facts: Vec<(Kind, String)>,
    /// What the profile couldn't find out, and why.
    pub note: Option<String>,
}

/// One operating system family.
pub trait OsProfile: Detector {
    fn family(&self) -> Family;

    /// The views of a system this profile detected.
    fn build_views(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
        new_id: &mut dyn FnMut() -> ViewId,
    ) -> Vec<View>;

    /// The identity of a system this profile detected.
    fn identity(&self, system: &System, volumes: &[&dyn VolumeProbe]) -> Identity;
}

/// The profile for a family, if one is given.
pub fn profile_for<'a>(
    family: &Family,
    profiles: &[&'a dyn OsProfile],
) -> Option<&'a dyn OsProfile> {
    profiles.iter().copied().find(|p| &p.family() == family)
}

/// Detects the systems on a source's volumes and builds their views and identities. Systems of a
/// family without a profile keep no views. IDs come from the two generators.
pub fn build_systems(
    volumes: &[&dyn VolumeProbe],
    profiles: &[&dyn OsProfile],
    new_system_id: impl FnMut() -> SystemId,
    mut new_view_id: impl FnMut() -> ViewId,
) -> (Vec<System>, Vec<Identity>) {
    let detectors: Vec<&dyn Detector> = profiles.iter().map(|p| *p as &dyn Detector).collect();
    let detected: Vec<Detected> = detect_systems(volumes, &detectors);
    let mut systems = to_systems(&detected, new_system_id);
    let mut identities = Vec::with_capacity(systems.len());
    for system in &mut systems {
        let Some(profile) = profile_for(&system.family, profiles) else {
            identities.push(Identity {
                note: Some(format!("no profile for family {}", system.family.as_str())),
                ..Identity::default()
            });
            continue;
        };
        system.views = profile.build_views(system, volumes, &mut new_view_id);
        let identity = profile.identity(system, volumes);
        if system.label.is_none() {
            system.label = identity.label.clone();
        }
        identities.push(identity);
    }
    (systems, identities)
}

/// The volumes of `system`, in its order, from the source's probes.
pub fn system_volumes<'a>(
    system: &System,
    volumes: &[&'a dyn VolumeProbe],
) -> Vec<&'a dyn VolumeProbe> {
    system
        .volumes
        .iter()
        .filter_map(|id| volumes.iter().copied().find(|v| v.id() == *id))
        .collect()
}

/// Volumes without an operating system, such as a data stick.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoneProfile;

impl Detector for NoneProfile {
    /// Claims nothing: the `none` system is made of the volumes no other profile claimed.
    fn detect(&self, _volumes: &[&dyn VolumeProbe]) -> Vec<Detected> {
        Vec::new()
    }
}

impl OsProfile for NoneProfile {
    fn family(&self) -> Family {
        Family::None
    }

    /// One view with `/` between names. It ignores case only if every volume does. Each volume
    /// appears under its label, or as `volume1`, `volume2` and so on.
    fn build_views(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
        new_id: &mut dyn FnMut() -> ViewId,
    ) -> Vec<View> {
        let vols = system_volumes(system, volumes);
        let case = if !vols.is_empty() && vols.iter().all(|v| v.case() == CasePolicy::Insensitive) {
            CasePolicy::Insensitive
        } else {
            CasePolicy::Exact
        };
        let mounts = vols
            .iter()
            .enumerate()
            .map(|(i, v)| Mount {
                point: v.label().unwrap_or_else(|| format!("volume{}", i + 1)),
                volume: v.id(),
            })
            .collect();
        vec![View {
            id: new_id(),
            system: system.id,
            style: PathStyle {
                separator: '/',
                case,
            },
            mounts,
        }]
    }

    /// The volume labels, if any.
    fn identity(&self, system: &System, volumes: &[&dyn VolumeProbe]) -> Identity {
        let labels: Vec<String> = system_volumes(system, volumes)
            .iter()
            .filter_map(|v| v.label())
            .collect();
        let kind = Kind::new("volume.label").expect("valid kind");
        Identity {
            label: (!labels.is_empty()).then(|| labels.join(", ")),
            facts: labels.iter().map(|l| (kind.clone(), l.clone())).collect(),
            note: labels.is_empty().then(|| "no volume label".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::MemVolume;

    fn ids() -> (impl FnMut() -> SystemId, impl FnMut() -> ViewId) {
        let mut s = 0;
        let mut v = 0;
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

    #[test]
    fn none_profile_on_a_stick() {
        let a = MemVolume::new(1, &["DCIM"]).with_label("KINGSTON");
        let b = MemVolume::new(2, &["backup"]);
        let (sid, vid) = ids();
        let (systems, identities) = build_systems(&[&a, &b], &[&NoneProfile], sid, vid);
        assert_eq!(systems.len(), 1);
        let s = &systems[0];
        assert_eq!(s.family, Family::None);
        assert_eq!(s.label.as_deref(), Some("KINGSTON"));
        let view = &s.views[0];
        assert_eq!(view.style.case, CasePolicy::Insensitive);
        let points: Vec<&str> = view.mounts.iter().map(|m| m.point.as_str()).collect();
        assert_eq!(points, ["KINGSTON", "volume2"]);
        assert_eq!(identities[0].facts.len(), 1);
    }

    #[test]
    fn exact_volume_makes_the_view_exact() {
        let a = MemVolume::new(1, &["x"]);
        let b = MemVolume::new(2, &["y"]).with_case(CasePolicy::Exact);
        let (sid, vid) = ids();
        let (systems, identities) = build_systems(&[&a, &b], &[&NoneProfile], sid, vid);
        assert_eq!(systems[0].views[0].style.case, CasePolicy::Exact);
        assert_eq!(identities[0].label, None);
        assert_eq!(identities[0].note.as_deref(), Some("no volume label"));
    }

    #[test]
    fn family_without_a_profile_keeps_no_views() {
        let a = MemVolume::new(1, &["x"]);
        let (sid, vid) = ids();
        let (systems, identities) = build_systems(&[&a], &[], sid, vid);
        assert_eq!(systems[0].family, Family::None);
        assert!(systems[0].views.is_empty());
        assert!(identities[0].note.is_some());
    }
}
