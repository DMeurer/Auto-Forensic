//! Systems, views and system detection (piece F9).
//!
//! A source (an image, a device, loose files) can hold several systems: a dual-boot disk holds
//! two, a stick usually holds one with no operating system (`family = none`). Each system has
//! its own [`SystemId`] and one or more views, which are ways of seeing its files with a path
//! style (separator and case policy). A system may sit inside another, such as WSL inside
//! Windows; the `parent` column records that, and no discovery code exists for it yet.
//!
//! Detection runs every [`Detector`] over the volumes of one source. Each detection claims the
//! volumes it found, the first being the system volume. A volume may be claimed twice, for
//! example a data partition both systems of a dual boot use. All volumes no detector claims
//! form one more system with family `none`. The result never depends on detector order.

use crate::ids::SystemId;
use crate::path::{CasePolicy, Name, NameKind, PathStyle, ViewPath};
use std::collections::BTreeSet;

/// The operating system family of a system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    /// No operating system: a data volume or stick.
    None,
    Windows,
    Linux,
    MacOs,
    Android,
    Ios,
    /// Another family, by name.
    Other(String),
}

impl Family {
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Other(s) => s,
        }
    }
}

/// The ID of a volume within a source. How volumes are found is stage 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VolumeId(pub u128);

/// The ID of a view, unique within a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ViewId(pub u128);

impl ViewId {
    /// A new random ID (UUID version 4).
    pub fn new_random() -> Self {
        Self(uuid::Uuid::new_v4().as_u128())
    }
}

/// A way of seeing a system's files. The OS profile builds it (piece F10), for example a Windows
/// view that maps drive letters to volumes and ignores case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub id: ViewId,
    pub system: SystemId,
    pub style: PathStyle,
    pub mounts: Vec<Mount>,
}

/// Where a volume appears in a view. The point is the profile's business: a drive letter on
/// Windows, a mount path on Linux, a volume label on a stick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub point: String,
    pub volume: VolumeId,
}

/// A system in a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    pub id: SystemId,
    pub family: Family,
    /// A name for people, such as the computer name. Not unique.
    pub label: Option<String>,
    /// The system this one sits inside, such as Windows for a WSL distribution.
    pub parent: Option<SystemId>,
    /// The volumes it claims, the system volume first.
    pub volumes: Vec<VolumeId>,
    pub views: Vec<View>,
}

/// What a detector can ask of a volume while detecting.
pub trait VolumeProbe {
    fn id(&self) -> VolumeId;
    /// Whether a file or folder exists, by the volume's own case rules.
    fn exists(&self, path: &ViewPath) -> bool;
    /// The volume label, if the file system has one.
    fn label(&self) -> Option<String> {
        None
    }
    /// How the volume's file system compares names (FAT and NTFS ignore case, ext4 doesn't).
    fn case(&self) -> CasePolicy {
        CasePolicy::Exact
    }
    /// A small file's content, for profiles that read names and settings while detecting
    /// (`/etc/hostname`). `None` if absent or the volume can't be read this way.
    fn read(&self, _path: &ViewPath) -> Option<Vec<u8>> {
        None
    }
    /// The names directly inside a folder, for profiles that look for per-user files
    /// (`Users/<name>/NTUSER.DAT`). Empty if absent or the volume can't list.
    fn list(&self, _dir: &ViewPath) -> Vec<Name> {
        Vec::new()
    }
}

/// A folder of another volume seen as a volume of its own, such as a drive folder (`C`) of a
/// KAPE collection.
pub struct SubVolume<'a> {
    pub id: VolumeId,
    pub inner: &'a dyn VolumeProbe,
    pub root: ViewPath,
}

impl SubVolume<'_> {
    /// A path of this volume as a path of the inner one.
    pub fn full(&self, path: &ViewPath) -> ViewPath {
        ViewPath::new(
            self.root
                .names()
                .iter()
                .chain(path.names())
                .cloned()
                .collect(),
        )
    }
}

impl VolumeProbe for SubVolume<'_> {
    fn id(&self) -> VolumeId {
        self.id
    }
    fn exists(&self, path: &ViewPath) -> bool {
        self.inner.exists(&self.full(path))
    }
    fn case(&self) -> CasePolicy {
        self.inner.case()
    }
    fn read(&self, path: &ViewPath) -> Option<Vec<u8>> {
        self.inner.read(&self.full(path))
    }
    fn list(&self, dir: &ViewPath) -> Vec<Name> {
        self.inner.list(&self.full(dir))
    }
}

/// The folders at the top of a volume named by one drive letter (`C`, `d`), as a collection
/// tool such as KAPE writes them: each one is a drive of its own.
pub fn drive_folders(vol: &dyn VolumeProbe) -> Vec<Name> {
    vol.list(&ViewPath::default())
        .into_iter()
        .filter(|n| {
            let d = n.display();
            d.len() == 1
                && d.as_bytes()[0].is_ascii_alphabetic()
                && !vol.list(&ViewPath::new(vec![n.clone()])).is_empty()
        })
        .collect()
}

/// An in-memory volume that only knows which paths exist, for tests and fixtures. Paths are
/// written with `/` between names.
#[derive(Debug, Clone)]
pub struct MemVolume {
    pub id: VolumeId,
    pub paths: Vec<String>,
    /// Content for [`VolumeProbe::read`], by path.
    pub contents: Vec<(String, Vec<u8>)>,
    pub label: Option<String>,
    pub case: CasePolicy,
}

impl MemVolume {
    /// A case-insensitive volume (like FAT or NTFS) with the given paths.
    pub fn new(id: u128, paths: &[&str]) -> Self {
        Self {
            id: VolumeId(id),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            contents: Vec::new(),
            label: None,
            case: CasePolicy::Insensitive,
        }
    }

    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    /// Adds a file with content (and its path).
    pub fn with_file(mut self, path: &str, data: &[u8]) -> Self {
        self.paths.push(path.to_string());
        self.contents.push((path.to_string(), data.to_vec()));
        self
    }

    pub fn with_case(mut self, case: CasePolicy) -> Self {
        self.case = case;
        self
    }

    /// A path from text with `/` between names.
    pub fn path(text: &str) -> ViewPath {
        ViewPath::new(
            text.split('/')
                .filter(|n| !n.is_empty())
                .map(|n| Name::from_text(n, NameKind::Utf16))
                .collect(),
        )
    }
}

impl VolumeProbe for MemVolume {
    fn id(&self) -> VolumeId {
        self.id
    }
    fn exists(&self, path: &ViewPath) -> bool {
        let want = path.key(self.case);
        self.paths
            .iter()
            .any(|p| Self::path(p).key(self.case) == want)
    }
    fn label(&self) -> Option<String> {
        self.label.clone()
    }
    fn case(&self) -> CasePolicy {
        self.case
    }
    fn read(&self, path: &ViewPath) -> Option<Vec<u8>> {
        let want = path.key(self.case);
        self.contents
            .iter()
            .find(|(p, _)| Self::path(p).key(self.case) == want)
            .map(|(_, d)| d.clone())
    }
    fn list(&self, dir: &ViewPath) -> Vec<Name> {
        let (want, depth) = (dir.key(self.case), dir.names().len());
        let mut out: Vec<Name> = Vec::new();
        for p in self.paths.iter().map(|p| Self::path(p)) {
            if p.names().len() > depth
                && ViewPath::new(p.names()[..depth].to_vec()).key(self.case) == want
            {
                let n = &p.names()[depth];
                if !out.iter().any(|o| o.key(self.case) == n.key(self.case)) {
                    out.push(n.clone());
                }
            }
        }
        out
    }
}

/// One system found by a detector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Detected {
    pub family: Family,
    /// The volumes it claims, the system volume first. Never empty.
    pub volumes: Vec<VolumeId>,
    pub label: Option<String>,
    /// For a system inside another: the parent's system volume.
    pub parent_volume: Option<VolumeId>,
    /// Why the detector thinks so, for `af status` and `af explain`.
    pub reason: String,
}

/// Finds systems of one family on a source's volumes. It may return several, or none.
pub trait Detector {
    fn detect(&self, volumes: &[&dyn VolumeProbe]) -> Vec<Detected>;
}

/// All systems on a source's volumes: every detector's findings, plus one `none` system for the
/// volumes nobody claimed. Sorted, so detector order doesn't matter.
pub fn detect_systems(volumes: &[&dyn VolumeProbe], detectors: &[&dyn Detector]) -> Vec<Detected> {
    let mut found: Vec<Detected> = detectors
        .iter()
        .flat_map(|d| d.detect(volumes))
        .filter(|d| !d.volumes.is_empty())
        .collect();
    let claimed: BTreeSet<VolumeId> = found
        .iter()
        .flat_map(|d| d.volumes.iter().copied())
        .collect();
    let mut unclaimed: Vec<VolumeId> = volumes
        .iter()
        .map(|v| v.id())
        .filter(|id| !claimed.contains(id))
        .collect();
    unclaimed.sort();
    unclaimed.dedup();
    if !unclaimed.is_empty() {
        found.push(Detected {
            family: Family::None,
            volumes: unclaimed,
            label: None,
            parent_volume: None,
            reason: "no operating system claimed these volumes".into(),
        });
    }
    found.sort();
    found.dedup();
    found
}

/// Turns detections into systems with fresh IDs from `new_id`, linking each nested system to its
/// parent: the system whose system volume is its `parent_volume`. A parent that wasn't detected
/// is left unset.
pub fn to_systems(detected: &[Detected], mut new_id: impl FnMut() -> SystemId) -> Vec<System> {
    let mut systems: Vec<System> = detected
        .iter()
        .map(|d| System {
            id: new_id(),
            family: d.family.clone(),
            label: d.label.clone(),
            parent: None,
            volumes: d.volumes.clone(),
            views: Vec::new(),
        })
        .collect();
    for (i, d) in detected.iter().enumerate() {
        let Some(pv) = d.parent_volume else { continue };
        let parent = systems
            .iter()
            .enumerate()
            .find(|(j, s)| *j != i && s.volumes.first() == Some(&pv))
            .map(|(_, s)| s.id);
        systems[i].parent = parent;
    }
    systems
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(text: &str) -> ViewPath {
        MemVolume::path(text)
    }

    /// Finds a system by one marker file, like the real profiles will (F10).
    struct Marker {
        family: Family,
        marker: &'static str,
    }

    impl Detector for Marker {
        fn detect(&self, volumes: &[&dyn VolumeProbe]) -> Vec<Detected> {
            volumes
                .iter()
                .filter(|v| v.exists(&p(self.marker)))
                .map(|v| Detected {
                    family: self.family.clone(),
                    volumes: vec![v.id()],
                    label: None,
                    parent_volume: None,
                    reason: format!("{} exists", self.marker),
                })
                .collect()
        }
    }

    fn windows() -> Marker {
        Marker {
            family: Family::Windows,
            marker: "Windows/System32/config/SYSTEM",
        }
    }

    fn linux() -> Marker {
        Marker {
            family: Family::Linux,
            marker: "etc/os-release",
        }
    }

    fn families(found: &[Detected]) -> Vec<(&str, Vec<u128>)> {
        found
            .iter()
            .map(|d| (d.family.as_str(), d.volumes.iter().map(|v| v.0).collect()))
            .collect()
    }

    #[test]
    fn dual_boot_gives_two_systems() {
        let win = MemVolume::new(1, &["Windows/System32/config/SYSTEM", "Users"]);
        let lin = MemVolume::new(2, &["etc/os-release", "home"]).with_case(CasePolicy::Exact);
        let vols: [&dyn VolumeProbe; 2] = [&win, &lin];
        let found = detect_systems(&vols, &[&windows(), &linux()]);
        assert_eq!(families(&found), [("windows", vec![1]), ("linux", vec![2])]);
        // Detector order doesn't matter.
        assert_eq!(detect_systems(&vols, &[&linux(), &windows()]), found);
    }

    #[test]
    fn data_stick_gives_family_none() {
        // Two data partitions on one stick: one system, family none.
        let a = MemVolume::new(7, &["DCIM", "photo.jpg"]);
        let b = MemVolume::new(8, &["backup"]);
        let found = detect_systems(&[&a, &b], &[&windows(), &linux()]);
        assert_eq!(families(&found), [("none", vec![7, 8])]);
        let systems = to_systems(&found, || SystemId(42));
        assert_eq!(systems[0].family, Family::None);
        assert_eq!(systems[0].volumes, [VolumeId(7), VolumeId(8)]);
    }

    #[test]
    fn os_volume_plus_unclaimed_data_volume() {
        let win = MemVolume::new(1, &["Windows/System32/config/SYSTEM"]);
        let data = MemVolume::new(3, &["Projects"]);
        let found = detect_systems(&[&win, &data], &[&windows()]);
        assert_eq!(families(&found), [("none", vec![3]), ("windows", vec![1])]);
    }

    #[test]
    fn no_volumes_and_no_detectors() {
        assert!(detect_systems(&[], &[&windows()]).is_empty());
        let v = MemVolume::new(1, &["Windows/System32/config/SYSTEM"]);
        assert_eq!(families(&detect_systems(&[&v], &[])), [("none", vec![1])]);
    }

    /// A WSL-like system inside Windows: its parent is the Windows system.
    struct Nested;

    impl Detector for Nested {
        fn detect(&self, volumes: &[&dyn VolumeProbe]) -> Vec<Detected> {
            volumes
                .iter()
                .filter(|v| v.exists(&p("ext4.vhdx")))
                .map(|_| Detected {
                    family: Family::Linux,
                    volumes: vec![VolumeId(100)],
                    label: Some("Ubuntu".into()),
                    parent_volume: Some(VolumeId(1)),
                    reason: "a WSL disk image".into(),
                })
                .collect()
        }
    }

    #[test]
    fn nested_system_gets_its_parent() {
        let win = MemVolume::new(1, &["Windows/System32/config/SYSTEM", "ext4.vhdx"]);
        let found = detect_systems(&[&win], &[&windows(), &Nested]);
        let mut next = 0u128;
        let systems = to_systems(&found, || {
            next += 1;
            SystemId(next)
        });
        let win_sys = systems
            .iter()
            .find(|s| s.family == Family::Windows)
            .unwrap();
        let wsl = systems.iter().find(|s| s.family == Family::Linux).unwrap();
        assert_eq!(wsl.parent, Some(win_sys.id));
        assert_eq!(win_sys.parent, None);
        // The WSL volume isn't one of the source's own volumes, so nothing is left unclaimed.
        assert!(systems.iter().all(|s| s.family != Family::None));
    }
}
