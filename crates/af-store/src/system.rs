//! Systems of a project (piece F23): every import gets its own, and merging is the analyst's call.
//!
//! The same computer often arrives twice: an image and, later, a hive exported from it, or two
//! images taken months apart. The tool never merges them on its own, because a wrong merge mixes
//! two machines' timelines. Instead, systems from different sources that share an identifying
//! fact (the same computer name) give a merge suggestion with its reason.

use crate::project::{Project, ProjectError};
use af_core::ids::{SourceId, SystemId};
use af_core::names::Kind;
use af_core::system::Family;

/// Fact kinds that identify a machine well enough to suggest a merge. A volume label doesn't:
/// thousands of sticks are called `USB`.
pub const IDENTIFYING: &[&str] = &["windows.computer_name"];

/// A system as the project lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRow {
    pub id: SystemId,
    pub source: SourceId,
    pub family: String,
    pub label: Option<String>,
    /// Identifying facts, such as `windows.computer_name`.
    pub facts: Vec<(String, String)>,
}

/// Two systems that may be the same machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSuggestion {
    pub a: SystemId,
    pub b: SystemId,
    /// Such as `same windows.computer_name: DESKTOP-ICH`.
    pub reason: String,
}

impl Project {
    /// Detects the systems in a folder source with `profiles` (C1), records each as a system of
    /// that source with its identity, and adds the artifacts each profile knows by path to the
    /// artifact index. A folder nothing claims becomes one `none` system.
    pub fn add_folder_systems(
        &mut self,
        source: &crate::source::SourceInfo,
        profiles: &[&dyn af_core::profile::OsProfile],
    ) -> Result<Vec<SystemId>, ProjectError> {
        use af_core::artifact::Artifact;
        use af_core::bytes::Locator;
        use af_core::system::{ViewId, VolumeId, VolumeProbe};
        let vol = af_host::folder::FolderVolume::new(VolumeId(source.id.0), &source.files[0]);
        let vols: [&dyn VolumeProbe; 1] = [&vol];
        let (systems, identities) = af_core::profile::build_systems(
            &vols,
            profiles,
            &af_core::capability::Capabilities::default(),
            SystemId::new_random,
            ViewId::new_random,
        );
        let mut index = self.store.artifacts()?;
        let mut ids = Vec::new();
        for (sys, identity) in systems.iter().zip(&identities) {
            let id = self.add_system(
                source.id,
                &sys.family,
                sys.label.as_deref().or(Some(&source.label)),
                &identity.facts,
            )?;
            if let Some(profile) = af_core::profile::profile_for(&sys.family, profiles) {
                for (_, path, kind) in profile.index(sys, &vols) {
                    let Some(on_disk) = vol.on_disk(&path) else {
                        continue;
                    };
                    index.add(Artifact {
                        kind,
                        locator: Locator::root("source.folder", &source.id.to_string())
                            .child("fs.path", &crate::run::folder_locator_path(&path)),
                        source: source.id,
                        system: Some(id),
                        sha256: crate::source::full_hash(&[on_disk])?,
                    });
                }
            }
            ids.push(id);
        }
        self.store.save_artifacts(&index)?;
        Ok(ids)
    }

    /// Records a new system for an import, with its identity facts. Always a new system, even
    /// if an existing one looks the same.
    pub fn add_system(
        &mut self,
        source: SourceId,
        family: &Family,
        label: Option<&str>,
        facts: &[(Kind, String)],
    ) -> Result<SystemId, ProjectError> {
        let id = SystemId::new_random();
        let tx = self.store.conn.transaction()?;
        tx.execute(
            "INSERT INTO systems VALUES (?, ?, ?, ?)",
            duckdb::params![id.0, source.0, family.as_str(), label],
        )?;
        for (kind, value) in facts {
            tx.execute(
                "INSERT INTO system_facts VALUES (?, ?, ?)",
                duckdb::params![id.0, kind.as_str(), value],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn systems(&self) -> Result<Vec<SystemRow>, ProjectError> {
        let conn = &self.store.conn;
        let mut stmt = conn.prepare("SELECT id, source, family, label FROM systems ORDER BY id")?;
        let mut rows: Vec<SystemRow> = stmt
            .query_map([], |r| {
                Ok(SystemRow {
                    id: SystemId(r.get(0)?),
                    source: SourceId(r.get(1)?),
                    family: r.get(2)?,
                    label: r.get(3)?,
                    facts: Vec::new(),
                })
            })?
            .collect::<Result<_, _>>()?;
        let mut facts = conn.prepare(
            "SELECT kind, value FROM system_facts WHERE system = ? ORDER BY kind, value",
        )?;
        for s in &mut rows {
            s.facts = facts
                .query_map([s.id.0], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
        }
        Ok(rows)
    }

    /// Pairs of systems from different sources that share an identifying fact (compared without
    /// case, as Windows compares computer names). Nothing is merged.
    pub fn merge_suggestions(&self) -> Result<Vec<MergeSuggestion>, ProjectError> {
        let kinds = IDENTIFYING
            .iter()
            .map(|k| format!("'{k}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut stmt = self.store.conn.prepare(&format!(
            "SELECT a.id, b.id, fa.kind, fa.value
             FROM systems a JOIN systems b ON a.id < b.id AND a.source <> b.source
             JOIN system_facts fa ON fa.system = a.id
             JOIN system_facts fb ON fb.system = b.id AND fb.kind = fa.kind
                                  AND lower(fb.value) = lower(fa.value)
             WHERE fa.kind IN ({kinds})
             ORDER BY a.id, b.id, fa.kind"
        ))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(MergeSuggestion {
                    a: SystemId(r.get(0)?),
                    b: SystemId(r.get(1)?),
                    reason: format!(
                        "same {}: {}",
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?
                    ),
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn project() -> (std::path::PathBuf, Project) {
        let d = std::env::temp_dir().join(format!(
            "af-systems-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let p = Project::create(&d.join("case"), "case").unwrap();
        (d, p)
    }

    fn name(n: &str) -> Vec<(Kind, String)> {
        vec![(Kind::new("windows.computer_name").unwrap(), n.into())]
    }

    #[test]
    fn matching_computer_names_give_a_suggestion_only() {
        let (dir, mut p) = project();
        let (image, hive, other) = (SourceId(1), SourceId(2), SourceId(3));
        let a = p
            .add_system(
                image,
                &Family::Windows,
                Some("DESKTOP-ICH"),
                &name("DESKTOP-ICH"),
            )
            .unwrap();
        let b = p
            .add_system(hive, &Family::Windows, None, &name("desktop-ich"))
            .unwrap();
        p.add_system(other, &Family::Windows, None, &name("LAPTOP-2"))
            .unwrap();
        let s = p.merge_suggestions().unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(
            (s[0].a.min(s[0].b), s[0].a.max(s[0].b)),
            (a.min(b), a.max(b))
        );
        assert_eq!(
            s[0].reason.to_lowercase(),
            "same windows.computer_name: desktop-ich"
        );
        // Still three systems: nothing was merged.
        assert_eq!(p.systems().unwrap().len(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn same_source_and_weak_facts_suggest_nothing() {
        let (dir, mut p) = project();
        // Two systems of one source (a dual boot) with the same name: not a merge case.
        p.add_system(SourceId(1), &Family::Windows, None, &name("PC"))
            .unwrap();
        p.add_system(SourceId(1), &Family::Windows, None, &name("PC"))
            .unwrap();
        // Two sticks both labelled USB: a volume label isn't identifying.
        let usb = vec![(Kind::new("volume.label").unwrap(), "USB".to_string())];
        p.add_system(SourceId(2), &Family::None, Some("USB"), &usb)
            .unwrap();
        p.add_system(SourceId(3), &Family::None, Some("USB"), &usb)
            .unwrap();
        assert!(p.merge_suggestions().unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
