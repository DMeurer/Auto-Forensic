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
