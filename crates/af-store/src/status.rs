//! `af status` (piece F26): what was read, what's missing, and why.
//!
//! The report lists the sources, the systems, the artifact kinds found, and for each system what
//! every plugin's last run came to. Its outcome words keep "not in this project" (no input was
//! ever added) apart from "present, nothing relevant" (the input was read and held nothing).

use crate::project::{Project, ProjectError};
use crate::{Error, Store};
use af_core::ids::SystemId;
use af_core::names::Kind;
use af_core::plugin::{Outcome, OutcomeColumns, OutcomeLog, OutcomeRecord};
use duckdb::params;
use std::fmt::Write;

impl Store {
    /// Replaces the stored outcomes with `log`.
    pub fn save_outcomes(&mut self, log: &OutcomeLog) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        tx.execute_batch("DELETE FROM outcomes;")?;
        for r in log.all() {
            let c = r.outcome.to_columns();
            tx.execute(
                "INSERT INTO outcomes VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    r.plugin.as_str(),
                    r.version,
                    r.system.0,
                    c.outcome,
                    c.count,
                    c.detail
                ],
            )?;
        }
        tx.commit()
    }

    /// The stored outcomes. Rows this code didn't write are skipped.
    pub fn outcomes(&self) -> Result<OutcomeLog, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT plugin, version, system, outcome, count, detail FROM outcomes \
             ORDER BY system, plugin",
        )?;
        let mut log = OutcomeLog::new();
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, u128>(2)?,
                OutcomeColumns {
                    outcome: r.get(3)?,
                    count: r.get(4)?,
                    detail: r.get(5)?,
                },
            ))
        })? {
            let (plugin, version, system, cols) = row?;
            if let (Ok(plugin), Some(outcome)) = (Kind::new(&plugin), Outcome::from_columns(&cols))
            {
                log.record(OutcomeRecord {
                    plugin,
                    version,
                    system: SystemId(system),
                    outcome,
                });
            }
        }
        Ok(log)
    }
}

impl Project {
    /// The status report as text.
    pub fn status(&self) -> Result<String, ProjectError> {
        let mut out = String::new();
        let info = self.info()?;
        let sources = self.sources()?;
        let systems = self.systems()?;
        let index = self.store.artifacts()?;
        let outcomes = self.store.outcomes()?;
        let _ = writeln!(out, "project {:?}", info.name);
        let _ = writeln!(out, "sources: {}", sources.len());
        for s in &sources {
            let missing = s.files.iter().filter(|f| !f.exists()).count();
            let note = if missing > 0 {
                format!(", {missing} file(s) missing: relink")
            } else {
                String::new()
            };
            let _ = writeln!(out, "  {} {} {}{note}", s.id, s.kind, s.label);
        }
        let kinds = index.kinds();
        let _ = writeln!(out, "artifacts: {} kind(s)", kinds.len());
        for k in &kinds {
            let _ = writeln!(out, "  {k}: {}", index.find(k).len());
        }
        let _ = writeln!(out, "systems: {}", systems.len());
        for sys in &systems {
            let label = sys.label.as_deref().unwrap_or("-");
            let _ = writeln!(out, "  {} {} {label}", sys.id, sys.family);
            let mut any = false;
            for o in outcomes.for_system(sys.id) {
                any = true;
                let _ = writeln!(
                    out,
                    "    {} v{}: {}",
                    o.plugin,
                    o.version,
                    o.outcome.meaning()
                );
            }
            if !any {
                let _ = writeln!(out, "    no plugin has run on it yet");
            }
        }
        for m in self.merge_suggestions()? {
            let _ = writeln!(
                out,
                "maybe the same machine: {} and {} ({})",
                m.a, m.b, m.reason
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::system::Family;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn not_in_this_project_differs_from_nothing_relevant() {
        let dir = std::env::temp_dir().join(format!(
            "af-status-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut p = Project::create(&dir.join("case"), "Exam").unwrap();
        let sys = p
            .add_system(af_core::ids::SourceId(1), &Family::Windows, Some("PC"), &[])
            .unwrap();
        let mut log = OutcomeLog::new();
        for (plugin, outcome) in [
            ("windows.registry.usb", Outcome::Ok(0)),
            ("windows.prefetch", Outcome::NotAcquired),
            ("windows.evtx", Outcome::Ok(1234)),
            ("windows.bitlocker", Outcome::Locked),
        ] {
            log.record(OutcomeRecord {
                plugin: Kind::new(plugin).unwrap(),
                version: 1,
                system: sys,
                outcome,
            });
        }
        p.store.save_outcomes(&log).unwrap();
        assert_eq!(p.store.outcomes().unwrap().all().len(), 4);

        let report = p.status().unwrap();
        assert!(
            report.contains("windows.registry.usb v1: present, nothing relevant"),
            "{report}"
        );
        assert!(
            report.contains("windows.prefetch v1: not in this project"),
            "{report}"
        );
        assert!(
            report.contains("windows.evtx v1: read, 1234 items"),
            "{report}"
        );
        assert!(
            report.contains("windows.bitlocker v1: there, but encrypted or locked"),
            "{report}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
