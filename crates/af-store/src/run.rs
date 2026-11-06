//! `af run` (piece C0b): runs the compiled-in plugins on a project.
//!
//! 1. The project is opened read-only to read its sources, systems, artifacts, run log and
//!    outcomes; the plugins run and their events, facts and links go into a spool store in a
//!    run folder under `tmp/` (F3, F17).
//! 2. Only then is the project opened for writing, briefly (F32): the earlier output of every
//!    plugin that extracted again is cleared, derived links and groups are cleared (F25), the
//!    spool is loaded sorted by time, and the run log and outcomes are saved.

use crate::facts::FactRow;
use crate::project::{Project, ProjectError};
use crate::source::SourceInfo;
use crate::{EventRow, Store};
use af_core::artifact::Artifact;
use af_core::bytes::ByteSource;
use af_core::capability::Capabilities;
use af_core::ids::SystemId;
use af_core::names::Kind;
use af_core::path::{NameKind, ViewPath};
use af_core::runner::{NewEvent, NewFact, NewLink, Opener, Plugin, Sink, Target, run};
use af_core::system::{Family, System, VolumeId};
use af_host::folder::{FileSource, FolderVolume};
use std::io;
use std::path::Path;

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    pub systems: usize,
    /// (plugin, system) pairs that extracted this time; the others were current.
    pub extracted: usize,
    pub events_loaded: u64,
}

/// Collects plugin output in a spool store.
struct SpoolSink {
    events: Vec<EventRow>,
    facts: Vec<FactRow>,
    links: Vec<(NewLink, String)>,
}

impl Sink for SpoolSink {
    fn emit(&mut self, _plugin: &Kind, _kind: &Kind, _payload: String) {
        // Untyped output has no place in the store; real plugins use the typed methods.
    }
    fn event(&mut self, plugin: &Kind, system: SystemId, e: NewEvent) {
        self.events.push(EventRow {
            id: e.id.0,
            source: e.source.0,
            record: e.record,
            system: system.0,
            kind: e.kind.as_str().into(),
            meaning: e.meaning.as_str().into(),
            time: e.time.to_columns(),
            clock_domain: e.clock.0,
            seq_domain: e.seq.as_ref().map(|s| s.domain.clone()),
            seq_no: e.seq.map(|s| s.no),
            created_by: plugin.as_str().into(),
        });
    }
    fn fact(&mut self, plugin: &Kind, system: SystemId, f: NewFact) {
        self.facts.push(FactRow {
            id: f.id.0,
            source: f.source.0,
            system: system.0,
            kind: f.kind.as_str().into(),
            subject: f.subject,
            attrs: f.attrs,
            created_by: plugin.as_str().into(),
        });
    }
    fn link(&mut self, plugin: &Kind, l: NewLink) {
        self.links.push((l, plugin.as_str().into()));
    }
}

/// Opens artifacts of a project: loose files from their copy, folder files in place.
struct ProjectOpener {
    sources: Vec<SourceInfo>,
}

impl Opener for ProjectOpener {
    fn open(&self, a: &Artifact) -> io::Result<Box<dyn ByteSource>> {
        let s = self
            .sources
            .iter()
            .find(|s| s.id == a.source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "artifact without a source"))?;
        match s.kind.as_str() {
            "loose" => Ok(Box::new(FileSource::open(&s.files[0], a.locator.clone())?)),
            "folder" => {
                // The locator's last step holds the path below the folder, `/` between names.
                let rel = a
                    .locator
                    .steps()
                    .last()
                    .map(|st| st.id.as_str())
                    .unwrap_or("");
                let path = ViewPath::parse(
                    rel,
                    af_core::path::PathStyle {
                        separator: '/',
                        case: af_core::path::CasePolicy::Exact,
                    },
                    if cfg!(windows) {
                        NameKind::Utf16
                    } else {
                        NameKind::Bytes
                    },
                )
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                let vol = FolderVolume::new(VolumeId(0), &s.files[0]);
                Ok(Box::new(vol.open(&path, a.locator.clone())?))
            }
            other => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{other} sources can't be read yet (stage 3)"),
            )),
        }
    }
}

fn family(name: &str) -> Family {
    match name {
        "none" => Family::None,
        "windows" => Family::Windows,
        "linux" => Family::Linux,
        "macos" => Family::MacOs,
        "android" => Family::Android,
        "ios" => Family::Ios,
        other => Family::Other(other.into()),
    }
}

/// Runs `plugins` on the project in `dir`.
pub fn run_project(dir: &Path, plugins: &[&dyn Plugin]) -> Result<RunSummary, ProjectError> {
    // 1. Read the project, run, spool.
    let reader = Project::open_read_only(dir, std::time::Duration::from_secs(30))?;
    let systems: Vec<System> = reader
        .systems()?
        .into_iter()
        .map(|s| System {
            id: s.id,
            family: family(&s.family),
            label: s.label,
            parent: None,
            volumes: vec![],
            views: vec![],
        })
        .collect();
    let index = reader.store.artifacts()?;
    let mut runs = reader.store.run_log()?;
    let mut outcomes = reader.store.outcomes()?;
    let opener = ProjectOpener {
        sources: reader.sources()?,
    };
    let run_dir = reader.temp.run_dir()?;
    drop(reader);

    let targets: Vec<Target<'_>> = systems
        .iter()
        .map(|s| {
            let artifacts = index
                .all()
                .filter(|a| a.system == Some(s.id))
                .cloned()
                .collect();
            Target::new(s, Capabilities::default(), artifacts, Some(&opener))
        })
        .collect();
    let mut sink = SpoolSink {
        events: vec![],
        facts: vec![],
        links: vec![],
    };
    let extracted = run(plugins, &targets, &mut sink, &mut outcomes, &mut runs);
    let spool_path = run_dir.path().join("spool.duckdb");
    {
        let mut spool = Store::open(&spool_path, 1024)?;
        spool.insert_events(&sink.events)?;
        spool.insert_facts(&sink.facts)?;
        for (l, by) in &sink.links {
            spool.add_link(l.id, l.kind.as_str(), &l.from, &l.to, by)?;
        }
    }

    // 2. Write the project, briefly.
    let mut writer = Project::open(dir)?;
    for (plugin, system) in &extracted {
        writer
            .store
            .clear_plugin_output(plugin.as_str(), system.0)?;
    }
    writer.store.clear_derived_links()?;
    writer.store.clear_derived_groups()?;
    let events_loaded = writer.store.load_spools(&[&spool_path])?;
    writer.store.save_run_log(&runs)?;
    writer.store.save_outcomes(&outcomes)?;
    Ok(RunSummary {
        systems: systems.len(),
        extracted: extracted.len(),
        events_loaded,
    })
}

/// A path below a folder source as the locator step `fs.path` holds it.
pub fn folder_locator_path(path: &ViewPath) -> String {
    let style = af_core::path::PathStyle {
        separator: '/',
        case: af_core::path::CasePolicy::Exact,
    };
    path.display(style).trim_start_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::bytes::Locator;
    use af_core::ids::{EventId, SourceId};
    use af_core::plugin::{Input, Manifest, Outcome, Phase};
    use af_core::runner::RunContext;
    use af_core::time::Time;
    use af_core::timeline::{ClockDomainId, TimeMeaning};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Reads each `test.blob` artifact and makes one event per byte value it finds first.
    struct Counter {
        manifest: Manifest,
        extracts: AtomicUsize,
    }

    impl Plugin for Counter {
        fn manifest(&self) -> &Manifest {
            &self.manifest
        }
        fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
            self.extracts.fetch_add(1, Ordering::SeqCst);
            let mut n = 0;
            for a in ctx
                .artifacts
                .iter()
                .filter(|a| a.kind.as_str() == "test.blob")
            {
                let src = match ctx.opener.map(|o| o.open(a)) {
                    Some(Ok(s)) => s,
                    _ => return Outcome::Failed("can't open".into()),
                };
                let mut buf = vec![0; src.len() as usize];
                if src.read_exact_at(0, &mut buf).is_err() {
                    return Outcome::Failed("can't read".into());
                }
                for (i, b) in buf.iter().enumerate().take(2) {
                    ctx.sink.event(
                        &self.manifest.id,
                        ctx.system.id,
                        NewEvent {
                            id: EventId(u128::from(*b) << 8 | i as u128),
                            source: a.source,
                            record: 1,
                            kind: Kind::new("test.byte").unwrap(),
                            meaning: TimeMeaning::new("test.read").unwrap(),
                            time: Time::from_unix_seconds(1_700_000_000 + i as i64),
                            clock: ClockDomainId("wall".into()),
                            seq: None,
                        },
                    );
                    n += 1;
                }
            }
            Outcome::Ok(n)
        }
    }

    #[test]
    fn a_test_plugins_events_land_in_the_project_and_a_second_run_extracts_nothing() {
        let parent = std::env::temp_dir().join(format!("af-run-{}", std::process::id()));
        let blob = parent.join("blob.bin");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(&blob, b"AB").unwrap();
        let dir = parent.join("case");
        let mut p = Project::create(&dir, "case").unwrap();
        let s = p.add_source(&blob).unwrap();
        let sys = p.add_system(s.id, &Family::None, None, &[]).unwrap();
        let mut index = p.store.artifacts().unwrap();
        index.add(Artifact {
            kind: Kind::new("test.blob").unwrap(),
            locator: Locator::root("source.loose", &s.id.to_string()),
            source: SourceId(s.id.0),
            system: Some(sys),
            sha256: s.sha256.clone(),
        });
        p.store.save_artifacts(&index).unwrap();
        drop(p);

        let plugin = Counter {
            manifest: Manifest {
                id: Kind::new("test.counter").unwrap(),
                version: 1,
                applies_to: vec![],
                phases: vec![Phase::Extract],
                inputs: vec![Input {
                    kind: Kind::new("test.blob").unwrap(),
                    required: true,
                }],
                needs: vec![],
                produces: vec![Kind::new("test.byte").unwrap()],
            },
            extracts: AtomicUsize::new(0),
        };
        let first = run_project(&dir, &[&plugin]).unwrap();
        assert_eq!((first.extracted, first.events_loaded), (1, 2));
        let p = Project::open_read_only(&dir, std::time::Duration::from_secs(1)).unwrap();
        let events = p.store.events().unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|e| e.created_by == "test.counter" && e.system == sys.0)
        );
        assert!(
            p.status()
                .unwrap()
                .contains("test.counter v1: read, 2 items")
        );
        drop(p);

        let second = run_project(&dir, &[&plugin]).unwrap();
        assert_eq!((second.extracted, second.events_loaded), (0, 0));
        assert_eq!(
            plugin.extracts.load(Ordering::SeqCst),
            1,
            "nothing extracted again"
        );
        let p = Project::open_read_only(&dir, std::time::Duration::from_secs(1)).unwrap();
        assert_eq!(
            p.store.events().unwrap().len(),
            2,
            "events kept, not duplicated"
        );
        assert!(
            p.status()
                .unwrap()
                .contains("test.counter v1: read, 2 items")
        );
        drop(p);
        std::fs::remove_dir_all(&parent).unwrap();
    }
}
