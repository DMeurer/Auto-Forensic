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
use crate::{EventRow, RecordRow, Store};
use af_core::artifact::Artifact;
use af_core::bytes::{ByteSource, ExtentSource, Locator};
use af_core::capability::Capabilities;
use af_core::fs::{FileSystem, FsVolume, StreamName};
use af_core::ids::SourceId;
use af_core::ids::SystemId;
use af_core::names::Kind;
use af_core::path::{NameKind, ViewPath};
use af_core::runner::{NewEvent, NewFact, NewLink, NewRecord, Opener, Plugin, Sink, Target, run};
use af_core::system::{Family, System, VolumeId};
use af_fs_archive::Archive;
use af_fs_ntfs::Ntfs;
use af_host::folder::{FileSource, FolderVolume};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

/// Who the notes of a profile's registry are by (R3).
const REGISTRY_NOTES: &str = "af.registry";

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
    records: Vec<RecordRow>,
    /// (system, note, plugin)
    notes: Vec<(SystemId, String, String)>,
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
    fn record(&mut self, plugin: &Kind, system: SystemId, r: NewRecord) {
        self.records.push(RecordRow {
            id: r.id,
            source: r.source.0,
            system: system.0,
            kind: r.kind.as_str().into(),
            locator: r.locator.to_string(),
            attrs: r.attrs,
            created_by: plugin.as_str().into(),
        });
    }
    fn note(&mut self, plugin: &Kind, system: SystemId, text: String) {
        self.notes.push((system, text, plugin.as_str().into()));
    }
}

/// Opens artifacts of a project: loose files from their copy, everything else in place. A
/// source's file systems are opened once and kept for the run.
struct ProjectOpener {
    sources: Vec<SourceInfo>,
    opened: Mutex<HashMap<SourceId, Arc<FileSystems>>>,
}

impl ProjectOpener {
    fn file_systems(&self, s: &SourceInfo) -> io::Result<Arc<FileSystems>> {
        let mut opened = self
            .opened
            .lock()
            .map_err(|_| io::Error::other("opener lock poisoned"))?;
        if let Some(f) = opened.get(&s.id) {
            return Ok(f.clone());
        }
        let f = Arc::new(file_systems(s)?);
        opened.insert(s.id, f.clone());
        Ok(f)
    }
}

impl Opener for ProjectOpener {
    fn file_system(&self, a: &Artifact, f: &mut dyn FnMut(&dyn FileSystem)) -> io::Result<()> {
        let s = self
            .sources
            .iter()
            .find(|s| s.id == a.source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "artifact without a source"))?;
        let fss = self.file_systems(s)?;
        let (_, fs) = fss
            .iter()
            .find(|(at, _)| at == &a.locator)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no file system there"))?;
        f(fs.as_ref());
        Ok(())
    }

    fn open(&self, a: &Artifact) -> io::Result<Box<dyn ByteSource>> {
        let s = self
            .sources
            .iter()
            .find(|s| s.id == a.source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "artifact without a source"))?;
        // The locator's last step holds the path below the folder or volume, `/` between names.
        let rel = a
            .locator
            .steps()
            .last()
            .map(|st| st.id.as_str())
            .unwrap_or("");
        let parse = |kind| {
            ViewPath::parse(
                rel,
                af_core::path::PathStyle {
                    separator: '/',
                    case: af_core::path::CasePolicy::Exact,
                },
                kind,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        };
        let missing = || {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{rel} isn't in the source"),
            )
        };
        match s.kind.as_str() {
            "loose" => Ok(Box::new(FileSource::open(&s.files[0], a.locator.clone())?)),
            "folder" => {
                let path = parse(if cfg!(windows) {
                    NameKind::Utf16
                } else {
                    NameKind::Bytes
                })?;
                let vol = FolderVolume::new(VolumeId(0), &s.files[0]);
                Ok(Box::new(vol.open(&path, a.locator.clone())?))
            }
            "archive" | "image" | "device" => {
                // The locator is that of the file system's volume, then the path.
                let steps = a.locator.steps();
                let on = Locator(steps[..steps.len().saturating_sub(1)].to_vec());
                let fss = self.file_systems(s)?;
                let fs = &fss.iter().find(|(l, _)| *l == on).ok_or_else(missing)?.1;
                let names = if s.kind == "archive" {
                    NameKind::Bytes
                } else {
                    NameKind::Utf16
                };
                let vol = FsVolume {
                    id: VolumeId(0),
                    fs: fs.as_ref(),
                };
                let id = vol.lookup(&parse(names)?).ok_or_else(missing)?;
                let data = fs.open(&id, &StreamName::Default)?.ok_or_else(missing)?;
                let len = data.len();
                Ok(Box::new(ExtentSource::slice(
                    data,
                    0,
                    len,
                    a.locator.clone(),
                )?))
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

/// Runs `plugins` on the project in `dir`. Each system's profile from `profiles` offers its
/// capabilities, such as a Windows system's registry.
pub fn run_project(
    dir: &Path,
    plugins: &[&dyn Plugin],
    profiles: &[&dyn af_core::profile::OsProfile],
) -> Result<RunSummary, ProjectError> {
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
        opened: Mutex::new(HashMap::new()),
    };
    let run_dir = reader.temp.run_dir()?;
    drop(reader);

    let per_system: Vec<Vec<Artifact>> = systems
        .iter()
        .map(|s| {
            index
                .all()
                .filter(|a| a.system == Some(s.id))
                .cloned()
                .collect()
        })
        .collect();
    let (registries, notes): (Vec<_>, Vec<_>) = systems
        .iter()
        .zip(&per_system)
        .map(|(s, artifacts)| {
            af_core::profile::profile_for(&s.family, profiles)
                .map(|p| p.registry(artifacts, &opener))
                .unwrap_or_default()
        })
        .unzip();
    // R6: a system with a registry gets its identity from it, every run; others keep the one
    // from `source add` (a Linux hostname, or a Windows zone that is unknown without SYSTEM).
    let identities: Vec<Option<af_core::profile::Identity>> = systems
        .iter()
        .zip(&registries)
        .map(|(s, reg)| {
            let caps = Capabilities {
                registry: Some(reg.as_deref()?),
            };
            let p = af_core::profile::profile_for(&s.family, profiles)?;
            Some(p.identity(s, &[], &caps))
        })
        .collect();
    let targets: Vec<Target<'_>> = systems
        .iter()
        .zip(per_system)
        .zip(&registries)
        .map(|((s, artifacts), reg)| {
            let caps = Capabilities {
                registry: reg.as_deref(),
            };
            Target::new(s, caps, artifacts, Some(&opener))
        })
        .collect();
    let mut sink = SpoolSink {
        events: vec![],
        facts: vec![],
        links: vec![],
        records: vec![],
        notes: vec![],
    };
    let extracted = run(plugins, &targets, &mut sink, &mut outcomes, &mut runs);
    let spool_path = run_dir.path().join("spool.duckdb");
    {
        let mut spool = Store::open(&spool_path, 1024)?;
        spool.insert_events(&sink.events)?;
        spool.insert_facts(&sink.facts)?;
        spool.insert_records(&sink.records)?;
        let mut by_plugin: HashMap<&str, Vec<(SystemId, String)>> = HashMap::new();
        for (system, note, plugin) in &sink.notes {
            by_plugin
                .entry(plugin)
                .or_default()
                .push((*system, note.clone()));
        }
        for (plugin, notes) in by_plugin {
            spool.save_system_notes(plugin, &notes)?;
        }
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
    let notes: Vec<_> = systems
        .iter()
        .zip(notes)
        .flat_map(|(s, n)| n.into_iter().map(|n| (s.id, n)))
        .collect();
    writer.store.save_system_notes(REGISTRY_NOTES, &notes)?;
    for (s, identity) in systems.iter().zip(&identities) {
        if let Some(i) = identity {
            writer.set_identity(s.id, i.label.as_deref(), &i.facts)?;
        }
    }
    Ok(RunSummary {
        systems: systems.len(),
        extracted: extracted.len(),
        events_loaded,
    })
}

/// A path below a folder source as the locator step `fs.path` holds it.
/// A source's file systems, each with the locator of what it sits on: the archive, or a volume
/// of an image or device. Only NTFS volumes have an adapter so far; others, and NTFS volumes
/// that don't open, are left out. Empty for folders and loose files.
pub(crate) type FileSystems = Vec<(Locator, Box<dyn FileSystem>)>;

pub(crate) fn file_systems(s: &SourceInfo) -> io::Result<FileSystems> {
    let root = Locator::root(&format!("source.{}", s.kind), &s.id.to_string());
    match s.kind.as_str() {
        "archive" => {
            let file = FileSource::open(&s.files[0], root.clone())?;
            Ok(vec![(root, Box::new(Archive::open(Arc::new(file))?))])
        }
        "image" | "device" => {
            let img: Arc<dyn ByteSource> = Arc::from(af_host::ewf::open_image(&s.files, root)?);
            Ok(af_host::volumes::list(img)?
                .volumes
                .into_iter()
                .filter_map(|v| Some((v.view.locator().clone(), open_fs(&v)?.ok()?)))
                .collect())
        }
        _ => Ok(vec![]),
    }
}

/// The file system on a volume: `None` when this build has no reader for its content, else
/// whether the reader opened it. `af status` reports the same answer as coverage.
pub(crate) fn open_fs(v: &af_host::volumes::Volume) -> Option<io::Result<Box<dyn FileSystem>>> {
    match v.content.name() {
        "ntfs" => Some(Ntfs::open(v.view.clone()).map(|fs| Box::new(fs) as Box<dyn FileSystem>)),
        _ => None,
    }
}

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
        let first = run_project(&dir, &[&plugin], &[]).unwrap();
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
            p.status(&[&plugin])
                .unwrap()
                .contains("test.counter v1: read, 2 items")
        );
        drop(p);

        let second = run_project(&dir, &[&plugin], &[]).unwrap();
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
            p.status(&[&plugin])
                .unwrap()
                .contains("test.counter v1: read, 2 items")
        );
        drop(p);
        std::fs::remove_dir_all(&parent).unwrap();
    }
}
