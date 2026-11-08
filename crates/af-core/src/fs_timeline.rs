//! File times from the file system layer (piece M3), for any file system with an adapter: every
//! entry of every file system a system holds becomes an `fs.entry` record (its paths, kind,
//! allocated or not, how a deleted one was found, its data size), and each of its named times an
//! event named as the file system names it (`ntfs.si.created`, `ntfs.fn.changed`, later
//! `ext4.dtime`). A stored zero is no event.
//!
//! On NTFS this covers every volume of an image (your choice); a loose `$MFT` is read by the
//! Windows `$MFT` plugin (M2) with the same names.

use crate::fs::{Entry, EntryKind, EntryName, EntryPath, FileSystem, StreamName};
use crate::ids::{EventId, FileId, record_id};
use crate::names::Kind;
use crate::path::{Name, ViewPath};
use crate::plugin::{Input, Manifest, Outcome, Phase};
use crate::runner::{NewEvent, NewRecord, Plugin, RunContext};
use crate::time::TimeStatus;
use crate::timeline::{ClockDomainId, TimeMeaning};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Folder chains longer than this are taken as loops, as in [`crate::fs::paths`].
const MAX_DEPTH: usize = 4096;

/// Every entry of every file system as a record, with its times as events.
pub struct Timeline;

impl Plugin for Timeline {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("fs.timeline").expect("valid kind"),
            version: 1,
            applies_to: vec![],
            phases: vec![Phase::Extract],
            // shortcut: required while NTFS is the only adapter; with a second one, list both as
            // optional, so systems without a file system don't count as extracted.
            inputs: vec![Input {
                kind: Kind::new("fs.ntfs").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: vec![Kind::new("fs.entry").expect("valid kind")],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let wanted: Vec<&Kind> = self.manifest().inputs.iter().map(|i| &i.kind).collect();
        let (system, sink) = (ctx.system.id, &mut *ctx.sink);
        let mut n = 0;
        for a in ctx.artifacts.iter().filter(|a| wanted.contains(&&a.kind)) {
            let source_text = a.source.to_string();
            let mut broken = (0, None);
            let opened = opener.file_system(a, &mut |fs| {
                let mut entries = vec![];
                for e in fs.all() {
                    match e {
                        Ok(e) => entries.push(e),
                        Err(err) => {
                            broken.0 += 1;
                            broken.1.get_or_insert(err.to_string());
                        }
                    }
                }
                let paths = Paths::new(fs, &entries);
                for e in &entries {
                    let locator = a.locator.child("fs.entry", &file_id(&e.id));
                    let record = record_id(&source_text, &locator);
                    let attrs = serde_json::json!({
                        "paths": paths.of(e),
                        "kind": match e.kind {
                            EntryKind::File => "file",
                            EntryKind::Folder => "folder",
                            EntryKind::Symlink => "symlink",
                            EntryKind::Other => "other",
                        },
                        "allocated": e.allocated,
                        "recovered": e.recovered.as_ref().map(Kind::as_str),
                        "size": e.streams.iter().find(|s| s.name == StreamName::Default).map(|s| s.size),
                    });
                    sink.record(
                        &id,
                        system,
                        NewRecord {
                            id: record,
                            source: a.source,
                            kind: Kind::new("fs.entry").expect("valid kind"),
                            locator: locator.clone(),
                            attrs: Some(attrs.to_string()),
                        },
                    );
                    for (kind, time) in e.times.iter().filter(|(_, t)| t.status != TimeStatus::NotSet) {
                        let meaning = TimeMeaning::new(kind.as_str()).expect("a kind is a meaning");
                        sink.event(
                            &id,
                            system,
                            NewEvent {
                                id: EventId::derive(&source_text, &locator, None, kind, &meaning, 0),
                                source: a.source,
                                record,
                                kind: kind.clone(),
                                meaning,
                                time: time.clone(),
                                clock: ClockDomainId("wall".into()),
                                seq: None,
                            },
                        );
                        n += 1;
                    }
                }
            });
            if let Err(e) = opened {
                sink.note(
                    &id,
                    system,
                    format!("file system at {} wasn't read: {e}", a.locator),
                );
            }
            if let (count @ 1.., Some(first)) = broken {
                sink.note(
                    &id,
                    system,
                    format!(
                        "file system at {}: {count} entries failed to read (first: {first})",
                        a.locator
                    ),
                );
            }
        }
        Outcome::Ok(n)
    }
}

/// An entry ID as locator text: its scheme and value in hex.
fn file_id(id: &FileId) -> String {
    let hex: String = id.value.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}:{hex}", id.scheme)
}

/// Paths built from one walk, as [`crate::fs::paths`] builds them, without reading each folder
/// again for every entry below it.
struct Paths<'a> {
    root: FileId,
    /// A folder's first long name and its parent.
    folders: HashMap<&'a FileId, (&'a Name, &'a FileId)>,
}

impl<'a> Paths<'a> {
    fn new(fs: &dyn FileSystem, entries: &'a [Entry]) -> Self {
        let folders = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Folder)
            .filter_map(|e| {
                let n = e.names.iter().find(|n| !n.alias).or(e.names.first())?;
                Some((&e.id, (&n.name, &n.parent)))
            })
            .collect();
        Self {
            root: fs.root(),
            folders,
        }
    }

    /// Every path of `e`, one per name that isn't an alias.
    fn of(&self, e: &Entry) -> Vec<String> {
        if e.id == self.root {
            let root = EntryPath {
                orphan: false,
                path: ViewPath::new(vec![]),
            };
            return vec![root.display()];
        }
        let long: Vec<&EntryName> = e.names.iter().filter(|n| !n.alias).collect();
        let own = if long.is_empty() {
            e.names.iter().collect()
        } else {
            long
        };
        own.into_iter()
            .map(|n| {
                let (mut names, mut at) = (vec![n.name.clone()], &n.parent);
                let orphan = loop {
                    if *at == self.root {
                        break false;
                    }
                    match self.folders.get(at) {
                        Some((name, parent)) if names.len() <= MAX_DEPTH => {
                            names.push((*name).clone());
                            at = parent;
                        }
                        _ => break true,
                    }
                };
                names.reverse();
                EntryPath {
                    orphan,
                    path: ViewPath::new(names),
                }
                .display()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::Artifact;
    use crate::bytes::{ByteSource, Locator};
    use crate::capability::Capabilities;
    use crate::fs::{FakeFs, paths};
    use crate::ids::{SourceId, SystemId};
    use crate::path::CasePolicy;
    use crate::runner::{NewFact, Opener, Sink, Target, run};
    use crate::system::{Family, System};
    use crate::time::Time;

    struct One(Artifact, FakeFs);

    impl Opener for One {
        fn open(&self, _: &Artifact) -> std::io::Result<Box<dyn ByteSource>> {
            unreachable!("fs.timeline opens no bytes")
        }
        fn file_system(
            &self,
            a: &Artifact,
            f: &mut dyn FnMut(&dyn FileSystem),
        ) -> std::io::Result<()> {
            assert_eq!(a, &self.0);
            f(&self.1);
            Ok(())
        }
    }

    #[derive(Default)]
    struct Out(Vec<String>);

    impl Sink for Out {
        fn emit(&mut self, _: &Kind, _: &Kind, _: String) {}
        fn fact(&mut self, _: &Kind, _: SystemId, _: NewFact) {}
        fn event(&mut self, _: &Kind, _: SystemId, e: NewEvent) {
            self.0.push(format!("{} {}", e.kind, e.time.display()));
        }
        fn record(&mut self, _: &Kind, _: SystemId, r: NewRecord) {
            self.0.push(r.attrs.unwrap());
        }
    }

    /// A file with a hard link and a time, a deleted file whose folder is gone, and a stored
    /// zero (no event). Paths agree with [`paths`].
    #[test]
    fn records_paths_and_times() {
        let mut fs = FakeFs::new(CasePolicy::Insensitive);
        let root = fs.root();
        let docs = fs.folder(&root, "Docs");
        let other = fs.folder(&root, "Other");
        let file = fs.file(&docs, "a.txt", b"abc");
        fs.link(&file, &other, "b.txt");
        fs.time(
            &file,
            "ntfs.si.created",
            Time::from_ticks_1601(132_000_000_000_000_000),
        );
        fs.time(&file, "ntfs.si.accessed", Time::from_ticks_1601(0));
        let gone = fs.folder(&root, "Gone");
        let deleted = fs.file(&gone, "old.txt", b"");
        fs.delete(&deleted);
        fs.purge(&gone);
        let want: Vec<String> = fs
            .all()
            .map(|e| e.unwrap())
            .flat_map(|e| paths(&fs, &e).unwrap())
            .map(|p| p.display())
            .collect();
        let a = Artifact {
            kind: Kind::new("fs.ntfs").expect("valid kind"),
            locator: Locator::root("source.image", "1"),
            source: SourceId(1),
            system: Some(SystemId(1)),
            sha256: String::new(),
        };
        let opener = One(a.clone(), fs);
        let sys = System {
            id: SystemId(1),
            family: Family::None,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let targets = [Target::new(
            &sys,
            Capabilities::default(),
            vec![a],
            Some(&opener),
        )];
        let mut out = Out::default();
        run(
            &[&Timeline],
            &targets,
            &mut out,
            &mut crate::plugin::OutcomeLog::new(),
            &mut crate::runner::RunLog::new(),
        );
        let got: Vec<String> = out
            .0
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .flat_map(|v| v["paths"].as_array().unwrap().clone())
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, want);
        assert!(got.contains(&"<orphan>/old.txt".to_string()), "{got:?}");
        let i = out.0.iter().position(|l| l.contains("a.txt")).unwrap();
        // Compared as values: key order depends on serde_json features elsewhere in the build.
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&out.0[i]).unwrap(),
            serde_json::json!({
                "paths": ["/Docs/a.txt", "/Other/b.txt"],
                "kind": "file",
                "allocated": true,
                "recovered": null,
                "size": 3,
            })
        );
        assert_eq!(
            out.0[i + 1],
            "ntfs.si.created 2019-04-17 18:40:00.0000000 UTC"
        );
        assert!(
            !out.0.iter().any(|l| l.starts_with("ntfs.si.accessed")),
            "{:?}",
            out.0
        );
    }
}
