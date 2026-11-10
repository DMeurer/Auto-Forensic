//! Prefetch files as run events (piece X2): every `.pf` file becomes a `windows.prefetch.file`
//! record (executable name and path, run count, last run, loaded files, volumes), and every
//! stored run time a `windows.prefetch.run` event, numbered by its slot. "Last run" is the latest
//! stored time, not the first slot: on Windows 11, `CHRMSTP.EXE` stores 07:49:57.368 before
//! 07:49:58.809, and PECmd calls the first one "LastRun" (stage 1).
//!
//! A file Windows never wrote (only zeros) and a file that doesn't parse are each a note.

use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use af_fmt_prefetch::Error;
use std::sync::OnceLock;

/// Every Prefetch file as a record, with one event per stored run time.
pub struct Prefetch;

impl Plugin for Prefetch {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.prefetch").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("windows.prefetch").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: ["windows.prefetch.file", "windows.prefetch.run"]
                .into_iter()
                .map(|k| Kind::new(k).expect("valid kind"))
                .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let record_kind = Kind::new("windows.prefetch.file").expect("valid kind");
        let kind = Kind::new("windows.prefetch.run").expect("valid kind");
        let meaning = TimeMeaning::new(kind.as_str()).expect("valid meaning");
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "windows.prefetch")
        {
            let path = a.locator.steps().last().map_or("", |s| s.id.as_str());
            let file_name = path.rsplit('/').next().unwrap_or(path);
            let data = opener.open(a).and_then(|src| {
                let mut buf = vec![0; usize::try_from(src.len()).map_err(std::io::Error::other)?];
                src.read_exact_at(0, &mut buf).map(|()| buf)
            });
            let pf = match data.map_err(|e| Error::Bad(e.to_string())) {
                Ok(data) => af_fmt_prefetch::read(file_name, &data),
                Err(e) => Err(e),
            };
            let pf = match pf {
                Ok(pf) => pf,
                Err(e) => {
                    let why = match e {
                        Error::NeverWritten => "was never written (only zeros)".to_string(),
                        Error::Bad(e) => format!("wasn't read: {e}"),
                    };
                    ctx.sink
                        .note(&id, ctx.system.id, format!("Prefetch file {path} {why}"));
                    continue;
                }
            };
            let source_text = a.source.to_string();
            let record = record_id(&source_text, &a.locator);
            let executable = executable(&pf.name, &pf.files);
            let attrs = serde_json::json!({
                "name": pf.name,
                "executable": executable,
                "version": pf.version,
                "run_count": pf.run_count,
                "last_run": pf.run_times.iter().max().map(|&t| Time::from_ticks_1601(t).display()),
                "files": pf.files,
                "volumes": pf.volumes.iter().map(|v| serde_json::json!({
                    "device_path": v.device_path,
                    "serial": format!("{:08X}", v.serial),
                    "created": Time::from_ticks_1601(v.created).display(),
                })).collect::<Vec<_>>(),
            });
            ctx.sink.record(
                &id,
                ctx.system.id,
                NewRecord {
                    id: record,
                    source: a.source,
                    kind: record_kind.clone(),
                    locator: a.locator.clone(),
                    attrs: Some(attrs.to_string()),
                },
            );
            for (slot, &ticks) in pf.run_times.iter().enumerate() {
                let slot = slot as u32;
                ctx.sink.event(
                    &id,
                    ctx.system.id,
                    NewEvent {
                        id: EventId::derive(&source_text, &a.locator, None, &kind, &meaning, slot),
                        source: a.source,
                        record,
                        kind: kind.clone(),
                        meaning: meaning.clone(),
                        time: Time::from_ticks_1601(ticks),
                        clock: ClockDomainId("wall".into()),
                        // Slots aren't in time order, so they are no sequence.
                        seq: None,
                    },
                );
                n += 1;
            }
        }
        Outcome::Ok(n)
    }
}

/// The longest executable name a Prefetch file stores; longer ones are cut there.
const STORED_NAME: usize = 29;

/// The loaded file that is the program itself, as PECmd finds it: the one named `name`, or, for
/// a name cut at [`STORED_NAME`] characters, the one whose name starts with it. `None` when the
/// program isn't among its loaded files (PECmd then shows the bare name).
fn executable<'a>(name: &str, files: &'a [String]) -> Option<&'a String> {
    let name = name.to_uppercase();
    let last = |f: &String| f.rsplit('\\').next().map(str::to_uppercase);
    files
        .iter()
        .find(|f| last(f).as_deref() == Some(name.as_str()))
        .or_else(|| {
            (name.chars().count() == STORED_NAME)
                .then(|| {
                    files
                        .iter()
                        .find(|f| last(f).is_some_and(|l| l.starts_with(&name)))
                })
                .flatten()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::artifact::Artifact;
    use af_core::bytes::{ByteSource, Locator, MemSource};
    use af_core::capability::Capabilities;
    use af_core::ids::{SourceId, SystemId};
    use af_core::runner::{NewFact, Opener, Sink, Target, run};
    use af_core::system::System;

    struct Files(Vec<(Artifact, Vec<u8>)>);

    impl Opener for Files {
        fn open(&self, a: &Artifact) -> std::io::Result<Box<dyn ByteSource>> {
            let (_, data) = self.0.iter().find(|(x, _)| x == a).expect("known artifact");
            Ok(Box::new(MemSource::new(data.clone(), a.locator.clone())))
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
            let a: serde_json::Value = serde_json::from_str(&r.attrs.unwrap()).unwrap();
            self.0.push(format!(
                "{} {} {} {} {}",
                r.kind, a["name"], a["run_count"], a["last_run"], a["executable"]
            ));
        }
        fn note(&mut self, _: &Kind, _: SystemId, text: String) {
            self.0.push(text);
        }
    }

    #[test]
    fn executable_by_name_or_cut_name() {
        let files = [
            "\\VOLUME{1}\\WINDOWS\\SYSTEM32\\EN-US\\CMD.EXE.MUI".to_string(),
            "\\VOLUME{1}\\WINDOWS\\SYSTEM32\\CMD.EXE".into(),
            "\\VOLUME{1}\\INSTALL\\AM_ENGINE_PATCH_1.1.14600.4.EXE".into(),
        ];
        assert_eq!(executable("CMD.EXE", &files), Some(&files[1]));
        assert_eq!(
            executable("AM_ENGINE_PATCH_1.1.14600.4.E", &files),
            Some(&files[2])
        );
        // Not cut, so no prefix match: CMD.EXE.MUI is not CMD.EX.
        assert_eq!(executable("CMD.EX", &files), None);
    }

    fn artifact(path: &str) -> Artifact {
        Artifact {
            kind: Kind::new("windows.prefetch").expect("valid kind"),
            locator: Locator::root("source.folder", "1").child("fs.path", path),
            source: SourceId(1),
            system: Some(SystemId(1)),
            sha256: String::new(),
        }
    }

    /// frnsc-prefetch's own CMD.EXE file (testdata/README.md): four runs; and a file of zeros.
    #[test]
    fn one_event_per_run_and_a_note_for_zeros() {
        let cmd = artifact("Windows/Prefetch/CMD.EXE-6D6290C5.pf");
        let zeros = artifact("Windows/Prefetch/GETHELP.EXE-40796CE6.pf");
        let opener = Files(vec![
            (
                cmd.clone(),
                include_bytes!("../testdata/CMD.EXE-6D6290C5.pf").to_vec(),
            ),
            (zeros.clone(), vec![0; 9036]),
        ]);
        let sys = System {
            id: SystemId(1),
            family: Family::Windows,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let targets = [Target::new(
            &sys,
            Capabilities::default(),
            vec![cmd, zeros],
            Some(&opener),
        )];
        let mut out = Out::default();
        run(
            &[&Prefetch],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        assert_eq!(out.0.len(), 6, "{:#?}", out.0);
        assert!(
            out.0[0].starts_with(
                r#"windows.prefetch.file "CMD.EXE" 4 "2024-02-05 06:17:41.1440142 UTC" "#
            ),
            "{}",
            out.0[0]
        );
        assert!(
            out.0[0].ends_with(r#"\\WINDOWS\\SYSWOW64\\CMD.EXE""#),
            "{}",
            out.0[0]
        );
        assert_eq!(
            out.0[1],
            "windows.prefetch.run 2024-02-05 06:17:41.1440142 UTC"
        );
        assert_eq!(
            out.0[4],
            "windows.prefetch.run 2024-02-04 04:15:17.0602624 UTC"
        );
        assert_eq!(
            out.0[5],
            "Prefetch file Windows/Prefetch/GETHELP.EXE-40796CE6.pf was never written (only zeros)"
        );
    }
}
