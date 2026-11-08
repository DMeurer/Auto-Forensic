//! NTFS file times from a loose `$MFT` (piece M2): every file record becomes an `ntfs.mft.record`
//! record (path, number, sequence, in use, directory, size) with its `$STANDARD_INFORMATION`
//! times as `ntfs.si.*` events and the times of each of its `$FILE_NAME` attributes as
//! `ntfs.fn.*` events (created, modified, changed for the MFT entry, accessed). An `$MFT` inside
//! an image is read by `fs.timeline` (M3, your choice), with the NTFS adapter's names, as here.
//!
//! The meanings say which attribute a time is from and nothing more: `ntfs.si.created` is when
//! the `$SI` says the file was made, which a copy, an extraction or a timestomp can set to
//! anything (stage 0: the Tor installer set `firefox.exe` to a time before its own download).
//! DOS-only names (namespace 2) are left out; their times repeat the long name's.

use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

const SI: [&str; 4] = [
    "ntfs.si.created",
    "ntfs.si.modified",
    "ntfs.si.changed",
    "ntfs.si.accessed",
];
const FN: [&str; 4] = [
    "ntfs.fn.created",
    "ntfs.fn.modified",
    "ntfs.fn.changed",
    "ntfs.fn.accessed",
];
/// `$FILE_NAME` namespace of a DOS 8.3 name that has a long name beside it.
const DOS: u8 = 2;

/// Every record of a loose `$MFT` as a record, with its `$SI` and `$FN` times as events.
pub struct Mft;

impl Plugin for Mft {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.mft").expect("valid kind"),
            // 2: `mft_modified` renamed `changed`, as the NTFS adapter names it.
            version: 2,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("windows.mft").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: ["ntfs.mft.record"]
                .into_iter()
                .chain(SI)
                .chain(FN)
                .map(|k| Kind::new(k).expect("valid kind"))
                .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let record_kind = Kind::new("ntfs.mft.record").expect("valid kind");
        let kinds = |names: [&str; 4]| {
            names.map(|k| {
                let kind = Kind::new(k).expect("valid kind");
                let meaning = TimeMeaning::new(k).expect("valid meaning");
                (kind, meaning)
            })
        };
        let (si, fname) = (kinds(SI), kinds(FN));
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "windows.mft")
        {
            let path = a.locator.steps().last().map_or("", |s| s.id.as_str());
            let data = opener.open(a).and_then(|src| {
                let mut buf = vec![0; usize::try_from(src.len()).map_err(std::io::Error::other)?];
                src.read_exact_at(0, &mut buf).map(|()| buf)
            });
            let source = a.source;
            let source_text = source.to_string();
            let (system, sink) = (ctx.system.id, &mut *ctx.sink);
            let summary = data.map_err(|e| e.to_string()).and_then(|data| {
                af_fmt_mft::read(data, |r| {
                    let locator = a.locator.child("ntfs.mft_record", &r.number.to_string());
                    let record = record_id(&source_text, &locator);
                    let attrs = serde_json::json!({
                        "path": r.path,
                        "number": r.number,
                        "sequence": r.sequence,
                        "in_use": r.in_use,
                        "dir": r.is_dir,
                        "size": r.size,
                    });
                    sink.record(
                        &id,
                        system,
                        NewRecord {
                            id: record,
                            source,
                            kind: record_kind.clone(),
                            locator: locator.clone(),
                            attrs: Some(attrs.to_string()),
                        },
                    );
                    let mut times = vec![];
                    if let Some(i) = &r.info {
                        let t = [i.created, i.modified, i.mft_modified, i.accessed];
                        times.extend(si.iter().zip(t).map(|(k, t)| (k, t, 0)));
                    }
                    for (nth, f) in r
                        .names
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| f.namespace != DOS)
                    {
                        let t = [f.created, f.modified, f.mft_modified, f.accessed];
                        let nth = u32::try_from(nth).unwrap_or(u32::MAX);
                        times.extend(fname.iter().zip(t).map(|(k, t)| (k, t, nth)));
                    }
                    for ((kind, meaning), ticks, nth) in times.into_iter().filter(|t| t.1 != 0) {
                        sink.event(
                            &id,
                            system,
                            NewEvent {
                                id: EventId::derive(
                                    &source_text,
                                    &locator,
                                    None,
                                    kind,
                                    meaning,
                                    nth,
                                ),
                                source,
                                record,
                                kind: kind.clone(),
                                meaning: meaning.clone(),
                                time: Time::from_ticks_1601(ticks),
                                clock: ClockDomainId("wall".into()),
                                seq: None,
                            },
                        );
                        n += 1;
                    }
                })
            });
            match summary {
                Ok(s) if !s.errors.is_empty() => ctx.sink.note(
                    &id,
                    ctx.system.id,
                    format!(
                        "$MFT {path}: {} record(s) failed, {} read (first error: {})",
                        s.errors.len(),
                        s.records,
                        s.errors[0]
                    ),
                ),
                Ok(_) => {}
                Err(e) => {
                    ctx.sink
                        .note(&id, ctx.system.id, format!("$MFT {path} wasn't read: {e}"))
                }
            }
        }
        Outcome::Ok(n)
    }
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

    struct Loose(Artifact, Vec<u8>);

    impl Opener for Loose {
        fn open(&self, a: &Artifact) -> std::io::Result<Box<dyn ByteSource>> {
            assert_eq!(a, &self.0);
            Ok(Box::new(MemSource::new(self.1.clone(), a.locator.clone())))
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
            self.0.push(format!("{} {}", r.locator, r.attrs.unwrap()));
        }
    }

    /// A file whose `$SI` was set back before its `$FN` (as a timestomp or an installer does):
    /// both sets appear under their own names; the DOS name's times don't.
    #[test]
    fn si_and_fn_times() {
        let early = 132_000_000_000_000_000; // 2019-04-17 18:40:00
        let late = 134_000_000_000_000_000; // 2025-08-18 14:13:20
        let a = Artifact {
            kind: Kind::new("windows.mft").expect("valid kind"),
            locator: Locator::root("source.loose", "1"),
            source: SourceId(1),
            system: Some(SystemId(1)),
            sha256: String::new(),
        };
        let opener = Loose(
            a.clone(),
            af_fmt_mft::build_test_mft("firefox.exe", [early, early, late, late], late),
        );
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
            vec![a],
            Some(&opener),
        )];
        let mut out = Out::default();
        run(
            &[&Mft],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        let file: Vec<&str> = out
            .0
            .iter()
            .skip_while(|l| !l.contains("firefox"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            file,
            [
                r#"source.loose:1/ntfs.mft_record:6 {"path":"firefox.exe","number":6,"sequence":1,"in_use":true,"dir":false,"size":null}"#,
                "ntfs.si.created 2019-04-17 18:40:00.0000000 UTC",
                "ntfs.si.modified 2019-04-17 18:40:00.0000000 UTC",
                "ntfs.si.changed 2025-08-18 14:13:20.0000000 UTC",
                "ntfs.si.accessed 2025-08-18 14:13:20.0000000 UTC",
                "ntfs.fn.created 2025-08-18 14:13:20.0000000 UTC",
                "ntfs.fn.modified 2025-08-18 14:13:20.0000000 UTC",
                "ntfs.fn.changed 2025-08-18 14:13:20.0000000 UTC",
                "ntfs.fn.accessed 2025-08-18 14:13:20.0000000 UTC",
            ]
        );
    }
}
