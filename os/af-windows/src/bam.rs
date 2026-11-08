//! Background and Desktop Activity Moderator (piece R13): the last run time of each program per
//! user, from SYSTEM's `Services\bam` and `Services\dam` in every control set, as RECmd's Bam
//! plugin reads them. Windows 10 1709 to 1803 keep them in `UserSettings\<SID>`, later versions
//! in `State\UserSettings\<SID>`. Each entry is a record (program and SID) with its time as an
//! event.

use crate::autoruns::{control_sets, plain};
use crate::registry::{REG_BINARY, path, system_hive};
use crate::registry_timeline::key_locator;
use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::path::Name;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{CAPABILITY_REGISTRY, NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

/// Each BAM and DAM entry as a `windows.bam.entry` record and a `windows.bam.last_run` event.
pub struct Bam;

impl Plugin for Bam {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.bam").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: ["windows.hive.system", "windows.hive.log"]
                .into_iter()
                .map(|k| Input {
                    kind: Kind::new(k).expect("valid kind"),
                    required: false,
                })
                .collect(),
            needs: vec![Kind::new(CAPABILITY_REGISTRY).expect("valid kind")],
            produces: ["windows.bam.entry", "windows.bam.last_run"]
                .into_iter()
                .map(|k| Kind::new(k).expect("valid kind"))
                .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(reg) = ctx.caps.registry else {
            return Outcome::NotAcquired;
        };
        let system = system_hive();
        let Some((source, hive)) = reg.origin(&system) else {
            return Outcome::Ok(0);
        };
        let id = self.manifest().id.clone();
        let source_text = source.to_string();
        let record_kind = Kind::new("windows.bam.entry").expect("valid kind");
        let kind = Kind::new("windows.bam.last_run").expect("valid kind");
        let meaning = TimeMeaning::new(kind.as_str()).expect("valid meaning");
        let mut n = 0;
        for set in control_sets(reg) {
            for (moderator, layout) in [
                ("bam", "State\\UserSettings"),
                ("bam", "UserSettings"),
                ("dam", "State\\UserSettings"),
                ("dam", "UserSettings"),
            ] {
                let at = format!("{set}\\Services\\{moderator}\\{layout}");
                let Some(list) = reg.key(&system, &path(&at)) else {
                    continue;
                };
                for sid in list.subkeys.iter().map(Name::display) {
                    let Some(k) = reg.key(&system, &path(&format!("{at}\\{sid}"))) else {
                        continue;
                    };
                    let key = key_locator(&hive, &k);
                    // `Version` and `SequenceNumber` are DWORDs; entries are a FILETIME and more.
                    for v in k.values.iter().filter(|v| v.value_type == REG_BINARY) {
                        let Some(ticks) = v.data.get(..8) else {
                            continue;
                        };
                        let program = plain(&v.name);
                        let locator = key.child("reg.value", &program);
                        let record = record_id(&source_text, &locator);
                        let attrs = serde_json::json!({
                            "moderator": moderator,
                            "sid": sid,
                            "program": program,
                            "control_set": set,
                        });
                        ctx.sink.record(
                            &id,
                            ctx.system.id,
                            NewRecord {
                                id: record,
                                source,
                                kind: record_kind.clone(),
                                locator: locator.clone(),
                                attrs: Some(attrs.to_string()),
                            },
                        );
                        ctx.sink.event(
                            &id,
                            ctx.system.id,
                            NewEvent {
                                id: EventId::derive(
                                    &source_text,
                                    &locator,
                                    None,
                                    &kind,
                                    &meaning,
                                    0,
                                ),
                                source,
                                record,
                                kind: kind.clone(),
                                meaning: meaning.clone(),
                                time: Time::from_ticks_1601(u64::from_le_bytes(
                                    ticks.try_into().expect("eight bytes"),
                                )),
                                clock: ClockDomainId("wall".into()),
                                seq: None,
                            },
                        );
                        n += 1;
                    }
                }
            }
        }
        Outcome::Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::REG_DWORD;
    use af_core::bytes::Locator;
    use af_core::capability::{Capabilities, FakeRegistry};
    use af_core::ids::{SourceId, SystemId};
    use af_core::runner::{NewFact, Sink, Target, run};
    use af_core::system::System;

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

    /// LoneWolf's csrss.exe entry (1709 layout, as RECmd shows it) and a later Windows' DAM
    /// entry; `Version` is no entry.
    #[test]
    fn both_layouts_and_moderators() {
        let old = "ControlSet001\\Services\\bam\\UserSettings\\S-1-5-18";
        let new = "ControlSet001\\Services\\dam\\State\\UserSettings\\S-1-5-21-1";
        let mut entry = 131_674_920_388_104_203u64.to_le_bytes().to_vec();
        entry.extend([0; 16]);
        let mut r = FakeRegistry::new();
        r.set(
            "windows.system",
            old,
            "\\Device\\HarddiskVolume4\\Windows\\System32\\csrss.exe",
            REG_BINARY,
            &entry,
        )
        .set(
            "windows.system",
            old,
            "Version",
            REG_DWORD,
            &1u32.to_le_bytes(),
        )
        .set(
            "windows.system",
            new,
            "Microsoft.Photos",
            REG_BINARY,
            &entry,
        )
        .set_origin(
            "windows.system",
            SourceId(1),
            Locator::root("source.loose", "SYSTEM"),
        );
        let sys = System {
            id: SystemId(1),
            family: Family::Windows,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let caps = Capabilities { registry: Some(&r) };
        let targets = [Target::new(&sys, caps, vec![], None)];
        let mut out = Out::default();
        run(
            &[&Bam],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        assert_eq!(out.0.len(), 4, "{:#?}", out.0);
        assert!(
            out.0[0].ends_with(
                r#"reg.value:\Device\HarddiskVolume4\Windows\System32\csrss.exe {"moderator":"bam","sid":"S-1-5-18","program":"\\Device\\HarddiskVolume4\\Windows\\System32\\csrss.exe","control_set":"ControlSet001"}"#
            ),
            "{}",
            out.0[0]
        );
        assert_eq!(
            out.0[1],
            "windows.bam.last_run 2018-04-06 12:40:38.8104203 UTC"
        );
        assert!(out.0[2].contains(r#""moderator":"dam""#), "{}", out.0[2]);
    }
}
