//! Registry key last-write times as a timeline (piece R7): one record and one event per key of
//! every hive the registry capability offers, machine and user hives alike. The record's locator
//! is the hive file's with a `reg.key` step holding the key's path (`\` for the root), so a
//! value-based event of a later plugin points at the record of the key that holds the value and
//! carries that key's time, never a parent's (stage 0: RECmd dated a USB serial by its parent).

use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::path::Name;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{CAPABILITY_REGISTRY, NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

/// Every registry key's last-written time.
pub struct KeyTimes;

impl Plugin for KeyTimes {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.registry.key_times").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            // The hives and their logs, so a changed hive or log extracts again.
            inputs: crate::plugins::HIVES
                .iter()
                .chain(&["windows.hive.log"])
                .map(|k| Input {
                    kind: Kind::new(k).expect("valid kind"),
                    required: false,
                })
                .collect(),
            needs: vec![Kind::new(CAPABILITY_REGISTRY).expect("valid kind")],
            produces: vec![
                Kind::new("windows.registry.key").expect("valid kind"),
                Kind::new("windows.registry.key_written").expect("valid kind"),
            ],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(reg) = ctx.caps.registry else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let record_kind = Kind::new("windows.registry.key").expect("valid kind");
        let event_kind = Kind::new("windows.registry.key_written").expect("valid kind");
        let meaning = TimeMeaning::new("registry.key.last_written").expect("valid meaning");
        let system = ctx.system.id;
        let mut n = 0;
        for hive in reg.hives() {
            let Some((source, hive_locator)) = reg.origin(&hive) else {
                continue;
            };
            let source_text = source.to_string();
            let sink = &mut *ctx.sink;
            reg.walk(&hive, &mut |k| {
                let names: Vec<String> = k.path.names().iter().map(Name::display).collect();
                let path = format!("\\{}", names.join("\\"));
                let locator = hive_locator.child("reg.key", &path);
                let record = record_id(&source_text, &locator);
                let attrs = serde_json::json!({
                    "hive": hive.kind.as_str(),
                    "owner": hive.owner,
                    "path": path,
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
                sink.event(
                    &id,
                    system,
                    NewEvent {
                        id: EventId::derive(&source_text, &locator, None, &event_kind, &meaning, 0),
                        source,
                        record,
                        kind: event_kind.clone(),
                        meaning: meaning.clone(),
                        time: k
                            .last_written
                            .clone()
                            .unwrap_or_else(|| Time::from_ticks_1601(0)),
                        clock: ClockDomainId("wall".into()),
                        seq: None,
                    },
                );
                n += 1;
            });
        }
        Outcome::Ok(n)
    }
}
