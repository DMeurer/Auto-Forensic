//! Event logs as generic events (piece E2). Every EVTX record becomes one record row, with the
//! whole `Event` element as its attributes, and one event at its `TimeCreated` of kind
//! `windows.evtx.<event ID>`, numbered by its record number within its log. What a log's
//! fields mean comes later, from maps (E3, E4).

use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, Sequence, TimeMeaning};
use std::sync::OnceLock;

/// Every record of every event log, as `windows.evtx.record` records and
/// `windows.evtx.<event ID>` events.
pub struct EventLogs;

impl Plugin for EventLogs {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.evtx.events").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("windows.evtx").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: vec![Kind::new("windows.evtx.record").expect("valid kind")],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let record_kind = Kind::new("windows.evtx.record").expect("valid kind");
        let meaning = TimeMeaning::new("evtx.time_created").expect("valid meaning");
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "windows.evtx")
        {
            let path = a.locator.steps().last().map_or("", |s| s.id.as_str());
            let data = opener.open(a).and_then(|src| {
                let mut buf = vec![0; usize::try_from(src.len()).map_err(std::io::Error::other)?];
                src.read_exact_at(0, &mut buf).map(|()| buf)
            });
            let log = match data.map_err(|e| e.to_string()).and_then(af_fmt_evtx::read) {
                Ok(log) => log,
                Err(e) => {
                    ctx.sink.note(
                        &id,
                        ctx.system.id,
                        format!("event log {path} wasn't read: {e}"),
                    );
                    continue;
                }
            };
            if !log.errors.is_empty() {
                ctx.sink.note(
                    &id,
                    ctx.system.id,
                    format!(
                        "event log {path} is damaged: {} chunk(s) or record(s) failed, {} \
                         records read (first error: {})",
                        log.errors.len(),
                        log.records.len(),
                        log.errors[0].lines().next().unwrap_or("")
                    ),
                );
            }
            if log.bad_header {
                ctx.sink.note(
                    &id,
                    ctx.system.id,
                    format!("event log {path} has a damaged header; its chunks were read anyway"),
                );
            }
            let source = a.source.to_string();
            let domain = a.locator.to_string();
            for r in log.records {
                let locator = a.locator.child("evtx.record", &r.record_id.to_string());
                let record = record_id(&source, &locator);
                let Ok(kind) = Kind::new(&format!("windows.evtx.{}", r.event_id)) else {
                    continue;
                };
                ctx.sink.event(
                    &id,
                    ctx.system.id,
                    NewEvent {
                        id: EventId::derive(&source, &locator, None, &kind, &meaning, 0),
                        source: a.source,
                        record,
                        kind,
                        meaning: meaning.clone(),
                        time: Time::from_ticks_1601(r.written as u64),
                        clock: ClockDomainId("wall".into()),
                        seq: Some(Sequence {
                            domain: domain.clone(),
                            no: i64::try_from(r.record_id).unwrap_or(i64::MAX),
                        }),
                    },
                );
                ctx.sink.record(
                    &id,
                    ctx.system.id,
                    NewRecord {
                        id: record,
                        source: a.source,
                        kind: record_kind.clone(),
                        locator,
                        attrs: Some(r.event.to_string()),
                    },
                );
                n += 1;
            }
        }
        Outcome::Ok(n)
    }
}
