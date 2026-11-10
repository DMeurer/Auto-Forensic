//! Shortcut files as records and events (piece X3): every `.lnk` the profile indexes (anything
//! below a user's profile folder and in the shared Start Menu, the user's choice) becomes a
//! `windows.lnk.file` record: the target's path, volume (drive type, serial, label), size,
//! strings, MFT reference and tracker data. The target times it stores are events
//! (`windows.lnk.target_created`, `target_modified`, `target_accessed`), and so is the time its
//! tracker droid was made (`windows.lnk.tracker_created`). The shortcut's own file times come
//! from `fs.timeline`. A file that doesn't parse is a note.

use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

const EVENTS: [&str; 4] = [
    "windows.lnk.target_created",
    "windows.lnk.target_modified",
    "windows.lnk.target_accessed",
    "windows.lnk.tracker_created",
];

/// Every indexed shortcut as a record, with the times it stores as events.
pub struct Shortcuts;

impl Plugin for Shortcuts {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.lnk").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("windows.lnk").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: std::iter::once("windows.lnk.file")
                .chain(EVENTS)
                .map(|k| Kind::new(k).expect("valid kind"))
                .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let record_kind = Kind::new("windows.lnk.file").expect("valid kind");
        let kinds = EVENTS.map(|k| {
            (
                Kind::new(k).expect("valid kind"),
                TimeMeaning::new(k).expect("valid meaning"),
            )
        });
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "windows.lnk")
        {
            let path = a.locator.steps().last().map_or("", |s| s.id.as_str());
            let data = opener.open(a).and_then(|src| {
                let mut buf = vec![0; usize::try_from(src.len()).map_err(std::io::Error::other)?];
                src.read_exact_at(0, &mut buf).map(|()| buf)
            });
            let link = match data
                .map_err(|e| e.to_string())
                .and_then(|d| af_fmt_lnk::read(&d))
            {
                Ok(l) => l,
                Err(e) => {
                    ctx.sink.note(
                        &id,
                        ctx.system.id,
                        format!("shortcut {path} wasn't read: {e}"),
                    );
                    continue;
                }
            };
            let source_text = a.source.to_string();
            let record = record_id(&source_text, &a.locator);
            let target = match (&link.local_path, &link.network, &link.common_path) {
                (Some(p), _, suffix) => Some(format!("{p}{}", suffix.as_deref().unwrap_or(""))),
                (None, Some(net), suffix) => net.net_name.as_ref().map(|n| match suffix {
                    Some(s) => format!("{n}\\{s}"),
                    None => n.clone(),
                }),
                (None, None, _) => None,
            };
            let attrs = serde_json::json!({
                "target": target,
                "environment": link.environment,
                "size": link.size,
                "attributes": link.attributes,
                "drive_type": link.volume.as_ref().map(|v| drive_type(v.drive_type)),
                "volume_serial": link.volume.as_ref().map(|v| format!("{:08X}", v.serial)),
                "volume_label": link.volume.as_ref().and_then(|v| v.label.clone()),
                "network_share": link.network.as_ref().and_then(|n| n.net_name.clone()),
                "network_drive": link.network.as_ref().and_then(|n| n.device_name.clone()),
                "name": link.name,
                "relative_path": link.relative_path,
                "working_dir": link.working_dir,
                "arguments": link.arguments,
                "icon_location": link.icon_location,
                "target_mft_entry": link.target_mft.map(|(e, _)| e),
                "target_mft_sequence": link.target_mft.map(|(_, s)| s),
                "machine_id": link.tracker.as_ref().map(|t| t.machine_id.clone()),
                "mac": link.tracker.as_ref().and_then(|t| t.mac.clone()),
                "volume_droid": link.tracker.as_ref().map(|t| t.volume_droid.clone()),
                "file_droid": link.tracker.as_ref().map(|t| t.file_droid.clone()),
                "volume_droid_birth": link.tracker.as_ref().map(|t| t.volume_droid_birth.clone()),
                "file_droid_birth": link.tracker.as_ref().map(|t| t.file_droid_birth.clone()),
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
            let times = [
                link.created,
                link.modified,
                link.accessed,
                link.tracker
                    .as_ref()
                    .and_then(|t| t.droid_created)
                    .unwrap_or(0),
            ];
            for ((kind, meaning), ticks) in kinds.iter().zip(times).filter(|(_, t)| *t != 0) {
                ctx.sink.event(
                    &id,
                    ctx.system.id,
                    NewEvent {
                        id: EventId::derive(&source_text, &a.locator, None, kind, meaning, 0),
                        source: a.source,
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
        }
        Outcome::Ok(n)
    }
}

/// `DRIVE_*` as a word.
fn drive_type(t: u32) -> String {
    match t {
        0 => "unknown".into(),
        1 => "no root folder".into(),
        2 => "removable".into(),
        3 => "fixed".into(),
        4 => "network".into(),
        5 => "CD-ROM".into(),
        6 => "RAM disk".into(),
        t => t.to_string(),
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
                "{} size {} target {}",
                r.kind, a["size"], a["target"]
            ));
        }
        fn note(&mut self, _: &Kind, _: SystemId, text: String) {
            self.0.push(text);
        }
    }

    fn artifact(path: &str) -> Artifact {
        Artifact {
            kind: Kind::new("windows.lnk").expect("valid kind"),
            locator: Locator::root("source.folder", "1").child("fs.path", path),
            source: SourceId(1),
            system: Some(SystemId(1)),
            sha256: String::new(),
        }
    }

    /// A bare header (target created and modified, no paths) and a file that is no shortcut.
    #[test]
    fn target_times_are_events_and_damage_a_note() {
        let mut header = vec![0u8; 0x4C];
        header[0] = 0x4C;
        header[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
        ]);
        header[0x1C..0x24].copy_from_slice(&131_674_911_875_724_698u64.to_le_bytes());
        header[0x2C..0x34].copy_from_slice(&131_674_920_388_104_203u64.to_le_bytes());
        header[0x34..0x38].copy_from_slice(&3u32.to_le_bytes());
        let good = artifact("Users/u/Desktop/a.lnk");
        let bad = artifact("Users/u/Desktop/b.lnk");
        let opener = Files(vec![(good.clone(), header), (bad.clone(), b"MZ".to_vec())]);
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
            vec![good, bad],
            Some(&opener),
        )];
        let mut out = Out::default();
        run(
            &[&Shortcuts],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        assert_eq!(
            out.0,
            [
                "windows.lnk.file size 3 target null",
                "windows.lnk.target_created 2018-04-06 12:26:27.5724698 UTC",
                "windows.lnk.target_modified 2018-04-06 12:40:38.8104203 UTC",
                "shortcut Users/u/Desktop/b.lnk wasn't read: not a shortcut: no ShellLinkHeader",
            ]
        );
    }
}
