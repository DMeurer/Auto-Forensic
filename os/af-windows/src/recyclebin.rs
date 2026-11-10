//! The Recycle Bin (piece X4): every `$I` file in `$Recycle.Bin\<SID>` (Vista and later) holds a
//! deleted file's original path, size and deletion time; its content is the `$R` file (or
//! folder, for a deleted folder) of the same name beside it, until the bin is emptied. Each
//! `$I` becomes a `windows.recyclebin.item` record (original path, size, the SID of the user who
//! deleted it, and whether the `$R` still exists: `recoverable`) and a
//! `windows.recyclebin.deleted` event. XP's `RECYCLER\INFO2` is not read.

use af_core::artifact::Artifact;
use af_core::bytes::{Locator, LocatorStep};
use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

/// Every Recycle Bin `$I` file as a record and a deletion event.
pub struct RecycleBin;

impl Plugin for RecycleBin {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.recyclebin").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("windows.recyclebin.info").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: ["windows.recyclebin.item", "windows.recyclebin.deleted"]
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
        let record_kind = Kind::new("windows.recyclebin.item").expect("valid kind");
        let kind = Kind::new("windows.recyclebin.deleted").expect("valid kind");
        let meaning = TimeMeaning::new(kind.as_str()).expect("valid meaning");
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "windows.recyclebin.info")
        {
            let path = a.locator.steps().last().map_or("", |s| s.id.as_str());
            let data = opener.open(a).and_then(|src| {
                let mut buf = vec![0; usize::try_from(src.len()).map_err(std::io::Error::other)?];
                src.read_exact_at(0, &mut buf).map(|()| buf)
            });
            let Some(info) = data.ok().and_then(|d| read(&d)) else {
                ctx.sink.note(
                    &id,
                    ctx.system.id,
                    format!("Recycle Bin file {path} wasn't read"),
                );
                continue;
            };
            let mut parts = path.rsplit('/');
            let name = parts.next().unwrap_or("");
            let sid = parts.next();
            // `None`: this source can't tell (a loose file).
            let recoverable = data_beside(a).and_then(|r| opener.exists(&r).ok());
            let source_text = a.source.to_string();
            let record = record_id(&source_text, &a.locator);
            let attrs = serde_json::json!({
                "original_path": info.path,
                "size": info.size,
                "sid": sid,
                "recoverable": recoverable,
                "data": format!("$R{}", name.get(2..).unwrap_or("")),
                "version": info.version,
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
            if info.deleted != 0 {
                ctx.sink.event(
                    &id,
                    ctx.system.id,
                    NewEvent {
                        id: EventId::derive(&source_text, &a.locator, None, &kind, &meaning, 0),
                        source: a.source,
                        record,
                        kind: kind.clone(),
                        meaning: meaning.clone(),
                        time: Time::from_ticks_1601(info.deleted),
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

/// What a `$I` file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Info {
    /// 1 (Vista to 8.1: a fixed 260-character path) or 2 (10 and later: a counted path).
    pub version: u64,
    pub size: u64,
    /// The deletion time, a FILETIME.
    pub deleted: u64,
    pub path: String,
}

/// A `$I` file, or `None` if it isn't one.
pub(crate) fn read(d: &[u8]) -> Option<Info> {
    let u64_at = |o: usize| Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?));
    let version = u64_at(0)?;
    let path = match version {
        1 => d.get(24..)?,
        2 => {
            let chars = u32::from_le_bytes(d.get(24..28)?.try_into().ok()?) as usize;
            d.get(28..28 + chars.checked_mul(2)?)?
        }
        _ => return None,
    };
    Some(Info {
        version,
        size: u64_at(8)?,
        deleted: u64_at(16)?,
        path: crate::sam::utf16(path)?,
    })
}

/// The `$R` beside a `$I` artifact, as an artifact the opener can look for.
fn data_beside(a: &Artifact) -> Option<Artifact> {
    let mut steps = a.locator.steps().to_vec();
    let last = steps.pop()?;
    let (dir, name) = last.id.rsplit_once('/').unwrap_or(("", &last.id));
    let rest = name
        .strip_prefix("$I")
        .or_else(|| name.strip_prefix("$i"))?;
    let id = if dir.is_empty() {
        format!("$R{rest}")
    } else {
        format!("{dir}/$R{rest}")
    };
    steps.push(LocatorStep {
        kind: last.kind,
        id,
    });
    Some(Artifact {
        locator: Locator(steps),
        ..a.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::bytes::{ByteSource, MemSource};
    use af_core::capability::Capabilities;
    use af_core::ids::{SourceId, SystemId};
    use af_core::runner::{NewFact, Opener, Sink, Target, run};
    use af_core::system::System;

    /// A version 2 `$I` (Windows 10) for `path`, 41,171,024 bytes, deleted at `when`.
    fn info_v2(path: &str, when: u64) -> Vec<u8> {
        let units: Vec<u16> = path.encode_utf16().chain([0]).collect();
        let mut d = 2u64.to_le_bytes().to_vec();
        d.extend(41_171_024u64.to_le_bytes());
        d.extend(when.to_le_bytes());
        d.extend((units.len() as u32).to_le_bytes());
        d.extend(units.iter().flat_map(|u| u.to_le_bytes()));
        d
    }

    #[test]
    fn both_versions() {
        let v2 = read(&info_v2("C:\\Users\\u\\Desktop\\plan.docx", 7)).unwrap();
        assert_eq!(
            (v2.version, v2.size, v2.deleted, v2.path.as_str()),
            (2, 41_171_024, 7, "C:\\Users\\u\\Desktop\\plan.docx")
        );
        // Version 1: the path in a fixed 520-byte field.
        let mut v1 = 1u64.to_le_bytes().to_vec();
        v1.extend(5u64.to_le_bytes());
        v1.extend(9u64.to_le_bytes());
        let mut path: Vec<u8> = "C:\\x.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        path.resize(520, 0);
        v1.extend(path);
        assert_eq!(read(&v1).unwrap().path, "C:\\x.txt");
        assert_eq!(read(&[3, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(read(&2u64.to_le_bytes()), None);
    }

    /// One `$I` whose `$R` is still there, one whose `$R` is gone.
    struct Bin(Vec<(Artifact, Vec<u8>)>, Vec<String>);

    impl Opener for Bin {
        fn open(&self, a: &Artifact) -> std::io::Result<Box<dyn ByteSource>> {
            let (_, d) = self.0.iter().find(|(x, _)| x == a).expect("known artifact");
            Ok(Box::new(MemSource::new(d.clone(), a.locator.clone())))
        }
        fn exists(&self, a: &Artifact) -> std::io::Result<bool> {
            Ok(self.1.contains(&a.locator.steps()[1].id))
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
                "{} {} {} {}",
                a["original_path"], a["sid"], a["recoverable"], a["data"]
            ));
        }
    }

    #[test]
    fn recoverable_when_the_data_is_still_there() {
        let dir = "$Recycle.Bin/S-1-5-21-1-1001";
        let artifact = |name: &str| Artifact {
            kind: Kind::new("windows.recyclebin.info").expect("valid kind"),
            locator: Locator::root("source.folder", "1").child("fs.path", &format!("{dir}/{name}")),
            source: SourceId(1),
            system: Some(SystemId(1)),
            sha256: String::new(),
        };
        let (kept, gone) = (artifact("$I23A30B.docx"), artifact("$IQAU6NQ"));
        let when = 131_674_911_875_724_698;
        let opener = Bin(
            vec![
                (kept.clone(), info_v2("C:\\a.docx", when)),
                (gone.clone(), info_v2("C:\\b", when)),
            ],
            vec![format!("{dir}/$R23A30B.docx")],
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
            vec![kept, gone],
            Some(&opener),
        )];
        let mut out = Out::default();
        run(
            &[&RecycleBin],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        assert_eq!(
            out.0,
            [
                r#""C:\\a.docx" "S-1-5-21-1-1001" true "$R23A30B.docx""#,
                "windows.recyclebin.deleted 2018-04-06 12:26:27.5724698 UTC",
                r#""C:\\b" "S-1-5-21-1-1001" false "$RQAU6NQ""#,
                "windows.recyclebin.deleted 2018-04-06 12:26:27.5724698 UTC",
            ]
        );
    }
}
