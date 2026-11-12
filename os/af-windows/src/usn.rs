//! NTFS change journal events (piece M6): every record of `$Extend\$UsnJrnl:$J` on every NTFS
//! file system becomes an `ntfs.usn.record` record (USN, file and parent references, name, the
//! folder path it had then, its change flags as MFTECmd names them), and each change flag one
//! event at the record's time: `ntfs.usn.file_create`, `ntfs.usn.file_delete`,
//! `ntfs.usn.rename_new_name`, `ntfs.usn.close` and so on (one per flag, your choice). The record
//! names its file by MFT record and sequence number; it isn't linked to it (L6: a link from every
//! journal event to its file is the "links every file" noise the user ruled out).

use af_core::bytes::SourceReader;
use af_core::fs::{FileSystem, StreamName};
use af_core::ids::{EventId, FileId, record_id};
use af_core::names::Kind;
use af_core::path::{Name, NameKind};
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewRecord, Plugin, RunContext};
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use af_fmt_usn::{FileRef, Names, parent_paths};
use std::sync::OnceLock;

/// `USN_REASON_*`: bit, MFTECmd's name, the event kind's last part.
const REASONS: [(u32, &str, &str); 23] = [
    (0x0000_0001, "DataOverwrite", "data_overwrite"),
    (0x0000_0002, "DataExtend", "data_extend"),
    (0x0000_0004, "DataTruncation", "data_truncation"),
    (0x0000_0010, "NamedDataOverwrite", "named_data_overwrite"),
    (0x0000_0020, "NamedDataExtend", "named_data_extend"),
    (0x0000_0040, "NamedDataTruncation", "named_data_truncation"),
    (0x0000_0100, "FileCreate", "file_create"),
    (0x0000_0200, "FileDelete", "file_delete"),
    (0x0000_0400, "EaChange", "ea_change"),
    (0x0000_0800, "SecurityChange", "security_change"),
    (0x0000_1000, "RenameOldName", "rename_old_name"),
    (0x0000_2000, "RenameNewName", "rename_new_name"),
    (0x0000_4000, "IndexableChange", "indexable_change"),
    (0x0000_8000, "BasicInfoChange", "basic_info_change"),
    (0x0001_0000, "HardLinkChange", "hard_link_change"),
    (0x0002_0000, "CompressionChange", "compression_change"),
    (0x0004_0000, "EncryptionChange", "encryption_change"),
    (0x0008_0000, "ObjectIdChange", "object_id_change"),
    (0x0010_0000, "ReparsePointChange", "reparse_point_change"),
    (0x0020_0000, "StreamChange", "stream_change"),
    (0x0040_0000, "TransactedChange", "transacted_change"),
    (0x0080_0000, "IntegrityChange", "integrity_change"),
    (0x8000_0000, "Close", "close"),
];
/// The NTFS root folder's reference.
const ROOT: FileRef = (5, 5);

/// Every change journal record as a record, with one event per change flag.
pub struct Journal;

impl Plugin for Journal {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.usn").expect("valid kind"),
            // 2: no links to files (L6).
            version: 2,
            // NTFS on any system: a stick has a journal too.
            applies_to: vec![],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("fs.ntfs").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: std::iter::once("ntfs.usn.record".to_string())
                .chain(REASONS.iter().map(|(_, _, k)| format!("ntfs.usn.{k}")))
                .map(|k| Kind::new(&k).expect("valid kind"))
                .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let kinds: Vec<(u32, &str, Kind, TimeMeaning)> = REASONS
            .iter()
            .map(|(bit, name, k)| {
                let k = format!("ntfs.usn.{k}");
                (
                    *bit,
                    *name,
                    Kind::new(&k).expect("valid kind"),
                    TimeMeaning::new(&k).expect("valid meaning"),
                )
            })
            .collect();
        let record_kind = Kind::new("ntfs.usn.record").expect("valid kind");
        let (system, sink) = (ctx.system.id, &mut *ctx.sink);
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "fs.ntfs")
        {
            let source_text = a.source.to_string();
            let mut note = None;
            let opened = opener.file_system(a, &mut |fs| {
                let records = match journal(fs) {
                    Ok(Some(r)) => r,
                    Ok(None) => return,
                    Err(e) => {
                        note = Some(format!("change journal on {} wasn't read: {e}", a.locator));
                        return;
                    }
                };
                let paths = parent_paths(&records, names_now(fs));
                for (r, parent_path) in records.iter().zip(paths) {
                    let locator = a.locator.child("ntfs.usn", &r.usn.to_string());
                    let record = record_id(&source_text, &locator);
                    let flags: Vec<String> = REASONS
                        .iter()
                        .filter(|(bit, ..)| r.reasons & bit != 0)
                        .map(|(_, name, _)| name.to_string())
                        .chain(unknown(r.reasons))
                        .collect();
                    let attrs = serde_json::json!({
                        "usn": r.usn,
                        "entry": r.file.0,
                        "sequence": r.file.1,
                        "parent_entry": r.parent.0,
                        "parent_sequence": r.parent.1,
                        "name": r.name,
                        "parent_path": parent_path,
                        "reasons": flags,
                        "attributes": r.attributes,
                    });
                    sink.record(
                        &id,
                        system,
                        NewRecord {
                            id: record,
                            source: a.source,
                            kind: record_kind.clone(),
                            locator: locator.clone(),
                            attrs: Some(attrs.to_string()),
                        },
                    );
                    let Some(ticks) = r.ticks else { continue };
                    for (_, _, kind, meaning) in
                        kinds.iter().filter(|(bit, ..)| r.reasons & bit != 0)
                    {
                        sink.event(
                            &id,
                            system,
                            NewEvent {
                                id: EventId::derive(&source_text, &locator, None, kind, meaning, 0),
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
            });
            if let Err(e) = opened {
                note = Some(format!("file system at {} wasn't read: {e}", a.locator));
            }
            if let Some(text) = note {
                sink.note(&id, system, text);
            }
        }
        Outcome::Ok(n)
    }
}

/// The records of `$Extend\$UsnJrnl:$J`; `None` when the volume keeps no journal.
fn journal(fs: &dyn FileSystem) -> std::io::Result<Option<Vec<af_fmt_usn::Record>>> {
    let child = |dir: &FileId, name: &str| -> std::io::Result<Option<FileId>> {
        Ok(fs
            .list(dir)?
            .into_iter()
            .find(|(n, _)| n.display().eq_ignore_ascii_case(name))
            .map(|(_, id)| id))
    };
    let root = fs.root();
    let Some(extend) = child(&root, "$Extend")? else {
        return Ok(None);
    };
    let Some(jrnl) = child(&extend, "$UsnJrnl")? else {
        return Ok(None);
    };
    let j = StreamName::Named(Name::from_text("$J", NameKind::Utf16));
    let Some(src) = fs.open(&jrnl, &j)? else {
        return Ok(None);
    };
    af_fmt_usn::read(SourceReader::new(src))
        .and_then(|r| r.collect::<Result<Vec<_>, _>>())
        .map(Some)
        .map_err(std::io::Error::other)
}

/// The names the file system holds now: each allocated entry's long name and folder.
fn names_now(fs: &dyn FileSystem) -> Names {
    let mut names = Names::new(ROOT);
    for e in fs.all().flatten().filter(|e| e.allocated) {
        let (Some(file), Some(n)) = (file_ref(&e.id), e.names.iter().find(|n| !n.alias)) else {
            continue;
        };
        if let Some(parent) = file_ref(&n.parent) {
            names.insert(file, crate::autoruns::plain(&n.name), parent);
        }
    }
    names
}

/// An NTFS file reference from its file ID (`ntfs.file_ref`).
fn file_ref(id: &FileId) -> Option<FileRef> {
    let v = u64::from_le_bytes(id.value.as_slice().try_into().ok()?);
    (id.scheme.as_str() == "ntfs.file_ref").then_some((v & 0xFFFF_FFFF_FFFF, (v >> 48) as u16))
}

/// Flags without a name, as `Unknown0x...`.
fn unknown(reasons: u32) -> Option<String> {
    let known = REASONS.iter().fold(0, |m, (bit, ..)| m | bit);
    (reasons & !known != 0).then(|| format!("Unknown{:#x}", reasons & !known))
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::artifact::Artifact;
    use af_core::bytes::{ByteSource, Locator};
    use af_core::capability::Capabilities;
    use af_core::fs::FakeFs;
    use af_core::ids::{SourceId, SystemId};
    use af_core::path::CasePolicy;
    use af_core::runner::{NewFact, NewLink, Opener, Sink, Target, run};
    use af_core::system::{Family, System};
    use af_fmt_usn::{Record, build_test_record};

    struct One(Artifact, FakeFs);

    impl Opener for One {
        fn open(&self, _: &Artifact) -> std::io::Result<Box<dyn ByteSource>> {
            unreachable!("the journal is read through the file system")
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
        fn link(&mut self, _: &Kind, _: NewLink) {
            panic!("no links (L6)")
        }
    }

    /// A file created and closed, then deleted: one event per flag, and no links.
    #[test]
    fn one_event_per_flag_and_no_links() {
        let mut fs = FakeFs::new(CasePolicy::Insensitive);
        let root = fs.root();
        let extend = fs.folder(&root, "$Extend");
        let jrnl = fs.file(&extend, "$UsnJrnl", b"");
        let rec = |usn: i64, reasons: u32| Record {
            file: (300, 2),
            parent: ROOT,
            usn,
            ticks: Some(131_674_911_875_724_698),
            reasons,
            attributes: 0x20,
            name: "secret.docx".into(),
            version: 2,
        };
        let mut j = vec![0u8; 64];
        j.extend(build_test_record(&rec(64, 0x8000_0100)));
        j.extend(build_test_record(&rec(184, 0x8000_0200)));
        fs.stream(
            &jrnl,
            StreamName::Named(Name::from_text("$J", NameKind::Utf16)),
            &j,
        );
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
            &[&Journal],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        let t = "2018-04-06 12:26:27.5724698 UTC";
        assert_eq!(
            out.0,
            [
                r#"{"usn":64,"entry":300,"sequence":2,"parent_entry":5,"parent_sequence":5,"name":"secret.docx","parent_path":"/","reasons":["FileCreate","Close"],"attributes":32}"#.to_string(),
                format!("ntfs.usn.file_create {t}"),
                format!("ntfs.usn.close {t}"),
                r#"{"usn":184,"entry":300,"sequence":2,"parent_entry":5,"parent_sequence":5,"name":"secret.docx","parent_path":"/","reasons":["FileDelete","Close"],"attributes":32}"#.into(),
                format!("ntfs.usn.file_delete {t}"),
                format!("ntfs.usn.close {t}"),
            ]
        );
    }

    #[test]
    fn unknown_flags_are_named_by_value() {
        assert_eq!(unknown(0x8000_0100), None);
        assert_eq!(unknown(0x0100_0008).as_deref(), Some("Unknown0x1000008"));
    }
}
