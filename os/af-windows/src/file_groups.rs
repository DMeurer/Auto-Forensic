//! File groups (piece G3, stage 0's "group by file, not by source row"): all `$MFT` and change
//! journal events of one file reference (volume, MFT entry and sequence) as one `windows.file`
//! group, which `af events` shows folded per day. A file with a single event gets none.
//!
//! Deleted files (piece G2, the user's choice: creation and deletion both known): a journal
//! deletion with the same reference's journal creation or its left `$MFT` entry is one
//! `windows.deleted_file` group. Deleting frees the entry and raises its sequence by one, so the
//! left entry is the same entry at sequence + 1, unused, under the same name (all 3,072 such
//! entries on LoneWolf).

use crate::same_file::file_ref;
use crate::sessions::derive;
use af_core::ids::{Endpoint, GroupId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewGroup, Plugin, RunContext, StoredEvent, StoredRecord};
use af_core::system::Family;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Groups each file's `$MFT` and journal events.
pub struct FileGroups;

impl Plugin for FileGroups {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        let kind = |k: &str| Kind::new(k).expect("valid kind");
        M.get_or_init(|| Manifest {
            id: kind("windows.file"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: ["fs.ntfs", "windows.mft"]
                .iter()
                .map(|k| Input {
                    kind: kind(k),
                    required: false,
                })
                .collect(),
            needs: vec![],
            produces: vec![kind("windows.file"), kind("windows.deleted_file")],
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let mut files = Files::default();
        for k in ["fs.entry", "ntfs.mft.record", "ntfs.usn.record"] {
            let records = stored
                .records(ctx.system.id, &Kind::new(k).expect("valid kind"))
                .unwrap_or_default();
            for r in &records {
                files.add(k, r);
            }
        }
        let Ok(events) = stored.events_of(&files.records()) else {
            return Outcome::Ok(0);
        };
        let mut n = 0;
        let plugin = self.manifest().id.clone();
        for g in files.groups(&events) {
            let kind = Kind::new(g.kind).expect("valid kind");
            ctx.sink.group(
                &plugin,
                NewGroup {
                    id: GroupId(derive(&g.volume, &kind, &g.subject)),
                    kind: kind.clone(),
                    reason: g.reason,
                    members: g.members,
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// (volume locator, MFT entry, sequence)
type FileKey = (String, u64, u16);

/// Records by the file they are about.
#[derive(Default)]
struct Files {
    by_key: HashMap<FileKey, File>,
    /// Record ID to its file.
    of: HashMap<u128, (FileKey, &'static str)>,
}

#[derive(Default)]
struct File {
    /// The `$MFT` entry's path, else the journal's latest: a file renamed before it was deleted
    /// is left in `$MFT` under its last name.
    path: Option<String>,
    from_mft: bool,
    /// The update sequence number `path` is from, for journal paths.
    usn: u64,
    /// Its `$MFT` entry is no longer in use.
    unused: bool,
}

/// One file's group.
struct Group {
    kind: &'static str,
    volume: String,
    subject: String,
    reason: String,
    members: Vec<(Endpoint, String)>,
}

impl Files {
    /// Notes record `r` of `kind` under its file, if it names one.
    fn add(&mut self, kind: &str, r: &StoredRecord) {
        let a: Value = r
            .attrs
            .as_deref()
            .and_then(|a| serde_json::from_str(a).ok())
            .unwrap_or_default();
        let (step, why) = match kind {
            "fs.entry" => ("/fs.entry:ntfs.file_ref:", "$MFT entry"),
            "ntfs.mft.record" => ("/ntfs.mft_record:", "$MFT entry"),
            _ => ("/ntfs.usn:", "journal"),
        };
        let Some((volume, id)) = r.locator.rsplit_once(step) else {
            return;
        };
        let (entry, seq, path, unused) = match kind {
            "fs.entry" => {
                let Some((e, s)) = file_ref(id) else { return };
                (
                    e,
                    s,
                    a["paths"][0].as_str().map(str::to_string),
                    a["allocated"] == false,
                )
            }
            "ntfs.mft.record" => {
                let (Some(e), Some(s)) = (a["number"].as_u64(), a["sequence"].as_u64()) else {
                    return;
                };
                let path = a["path"]
                    .as_str()
                    .map(|p| format!("/{}", p.replace('\\', "/")));
                (e, s as u16, path, a["in_use"] == false)
            }
            _ => {
                let (Some(e), Some(s)) = (a["entry"].as_u64(), a["sequence"].as_u64()) else {
                    return;
                };
                let path = match (a["parent_path"].as_str(), a["name"].as_str()) {
                    (Some(p), Some(n)) => Some(format!("{}/{n}", p.trim_end_matches('/'))),
                    (None, Some(n)) => Some(n.to_string()),
                    _ => None,
                };
                (e, s as u16, path, false)
            }
        };
        let key = (volume.to_string(), entry, seq);
        let f = self.by_key.entry(key.clone()).or_default();
        let mft = why == "$MFT entry";
        let usn = if mft { 0 } else { id.parse().unwrap_or(0) };
        if mft || (!f.from_mft && usn >= f.usn) {
            f.path = path.or(f.path.take());
            f.from_mft |= mft;
            f.usn = usn;
        }
        f.unused |= unused;
        self.of.insert(r.id, (key, why));
    }

    fn records(&self) -> Vec<u128> {
        self.of.keys().copied().collect()
    }

    /// A file group for each file with two or more events, and a deleted-file group for each
    /// deletion whose creation is known; members by time.
    fn groups(&self, events: &[StoredEvent]) -> Vec<Group> {
        let mut by_key: HashMap<&FileKey, Vec<(&StoredEvent, &str)>> = HashMap::new();
        for e in events {
            if let Some((key, why)) = self.of.get(&e.record) {
                by_key.entry(key).or_default().push((e, why));
            }
        }
        for members in by_key.values_mut() {
            members.sort_by_key(|(e, _)| (e.ts, e.id.0));
        }
        let mut out = vec![];
        for (key, members) in &by_key {
            if let Some(g) = self.deleted(key, members, &by_key) {
                out.push(g);
            }
        }
        for (key, members) in by_key {
            if members.len() < 2 {
                continue;
            }
            let (volume, entry, seq) = key;
            let journal = members.iter().filter(|(_, w)| *w == "journal").count();
            let mut parts = vec![];
            if journal < members.len() {
                parts.push("its $MFT entry".to_string());
            }
            if journal > 0 {
                let s = if journal == 1 { "" } else { "s" };
                parts.push(format!("{journal} journal event{s}"));
            }
            let path = self.by_key[key].path.as_deref().unwrap_or("a file");
            out.push(Group {
                kind: "windows.file",
                volume: volume.clone(),
                subject: format!("{entry}-{seq}"),
                reason: format!(
                    "{} events of {path} (MFT entry {entry}, sequence {seq}): {}",
                    members.len(),
                    parts.join(" and ")
                ),
                members: members
                    .into_iter()
                    .map(|(e, why)| (Endpoint::Event(e.id), why.to_string()))
                    .collect(),
            });
        }
        out
    }

    /// The deleted-file group of `key`: its journal creation and deletion, and its `$MFT` entry
    /// left at sequence + 1, when the deletion and one of the others are there.
    fn deleted(
        &self,
        key: &FileKey,
        members: &[(&StoredEvent, &str)],
        by_key: &HashMap<&FileKey, Vec<(&StoredEvent, &str)>>,
    ) -> Option<Group> {
        let journal = |k: &str| -> Vec<&StoredEvent> {
            members
                .iter()
                .filter(|(e, w)| *w == "journal" && e.kind == k)
                .map(|(e, _)| *e)
                .collect()
        };
        let deleted = journal("ntfs.usn.file_delete");
        if deleted.is_empty() {
            return None;
        }
        let (volume, entry, seq) = key;
        let name = |p: Option<&str>| p.and_then(|p| p.rsplit('/').next()).map(str::to_lowercase);
        let path = self.by_key[key].path.as_deref();
        let next = (volume.clone(), *entry, seq.wrapping_add(1));
        let left: Vec<&StoredEvent> = self
            .by_key
            .get(&next)
            .filter(|f| f.from_mft && f.unused && name(f.path.as_deref()) == name(path))
            .and_then(|_| by_key.get(&next))
            .map(|m| {
                m.iter()
                    .filter(|(_, w)| *w != "journal")
                    .map(|(e, _)| *e)
                    .collect()
            })
            .unwrap_or_default();
        let created = journal("ntfs.usn.file_create");
        if created.is_empty() && left.is_empty() {
            return None;
        }
        let mut list: Vec<(&StoredEvent, String)> = created
            .into_iter()
            .map(|e| (e, "created (journal)".to_string()))
            .chain(
                deleted
                    .into_iter()
                    .map(|e| (e, "deleted (journal)".to_string())),
            )
            .chain(
                left.iter()
                    .map(|e| (*e, format!("left in $MFT as sequence {}", next.2))),
            )
            .collect();
        list.sort_by_key(|(e, _)| (e.ts, e.id.0));
        let mut reason = format!(
            "{} was created and deleted (MFT entry {entry}, sequence {seq})",
            path.unwrap_or("a file")
        );
        if !left.is_empty() {
            reason.push_str(&format!("; its $MFT entry is left as sequence {}", next.2));
        }
        Some(Group {
            kind: "windows.deleted_file",
            volume: volume.clone(),
            subject: format!("{entry}-{seq}"),
            reason,
            members: list
                .into_iter()
                .map(|(e, why)| (Endpoint::Event(e.id), why))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::ids::EventId;

    fn rec(id: u128, locator: &str, attrs: Value) -> StoredRecord {
        StoredRecord {
            id,
            locator: locator.into(),
            attrs: Some(attrs.to_string()),
        }
    }

    fn ev(id: u128, record: u128, ts: i64) -> StoredEvent {
        StoredEvent {
            id: EventId(id),
            record,
            kind: "k".into(),
            ts: Some(ts),
        }
    }

    /// LoneWolf's `sync_config.db-wal`: entry 35044 sequence 82 has its `$MFT` entry and a
    /// journal create; sequence 81 only a delete with one event, so no group; the same entry on
    /// another volume is another file.
    #[test]
    fn mft_and_journal_events_of_one_reference_group() {
        let vol = "source.image:1/volume.partition:4";
        let mut f = Files::default();
        let wal = "/Users/j/Drive/sync_config.db-wal";
        f.add(
            "fs.entry",
            &rec(
                1,
                &format!("{vol}/fs.entry:ntfs.file_ref:e488000000005200"),
                serde_json::json!({"paths": [wal]}),
            ),
        );
        let usn = |id, v: &str, n: u64, seq: u64| {
            rec(
                id,
                &format!("{v}/ntfs.usn:{n}"),
                serde_json::json!({"entry": 35044, "sequence": seq,
                    "parent_path": "/Users/j/Drive", "name": "sync_config.db-wal"}),
            )
        };
        f.add("ntfs.usn.record", &usn(2, vol, 100, 82));
        f.add("ntfs.usn.record", &usn(3, vol, 50, 81));
        f.add(
            "ntfs.usn.record",
            &usn(4, "source.image:1/volume.partition:2", 7, 82),
        );
        let events = [
            ev(10, 1, 5),
            ev(11, 1, 6),
            ev(12, 2, 4),
            ev(13, 3, 1),
            ev(14, 4, 1),
        ];
        let g = f.groups(&events);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].subject, "35044-82");
        assert_eq!(
            g[0].reason,
            format!(
                "3 events of {wal} (MFT entry 35044, sequence 82): its $MFT entry and 1 journal event"
            )
        );
        let ids: Vec<(Endpoint, String)> = g[0].members.clone();
        assert_eq!(
            ids,
            [
                (Endpoint::Event(EventId(12)), "journal".to_string()),
                (Endpoint::Event(EventId(10)), "$MFT entry".to_string()),
                (Endpoint::Event(EventId(11)), "$MFT entry".to_string()),
            ]
        );
    }

    /// A loose `$MFT`'s record names its file by number and sequence, its path with `\`.
    #[test]
    fn a_loose_mft_record_names_its_file() {
        let mut f = Files::default();
        f.add(
            "ntfs.mft.record",
            &rec(
                1,
                "source.folder:1/fs.path:$MFT/ntfs.mft_record:4622",
                serde_json::json!({"path": "Windows\\x.dll", "number": 4622, "sequence": 3}),
            ),
        );
        let g = f.groups(&[ev(10, 1, 1), ev(11, 1, 2)]);
        assert_eq!(g[0].subject, "4622-3");
        assert!(g[0].reason.contains("/Windows/x.dll"), "{}", g[0].reason);
    }

    fn evk(id: u128, record: u128, ts: i64, kind: &str) -> StoredEvent {
        StoredEvent {
            kind: kind.into(),
            ..ev(id, record, ts)
        }
    }

    /// `a.tmp` (entry 7, sequence 3) created and deleted in the journal, its entry left unused as
    /// sequence 4; `b.tmp` deleted with its creation known only from the left entry; `c.tmp`
    /// deleted with neither, and entry 9's left record now under another name.
    #[test]
    fn deletions_with_a_known_creation_group() {
        let vol = "source.image:1/volume.partition:4";
        let usn = |id, n: u64, entry: u64, name: &str| {
            rec(
                id,
                &format!("{vol}/ntfs.usn:{n}"),
                serde_json::json!({"entry": entry, "sequence": 3, "parent_path": "/T", "name": name}),
            )
        };
        let mft = |id, file_ref: &str, name: &str| {
            rec(
                id,
                &format!("{vol}/fs.entry:ntfs.file_ref:{file_ref}"),
                serde_json::json!({"paths": [format!("/T/{name}")], "allocated": false}),
            )
        };
        let mut f = Files::default();
        // Renamed from `a.db` before the deletion; read out of journal order.
        f.add("ntfs.usn.record", &usn(2, 20, 7, "a.tmp"));
        f.add("ntfs.usn.record", &usn(1, 10, 7, "a.db"));
        f.add("fs.entry", &mft(3, "0700000000000400", "A.TMP"));
        f.add("ntfs.usn.record", &usn(4, 30, 8, "b.tmp"));
        f.add("fs.entry", &mft(5, "0800000000000400", "b.tmp"));
        f.add("ntfs.usn.record", &usn(6, 40, 9, "c.tmp"));
        f.add("fs.entry", &mft(7, "0900000000000400", "other.tmp"));
        let events = [
            evk(10, 1, 100, "ntfs.usn.file_create"),
            evk(11, 2, 200, "ntfs.usn.file_delete"),
            evk(12, 3, 50, "ntfs.si.created"),
            evk(13, 4, 300, "ntfs.usn.file_delete"),
            evk(14, 5, 60, "ntfs.si.created"),
            evk(15, 6, 400, "ntfs.usn.file_delete"),
            evk(16, 7, 70, "ntfs.si.created"),
        ];
        let mut g: Vec<Group> = f
            .groups(&events)
            .into_iter()
            .filter(|g| g.kind == "windows.deleted_file")
            .collect();
        g.sort_by(|a, b| a.subject.cmp(&b.subject));
        assert_eq!(g.len(), 2);
        assert_eq!(
            g[0].reason,
            "/T/a.tmp was created and deleted (MFT entry 7, sequence 3); its $MFT entry is left as sequence 4"
        );
        let why: Vec<&str> = g[0].members.iter().map(|(_, w)| w.as_str()).collect();
        assert_eq!(
            why,
            [
                "left in $MFT as sequence 4",
                "created (journal)",
                "deleted (journal)"
            ]
        );
        assert_eq!(g[1].subject, "8-3");
        assert_eq!(g[1].members.len(), 2);
    }
}
