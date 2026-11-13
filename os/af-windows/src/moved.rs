//! Moved to (piece L11, NTFS part): the change journal writes a rename as a `RenameOldName`
//! record with the old name and folder, then a `RenameNewName` record with the new ones, both
//! for the same MFT entry and sequence. When the folder changes, the old name's event links to
//! the new name's, strong, labelled "moved to". Your choices: only folder changes (renames in
//! place are mostly programs saving through a temp file), not into `$Extend\$Deleted`, which
//! is Windows deleting a file, and not within `\Windows\WinSxS`, where Windows Update moves
//! thousands of files (93% of LoneWolf's moves). The FAT part (first cluster and size) comes with
//! the FAT reader in stage 5a.

use crate::sessions::derive;
use af_core::ids::{Endpoint, EventId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{LinkTier, NewLink, Plugin, RunContext, StoredRecord};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

const OLD: &str = "ntfs.usn.rename_old_name";
const NEW: &str = "ntfs.usn.rename_new_name";

/// Links a file's old journal name to its new one when it changed folder.
pub struct MovedTo;

impl Plugin for MovedTo {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.moved_to").expect("valid kind"),
            version: 1,
            // NTFS on any system, as the journal plugin.
            applies_to: vec![],
            phases: vec![Phase::Correlate],
            inputs: vec![Input {
                kind: Kind::new("fs.ntfs").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: vec![Kind::new("windows.moved_to").expect("valid kind")],
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let kind = self.manifest().id.clone();
        let Ok(records) = stored.records(
            ctx.system.id,
            &Kind::new("ntfs.usn.record").expect("valid kind"),
        ) else {
            return Outcome::Ok(0);
        };
        let found = moves(&records);
        let ids: Vec<u128> = found.iter().flat_map(|m| [m.old, m.new]).collect();
        let Ok(events) = stored.events_of(&ids) else {
            return Outcome::Ok(0);
        };
        let event: HashMap<(u128, &str), EventId> = events
            .iter()
            .map(|e| ((e.record, e.kind.as_str()), e.id))
            .collect();
        let mut n = 0;
        for m in &found {
            // A record without a time has no events.
            let (Some(from), Some(to)) = (event.get(&(m.old, OLD)), event.get(&(m.new, NEW)))
            else {
                continue;
            };
            ctx.sink.link(
                &kind,
                NewLink {
                    id: derive(&m.locator, &kind, "moved to"),
                    kind: kind.clone(),
                    from: Endpoint::Event(*from),
                    to: Endpoint::Event(*to),
                    tier: LinkTier::Strong,
                    label: "moved to".into(),
                    reason: format!(
                        "the journal renames MFT entry {} (sequence {}) from {} to {}",
                        m.entry, m.sequence, m.old_path, m.new_path
                    ),
                    key: format!("{}-{} / USN {} / {}", m.entry, m.sequence, m.usn.0, m.usn.1),
                    description: Some(format!("moved to {}", m.new_path)),
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// One rename into another folder.
#[derive(Debug, PartialEq)]
struct Move {
    old: u128,
    new: u128,
    locator: String,
    entry: u64,
    sequence: u64,
    usn: (u64, u64),
    old_path: String,
    new_path: String,
}

/// The journal record's fields this rule reads.
struct Rec<'a> {
    id: u128,
    locator: &'a str,
    usn: u64,
    parent: (u64, u64),
    path: String,
    old: bool,
    new: bool,
}

/// Each `RenameOldName` record with the next `RenameNewName` record of the same file on the
/// same volume, when the folder changed, the new one isn't `$Extend\$Deleted` and the move isn't
/// within `\Windows\WinSxS`.
fn moves(records: &[StoredRecord]) -> Vec<Move> {
    let mut files: BTreeMap<(&str, u64, u64), Vec<Rec>> = BTreeMap::new();
    for r in records {
        let Some(a) = r
            .attrs
            .as_deref()
            .and_then(|a| serde_json::from_str::<Value>(a).ok())
        else {
            continue;
        };
        let reasons: Vec<&str> = a["reasons"]
            .as_array()
            .map(|v| v.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let (old, new) = (
            reasons.contains(&"RenameOldName"),
            reasons.contains(&"RenameNewName"),
        );
        let (Some(usn), Some(entry), Some(sequence), Some(pe), Some(ps), Some(name)) = (
            a["usn"].as_u64(),
            a["entry"].as_u64(),
            a["sequence"].as_u64(),
            a["parent_entry"].as_u64(),
            a["parent_sequence"].as_u64(),
            a["name"].as_str(),
        ) else {
            continue;
        };
        if !(old || new) {
            continue;
        }
        let volume = r.locator.split("/ntfs.usn:").next().unwrap_or("");
        let path = match a["parent_path"].as_str() {
            Some("/") => format!("/{name}"),
            Some(p) => format!("{p}/{name}"),
            None => format!("<unknown folder>/{name}"),
        };
        files
            .entry((volume, entry, sequence))
            .or_default()
            .push(Rec {
                id: r.id,
                locator: &r.locator,
                usn,
                parent: (pe, ps),
                path,
                old,
                new,
            });
    }
    let mut out = vec![];
    for ((_, entry, sequence), mut recs) in files {
        recs.sort_by_key(|r| r.usn);
        for (i, o) in recs.iter().enumerate().filter(|(_, r)| r.old) {
            let Some(n) = recs[i + 1..].iter().find(|r| r.new) else {
                continue;
            };
            let winsxs = |p: &str| p.to_ascii_lowercase().starts_with("/windows/winsxs/");
            if n.parent == o.parent
                || n.path.starts_with("/$Extend/$Deleted/")
                || (winsxs(&o.path) && winsxs(&n.path))
            {
                continue;
            }
            out.push(Move {
                old: o.id,
                new: n.id,
                locator: o.locator.to_string(),
                entry,
                sequence,
                usn: (o.usn, n.usn),
                old_path: o.path.clone(),
                new_path: n.path.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        id: u128,
        usn: u64,
        file: u64,
        parent: u64,
        path: &str,
        name: &str,
        reasons: &[&str],
    ) -> StoredRecord {
        StoredRecord {
            id,
            locator: format!("source.image:1/volume.partition:4/ntfs.usn:{usn}"),
            attrs: Some(
                serde_json::json!({"usn": usn, "entry": file, "sequence": 2,
                    "parent_entry": parent, "parent_sequence": 1, "name": name,
                    "parent_path": path, "reasons": reasons})
                .to_string(),
            ),
        }
    }

    /// A video moved from Downloads to Music links; a rename in place, a POSIX delete into
    /// `$Extend\$Deleted`, a new name without an old one and a move within WinSxS don't.
    #[test]
    fn only_folder_changes_are_moves() {
        let records = [
            rec(
                1,
                100,
                40,
                10,
                "/Users/ich/Downloads",
                "a.mp4",
                &["RenameOldName"],
            ),
            rec(
                2,
                110,
                40,
                11,
                "/Users/ich/Music",
                "a.mp4",
                &["RenameNewName"],
            ),
            rec(
                3,
                120,
                40,
                11,
                "/Users/ich/Music",
                "a.mp4",
                &["RenameNewName", "Close"],
            ),
            rec(4, 130, 41, 12, "/p", "prefs-1.js", &["RenameOldName"]),
            rec(5, 140, 41, 12, "/p", "prefs.js", &["RenameNewName"]),
            rec(6, 150, 42, 12, "/p", "events", &["RenameOldName"]),
            rec(
                7,
                160,
                42,
                13,
                "/$Extend/$Deleted",
                "0002",
                &["RenameNewName"],
            ),
            rec(8, 170, 43, 12, "/", "x", &["RenameNewName"]),
            rec(
                9,
                180,
                44,
                14,
                "/Windows/WinSxS/Temp",
                "a.dll",
                &["RenameOldName"],
            ),
            rec(
                10,
                190,
                44,
                15,
                "/Windows/WinSxS/amd64_x",
                "a.dll",
                &["RenameNewName"],
            ),
        ];
        let found = moves(&records);
        assert_eq!(found.len(), 1);
        let m = &found[0];
        assert_eq!((m.old, m.new, m.usn), (1, 2, (100, 110)));
        assert_eq!(m.old_path, "/Users/ich/Downloads/a.mp4");
        assert_eq!(m.new_path, "/Users/ich/Music/a.mp4");
    }
}
