//! One file across sources (piece L5, the user's choice of one group per file): a file's
//! `$MFT` entry on an image volume, the shortcuts that point at it and the Prefetch file of the
//! program it is, as one `windows.same_file` group of all their events. A shortcut names its
//! target by MFT entry, sequence and volume serial; a Prefetch file names its program by path
//! on a volume with a serial. No links: stage 0 found a link per program to its runs true but
//! useless (264 of them), and L6 forbids it.

use af_core::artifact::Artifact;
use af_core::ids::{Endpoint, FactId, GroupId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewGroup, Plugin, RunContext, StoredRecord};
use af_core::system::Family;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Groups each file with its shortcuts and Prefetch file.
pub struct SameFile;

impl Plugin for SameFile {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.same_file").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: vec![
                Input {
                    kind: Kind::new("fs.ntfs").expect("valid kind"),
                    required: true,
                },
                Input {
                    kind: Kind::new("windows.lnk").expect("valid kind"),
                    required: false,
                },
                Input {
                    kind: Kind::new("windows.prefetch").expect("valid kind"),
                    required: false,
                },
            ],
            needs: vec![],
            produces: vec![Kind::new("windows.same_file").expect("valid kind")],
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let (Some(opener), Some(stored)) = (ctx.opener, ctx.stored) else {
            return Outcome::Ok(0);
        };
        let kind = self.manifest().id.clone();
        // Each NTFS volume by the low 32 bits of its serial, as shortcuts and Prefetch store it.
        let mut volumes: Vec<(String, &Artifact)> = Vec::new();
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "fs.ntfs")
        {
            let mut serial = None;
            let _ = opener.file_system(a, &mut |fs| serial = fs.info().serial.clone());
            if let Some(s) = serial.filter(|s| s.len() >= 8) {
                volumes.push((s[s.len() - 8..].to_uppercase(), a));
            }
        }
        let records = |k: &str| {
            stored
                .records(ctx.system.id, &Kind::new(k).expect("valid kind"))
                .unwrap_or_default()
        };
        let serials: Vec<(String, String)> = volumes
            .iter()
            .map(|(s, a)| (s.clone(), a.locator.to_string()))
            .collect();
        let found = same_files(
            &serials,
            &records("fs.entry"),
            &records("windows.lnk.file"),
            &records("windows.prefetch.file"),
        );
        let ids: Vec<u128> = found
            .iter()
            .flat_map(|f| {
                std::iter::once(f.entry)
                    .chain(f.lnks.iter().copied())
                    .chain(f.prefetch.iter().copied())
            })
            .collect();
        let Ok(events) = stored.events_of(&ids) else {
            return Outcome::Ok(0);
        };
        let mut by_record: HashMap<u128, Vec<Endpoint>> = HashMap::new();
        for e in events {
            by_record
                .entry(e.record)
                .or_default()
                .push(Endpoint::Event(e.id));
        }
        let mut n = 0;
        for f in &found {
            let sources: Vec<&Vec<Endpoint>> = std::iter::once(f.entry)
                .chain(f.lnks.iter().copied())
                .chain(f.prefetch.iter().copied())
                .filter_map(|r| by_record.get(&r))
                .collect();
            if sources.len() < 2 {
                continue;
            }
            let members: Vec<Endpoint> = sources.into_iter().flatten().cloned().collect();
            let (_, volume) = volumes
                .iter()
                .find(|(_, a)| f.locator.starts_with(&a.locator.to_string()))
                .expect("found entries are on a listed volume");
            let id = FactId::derive(
                &volume.source.to_string(),
                &volume.locator,
                &kind,
                &f.locator,
            );
            let mut parts = vec!["$MFT".to_string()];
            match f.lnks.len() {
                0 => {}
                1 => parts.push("a shortcut".into()),
                k => parts.push(format!("{k} shortcuts")),
            }
            match f.prefetch.len() {
                0 => {}
                1 => parts.push("a Prefetch file".into()),
                k => parts.push(format!("{k} Prefetch files")),
            }
            let last = parts.pop().expect("$MFT is there");
            ctx.sink.group(
                &kind,
                NewGroup {
                    id: GroupId(id.0),
                    kind: kind.clone(),
                    reason: format!(
                        "{} events of {} in {} and {last}",
                        members.len(),
                        f.path,
                        parts.join(", ")
                    ),
                    members,
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// A file entry and the shortcuts and Prefetch file that name it.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    entry: u128,
    locator: String,
    path: String,
    lnks: Vec<u128>,
    prefetch: Vec<u128>,
}

/// Matches shortcuts (volume serial, MFT entry and sequence) and Prefetch files (volume serial
/// and path) to `fs.entry` records. `volumes` are (serial's low 32 bits in hex, locator).
/// shortcut: a shortcut to a since-deleted file finds nothing (deletion bumps the sequence);
/// match the deleted entry with sequence + 1 and the same path if analysts miss those.
fn same_files(
    volumes: &[(String, String)],
    entries: &[StoredRecord],
    lnks: &[StoredRecord],
    prefetch: &[StoredRecord],
) -> Vec<Found> {
    let attrs = |r: &StoredRecord| -> serde_json::Value {
        r.attrs
            .as_deref()
            .and_then(|a| serde_json::from_str(a).ok())
            .unwrap_or_default()
    };
    // Entries by (volume, entry, sequence) and by (volume, lower-case path).
    let mut by_ref: HashMap<(&str, u64, u16), usize> = HashMap::new();
    let mut by_path: HashMap<(&str, String), Vec<Candidate>> = HashMap::new();
    let mut paths: Vec<String> = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        let a = attrs(e);
        let first = a["paths"][0].as_str().unwrap_or_default().to_string();
        paths.push(first);
        let Some((volume, hex)) = e.locator.rsplit_once("/fs.entry:ntfs.file_ref:") else {
            continue;
        };
        let Some((entry, seq)) = file_ref(hex) else {
            continue;
        };
        by_ref.insert((volume, entry, seq), i);
        let allocated = a["allocated"].as_bool().unwrap_or(false);
        for p in a["paths"].as_array().into_iter().flatten() {
            if let Some(p) = p.as_str() {
                by_path
                    .entry((volume, p.to_lowercase()))
                    .or_default()
                    .push((i, allocated, p.to_string()));
            }
        }
    }
    let volume_of = |serial: &str| {
        volumes
            .iter()
            .find(|(s, _)| s.eq_ignore_ascii_case(serial))
            .map(|(_, l)| l.as_str())
    };
    let mut found: HashMap<usize, Found> = HashMap::new();
    let new = |i: usize| Found {
        entry: entries[i].id,
        locator: entries[i].locator.clone(),
        path: paths[i].clone(),
        lnks: vec![],
        prefetch: vec![],
    };
    for l in lnks {
        let a = attrs(l);
        let (Some(serial), Some(entry), Some(seq)) = (
            a["volume_serial"].as_str(),
            a["target_mft_entry"].as_u64(),
            a["target_mft_sequence"].as_u64(),
        ) else {
            continue;
        };
        let Some(volume) = volume_of(serial) else {
            continue;
        };
        if let Some(&i) = u16::try_from(seq)
            .ok()
            .and_then(|seq| by_ref.get(&(volume, entry, seq)))
        {
            found.entry(i).or_insert_with(|| new(i)).lnks.push(l.id);
        }
    }
    for p in prefetch {
        let a = attrs(p);
        let Some(exe) = a["executable"].as_str() else {
            continue;
        };
        let Some((volume, rest)) = a["volumes"].as_array().into_iter().flatten().find_map(|v| {
            let device = v["device_path"].as_str()?;
            let rest = exe
                .get(..device.len())
                .filter(|d| d.eq_ignore_ascii_case(device))
                .map(|_| &exe[device.len()..])?;
            Some((volume_of(v["serial"].as_str()?)?, rest))
        }) else {
            continue;
        };
        let path = rest.replace('\\', "/").to_lowercase();
        let Some(candidates) = by_path.get(&(volume, path)) else {
            continue;
        };
        // One live entry with that path, or else one deleted one; never a guess between two.
        let live: Vec<&Candidate> = candidates.iter().filter(|c| c.1).collect();
        let &(pick, _, ref path) = match (live.as_slice(), candidates.as_slice()) {
            ([c], _) => *c,
            ([], [c]) => c,
            _ => continue,
        };
        let f = found.entry(pick).or_insert_with(|| new(pick));
        // A hard-linked program is named by the path it ran from, not its WinSxS name.
        f.path = path.clone();
        f.prefetch.push(p.id);
    }
    let mut found: Vec<Found> = found.into_values().collect();
    found.sort_by_key(|f| f.entry);
    found
}

/// An entry a path names: its index, whether it is allocated, and the path as stored.
type Candidate = (usize, bool, String);

/// Entry and sequence from an `ntfs.file_ref` in hex: 6 bytes entry and 2 bytes sequence,
/// little-endian.
fn file_ref(hex: &str) -> Option<(u64, u16)> {
    let v = u64::from_str_radix(hex, 16).ok()?.swap_bytes();
    (hex.len() == 16).then_some((v & 0xFFFF_FFFF_FFFF, (v >> 48) as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u128, locator: &str, attrs: serde_json::Value) -> StoredRecord {
        StoredRecord {
            id,
            locator: locator.into(),
            attrs: Some(attrs.to_string()),
        }
    }

    #[test]
    fn file_ref_is_entry_and_sequence() {
        assert_eq!(file_ref("bf25000000000100"), Some((0x25bf, 1)));
        assert_eq!(file_ref("bf2500"), None);
    }

    /// cmd.exe has a shortcut and a Prefetch file; a shortcut whose record now holds another
    /// file, one on another volume and a Prefetch path two deleted entries share match nothing.
    #[test]
    fn shortcuts_and_prefetch_find_their_file() {
        let vol = "source.image:1/volume.partition:4";
        let entry = |id, file_ref: &str, path: &str, allocated: bool| {
            rec(
                id,
                &format!("{vol}/fs.entry:ntfs.file_ref:{file_ref}"),
                serde_json::json!({"paths": [path], "allocated": allocated}),
            )
        };
        let entries = [
            rec(
                1,
                &format!("{vol}/fs.entry:ntfs.file_ref:2a00000000000300"),
                serde_json::json!({"paths": ["/Windows/WinSxS/x/cmd.exe",
                    "/Windows/System32/cmd.exe"], "allocated": true}),
            ),
            entry(2, "2b00000000000100", "/old/a.exe", false),
            entry(3, "2c00000000000100", "/old/a.exe", false),
        ];
        let lnk = |id, serial: &str, entry: u64, seq: u64| {
            rec(
                id,
                "l",
                serde_json::json!({"volume_serial": serial, "target_mft_entry": entry,
                    "target_mft_sequence": seq}),
            )
        };
        let lnks = [
            lnk(10, "4C36F4AC", 0x2a, 3),
            lnk(11, "4C36F4AC", 0x2a, 2),
            lnk(12, "DEB00001", 0x2a, 3),
        ];
        let pf = |id, exe: &str| {
            rec(
                id,
                "p",
                serde_json::json!({"executable": exe, "volumes": [
                    {"device_path": "\\VOLUME{01d3-4c36f4ac}", "serial": "4C36F4AC"}]}),
            )
        };
        let prefetch = [
            pf(20, "\\VOLUME{01d3-4c36f4ac}\\WINDOWS\\SYSTEM32\\CMD.EXE"),
            pf(21, "\\VOLUME{01d3-4c36f4ac}\\OLD\\A.EXE"),
            // Another command line of the same program: its own Prefetch file.
            pf(22, "\\VOLUME{01d3-4c36f4ac}\\WINDOWS\\SYSTEM32\\CMD.EXE"),
        ];
        let volumes = [("4C36F4AC".to_string(), vol.to_string())];
        assert_eq!(
            same_files(&volumes, &entries, &lnks, &prefetch),
            [Found {
                entry: 1,
                locator: entries[0].locator.clone(),
                path: "/Windows/System32/cmd.exe".into(),
                lnks: vec![10],
                prefetch: vec![20, 22],
            }]
        );
    }
}
