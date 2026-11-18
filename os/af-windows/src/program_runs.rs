//! Program runs (piece G1): one `windows.program_run` group per Prefetch run time, with what
//! shares its keys. The user's choices:
//! - the run lasts from its start to the next journal write of its Prefetch file (Windows writes
//!   it about 10 s after the start), at most [`MAX_WINDOW`]; without such a write it has no
//!   journal events;
//! - journal events in that window of the program, its Prefetch file and the files in its
//!   Prefetch file list join it, so a file two runs used is in both;
//! - a BAM entry joins the latest run of its program that started at or before its time: BAM
//!   keeps when the program last ended (on LoneWolf 0 s to 6.6 h after the last start).

use crate::sessions::derive;
use af_core::ids::{Endpoint, GroupId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewGroup, Plugin, RunContext, StoredEvent, StoredRecord};
use af_core::system::Family;
use af_core::time::Time;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// The longest a run's window may be, in time-key ticks (100 ns): 60 s.
const MAX_WINDOW: i64 = 600_000_000;

/// Groups each Prefetch run with its BAM entry and journal events.
pub struct ProgramRuns;

impl Plugin for ProgramRuns {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        let kind = |k: &str| Kind::new(k).expect("valid kind");
        M.get_or_init(|| Manifest {
            id: kind("windows.program_runs"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: vec![Input {
                kind: kind("windows.prefetch"),
                required: true,
            }],
            needs: vec![],
            produces: vec![kind("windows.program_run")],
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let system = ctx.system.id;
        let with_records = |kinds: &[&str]| -> Vec<(StoredEvent, StoredRecord)> {
            let events = stored.events(system, kinds).unwrap_or_default();
            let ids: Vec<u128> = events.iter().map(|e| e.record).collect();
            let records: HashMap<u128, StoredRecord> = stored
                .records_of(&ids)
                .unwrap_or_default()
                .into_iter()
                .map(|r| (r.id, r))
                .collect();
            events
                .into_iter()
                .filter_map(|e| Some((records.get(&e.record)?.clone(), e)))
                .map(|(r, e)| (e, r))
                .collect()
        };
        let runs: Vec<Run> = with_records(&["windows.prefetch.run"])
            .iter()
            .filter_map(|(e, r)| Run::new(e, r))
            .collect();
        let bam = with_records(&["windows.bam.last_run"]);
        // Journal records of the files runs name, then their events.
        let wanted: HashSet<(&str, &str)> = runs
            .iter()
            .flat_map(|r| r.paths().map(move |p| (r.volume.as_str(), p)))
            .collect();
        let usn = stored
            .records(system, &Kind::new("ntfs.usn.record").expect("valid kind"))
            .unwrap_or_default();
        let mut path_of: HashMap<u128, (String, String)> = HashMap::new();
        for r in &usn {
            if let Some((volume, path)) = journal_path(r)
                && wanted.contains(&(volume.as_str(), path.as_str()))
            {
                path_of.insert(r.id, (volume, path));
            }
        }
        drop(usn);
        let ids: Vec<u128> = path_of.keys().copied().collect();
        let journal = Journal::new(stored.events_of(&ids).unwrap_or_default(), &path_of);
        let kind = Kind::new("windows.program_run").expect("valid kind");
        let plugin = self.manifest().id.clone();
        let groups = groups(&runs, &bam, &journal);
        let n = groups.len() as u64;
        for g in groups {
            ctx.sink.group(
                &plugin,
                NewGroup {
                    id: GroupId(derive(&g.locator, &kind, &g.subject)),
                    kind: kind.clone(),
                    reason: g.reason,
                    members: g.members,
                },
            );
        }
        Outcome::Ok(n)
    }
}

/// One Prefetch run time with its file's keys.
struct Run {
    event: StoredEvent,
    start: i64,
    /// The Prefetch file's record locator, and its volume's (up to `/fs.path:`).
    locator: String,
    volume: String,
    /// The program's name and Prefetch file name as Prefetch writes them.
    name: String,
    pf_name: String,
    /// Lower-case paths on the volume, with `/`: the program, the Prefetch file and its file list.
    /// The program, when its Prefetch file names it (some OneDriveSetup files don't).
    exe: Option<String>,
    pf: String,
    files: Vec<String>,
}

impl Run {
    fn new(e: &StoredEvent, r: &StoredRecord) -> Option<Self> {
        let a: Value = serde_json::from_str(r.attrs.as_deref()?).ok()?;
        let start = e.ts?;
        let (volume, file) = r.locator.split_once("/fs.path:")?;
        let pf = format!("/{}", unescape(file));
        let pf_name = pf.rsplit('/').next()?.to_string();
        Some(Self {
            event: e.clone(),
            start,
            locator: r.locator.clone(),
            volume: volume.to_string(),
            name: a["name"].as_str().unwrap_or("?").to_string(),
            pf_name,
            exe: a["executable"].as_str().and_then(volume_path),
            pf: pf.to_lowercase(),
            files: a["files"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|f| volume_path(f.as_str()?))
                .collect(),
        })
    }

    fn paths(&self) -> impl Iterator<Item = &str> {
        self.exe
            .as_deref()
            .into_iter()
            .chain([self.pf.as_str()])
            .chain(self.files.iter().map(String::as_str))
    }
}

/// `\VOLUME{…}\WINDOWS\X.DLL` or `\Device\HarddiskVolume4\Windows\x.dll` as `/windows/x.dll`.
fn volume_path(p: &str) -> Option<String> {
    let rest = p
        .strip_prefix("\\VOLUME{")
        .and_then(|r| r.split_once('}'))
        .map(|(_, r)| r)
        .or_else(|| {
            let r = p.strip_prefix("\\Device\\HarddiskVolume")?;
            Some(r.trim_start_matches(|c: char| c.is_ascii_digit()))
        })?;
    Some(rest.replace('\\', "/").to_lowercase())
}

/// A locator step's `%`-escapes undone (`Windows%2FPrefetch%2FX.pf`).
fn unescape(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%')
            .then(|| s.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A journal record's volume and lower-case path.
fn journal_path(r: &StoredRecord) -> Option<(String, String)> {
    let (volume, _) = r.locator.rsplit_once("/ntfs.usn:")?;
    let a: Value = serde_json::from_str(r.attrs.as_deref()?).ok()?;
    let path = format!(
        "{}/{}",
        a["parent_path"].as_str()?.trim_end_matches('/'),
        a["name"].as_str()?
    );
    Some((volume.to_string(), path.to_lowercase()))
}

/// Journal events by (volume, path), each list by time.
struct Journal {
    by_path: HashMap<(String, String), Vec<StoredEvent>>,
}

impl Journal {
    fn new(events: Vec<StoredEvent>, path_of: &HashMap<u128, (String, String)>) -> Self {
        let mut by_path: HashMap<(String, String), Vec<StoredEvent>> = HashMap::new();
        for e in events.into_iter().filter(|e| e.ts.is_some()) {
            if let Some(k) = path_of.get(&e.record) {
                by_path.entry(k.clone()).or_default().push(e);
            }
        }
        for v in by_path.values_mut() {
            v.sort_by_key(|e| (e.ts, e.id.0));
        }
        Self { by_path }
    }

    /// The events of `path` on `volume` from `from` to `to`, both included.
    fn between(&self, volume: &str, path: &str, from: i64, to: i64) -> &[StoredEvent] {
        let Some(v) = self.by_path.get(&(volume.to_string(), path.to_string())) else {
            return &[];
        };
        let lo = v.partition_point(|e| e.ts < Some(from));
        let hi = v.partition_point(|e| e.ts <= Some(to));
        &v[lo..hi.max(lo)]
    }
}

/// One run's group.
struct Group {
    locator: String,
    subject: String,
    reason: String,
    members: Vec<(Endpoint, String)>,
}

fn at(ts: i64) -> String {
    u64::try_from(ts).map_or_else(|_| ts.to_string(), |t| Time::from_ticks_1601(t).display())
}

fn groups(runs: &[Run], bam: &[(StoredEvent, StoredRecord)], journal: &Journal) -> Vec<Group> {
    // Each BAM entry to the latest run of its program that started at or before it.
    let mut bam_of: HashMap<usize, Vec<&StoredEvent>> = HashMap::new();
    for (e, r) in bam {
        let program = r
            .attrs
            .as_deref()
            .and_then(|a| serde_json::from_str::<Value>(a).ok())
            .and_then(|a| volume_path(a["program"].as_str()?));
        let (Some(program), Some(ts)) = (program, e.ts) else {
            continue;
        };
        let latest = runs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.exe.as_ref() == Some(&program) && r.start <= ts)
            .max_by_key(|(_, r)| r.start);
        if let Some((i, _)) = latest {
            bam_of.entry(i).or_default().push(e);
        }
    }
    let mut out = vec![];
    for (i, run) in runs.iter().enumerate() {
        let mut members = vec![(Endpoint::Event(run.event.id), "Prefetch run".to_string())];
        let mut parts = vec![format!("Prefetch {}", run.pf_name)];
        for b in bam_of.get(&i).into_iter().flatten() {
            members.push((
                Endpoint::Event(b.id),
                "BAM last run, the latest start before it".to_string(),
            ));
        }
        if bam_of.contains_key(&i) {
            parts.push("BAM's last run of the same path".to_string());
        }
        let write = journal
            .between(&run.volume, &run.pf, run.start, run.start + MAX_WINDOW)
            .first()
            .and_then(|e| e.ts);
        let mut seen = HashSet::new();
        let mut journal_n = 0;
        if let Some(end) = write {
            for path in run.paths() {
                if !seen.insert(path) {
                    continue;
                }
                for e in journal.between(&run.volume, path, run.start, end) {
                    let name = path.rsplit('/').next().unwrap_or(path);
                    members.push((Endpoint::Event(e.id), format!("journal: {name}")));
                    journal_n += 1;
                }
            }
            parts.push(format!(
                "{journal_n} journal events of the program, its Prefetch file and the files it \
                 lists until the Prefetch write at {}",
                at(end)
            ));
        } else {
            parts.push("no Prefetch write within 60 s in the journal".to_string());
        }
        out.push(Group {
            locator: run.locator.clone(),
            subject: run.start.to_string(),
            reason: format!(
                "run of {} at {}: {}",
                run.name,
                at(run.start),
                parts.join("; ")
            ),
            members,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::ids::EventId;

    fn ev(id: u128, record: u128, ts: i64) -> StoredEvent {
        StoredEvent {
            id: EventId(id),
            record,
            kind: "k".into(),
            ts: Some(ts),
        }
    }

    const S: i64 = 10_000_000;

    /// LoneWolf's Notepad, run twice: each run gets the journal events of `ntdll.dll` (in its
    /// Prefetch list) up to its Prefetch write, so the DLL's events between both runs are in
    /// neither and one at each run start in its own; BAM goes to the second run. A third run has
    /// no Prefetch write within 60 s.
    #[test]
    fn runs_take_their_window_and_bam_the_latest() {
        let vol = "source.image:1/volume.partition:4";
        let pf = rec(
            1,
            &format!("{vol}/fs.path:Windows%2FPrefetch%2FNOTEPAD.EXE-B28CC291.pf"),
            serde_json::json!({"name": "NOTEPAD.EXE",
                "executable": "\\VOLUME{01d3-aa92}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",
                "files": ["\\VOLUME{01d3-aa92}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"]}),
        );
        let runs: Vec<Run> = [100 * S, 200 * S, 300 * S]
            .iter()
            .enumerate()
            .map(|(i, &t)| Run::new(&ev(i as u128 + 1, 1, t), &pf).unwrap())
            .collect();
        assert_eq!(runs[0].pf, "/windows/prefetch/notepad.exe-b28cc291.pf");
        assert_eq!(runs[0].files, ["/windows/system32/ntdll.dll"]);
        let k = |p: &str| (vol.to_string(), p.to_string());
        let mut path_of = HashMap::new();
        path_of.insert(10, k("/windows/prefetch/notepad.exe-b28cc291.pf"));
        path_of.insert(11, k("/windows/system32/ntdll.dll"));
        let journal = Journal::new(
            vec![
                ev(20, 10, 110 * S),
                ev(21, 10, 210 * S),
                ev(22, 11, 100 * S),
                ev(23, 11, 150 * S),
                ev(24, 11, 205 * S),
                ev(25, 10, 400 * S),
            ],
            &path_of,
        );
        let bam_rec = rec(
            2,
            "bam",
            serde_json::json!({"program": "\\Device\\HarddiskVolume4\\Windows\\System32\\notepad.exe"}),
        );
        let bam = [(ev(30, 2, 250 * S), bam_rec)];
        let g = groups(&runs, &bam, &journal);
        let ids = |g: &Group| -> Vec<u128> {
            g.members
                .iter()
                .map(|(e, _)| match e {
                    Endpoint::Event(e) => e.0,
                    _ => 0,
                })
                .collect()
        };
        assert_eq!(ids(&g[0]), [1, 20, 22]);
        assert_eq!(ids(&g[1]), [2, 30, 21, 24]);
        assert_eq!(ids(&g[2]), [3]);
        assert!(
            g[2].reason
                .ends_with("no Prefetch write within 60 s in the journal")
        );
        assert!(
            g[1].reason.starts_with("run of NOTEPAD.EXE at "),
            "{}",
            g[1].reason
        );
    }

    fn rec(id: u128, locator: &str, attrs: Value) -> StoredRecord {
        StoredRecord {
            id,
            locator: locator.into(),
            attrs: Some(attrs.to_string()),
        }
    }
}
