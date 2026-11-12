//! From a browser download to the program being used (piece L9, stage 0's rule r1). Every step
//! has a shared key; time only chooses among events, except in the folder step, which is
//! therefore "possible":
//! 1. download → the file on disk: same path and size (strong);
//! 2. that file → its earliest stored Prefetch run: Prefetch's executable is the file (strong);
//! 3. that run → the folder it probably created: the folder name starts the installer's name and
//!    the folder was made up to 10 minutes after the run (possible);
//! 4. that folder → programs inside it that ran (strong);
//! 5. those programs → browser databases in their Prefetch file list (strong, known names only).
//!
//! Only files reached from a download are followed: stage 0 found a link from every program to
//! its runs true but useless (264), and from programs to every loaded file hundreds.
//!
//! Drive letters, the user's choice: the volume holding the Windows folder is the drive of
//! SOFTWARE's SystemRoot, for an image volume and a loose `$MFT` beside `Windows` alike. Downloads
//! to other drives find nothing until MountedDevices maps them. Prefetch names volumes by serial:
//! an image volume's own, or for a loose `$MFT` the serial Prefetch gives the Windows folder.

use crate::registry::{path, reg_sz};
use crate::sessions::derive;
use af_core::capability::HiveId;
use af_core::ids::{Endpoint, EventId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{LinkTier, NewLink, Plugin, RunContext, StoredRecord};
use af_core::system::Family;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

/// How long after an installer ran a folder it made may appear: 10 minutes in 100 ns ticks.
const INSTALL_WINDOW: i64 = 10 * 60 * 10_000_000;

/// Browser databases a program's Prefetch list may name (Firefox, then Chromium).
const DATABASES: [&str; 9] = [
    "places.sqlite",
    "cookies.sqlite",
    "formhistory.sqlite",
    "downloads.sqlite",
    "favicons.sqlite",
    "history",
    "cookies",
    "login data",
    "web data",
];

/// The download-to-use chain as links.
pub struct DownloadToUse;

impl Plugin for DownloadToUse {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.download_to_use").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: ["browser.chromium.history", "browser.firefox.places"]
                .map(|k| Input {
                    kind: Kind::new(k).expect("valid kind"),
                    required: false,
                })
                .into(),
            needs: vec![],
            produces: vec![Kind::new("windows.download_to_use").expect("valid kind")],
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let records = |k: &str| {
            stored
                .records(ctx.system.id, &Kind::new(k).expect("valid kind"))
                .unwrap_or_default()
        };
        let downloads = records("browser.download");
        if downloads.is_empty() {
            return Outcome::Ok(0);
        }
        // The system volume: where SOFTWARE is, by its locator up to the path in the volume.
        let system_volume = ctx
            .artifacts
            .iter()
            .find(|a| a.kind.as_str() == "windows.hive.software")
            .map(|a| volume_of(&a.locator.to_string()));
        let letter = ctx.caps.registry.and_then(|reg| {
            let software = HiveId::machine(Kind::new("windows.software").expect("valid kind"));
            let k = reg.key(&software, &path("Microsoft\\Windows NT\\CurrentVersion"))?;
            let root = reg_sz(&k, "SystemRoot")?;
            let (l, rest) = root.split_once(':')?;
            (l.len() == 1 && rest.starts_with('\\')).then(|| l.to_uppercase())
        });
        let mut serials: HashMap<String, String> = HashMap::new();
        if let Some(opener) = ctx.opener {
            for a in ctx
                .artifacts
                .iter()
                .filter(|a| a.kind.as_str() == "fs.ntfs")
            {
                let mut serial = None;
                let _ = opener.file_system(a, &mut |fs| serial = fs.info().serial.clone());
                if let Some(s) = serial.filter(|s| s.len() >= 8) {
                    serials.insert(s[s.len() - 8..].to_uppercase(), a.locator.to_string());
                }
            }
        }
        let mut files = records("fs.entry");
        files.extend(records("ntfs.mft.record"));
        let prefetch = records("windows.prefetch.file");
        let kinds = [
            "ntfs.si.created",
            "windows.prefetch.run",
            "browser.download.started",
        ];
        let Ok(events) = stored.events(ctx.system.id, &kinds) else {
            return Outcome::Ok(0);
        };
        let input = Facts::new(
            system_volume.zip(letter),
            serials,
            &downloads,
            &files,
            &prefetch,
            &events,
        );
        let id = self.manifest().id.clone();
        let links = input.chain();
        for l in &links {
            ctx.sink.link(
                &id,
                NewLink {
                    id: derive(&l.anchor, &id, &format!("{} {}", l.label, l.key)),
                    kind: id.clone(),
                    from: Endpoint::Event(l.from),
                    to: Endpoint::Event(l.to),
                    tier: l.tier,
                    label: l.label.into(),
                    reason: l.reason.clone(),
                    key: l.key.clone(),
                    description: l.description.clone(),
                },
            );
        }
        Outcome::Ok(links.len() as u64)
    }
}

/// A locator up to the path inside its volume or folder: what a file entry, a loose `$MFT`
/// record and a hive on the same volume share.
fn volume_of(locator: &str) -> String {
    ["/fs.path:", "/fs.entry:"]
        .iter()
        .filter_map(|cut| locator.find(cut))
        .min()
        .map_or(locator, |i| &locator[..i])
        .to_string()
}

fn attrs(r: &StoredRecord) -> Value {
    r.attrs
        .as_deref()
        .and_then(|a| serde_json::from_str(a).ok())
        .unwrap_or_default()
}

/// A link the chain makes, with the locator of the record its ID comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    anchor: String,
    from: EventId,
    to: EventId,
    tier: LinkTier,
    label: &'static str,
    reason: String,
    key: String,
    description: Option<String>,
}

/// A file entry: volume, path as shown, lower-case path, size, folder, in use, created event.
struct File {
    locator: String,
    volume: String,
    path: String,
    size: Option<u64>,
    dir: bool,
    live: bool,
    created: Option<(EventId, i64)>,
}

/// A Prefetch file: the executable as (volume, lower-case path), its loaded files the same way,
/// and its earliest stored run.
struct Pf {
    locator: String,
    name: String,
    run_count: u64,
    exe: Option<(String, String)>,
    files: Vec<(String, String)>,
    first_run: Option<(EventId, i64)>,
}

struct Download {
    locator: String,
    start: EventId,
    path: String,
    /// (volume, lower-case path), where the drive letter is known.
    at: Option<(String, String)>,
    size: u64,
    browser: String,
    url: String,
}

struct Facts {
    files: Vec<File>,
    by_path: HashMap<(String, String), Vec<usize>>,
    pfs: Vec<Pf>,
    downloads: Vec<Download>,
}

impl Facts {
    /// `system` is the system volume and its drive letter; `serials` maps volume serials (low 32
    /// bits, hex) to image volumes.
    fn new(
        system: Option<(String, String)>,
        mut serials: HashMap<String, String>,
        downloads: &[StoredRecord],
        files: &[StoredRecord],
        prefetch: &[StoredRecord],
        events: &[af_core::runner::StoredEvent],
    ) -> Self {
        let mut first: HashMap<(u128, &str), (EventId, i64)> = HashMap::new();
        for e in events {
            let Some(ts) = e.ts else { continue };
            first
                .entry((e.record, e.kind.as_str()))
                .or_insert((e.id, ts));
        }
        // A loose `$MFT` has no serial: Prefetch's serial for the Windows folder's volume is the
        // system volume's, if it gives exactly one.
        // shortcut: assumes Windows ran from the volume of its own Windows folder; a second
        // Windows on another volume of the same system would need its own SystemRoot.
        let pf_attrs: Vec<(u128, &str, Value)> = prefetch
            .iter()
            .map(|r| (r.id, r.locator.as_str(), attrs(r)))
            .collect();
        if let Some((volume, _)) = &system
            && !serials.values().any(|v| v == volume)
        {
            let mut windows: Vec<String> = pf_attrs
                .iter()
                .filter_map(|(_, _, a)| {
                    let (serial, rest) = split_device(a, a["executable"].as_str()?)?;
                    rest.to_uppercase()
                        .starts_with("\\WINDOWS\\")
                        .then_some(serial)
                })
                .collect();
            windows.sort();
            windows.dedup();
            if let [serial] = windows.as_slice() {
                serials.insert(serial.clone(), volume.clone());
            }
        }
        let on_volume = |a: &Value, p: &str| -> Option<(String, String)> {
            let (serial, rest) = split_device(a, p)?;
            Some((serials.get(&serial)?.clone(), lower(&rest)))
        };
        let pfs = pf_attrs
            .iter()
            .map(|(id, locator, a)| Pf {
                locator: locator.to_string(),
                name: a["name"].as_str().unwrap_or_default().to_string(),
                // Prefetch's own count: it keeps the times of the last 8 runs only.
                run_count: a["run_count"].as_u64().unwrap_or_default(),
                exe: a["executable"].as_str().and_then(|p| on_volume(a, p)),
                files: a["files"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|f| on_volume(a, f.as_str()?))
                    .collect(),
                first_run: first.get(&(*id, "windows.prefetch.run")).copied(),
            })
            .collect();

        let mut out = Vec::new();
        let mut by_path: HashMap<(String, String), Vec<usize>> = HashMap::new();
        for r in files {
            let a = attrs(r);
            let created = first.get(&(r.id, "ntfs.si.created")).copied();
            // An image's file entry, with all its names, or a loose `$MFT` record.
            let (paths, dir, live): (Vec<String>, bool, bool) = if r.locator.contains("/fs.entry:")
            {
                let paths = a["paths"].as_array().into_iter().flatten();
                (
                    paths
                        .filter_map(|p| Some(p.as_str()?.to_string()))
                        .collect(),
                    a["kind"] == "folder",
                    a["allocated"].as_bool().unwrap_or(false),
                )
            } else {
                let p = a["path"].as_str().unwrap_or_default().replace('\\', "/");
                (
                    vec![format!("/{p}")],
                    a["dir"].as_bool().unwrap_or(false),
                    a["in_use"].as_bool().unwrap_or(false),
                )
            };
            let volume = volume_of(&r.locator);
            for p in paths {
                by_path
                    .entry((volume.clone(), lower(&p)))
                    .or_default()
                    .push(out.len());
                out.push(File {
                    locator: r.locator.clone(),
                    volume: volume.clone(),
                    path: p,
                    size: a["size"].as_u64(),
                    dir,
                    live,
                    created,
                });
            }
        }
        let downloads = downloads
            .iter()
            .filter_map(|r| {
                let a = attrs(r);
                let path = a["target_path"].as_str()?.to_string();
                let at = match (&system, path.split_once(':')) {
                    (Some((volume, letter)), Some((l, rest))) if l.eq_ignore_ascii_case(letter) => {
                        Some((volume.clone(), lower(rest)))
                    }
                    _ => None,
                };
                Some(Download {
                    locator: r.locator.clone(),
                    start: first.get(&(r.id, "browser.download.started"))?.0,
                    path,
                    at,
                    size: a["total_bytes"].as_u64()?,
                    browser: a["browser"].as_str().unwrap_or_default().to_string(),
                    url: a["url_chain"]
                        .as_array()
                        .and_then(|c| c.last()?.as_str())
                        .unwrap_or_default()
                        .to_string(),
                })
            })
            .collect();
        Self {
            files: out,
            by_path,
            pfs,
            downloads,
        }
    }

    /// The one file at a path: the live one, or else the only one; never a guess between two.
    fn file(&self, at: &(String, String), dir: bool) -> Option<&File> {
        let all: Vec<&File> = self
            .by_path
            .get(at)?
            .iter()
            .map(|&i| &self.files[i])
            .filter(|f| f.dir == dir)
            .collect();
        let live: Vec<&File> = all.iter().copied().filter(|f| f.live).collect();
        match (live.as_slice(), all.as_slice()) {
            ([f], _) | ([], [f]) => Some(f),
            _ => None,
        }
    }

    fn chain(&self) -> Vec<Link> {
        let mut links = Vec::new();
        // Prefetch files that ran a program reached by the chain, for step 5.
        let mut ran: BTreeMap<usize, ()> = BTreeMap::new();
        for d in &self.downloads {
            // 1. Download → file.
            let Some(at) = &d.at else { continue };
            let Some(file) = self.file(at, false).filter(|f| f.size == Some(d.size)) else {
                continue;
            };
            let Some((created, _)) = file.created else {
                continue;
            };
            links.push(Link {
                anchor: d.locator.clone(),
                from: d.start,
                to: created,
                tier: LinkTier::Strong,
                label: "saved as file",
                reason: "download target path and size match the file in $MFT".into(),
                key: format!("{} ({} bytes)", d.path, d.size),
                description: Some(format!("{} download from {}", d.browser, d.url)),
            });
            // 2. File → its runs.
            for (i, pf) in self.pfs.iter().enumerate() {
                let (Some(exe), Some((run, run_ts))) = (&pf.exe, pf.first_run) else {
                    continue;
                };
                if self.file(exe, false).map(|f| &f.locator) != Some(&file.locator) {
                    continue;
                }
                ran.insert(i, ());
                links.push(Link {
                    anchor: file.locator.clone(),
                    from: created,
                    to: run,
                    tier: LinkTier::Strong,
                    label: "run",
                    reason: "Prefetch records this exact path as the executable".into(),
                    key: file.path.clone(),
                    description: Some(format!(
                        "{}, run {} times; earliest of the stored run times",
                        pf.name, pf.run_count
                    )),
                });
                // 3. Installer run → the folder it probably made.
                let installer = exe.1.rsplit('/').next().unwrap_or_default().to_string();
                for folder in self.files.iter().filter(|f| {
                    let name = f.path.rsplit('/').next().unwrap_or_default();
                    let name = name.to_lowercase().replace(' ', "-");
                    f.dir
                        && f.volume == exe.0
                        && name.chars().count() >= 4
                        && installer.starts_with(&format!("{name}-"))
                        && f.created
                            .is_some_and(|(_, t)| (run_ts..=run_ts + INSTALL_WINDOW).contains(&t))
                }) {
                    let (made, made_ts) = folder.created.expect("filtered on it");
                    links.push(Link {
                        anchor: pf.locator.clone(),
                        from: run,
                        to: made,
                        tier: LinkTier::Possible,
                        label: "probably installed to",
                        reason: format!(
                            "folder name matches the installer name, and the folder was created \
                             {} s after the installer ran",
                            (made_ts - run_ts) / 10_000_000
                        ),
                        key: folder.path.clone(),
                        description: None,
                    });
                    // 4. Folder → programs inside it that ran.
                    let inside = format!("{}/", lower(&folder.path));
                    for (j, p) in self.pfs.iter().enumerate() {
                        let (Some(exe), Some((prun, _))) = (&p.exe, p.first_run) else {
                            continue;
                        };
                        if exe.0 != folder.volume || !exe.1.starts_with(&inside) {
                            continue;
                        }
                        ran.insert(j, ());
                        links.push(Link {
                            anchor: folder.locator.clone(),
                            from: made,
                            to: prun,
                            tier: LinkTier::Strong,
                            label: "contains program that ran",
                            reason: "Prefetch executable path is inside this folder".into(),
                            key: self
                                .file(exe, false)
                                .map_or_else(|| exe.1.clone(), |f| f.path.clone()),
                            description: Some(format!("{}, run {} times", p.name, p.run_count)),
                        });
                    }
                }
            }
        }
        // 5. Programs → browser databases they loaded.
        for &i in ran.keys() {
            let pf = &self.pfs[i];
            let Some((run, _)) = pf.first_run else {
                continue;
            };
            let mut seen = Vec::new();
            for at in &pf.files {
                let name = at.1.rsplit('/').next().unwrap_or_default();
                if !DATABASES.contains(&name) || seen.contains(&at) {
                    continue;
                }
                seen.push(at);
                let Some(db) = self.file(at, false) else {
                    continue;
                };
                let Some((created, _)) = db.created else {
                    continue;
                };
                links.push(Link {
                    anchor: pf.locator.clone(),
                    from: run,
                    to: created,
                    tier: LinkTier::Strong,
                    label: "used database",
                    reason: "file is in the program's Prefetch list of loaded files".into(),
                    key: db.path.clone(),
                    description: Some(format!("{} loaded {}", pf.name, db.path)),
                });
            }
        }
        links
    }
}

/// A Prefetch path's volume serial (from the file's volume list) and the path after the device.
fn split_device(a: &Value, p: &str) -> Option<(String, String)> {
    a["volumes"].as_array()?.iter().find_map(|v| {
        let device = v["device_path"].as_str()?;
        let head = p.get(..device.len())?;
        head.eq_ignore_ascii_case(device).then(|| {
            (
                v["serial"].as_str().unwrap_or_default().to_uppercase(),
                p[device.len()..].to_string(),
            )
        })
    })
}

/// A Windows path as compared here: forward slashes, lower case.
fn lower(p: &str) -> String {
    p.replace('\\', "/").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::runner::StoredEvent;

    const VOL: &str = "source.folder:1";
    const MIN: i64 = 60 * 10_000_000;

    fn rec(id: u128, locator: &str, attrs: Value) -> StoredRecord {
        StoredRecord {
            id,
            locator: locator.into(),
            attrs: Some(attrs.to_string()),
        }
    }

    fn ev(id: u128, record: u128, kind: &str, ts: i64) -> StoredEvent {
        StoredEvent {
            id: EventId(id),
            record,
            kind: kind.into(),
            ts: Some(ts),
        }
    }

    fn mft(id: u128, path: &str, dir: bool, size: Option<u64>) -> StoredRecord {
        rec(
            id,
            &format!("{VOL}/fs.path:%24MFT/ntfs.mft_record:{id}"),
            serde_json::json!({"path": path, "dir": dir, "in_use": true, "size": size}),
        )
    }

    fn pf(id: u128, name: &str, exe: &str, files: &[&str]) -> StoredRecord {
        let dev = "\\VOLUME{01dc-a86f8ee2}";
        rec(
            id,
            &format!("{VOL}/fs.path:Windows%2FPrefetch%2F{name}"),
            serde_json::json!({"name": name, "executable": format!("{dev}{exe}"),
                "files": files.iter().map(|f| format!("{dev}{f}")).collect::<Vec<_>>(),
                "volumes": [{"device_path": dev, "serial": "A86F8EE2"}]}),
        )
    }

    /// Stage 0's Tor chain in small: download, installer run, the folder it made, the browser
    /// in it, its cookies. A same-named download of another size and a folder made too late
    /// give nothing.
    #[test]
    fn the_tor_chain() {
        let files = [
            mft(
                1,
                "Users\\ich\\Downloads\\tor-browser-15.exe",
                false,
                Some(100),
            ),
            mft(2, "Users\\ich\\Desktop\\Tor Browser", true, None),
            mft(
                3,
                "Users\\ich\\Desktop\\Tor Browser\\Browser\\firefox.exe",
                false,
                Some(5),
            ),
            mft(
                4,
                "Users\\ich\\Desktop\\Tor Browser\\Data\\cookies.sqlite",
                false,
                Some(9),
            ),
            mft(5, "Users\\ich\\Desktop\\Tor", true, None),
            mft(6, "Windows\\System32\\cmd.exe", false, Some(7)),
        ];
        let prefetch = [
            pf(
                20,
                "TOR-BROWSER-15.EXE",
                "\\USERS\\ICH\\DOWNLOADS\\TOR-BROWSER-15.EXE",
                &[],
            ),
            pf(
                21,
                "FIREFOX.EXE",
                "\\USERS\\ICH\\DESKTOP\\TOR BROWSER\\BROWSER\\FIREFOX.EXE",
                &[
                    "\\USERS\\ICH\\DESKTOP\\TOR BROWSER\\DATA\\COOKIES.SQLITE",
                    "\\USERS\\ICH\\DESKTOP\\TOR BROWSER\\DATA\\X.DLL",
                ],
            ),
            pf(22, "CMD.EXE", "\\WINDOWS\\SYSTEM32\\CMD.EXE", &[]),
        ];
        let download = |id, size| {
            rec(
                id,
                &format!("dl{id}"),
                serde_json::json!({"browser": "edge", "total_bytes": size,
                    "target_path": "C:\\Users\\ich\\Downloads\\tor-browser-15.exe",
                    "url_chain": ["https://a/tor.exe", "https://b/tor.exe"]}),
            )
        };
        let downloads = [download(30, 100), download(31, 99)];
        let events = [
            ev(100, 1, "ntfs.si.created", 1000),
            ev(101, 20, "windows.prefetch.run", 2000),
            ev(102, 2, "ntfs.si.created", 2000 + 11 * 10_000_000),
            ev(103, 21, "windows.prefetch.run", 9000),
            ev(104, 21, "windows.prefetch.run", 9999),
            ev(105, 4, "ntfs.si.created", 5000),
            ev(106, 5, "ntfs.si.created", 2000 + 11 * MIN),
            ev(107, 30, "browser.download.started", 900),
            ev(108, 31, "browser.download.started", 901),
            ev(109, 3, "ntfs.si.created", 10),
        ];
        let input = Facts::new(
            Some((VOL.into(), "C".into())),
            HashMap::new(),
            &downloads,
            &files,
            &prefetch,
            &events,
        );
        let got: Vec<(u128, u128, &str, LinkTier)> = input
            .chain()
            .iter()
            .map(|l| (l.from.0, l.to.0, l.label, l.tier))
            .collect();
        assert_eq!(
            got,
            [
                (107, 100, "saved as file", LinkTier::Strong),
                (100, 101, "run", LinkTier::Strong),
                (101, 102, "probably installed to", LinkTier::Possible),
                (102, 103, "contains program that ran", LinkTier::Strong),
                (103, 105, "used database", LinkTier::Strong),
            ]
        );
        // Another drive letter is another volume: nothing.
        let input = Facts::new(
            Some((VOL.into(), "D".into())),
            HashMap::new(),
            &downloads,
            &files,
            &prefetch,
            &events,
        );
        assert!(input.chain().is_empty());
    }

    #[test]
    fn volumes_of_locators() {
        assert_eq!(
            volume_of("source.image:1/volume.partition:4/fs.entry:ntfs.file_ref:00"),
            "source.image:1/volume.partition:4"
        );
        assert_eq!(
            volume_of("source.folder:1/fs.path:%24MFT/ntfs.mft_record:5"),
            VOL
        );
    }
}
