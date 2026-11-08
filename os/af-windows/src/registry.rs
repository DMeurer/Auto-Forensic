//! Windows registry names and the first reader on the registry capability (piece F11).
//!
//! Windows shows hives under root keys (`HKLM\SYSTEM`, `HKU\<SID>`); core only knows neutral
//! hive IDs. This module maps between them and decodes Windows value types.

use af_core::artifact::Artifact;
use af_core::capability::{HiveId, RegKey, RegValue, Registry};
use af_core::names::Kind;
use af_core::path::{Name, NameKind, ViewPath};
use af_core::runner::Opener;
use af_core::time::Time;
use af_fmt_regf::hive::{Hive, Replay};
use std::cell::RefCell;

/// Registry value type numbers.
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;

/// The SYSTEM hive (`HKLM\SYSTEM`).
pub fn system_hive() -> HiveId {
    HiveId::machine(Kind::new("windows.system").expect("valid kind"))
}

/// The neutral hive ID for a Windows root path such as `HKLM\SYSTEM` or
/// `HKEY_LOCAL_MACHINE\SOFTWARE`, ignoring case. `None` for roots without a hive file mapping yet.
pub fn hive_for_root(root: &str) -> Option<HiveId> {
    let upper = root.to_ascii_uppercase();
    let rest = upper
        .strip_prefix("HKLM\\")
        .or_else(|| upper.strip_prefix("HKEY_LOCAL_MACHINE\\"))?;
    let id = match rest {
        "SYSTEM" => "windows.system",
        "SOFTWARE" => "windows.software",
        "SAM" => "windows.sam",
        "SECURITY" => "windows.security",
        _ => return None,
    };
    Some(HiveId::machine(Kind::new(id).expect("valid kind")))
}

pub(crate) fn path(text: &str) -> ViewPath {
    ViewPath::new(
        text.split('\\')
            .map(|n| Name::from_text(n, NameKind::Utf16))
            .collect(),
    )
}

/// A `REG_SZ` or `REG_EXPAND_SZ` value as text (variables such as `%SystemDrive%` left as they
/// are): UTF-16LE up to the first NUL. `None` for another type or broken data (an odd length).
pub fn reg_sz(key: &RegKey, name: &str) -> Option<String> {
    let v = key.value(name)?;
    if !matches!(v.value_type, REG_SZ | REG_EXPAND_SZ) || v.data.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = v
        .data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// A `REG_DWORD` value.
pub fn reg_dword(key: &RegKey, name: &str) -> Option<u32> {
    let v = key.value(name)?;
    let bytes: [u8; 4] = v.data.get(..4)?.try_into().ok()?;
    (v.value_type == REG_DWORD).then(|| u32::from_le_bytes(bytes))
}

/// The control set Windows was using: `Select\Current`, as `ControlSet001` and so on.
pub fn current_control_set(reg: &dyn Registry) -> Option<String> {
    let select = reg.key(&system_hive(), &path("Select"))?;
    let n = reg_dword(&select, "Current")?;
    Some(format!("ControlSet{n:03}"))
}

/// The computer name from the SYSTEM hive, in the current control set.
pub fn computer_name(reg: &dyn Registry) -> Option<String> {
    let set = current_control_set(reg)?;
    let key = reg.key(
        &system_hive(),
        &path(&format!("{set}\\Control\\ComputerName\\ComputerName")),
    )?;
    reg_sz(&key, "ComputerName")
}

/// Machine hives by artifact kind, with the hive kind plugins ask for.
const MACHINE_HIVES: [(&str, &str); 6] = [
    ("windows.hive.system", "windows.system"),
    ("windows.hive.software", "windows.software"),
    ("windows.hive.sam", "windows.sam"),
    ("windows.hive.security", "windows.security"),
    ("windows.hive.default", "windows.default"),
    ("windows.hive.amcache", "windows.amcache"),
];

/// Hive kinds per user, with the hive kind plugins ask for (R5); the owner tells users apart.
const USER_HIVES: [(&str, &str); 2] = [
    ("windows.hive.ntuser", "windows.ntuser"),
    ("windows.hive.usrclass", "windows.usrclass"),
];

/// A system's hives as the registry capability (R1, R5), on `af_fmt_regf::hive`: the machine
/// hives, and every user's NTUSER.DAT and UsrClass.dat with its owner.
pub struct HiveRegistry {
    hives: Vec<(HiveId, RefCell<Hive>)>,
}

impl HiveRegistry {
    /// The hives among a system's artifacts, each with its `.LOG1` and `.LOG2` artifacts
    /// replayed. A user hive's owner is the SID whose ProfileImagePath (in SOFTWARE's
    /// ProfileList) is the hive's folder, or else `unknown user N`, one N per folder or loose
    /// hive. A hive that doesn't open is left out; `None` if none opens. The notes name every
    /// hive that doesn't open or whose logs are missing or didn't replay (R3).
    pub fn from_artifacts(
        artifacts: &[Artifact],
        opener: &dyn Opener,
    ) -> (Option<Self>, Vec<String>) {
        let read = |a: &Artifact| -> Option<Vec<u8>> {
            let src = opener.open(a).ok()?;
            let mut buf = vec![0; usize::try_from(src.len()).ok()?];
            src.read_exact_at(0, &mut buf).ok()?;
            Some(buf)
        };
        let mut reg = Self { hives: Vec::new() };
        let mut users = Vec::new();
        let mut notes = Vec::new();
        let hive_kinds = artifacts.iter().filter(|a| {
            let k = a.kind.as_str();
            k.starts_with("windows.hive.") && k != "windows.hive.log"
        });
        for hive in hive_kinds {
            let path = hive.locator.steps().last().map_or("", |s| s.id.as_str());
            let logs = artifacts
                .iter()
                .filter(|l| l.kind.as_str() == "windows.hive.log" && is_log_of(l, hive))
                .filter_map(read)
                .collect();
            let opened = read(hive)
                .ok_or_else(|| "can't be read".to_string())
                .and_then(|data| Hive::open(data, logs));
            let h = match opened {
                Ok(h) => h,
                Err(e) => {
                    notes.push(format!("hive {path} doesn't open: {e}"));
                    continue;
                }
            };
            match h.replay() {
                Replay::Clean | Replay::Replayed => {}
                Replay::NoLogs => notes.push(format!(
                    "hive {path} is dirty and its transaction logs are missing: read as it is, \
                     recent changes may be missing"
                )),
                Replay::Failed(e) => notes.push(format!(
                    "hive {path} is dirty and its log replay failed ({e}): read as far as it got"
                )),
            }
            let kind = |id: &str| Kind::new(id).expect("valid kind");
            if let Some((_, id)) = MACHINE_HIVES.iter().find(|(k, _)| *k == hive.kind.as_str()) {
                if !reg.hives.iter().any(|(h, _)| h.kind.as_str() == *id) {
                    reg.hives.push((HiveId::machine(kind(id)), RefCell::new(h)));
                }
            } else if let Some((_, id)) = USER_HIVES.iter().find(|(k, _)| *k == hive.kind.as_str())
            {
                users.push((crate::plugins::home_of(hive), kind(id), h));
            }
        }
        let profiles = reg.profiles();
        let mut unknown: Vec<Option<String>> = Vec::new();
        for (home, kind, h) in users {
            let sid = home.as_deref().and_then(|home| {
                profiles
                    .iter()
                    .find(|(_, p)| crate::plugins::same_home(home, p))
                    .map(|(sid, _)| sid.clone())
            });
            let owner = sid.unwrap_or_else(|| {
                let lower = home.as_deref().map(str::to_ascii_lowercase);
                let n = match unknown.iter().position(|u| lower.is_some() && *u == lower) {
                    Some(n) => n,
                    None => {
                        unknown.push(lower);
                        unknown.len() - 1
                    }
                };
                format!("unknown user {}", n + 1)
            });
            reg.hives
                .push((HiveId::user(kind, &owner), RefCell::new(h)));
        }
        ((!reg.hives.is_empty()).then_some(reg), notes)
    }

    /// SOFTWARE's ProfileList: each SID with its profile folder below the system volume, and
    /// the `Default` and `Public` template folders as `default profile` and `public profile`.
    fn profiles(&self) -> Vec<(String, String)> {
        let software = HiveId::machine(Kind::new("windows.software").expect("valid kind"));
        let Some(list) = self.key(&software, &path(crate::plugins::PROFILE_LIST)) else {
            return Vec::new();
        };
        let templates = ["Default", "Public"].into_iter().filter_map(|t| {
            let home = crate::plugins::volume_path(&reg_sz(&list, t)?)?;
            Some((format!("{} profile", t.to_ascii_lowercase()), home))
        });
        list.subkeys
            .iter()
            .filter_map(|sid| {
                let k = self.key(&software, &list.path.join(sid.clone()))?;
                let home = crate::plugins::volume_path(&reg_sz(&k, "ProfileImagePath")?)?;
                Some((sid.display(), home))
            })
            .chain(templates)
            .collect()
    }
}

/// Whether `log` is `hive`'s `.LOG1` or `.LOG2`: the same locator up to the path, and the
/// path with that suffix, ignoring case.
fn is_log_of(log: &Artifact, hive: &Artifact) -> bool {
    let (Some((l, l_on)), Some((h, h_on))) = (
        log.locator.steps().split_last(),
        hive.locator.steps().split_last(),
    ) else {
        return false;
    };
    let (l, h) = (l.id.to_lowercase(), h.id.to_lowercase());
    l_on == h_on && (l == format!("{h}.log1") || l == format!("{h}.log2"))
}

impl Registry for HiveRegistry {
    fn hives(&self) -> Vec<HiveId> {
        self.hives.iter().map(|(id, _)| id.clone()).collect()
    }

    fn key(&self, hive: &HiveId, path: &ViewPath) -> Option<RegKey> {
        let (_, h) = self.hives.iter().find(|(id, _)| id == hive)?;
        let text: Vec<String> = path.names().iter().map(Name::display).collect();
        let k = h.borrow_mut().key(&text.join("\\"))?;
        let name = |s: &str| Name::from_text(s, NameKind::Utf16);
        Some(RegKey {
            path: path.clone(),
            last_written: u64::try_from(k.last_written)
                .ok()
                .map(Time::from_ticks_1601),
            subkeys: k.subkeys.iter().map(|s| name(s)).collect(),
            values: k
                .values
                .into_iter()
                .map(|v| RegValue {
                    name: name(&v.name),
                    value_type: v.value_type,
                    data: v.data,
                })
                .collect(),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use af_core::capability::FakeRegistry;

    pub(crate) fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// A SYSTEM hive with two control sets, the second one current.
    pub(crate) fn system_with_name(name: &str) -> FakeRegistry {
        let mut r = FakeRegistry::new();
        r.set(
            "windows.system",
            "Select",
            "Current",
            REG_DWORD,
            &2u32.to_le_bytes(),
        )
        .set(
            "windows.system",
            "ControlSet001\\Control\\ComputerName\\ComputerName",
            "ComputerName",
            REG_SZ,
            &utf16z("OLD-NAME"),
        )
        .set(
            "windows.system",
            "ControlSet002\\Control\\ComputerName\\ComputerName",
            "ComputerName",
            REG_SZ,
            &utf16z(name),
        );
        r
    }

    #[test]
    fn fake_registry_serves_the_computer_name_reader() {
        let r = system_with_name("DESKTOP-ICH");
        assert_eq!(current_control_set(&r).as_deref(), Some("ControlSet002"));
        assert_eq!(computer_name(&r).as_deref(), Some("DESKTOP-ICH"));
    }

    #[test]
    fn missing_or_broken_values_give_none() {
        assert_eq!(computer_name(&FakeRegistry::new()), None);
        let mut r = FakeRegistry::new();
        r.set("windows.system", "Select", "Current", REG_SZ, &utf16z("2"));
        assert_eq!(current_control_set(&r), None, "wrong type");
        let mut r = system_with_name("X");
        r.set(
            "windows.system",
            "ControlSet002\\Control\\ComputerName\\ComputerName",
            "ComputerName",
            REG_SZ,
            &[0x41, 0x00, 0x42],
        );
        assert_eq!(computer_name(&r), None, "odd length");
    }

    fn artifact(kind: &str, path: &str) -> Artifact {
        Artifact {
            kind: Kind::new(kind).unwrap(),
            locator: af_core::bytes::Locator::root("source.folder", "pc").child("fs.path", path),
            source: af_core::ids::SourceId(1),
            system: None,
            sha256: String::new(),
        }
    }

    /// What a plugin sees of every user hive through the registry capability alone: owner,
    /// kind and the root key's subkeys. The same code reads loose hives and an image (R5).
    pub(crate) fn user_roots(reg: &dyn Registry) -> Vec<(String, String, Vec<String>)> {
        let mut out: Vec<_> = reg
            .hives()
            .into_iter()
            .filter_map(|h| {
                let root = reg.key(&h, &ViewPath::default())?;
                Some((
                    h.owner?,
                    h.kind.as_str().to_string(),
                    root.subkeys.iter().map(Name::display).collect(),
                ))
            })
            .collect();
        out.sort();
        out
    }

    /// R5 on LoneWolf's hives as TSK copied them out of the image (`~/af-stage3/r5`, local only),
    /// at their image paths: user hives get the SIDs ProfileList names, the template its own
    /// owner, and the same reader as for loose hives sees their keys.
    #[test]
    fn lonewolf_user_hives_get_their_sids() {
        let dir = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("af-stage3/r5/lonewolf");
        if !dir.is_dir() {
            return;
        }
        let files = [
            ("windows.hive.software", "Windows/System32/config/SOFTWARE"),
            ("windows.hive.log", "Windows/System32/config/SOFTWARE.LOG1"),
            ("windows.hive.log", "Windows/System32/config/SOFTWARE.LOG2"),
            ("windows.hive.ntuser", "Users/jcloudy/NTUSER.DAT"),
            ("windows.hive.log", "Users/jcloudy/ntuser.dat.LOG1"),
            ("windows.hive.log", "Users/jcloudy/ntuser.dat.LOG2"),
            (
                "windows.hive.usrclass",
                "Users/jcloudy/AppData/Local/Microsoft/Windows/UsrClass.dat",
            ),
            ("windows.hive.ntuser", "Users/Default/NTUSER.DAT"),
            (
                "windows.hive.ntuser",
                "Windows/ServiceProfiles/LocalService/NTUSER.DAT",
            ),
            (
                "windows.hive.ntuser",
                "Windows/ServiceProfiles/NetworkService/NTUSER.DAT",
            ),
        ];
        // Each hive's .LOG1 and .LOG2 next to it, as the profile indexes them.
        let logs: Vec<(&str, String)> = files[3..]
            .iter()
            .filter(|(k, _)| *k != "windows.hive.log")
            .flat_map(|(_, p)| [1, 2].map(|i| ("windows.hive.log", format!("{p}.LOG{i}"))))
            .filter(|(_, p)| dir.join(p).is_file())
            .collect();
        let files = files.iter().map(|(k, p)| (*k, p.to_string())).chain(logs);
        let mem = Mem(files
            .map(|(k, p)| {
                let a = Artifact {
                    kind: Kind::new(k).unwrap(),
                    locator: af_core::bytes::Locator::root("source.image", "lw")
                        .child("fs.path", &p),
                    source: af_core::ids::SourceId(1),
                    system: None,
                    sha256: String::new(),
                };
                (a, std::fs::read(dir.join(&p)).unwrap())
            })
            .collect());
        let artifacts: Vec<Artifact> = mem.0.iter().map(|(a, _)| a.clone()).collect();
        let (reg, notes) = HiveRegistry::from_artifacts(&artifacts, &mem);
        assert!(notes.is_empty(), "{notes:?}");
        let roots = user_roots(&reg.unwrap());
        let owners: Vec<(&str, &str)> = roots
            .iter()
            .map(|(o, k, _)| (o.as_str(), k.as_str()))
            .collect();
        let jc = "S-1-5-21-2734969515-1644526556-1039763013-1001";
        assert_eq!(
            owners,
            [
                ("S-1-5-19", "windows.ntuser"),
                ("S-1-5-20", "windows.ntuser"),
                (jc, "windows.ntuser"),
                (jc, "windows.usrclass"),
                ("default profile", "windows.ntuser"),
            ]
        );
        let jc_ntuser = &roots
            .iter()
            .find(|(o, k, _)| o == jc && k == "windows.ntuser")
            .unwrap()
            .2;
        assert!(jc_ntuser.iter().any(|s| s == "Software"), "{jc_ntuser:?}");
    }

    struct Mem(Vec<(Artifact, Vec<u8>)>);

    impl Opener for Mem {
        fn open(&self, a: &Artifact) -> std::io::Result<Box<dyn af_core::bytes::ByteSource>> {
            let (_, d) = self.0.iter().find(|(x, _)| x == a).expect("known artifact");
            Ok(Box::new(af_core::bytes::MemSource::new(
                d.clone(),
                a.locator.clone(),
            )))
        }
    }

    /// R5: user hives are offered with an owner; without ProfileList (none here) a folder is one
    /// unknown user, NTUSER.DAT and UsrClass.dat alike, and each loose hive another.
    #[test]
    fn user_hives_have_owners() {
        let hive = |kind: &str, loc: af_core::bytes::Locator, root: &str| {
            let a = Artifact {
                kind: Kind::new(kind).unwrap(),
                locator: loc,
                source: af_core::ids::SourceId(1),
                system: None,
                sha256: String::new(),
            };
            (a, af_fmt_regf::build_test_hive(&[root], "lh"))
        };
        let img = |p: &str| af_core::bytes::Locator::root("source.image", "x").child("fs.path", p);
        let loose = |n: &str| af_core::bytes::Locator::root("source.loose", n);
        let files = Mem(vec![
            hive(
                "windows.hive.system",
                img("Windows/System32/config/SYSTEM"),
                "Select",
            ),
            hive(
                "windows.hive.ntuser",
                img("Users/ann/NTUSER.DAT"),
                "Software",
            ),
            hive(
                "windows.hive.usrclass",
                img("Users/Ann/AppData/Local/Microsoft/Windows/UsrClass.dat"),
                "Local Settings",
            ),
            hive("windows.hive.ntuser", loose("a"), "AppEvents"),
            hive("windows.hive.ntuser", loose("b"), "Console"),
        ]);
        let artifacts: Vec<Artifact> = files.0.iter().map(|(a, _)| a.clone()).collect();
        let (reg, notes) = HiveRegistry::from_artifacts(&artifacts, &files);
        assert!(notes.is_empty(), "{notes:?}");
        let reg = reg.unwrap();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            user_roots(&reg),
            [
                (
                    "unknown user 1".into(),
                    "windows.ntuser".into(),
                    s(&["Software"])
                ),
                (
                    "unknown user 1".into(),
                    "windows.usrclass".into(),
                    s(&["Local Settings"])
                ),
                (
                    "unknown user 2".into(),
                    "windows.ntuser".into(),
                    s(&["AppEvents"])
                ),
                (
                    "unknown user 3".into(),
                    "windows.ntuser".into(),
                    s(&["Console"])
                ),
            ]
        );
        assert!(
            reg.key(&system_hive(), &path("Select")).is_some(),
            "machine hives stay"
        );
    }

    /// R2: a hive's logs pair with it in any letter case, and only with it.
    #[test]
    fn logs_pair_ignoring_case() {
        let hive = artifact("windows.hive.system", "Windows/System32/config/SYSTEM");
        for log in [
            "Windows/System32/config/SYSTEM.LOG1",
            "Windows/System32/config/system.log1",
            "windows/system32/CONFIG/System.Log2",
        ] {
            assert!(
                is_log_of(&artifact("windows.hive.log", log), &hive),
                "{log}"
            );
        }
        for other in [
            "Windows/System32/config/SOFTWARE.LOG1",
            "Windows/System32/config/SYSTEM.LOG",
            "Users/x/SYSTEM.LOG1",
        ] {
            assert!(
                !is_log_of(&artifact("windows.hive.log", other), &hive),
                "{other}"
            );
        }
    }

    /// R2 on real data: notatin's dirty `system` test hive with its lower-case logs replays
    /// (local only, the files are in the notatin checkout).
    #[test]
    fn notatins_dirty_system_hive_replays() {
        let dir = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("repos/notatin/test_data");
        let Ok(hive) = std::fs::read(dir.join("system")) else {
            return;
        };
        assert!(af_fmt_regf::hive::is_dirty(&hive));
        let logs = ["system.log1", "system.log2"].map(|f| std::fs::read(dir.join(f)).unwrap());
        let h = Hive::open(hive.clone(), logs.to_vec()).unwrap();
        assert_eq!(h.replay(), &Replay::Replayed);
        let h = Hive::open(hive, vec![]).unwrap();
        assert_eq!(h.replay(), &Replay::NoLogs);
    }

    #[test]
    fn root_names_map_to_neutral_hives() {
        assert_eq!(hive_for_root("HKLM\\SYSTEM"), Some(system_hive()));
        assert_eq!(
            hive_for_root("hkey_local_machine\\System"),
            Some(system_hive())
        );
        assert_eq!(
            hive_for_root("HKLM\\SOFTWARE").map(|h| h.kind.as_str().to_string()),
            Some("windows.software".to_string())
        );
        assert_eq!(hive_for_root("HKCU\\Software"), None);
    }
}
