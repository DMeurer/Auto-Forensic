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
    HiveId(Kind::new("windows.system").expect("valid kind"))
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
    Some(HiveId(Kind::new(id).expect("valid kind")))
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

/// Machine hives by artifact kind, with the hive ID plugins ask for.
const MACHINE_HIVES: [(&str, &str); 6] = [
    ("windows.hive.system", "windows.system"),
    ("windows.hive.software", "windows.software"),
    ("windows.hive.sam", "windows.sam"),
    ("windows.hive.security", "windows.security"),
    ("windows.hive.default", "windows.default"),
    ("windows.hive.amcache", "windows.amcache"),
];

/// A system's machine hives as the registry capability (R1), on `af_fmt_regf::hive`.
pub struct HiveRegistry {
    hives: Vec<(HiveId, RefCell<Hive>)>,
}

impl HiveRegistry {
    /// The machine hives among a system's artifacts, each with its `.LOG1` and `.LOG2`
    /// artifacts replayed. A hive that doesn't open is left out; `None` if none opens. The
    /// notes name every hive, user hives too, that doesn't open or whose logs are missing or
    /// didn't replay (R3).
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
        let mut hives = Vec::new();
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
            // shortcut: user hives are only checked here, not offered, until R5.
            let machine = MACHINE_HIVES.iter().find(|(k, _)| *k == hive.kind.as_str());
            if let Some((_, id)) = machine
                && !hives.iter().any(|(h, _): &(HiveId, _)| h.0.as_str() == *id)
            {
                hives.push((HiveId(Kind::new(id).expect("valid kind")), RefCell::new(h)));
            }
        }
        ((!hives.is_empty()).then_some(Self { hives }), notes)
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
            hive_for_root("HKLM\\SOFTWARE").map(|h| h.0.as_str().to_string()),
            Some("windows.software".to_string())
        );
        assert_eq!(hive_for_root("HKCU\\Software"), None);
    }
}
