//! Windows registry names and the first reader on the registry capability (piece F11).
//!
//! Windows shows hives under root keys (`HKLM\SYSTEM`, `HKU\<SID>`); core only knows neutral
//! hive IDs. This module maps between them and decodes Windows value types.

use af_core::artifact::Artifact;
use af_core::capability::{HiveId, RegKey, RegValue, Registry};
use af_core::names::Kind;
use af_core::path::{Name, NameKind, ViewPath};
use af_core::runner::Opener;
use af_core::time::{TICKS_PER_DAY, Time, TimeKey};
use af_fmt_regf::hive::{Hive, Replay};
use std::cell::RefCell;

/// Registry value type numbers.
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
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

/// A key path from text with `\\` between names; empty for the root.
pub(crate) fn path(text: &str) -> ViewPath {
    ViewPath::new(
        text.split('\\')
            .filter(|n| !n.is_empty())
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

/// The time zone Windows was set to, from `Control\TimeZoneInformation` in the current control
/// set (R6), with its daylight saving rules (R9, user's choice: apply the hive's rules).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimeZone {
    /// `TimeZoneKeyName` (Windows 7 on), else `StandardName`, such as `Eastern Standard Time`.
    pub name: Option<String>,
    /// `Bias`: minutes to add to local standard time to get UTC (300 for UTC-05:00).
    pub bias: Option<i32>,
    /// `StandardBias` and `DaylightBias`, added to `Bias` in each season (0 and -60 mostly).
    pub standard_bias: i32,
    pub daylight_bias: i32,
    /// When daylight saving time starts (in standard time) and ends (in daylight time); `None`
    /// for a zone without it, or with `DynamicDaylightTimeDisabled` set.
    pub daylight_start: Option<Transition>,
    pub standard_start: Option<Transition>,
}

/// A SYSTEMTIME transition rule: with `year` 0 (the usual case) the `week`th `weekday` (0 is
/// Sunday) of `month`, 5 meaning the last; otherwise that exact date, `week` holding the day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    pub year: u16,
    pub month: u16,
    pub weekday: u16,
    pub week: u16,
    pub hour: u16,
    pub minute: u16,
}

impl Transition {
    fn parse(data: &[u8]) -> Option<Self> {
        let w = |i: usize| -> Option<u16> {
            Some(u16::from_le_bytes(
                data.get(i * 2..i * 2 + 2)?.try_into().ok()?,
            ))
        };
        let t = Self {
            year: w(0)?,
            month: w(1)?,
            weekday: w(2)?,
            week: w(3)?,
            hour: w(4)?,
            minute: w(5)?,
        };
        (1..=12).contains(&t.month).then_some(t)
    }

    /// The local (month, day, hour, minute) this rule falls on in `year`.
    fn on(&self, year: i64) -> Option<(u16, u16, u16, u16)> {
        let day = if self.year != 0 {
            self.week
        } else {
            let first = TimeKey::from_utc(year, self.month.into(), 1, 0, 0, 0)?;
            // 1601-01-01 was a Monday, so day 0 counts as weekday 1.
            let first_weekday = ((first.0 / TICKS_PER_DAY + 1) % 7) as u16;
            let mut day = 1 + (self.weekday + 7 - first_weekday) % 7 + 7 * (self.week.max(1) - 1);
            while day > 28
                && TimeKey::from_utc(year, self.month.into(), day.into(), 0, 0, 0).is_none()
            {
                day -= 7;
            }
            day
        };
        Some((self.month, day, self.hour, self.minute))
    }
}

impl TimeZone {
    /// The offset in minutes east of UTC that applied at a local time (year, month, day, hour,
    /// minute), by the hive's daylight saving rules. In the hour that repeats when clocks go back
    /// it gives the daylight offset. `None` without `Bias`.
    pub fn offset_at(
        &self,
        year: i64,
        month: u16,
        day: u16,
        hour: u16,
        minute: u16,
    ) -> Option<i16> {
        let standard = self.bias? + self.standard_bias;
        let daylight = self.bias? + self.daylight_bias;
        let in_daylight = match (self.daylight_start, self.standard_start) {
            (Some(ds), Some(ss)) => {
                let (from, to) = (ds.on(year)?, ss.on(year)?);
                let t = (month, day, hour, minute);
                if from < to {
                    t >= from && t < to
                } else {
                    t >= from || t < to
                }
            }
            _ => false,
        };
        i16::try_from(-(if in_daylight { daylight } else { standard })).ok()
    }

    /// The standard offset from UTC as `UTC-05:00`.
    pub fn offset(&self) -> Option<String> {
        let off = -self.bias?;
        let sign = if off < 0 { '-' } else { '+' };
        Some(format!(
            "UTC{sign}{:02}:{:02}",
            off.abs() / 60,
            off.abs() % 60
        ))
    }
}

/// The time zone from the SYSTEM hive; `None` without SYSTEM or the key.
pub fn time_zone(reg: &dyn Registry) -> Option<TimeZone> {
    let set = current_control_set(reg)?;
    let key = reg.key(
        &system_hive(),
        &path(&format!("{set}\\Control\\TimeZoneInformation")),
    )?;
    let name = reg_sz(&key, "TimeZoneKeyName")
        .filter(|n| !n.is_empty())
        .or_else(|| reg_sz(&key, "StandardName"));
    let dword = |n: &str| reg_dword(&key, n).map(|b| b as i32);
    let rule = |n: &str| key.value(n).and_then(|v| Transition::parse(&v.data));
    let dst = dword("DynamicDaylightTimeDisabled") != Some(1);
    Some(TimeZone {
        name,
        bias: dword("Bias"),
        standard_bias: dword("StandardBias").unwrap_or(0),
        daylight_bias: dword("DaylightBias").unwrap_or(0),
        daylight_start: rule("DaylightStart").filter(|_| dst),
        standard_start: rule("StandardStart").filter(|_| dst),
    })
}

/// Hive kinds per user, with the hive kind plugins ask for (R5); the owner tells users apart.
const USER_HIVES: [(&str, &str); 2] = [
    ("windows.hive.ntuser", "windows.ntuser"),
    ("windows.hive.usrclass", "windows.usrclass"),
];

/// A system's hives as the registry capability (R1, R5), on `af_fmt_regf::hive`: the machine
/// hives, and every user's NTUSER.DAT and UsrClass.dat with its owner.
pub struct HiveRegistry {
    hives: Vec<(HiveId, RefCell<Hive>)>,
    /// The file each hive came from.
    origins: std::collections::HashMap<HiveId, (af_core::ids::SourceId, af_core::bytes::Locator)>,
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
        let mut reg = Self {
            hives: Vec::new(),
            origins: std::collections::HashMap::new(),
        };
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
                    let id = HiveId::machine(kind(id));
                    reg.origins
                        .insert(id.clone(), (hive.source, hive.locator.clone()));
                    reg.hives.push((id, RefCell::new(h)));
                }
            } else if let Some((_, id)) = USER_HIVES.iter().find(|(k, _)| *k == hive.kind.as_str())
            {
                users.push((crate::plugins::home_of(hive), kind(id), h, hive));
            }
        }
        let profiles = reg.profiles();
        let mut unknown: Vec<Option<String>> = Vec::new();
        for (home, kind, h, hive) in users {
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
            let id = HiveId::user(kind, &owner);
            reg.origins
                .insert(id.clone(), (hive.source, hive.locator.clone()));
            reg.hives.push((id, RefCell::new(h)));
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
        // The path as the hive stores it, as `walk` gives it too.
        Some(reg_key(self::path(&k.path), k))
    }

    fn walk(&self, hive: &HiveId, visit: &mut dyn FnMut(&RegKey)) {
        let Some((_, h)) = self.hives.iter().find(|(id, _)| id == hive) else {
            return;
        };
        h.borrow_mut()
            .walk(|p, k| visit(&reg_key(path(p), k.clone())));
    }

    fn origin(&self, hive: &HiveId) -> Option<(af_core::ids::SourceId, af_core::bytes::Locator)> {
        self.origins.get(hive).cloned()
    }
}

fn reg_key(path: ViewPath, k: af_fmt_regf::hive::Key) -> RegKey {
    let name = |s: &str| Name::from_text(s, NameKind::Utf16);
    RegKey {
        path,
        last_written: Some(Time::from_ticks_1601(k.last_written)),
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
    fn time_zone_from_the_current_control_set() {
        let mut r = system_with_name("PC");
        r.set(
            "windows.system",
            "ControlSet002\\Control\\TimeZoneInformation",
            "TimeZoneKeyName",
            REG_SZ,
            &utf16z("Eastern Standard Time"),
        )
        .set(
            "windows.system",
            "ControlSet002\\Control\\TimeZoneInformation",
            "Bias",
            REG_DWORD,
            &300u32.to_le_bytes(),
        );
        let tz = time_zone(&r).unwrap();
        assert_eq!(tz.name.as_deref(), Some("Eastern Standard Time"));
        assert_eq!(tz.offset().as_deref(), Some("UTC-05:00"));
        let east = TimeZone {
            bias: Some(-330),
            ..TimeZone::default()
        };
        assert_eq!(east.offset().as_deref(), Some("UTC+05:30"));
        assert_eq!(time_zone(&FakeRegistry::new()), None);
    }

    /// Germany's rule as Windows stores it: daylight time from the last Sunday of March 02:00
    /// to the last Sunday of October 03:00, bias -60, daylight bias -60.
    #[test]
    fn daylight_saving_by_the_hives_rules() {
        let rule = |month, hour| Transition {
            year: 0,
            month,
            weekday: 0,
            week: 5,
            hour,
            minute: 0,
        };
        let berlin = TimeZone {
            name: None,
            bias: Some(-60),
            standard_bias: 0,
            daylight_bias: -60,
            daylight_start: Some(rule(3, 2)),
            standard_start: Some(rule(10, 3)),
        };
        assert_eq!(
            berlin.offset_at(2026, 4, 18, 12, 4),
            Some(120),
            "exam image, April"
        );
        assert_eq!(berlin.offset_at(2026, 9, 8, 10, 57), Some(120), "September");
        assert_eq!(berlin.offset_at(2026, 1, 10, 12, 0), Some(60), "winter");
        // 2026: the last Sunday of March is the 29th, of October the 25th.
        assert_eq!(berlin.offset_at(2026, 3, 29, 1, 59), Some(60));
        assert_eq!(berlin.offset_at(2026, 3, 29, 2, 0), Some(120));
        assert_eq!(berlin.offset_at(2026, 10, 25, 2, 59), Some(120));
        assert_eq!(berlin.offset_at(2026, 10, 25, 3, 0), Some(60));
        // Sydney: daylight time across the new year (first Sunday of October to April).
        let sydney = TimeZone {
            name: None,
            bias: Some(-600),
            standard_bias: 0,
            daylight_bias: -60,
            daylight_start: Some(Transition {
                week: 1,
                ..rule(10, 2)
            }),
            standard_start: Some(Transition {
                week: 1,
                ..rule(4, 3)
            }),
        };
        assert_eq!(sydney.offset_at(2026, 1, 15, 12, 0), Some(660));
        assert_eq!(sydney.offset_at(2026, 6, 15, 12, 0), Some(600));
        let no_dst = TimeZone {
            bias: Some(300),
            ..TimeZone::default()
        };
        assert_eq!(no_dst.offset_at(2026, 7, 1, 12, 0), Some(-300));
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
