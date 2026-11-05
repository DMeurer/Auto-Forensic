//! Windows registry names and the first reader on the registry capability (piece F11).
//!
//! Windows shows hives under root keys (`HKLM\SYSTEM`, `HKU\<SID>`); core only knows neutral
//! hive IDs. This module maps between them and decodes Windows value types.

use af_core::capability::{HiveId, RegKey, Registry};
use af_core::names::Kind;
use af_core::path::{Name, NameKind, ViewPath};

/// Registry value type numbers.
pub const REG_SZ: u32 = 1;
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

fn path(text: &str) -> ViewPath {
    ViewPath::new(
        text.split('\\')
            .map(|n| Name::from_text(n, NameKind::Utf16))
            .collect(),
    )
}

/// A `REG_SZ` value as text: UTF-16LE up to the first NUL. `None` for another type or broken
/// data (an odd length).
pub fn reg_sz(key: &RegKey, name: &str) -> Option<String> {
    let v = key.value(name)?;
    if v.value_type != REG_SZ || v.data.len() % 2 != 0 {
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
