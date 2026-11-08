//! What a loose Windows file is (piece F22): registry hives by their root keys, not their names.
//!
//! Analysts get hives as `SYSTEM`, `system.hiv`, `export(3)` or `file1`. The root key's subkeys
//! tell them apart: a SYSTEM hive has `Select` and its control sets, NTUSER.DAT has `Software`
//! and `Control Panel`, and so on. A file that matches no rule gets no kind; `af source add --as`
//! names it by hand.

use af_core::names::Kind;
use af_fmt_regf::{is_regf, root_subkey_names};

/// The rules, checked in order: a hive kind and the root keys that must all be there.
const RULES: &[(&str, &[&str])] = &[
    ("windows.hive.system", &["Select", "MountedDevices"]),
    (
        "windows.hive.software",
        &["Microsoft", "Classes", "Policies"],
    ),
    (
        "windows.hive.ntuser",
        &["Software", "Control Panel", "Environment"],
    ),
    ("windows.hive.usrclass", &["Local Settings", "CLSID"]),
    // Before SAM: a SECURITY hive has a SAM key at its root too.
    ("windows.hive.security", &["Policy", "RXACT"]),
    ("windows.hive.sam", &["SAM"]),
    ("windows.hive.amcache", &["Root"]),
];

/// The kind of a loose file from its bytes (a hive, or an NTFS `$MFT`), or `None` if no rule
/// matches. A hive no rule matches is still a hive: `windows.hive.unknown`.
pub fn detect(data: &[u8]) -> Option<Kind> {
    // An `$MFT` starts with its own file record.
    if data.starts_with(b"FILE") {
        return Some(Kind::new("windows.mft").expect("valid kind"));
    }
    if !is_regf(data) {
        return None;
    }
    let names: Vec<String> = root_subkey_names(data)
        .ok()?
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    let has = |k: &&str| names.iter().any(|n| n == &k.to_ascii_lowercase());
    let kind = RULES
        .iter()
        .find(|(_, keys)| keys.iter().all(has))
        .map(|(kind, _)| *kind)
        .unwrap_or("windows.hive.unknown");
    Some(Kind::new(kind).expect("valid kind"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_fmt_regf::build_test_hive;

    fn kind(roots: &[&str]) -> Option<String> {
        detect(&build_test_hive(roots, "lh")).map(|k| k.as_str().to_string())
    }

    #[test]
    fn hives_are_identified_by_their_root_keys() {
        // Root keys as Windows 10 and 11 have them. No file names are involved at all.
        let cases: &[(&[&str], &str)] = &[
            (
                &[
                    "ActivationBroker",
                    "ControlSet001",
                    "DriverDatabase",
                    "HardwareConfig",
                    "Input",
                    "Keyboard Layout",
                    "Maps",
                    "MountedDevices",
                    "ResourceManager",
                    "ResourcePolicyStore",
                    "RNG",
                    "Select",
                    "Setup",
                    "Software",
                    "State",
                    "WaaS",
                    "WPA",
                ],
                "windows.hive.system",
            ),
            (
                &[
                    "Classes",
                    "Clients",
                    "DefaultUserEnvironment",
                    "Google",
                    "Intel",
                    "Microsoft",
                    "ODBC",
                    "OEM",
                    "OpenSSH",
                    "Partner",
                    "Policies",
                    "RegisteredApplications",
                    "Setup",
                    "WOW6432Node",
                ],
                "windows.hive.software",
            ),
            (
                &[
                    "AppEvents",
                    "Console",
                    "Control Panel",
                    "Environment",
                    "EUDC",
                    "Keyboard Layout",
                    "Network",
                    "Printers",
                    "Software",
                    "System",
                    "Volatile Environment",
                ],
                "windows.hive.ntuser",
            ),
            (
                &[
                    "*",
                    "AppID",
                    "CLSID",
                    "Interface",
                    "Local Settings",
                    "TypeLib",
                ],
                "windows.hive.usrclass",
            ),
            (&["SAM"], "windows.hive.sam"),
            (
                &["Cache", "Policy", "RXACT", "SAM"],
                "windows.hive.security",
            ),
            (&["Root"], "windows.hive.amcache"),
        ];
        for (roots, want) in cases {
            assert_eq!(kind(roots).as_deref(), Some(*want), "{roots:?}");
        }
    }

    #[test]
    fn mft() {
        // The test `$MFT` leaves records 0 to 4 empty; a real one starts with the `$MFT` record.
        let mft = af_fmt_mft::build_test_mft("a", [1; 4], 1);
        assert_eq!(
            detect(&mft[5 * 1024..]).map(|k| k.to_string()).as_deref(),
            Some("windows.mft")
        );
        assert_eq!(detect(b"MZ"), None);
    }

    #[test]
    fn case_doesnt_matter_and_unknown_hives_stay_hives() {
        assert_eq!(
            kind(&["select", "MOUNTEDDEVICES"]).as_deref(),
            Some("windows.hive.system")
        );
        assert_eq!(
            kind(&["Something"]).as_deref(),
            Some("windows.hive.unknown")
        );
        assert_eq!(detect(b"MZ\x90\x00 not a hive"), None);
        // A broken hive is not guessed at.
        let mut broken = build_test_hive(&["Select", "MountedDevices"], "lf");
        broken.truncate(0x1010);
        assert_eq!(detect(&broken), None);
    }
}
