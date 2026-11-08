//! Run keys and services (piece R10), as RECmd's Kroll batch reads them. Both are facts: neither
//! has a time of its own, and each fact's key has its last-write event from R7.
//!
//! Run keys (user's choice: Kroll's set): `Run`, `RunOnce` and the Group Policy `Run` in SOFTWARE
//! and in every user's NTUSER.DAT, each entry with its enabled state from `StartupApproved\Run`.
//! Services (user's choice: all control sets): every `ControlSetNNN\Services` subkey.

use crate::registry::{REG_BINARY, path, reg_dword, reg_multi_sz, reg_sz, system_hive};
use crate::registry_timeline::key_locator;
use af_core::capability::{HiveId, RegKey, Registry};
use af_core::ids::FactId;
use af_core::names::Kind;
use af_core::path::Name;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{CAPABILITY_REGISTRY, NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use std::sync::OnceLock;

/// Run keys below `Microsoft\Windows\CurrentVersion` (in NTUSER.DAT below `Software\` too).
const RUN_KEYS: [&str; 3] = ["Run", "RunOnce", "Policies\\Explorer\\Run"];
const CURRENT_VERSION: &str = "Microsoft\\Windows\\CurrentVersion";

fn manifest(id: &str, inputs: &[&str], produces: &str) -> Manifest {
    let kind = |k: &str| Kind::new(k).expect("valid kind");
    Manifest {
        id: kind(id),
        version: 1,
        applies_to: vec![Family::Windows],
        phases: vec![Phase::Extract],
        inputs: inputs
            .iter()
            .map(|k| Input {
                kind: kind(k),
                required: false,
            })
            .collect(),
        needs: vec![kind(CAPABILITY_REGISTRY)],
        produces: vec![kind(produces)],
    }
}

/// One fact of `kind` about the key `k` of `hive`, told apart from the key's other facts by
/// `subject`.
fn fact(
    ctx: &mut RunContext<'_>,
    reg: &dyn Registry,
    hive: &HiveId,
    k: &RegKey,
    (plugin, kind): (&Kind, &str),
    subject: String,
    attrs: serde_json::Value,
) -> bool {
    let Some((source, at)) = reg.origin(hive) else {
        return false;
    };
    let locator = key_locator(&at, k);
    let kind = Kind::new(kind).expect("valid kind");
    ctx.sink.fact(
        plugin,
        ctx.system.id,
        NewFact {
            id: FactId::derive(&source.to_string(), &locator, &kind, &subject),
            source,
            kind,
            subject,
            attrs: Some(attrs.to_string()),
        },
    );
    true
}

/// Each Run key entry as a `windows.autorun` fact.
pub struct RunKeys;

impl Plugin for RunKeys {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| {
            manifest(
                "windows.run_keys",
                &[
                    "windows.hive.software",
                    "windows.hive.ntuser",
                    "windows.hive.log",
                ],
                "windows.autorun",
            )
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(reg) = ctx.caps.registry else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let mut n = 0;
        for hive in reg.hives() {
            let base = match hive.kind.as_str() {
                "windows.software" => CURRENT_VERSION.to_string(),
                "windows.ntuser" => format!("Software\\{CURRENT_VERSION}"),
                _ => continue,
            };
            let approved = reg.key(
                &hive,
                &path(&format!("{base}\\Explorer\\StartupApproved\\Run")),
            );
            for run in RUN_KEYS {
                let Some(k) = reg.key(&hive, &path(&format!("{base}\\{run}"))) else {
                    continue;
                };
                for v in &k.values {
                    let name = plain(&v.name);
                    if name.is_empty() {
                        continue;
                    }
                    let (enabled, disabled_at) = approved
                        .as_ref()
                        .and_then(|a| a.value(&name))
                        .filter(|a| a.value_type == REG_BINARY)
                        .and_then(|a| startup_approved(&a.data))
                        .unzip();
                    let attrs = serde_json::json!({
                        "hive": hive.kind.as_str(),
                        "owner": hive.owner,
                        "key": run,
                        "command": reg_sz(&k, &name),
                        "enabled": enabled,
                        "disabled_at": disabled_at.flatten().map(|t: Time| t.display()),
                    });
                    n += u64::from(fact(
                        ctx,
                        reg,
                        &hive,
                        &k,
                        (&id, "windows.autorun"),
                        name,
                        attrs,
                    ));
                }
            }
        }
        Outcome::Ok(n)
    }
}

/// A value name as plain text: unlike [`Name::display`], `\` stays as it is (value names may
/// hold it, as `Uninstall 18.025.0204.0009\amd64` in RunOnce).
pub(crate) fn plain(n: &Name) -> String {
    match n {
        Name::Utf16(u) => String::from_utf16_lossy(u),
        Name::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
    }
}

/// A `StartupApproved` entry: the first byte even when enabled, odd when disabled; a disabled
/// entry holds the FILETIME it was disabled at in bytes 4 to 12.
fn startup_approved(data: &[u8]) -> Option<(bool, Option<Time>)> {
    let enabled = data.first()? % 2 == 0;
    let at = data
        .get(4..12)
        .map(|b| u64::from_le_bytes(b.try_into().expect("eight bytes")))
        .filter(|&t| !enabled && t != 0)
        .map(Time::from_ticks_1601);
    Some((enabled, at))
}

/// Each service of each control set as a `windows.service` fact.
pub struct Services;

impl Plugin for Services {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| {
            manifest(
                "windows.services",
                &["windows.hive.system", "windows.hive.log"],
                "windows.service",
            )
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(reg) = ctx.caps.registry else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let system = system_hive();
        let mut n = 0;
        for set in control_sets(reg) {
            let at = format!("{set}\\Services");
            let Some(list) = reg.key(&system, &path(&at)) else {
                continue;
            };
            for name in list.subkeys.iter().map(Name::display) {
                let Some(k) = reg.key(&system, &path(&format!("{at}\\{name}"))) else {
                    continue;
                };
                let params = reg.key(&system, &path(&format!("{at}\\{name}\\Parameters")));
                let attrs = serde_json::json!({
                    "control_set": set,
                    "display_name": reg_sz(&k, "DisplayName"),
                    "description": reg_sz(&k, "Description"),
                    // Absent stays null; RECmd shows 4 (Disabled, Adapter) then.
                    "start": reg_dword(&k, "Start").map(start_mode),
                    "type": reg_dword(&k, "Type").map(service_type),
                    "image_path": reg_sz(&k, "ImagePath"),
                    // The DLL svchost loads: Parameters first, then the service key.
                    "service_dll": params
                        .as_ref()
                        .and_then(|p| reg_sz(p, "ServiceDll"))
                        .or_else(|| reg_sz(&k, "ServiceDll")),
                    "group": reg_sz(&k, "Group"),
                    "account": reg_sz(&k, "ObjectName"),
                    "required_privileges": reg_multi_sz(&k, "RequiredPrivileges"),
                });
                n += u64::from(fact(
                    ctx,
                    reg,
                    &system,
                    &k,
                    (&id, "windows.service"),
                    name,
                    attrs,
                ));
            }
        }
        Outcome::Ok(n)
    }
}

/// The SYSTEM hive's control sets: root keys named `ControlSet` and three digits.
pub(crate) fn control_sets(reg: &dyn Registry) -> Vec<String> {
    let Some(root) = reg.key(&system_hive(), &path("")) else {
        return vec![];
    };
    root.subkeys
        .iter()
        .map(Name::display)
        .filter(|s| {
            s.len() == 13
                && s[..10].eq_ignore_ascii_case("ControlSet")
                && s[10..].bytes().all(|b| b.is_ascii_digit())
        })
        .collect()
}

/// `Start` as RECmd names it.
fn start_mode(v: u32) -> String {
    match v {
        0 => "Boot".into(),
        1 => "System".into(),
        2 => "Automatic".into(),
        3 => "Manual".into(),
        4 => "Disabled".into(),
        v => v.to_string(),
    }
}

/// `Type` as RECmd names it: its flags joined with `, `, or the number when it has a flag
/// without a name (user services, 0x60 and 0xE0).
fn service_type(v: u32) -> String {
    const FLAGS: [(u32, &str); 7] = [
        (0x1, "KernelDriver"),
        (0x2, "FileSystemDriver"),
        (0x4, "Adapter"),
        (0x8, "RecognizerDriver"),
        (0x10, "Win32OwnProcess"),
        (0x20, "Win32ShareProcess"),
        (0x100, "InteractiveProcess"),
    ];
    let known = FLAGS.iter().fold(0, |m, (f, _)| m | f);
    if v == 0 || v & !known != 0 {
        return v.to_string();
    }
    FLAGS
        .iter()
        .filter(|(f, _)| v & f != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::utf16z;
    use crate::registry::{REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ};
    use af_core::bytes::Locator;
    use af_core::capability::{Capabilities, FakeRegistry};
    use af_core::ids::{SourceId, SystemId};
    use af_core::runner::{NewEvent, NewRecord, Sink, Target, run};
    use af_core::system::System;

    #[derive(Default)]
    struct Out(Vec<String>);

    impl Sink for Out {
        fn emit(&mut self, _: &Kind, _: &Kind, _: String) {}
        fn fact(&mut self, _: &Kind, _: SystemId, f: NewFact) {
            self.0.push(format!("{} {}", f.subject, f.attrs.unwrap()));
        }
        fn event(&mut self, _: &Kind, _: SystemId, _: NewEvent) {}
        fn record(&mut self, _: &Kind, _: SystemId, _: NewRecord) {}
    }

    fn facts(r: &FakeRegistry, p: &dyn Plugin) -> Vec<String> {
        let sys = System {
            id: SystemId(1),
            family: Family::Windows,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let caps = Capabilities { registry: Some(r) };
        let targets = [Target::new(&sys, caps, vec![], None)];
        let mut out = Out::default();
        run(
            &[p],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        out.0
    }

    /// LoneWolf's Run entries (as RECmd shows them), one disabled in StartupApproved, and a
    /// user's own.
    #[test]
    fn run_keys_of_software_and_users() {
        let cv = CURRENT_VERSION;
        let user = HiveId::user(Kind::new("windows.ntuser").unwrap(), "S-1-5-21-1");
        let mut disabled = vec![3, 0, 0, 0];
        disabled.extend(131_666_264_075_286_063u64.to_le_bytes());
        let mut r = FakeRegistry::new();
        r.set(
            "windows.software",
            &format!("{cv}\\Run"),
            "Apoint",
            REG_SZ,
            &utf16z("\"C:\\Program Files\\DellTPad\\Apoint.exe\""),
        )
        .set(
            "windows.software",
            &format!("{cv}\\Run"),
            "SecurityHealth",
            REG_EXPAND_SZ,
            &utf16z("%ProgramFiles%\\Windows Defender\\MSASCuiL.exe"),
        )
        .set(
            "windows.software",
            &format!("{cv}\\Explorer\\StartupApproved\\Run"),
            "SecurityHealth",
            REG_BINARY,
            &disabled,
        )
        .set(
            "windows.software",
            &format!("{cv}\\Policies\\Explorer\\Run"),
            "application",
            REG_SZ,
            &utf16z("D:\\AKMonitor\\AKMonitor.exe hs"),
        )
        .set(
            "windows.software",
            &format!("{cv}\\RunOnce"),
            "",
            REG_SZ,
            &utf16z("x"),
        )
        .set(
            "windows.software",
            &format!("{cv}\\RunOnce"),
            "Uninstall 1\\amd64",
            REG_SZ,
            &utf16z("cmd.exe"),
        )
        .set_in(
            &user,
            &format!("Software\\{cv}\\Run"),
            "OneDrive",
            REG_SZ,
            &utf16z("OneDrive.exe /background"),
        )
        .set_origin(
            "windows.software",
            SourceId(1),
            Locator::root("source.loose", "SOFTWARE"),
        )
        .set_origin_in(
            user,
            SourceId(2),
            Locator::root("source.loose", "NTUSER.DAT"),
        );
        let mut f = facts(&r, &RunKeys);
        f.sort();
        assert_eq!(f.len(), 5, "the default value is no entry: {f:#?}");
        assert!(
            f[3].starts_with(r"Uninstall 1\amd64 {") && f[3].contains(r#""command":"cmd.exe""#),
            "a value name with a backslash: {}",
            f[3]
        );
        assert!(
            f[0].starts_with("Apoint {") && f[0].contains(r#""enabled":null"#),
            "{}",
            f[0]
        );
        assert!(f[1].contains(r#""owner":"S-1-5-21-1""#) && f[1].starts_with("OneDrive "));
        assert!(
            f[2].starts_with("SecurityHealth ")
                && f[2].contains(r#""enabled":false"#)
                && f[2].contains(r#""disabled_at":"2018-03-27 12:13:27.5286063 UTC""#),
            "{}",
            f[2]
        );
        assert!(
            f[4].starts_with("application ") && f[4].contains(r#""key":"Policies\\Explorer\\Run""#)
        );
    }

    /// AppIDSvc as RECmd shows it, in two control sets; `ControlSet001x` is none.
    #[test]
    fn services_of_every_control_set() {
        let mut r = FakeRegistry::new();
        for set in ["ControlSet001", "ControlSet002"] {
            let k = format!("{set}\\Services\\AppIDSvc");
            r.set(
                "windows.system",
                &k,
                "Start",
                REG_DWORD,
                &3u32.to_le_bytes(),
            )
            .set(
                "windows.system",
                &k,
                "Type",
                REG_DWORD,
                &0x20u32.to_le_bytes(),
            )
            .set(
                "windows.system",
                &k,
                "RequiredPrivileges",
                REG_MULTI_SZ,
                &[
                    utf16z("SeChangeNotifyPrivilege"),
                    utf16z("SeImpersonatePrivilege"),
                    vec![0, 0],
                ]
                .concat(),
            )
            .set(
                "windows.system",
                &format!("{k}\\Parameters"),
                "ServiceDll",
                REG_EXPAND_SZ,
                &utf16z("%SystemRoot%\\System32\\appidsvc.dll"),
            );
        }
        r.set(
            "windows.system",
            "ControlSet001x\\Services\\Nope",
            "Start",
            REG_DWORD,
            &[0; 4],
        )
        .set_origin(
            "windows.system",
            SourceId(1),
            Locator::root("source.loose", "SYSTEM"),
        );
        let f = facts(&r, &Services);
        assert_eq!(f.len(), 2, "{f:#?}");
        for part in [
            r#""start":"Manual""#,
            r#""type":"Win32ShareProcess""#,
            r#""service_dll":"%SystemRoot%\\System32\\appidsvc.dll""#,
            r#""required_privileges":["SeChangeNotifyPrivilege","SeImpersonatePrivilege"]"#,
        ] {
            assert!(f[0].contains(part), "{part} in {}", f[0]);
        }
        assert!(f[1].contains(r#""control_set":"ControlSet002""#));
    }

    #[test]
    fn service_types_as_recmd_names_them() {
        assert_eq!(service_type(0x110), "Win32OwnProcess, InteractiveProcess");
        assert_eq!(service_type(0x60), "96");
        assert_eq!(service_type(0xE0), "224");
        assert_eq!(service_type(4), "Adapter");
    }
}
