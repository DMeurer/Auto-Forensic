//! The host from the registry (piece R8): which Windows it is, when it was installed and when it
//! last shut down, as RECmd's `BasicSystemInfo` and `Kroll_Batch` read them. Each event points at
//! the record of the key that holds its value (R7), so the key's last-write time stays with it.

use crate::registry::{REG_BINARY, current_control_set, path, reg_dword, reg_sz, system_hive};
use crate::registry_timeline::key_locator;
use af_core::capability::{HiveId, RegKey};
use af_core::ids::{EventId, FactId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{CAPABILITY_REGISTRY, NewEvent, NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

const CURRENT_VERSION: &str = "Microsoft\\Windows NT\\CurrentVersion";
const REG_QWORD: u32 = 11;

/// The OS as a `windows.os` fact, and its install and last shutdown times as events.
pub struct Host;

impl Plugin for Host {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.host").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: [
                "windows.hive.software",
                "windows.hive.system",
                "windows.hive.log",
            ]
            .into_iter()
            .map(|k| Input {
                kind: Kind::new(k).expect("valid kind"),
                required: false,
            })
            .collect(),
            needs: vec![Kind::new(CAPABILITY_REGISTRY).expect("valid kind")],
            produces: ["windows.os", "windows.os.installed", "windows.os.shutdown"]
                .into_iter()
                .map(|k| Kind::new(k).expect("valid kind"))
                .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(reg) = ctx.caps.registry else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let mut n = 0;
        let software = HiveId::machine(Kind::new("windows.software").expect("valid kind"));
        if let Some(k) = reg.key(&software, &path(CURRENT_VERSION))
            && let Some((source, hive)) = reg.origin(&software)
        {
            let locator = key_locator(&hive, &k);
            let text = |name: &str| reg_sz(&k, name);
            let version = match (
                reg_dword(&k, "CurrentMajorVersionNumber"),
                reg_dword(&k, "CurrentMinorVersionNumber"),
            ) {
                (Some(a), Some(b)) => Some(format!("{a}.{b}")),
                _ => text("CurrentVersion"),
            };
            let attrs = serde_json::json!({
                "product_name": text("ProductName"),
                "edition": text("EditionID"),
                "release": text("DisplayVersion").or_else(|| text("ReleaseId")),
                "build": text("CurrentBuild").or_else(|| text("CurrentBuildNumber")),
                "ubr": reg_dword(&k, "UBR"),
                "version": version,
            });
            let kind = Kind::new("windows.os").expect("valid kind");
            ctx.sink.fact(
                &id,
                ctx.system.id,
                NewFact {
                    id: FactId::derive(&source.to_string(), &locator, &kind, "os"),
                    source,
                    kind,
                    subject: text("ProductName").unwrap_or_else(|| "Windows".into()),
                    attrs: Some(attrs.to_string()),
                },
            );
            n += 1;
            // InstallTime (FILETIME) is exact; older systems have only InstallDate (seconds).
            let installed = filetime(&k, "InstallTime").or_else(|| {
                reg_dword(&k, "InstallDate").map(|s| Time::from_unix_seconds(s.into()))
            });
            if let Some(t) = installed {
                event(ctx, &id, (source, &locator), "windows.os.installed", t);
                n += 1;
            }
        }
        let system = system_hive();
        if let Some(set) = current_control_set(reg)
            && let Some(k) = reg.key(&system, &path(&format!("{set}\\Control\\Windows")))
            && let Some(t) = filetime(&k, "ShutdownTime")
            && let Some((source, hive)) = reg.origin(&system)
        {
            let locator = key_locator(&hive, &k);
            event(ctx, &id, (source, &locator), "windows.os.shutdown", t);
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// A FILETIME stored as 8 bytes of `REG_BINARY` (or `REG_QWORD`).
fn filetime(k: &RegKey, name: &str) -> Option<Time> {
    let v = k.value(name)?;
    if !matches!(v.value_type, REG_BINARY | REG_QWORD) {
        return None;
    }
    let b: [u8; 8] = v.data.get(..8)?.try_into().ok()?;
    Some(Time::from_ticks_1601(u64::from_le_bytes(b)))
}

/// One event of `kind` (also its time meaning), pointing at the key's record.
pub(crate) fn event(
    ctx: &mut RunContext<'_>,
    plugin: &Kind,
    (source, locator): (af_core::ids::SourceId, &af_core::bytes::Locator),
    kind: &str,
    time: Time,
) -> EventId {
    let kind = Kind::new(kind).expect("valid kind");
    let meaning = TimeMeaning::new(kind.as_str()).expect("valid meaning");
    let source_text = source.to_string();
    let id = EventId::derive(&source_text, locator, None, &kind, &meaning, 0);
    ctx.sink.event(
        plugin,
        ctx.system.id,
        NewEvent {
            id,
            source,
            record: record_id(&source_text, locator),
            kind,
            meaning,
            time,
            clock: ClockDomainId("wall".into()),
            seq: None,
        },
    );
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::REG_SZ;
    use crate::registry::tests::utf16z;
    use af_core::bytes::Locator;
    use af_core::capability::{Capabilities, FakeRegistry};
    use af_core::ids::{SourceId, SystemId};
    use af_core::runner::{NewRecord, Sink, Target, run};
    use af_core::system::System;

    #[derive(Default)]
    struct Out(Vec<String>);

    impl Sink for Out {
        fn emit(&mut self, _: &Kind, _: &Kind, _: String) {}
        fn fact(&mut self, _: &Kind, _: SystemId, f: NewFact) {
            self.0
                .push(format!("fact {} {}", f.subject, f.attrs.unwrap()));
        }
        fn event(&mut self, _: &Kind, _: SystemId, e: NewEvent) {
            self.0.push(format!("{} {}", e.kind, e.time.display()));
        }
        fn record(&mut self, _: &Kind, _: SystemId, _: NewRecord) {}
    }

    /// R8 with LoneWolf's values (as RECmd reads them): the OS fact, InstallTime over
    /// InstallDate, and ShutdownTime from the current control set.
    #[test]
    fn os_install_and_shutdown() {
        let cv = CURRENT_VERSION;
        let mut r = FakeRegistry::new();
        r.set(
            "windows.software",
            cv,
            "ProductName",
            REG_SZ,
            &utf16z("Windows 10 Education"),
        )
        .set(
            "windows.software",
            cv,
            "EditionID",
            REG_SZ,
            &utf16z("Education"),
        )
        .set(
            "windows.software",
            cv,
            "CurrentBuild",
            REG_SZ,
            &utf16z("16299"),
        )
        .set("windows.software", cv, "ReleaseId", REG_SZ, &utf16z("1709"))
        .set(
            "windows.software",
            cv,
            "InstallDate",
            REG_DWORD_T,
            &1_522_152_807u32.to_le_bytes(),
        )
        .set(
            "windows.software",
            cv,
            "InstallTime",
            REG_QWORD,
            &131_666_264_075_286_063u64.to_le_bytes(),
        )
        .set(
            "windows.system",
            "Select",
            "Current",
            REG_DWORD_T,
            &1u32.to_le_bytes(),
        )
        .set(
            "windows.system",
            "ControlSet001\\Control\\Windows",
            "ShutdownTime",
            REG_BINARY,
            &131_666_607_280_567_018u64.to_le_bytes(),
        );
        for (h, p) in [
            ("windows.software", "SOFTWARE"),
            ("windows.system", "SYSTEM"),
        ] {
            r.set_origin(h, SourceId(1), Locator::root("source.loose", p));
        }
        let sys = System {
            id: SystemId(1),
            family: Family::Windows,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let caps = Capabilities { registry: Some(&r) };
        let targets = [Target::new(&sys, caps, vec![], None)];
        let mut out = Out::default();
        run(
            &[&Host],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        assert_eq!(out.0.len(), 3, "{:?}", out.0);
        assert!(
            out.0[0].starts_with("fact Windows 10 Education {"),
            "{:?}",
            out.0
        );
        for part in [
            r#""build":"16299""#,
            r#""edition":"Education""#,
            r#""release":"1709""#,
        ] {
            assert!(out.0[0].contains(part), "{part} in {}", out.0[0]);
        }
        assert_eq!(
            out.0[1],
            "windows.os.installed 2018-03-27 12:13:27.5286063 UTC"
        );
        assert_eq!(
            out.0[2],
            "windows.os.shutdown 2018-03-27 21:45:28.0567018 UTC"
        );
    }

    const REG_DWORD_T: u32 = crate::registry::REG_DWORD;
}
