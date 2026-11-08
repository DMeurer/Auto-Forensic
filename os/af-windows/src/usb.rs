//! USB devices (piece R11), as RECmd's USB, USBSTOR and MountedDevices plugins read them from
//! SYSTEM: a `windows.usb_device` fact per `Enum\USB\<model>\<serial>` key, a
//! `windows.usb_storage` fact per `Enum\USBSTOR\<disk>\<instance>` key (every control set), and a
//! `windows.mounted_device` fact per `MountedDevices` value. Install, first install, last arrival
//! and last removal times from each device's `Properties` key become events.
//!
//! A serial with `&` as its second character was made up by Windows, as the device has none; it
//! is only unique on this system (`weak_serial`). A storage instance is named by its USB
//! device's serial plus `&0` and so on, or, for a weak serial, by the USB device's
//! `ParentIdPrefix` (on the exam image, `6&1526ad36&0`).

use crate::autoruns::{control_sets, plain};
use crate::host::event;
use crate::registry::{path, reg_sz, system_hive};
use crate::registry_timeline::key_locator;
use crate::sam::utf16;
use af_core::bytes::Locator;
use af_core::capability::{HiveId, RegKey, Registry};
use af_core::ids::{FactId, SourceId};
use af_core::names::Kind;
use af_core::path::{Name, ViewPath};
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{CAPABILITY_REGISTRY, NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use std::sync::OnceLock;

/// The device property set with the install and connection times, and their property numbers.
const TIMES: &str = "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}";
const TIME_KINDS: [(&str, &str); 4] = [
    ("0064", "windows.usb.installed"),
    ("0065", "windows.usb.first_installed"),
    ("0066", "windows.usb.last_connected"),
    ("0067", "windows.usb.last_removed"),
];
/// The device name the bus reports (DEVPKEY_Device_BusReportedDeviceDesc).
const BUS_NAME: &str = "Properties\\{540b947e-8b40-45bc-a8a2-6a0b894cbda2}\\0004";

/// USB devices, USB disks and mounted devices as facts, with the device times as events.
pub struct Usb;

impl Plugin for Usb {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.usb").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: ["windows.hive.system", "windows.hive.log"]
                .into_iter()
                .map(|k| Input {
                    kind: Kind::new(k).expect("valid kind"),
                    required: false,
                })
                .collect(),
            needs: vec![Kind::new(CAPABILITY_REGISTRY).expect("valid kind")],
            produces: [
                "windows.usb_device",
                "windows.usb_storage",
                "windows.mounted_device",
            ]
            .into_iter()
            .chain(TIME_KINDS.map(|(_, k)| k))
            .map(|k| Kind::new(k).expect("valid kind"))
            .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(reg) = ctx.caps.registry else {
            return Outcome::NotAcquired;
        };
        let system = system_hive();
        let Some((source, hive)) = reg.origin(&system) else {
            return Outcome::Ok(0);
        };
        let id = self.manifest().id.clone();
        let mut n = 0;
        let fact = |ctx: &mut RunContext<'_>,
                    locator: &Locator,
                    kind: &str,
                    subject: String,
                    attrs: serde_json::Value| {
            let kind = Kind::new(kind).expect("valid kind");
            ctx.sink.fact(
                &id,
                ctx.system.id,
                NewFact {
                    id: FactId::derive(&source.to_string(), locator, &kind, &subject),
                    source,
                    kind,
                    subject,
                    attrs: Some(attrs.to_string()),
                },
            );
        };
        // (value name, target)
        let mut mounted = vec![];
        if let Some(k) = reg.key(&system, &path("MountedDevices")) {
            let locator = key_locator(&hive, &k);
            for v in &k.values {
                let (name, target) = (plain(&v.name), mounted_target(&v.data));
                let at = locator.child("reg.value", &name);
                fact(
                    ctx,
                    &at,
                    "windows.mounted_device",
                    name.clone(),
                    serde_json::json!({ "target": target }),
                );
                mounted.push((name, target));
                n += 1;
            }
        }
        for set in control_sets(reg) {
            let devices = instances(reg, &system, &format!("{set}\\Enum\\USB"));
            for (model, serial, k) in &devices {
                let (mut vid, mut pid) = (None, None);
                for part in model.split('&') {
                    if let Some(v) = part.strip_prefix("VID_") {
                        vid = Some(v);
                    } else if let Some(p) = part.strip_prefix("PID_") {
                        pid = Some(p);
                    }
                }
                let locator = key_locator(&hive, k);
                let attrs = serde_json::json!({
                    "control_set": set,
                    "vid": vid,
                    "pid": pid,
                    "serial": serial,
                    "weak_serial": weak(serial),
                    "parent_id_prefix": reg_sz(k, "ParentIdPrefix"),
                    "service": reg_sz(k, "Service"),
                    "description": reg_sz(k, "DeviceDesc").map(|d| description(&d)),
                    "friendly_name": reg_sz(k, "FriendlyName"),
                    "device_name": property(reg, &system, k, BUS_NAME),
                    "location": reg_sz(k, "LocationInformation"),
                });
                fact(
                    ctx,
                    &locator,
                    "windows.usb_device",
                    format!("{model}\\{serial}"),
                    attrs,
                );
                n += 1 + times(ctx, reg, &system, (source, &hive), k, &id);
            }
            for (disk, serial, k) in instances(reg, &system, &format!("{set}\\Enum\\USBSTOR")) {
                let part = |p: &str| {
                    disk.split('&')
                        .find_map(|s| s.strip_prefix(p))
                        .map(String::from)
                };
                let usb = devices.iter().find(|(_, s, d)| {
                    let prefix = if weak(s) {
                        reg_sz(d, "ParentIdPrefix")
                    } else {
                        Some(s.clone())
                    };
                    prefix.is_some_and(|p| serial.starts_with(&format!("{p}&")))
                });
                // A mounted device's target: `\??\USBSTOR#<disk>#<instance>#{class}`.
                let needle = format!("#{disk}#{serial}#").to_ascii_lowercase();
                let locator = key_locator(&hive, &k);
                let attrs = serde_json::json!({
                    "control_set": set,
                    "vendor": part("Ven_"),
                    "product": part("Prod_"),
                    "revision": part("Rev_"),
                    "serial": serial,
                    "weak_serial": weak(&serial),
                    "friendly_name": reg_sz(&k, "FriendlyName"),
                    "disk_id": reg
                        .key(&system, &below(&k, "Device Parameters\\Partmgr"))
                        .and_then(|p| reg_sz(&p, "DiskId")),
                    "usb_device": usb.map(|(m, s, _)| format!("{m}\\{s}")),
                    "mounted_as": mounted
                        .iter()
                        .filter(|(_, t)| t.to_ascii_lowercase().contains(&needle))
                        .map(|(name, _)| name)
                        .collect::<Vec<_>>(),
                });
                fact(
                    ctx,
                    &locator,
                    "windows.usb_storage",
                    format!("{disk}\\{serial}"),
                    attrs,
                );
                n += 1 + times(ctx, reg, &system, (source, &hive), &k, &id);
            }
        }
        Outcome::Ok(n)
    }
}

/// Every `<class>\<model>\<instance>` key under `at`, as (model, instance, key).
fn instances(reg: &dyn Registry, hive: &HiveId, at: &str) -> Vec<(String, String, RegKey)> {
    let Some(list) = reg.key(hive, &path(at)) else {
        return vec![];
    };
    let mut out = vec![];
    for model in list.subkeys.iter().map(Name::display) {
        let Some(m) = reg.key(hive, &path(&format!("{at}\\{model}"))) else {
            continue;
        };
        for serial in m.subkeys.iter().map(Name::display) {
            if let Some(k) = reg.key(hive, &path(&format!("{at}\\{model}\\{serial}"))) {
                out.push((model.clone(), serial, k));
            }
        }
    }
    out
}

/// The device's install and connection times as events; how many there were.
fn times(
    ctx: &mut RunContext<'_>,
    reg: &dyn Registry,
    hive: &HiveId,
    (source, hive_loc): (SourceId, &Locator),
    device: &RegKey,
    plugin: &Kind,
) -> u64 {
    let mut n = 0;
    for (number, kind) in TIME_KINDS {
        let Some(k) = reg.key(hive, &below(device, &format!("{TIMES}\\{number}"))) else {
            continue;
        };
        let Some(ticks) = k.value("").and_then(|v| v.data.get(..8)) else {
            continue;
        };
        let ticks = u64::from_le_bytes(ticks.try_into().expect("eight bytes"));
        if ticks != 0 {
            let locator = key_locator(hive_loc, &k);
            event(
                ctx,
                plugin,
                (source, &locator),
                kind,
                Time::from_ticks_1601(ticks),
            );
            n += 1;
        }
    }
    n
}

/// A string device property: the default value of `<device>\<at>`.
fn property(reg: &dyn Registry, hive: &HiveId, device: &RegKey, at: &str) -> Option<String> {
    let k = reg.key(hive, &below(device, at))?;
    utf16(&k.value("")?.data)
}

/// The path `rel` below key `k`.
fn below(k: &RegKey, rel: &str) -> ViewPath {
    ViewPath::new(
        k.path
            .names()
            .iter()
            .chain(path(rel).names())
            .cloned()
            .collect(),
    )
}

/// Made up by Windows: `&` as the second character.
fn weak(serial: &str) -> bool {
    serial.as_bytes().get(1) == Some(&b'&')
}

/// `DeviceDesc` without its INF reference: `@usbstor.inf,%...%;USB Mass Storage Device`.
fn description(d: &str) -> String {
    match d.strip_prefix('@').and_then(|d| d.rsplit_once(';')) {
        Some((_, text)) => text.to_string(),
        None => d.to_string(),
    }
}

/// What a `MountedDevices` value points at: a GPT partition (`DMIO:ID:` and its GUID), an MBR
/// partition (disk signature and byte offset, 12 bytes) or a device path (UTF-16).
fn mounted_target(d: &[u8]) -> String {
    if let Some(g) = d.strip_prefix(b"DMIO:ID:").filter(|g| g.len() == 16) {
        let u32_at = u32::from_le_bytes(g[..4].try_into().expect("four bytes"));
        let u16_at = |o: usize| u16::from_le_bytes([g[o], g[o + 1]]);
        let tail: String = g[8..].iter().map(|b| format!("{b:02x}")).collect();
        return format!(
            "GPT partition {{{u32_at:08x}-{:04x}-{:04x}-{}-{}}}",
            u16_at(4),
            u16_at(6),
            &tail[..4],
            &tail[4..]
        );
    }
    if d.len() == 12 {
        let sig = u32::from_le_bytes(d[..4].try_into().expect("four bytes"));
        let offset = u64::from_le_bytes(d[4..].try_into().expect("eight bytes"));
        return format!("MBR disk {sig:08x}, offset {offset}");
    }
    utf16(d).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::REG_SZ;
    use crate::registry::tests::utf16z;
    use af_core::capability::{Capabilities, FakeRegistry};
    use af_core::ids::SystemId;
    use af_core::runner::{NewEvent, NewRecord, Sink, Target, run};
    use af_core::system::System;

    #[derive(Default)]
    struct Out(Vec<String>);

    impl Sink for Out {
        fn emit(&mut self, _: &Kind, _: &Kind, _: String) {}
        fn fact(&mut self, _: &Kind, _: SystemId, f: NewFact) {
            self.0
                .push(format!("{} {} {}", f.kind, f.subject, f.attrs.unwrap()));
        }
        fn event(&mut self, _: &Kind, _: SystemId, e: NewEvent) {
            self.0.push(format!("{} {}", e.kind, e.time.display()));
        }
        fn record(&mut self, _: &Kind, _: SystemId, _: NewRecord) {}
    }

    /// The exam image's stick: a weak serial, its disk found by `ParentIdPrefix` and mounted as
    /// `F:` (as RECmd shows them); `C:` is a GPT partition.
    #[test]
    fn exam_stick() {
        let usb = "ControlSet001\\Enum\\USB\\VID_ABCD&PID_1234\\5&12c8f4c0&0&2";
        let disk =
            "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_General&Prod_UDisk&Rev_5.00\\6&1526ad36&0&_&0";
        let target = "_??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#6&1526ad36&0&_&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        let mut gpt = b"DMIO:ID:".to_vec();
        gpt.extend([
            0xBC, 0xC8, 0x72, 0x82, 0x8C, 0x90, 0xD9, 0x47, 0x95, 0x1A, 0xD2, 0xAB, 0x30, 0x51,
            0x77, 0x22,
        ]);
        let mut r = FakeRegistry::new();
        r.set(
            "windows.system",
            usb,
            "ParentIdPrefix",
            REG_SZ,
            &utf16z("6&1526ad36&0"),
        )
        .set(
            "windows.system",
            usb,
            "DeviceDesc",
            REG_SZ,
            &utf16z("@usbstor.inf,%genericbulkonly.devicedesc%;USB Mass Storage Device"),
        )
        .set(
            "windows.system",
            &format!("{usb}\\{BUS_NAME}"),
            "",
            0xFFFF_0012,
            &utf16z("UDisk"),
        )
        .set(
            "windows.system",
            &format!("{usb}\\{TIMES}\\0066"),
            "",
            0xFFFF_0010,
            &0x01dc_cf1a_ba18_725b_u64.to_le_bytes(),
        )
        .set(
            "windows.system",
            disk,
            "FriendlyName",
            REG_SZ,
            &utf16z("General UDisk USB Device"),
        )
        .set(
            "windows.system",
            "MountedDevices",
            "\\DosDevices\\F:",
            3,
            &utf16z(target),
        )
        .set(
            "windows.system",
            "MountedDevices",
            "\\DosDevices\\C:",
            3,
            &gpt,
        )
        .set_origin(
            "windows.system",
            SourceId(1),
            Locator::root("source.loose", "SYSTEM"),
        );
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
            &[&Usb],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        let mut want = vec![
            r#"windows.mounted_device \DosDevices\C: {"target":"GPT partition {8272c8bc-908c-47d9-951a-d2ab30517722}"}"#.to_string(),
            format!(r#"windows.mounted_device \DosDevices\F: {{"target":"{target}"}}"#),
            r#"windows.usb_device VID_ABCD&PID_1234\5&12c8f4c0&0&2 {"control_set":"ControlSet001","vid":"ABCD","pid":"1234","serial":"5&12c8f4c0&0&2","weak_serial":true,"parent_id_prefix":"6&1526ad36&0","service":null,"description":"USB Mass Storage Device","friendly_name":null,"device_name":"UDisk","location":null}"#.into(),
            "windows.usb.last_connected 2026-04-18 10:04:21.2535899 UTC".into(),
            r#"windows.usb_storage Disk&Ven_General&Prod_UDisk&Rev_5.00\6&1526ad36&0&_&0 {"control_set":"ControlSet001","vendor":"General","product":"UDisk","revision":"5.00","serial":"6&1526ad36&0&_&0","weak_serial":true,"friendly_name":"General UDisk USB Device","disk_id":null,"usb_device":"VID_ABCD&PID_1234\\5&12c8f4c0&0&2","mounted_as":["\\DosDevices\\F:"]}"#.into(),
        ];
        want.sort();
        out.0.sort();
        assert_eq!(out.0, want);
    }

    #[test]
    fn mbr_target_and_strong_serial() {
        let mut mbr = 0x7694_d459_u32.to_le_bytes().to_vec();
        mbr.extend(1_048_576u64.to_le_bytes());
        assert_eq!(mounted_target(&mbr), "MBR disk 7694d459, offset 1048576");
        assert!(!weak("AA010215170355310594"));
        assert!(weak("6&1526ad36&0&_&0"));
    }
}
