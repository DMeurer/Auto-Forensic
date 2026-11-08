//! Network interfaces and the networks Windows connected to (piece R9), as RECmd's Kroll batch
//! reads them: each TCP/IP interface's settings from SYSTEM, and each NetworkList profile from
//! SOFTWARE with the gateway MAC of its signature. Profile dates are local SYSTEMTIMEs, turned
//! into UTC with the hive's time zone and its daylight saving rules.

use crate::host::event;
use crate::registry::{
    REG_BINARY, TimeZone, current_control_set, path, reg_dword, reg_multi_sz, reg_sz, system_hive,
    time_zone,
};
use crate::registry_timeline::key_locator;
use af_core::capability::{HiveId, RegKey, Registry};
use af_core::ids::FactId;
use af_core::names::Kind;
use af_core::path::Name;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{CAPABILITY_REGISTRY, NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use std::collections::HashMap;
use std::sync::OnceLock;

const INTERFACES: &str = "Services\\Tcpip\\Parameters\\Interfaces";
/// The network adapter class, whose `{GUID}\Connection\Name` is the name users see.
const ADAPTERS: &str = "Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
const NETWORK_LIST: &str = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList";
/// 2000-01-01 in Unix seconds. LoneWolf's lease times are about 830,000 (January 1970), which
/// is no calendar time; earlier values are kept raw, without an event.
const LEASE_PLAUSIBLE_FROM: u32 = 946_684_800;

/// Interfaces and network profiles as facts; DHCP leases and profile dates as events.
pub struct Network;

impl Plugin for Network {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.network").expect("valid kind"),
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
            produces: [
                "windows.network.interface",
                "windows.network.lease_obtained",
                "windows.network.lease_expires",
                "windows.network.profile",
                "windows.network.profile_created",
                "windows.network.last_connected",
            ]
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
        Outcome::Ok(interfaces(ctx, reg, &id) + profiles(ctx, reg, &id))
    }
}

/// One fact per interface key with values; lease events only while DHCP is on (a static
/// adapter keeps the times of an old lease).
fn interfaces(ctx: &mut RunContext<'_>, reg: &dyn Registry, id: &Kind) -> u64 {
    let system = system_hive();
    let (Some(set), Some((source, hive))) = (current_control_set(reg), reg.origin(&system)) else {
        return 0;
    };
    let Some(list) = reg.key(&system, &path(&format!("{set}\\{INTERFACES}"))) else {
        return 0;
    };
    let mut n = 0;
    for guid in list.subkeys.iter().map(Name::display) {
        let Some(k) = reg.key(&system, &path(&format!("{set}\\{INTERFACES}\\{guid}"))) else {
            continue;
        };
        if k.values.is_empty() {
            continue;
        }
        let locator = key_locator(&hive, &k);
        let name = reg
            .key(
                &system,
                &path(&format!("{set}\\{ADAPTERS}\\{guid}\\Connection")),
            )
            .and_then(|c| reg_sz(&c, "Name"));
        let dhcp = reg_dword(&k, "EnableDHCP") == Some(1);
        let p = if dhcp { "Dhcp" } else { "" };
        let mut attrs = serde_json::json!({
            "guid": guid,
            "name": name,
            "dhcp": dhcp,
            "ip": list_of(&k, if dhcp { "DhcpIPAddress" } else { "IPAddress" }),
            "mask": list_of(&k, &format!("{p}SubnetMask")),
            "gateway": list_of(&k, &format!("{p}DefaultGateway")),
            "dns": list_of(&k, &format!("{p}NameServer")),
            "domain": reg_sz(&k, &format!("{p}Domain")).filter(|d| !d.is_empty()),
        });
        let mut leases = vec![];
        if dhcp {
            attrs["dhcp_server"] = reg_sz(&k, "DhcpServer").into();
            if let Some((ip, mac)) = gateway_hardware(&k) {
                attrs["gateway_ip"] = ip.into();
                attrs["gateway_mac"] = mac.into();
            }
            for (value, kind, raw) in [
                (
                    "LeaseObtainedTime",
                    "windows.network.lease_obtained",
                    "lease_obtained_raw",
                ),
                (
                    "LeaseTerminatesTime",
                    "windows.network.lease_expires",
                    "lease_expires_raw",
                ),
            ] {
                match reg_dword(&k, value) {
                    Some(s) if s >= LEASE_PLAUSIBLE_FROM => leases.push((kind, s)),
                    Some(s) => attrs[raw] = s.into(),
                    None => {}
                }
            }
        }
        let shown = name.clone().unwrap_or_else(|| guid.clone());
        if attrs.get("lease_obtained_raw").is_some() || attrs.get("lease_expires_raw").is_some() {
            ctx.sink.note(
                id,
                ctx.system.id,
                format!(
                    "interface {shown}: DHCP lease times before 2000 are no calendar times; kept raw, without events"
                ),
            );
        }
        let kind = Kind::new("windows.network.interface").expect("valid kind");
        ctx.sink.fact(
            id,
            ctx.system.id,
            NewFact {
                id: FactId::derive(&source.to_string(), &locator, &kind, &guid),
                source,
                kind,
                subject: shown,
                attrs: Some(attrs.to_string()),
            },
        );
        n += 1;
        for (kind, s) in leases {
            event(
                ctx,
                id,
                (source, &locator),
                kind,
                Time::from_unix_seconds(s.into()),
            );
            n += 1;
        }
    }
    n
}

/// One fact per NetworkList profile, and events for when it was created and last connected.
fn profiles(ctx: &mut RunContext<'_>, reg: &dyn Registry, id: &Kind) -> u64 {
    let software = HiveId::machine(Kind::new("windows.software").expect("valid kind"));
    let Some((source, hive)) = reg.origin(&software) else {
        return 0;
    };
    let Some(list) = reg.key(&software, &path(&format!("{NETWORK_LIST}\\Profiles"))) else {
        return 0;
    };
    // Gateway MAC and DNS suffix by profile GUID, from the signatures.
    let mut signatures = HashMap::new();
    for kind in ["Unmanaged", "Managed"] {
        let at = format!("{NETWORK_LIST}\\Signatures\\{kind}");
        let Some(sigs) = reg.key(&software, &path(&at)) else {
            continue;
        };
        for s in sigs.subkeys.iter().map(Name::display) {
            if let Some(k) = reg.key(&software, &path(&format!("{at}\\{s}")))
                && let Some(g) = reg_sz(&k, "ProfileGuid")
            {
                let mac = k.value("DefaultGatewayMac").map(|v| mac_text(&v.data));
                signatures.insert(g.to_uppercase(), (mac, reg_sz(&k, "DnsSuffix")));
            }
        }
    }
    let zone = time_zone(reg);
    let mut n = 0;
    for guid in list.subkeys.iter().map(Name::display) {
        let Some(k) = reg.key(
            &software,
            &path(&format!("{NETWORK_LIST}\\Profiles\\{guid}")),
        ) else {
            continue;
        };
        let locator = key_locator(&hive, &k);
        let (mac, suffix) = signatures
            .get(&guid.to_uppercase())
            .cloned()
            .unwrap_or_default();
        let name = reg_sz(&k, "ProfileName");
        let attrs = serde_json::json!({
            "guid": guid,
            "name": name,
            "description": reg_sz(&k, "Description"),
            "category": reg_dword(&k, "Category"),
            "name_type": reg_dword(&k, "NameType"),
            "managed": reg_dword(&k, "Managed"),
            "gateway_mac": mac,
            "dns_suffix": suffix,
        });
        let kind = Kind::new("windows.network.profile").expect("valid kind");
        ctx.sink.fact(
            id,
            ctx.system.id,
            NewFact {
                id: FactId::derive(&source.to_string(), &locator, &kind, &guid),
                source,
                kind,
                subject: name.unwrap_or_else(|| guid.clone()),
                attrs: Some(attrs.to_string()),
            },
        );
        n += 1;
        for (value, kind) in [
            ("DateCreated", "windows.network.profile_created"),
            ("DateLastConnected", "windows.network.last_connected"),
        ] {
            if let Some(t) = local_systemtime(&k, value, zone.as_ref()) {
                event(ctx, id, (source, &locator), kind, t);
                n += 1;
            }
        }
    }
    n
}

/// Addresses from a `REG_MULTI_SZ`, or a `REG_SZ` with spaces or commas between them.
fn list_of(k: &RegKey, name: &str) -> Vec<String> {
    reg_multi_sz(k, name)
        .or_else(|| {
            reg_sz(k, name).map(|s| {
                s.split([' ', ','])
                    .filter(|a| !a.is_empty())
                    .map(String::from)
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// `DhcpGatewayHardware`: the gateway's IPv4 address, the MAC's length, then the MAC.
fn gateway_hardware(k: &RegKey) -> Option<(String, String)> {
    let d = &k.value("DhcpGatewayHardware")?.data;
    let ip = d.get(..4)?;
    let len = u32::from_le_bytes(d.get(4..8)?.try_into().ok()?) as usize;
    let mac = d.get(8..8 + len)?;
    Some((
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        mac_text(mac),
    ))
}

/// A MAC as Windows shows it: `52-55-0A-00-02-02`.
fn mac_text(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("-")
}

/// A 16-byte local SYSTEMTIME value, in UTC by the zone's rules when the zone is known.
fn local_systemtime(k: &RegKey, name: &str, zone: Option<&TimeZone>) -> Option<Time> {
    let v = k.value(name).filter(|v| v.value_type == REG_BINARY)?;
    let w = |i: usize| -> Option<u16> {
        Some(u16::from_le_bytes(
            v.data.get(i * 2..i * 2 + 2)?.try_into().ok()?,
        ))
    };
    // year, month, day of week (unused), day, hour, minute, second, milliseconds
    let (y, mo, d, h, mi, s, ms) = (w(0)?, w(1)?, w(3)?, w(4)?, w(5)?, w(6)?, w(7)?);
    let t = Time::from_local_calendar(y, mo, d, h, mi, s, ms);
    Some(
        match zone.and_then(|z| z.offset_at(y.into(), mo, d, h, mi)) {
            Some(off) => t.with_local_offset(off, false),
            None => t,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::utf16z;
    use crate::registry::{REG_DWORD, REG_SZ};
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
            self.0
                .push(format!("fact {} {}", f.subject, f.attrs.unwrap()));
        }
        fn event(&mut self, _: &Kind, _: SystemId, e: NewEvent) {
            self.0.push(format!("{} {}", e.kind, e.time.display()));
        }
        fn record(&mut self, _: &Kind, _: SystemId, _: NewRecord) {}
        fn note(&mut self, _: &Kind, _: SystemId, text: String) {
            self.0.push(format!("note {text}"));
        }
    }

    fn multi(items: &[&str]) -> Vec<u8> {
        let mut b: Vec<u8> = items.iter().flat_map(|s| utf16z(s)).collect();
        b.extend([0, 0]);
        b
    }

    fn systemtime(f: [u16; 8]) -> Vec<u8> {
        f.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// The exam image's case: a static adapter with an old lease, a DHCP adapter, LoneWolf's
    /// lease values, and the profile "Netzwerk 2" in Berlin time.
    #[test]
    fn interfaces_leases_and_profiles() {
        let ifs = "ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";
        let (st, dh, lw) = (
            format!("{ifs}\\{{2c0bb2da}}"),
            format!("{ifs}\\{{4fbc1540}}"),
            format!("{ifs}\\{{4b0ae068}}"),
        );
        let tz = "ControlSet001\\Control\\TimeZoneInformation";
        let profile = format!("{NETWORK_LIST}\\Profiles\\{{B6CEA23B}}");
        let sig = format!("{NETWORK_LIST}\\Signatures\\Unmanaged\\0101");
        let d = |v: u32| v.to_le_bytes();
        let mut r = FakeRegistry::new();
        r.set("windows.system", "Select", "Current", REG_DWORD, &d(1))
            .set("windows.system", &st, "EnableDHCP", REG_DWORD, &d(0))
            .set(
                "windows.system",
                &st,
                "IPAddress",
                7,
                &multi(&["192.168.20.111"]),
            )
            .set(
                "windows.system",
                &st,
                "LeaseObtainedTime",
                REG_DWORD,
                &d(0x6a9f_cba7),
            )
            .set(
                "windows.system",
                &format!("ControlSet001\\{ADAPTERS}\\{{2C0BB2DA}}\\Connection"),
                "Name",
                REG_SZ,
                &utf16z("Ethernet"),
            )
            .set("windows.system", &dh, "EnableDHCP", REG_DWORD, &d(1))
            .set(
                "windows.system",
                &dh,
                "DhcpIPAddress",
                REG_SZ,
                &utf16z("10.0.2.15"),
            )
            .set(
                "windows.system",
                &dh,
                "DhcpNameServer",
                REG_SZ,
                &utf16z("1.1.1.1 8.8.8.8"),
            )
            .set(
                "windows.system",
                &dh,
                "LeaseObtainedTime",
                REG_DWORD,
                &d(0x6a9f_cba7),
            )
            .set(
                "windows.system",
                &dh,
                "DhcpGatewayHardware",
                REG_BINARY,
                &[
                    0xc0, 0xa8, 2, 1, 6, 0, 0, 0, 0xb4, 0xfc, 0x7d, 0x1d, 0xaf, 0x5f,
                ],
            )
            .set("windows.system", &lw, "EnableDHCP", REG_DWORD, &d(1))
            .set(
                "windows.system",
                &lw,
                "LeaseObtainedTime",
                REG_DWORD,
                &d(830_452),
            )
            .set(
                "windows.system",
                &format!("{ifs}\\{{empty}}\\sub"),
                "x",
                REG_DWORD,
                &d(0),
            )
            .set("windows.system", tz, "Bias", REG_DWORD, &d(-60i32 as u32))
            .set(
                "windows.system",
                tz,
                "DaylightBias",
                REG_DWORD,
                &d(-60i32 as u32),
            )
            .set(
                "windows.system",
                tz,
                "StandardStart",
                REG_BINARY,
                &systemtime([0, 10, 0, 5, 3, 0, 0, 0]),
            )
            .set(
                "windows.system",
                tz,
                "DaylightStart",
                REG_BINARY,
                &systemtime([0, 3, 0, 5, 2, 0, 0, 0]),
            )
            .set(
                "windows.software",
                &profile,
                "ProfileName",
                REG_SZ,
                &utf16z("Netzwerk 2"),
            )
            .set(
                "windows.software",
                &profile,
                "DateLastConnected",
                REG_BINARY,
                &systemtime([2026, 4, 6, 18, 12, 4, 28, 829]),
            )
            .set(
                "windows.software",
                &sig,
                "ProfileGuid",
                REG_SZ,
                &utf16z("{b6cea23b}"),
            )
            .set(
                "windows.software",
                &sig,
                "DefaultGatewayMac",
                REG_BINARY,
                &[0x08, 0x00, 0x27, 0x6b, 0x5c, 0x6e],
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
            &[&Network],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        let has = |s: &str| out.0.iter().any(|l| l.contains(s));
        let line = |start: &str| {
            out.0
                .iter()
                .find(|l| l.starts_with(start))
                .unwrap_or_else(|| panic!("{start} in {:#?}", out.0))
                .clone()
        };
        let st = line("fact Ethernet ");
        assert!(st.contains(r#""ip":["192.168.20.111"]"#), "{st}");
        assert!(
            !st.contains("lease"),
            "a static adapter shows no lease: {st}"
        );
        let dh = line("fact {4fbc1540} ");
        for part in [
            r#""dns":["1.1.1.1","8.8.8.8"]"#,
            r#""gateway_ip":"192.168.2.1""#,
            r#""gateway_mac":"B4-FC-7D-1D-AF-5F""#,
        ] {
            assert!(dh.contains(part), "{part} in {dh}");
        }
        assert_eq!(
            out.0
                .iter()
                .filter(|l| l.starts_with("windows.network.lease"))
                .collect::<Vec<_>>(),
            ["windows.network.lease_obtained 2026-09-08 08:47:35 UTC"],
            "one lease event, from the DHCP adapter"
        );
        assert!(line("fact {4b0ae068} ").contains(r#""lease_obtained_raw":830452"#));
        assert!(has(
            "note interface {4b0ae068}: DHCP lease times before 2000"
        ));
        assert!(!has("{empty}"), "keys without values are no interfaces");
        assert!(line("fact Netzwerk 2 ").contains(r#""gateway_mac":"08-00-27-6B-5C-6E""#));
        assert_eq!(
            line("windows.network.last_connected"),
            "windows.network.last_connected 2026-04-18 10:04:28.829 UTC, local UTC+02:00"
        );
    }
}
