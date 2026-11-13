//! USB devices in the event logs (piece L8, your choice): every event log entry with a field that
//! holds a device's exact instance ID (`USB\<model>\<serial>` for a USB device fact,
//! `USBSTOR\<disk>\<serial>` for a disk fact, also in the `#` form of device paths) gets a strong
//! link from that fact, so the fact lists its connections and each entry points back. On the exam
//! image: Partition/Diagnostic 1006, Kernel-PnP 400, 410 and 430, StorageVolume and Storsvc 1001.

use crate::sessions::derive;
use af_core::ids::{Endpoint, EventId, FactId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{LinkTier, NewLink, Plugin, RunContext, StoredFact, StoredRecord};
use af_core::system::Family;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Links USB device and disk facts to the event log entries that name them.
pub struct UsbConnections;

impl Plugin for UsbConnections {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.usb_connections").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: vec![Input {
                kind: Kind::new("windows.evtx").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: vec![Kind::new("windows.usb_connections").expect("valid kind")],
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let kind = self.manifest().id.clone();
        let Ok(facts) = stored.facts(
            ctx.system.id,
            &["windows.usb_device", "windows.usb_storage"],
        ) else {
            return Outcome::Ok(0);
        };
        let devices: Vec<Device> = facts.iter().filter_map(Device::new).collect();
        let words: Vec<String> = devices.iter().map(|d| d.serial.clone()).collect();
        let Ok(records) = stored.records_mentioning(
            ctx.system.id,
            &Kind::new("windows.evtx.record").expect("valid kind"),
            &words,
        ) else {
            return Outcome::Ok(0);
        };
        let found = matches(&devices, &records);
        let ids: Vec<u128> = found.iter().map(|m| m.record).collect();
        let Ok(events) = stored.events_of(&ids) else {
            return Outcome::Ok(0);
        };
        let event: HashMap<u128, EventId> = events.iter().map(|e| (e.record, e.id)).collect();
        let mut n = 0;
        for m in &found {
            let Some(e) = event.get(&m.record) else {
                continue;
            };
            let d = &devices[m.device];
            ctx.sink.link(
                &kind,
                NewLink {
                    id: derive(&m.locator, &kind, &d.instance),
                    kind: kind.clone(),
                    from: Endpoint::Fact(FactId(d.fact)),
                    to: Endpoint::Event(*e),
                    tier: LinkTier::Strong,
                    label: "named in log".into(),
                    reason: format!("the entry's {} holds the device instance ID", m.field),
                    key: d.instance.clone(),
                    description: Some(m.what.clone()),
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// A device fact with the instance ID log entries name it by.
struct Device {
    fact: u128,
    /// `USB\…` or `USBSTOR\…`, as the logs write it.
    instance: String,
    /// Lowercase, with `\` for the `#` of device paths, for matching.
    needle: String,
    /// Its last part, to find candidate entries.
    serial: String,
}

impl Device {
    fn new(f: &StoredFact) -> Option<Self> {
        let bus = match f.kind.as_str() {
            "windows.usb_device" => "USB",
            "windows.usb_storage" => "USBSTOR",
            _ => return None,
        };
        let instance = format!("{bus}\\{}", f.subject);
        Some(Self {
            fact: f.id,
            needle: instance.to_lowercase(),
            serial: f.subject.rsplit('\\').next()?.to_string(),
            instance,
        })
    }
}

/// One log entry naming one device.
#[derive(Debug, PartialEq)]
struct Match {
    device: usize,
    record: u128,
    locator: String,
    /// The field that names it.
    field: String,
    /// The entry's channel and event ID.
    what: String,
}

/// Each device named by each record, once per pair.
fn matches(devices: &[Device], records: &[StoredRecord]) -> Vec<Match> {
    let mut out = vec![];
    for r in records {
        let Some(v) = r
            .attrs
            .as_deref()
            .and_then(|a| serde_json::from_str::<Value>(a).ok())
        else {
            continue;
        };
        let mut fields = vec![];
        strings(&v, "", &mut fields);
        let system = &v["System"];
        let channel = system["Channel"].as_str().unwrap_or("?");
        let id = &system["EventID"];
        let id = id
            .as_u64()
            .or_else(|| id["#text"].as_u64())
            .map_or("?".to_string(), |i| i.to_string());
        for (i, d) in devices.iter().enumerate() {
            if let Some((field, _)) = fields.iter().find(|(_, text)| names(text, &d.needle)) {
                out.push(Match {
                    device: i,
                    record: r.id,
                    locator: r.locator.clone(),
                    field: field.clone(),
                    what: format!("{channel} event {id}"),
                });
            }
        }
    }
    out
}

/// Every string in `v` with the name of the field that holds it.
fn strings(v: &Value, name: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => out.push((name.to_string(), s.clone())),
        Value::Array(a) => a.iter().for_each(|x| strings(x, name, out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| strings(x, k, out)),
        _ => {}
    }
}

/// Whether `text` holds the instance ID `needle` as a whole: not inside a longer name, as
/// `…&0&2` is inside `…&0&21`. Device paths write `#` for `\`, and a child device (the disk's
/// volume, its portable device) names it after `_??_`.
fn names(text: &str, needle: &str) -> bool {
    let text = text.to_lowercase().replace('#', "\\");
    let after = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '&' || c == '_');
    text.match_indices(needle).any(|(at, _)| {
        !text[..at]
            .chars()
            .next_back()
            .is_some_and(char::is_alphanumeric)
            && !after(text[at + needle.len()..].chars().next())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u128, data: Value) -> StoredRecord {
        StoredRecord {
            id,
            locator: format!("evtx.record:{id}"),
            attrs: Some(
                serde_json::json!({"System": {"Channel": "C", "EventID": 400}, "EventData": data})
                    .to_string(),
            ),
        }
    }

    fn fact(id: u128, kind: &str, subject: &str) -> StoredFact {
        StoredFact {
            id,
            kind: kind.into(),
            subject: subject.into(),
            attrs: None,
        }
    }

    /// The exam stick: its USB device by ParentId, its disk by instance ID, by device path and in
    /// its portable device's ID; a device whose serial only starts the same matches nothing.
    #[test]
    fn entries_naming_the_exact_instance_link() {
        let facts = [
            fact(1, "windows.usb_device", "VID_ABCD&PID_1234\\5&12c8f4c0&0&2"),
            fact(
                2,
                "windows.usb_storage",
                "Disk&Ven_General&Prod_UDisk&Rev_5.00\\6&1526ad36&0&_&0",
            ),
            fact(
                3,
                "windows.usb_device",
                "VID_ABCD&PID_1234\\5&12c8f4c0&0&21",
            ),
            fact(4, "windows.mounted_device", "\\DosDevices\\F:"),
        ];
        let devices: Vec<Device> = facts.iter().filter_map(Device::new).collect();
        assert_eq!(devices.len(), 3);
        let records = [
            rec(
                10,
                serde_json::json!({"ParentId": "USB\\VID_ABCD&PID_1234\\5&12C8F4C0&0&2"}),
            ),
            rec(
                11,
                serde_json::json!({"DeviceInstanceId":
                    "USBSTOR\\Disk&Ven_General&Prod_UDisk&Rev_5.00\\6&1526ad36&0&_&0"}),
            ),
            rec(
                12,
                serde_json::json!({"VolumeName": "\\\\?\\USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#6&1526ad36&0&_&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"}),
            ),
            rec(13, serde_json::json!({"Other": "5&12c8f4c0&0&2"})),
            rec(
                14,
                serde_json::json!({"DeviceId": "SWD\\WPDBUSENUM\\_??_USBSTOR#DISK&VEN_GENERAL&PROD_UDISK&REV_5.00#6&1526AD36&0&_&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}"}),
            ),
        ];
        let found: Vec<(usize, u128, &str)> = matches(&devices, &records)
            .iter()
            .map(|m| (m.device, m.record, m.field.as_str()))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(d, r, f)| (d, r, if f == "ParentId" { "ParentId" } else { "other" }))
            .collect();
        assert_eq!(
            found,
            [
                (0, 10, "ParentId"),
                (1, 11, "other"),
                (1, 12, "other"),
                (1, 14, "other")
            ]
        );
        assert_eq!(matches(&devices, &records)[0].what, "C event 400");
    }
}
