//! Logon sessions in the event logs (piece L4), within one boot:
//! - a session logon (LocalSessionManager 21) links to the session's next logoff (23) or
//!   disconnect (24), the user's choice: same session ID and user, strong;
//! - a user's logon (Security 4624, a machine or domain SID) and the processes started in it
//!   (4688 with that logon ID) are one group, the user's choice, so a system that audits every
//!   process doesn't get a link per process.
//!
//! Session and logon IDs only count within one boot. Boots start at Security 4608 or System
//! Kernel-General 12. Before the earliest Security event read, a boot could have gone unlogged
//! (the log rolled over), so nothing there is paired.

use af_core::bytes::Locator;
use af_core::ids::SystemId;
use af_core::ids::{Endpoint, EventId, FactId, GroupId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{LinkTier, NewGroup, NewLink, Plugin, RunContext, Stored, StoredEvent};
use af_core::system::Family;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

/// Session links and logon groups.
pub struct Sessions;

impl Plugin for Sessions {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.sessions").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: vec![Input {
                kind: Kind::new("windows.evtx").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: ["windows.session.ended", "windows.logon.processes"]
                .map(|k| Kind::new(k).expect("valid kind"))
                .into(),
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let Some((events, records)) = load(
            stored,
            ctx.system.id,
            &[12, 21, 23, 24, 4608, 4624, 4688],
            &[],
        ) else {
            return Outcome::Ok(0);
        };
        let read = read_all(&events, &records);
        let found = find(&read);
        let id = self.manifest().id.clone();
        let mut n = 0;
        for s in &found.sessions {
            let (start, end) = (&read[s.start], &read[s.end]);
            let kind = Kind::new("windows.session.ended").expect("valid kind");
            let key = format!("session {}, {}", start.session.0, start.session.1);
            ctx.sink.link(
                &id,
                NewLink {
                    id: derive(start.locator, &kind, &key),
                    kind,
                    from: Endpoint::Event(start.id),
                    to: Endpoint::Event(end.id),
                    tier: LinkTier::Strong,
                    label: if end.event == 24 {
                        "session disconnected"
                    } else {
                        "session logged off"
                    }
                    .into(),
                    reason: "same session ID and user, same boot".into(),
                    key,
                    description: None,
                },
            );
            n += 1;
        }
        for g in &found.logons {
            let logon = &read[g.logon];
            let kind = Kind::new("windows.logon.processes").expect("valid kind");
            let (user, logon_type) = (&logon.data["TargetUserName"], &logon.data["LogonType"]);
            let domain = text(&logon.data["TargetDomainName"]).unwrap_or_default();
            ctx.sink.group(
                &id,
                NewGroup {
                    id: GroupId(derive(logon.locator, &kind, "processes")),
                    kind,
                    reason: format!(
                        "{} process{} started in {domain}\\{}'s logon (type {}), logon ID {}",
                        g.processes.len(),
                        if g.processes.len() == 1 { "" } else { "es" },
                        text(user).unwrap_or_default(),
                        text(logon_type).unwrap_or_default(),
                        logon.logon_id.as_deref().unwrap_or_default(),
                    ),
                    members: std::iter::once((Endpoint::Event(logon.id), "the logon".to_string()))
                        .chain(g.processes.iter().map(|&p| {
                            let exe = text(&read[p].data["NewProcessName"]).unwrap_or_default();
                            (
                                Endpoint::Event(read[p].id),
                                format!("started {exe} under its logon ID"),
                            )
                        }))
                        .collect(),
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// Records by ID: locator and attributes.
pub(crate) type Records = HashMap<u128, (String, Value)>;

/// The events of these event IDs (`windows.evtx.<id>`) and other kinds on `system`, by time,
/// with their records.
pub(crate) fn load(
    stored: &dyn Stored,
    system: SystemId,
    ids: &[u32],
    other: &[&str],
) -> Option<(Vec<StoredEvent>, Records)> {
    let kinds: Vec<String> = ids
        .iter()
        .map(|id| format!("windows.evtx.{id}"))
        .chain(other.iter().map(|k| k.to_string()))
        .collect();
    let kinds: Vec<&str> = kinds.iter().map(String::as_str).collect();
    let events = stored.events(system, &kinds).ok()?;
    let ids: Vec<u128> = events.iter().map(|e| e.record).collect();
    let records = stored
        .records_of(&ids)
        .ok()?
        .into_iter()
        .map(|r| {
            let attrs = r
                .attrs
                .as_deref()
                .and_then(|a| serde_json::from_str(a).ok());
            (r.id, (r.locator, attrs.unwrap_or_default()))
        })
        .collect();
    Some((events, records))
}

/// The event log events among `events`, in their order.
pub(crate) fn read_all<'a>(events: &[StoredEvent], records: &'a Records) -> Vec<Read<'a>> {
    events
        .iter()
        .filter_map(|e| Read::new(e, records.get(&e.record)?))
        .collect()
}

/// The time from which events pair (the earliest Security event: before it a boot may have
/// gone unlogged) and each event's boot number (the boot markers at or before it).
pub(crate) fn boots(read: &[Read]) -> Option<(i64, Vec<usize>)> {
    let from = read.iter().find(|r| r.channel == "Security")?.ts;
    let mut boot = 0;
    let boots = read
        .iter()
        .map(|r| {
            boot += usize::from(r.boot_marker);
            boot
        })
        .collect();
    Some((from, boots))
}

/// A stable ID for what a rule makes about the record at `locator`.
pub(crate) fn derive(locator: &str, kind: &Kind, subject: &str) -> u128 {
    let locator = Locator::parse(locator).unwrap_or_else(|| Locator::root("record", locator));
    FactId::derive("", &locator, kind, subject).0
}

/// A field as text, numbers included (the parser keeps numbers as numbers).
pub(crate) fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// What the rules need of one event.
pub(crate) struct Read<'a> {
    pub(crate) id: EventId,
    pub(crate) ts: i64,
    pub(crate) locator: &'a str,
    pub(crate) channel: String,
    pub(crate) event: u32,
    pub(crate) boot_marker: bool,
    /// LocalSessionManager's (session ID, user).
    pub(crate) session: (String, String),
    pub(crate) data: &'a Value,
    /// The target logon ID of 4624, 4634 and 4647, or 4688's subject logon ID, lower case.
    pub(crate) logon_id: Option<String>,
}

impl<'a> Read<'a> {
    pub(crate) fn new(e: &StoredEvent, (locator, attrs): &'a (String, Value)) -> Option<Self> {
        let system = &attrs["System"];
        let channel = system["Channel"].as_str()?.to_string();
        let event = u32::try_from(system["EventID"].as_u64()?).ok()?;
        let provider = system["Provider"]["#attributes"]["Name"]
            .as_str()
            .unwrap_or_default();
        let user = &attrs["UserData"]["EventXML"];
        let data = &attrs["EventData"];
        let logon_id = match event {
            4624 | 4634 | 4647 => text(&data["TargetLogonId"]),
            4688 => text(&data["SubjectLogonId"]),
            _ => None,
        };
        Some(Self {
            id: e.id,
            ts: e.ts?,
            locator,
            boot_marker: (event == 4608 && channel == "Security")
                || (event == 12 && provider == "Microsoft-Windows-Kernel-General"),
            session: (
                text(&user["SessionID"]).unwrap_or_default(),
                text(&user["User"]).unwrap_or_default(),
            ),
            channel,
            event,
            data,
            logon_id: logon_id.map(|l| l.to_lowercase()),
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Found {
    sessions: Vec<Session>,
    logons: Vec<Logon>,
}

/// A session logon and its end, as indexes into the events.
#[derive(Debug, PartialEq, Eq)]
struct Session {
    start: usize,
    end: usize,
}

/// A user logon and the processes started in it.
#[derive(Debug, PartialEq, Eq)]
struct Logon {
    logon: usize,
    processes: Vec<usize>,
}

/// Pairs sessions and groups logons. `read` is in time order.
fn find(read: &[Read]) -> Found {
    let Some((from, boots)) = boots(read) else {
        return Found::default();
    };
    let mut found = Found::default();
    let mut open: HashMap<&(String, String), usize> = HashMap::new();
    let mut logons: HashMap<(usize, &str), usize> = HashMap::new();
    for (i, r) in read.iter().enumerate().filter(|(_, r)| r.ts >= from) {
        if r.boot_marker {
            open.clear();
            logons.clear();
            continue;
        }
        match (r.channel.as_str(), r.event) {
            (LSM, 21) => {
                open.insert(&r.session, i);
            }
            (LSM, 23 | 24) => {
                if let Some(start) = open.remove(&r.session) {
                    found.sessions.push(Session { start, end: i });
                }
            }
            ("Security", 4624)
                if text(&r.data["TargetUserSid"]).is_some_and(|s| s.starts_with("S-1-5-21-")) =>
            {
                if let Some(l) = &r.logon_id {
                    logons.insert((boots[i], l), i);
                }
            }
            ("Security", 4688) => {
                let Some(&logon) = r
                    .logon_id
                    .as_deref()
                    .and_then(|l| logons.get(&(boots[i], l)))
                else {
                    continue;
                };
                match found.logons.iter_mut().find(|g| g.logon == logon) {
                    Some(g) => g.processes.push(i),
                    None => found.logons.push(Logon {
                        logon,
                        processes: vec![i],
                    }),
                }
            }
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(i: u128, ts: i64) -> StoredEvent {
        StoredEvent {
            id: EventId(i),
            record: i,
            kind: String::new(),
            ts: Some(ts),
        }
    }

    fn session(event: u32, id: u32, user: &str) -> Value {
        serde_json::json!({"System": {"Channel": LSM, "EventID": event},
            "UserData": {"EventXML": {"SessionID": id, "User": user}}})
    }

    fn security(event: u32, data: Value) -> Value {
        serde_json::json!({"System": {"Channel": "Security", "EventID": event}, "EventData": data})
    }

    #[test]
    fn sessions_pair_within_a_boot_and_logons_group_their_processes() {
        let kernel_boot = serde_json::json!({"System": {"Channel": "System", "EventID": 12,
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Kernel-General"}}}});
        let attrs = [
            // Before the first Security event: a boot may be missing, so no pair.
            session(21, 1, "PC\\a"),
            session(23, 1, "PC\\a"),
            security(
                4624,
                serde_json::json!({"TargetUserSid": "S-1-5-18", "TargetLogonId": "0x3e7"}),
            ),
            session(21, 2, "PC\\a"),
            security(
                4624,
                serde_json::json!({"TargetUserSid": "S-1-5-21-1-2-3-1001",
                "TargetLogonId": "0x5A1", "TargetUserName": "a", "LogonType": 2}),
            ),
            security(4688, serde_json::json!({"SubjectLogonId": "0x5a1"})),
            // SYSTEM's processes join no group.
            security(4688, serde_json::json!({"SubjectLogonId": "0x3e7"})),
            // Another user's logoff of session 2 doesn't end a's session.
            session(23, 2, "PC\\b"),
            session(24, 2, "PC\\a"),
            security(4688, serde_json::json!({"SubjectLogonId": "0x5a1"})),
            session(21, 3, "PC\\a"),
            kernel_boot,
            // A new boot: session 3 and logon 0x5a1 from before don't carry over.
            session(23, 3, "PC\\a"),
            security(4688, serde_json::json!({"SubjectLogonId": "0x5a1"})),
        ];
        let events: Vec<StoredEvent> = (0..attrs.len()).map(|i| ev(i as u128, i as i64)).collect();
        let records: Vec<(String, Value)> =
            attrs.into_iter().map(|a| ("loc".to_string(), a)).collect();
        let read: Vec<Read> = events
            .iter()
            .zip(&records)
            .map(|(e, r)| Read::new(e, r).unwrap())
            .collect();
        assert_eq!(
            find(&read),
            Found {
                sessions: vec![Session { start: 3, end: 8 }],
                logons: vec![Logon {
                    logon: 4,
                    processes: vec![5, 9]
                }],
            }
        );
    }
}
