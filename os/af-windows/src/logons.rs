//! Logons of real accounts (piece L10, stage 0's rule r3), from the Security log and SAM. Only
//! accounts with a machine or domain SID (`S-1-5-21-…`): SYSTEM and the service accounts reuse
//! logon IDs all the time. Logon and process IDs count within one boot (see [`crate::sessions`]).
//! - A failed logon (4625) links to the next successful logon (4624) of the same account, logon
//!   type and logon process, strong.
//! - A logon links to its logoff (4647 "user logged off", or 4634 "session ended") by logon ID and
//!   SID, strong. Logons that end within 10 seconds don't: they are one group per account and
//!   boot, the user's choice (stage 0: 40 of 86 links were such logons).
//! - The normal and the elevated token of one logon, each naming the other as its linked logon,
//!   are a group, the user's choice.
//! - SAM's last logon and last wrong password link from the latest such event of the account.

use crate::sessions::{Read, boots, derive, load, read_all, text};
use af_core::ids::{Endpoint, EventId, GroupId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{LinkTier, NewGroup, NewLink, Plugin, RunContext, StoredEvent};
use af_core::system::Family;
use af_core::time::Time;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

/// Logons that end sooner than this are grouped: 10 s in 100 ns ticks (the user's choice).
const SHORT: i64 = 10 * 10_000_000;
const LAST_LOGIN: &str = "windows.account.last_login";
const LAST_FAILED: &str = "windows.account.last_failed_login";

/// Logon links and groups.
pub struct Logons;

impl Plugin for Logons {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.logons").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: vec![Input {
                kind: Kind::new("windows.evtx").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: [
                "windows.logon",
                "windows.logon.short",
                "windows.logon.tokens",
            ]
            .map(|k| Kind::new(k).expect("valid kind"))
            .into(),
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let ids = [12, 4608, 4624, 4625, 4634, 4647];
        let Some((events, records)) = load(stored, ctx.system.id, &ids, &[LAST_LOGIN, LAST_FAILED])
        else {
            return Outcome::Ok(0);
        };
        let read = read_all(&events, &records);
        let sam: Vec<Sam> = events
            .iter()
            .filter_map(|e| Sam::new(e, &records.get(&e.record)?.1))
            .collect();
        let found = find(&read, &sam);
        let plugin = self.manifest().id.clone();
        let link_kind = Kind::new("windows.logon").expect("valid kind");
        for l in &found.links {
            ctx.sink.link(
                &plugin,
                NewLink {
                    id: derive(l.anchor, &link_kind, &format!("{} {}", l.label, l.key)),
                    kind: link_kind.clone(),
                    from: Endpoint::Event(l.from),
                    to: Endpoint::Event(l.to),
                    tier: LinkTier::Strong,
                    label: l.label.into(),
                    reason: l.reason.clone(),
                    key: l.key.clone(),
                    description: l.description.clone(),
                },
            );
        }
        for g in &found.groups {
            let kind = Kind::new(g.kind).expect("valid kind");
            ctx.sink.group(
                &plugin,
                NewGroup {
                    id: GroupId(derive(g.anchor, &kind, g.kind)),
                    kind,
                    reason: g.reason.clone(),
                    members: g
                        .members
                        .iter()
                        .map(|(e, why)| (Endpoint::Event(*e), why.clone()))
                        .collect(),
                },
            );
        }
        Outcome::Ok((found.links.len() + found.groups.len()) as u64)
    }
}

/// One of SAM's per-account times, with the account's RID and name.
struct Sam {
    id: EventId,
    ts: i64,
    last_login: bool,
    rid: String,
    name: String,
}

impl Sam {
    fn new(e: &StoredEvent, attrs: &Value) -> Option<Self> {
        Some(Self {
            id: e.id,
            ts: e.ts?,
            last_login: match e.kind.as_str() {
                LAST_LOGIN => true,
                LAST_FAILED => false,
                _ => return None,
            },
            rid: text(&attrs["rid"])?,
            name: attrs["name"].as_str()?.to_lowercase(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Link<'a> {
    anchor: &'a str,
    from: EventId,
    to: EventId,
    label: &'static str,
    reason: String,
    key: String,
    description: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Group<'a> {
    anchor: &'a str,
    kind: &'static str,
    reason: String,
    /// Each member with why it is there (O8).
    members: Vec<(EventId, String)>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Found<'a> {
    links: Vec<Link<'a>>,
    groups: Vec<Group<'a>>,
}

/// The Security fields the rule compares, lower case.
struct Logon {
    sid: String,
    user: String,
    logon_type: String,
    pid: String,
    linked: String,
    elevated: bool,
}

impl Logon {
    fn of(r: &Read) -> Self {
        let f = |name: &str| text(&r.data[name]).unwrap_or_default().to_lowercase();
        Self {
            sid: text(&r.data["TargetUserSid"]).unwrap_or_default(),
            user: f("TargetUserName"),
            logon_type: f("LogonType"),
            pid: f("ProcessId"),
            linked: f("TargetLinkedLogonId"),
            elevated: f("ElevatedToken") == "%%1842",
        }
    }

    fn real(&self) -> bool {
        self.sid.starts_with("S-1-5-21-")
    }
}

fn seconds(ticks: i64) -> i64 {
    ticks / 10_000_000
}

fn clock(ts: i64) -> String {
    let t = Time::from_ticks_1601(ts as u64).display();
    // "2026-09-08 09:09:48.5840000 UTC" -> "09:09:48.584"
    t.get(11..23).unwrap_or(&t).to_string()
}

/// `read` is in time order.
fn find<'a>(read: &[Read<'a>], sam: &[Sam]) -> Found<'a> {
    let mut found = Found::default();
    let Some((from, boots)) = boots(read) else {
        return found;
    };
    let security = |i: usize, id: u32| read[i].channel == "Security" && read[i].event == id;
    let info: Vec<Logon> = read.iter().map(Logon::of).collect();
    let all: Vec<usize> = (0..read.len()).filter(|&i| read[i].ts >= from).collect();
    let logons: Vec<usize> = all
        .iter()
        .copied()
        .filter(|&i| security(i, 4624) && info[i].real())
        .collect();

    // A failed logon -> the next success of the same account, type and logon process.
    for &f in all.iter().filter(|&&i| security(i, 4625)) {
        let (fl, fr) = (&info[f], &read[f]);
        let mut next = logons.iter().copied().filter(|&s| {
            let sl = &info[s];
            boots[s] == boots[f]
                && read[s].ts > fr.ts
                && (&sl.user, &sl.logon_type, &sl.pid) == (&fl.user, &fl.logon_type, &fl.pid)
        });
        let Some(first) = next.next() else { continue };
        // Of two tokens made at once, the elevated one.
        let s = std::iter::once(first)
            .chain(next.take_while(|&s| read[s].ts == read[first].ts))
            .max_by_key(|&s| info[s].elevated)
            .expect("one at least");
        found.links.push(Link {
            anchor: fr.locator,
            from: fr.id,
            to: read[s].id,
            label: "then logged on",
            reason: format!(
                "same account, logon type {} and logon process ID {}, first success after the \
                 failure",
                fl.logon_type, fl.pid
            ),
            key: format!("{} / type {} / pid {}", fl.user, fl.logon_type, fl.pid),
            description: Some(format!(
                "{} s after the failed attempt",
                seconds(read[s].ts - fr.ts)
            )),
        });
    }

    // A logon -> its logoff; short ones grouped per account and boot.
    let mut short: BTreeMap<(usize, &str), Vec<usize>> = BTreeMap::new();
    for &s in &logons {
        let (sl, sr) = (&info[s], &read[s]);
        let Some(e) = all.iter().copied().find(|&e| {
            (security(e, 4634) || security(e, 4647))
                && boots[e] == boots[s]
                && read[e].ts >= sr.ts
                && read[e].logon_id == sr.logon_id
                && info[e].sid == sl.sid
        }) else {
            continue;
        };
        let lasted = read[e].ts - sr.ts;
        if lasted < SHORT {
            short.entry((boots[s], &sl.sid)).or_default().extend([s, e]);
            continue;
        }
        let lid = sr.logon_id.as_deref().unwrap_or_default();
        found.links.push(Link {
            anchor: sr.locator,
            from: sr.id,
            to: read[e].id,
            label: if read[e].event == 4647 {
                "user logged off"
            } else {
                "session ended"
            },
            reason: format!("same logon ID {lid} and account SID"),
            key: format!("{} / {lid}", sl.sid),
            description: Some(format!("session lasted {} s", seconds(lasted))),
        });
    }
    for members in short.values() {
        let first = members[0];
        let n = members.len() / 2;
        found.groups.push(Group {
            anchor: read[first].locator,
            kind: "windows.logon.short",
            reason: format!(
                "{n} logon{} of {} that ended within 10 s, same boot",
                if n == 1 { "" } else { "s" },
                info[first].user
            ),
            members: members
                .chunks(2)
                .flat_map(|p| {
                    let (s, e) = (p[0], p[1]);
                    let lid = read[s].logon_id.as_deref().unwrap_or_default();
                    let end = if read[e].event == 4647 {
                        "user logged off"
                    } else {
                        "session ended"
                    };
                    [
                        (read[s].id, format!("logon {lid} at {}", clock(read[s].ts))),
                        (
                            read[e].id,
                            format!(
                                "{end} {:.1} s after logon {lid}",
                                (read[e].ts - read[s].ts) as f64 / 1e7
                            ),
                        ),
                    ]
                })
                .collect(),
        });
    }

    // The normal and the elevated token of one logon.
    let mut by_id: HashMap<(usize, &str), usize> = HashMap::new();
    for &s in &logons {
        if let Some(l) = read[s].logon_id.as_deref() {
            by_id.insert((boots[s], l), s);
        }
    }
    for &a in &logons {
        let al = &info[a];
        let Some(&b) = by_id.get(&(boots[a], al.linked.as_str())) else {
            continue;
        };
        let bl = &info[b];
        if a < b && read[a].logon_id.as_deref() == Some(bl.linked.as_str()) && bl.sid == al.sid {
            found.groups.push(Group {
                anchor: read[a].locator,
                kind: "windows.logon.tokens",
                reason: format!("logon of {} (normal and elevated token)", al.user),
                members: [a, b]
                    .map(|t| {
                        let which = if info[t].elevated {
                            "elevated token"
                        } else {
                            "normal token"
                        };
                        let lid = read[t].logon_id.as_deref().unwrap_or_default();
                        (read[t].id, format!("{which}, logon ID {lid}"))
                    })
                    .into(),
            });
        }
    }

    // SAM keeps only the latest logon and wrong password: the latest such event of the account.
    for m in sam {
        let latest = if m.last_login {
            logons
                .iter()
                .copied()
                .filter(|&s| info[s].sid.ends_with(&format!("-{}", m.rid)))
                .max_by_key(|&s| (read[s].ts, info[s].elevated))
        } else {
            all.iter()
                .copied()
                .filter(|&f| security(f, 4625) && info[f].user == m.name)
                .max_by_key(|&f| read[f].ts)
        };
        let Some(e) = latest else { continue };
        let (label, reason, key) = if m.last_login {
            (
                "is SAM's last logon",
                format!(
                    "SAM keeps the time of the account's latest logon; this is the latest logon \
                     event of RID {}",
                    m.rid
                ),
                format!("{} / RID {}", m.name, m.rid),
            )
        } else {
            (
                "is SAM's last wrong password",
                format!(
                    "SAM keeps the time of the account's latest wrong password; this is the \
                     latest failed logon for {}",
                    m.name
                ),
                m.name.clone(),
            )
        };
        found.links.push(Link {
            anchor: read[e].locator,
            from: read[e].id,
            to: m.id,
            label,
            reason,
            key,
            description: Some(format!("SAM {}, event {}", clock(m.ts), clock(read[e].ts))),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security(event: u32, data: Value) -> Value {
        serde_json::json!({"System": {"Channel": "Security", "EventID": event}, "EventData": data})
    }

    fn logon(lid: &str, linked: &str, elevated: bool) -> Value {
        security(
            4624,
            serde_json::json!({"TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetUserName": "Ich",
                "TargetLogonId": lid, "TargetLinkedLogonId": linked, "LogonType": 2,
                "ProcessId": "0x2e4", "ElevatedToken": if elevated { "%%1842" } else { "%%1843" }}),
        )
    }

    fn logoff(event: u32, lid: &str) -> Value {
        security(
            event,
            serde_json::json!({"TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetLogonId": lid}),
        )
    }

    const S: i64 = 10_000_000;

    #[test]
    fn failures_logoffs_short_logons_tokens_and_sam() {
        let failed = security(
            4625,
            serde_json::json!({"TargetUserSid": "S-1-0-0", "TargetUserName": "ich",
                "LogonType": 2, "ProcessId": "0x2E4"}),
        );
        let attrs = [
            (0, security(4608, serde_json::json!({}))),
            (S, failed.clone()),
            // Two tokens at once: the elevated one is the failure's success.
            (6 * S, logon("0x10", "0x11", false)),
            (6 * S, logon("0x11", "0x10", true)),
            // A logon that ends within a second.
            (7 * S, logon("0x20", "0x0", false)),
            (7 * S + 1, logoff(4634, "0x20")),
            (100 * S, logoff(4647, "0x11")),
            (101 * S, logoff(4634, "0x10")),
            (200 * S, failed),
        ];
        let events: Vec<StoredEvent> = attrs
            .iter()
            .enumerate()
            .map(|(i, (ts, _))| StoredEvent {
                id: EventId(i as u128),
                record: i as u128,
                kind: String::new(),
                ts: Some(*ts),
            })
            .collect();
        let records: Vec<(String, Value)> = attrs
            .into_iter()
            .map(|(_, a)| ("loc".to_string(), a))
            .collect();
        let read: Vec<Read> = events
            .iter()
            .zip(&records)
            .map(|(e, r)| Read::new(e, r).unwrap())
            .collect();
        let sam = [
            Sam {
                id: EventId(50),
                ts: 6 * S,
                last_login: true,
                rid: "1001".into(),
                name: "ich".into(),
            },
            Sam {
                id: EventId(51),
                ts: 200 * S,
                last_login: false,
                rid: "1001".into(),
                name: "ich".into(),
            },
        ];
        let found = find(&read, &sam);
        let links: Vec<(u128, u128, &str)> = found
            .links
            .iter()
            .map(|l| (l.from.0, l.to.0, l.label))
            .collect();
        assert_eq!(
            links,
            [
                (1, 3, "then logged on"),
                // The second failure has no success after it.
                (2, 7, "session ended"),
                (3, 6, "user logged off"),
                // The latest logon is the short one at 7 s.
                (4, 50, "is SAM's last logon"),
                (8, 51, "is SAM's last wrong password"),
            ]
        );
        let groups: Vec<(&str, Vec<u128>)> = found
            .groups
            .iter()
            .map(|g| (g.kind, g.members.iter().map(|m| m.0.0).collect()))
            .collect();
        assert_eq!(
            groups,
            [
                ("windows.logon.short", vec![4, 5]),
                ("windows.logon.tokens", vec![2, 3]),
            ]
        );
        // O8: why each member is there.
        let whys: Vec<Vec<&str>> = found
            .groups
            .iter()
            .map(|g| g.members.iter().map(|m| m.1.as_str()).collect())
            .collect();
        assert_eq!(
            whys,
            [
                vec![
                    "logon 0x20 at 00:00:07.000",
                    "session ended 0.0 s after logon 0x20"
                ],
                vec![
                    "normal token, logon ID 0x10",
                    "elevated token, logon ID 0x11"
                ],
            ]
        );
    }
}
