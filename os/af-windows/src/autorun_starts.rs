//! Run key to its start (piece L3): Shell-Core event 9707 logs each command Explorer starts from a
//! Run key, cut after its last `\` (`"C:\…\Apoint.exe"` is logged as `Apoint.exe"`). A Run value
//! whose command ends in exactly that text gets a possible link, labelled "consistent with": the
//! log doesn't name the value, and the value may have changed since. A user's own Run key only
//! matches that user's entries. `RunOnce` values are left out: Windows deletes one before running
//! it, so one still there never ran from this value (LoneWolf's OneDrive uninstall entries look
//! like older ones that did).

use crate::sessions::derive;
use af_core::ids::{Endpoint, EventId, FactId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{LinkTier, NewLink, Plugin, RunContext, StoredFact, StoredRecord};
use af_core::system::Family;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Links Run key facts to the 9707 entries consistent with them.
pub struct AutorunStarts;

impl Plugin for AutorunStarts {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.autorun_starts").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Correlate],
            inputs: vec![Input {
                kind: Kind::new("windows.evtx").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: vec![Kind::new("windows.autorun_starts").expect("valid kind")],
        })
    }

    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(stored) = ctx.stored else {
            return Outcome::Ok(0);
        };
        let kind = self.manifest().id.clone();
        let (Ok(facts), Ok(events)) = (
            stored.facts(ctx.system.id, &["windows.autorun"]),
            stored.events(ctx.system.id, &["windows.evtx.9707"]),
        ) else {
            return Outcome::Ok(0);
        };
        let ids: Vec<u128> = events.iter().map(|e| e.record).collect();
        let Ok(records) = stored.records_of(&ids) else {
            return Outcome::Ok(0);
        };
        let event: HashMap<u128, EventId> = events.iter().map(|e| (e.record, e.id)).collect();
        let mut n = 0;
        for (f, r, logged) in matches(&facts, &records) {
            let Some(e) = event.get(&r.id) else {
                continue;
            };
            ctx.sink.link(
                &kind,
                NewLink {
                    id: derive(&r.locator, &kind, &f.subject),
                    kind: kind.clone(),
                    from: Endpoint::Fact(FactId(f.id)),
                    to: Endpoint::Event(*e),
                    tier: LinkTier::Possible,
                    label: "consistent with".into(),
                    reason: "the logged command is the Run value's command after its last \\"
                        .into(),
                    key: logged,
                    description: Some(format!("Run value {}", f.subject)),
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// A Run value: its command after the last `\`, and the user whose hive holds it (`None` for
/// SOFTWARE's, which start for every user).
struct Run<'a> {
    fact: &'a StoredFact,
    tail: String,
    owner: Option<String>,
}

impl<'a> Run<'a> {
    fn new(fact: &'a StoredFact) -> Option<Self> {
        let a: Value = serde_json::from_str(fact.attrs.as_deref()?).ok()?;
        if a["key"] == "RunOnce" {
            return None;
        }
        let command = a["command"].as_str()?.trim_end();
        let tail = &command[command.rfind('\\').map_or(0, |i| i + 1)..];
        (!tail.is_empty()).then(|| Self {
            fact,
            tail: tail.to_string(),
            owner: a["owner"].as_str().map(str::to_string),
        })
    }
}

/// Each Run value with each 9707 record consistent with it, and the logged command.
fn matches<'a>(
    facts: &'a [StoredFact],
    records: &'a [StoredRecord],
) -> Vec<(&'a StoredFact, &'a StoredRecord, String)> {
    let runs: Vec<Run> = facts.iter().filter_map(Run::new).collect();
    let mut out = vec![];
    for r in records {
        let Some(v) = r
            .attrs
            .as_deref()
            .and_then(|a| serde_json::from_str::<Value>(a).ok())
        else {
            continue;
        };
        let Some(logged) = v["EventData"]["Command"].as_str() else {
            continue;
        };
        let user = v["System"]["Security"]["#attributes"]["UserID"].as_str();
        for run in &runs {
            if logged.trim_end() == run.tail && run.owner.as_deref().is_none_or(|o| Some(o) == user)
            {
                out.push((run.fact, r, logged.to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(id: u128, name: &str, key: &str, owner: Option<&str>, command: &str) -> StoredFact {
        StoredFact {
            id,
            kind: "windows.autorun".into(),
            subject: name.into(),
            attrs: Some(
                serde_json::json!({"key": key, "owner": owner, "command": command}).to_string(),
            ),
        }
    }

    fn rec(id: u128, user: &str, command: &str) -> StoredRecord {
        StoredRecord {
            id,
            locator: format!("evtx.record:{id}"),
            attrs: Some(
                serde_json::json!({
                    "System": {"EventID": 9707, "Security": {"#attributes": {"UserID": user}}},
                    "EventData": {"Command": command},
                })
                .to_string(),
            ),
        }
    }

    /// LoneWolf's Run values and 9707 entries: SOFTWARE's start for any user, a user's own only
    /// for that user; present RunOnce values and 9707s from elsewhere (Active Setup) stay unlinked.
    #[test]
    fn run_values_link_to_their_logged_starts() {
        let me = "S-1-5-21-1-1001";
        let facts = [
            run(
                1,
                "Apoint",
                "Run",
                None,
                r#""C:\Program Files\DellTPad\Apoint.exe""#,
            ),
            run(
                2,
                "application",
                "Policies\\Explorer\\Run",
                None,
                r"D:\AKMonitor\AKMonitor.exe hs",
            ),
            run(
                3,
                "OneDrive",
                "Run",
                Some(me),
                r#""C:\Users\j\OneDrive.exe" /background"#,
            ),
            run(
                4,
                "OneDriveSetup",
                "Run",
                Some("S-1-5-19"),
                r"C:\Windows\SysWOW64\OneDriveSetup.exe /thfirstsetup",
            ),
            run(
                5,
                r"Uninstall 18\amd64",
                "RunOnce",
                Some(me),
                r#"cmd.exe /q /c rmdir /s /q "C:\Users\j\18\amd64""#,
            ),
        ];
        let records = [
            rec(10, me, "Apoint.exe\""),
            rec(11, "S-1-5-21-1-1002", "Apoint.exe\""),
            rec(12, me, "AKMonitor.exe hs"),
            rec(13, me, "OneDrive.exe\" /background"),
            rec(14, "S-1-5-21-1-1002", "OneDrive.exe\" /background"),
            rec(15, me, "OneDriveSetup.exe /thfirstsetup"),
            rec(16, me, "amd64\""),
            rec(17, me, "ie4uinit.exe -UserConfig"),
            rec(18, me, "Apoint.exe"),
        ];
        let found: Vec<(u128, u128)> = matches(&facts, &records)
            .iter()
            .map(|(f, r, _)| (f.id, r.id))
            .collect();
        assert_eq!(found, [(1, 10), (1, 11), (2, 12), (3, 13)]);
    }
}
