//! Event log maps (piece E3) in EvtxECmd's YAML format (user's choice, 2026-11-08), so its
//! community maps work here and af's output can be compared with EvtxECmd's field by field.
//!
//! A map names one event (`EventId`, with `Channel` and `Provider`) and fills EvtxECmd's output
//! fields (`UserName`, `RemoteHost`, `ExecutableInfo`, `PayloadData1` to `6`) from templates
//! such as `"%domain%\%user%"`, each `%name%` from an XPath into the event. af adds one field,
//! `Note`, for what a reader should know, such as an audit policy the event needs.
//!
//! The XPaths run on the event as stored (the `evtx` crate's JSON of the XML), for the forms maps
//! use: element steps from `/Event`, `Data[@Name="X"]` and other `[@attr="v"]` predicates,
//! `[n]` positions, a last `@attr` step, and `text()`.

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// The maps compiled in (E4, the starter set), as file name and text. Written for af to give
/// EvtxECmd's fields for these events on LoneWolf; a project's own maps come first.
pub const BUILTIN: &[(&str, &str)] = &[
    (
        "Security_Microsoft-Windows-Security-Auditing_4624.map",
        include_str!("../maps/Security_Microsoft-Windows-Security-Auditing_4624.map"),
    ),
    (
        "Security_Microsoft-Windows-Security-Auditing_4634.map",
        include_str!("../maps/Security_Microsoft-Windows-Security-Auditing_4634.map"),
    ),
    (
        "Security_Microsoft-Windows-Security-Auditing_4688.map",
        include_str!("../maps/Security_Microsoft-Windows-Security-Auditing_4688.map"),
    ),
    (
        "System_Service-Control-Manager_7045.map",
        include_str!("../maps/System_Service-Control-Manager_7045.map"),
    ),
    (
        "Microsoft-Windows-Partition-Diagnostic_Microsoft-Windows-Partition_1006.map",
        include_str!(
            "../maps/Microsoft-Windows-Partition-Diagnostic_Microsoft-Windows-Partition_1006.map"
        ),
    ),
    (
        "Microsoft-Windows-Shell-Core-Operational_Microsoft-Windows-Shell-Core_9707.map",
        include_str!(
            "../maps/Microsoft-Windows-Shell-Core-Operational_Microsoft-Windows-Shell-Core_9707.map"
        ),
    ),
];

/// The first of `maps` for a stored `Event` element, applied to it.
pub fn map_event<'m>(maps: &'m [EventMap], event: &Value) -> Option<(&'m EventMap, Mapped)> {
    let field = |p: &str| select(event, p).unwrap_or_default();
    let id: u32 = field("/Event/System/EventID").parse().ok()?;
    let (channel, provider) = (
        field("/Event/System/Channel"),
        field("/Event/System/Provider/@Name"),
    );
    let m = maps.iter().find(|m| m.is_for(id, &channel, &provider))?;
    Some((m, m.apply(event)))
}

/// One map file.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventMap {
    #[serde(default)]
    pub description: String,
    pub event_id: u32,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub maps: Vec<Property>,
    #[serde(default)]
    pub lookups: Vec<Lookup>,
    /// af's addition: shown with the map's events.
    #[serde(default)]
    pub note: Option<String>,
}

/// One output field and how to fill it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Property {
    pub property: String,
    pub property_value: String,
    #[serde(default)]
    pub values: Vec<ValueRef>,
}

/// One `%name%` in a template: where its text comes from.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ValueRef {
    pub name: String,
    pub value: String,
    /// A regex; its first match replaces the text.
    #[serde(default)]
    pub refine: Option<String>,
}

/// Codes to words for the value of the same name.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Lookup {
    pub name: String,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

/// EvtxECmd's output fields for one event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mapped {
    pub description: String,
    pub user_name: String,
    pub remote_host: String,
    pub executable_info: String,
    pub payload: [String; 6],
}

impl EventMap {
    /// Parses a map file.
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_saphyr::from_str(text).map_err(|e| e.to_string())
    }

    /// Whether the map is for this event: the same ID, and channel and provider where the map
    /// names them, ignoring case.
    pub fn is_for(&self, event_id: u32, channel: &str, provider: &str) -> bool {
        let same = |want: &Option<String>, have: &str| {
            want.as_deref().is_none_or(|w| w.eq_ignore_ascii_case(have))
        };
        self.event_id == event_id && same(&self.channel, channel) && same(&self.provider, provider)
    }

    /// The output fields for `event`, the stored `Event` element.
    pub fn apply(&self, event: &Value) -> Mapped {
        let mut out = Mapped {
            description: self.description.clone(),
            ..Mapped::default()
        };
        for p in &self.maps {
            let mut text = p.property_value.clone();
            for v in &p.values {
                let mut got = select(event, &v.value).unwrap_or_default();
                if let Some(re) = v.refine.as_deref().and_then(|r| Regex::new(r).ok())
                    && let Some(m) = re.find(&got)
                {
                    got = m.as_str().to_string();
                }
                if let Some(l) = self.lookups.iter().find(|l| l.name == v.name) {
                    got = match (l.values.get(&got), &l.default) {
                        (Some(word), _) => word.clone(),
                        (None, Some(d)) => d.clone(),
                        (None, None) => got,
                    };
                }
                text = text.replace(&format!("%{}%", v.name), &got);
            }
            let slot = match p.property.as_str() {
                "UserName" => &mut out.user_name,
                "RemoteHost" => &mut out.remote_host,
                "ExecutableInfo" => &mut out.executable_info,
                other => match other
                    .strip_prefix("PayloadData")
                    .and_then(|n| n.parse::<usize>().ok())
                    .and_then(|n| out.payload.get_mut(n.wrapping_sub(1)))
                {
                    Some(s) => s,
                    None => continue,
                },
            };
            *slot = text;
        }
        out
    }
}

/// The text an XPath (the subset the module docs list) selects in an `Event` element stored as
/// the `evtx` crate's JSON. `None` if nothing matches.
pub fn select(event: &Value, path: &str) -> Option<String> {
    let rest = path.trim().strip_prefix("/Event")?;
    let mut cur = event;
    for step in steps(rest) {
        if step.is_empty() || step == "text()" {
            continue;
        }
        if let Some(attr) = step.strip_prefix('@') {
            cur = cur.get("#attributes")?.get(attr)?;
            continue;
        }
        let (name, pred) = match step.split_once('[') {
            Some((n, p)) => (n, Some(p.strip_suffix(']')?)),
            None => (step, None),
        };
        cur = match pred {
            None => first(cur.get(name)?),
            Some(p) if p.starts_with('@') => {
                let (attr, want) = p[1..].split_once('=')?;
                let want = want.trim().trim_matches(['"', '\'']);
                // `evtx` turns `<Data Name="X">` into a key `X` of `EventData`.
                match cur.get(name) {
                    None if name == "Data" && attr == "Name" => cur.get(want)?,
                    None => return None,
                    Some(Value::Array(items)) => items.iter().find(|i| has_attr(i, attr, want))?,
                    Some(v) if has_attr(v, attr, want) => v,
                    Some(_) => return None,
                }
            }
            Some(p) => {
                let n: usize = p.trim().parse().ok()?;
                match cur.get(name)? {
                    Value::Array(items) => items.get(n.checked_sub(1)?)?,
                    v if n == 1 => v,
                    _ => return None,
                }
            }
        };
    }
    text(cur)
}

/// Path steps, split at `/` outside predicates.
fn steps(path: &str) -> Vec<&str> {
    let mut out = vec![];
    let (mut depth, mut start) = (0, 0);
    for (i, c) in path.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            '/' if depth == 0 => {
                out.push(&path[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&path[start..]);
    out
}

/// XPath's first node where an element repeats.
fn first(v: &Value) -> &Value {
    match v {
        Value::Array(items) => items.first().unwrap_or(v),
        _ => v,
    }
}

fn has_attr(v: &Value, attr: &str, want: &str) -> bool {
    v.get("#attributes")
        .and_then(|a| a.get(attr))
        .and_then(text)
        .is_some_and(|t| t == want)
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some(String::new()),
        Value::Object(o) => o
            .get("#text")
            .map_or(Some(String::new()), |t| text(first(t))),
        Value::Array(_) => text(first(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event() -> Value {
        json!({
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": 4624,
                "Security": {"#attributes": {"UserID": "S-1-5-18"}}
            },
            "EventData": {"TargetUserName": "jcloudy", "TargetDomainName": "DESKTOP", "LogonType": 2},
            "UserData": {"Ev": {"Item": [
                {"#attributes": {"Kind": "a"}, "#text": "first"},
                {"#attributes": {"Kind": "b"}, "#text": "second"}
            ]}}
        })
    }

    #[test]
    fn xpaths_of_the_forms_maps_use() {
        let e = event();
        let s = |p: &str| select(&e, p);
        assert_eq!(
            s("/Event/EventData/Data[@Name=\"TargetUserName\"]").as_deref(),
            Some("jcloudy")
        );
        assert_eq!(
            s("/Event/EventData/Data[@Name='LogonType']").as_deref(),
            Some("2")
        );
        assert_eq!(
            s("/Event/System/Provider/@Name").as_deref(),
            Some("Microsoft-Windows-Security-Auditing")
        );
        assert_eq!(
            s("/Event/System/Security/@UserID").as_deref(),
            Some("S-1-5-18")
        );
        assert_eq!(s("/Event/UserData/Ev/Item").as_deref(), Some("first"));
        assert_eq!(s("/Event/UserData/Ev/Item[2]").as_deref(), Some("second"));
        assert_eq!(
            s("/Event/UserData/Ev/Item[@Kind=\"b\"]/text()").as_deref(),
            Some("second")
        );
        assert_eq!(s("/Event/EventData/Data[@Name=\"Nope\"]"), None);
        assert_eq!(s("/Other/x"), None);
        assert_eq!(s("/Event/UserData/Ev/Item[0]"), None);
    }

    #[test]
    fn a_map_fills_fields_with_templates_and_lookups() {
        let m = EventMap::parse(
            r#"
Author: test
Description: Successful logon
EventId: 4624
Channel: Security
Provider: Microsoft-Windows-Security-Auditing
Note: needs nothing
Maps:
  -
    Property: UserName
    PropertyValue: "%domain%\\%user%"
    Values:
      -
        Name: domain
        Value: "/Event/EventData/Data[@Name=\"TargetDomainName\"]"
      -
        Name: user
        Value: "/Event/EventData/Data[@Name=\"TargetUserName\"]"
        Refine: "[a-z]+"
  -
    Property: PayloadData2
    PropertyValue: "LogonType %LogonType%"
    Values:
      -
        Name: LogonType
        Value: "/Event/EventData/Data[@Name=\"LogonType\"]"
  -
    Property: SomethingElse
    PropertyValue: ignored
Lookups:
  -
    Name: LogonType
    Default: Unknown
    Values:
      2: Interactive
      3: Network
"#,
        )
        .unwrap();
        assert!(m.is_for(4624, "security", "Microsoft-Windows-Security-Auditing"));
        assert!(!m.is_for(4624, "System", "Microsoft-Windows-Security-Auditing"));
        assert!(!m.is_for(4625, "Security", "Microsoft-Windows-Security-Auditing"));
        assert_eq!(m.note.as_deref(), Some("needs nothing"));
        let out = m.apply(&event());
        assert_eq!(out.description, "Successful logon");
        assert_eq!(out.user_name, "DESKTOP\\jcloudy");
        assert_eq!(out.payload[1], "LogonType Interactive");
        assert_eq!(out.payload[0], "");
    }

    #[test]
    fn built_in_maps_parse_and_4688_says_it_needs_auditing() {
        let maps: Vec<EventMap> = BUILTIN
            .iter()
            .map(|(n, t)| EventMap::parse(t).unwrap_or_else(|e| panic!("{n}: {e}")))
            .collect();
        let ids: Vec<u32> = maps.iter().map(|m| m.event_id).collect();
        assert_eq!(ids, [4624, 4634, 4688, 7045, 1006, 9707]);
        let note = maps[2].note.as_deref().unwrap();
        assert!(note.contains("Audit Process Creation"), "{note}");
        // 1006 of another provider (Wcmsvc's, on LoneWolf too) isn't the disk event.
        assert!(!maps[4].is_for(
            1006,
            "Microsoft-Windows-Wcmsvc/Operational",
            "Microsoft-Windows-Wcmsvc"
        ));
    }

    #[test]
    fn broken_maps_are_errors() {
        assert!(EventMap::parse("Description: no event id").is_err());
        assert!(EventMap::parse("EventId: [").is_err());
    }
}
