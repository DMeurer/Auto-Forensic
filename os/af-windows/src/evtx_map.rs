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
        // EvtxECmd's lookups list one code in several spellings (`0xC000005E` and `3221225566`,
        // `0xFFFFFFFF` and `0xffffffff`): keys stay as written, not as the numbers they are.
        let options = serde_saphyr::options! {
            duplicate_keys: serde_saphyr::DuplicateKeyPolicy::PassThrough,
        };
        serde_saphyr::from_str_with_options(text, options).map_err(|e| e.to_string())
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
                let (mut got, one_node) = select_nodes(event, &v.value).unwrap_or_default();
                if let Some(r) = v.refine.as_deref()
                    && let Some(m) = refine(r, &got)
                {
                    got = m;
                }
                if let Some(l) = self.lookups.iter().find(|l| l.name == v.name)
                    && !got.is_empty()
                {
                    // As EvtxECmd: an unknown code shows the default with the code.
                    // Codes ignore case: the `evtx` crate writes hex in lower case, maps in upper.
                    let word = l
                        .values
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(&got))
                        .map(|(_, w)| w);
                    got = match (word, &l.default) {
                        (Some(word), _) => word.clone(),
                        (None, Some(d)) => format!("{d} ({got})"),
                        (None, None) => got,
                    };
                }
                // As EvtxECmd: in one node's text, line breaks with the blank lines and indent
                // after them become `, ` (joined nodes keep theirs).
                if one_node {
                    got = line_breaks().replace_all(&got, ", ").into_owned();
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
    select_nodes(event, path).map(|(t, _)| t)
}

/// [`select`], and whether the path picked one node rather than several (whose texts are
/// joined).
fn select_nodes(event: &Value, path: &str) -> Option<(String, bool)> {
    let rest = path.trim().strip_prefix("/Event")?;
    let mut cur = event;
    for step in steps(rest) {
        if step.is_empty() || step == "text()" {
            continue;
        }
        // Below a repeated element, XPath goes on from its first node; a last step keeps all.
        cur = first(cur);
        if let Some(attr) = step.strip_prefix('@') {
            cur = cur.get("#attributes")?.get(attr)?;
            continue;
        }
        let (name, pred) = match step.split_once('[') {
            Some((n, p)) => (n, Some(p.strip_suffix(']')?)),
            None => (step, None),
        };
        // `evtx` turns `<Data Name="X">` elements into keys `X` of `EventData`; maps that
        // address them as `Data`, `Data[n]` or `Data[@Name="X"]` get those fields.
        let named = name == "Data" && cur.get("Data").is_none() && cur.is_object();
        let field = |n: usize| {
            cur.as_object()?
                .iter()
                .filter(|(k, _)| *k != "#attributes")
                .nth(n)
                .map(|(_, v)| v)
        };
        cur = match pred {
            None if named => field(0)?,
            None => cur.get(name)?,
            Some(p) if p.starts_with('@') => {
                let (attr, want) = p[1..].split_once('=')?;
                let want = want.trim().trim_matches(['"', '\'']);
                match cur.get(name) {
                    None if named && attr == "Name" => cur.get(want)?,
                    None => return None,
                    Some(Value::Array(items)) => items.iter().find(|i| has_attr(i, attr, want))?,
                    Some(v) if has_attr(v, attr, want) => v,
                    Some(_) => return None,
                }
            }
            Some(p) => {
                let n: usize = p.trim().parse().ok()?;
                if named {
                    field(n.checked_sub(1)?)?
                } else {
                    match cur.get(name)? {
                        Value::Array(items) => items.get(n.checked_sub(1)?)?,
                        // Unnamed `<Data>` elements: `{"Data": {"#text": [...]}}`.
                        Value::Object(o) if o.get("#text").is_some_and(Value::is_array) => {
                            o["#text"].as_array()?.get(n.checked_sub(1)?)?
                        }
                        v if n == 1 => v,
                        _ => return None,
                    }
                }
            }
        };
    }
    let several = match cur {
        Value::Array(_) => true,
        Value::Object(o) => o.get("#text").is_some_and(Value::is_array),
        _ => false,
    };
    Some((text(cur)?, !several))
}

/// The text a `Refine` regex picks, as EvtxECmd takes it: every match, joined with ` | `.
/// `None` if it doesn't match or can't be compiled (see [`without_lookaround`]).
fn refine(pattern: &str, text: &str) -> Option<String> {
    let found: Vec<&str> = if let Ok(re) = Regex::new(pattern) {
        re.find_iter(text).map(|m| m.as_str()).collect()
    } else {
        let re = Regex::new(&without_lookaround(pattern)?).ok()?;
        re.captures_iter(text)
            .filter_map(|c| c.name("af").map(|m| m.as_str()))
            .collect()
    };
    (!found.is_empty()).then(|| found.join(" | "))
}

/// EvtxECmd's maps are .NET regexes, and most of their lookarounds are a lookbehind at the start
/// and a lookahead at the end: `(?<=X)Y(?=Z)` becomes `X(?P<af>Y)Z`, whose `af` group is the
/// match. `None` for other lookarounds.
fn without_lookaround(p: &str) -> Option<String> {
    let (anchor, mut rest) = match p.strip_prefix('^') {
        Some(r) if r.starts_with("(?<=") => ("^", r),
        _ => ("", p),
    };
    let mut before = "";
    if rest.starts_with("(?<=") {
        let end = group_end(rest, 0)?;
        before = &rest[4..end];
        rest = &rest[end + 1..];
    }
    let mut after = "";
    let mut i = 0;
    while i < rest.len() {
        match rest.as_bytes()[i] {
            b'\\' => i += 2,
            b'[' => i = class_end(rest, i)? + 1,
            b'(' => {
                let end = group_end(rest, i)?;
                if rest[i..].starts_with("(?=") && end == rest.len() - 1 {
                    after = &rest[i + 3..end];
                    rest = &rest[..i];
                    break;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    let out = format!("{anchor}{before}(?P<af>{rest}){after}");
    (!out.contains("(?<=") && !out.contains("(?=") && !out.contains("(?!") && !out.contains("(?<!"))
        .then_some(out)
}

/// The index of the `)` closing the group that opens at `start`.
fn group_end(p: &str, start: usize) -> Option<usize> {
    let b = p.as_bytes();
    let (mut depth, mut i) = (0, start);
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' => i = class_end(p, i)?,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The index of the `]` closing the character class that opens at `start`.
fn class_end(p: &str, start: usize) -> Option<usize> {
    let b = p.as_bytes();
    let mut i = start + 1;
    if b.get(i) == Some(&b'^') {
        i += 1;
    }
    if b.get(i) == Some(&b']') {
        i += 1;
    }
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b']' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn line_breaks() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\r?\n\s*").expect("valid regex"))
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
        Value::Object(o) => o.get("#text").map_or(Some(String::new()), text),
        // Several nodes: EvtxECmd joins their texts, leaving out empty ones.
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(text)
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join(", "),
        ),
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
        assert_eq!(
            s("/Event/UserData/Ev/Item").as_deref(),
            Some("first, second")
        );
        assert_eq!(s("/Event/UserData/Ev/Item[2]").as_deref(), Some("second"));
        assert_eq!(
            s("/Event/UserData/Ev/Item[@Kind=\"b\"]/text()").as_deref(),
            Some("second")
        );
        assert_eq!(s("/Event/EventData/Data[@Name=\"Nope\"]"), None);
        assert_eq!(s("/Event/EventData/Data[2]").as_deref(), Some("DESKTOP"));
        assert_eq!(s("/Event/EventData/Data").as_deref(), Some("jcloudy"));
        assert_eq!(s("/Event/EventData/Data[4]"), None);
        let unnamed = json!({"EventData": {"Data": {"#text": ["a", "b", "", "c"]}}});
        assert_eq!(
            select(&unnamed, "/Event/EventData/Data").as_deref(),
            Some("a, b, c")
        );
        assert_eq!(
            select(&unnamed, "/Event/EventData/Data[2]").as_deref(),
            Some("b")
        );
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
      0xA: Hex ten
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
        let mut e = event();
        e["EventData"]["LogonType"] = json!(9);
        assert_eq!(m.apply(&e).payload[1], "LogonType Unknown (9)");
        e["EventData"]["LogonType"] = json!("");
        assert_eq!(m.apply(&e).payload[1], "LogonType ");
        e["EventData"]["LogonType"] = json!("2");
        assert_eq!(m.apply(&e).payload[1], "LogonType Interactive");
        e["EventData"]["LogonType"] = json!("0xa");
        assert_eq!(
            m.apply(&e).payload[1],
            "LogonType Hex ten",
            "codes ignore case"
        );
        e["EventData"]["TargetDomainName"] = json!("ab\r\n\r\n\t\tcd\nef");
        assert_eq!(m.apply(&e).user_name, "ab, cd, ef\\jcloudy");
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

    /// EvtxECmd's maps list one code in two spellings; both stay as written.
    #[test]
    fn lookup_keys_keep_their_spelling() {
        let m = EventMap::parse(
            "EventId: 1\nLookups:\n  - Name: Status\n    Values:\n      0xC000005E: no logon servers\n      3221225566: no logon servers\n      0xFFFFFFFF: failure\n      0xffffffff: failure\n",
        )
        .unwrap();
        let keys: Vec<&str> = m.lookups[0].values.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["0xC000005E", "0xFFFFFFFF", "0xffffffff", "3221225566"]
        );
    }

    /// EvtxECmd's lookaround forms, as its maps use them.
    #[test]
    fn refine_takes_lookarounds_at_the_ends() {
        let r = |p: &str, t: &str| refine(p, t);
        assert_eq!(
            r("^.*(?=,)", "time.windows.com,0x9 (ntp)").as_deref(),
            Some("time.windows.com")
        );
        assert_eq!(
            r("(?<=Users\\\\).*", "C:\\Users\\defaultuser0").as_deref(),
            Some("defaultuser0")
        );
        assert_eq!(
            r("(?<=, )[^,\\d]+(?=,)", "1, Search, 2,").as_deref(),
            Some("Search")
        );
        assert_eq!(
            r("(?<=URL=\"?)[^\";]+", "x URL=\"http://a\"; y").as_deref(),
            Some("http://a")
        );
        assert_eq!(
            r("CLIENT.*(?=])", "[CLIENT 1.2]").as_deref(),
            Some("CLIENT 1.2")
        );
        assert_eq!(
            r("(?<=MAC:).*?(?=\n)", "IP:1\nMAC:aa\nX").as_deref(),
            Some("aa")
        );
        assert_eq!(
            r("HostName=(.+)", "a\nHostName=ConsoleHost\n").as_deref(),
            Some("HostName=ConsoleHost")
        );
        assert_eq!(r("(?<=a)b(?=c)", "xyz"), None);
        assert_eq!(
            r(
                "([a-zA-Z0-9_\\.\\-\\(\\):])+(.exe|.dll)",
                "Dropbox.exe, 1, ntdll.dll"
            )
            .as_deref(),
            Some("Dropbox.exe | ntdll.dll"),
            "every match"
        );
        assert_eq!(
            without_lookaround("a(?=b)c"),
            None,
            "a lookahead in the middle"
        );
    }

    /// Local only: how many of EvtxECmd's Refine patterns af can run (`cargo xtask`-free: the
    /// map clone in `~/af-stage3/evtx-maps`).
    #[test]
    fn evtxecmd_refines_compile() {
        let dir = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("af-stage3/evtx-maps/repo/evtx/Maps");
        let Ok(files) = std::fs::read_dir(dir) else {
            return;
        };
        let mut bad = vec![];
        for f in files
            .flatten()
            .filter(|f| f.path().extension().is_some_and(|x| x == "map"))
        {
            let m = EventMap::parse(&std::fs::read_to_string(f.path()).unwrap()).unwrap();
            for p in m
                .maps
                .iter()
                .flat_map(|p| &p.values)
                .filter_map(|v| v.refine.as_deref())
            {
                if Regex::new(p).is_err()
                    && without_lookaround(p)
                        .and_then(|q| Regex::new(&q).ok())
                        .is_none()
                {
                    bad.push(p.to_string());
                }
            }
        }
        // `(?=))` has one `)` too many, for .NET as well (Time-Service 35 and 37, ServerIP).
        assert_eq!(
            bad, ["(?<=-&gt;).*(?=))"; 2],
            "only the broken pattern isn't run"
        );
    }

    #[test]
    fn broken_maps_are_errors() {
        assert!(EventMap::parse("Description: no event id").is_err());
        assert!(EventMap::parse("EventId: [").is_err());
    }
}
