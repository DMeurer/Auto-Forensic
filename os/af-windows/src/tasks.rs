//! Scheduled tasks (piece X4): every file below `Windows\System32\Tasks` is a task in XML (UTF-16
//! with a byte order mark, as Windows writes them, or UTF-8), read with `roxmltree` (the user's
//! choice). Each becomes a `windows.task` record: URI, author, description, the account it runs
//! as, whether it is enabled and hidden, its triggers and its actions (a command with its
//! arguments, or a COM handler). Its registration date is a `windows.task.registered` event.
//! That date is local time unless it carries an offset; with the registry it gets the system's
//! zone, as R9's dates do. A file that isn't task XML is a note.

use crate::registry::{TimeZone, time_zone};
use af_core::ids::{EventId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewRecord, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use roxmltree::{Document, Node};
use std::sync::OnceLock;

/// Every scheduled task as a record, with its registration date as an event.
pub struct Tasks;

impl Plugin for Tasks {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.tasks").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("windows.task").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: ["windows.task", "windows.task.registered"]
                .into_iter()
                .map(|k| Kind::new(k).expect("valid kind"))
                .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let id = self.manifest().id.clone();
        let record_kind = Kind::new("windows.task").expect("valid kind");
        let kind = Kind::new("windows.task.registered").expect("valid kind");
        let meaning = TimeMeaning::new(kind.as_str()).expect("valid meaning");
        let zone = ctx.caps.registry.and_then(time_zone);
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "windows.task")
        {
            let path = a.locator.steps().last().map_or("", |s| s.id.as_str());
            let data = opener.open(a).and_then(|src| {
                let mut buf = vec![0; usize::try_from(src.len()).map_err(std::io::Error::other)?];
                src.read_exact_at(0, &mut buf).map(|()| buf)
            });
            let task = match data.map_err(|e| e.to_string()).and_then(|d| read(&d)) {
                Ok(t) => t,
                Err(e) => {
                    ctx.sink
                        .note(&id, ctx.system.id, format!("task {path} wasn't read: {e}"));
                    continue;
                }
            };
            let source_text = a.source.to_string();
            let record = record_id(&source_text, &a.locator);
            ctx.sink.record(
                &id,
                ctx.system.id,
                NewRecord {
                    id: record,
                    source: a.source,
                    kind: record_kind.clone(),
                    locator: a.locator.clone(),
                    attrs: Some(task.attrs.to_string()),
                },
            );
            if let Some(time) = task.date.as_deref().and_then(|d| date(d, zone.as_ref())) {
                ctx.sink.event(
                    &id,
                    ctx.system.id,
                    NewEvent {
                        id: EventId::derive(&source_text, &a.locator, None, &kind, &meaning, 0),
                        source: a.source,
                        record,
                        kind: kind.clone(),
                        meaning: meaning.clone(),
                        time,
                        clock: ClockDomainId("wall".into()),
                        seq: None,
                    },
                );
                n += 1;
            }
        }
        Outcome::Ok(n)
    }
}

/// A task file's attributes and its registration date as written.
pub(crate) struct Task {
    pub attrs: serde_json::Value,
    pub date: Option<String>,
}

/// A task file: XML in UTF-16 (byte order mark `FF FE` or `FE FF`) or UTF-8.
pub(crate) fn read(data: &[u8]) -> Result<Task, String> {
    let text = match data {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => {
            String::from_utf8(rest.to_vec()).map_err(|e| e.to_string())?
        }
        _ => String::from_utf8(data.to_vec()).map_err(|e| e.to_string())?,
    };
    // roxmltree reads the encoding from the text it gets, not the declaration's.
    let text = text.replacen("encoding=\"UTF-16\"", "encoding=\"UTF-8\"", 1);
    let doc = Document::parse(&text).map_err(|e| e.to_string())?;
    let task = doc.root_element();
    if task.tag_name().name() != "Task" {
        return Err(format!("no Task element but {}", task.tag_name().name()));
    }
    let info = child(task, "RegistrationInfo");
    let principal = child(task, "Principals").and_then(|p| child(p, "Principal"));
    let settings = child(task, "Settings");
    let text_of = |n: Option<Node>, name: &str| {
        n.and_then(|n| child(n, name))
            .and_then(|c| c.text())
            .map(str::trim)
            .map(String::from)
    };
    let flag = |n: Option<Node>, name: &str, default: bool| {
        text_of(n, name).map_or(default, |v| v == "true")
    };
    let triggers: Vec<serde_json::Value> = child(task, "Triggers")
        .map(|t| t.children().filter(Node::is_element).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "type": t.tag_name().name(),
                "start": text_of(Some(t), "StartBoundary"),
                "enabled": flag(Some(t), "Enabled", true),
            })
        })
        .collect();
    let actions: Vec<serde_json::Value> = child(task, "Actions")
        .map(|t| t.children().filter(Node::is_element).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|a| match a.tag_name().name() {
            "Exec" => serde_json::json!({
                "exec": text_of(Some(a), "Command"),
                "arguments": text_of(Some(a), "Arguments"),
                "working_dir": text_of(Some(a), "WorkingDirectory"),
            }),
            "ComHandler" => serde_json::json!({
                "com_handler": text_of(Some(a), "ClassId"),
                "data": text_of(Some(a), "Data"),
            }),
            other => serde_json::json!({ "other": other }),
        })
        .collect();
    let date = text_of(info, "Date");
    Ok(Task {
        attrs: serde_json::json!({
            "uri": text_of(info, "URI"),
            "author": text_of(info, "Author"),
            "description": text_of(info, "Description"),
            "source": text_of(info, "Source"),
            "registered": date,
            "user_id": text_of(principal, "UserId"),
            "group_id": text_of(principal, "GroupId"),
            "logon_type": text_of(principal, "LogonType"),
            "run_level": text_of(principal, "RunLevel"),
            "enabled": flag(settings, "Enabled", true),
            "hidden": flag(settings, "Hidden", false),
            "triggers": triggers,
            "actions": actions,
        }),
        date,
    })
}

fn child<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn utf16(b: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| unit(*c)).collect();
    String::from_utf16_lossy(&units)
}

/// An XML `dateTime` (`2018-03-27T13:11:50.6597296`, with `Z` or `+01:00` or no zone). Without
/// a zone it is the system's local time: given the zone's rules, converted; else kept local.
fn date(text: &str, zone: Option<&TimeZone>) -> Option<Time> {
    let (day, rest) = text.split_once('T')?;
    let mut d = day.splitn(3, '-').map(str::parse::<u16>);
    let (y, mo, dd) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let (clock, offset) = match rest.find(['Z', '+', '-']) {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let (hms, frac) = clock.split_once('.').unwrap_or((clock, ""));
    let mut t = hms.splitn(3, ':').map(str::parse::<u16>);
    let (h, mi, s) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    let ticks_frac: u64 = format!("{frac:0<7}").get(..7)?.parse().ok()?;
    match offset {
        Some(o) => {
            let minutes = match o {
                "Z" => 0,
                _ => {
                    let sign = if o.starts_with('-') { -1 } else { 1 };
                    let (oh, om) = o[1..].split_once(':')?;
                    sign * (oh.parse::<i64>().ok()? * 60 + om.parse::<i64>().ok()?)
                }
            };
            let secs = days_from_civil(y.into(), mo.into(), dd.into()) * 86_400
                + i64::from(h) * 3_600
                + i64::from(mi) * 60
                + i64::from(s)
                - minutes * 60;
            // Seconds from 1601 to 1970.
            let ticks = u64::try_from(secs + 11_644_473_600).ok()? * 10_000_000 + ticks_frac;
            Some(Time::from_ticks_1601(ticks))
        }
        None => {
            let t = Time::from_local_calendar(y, mo, dd, h, mi, s, (ticks_frac / 10_000) as u16);
            Some(
                match zone.and_then(|z| z.offset_at(y.into(), mo, dd, h, mi)) {
                    Some(off) => t.with_local_offset(off, false),
                    None => t,
                },
            )
        }
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_file(xml: &str) -> Vec<u8> {
        let mut d = vec![0xFF, 0xFE];
        d.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        d
    }

    const TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2018-03-29T16:23:12.0957426</Date>
    <Author>DESKTOP\jcloudy</Author>
    <URI>\Updater</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger><StartBoundary>2018-03-30T09:00:00</StartBoundary></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-21-1-1001</UserId><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Settings><Hidden>true</Hidden></Settings>
  <Actions Context="Author">
    <Exec><Command>C:\Users\jcloudy\AppData\Local\u.exe</Command><Arguments>-q</Arguments></Exec>
    <ComHandler><ClassId>{A6BA00FE-40E8-477C-B713-C7C60B1F8A80}</ClassId></ComHandler>
  </Actions>
</Task>"#;

    #[test]
    fn a_user_task_in_utf16() {
        let t = read(&utf16_file(TASK)).unwrap();
        assert_eq!(t.date.as_deref(), Some("2018-03-29T16:23:12.0957426"));
        let a = t.attrs;
        assert_eq!(a["uri"], "\\Updater");
        assert_eq!(a["user_id"], "S-1-5-21-1-1001");
        assert_eq!(
            (a["enabled"].as_bool(), a["hidden"].as_bool()),
            (Some(true), Some(true))
        );
        assert_eq!(a["triggers"][1]["type"], "TimeTrigger");
        assert_eq!(a["triggers"][1]["start"], "2018-03-30T09:00:00");
        assert_eq!(
            a["actions"][0]["exec"],
            "C:\\Users\\jcloudy\\AppData\\Local\\u.exe"
        );
        assert_eq!(a["actions"][0]["arguments"], "-q");
        assert_eq!(
            a["actions"][1]["com_handler"],
            "{A6BA00FE-40E8-477C-B713-C7C60B1F8A80}"
        );
    }

    #[test]
    fn not_task_xml_is_an_error() {
        assert!(read(b"MZ\x90\x00").is_err());
        assert!(read(&utf16_file("<Other/>")).is_err());
    }

    #[test]
    fn dates_with_and_without_a_zone() {
        // With an offset: exact, to the tick.
        let t = date("2018-03-29T16:23:12.0957426+02:00", None).unwrap();
        assert_eq!(t.display(), "2018-03-29 14:23:12.0957426 UTC");
        assert_eq!(
            date("2018-03-29T14:23:12Z", None).unwrap().display(),
            "2018-03-29 14:23:12.0000000 UTC"
        );
        // Without one and without the zone's rules: local, not UTC.
        assert!(
            !date("2018-03-29T16:23:12", None)
                .unwrap()
                .display()
                .ends_with("UTC")
        );
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert!(date("yesterday", None).is_none());
    }
}
