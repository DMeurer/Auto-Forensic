//! Windows event logs (EVTX) from bytes (piece E1), on the `evtx` crate (T3: all 107,950
//! records of three images match EvtxECmd in record ID, time, event ID and channel).
//!
//! [`read`] gives every record with the system fields plugins sort and filter by, plus the whole
//! `Event` element as JSON for the event data. A damaged file isn't hidden: each chunk or record
//! that fails is an entry in [`Log::errors`], next to the records that did read.

use evtx::EvtxParser;
use serde_json::Value;
use std::io::Cursor;

/// FILETIME ticks (100 ns since 1601) of the Unix epoch.
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// One event log.
#[derive(Debug, Clone, PartialEq)]
pub struct Log {
    pub records: Vec<Record>,
    /// Chunks or records that failed to read, in the crate's words.
    pub errors: Vec<String>,
    /// The header's checksum doesn't match: the header may be damaged.
    pub bad_header: bool,
    /// Windows hadn't closed the log cleanly (normal for a log taken from a running system).
    pub dirty: bool,
}

/// One record.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub record_id: u64,
    /// `TimeCreated`, FILETIME ticks.
    pub written: i64,
    pub event_id: u32,
    pub provider: String,
    pub channel: String,
    pub computer: String,
    /// `Security/@UserID`, when the record has one.
    pub user_sid: Option<String>,
    /// The whole `Event` element: `System`, and `EventData` or `UserData`.
    pub event: Value,
    /// The record's offset in the file and its size (O3), when its header was found.
    pub span: Option<(u64, u64)>,
}

/// Reads every record of an event log. `Err` only if the data isn't an event log at all.
// shortcut: the whole log is in memory (Security logs reach a few hundred MB at most); read
// through `Read + Seek` if that's ever too much.
pub fn read(data: Vec<u8>) -> Result<Log, String> {
    let spans = record_spans(&data);
    let mut parser = EvtxParser::from_read_seek(Cursor::new(data)).map_err(|e| e.to_string())?;
    let header = parser.header();
    let bad_header = !header.validate_checksum();
    let dirty = header.flags.contains(evtx::HeaderFlags::DIRTY);
    let mut log = Log {
        records: vec![],
        errors: vec![],
        bad_header,
        dirty,
    };
    for r in parser.records_json_value() {
        match r {
            Ok(r) => {
                let event = r.data.get("Event").cloned().unwrap_or(Value::Null);
                let system = &event["System"];
                log.records.push(Record {
                    record_id: r.event_record_id,
                    written: i64::try_from(r.timestamp.as_nanosecond() / 100)
                        .unwrap_or(i64::MAX)
                        .saturating_add(UNIX_EPOCH_TICKS),
                    event_id: text(&system["EventID"])
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(0),
                    provider: text(&system["Provider"]["#attributes"]["Name"]).unwrap_or_default(),
                    channel: text(&system["Channel"]).unwrap_or_default(),
                    computer: text(&system["Computer"]).unwrap_or_default(),
                    user_sid: text(&system["Security"]["#attributes"]["UserID"]),
                    event,
                    span: spans.get(&r.event_record_id).copied(),
                });
            }
            Err(e) => log.errors.push(e.to_string()),
        }
    }
    Ok(log)
}

/// Each record's offset and size by its record ID (O3): the file header takes 4 KiB, then
/// come 64 KiB chunks, whose records start 512 bytes in, one after another, each with the
/// signature `**\0\0`, its size and its ID.
fn record_spans(data: &[u8]) -> std::collections::HashMap<u64, (u64, u64)> {
    const HEADER: usize = 4096;
    const CHUNK: usize = 65536;
    let mut out = std::collections::HashMap::new();
    let u32_at = |at: usize| {
        data.get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let mut chunk = HEADER;
    while chunk + CHUNK <= data.len() {
        if data[chunk..].starts_with(b"ElfChnk\0") {
            let mut at = chunk + 512;
            while at + 24 <= chunk + CHUNK && data[at..].starts_with(b"\x2a\x2a\0\0") {
                let Some(size) = u32_at(at + 4).map(|n| n as usize).filter(|&n| n >= 24) else {
                    break;
                };
                if at + size > chunk + CHUNK {
                    break;
                }
                let id = u64::from_le_bytes(data[at + 8..at + 16].try_into().unwrap());
                out.insert(id, (at as u64, size as u64));
                at += size;
            }
        }
        chunk += CHUNK;
    }
    out
}

/// A field's text: a string or number, or the `#text` of an element with attributes.
fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Object(o) => o.get("#text").and_then(text),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_an_event_log_is_an_error() {
        assert!(read(b"nope".to_vec()).is_err());
        assert!(read(vec![0; 70_000]).is_err());
    }

    #[test]
    fn fields_come_from_plain_or_attributed_elements() {
        let v: Value = serde_json::json!({"a": 4624, "b": {"#attributes": {"Qualifiers": 0}, "#text": 7045}, "c": "Security"});
        assert_eq!(text(&v["a"]).as_deref(), Some("4624"));
        assert_eq!(text(&v["b"]).as_deref(), Some("7045"));
        assert_eq!(text(&v["c"]).as_deref(), Some("Security"));
        assert_eq!(text(&v["d"]), None);
    }
}
