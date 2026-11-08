//! Keys and values of a hive, with its transaction logs replayed (piece R1), on `notatin`
//! (Apache-2.0, the commit stage 1 tested in T7).
//!
//! Takes the hive and its logs as bytes; pairing a hive with its `.LOG1` and `.LOG2` files is the
//! caller's job, ignoring case (T7: `notatin`'s own CLI misses `system.log1`). Key paths have `\`
//! between names, start below the root key, and compare without case.

use notatin::log::LogCode;
use notatin::parser::Parser;
use notatin::parser_builder::ParserBuilder;
use std::io::Cursor;

/// FILETIME ticks (100 ns since 1601) of the Unix epoch.
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// A parsed hive.
pub struct Hive {
    parser: Parser,
    replay: Replay,
}

/// What became of the transaction logs (R3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replay {
    /// The hive was closed cleanly; logs aren't needed.
    Clean,
    /// The hive was dirty and its logs were replayed onto it.
    Replayed,
    /// The hive was dirty and no logs were given: read as it is, recent changes may be missing.
    NoLogs,
    /// The hive was dirty and the replay didn't (fully) work; read as far as it got.
    Failed(String),
}

/// The base block checksum: the XOR of its first 508 bytes as little-endian u32 (0 and
/// `u32::MAX` are stored as 1 and `u32::MAX - 1`).
pub fn header_checksum(hive: &[u8]) -> u32 {
    let x = hive
        .get(..0x1FC)
        .unwrap_or_default()
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0, |x, c| x ^ u32::from_le_bytes(*c));
    match x {
        0 => 1,
        u32::MAX => u32::MAX - 1,
        x => x,
    }
}

/// Whether the hive wasn't closed cleanly: its two sequence numbers differ, or the base block
/// checksum is wrong (both need the logs, as Windows would replay them).
pub fn is_dirty(hive: &[u8]) -> bool {
    let u32_at = |at: usize| {
        hive.get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
    };
    u32_at(4) != u32_at(8) || u32_at(0x1FC) != Some(header_checksum(hive))
}

/// One key: its subkeys' names and its values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub name: String,
    /// FILETIME ticks.
    pub last_written: i64,
    pub subkeys: Vec<String>,
    pub values: Vec<Value>,
}

/// One value as stored: the type number and the raw data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// Empty for the default value.
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

impl Hive {
    /// Parses a hive, replaying the given transaction logs (none, `.LOG1`, or both) onto it if
    /// it is dirty. A replay that fails falls back to the hive as it is; [`Hive::replay`] says
    /// which happened.
    pub fn open(hive: Vec<u8>, logs: Vec<Vec<u8>>) -> Result<Self, String> {
        let logs: Vec<Vec<u8>> = logs.into_iter().filter(|l| !l.is_empty()).collect();
        let parse = |logs: Vec<Vec<u8>>| {
            let mut b = ParserBuilder::from_file(Cursor::new(hive.clone()));
            for log in logs {
                b.with_transaction_log(Cursor::new(log));
            }
            b.build().map_err(|e| e.to_string())
        };
        if !is_dirty(&hive) || logs.is_empty() {
            let replay = if is_dirty(&hive) {
                Replay::NoLogs
            } else {
                Replay::Clean
            };
            return Ok(Self {
                parser: parse(vec![])?,
                replay,
            });
        }
        let parser = match parse(logs) {
            Ok(p) => p,
            Err(e) => {
                return Ok(Self {
                    parser: parse(vec![])?,
                    replay: Replay::Failed(e),
                });
            }
        };
        Ok(Self {
            replay: replay_result(&parser),
            parser,
        })
    }

    /// What became of the transaction logs.
    pub fn replay(&self) -> &Replay {
        &self.replay
    }

    /// The key at `path` (`\` between names, below the root; empty for the root).
    pub fn key(&mut self, path: &str) -> Option<Key> {
        let mut k = self.parser.get_key(path, false).ok()??;
        let subkeys = k
            .read_sub_keys(&mut self.parser)
            .into_iter()
            .map(|s| s.key_name)
            .collect();
        let values = k
            .value_iter()
            .map(|v| Value {
                name: v.detail.value_name(),
                value_type: v.data_type as u32,
                data: v.detail.value_bytes().unwrap_or_default(),
            })
            .collect();
        let t = k.last_key_written_date_and_time();
        Some(Key {
            name: k.key_name,
            last_written: t.timestamp() * 10_000_000
                + i64::from(t.timestamp_subsec_nanos() / 100)
                + UNIX_EPOCH_TICKS,
            subkeys,
            values,
        })
    }
}

/// Reads notatin's messages after a replay of a dirty hive. It leaves out a log whose entries
/// are older than the hive (normal) or don't follow the previous log's (lost entries), and when
/// it applied nothing it sets the sequence numbers to 0.
fn replay_result(parser: &Parser) -> Replay {
    let logs = parser.get_parse_logs().get().cloned().unwrap_or_default();
    let applied = logs.iter().find_map(|l| {
        let n = l
            .text
            .strip_prefix("Applied transaction log(s). Sequence numbers have been updated to ")?;
        n.split('.').next()?.parse::<u32>().ok()
    });
    let problems: Vec<String> = logs
        .iter()
        .filter(|l| {
            matches!(
                l.code,
                LogCode::WarningTransactionLog | LogCode::WarningParse
            )
        })
        .filter(|l| !l.text.contains("is less than the primary file's"))
        .map(|l| l.text.clone())
        .collect();
    match applied {
        Some(n) if n > 0 && problems.is_empty() => Replay::Replayed,
        Some(n) if n > 0 => Replay::Failed(problems.join("; ")),
        _ if problems.is_empty() => Replay::Failed("no log entry is newer than the hive".into()),
        _ => Replay::Failed(problems.join("; ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_keys_of_a_built_hive() {
        let mut h = Hive::open(crate::build_test_hive(&["Select", "Setup"], "lh"), vec![]).unwrap();
        let root = h.key("").unwrap();
        let mut subs = root.subkeys.clone();
        subs.sort();
        assert_eq!(subs, ["Select", "Setup"]);
        assert_eq!(h.key("select").unwrap().name, "Select", "without case");
        assert!(h.key("Nope").is_none());
        assert_eq!(h.replay(), &Replay::Clean);
    }

    #[test]
    fn a_dirty_hive_without_logs_says_so() {
        let mut data = crate::build_test_hive(&["Select"], "lh");
        data[4] = 7;
        let sum = header_checksum(&data);
        data[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
        assert!(is_dirty(&data));
        let mut h = Hive::open(data.clone(), vec![]).unwrap();
        assert_eq!(h.replay(), &Replay::NoLogs);
        assert_eq!(h.key("Select").unwrap().name, "Select", "still read");
        let h = Hive::open(data, vec![b"not a log".to_vec()]).unwrap();
        assert!(matches!(h.replay(), Replay::Failed(_)), "{:?}", h.replay());
    }
}
