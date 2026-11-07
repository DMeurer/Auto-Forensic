//! Keys and values of a hive, with its transaction logs replayed (piece R1), on `notatin`
//! (Apache-2.0, the commit stage 1 tested in T7).
//!
//! Takes the hive and its logs as bytes; pairing a hive with its `.LOG1` and `.LOG2` files is the
//! caller's job, ignoring case (T7: `notatin`'s own CLI misses `system.log1`). Key paths have `\`
//! between names, start below the root key, and compare without case.

use notatin::parser::Parser;
use notatin::parser_builder::ParserBuilder;
use std::io::Cursor;

/// FILETIME ticks (100 ns since 1601) of the Unix epoch.
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// A parsed hive.
pub struct Hive {
    parser: Parser,
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
    /// Parses a hive, replaying the given transaction logs (none, `.LOG1`, or both) onto it.
    pub fn open(hive: Vec<u8>, logs: Vec<Vec<u8>>) -> Result<Self, String> {
        let mut b = ParserBuilder::from_file(Cursor::new(hive));
        for log in logs.into_iter().filter(|l| !l.is_empty()) {
            b.with_transaction_log(Cursor::new(log));
        }
        Ok(Self {
            parser: b.build().map_err(|e| e.to_string())?,
        })
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
    }
}
