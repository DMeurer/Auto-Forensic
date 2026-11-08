//! Keys and values of a hive, with its transaction logs replayed (piece R1), on `notatin`
//! (Apache-2.0, the commit stage 1 tested in T7).
//!
//! Takes the hive and its logs as bytes; pairing a hive with its `.LOG1` and `.LOG2` files is the
//! caller's job, ignoring case (T7: `notatin`'s own CLI misses `system.log1`). Key paths have `\`
//! between names, start below the root key, and compare without case.

use notatin::cell_key_node::CellKeyNode;
use notatin::log::LogCode;
use notatin::parser::Parser;
use notatin::parser_builder::ParserBuilder;
use std::collections::HashMap;
use std::io::Cursor;

/// A parsed hive.
pub struct Hive {
    parser: Parser,
    replay: Replay,
    /// Each key's subkeys once read, by the key's path in lower case (R5): notatin's own path
    /// lookup reads every sibling at each level again, which made a walk of a large SOFTWARE
    /// hive take 10 minutes.
    children: HashMap<String, Vec<CellKeyNode>>,
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
    /// FILETIME ticks, as stored.
    pub last_written: u64,
    pub subkeys: Vec<String>,
    pub values: Vec<Value>,
}

/// One value as stored: the type number and the raw data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// Empty for the default value.
    pub name: String,
    /// The type number as stored, device property types such as `0xFFFF0011` included.
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
                children: HashMap::new(),
            });
        }
        let parser = match parse(logs) {
            Ok(p) => p,
            Err(e) => {
                return Ok(Self {
                    parser: parse(vec![])?,
                    replay: Replay::Failed(e),
                    children: HashMap::new(),
                });
            }
        };
        Ok(Self {
            replay: replay_result(&parser),
            parser,
            children: HashMap::new(),
        })
    }

    /// What became of the transaction logs.
    pub fn replay(&self) -> &Replay {
        &self.replay
    }

    /// The key at `path` (`\` between names, below the root; empty for the root).
    pub fn key(&mut self, path: &str) -> Option<Key> {
        let (k, at) = self.node(path)?;
        let subkeys = self
            .children(&at, &k)
            .iter()
            .map(|s| s.key_name.clone())
            .collect();
        Some(to_key(&k, subkeys))
    }

    /// Every key, depth first from the root in subkey list order, with its path (`\` between
    /// names, empty for the root). Reads each key once and keeps nothing, unlike [`Hive::key`]'s
    /// cache. A key cell met again (a crafted hive whose subkey lists loop or repeat) is skipped.
    pub fn walk(&mut self, mut visit: impl FnMut(&str, &Key)) {
        let Some(root) = self.parser.get_root_key().ok().flatten() else {
            return;
        };
        let mut seen = std::collections::HashSet::new();
        let mut todo = vec![(String::new(), root)];
        while let Some((path, mut node)) = todo.pop() {
            if !seen.insert(node.file_offset_absolute) {
                continue;
            }
            let kids = node.read_sub_keys(&mut self.parser);
            visit(
                &path,
                &to_key(&node, kids.iter().map(|k| k.key_name.clone()).collect()),
            );
            for kid in kids.into_iter().rev() {
                let p = if path.is_empty() {
                    kid.key_name.clone()
                } else {
                    format!("{path}\\{}", kid.key_name)
                };
                todo.push((p, kid));
            }
        }
    }
}

fn to_key(k: &CellKeyNode, subkeys: Vec<String>) -> Key {
    let values = k
        .value_iter()
        .map(|v| Value {
            name: v.detail.value_name(),
            value_type: v.detail.data_type_raw(),
            data: v.detail.value_bytes().unwrap_or_default(),
        })
        .collect();
    Key {
        name: k.key_name.clone(),
        // The raw FILETIME: notatin's date conversion overflows for 0 and far-off times.
        last_written: k.detail.last_key_written_date_and_time(),
        subkeys,
        values,
    }
}

impl Hive {
    /// The key at `path` from the root, one level at a time through [`Hive::children`], with its
    /// path in lower case. Only the matching child is followed, so a subkey list that names one
    /// key many times costs one read of the list.
    fn node(&mut self, path: &str) -> Option<(CellKeyNode, String)> {
        let mut cur = self.parser.get_root_key().ok()??;
        let mut at = String::new();
        for name in path.split('\\').filter(|n| !n.is_empty()) {
            let want = name.to_lowercase();
            let next = self
                .children(&at, &cur)
                .iter()
                .find(|k| k.key_name.to_lowercase() == want)?
                .clone();
            if !at.is_empty() {
                at.push('\\');
            }
            at.push_str(&want);
            cur = next;
        }
        Some((cur, at))
    }

    /// The subkeys of `node`, whose lower-case path is `at`, read once.
    fn children(&mut self, at: &str, node: &CellKeyNode) -> &[CellKeyNode] {
        if !self.children.contains_key(at) {
            let kids = node.clone().read_sub_keys(&mut self.parser);
            self.children.insert(at.to_string(), kids);
        }
        &self.children[at]
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
    fn walk_visits_every_key_once_in_order() {
        let mut h = Hive::open(crate::build_test_hive(&["B", "A"], "lf"), vec![]).unwrap();
        let mut seen = vec![];
        h.walk(|p, k| seen.push((p.to_string(), k.subkeys.len())));
        assert_eq!(seen, [(String::new(), 2), ("B".into(), 0), ("A".into(), 0)]);
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
