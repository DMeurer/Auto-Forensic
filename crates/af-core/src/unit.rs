//! Multi-file units and named streams (piece F13).
//!
//! Some artifacts are more than one file: a registry hive with its transaction logs, an SQLite
//! database with its write-ahead log. A [`Unit`] opens them together, so a plugin gets the main
//! file and its companions, each with a role. Which files belong together is a
//! [`CompanionRule`] from the plugin that knows the format: the main file's name plus a suffix,
//! compared by the rule's case policy (`SYSTEM.LOG1` and `system.log1` both match on NTFS).
//!
//! A file can also have several streams: the default data and named ones, such as an NTFS
//! alternate data stream (`Zone.Identifier`), an extended attribute or a resource fork.
//! [`Streams`] keeps them together under their names.

use crate::bytes::ByteSource;
use crate::names::Kind;
use crate::path::{CasePolicy, Name, NameKind};
use std::sync::Arc;

/// A file's name and bytes, as a directory listing gives them.
#[derive(Clone)]
pub struct FileEntry {
    pub name: Name,
    pub source: Arc<dyn ByteSource>,
}

/// How to find the companions of a main file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionRule {
    /// The kind of unit, such as `registry.hive` or `sqlite.database`.
    pub unit: Kind,
    /// Each companion's role and the suffix added to the main file's name.
    pub companions: Vec<(Kind, String)>,
    pub case: CasePolicy,
}

impl CompanionRule {
    pub fn new(unit: &str, companions: &[(&str, &str)], case: CasePolicy) -> Self {
        Self {
            unit: Kind::new(unit).expect("unit kind is a namespaced name"),
            companions: companions
                .iter()
                .map(|(role, suffix)| {
                    (
                        Kind::new(role).expect("role is a namespaced name"),
                        suffix.to_string(),
                    )
                })
                .collect(),
            case,
        }
    }
}

/// A main file and its companions, opened as one.
#[derive(Clone)]
pub struct Unit {
    pub kind: Kind,
    pub main: FileEntry,
    /// Companions found, in the rule's order, each with its role.
    pub companions: Vec<(Kind, FileEntry)>,
    /// Roles the rule names that weren't found, so a plugin can report "no log files".
    pub missing: Vec<Kind>,
}

impl Unit {
    /// The companion with this role, if found.
    pub fn companion(&self, role: &str) -> Option<&FileEntry> {
        self.companions
            .iter()
            .find(|(r, _)| r.as_str() == role)
            .map(|(_, f)| f)
    }
}

/// Opens `main` with its companions from `siblings` (the files in the same folder). A sibling
/// matches a role if its name equals the main name plus the suffix, by the rule's case policy.
/// If two siblings match one role (possible on a case-sensitive file system), the first in
/// listing order is used.
pub fn open_unit(main: &FileEntry, siblings: &[FileEntry], rule: &CompanionRule) -> Unit {
    let main_text = main.name.display();
    let mut companions = Vec::new();
    let mut missing = Vec::new();
    for (role, suffix) in &rule.companions {
        let want =
            Name::from_text(&format!("{main_text}{suffix}"), main.name.kind()).key(rule.case);
        match siblings
            .iter()
            .find(|s| s.name.key(rule.case) == want && !same(s, main))
        {
            Some(s) => companions.push((role.clone(), s.clone())),
            None => missing.push(role.clone()),
        }
    }
    Unit {
        kind: rule.unit.clone(),
        main: main.clone(),
        companions,
        missing,
    }
}

fn same(a: &FileEntry, b: &FileEntry) -> bool {
    Arc::ptr_eq(&a.source, &b.source)
}

/// The name of a stream within a file: the default data, or a named stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StreamName {
    Default,
    Named(Name),
}

/// All streams of one file.
#[derive(Clone, Default)]
pub struct Streams {
    streams: Vec<(StreamName, Arc<dyn ByteSource>)>,
}

impl Streams {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a stream, replacing one with the same name.
    pub fn insert(&mut self, name: StreamName, source: Arc<dyn ByteSource>) {
        self.streams.retain(|(n, _)| n != &name);
        self.streams.push((name, source));
    }

    pub fn default_stream(&self) -> Option<&Arc<dyn ByteSource>> {
        self.get(&StreamName::Default)
    }

    pub fn get(&self, name: &StreamName) -> Option<&Arc<dyn ByteSource>> {
        self.streams.iter().find(|(n, _)| n == name).map(|(_, s)| s)
    }

    /// A named stream by text, by `case` (NTFS stream names ignore case).
    pub fn named(&self, text: &str, case: CasePolicy) -> Option<&Arc<dyn ByteSource>> {
        let want = Name::from_text(text, NameKind::Utf16).key(case);
        self.streams.iter().find_map(|(n, s)| match n {
            StreamName::Named(name) if name.key(case) == want => Some(s),
            _ => None,
        })
    }

    /// Names of the named streams, in insertion order.
    pub fn names(&self) -> Vec<&Name> {
        self.streams
            .iter()
            .filter_map(|(n, _)| match n {
                StreamName::Named(name) => Some(name),
                StreamName::Default => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{Locator, MemSource};

    fn entry(name: &str, data: &[u8]) -> FileEntry {
        FileEntry {
            name: Name::from_text(name, NameKind::Utf16),
            source: Arc::new(MemSource::new(
                data.to_vec(),
                Locator::root("source.folder", name),
            )),
        }
    }

    fn hive_rule() -> CompanionRule {
        CompanionRule::new(
            "registry.hive",
            &[("registry.log1", ".LOG1"), ("registry.log2", ".LOG2")],
            CasePolicy::Insensitive,
        )
    }

    fn read(f: &FileEntry) -> Vec<u8> {
        let mut b = vec![0; f.source.len() as usize];
        f.source.read_exact_at(0, &mut b).unwrap();
        b
    }

    #[test]
    fn a_hive_plus_two_logs_opens_as_one_unit() {
        let system = entry("SYSTEM", b"regf main");
        let folder = [
            system.clone(),
            entry("SOFTWARE", b"regf other"),
            entry("SYSTEM.LOG1", b"log one"),
            entry("system.log2", b"log two"),
            entry("SOFTWARE.LOG1", b"other log"),
        ];
        let unit = open_unit(&system, &folder, &hive_rule());
        assert_eq!(unit.kind.as_str(), "registry.hive");
        assert_eq!(read(&unit.main), b"regf main");
        assert_eq!(unit.companions.len(), 2);
        assert_eq!(read(unit.companion("registry.log1").unwrap()), b"log one");
        assert_eq!(read(unit.companion("registry.log2").unwrap()), b"log two");
        assert!(unit.missing.is_empty());
    }

    #[test]
    fn missing_logs_are_reported() {
        let ntuser = entry("NTUSER.DAT", b"regf");
        let folder = [ntuser.clone(), entry("ntuser.dat.LOG1", b"log")];
        let unit = open_unit(&ntuser, &folder, &hive_rule());
        assert_eq!(unit.companions.len(), 1);
        assert_eq!(
            unit.missing.iter().map(Kind::as_str).collect::<Vec<_>>(),
            ["registry.log2"]
        );
    }

    #[test]
    fn exact_rules_ignore_other_cases() {
        let rule = CompanionRule::new(
            "sqlite.database",
            &[("sqlite.wal", "-wal"), ("sqlite.shm", "-shm")],
            CasePolicy::Exact,
        );
        let db = entry("History", b"SQLite format 3");
        let folder = [
            db.clone(),
            entry("History-WAL", b"no"),
            entry("History-wal", b"yes"),
        ];
        let unit = open_unit(&db, &folder, &rule);
        assert_eq!(read(unit.companion("sqlite.wal").unwrap()), b"yes");
        assert_eq!(unit.missing.len(), 1);
    }

    #[test]
    fn named_streams() {
        let mut s = Streams::new();
        s.insert(StreamName::Default, entry("setup.exe", b"MZ").source);
        s.insert(
            StreamName::Named(Name::from_text("Zone.Identifier", NameKind::Utf16)),
            entry("zone", b"[ZoneTransfer]\r\nZoneId=3").source,
        );
        assert_eq!(s.default_stream().unwrap().len(), 2);
        let zone = s.named("zone.identifier", CasePolicy::Insensitive).unwrap();
        assert_eq!(zone.len(), 24);
        assert!(s.named("zone.identifier", CasePolicy::Exact).is_none());
        assert_eq!(s.names().len(), 1);
        // Replacing a stream keeps one entry.
        s.insert(StreamName::Default, entry("setup.exe", b"MZ90").source);
        assert_eq!(s.default_stream().unwrap().len(), 4);
    }
}
