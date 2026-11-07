//! Capabilities (piece F11): services a source may or may not offer, which plugins and profiles
//! ask for instead of reading files themselves.
//!
//! The first one is a registry: hierarchical keys with a last-written time and typed values.
//! Core names hives only by namespaced IDs such as `windows.system`; how those map to hive files
//! and to the names Windows shows is the Windows crate's business, so core never mentions a
//! Windows root key. Key names compare without case, as in every registry.
//!
//! [`FakeRegistry`] is an in-memory registry for tests and fixtures. The real one is Windows's
//! `HiveRegistry`, on `notatin` (R1), which a system's profile offers to plugins during a run.

use crate::names::Kind;
use crate::path::{CasePolicy, Name, NameKind, ViewPath};
use crate::time::Time;
use std::collections::BTreeMap;

/// A hive, by namespaced ID, such as `windows.system` or `windows.ntuser`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HiveId(pub Kind);

/// One key, read from a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegKey {
    pub path: ViewPath,
    pub last_written: Option<Time>,
    pub subkeys: Vec<Name>,
    pub values: Vec<RegValue>,
}

impl RegKey {
    /// A value by name, ignoring case. The default value has an empty name.
    pub fn value(&self, name: &str) -> Option<&RegValue> {
        let want = Name::from_text(name, NameKind::Utf16).key(CasePolicy::Insensitive);
        self.values
            .iter()
            .find(|v| v.name.key(CasePolicy::Insensitive) == want)
    }
}

/// One value: name, the type number as stored, and the raw data. Decoding is the reader's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue {
    pub name: Name,
    pub value_type: u32,
    pub data: Vec<u8>,
}

/// A registry a source offers.
pub trait Registry {
    /// The hives this registry has.
    fn hives(&self) -> Vec<HiveId>;
    /// A key by path within a hive, ignoring case. `None` if it doesn't exist.
    fn key(&self, hive: &HiveId, path: &ViewPath) -> Option<RegKey>;
}

/// The capabilities available to a profile or plugin for one system.
#[derive(Clone, Copy, Default)]
pub struct Capabilities<'a> {
    pub registry: Option<&'a dyn Registry>,
}

/// An in-memory registry for tests and fixtures.
#[derive(Debug, Clone, Default)]
pub struct FakeRegistry {
    keys: BTreeMap<(HiveId, String), RegKey>,
}

impl FakeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a value under a key (path with `\` between names), creating the key and its parents.
    pub fn set(
        &mut self,
        hive: &str,
        key: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
    ) -> &mut Self {
        let hive = HiveId(Kind::new(hive).expect("hive ID is a namespaced name"));
        let path = Self::path(key);
        self.ensure(&hive, &path);
        let k = self
            .keys
            .get_mut(&(hive, path.key(CasePolicy::Insensitive)))
            .expect("just created");
        k.values.retain(|v| {
            v.name.key(CasePolicy::Insensitive)
                != Name::from_text(name, NameKind::Utf16).key(CasePolicy::Insensitive)
        });
        k.values.push(RegValue {
            name: Name::from_text(name, NameKind::Utf16),
            value_type,
            data: data.to_vec(),
        });
        self
    }

    /// A key path from text with `\` between names.
    pub fn path(key: &str) -> ViewPath {
        ViewPath::new(
            key.split('\\')
                .filter(|n| !n.is_empty())
                .map(|n| Name::from_text(n, NameKind::Utf16))
                .collect(),
        )
    }

    fn ensure(&mut self, hive: &HiveId, path: &ViewPath) {
        let id = (hive.clone(), path.key(CasePolicy::Insensitive));
        if self.keys.contains_key(&id) {
            return;
        }
        self.keys.insert(
            id,
            RegKey {
                path: path.clone(),
                last_written: None,
                subkeys: Vec::new(),
                values: Vec::new(),
            },
        );
        if let (Some(parent), Some(last)) = (path.parent(), path.names().last()) {
            self.ensure(hive, &parent);
            let p = self
                .keys
                .get_mut(&(hive.clone(), parent.key(CasePolicy::Insensitive)))
                .expect("just created");
            p.subkeys.push(last.clone());
        }
    }
}

impl Registry for FakeRegistry {
    fn hives(&self) -> Vec<HiveId> {
        let mut h: Vec<HiveId> = self.keys.keys().map(|(h, _)| h.clone()).collect();
        h.dedup();
        h
    }

    fn key(&self, hive: &HiveId, path: &ViewPath) -> Option<RegKey> {
        self.keys
            .get(&(hive.clone(), path.key(CasePolicy::Insensitive)))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_registry_keys_values_and_case() {
        let mut r = FakeRegistry::new();
        r.set("test.hive", "Software\\Vendor\\App", "Version", 1, b"1.0")
            .set("test.hive", "software\\vendor\\APP", "version", 1, b"2.0");
        let hive = HiveId(Kind::new("test.hive").unwrap());
        assert_eq!(r.hives(), std::slice::from_ref(&hive));
        let k = r
            .key(&hive, &FakeRegistry::path("SOFTWARE\\Vendor\\app"))
            .unwrap();
        assert_eq!(
            k.values.len(),
            1,
            "same name in another case replaces the value"
        );
        assert_eq!(k.value("VERSION").unwrap().data, b"2.0");
        let root = r.key(&hive, &ViewPath::default()).unwrap();
        assert_eq!(root.subkeys, [Name::from_text("Software", NameKind::Utf16)]);
        assert!(
            r.key(&hive, &FakeRegistry::path("Software\\Other"))
                .is_none()
        );
        let other = HiveId(Kind::new("test.other").unwrap());
        assert!(r.key(&other, &ViewPath::default()).is_none());
    }
}
