//! The artifact index (piece F21): plugins ask by kind, not by path.
//!
//! Index-phase plugins and loose-file detection (F22) register what they find: a kind such as
//! `windows.hive.system`, where it is (a locator), which source it came from, and its SHA-256.
//! Extract-phase plugins then ask [`ArtifactIndex::find`] for a kind and get zero, one or many
//! artifacts, the same way whether the hive sat at `Windows/System32/config/SYSTEM` inside an
//! image or was added as a loose file.
//!
//! The same bytes found twice (a hive added loose and also present in the image, or added twice)
//! are one [`Observation`], keyed by hash, so a plugin reads them once and every place they were
//! found stays known.

use crate::bytes::Locator;
use crate::ids::{SourceId, SystemId};
use crate::names::Kind;
use std::collections::{BTreeMap, BTreeSet};

/// One place an artifact was found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Artifact {
    pub kind: Kind,
    pub locator: Locator,
    pub source: SourceId,
    /// The system it belongs to, once known (a loose file may not have one yet).
    pub system: Option<SystemId>,
    /// SHA-256 of its bytes, lowercase hex.
    pub sha256: String,
}

/// The same bytes of one kind, wherever they were found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation<'a> {
    pub kind: &'a Kind,
    pub sha256: &'a str,
    /// Every place, in a stable order.
    pub found_at: Vec<&'a Artifact>,
}

/// All artifacts of a project, by kind.
#[derive(Debug, Clone, Default)]
pub struct ArtifactIndex {
    by_kind: BTreeMap<Kind, BTreeSet<Artifact>>,
}

impl ArtifactIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an artifact. Registering the same one again changes nothing.
    pub fn add(&mut self, a: Artifact) {
        self.by_kind.entry(a.kind.clone()).or_default().insert(a);
    }

    /// Every artifact of a kind, in a stable order. Empty if there is none.
    pub fn find(&self, kind: &Kind) -> Vec<&Artifact> {
        self.by_kind
            .get(kind)
            .map(|set| set.iter().collect())
            .unwrap_or_default()
    }

    /// The artifacts of a kind grouped by hash: what a plugin should read once each.
    pub fn observations(&self, kind: &Kind) -> Vec<Observation<'_>> {
        let mut by_hash: BTreeMap<&str, Vec<&Artifact>> = BTreeMap::new();
        for a in self.find(kind) {
            by_hash.entry(a.sha256.as_str()).or_default().push(a);
        }
        by_hash
            .into_iter()
            .map(|(sha256, found_at)| Observation {
                kind: &found_at[0].kind,
                sha256,
                found_at,
            })
            .collect()
    }

    /// The kinds present, which is what the runner checks required inputs against.
    pub fn kinds(&self) -> BTreeSet<Kind> {
        self.by_kind.keys().cloned().collect()
    }

    pub fn all(&self) -> impl Iterator<Item = &Artifact> {
        self.by_kind.values().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hive(source: u128, locator: Locator, sha: &str) -> Artifact {
        Artifact {
            kind: Kind::new("windows.hive.system").unwrap(),
            locator,
            source: SourceId(source),
            system: None,
            sha256: sha.into(),
        }
    }

    #[test]
    fn loose_hive_and_image_path_answer_alike() {
        let kind = Kind::new("windows.hive.system").unwrap();
        let mut idx = ArtifactIndex::new();
        assert!(idx.find(&kind).is_empty(), "zero is an answer too");
        let in_image = Locator::root("source.image", "exam.E01")
            .child("volume.partition", "2")
            .child("fs.path", "Windows/System32/config/SYSTEM");
        idx.add(hive(1, in_image.clone(), "aa"));
        idx.add(hive(2, Locator::root("source.loose", "SYSTEM"), "bb"));
        let found = idx.find(&kind);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|a| a.kind == kind));
        assert!(found.iter().any(|a| a.locator == in_image));
        assert_eq!(idx.kinds().into_iter().collect::<Vec<_>>(), [kind]);
    }

    #[test]
    fn the_same_hive_twice_is_one_observation() {
        let kind = Kind::new("windows.hive.system").unwrap();
        let mut idx = ArtifactIndex::new();
        idx.add(hive(1, Locator::root("source.loose", "SYSTEM"), "same"));
        idx.add(hive(
            2,
            Locator::root("source.loose", "SYSTEM (copy)"),
            "same",
        ));
        idx.add(hive(
            3,
            Locator::root("source.loose", "SYSTEM.old"),
            "other",
        ));
        // Registering an identical artifact again changes nothing.
        idx.add(hive(1, Locator::root("source.loose", "SYSTEM"), "same"));
        assert_eq!(idx.find(&kind).len(), 3);
        let obs = idx.observations(&kind);
        assert_eq!(obs.len(), 2);
        let same = obs.iter().find(|o| o.sha256 == "same").unwrap();
        assert_eq!(same.found_at.len(), 2);
        let sources: Vec<u128> = same.found_at.iter().map(|a| a.source.0).collect();
        assert_eq!(sources, [1, 2]);
    }
}
