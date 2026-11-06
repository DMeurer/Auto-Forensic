//! Plugin manifests and run outcomes (piece F14).
//!
//! A plugin declares what it is as data, before any code runs: which families it applies to,
//! which artifact kinds it reads (required or optional), which capabilities it needs, and which
//! kinds it produces. The runner (F15) uses the manifest to decide whether and on what to run.
//!
//! Every run of a plugin on a system ends in one stored [`Outcome`], so `af status` can tell
//! "not in this project" from "present, nothing relevant":
//!
//! | Outcome | Meaning |
//! |---|---|
//! | `ok(n)` | Ran, produced `n` items; `ok(0)` means present but nothing relevant |
//! | `not_acquired` | A required input isn't in the project (no SYSTEM hive was added) |
//! | `not_present` | The source was searched and the input isn't there |
//! | `unsupported_schema` | The input is there, in a version or layout the plugin can't read |
//! | `locked` | The input is there but encrypted or locked |
//! | `inert` | The input is there, and the feature was switched off on that system |
//! | `failed` | The plugin hit an error |

use crate::ids::SystemId;
use crate::names::Kind;
use crate::system::Family;

/// When in a run a plugin works (piece F15 runs them in this order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Phase {
    /// Finds artifacts and records where they are.
    Index,
    /// Reads artifacts into events and facts.
    Extract,
    /// Builds links and groups from what was extracted.
    Correlate,
}

/// An input a plugin reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The artifact kind, such as `windows.hive.system`.
    pub kind: Kind,
    pub required: bool,
}

/// What a plugin is, declared as data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The plugin's ID, such as `windows.registry.computer_name`.
    pub id: Kind,
    /// Raised whenever the plugin's output changes, so old results are rebuilt (F24).
    pub version: u32,
    /// Families it applies to; empty means every family.
    pub applies_to: Vec<Family>,
    pub phases: Vec<Phase>,
    pub inputs: Vec<Input>,
    /// Capabilities it needs, such as `capability.registry`.
    pub needs: Vec<Kind>,
    /// Kinds of events, facts, links or groups it produces.
    pub produces: Vec<Kind>,
}

impl Manifest {
    /// Whether the plugin applies to a system of this family.
    pub fn applies_to(&self, family: &Family) -> bool {
        self.applies_to.is_empty() || self.applies_to.contains(family)
    }

    pub fn required_inputs(&self) -> impl Iterator<Item = &Input> {
        self.inputs.iter().filter(|i| i.required)
    }
}

/// How one run of a plugin on one system ended.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Outcome {
    Ok(u64),
    NotAcquired,
    NotPresent,
    UnsupportedSchema(String),
    Locked,
    Inert,
    Failed(String),
}

impl Outcome {
    /// The stored name.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ok(_) => "ok",
            Self::NotAcquired => "not_acquired",
            Self::NotPresent => "not_present",
            Self::UnsupportedSchema(_) => "unsupported_schema",
            Self::Locked => "locked",
            Self::Inert => "inert",
            Self::Failed(_) => "failed",
        }
    }

    /// What the outcome means, in words for `af status`.
    pub fn meaning(&self) -> String {
        match self {
            Self::Ok(0) => "present, nothing relevant".into(),
            Self::Ok(n) => format!("read, {n} items"),
            Self::NotAcquired => "not in this project".into(),
            Self::NotPresent => "searched, not there".into(),
            Self::UnsupportedSchema(d) => format!("there, but a version it can't read ({d})"),
            Self::Locked => "there, but encrypted or locked".into(),
            Self::Inert => "there, but switched off on that system".into(),
            Self::Failed(d) => format!("failed: {d}"),
        }
    }

    /// Whether the input was there to be read (the plugin saw it, whatever came of it).
    pub fn input_was_there(&self) -> bool {
        matches!(
            self,
            Self::Ok(_) | Self::UnsupportedSchema(_) | Self::Locked | Self::Inert
        )
    }

    pub fn to_columns(&self) -> OutcomeColumns {
        let (count, detail) = match self {
            Self::Ok(n) => (Some(*n), None),
            Self::UnsupportedSchema(d) | Self::Failed(d) => (None, Some(d.clone())),
            _ => (None, None),
        };
        OutcomeColumns {
            outcome: self.kind().to_string(),
            count,
            detail,
        }
    }

    /// Back from the stored form; `None` for columns this code didn't write.
    pub fn from_columns(c: &OutcomeColumns) -> Option<Self> {
        Some(match (c.outcome.as_str(), c.count, &c.detail) {
            ("ok", Some(n), None) => Self::Ok(n),
            ("not_acquired", None, None) => Self::NotAcquired,
            ("not_present", None, None) => Self::NotPresent,
            ("unsupported_schema", None, Some(d)) => Self::UnsupportedSchema(d.clone()),
            ("locked", None, None) => Self::Locked,
            ("inert", None, None) => Self::Inert,
            ("failed", None, Some(d)) => Self::Failed(d.clone()),
            _ => return None,
        })
    }
}

/// The stored form of an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeColumns {
    pub outcome: String,
    pub count: Option<u64>,
    pub detail: Option<String>,
}

/// One stored outcome: which plugin, which version, on which system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeRecord {
    pub plugin: Kind,
    pub version: u32,
    pub system: SystemId,
    pub outcome: Outcome,
}

/// The outcomes of a project, queryable. The DuckDB table (F16) has the same shape.
#[derive(Debug, Clone, Default)]
pub struct OutcomeLog {
    records: Vec<OutcomeRecord>,
}

impl OutcomeLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an outcome, replacing an earlier one of the same plugin on the same system.
    pub fn record(&mut self, r: OutcomeRecord) {
        self.records
            .retain(|o| !(o.plugin == r.plugin && o.system == r.system));
        self.records.push(r);
    }

    pub fn all(&self) -> &[OutcomeRecord] {
        &self.records
    }

    /// The outcome of one plugin on one system.
    pub fn get(&self, plugin: &Kind, system: SystemId) -> Option<&OutcomeRecord> {
        self.records
            .iter()
            .find(|o| &o.plugin == plugin && o.system == system)
    }

    /// Every outcome of one kind, such as all `not_acquired` runs.
    pub fn with_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a OutcomeRecord> {
        self.records
            .iter()
            .filter(move |o| o.outcome.kind() == kind)
    }

    /// Every outcome on one system.
    pub fn for_system(&self, system: SystemId) -> impl Iterator<Item = &OutcomeRecord> {
        self.records.iter().filter(move |o| o.system == system)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> Kind {
        Kind::new(s).unwrap()
    }

    fn manifest() -> Manifest {
        Manifest {
            id: k("windows.registry.computer_name"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![
                Input {
                    kind: k("windows.hive.system"),
                    required: true,
                },
                Input {
                    kind: k("windows.hive.system_log"),
                    required: false,
                },
            ],
            needs: vec![k("capability.registry")],
            produces: vec![k("windows.computer_name")],
        }
    }

    #[test]
    fn manifest_is_data() {
        let m = manifest();
        assert!(m.applies_to(&Family::Windows));
        assert!(!m.applies_to(&Family::None));
        assert_eq!(m.required_inputs().count(), 1);
        let any = Manifest {
            applies_to: vec![],
            ..manifest()
        };
        assert!(any.applies_to(&Family::Linux));
    }

    #[test]
    fn every_outcome_round_trips_through_columns() {
        for o in [
            Outcome::Ok(0),
            Outcome::Ok(1234),
            Outcome::NotAcquired,
            Outcome::NotPresent,
            Outcome::UnsupportedSchema("regf 1.7".into()),
            Outcome::Locked,
            Outcome::Inert,
            Outcome::Failed("bad cell at 0x2040".into()),
        ] {
            assert_eq!(Outcome::from_columns(&o.to_columns()), Some(o));
        }
        let bad = OutcomeColumns {
            outcome: "ok".into(),
            count: None,
            detail: None,
        };
        assert_eq!(Outcome::from_columns(&bad), None);
    }

    #[test]
    fn outcomes_are_stored_and_queryable() {
        let (a, b) = (SystemId(1), SystemId(2));
        let mut log = OutcomeLog::new();
        let plugin = manifest().id;
        let prefetch = k("windows.prefetch");
        log.record(OutcomeRecord {
            plugin: plugin.clone(),
            version: 1,
            system: a,
            outcome: Outcome::Ok(1),
        });
        log.record(OutcomeRecord {
            plugin: plugin.clone(),
            version: 1,
            system: b,
            outcome: Outcome::NotAcquired,
        });
        log.record(OutcomeRecord {
            plugin: prefetch.clone(),
            version: 3,
            system: a,
            outcome: Outcome::Inert,
        });
        // "Not in this project" and "there, nothing relevant" are different questions.
        let missing: Vec<SystemId> = log.with_kind("not_acquired").map(|o| o.system).collect();
        assert_eq!(missing, [b]);
        assert!(log.get(&prefetch, a).unwrap().outcome.input_was_there());
        assert!(!log.get(&plugin, b).unwrap().outcome.input_was_there());
        assert_eq!(log.for_system(a).count(), 2);
        // A re-run replaces the old outcome.
        log.record(OutcomeRecord {
            plugin: plugin.clone(),
            version: 2,
            system: b,
            outcome: Outcome::Ok(0),
        });
        assert_eq!(log.all().len(), 3);
        assert_eq!(log.get(&plugin, b).unwrap().version, 2);
        assert_eq!(log.with_kind("not_acquired").count(), 0);
    }
}
