//! The plugin runner (piece F15).
//!
//! Plugins are compiled in and listed in a plain `const PLUGINS: &[&dyn Plugin]` in the binary;
//! there is no dynamic loading. A run goes through three phases, each over every system and
//! every plugin, so all indexing is done before any extraction, and all extraction before any
//! correlation:
//!
//! 1. **Index**: find artifacts and record where they are.
//! 2. **Extract**: read artifacts into events and facts.
//! 3. **Correlate**: build links and groups from what was extracted.
//!
//! Before a plugin runs on a system, the runner checks its manifest: it skips families the
//! plugin doesn't apply to, and records `not_acquired` when a required input kind or a needed
//! capability is missing. A plugin that panics is recorded as `failed` and the run goes on.
//! Each plugin's phases on one system end in one outcome: the first outcome that isn't `ok`
//! (later phases of that plugin are then skipped on that system), or `ok` with the counts added.
//!
//! **Run log (F24).** Extraction is the slow part, so the runner skips Extract when the
//! [`RunLog`] says this plugin version already extracted these inputs on this system: same
//! version and the same input fingerprint (SHA-256 over each input kind's artifact hashes). The
//! earlier outcome then stays. Index and Correlate always run, because links and groups are
//! rebuilt every run (F25). A failed extraction isn't logged, so it is tried again.

use crate::artifact::Artifact;
use crate::bytes::ByteSource;
use crate::capability::Capabilities;
use crate::ids::{Endpoint, EventId, FactId, SourceId, SystemId};
use crate::names::Kind;
use crate::plugin::{Manifest, Outcome, OutcomeLog, OutcomeRecord, Phase};
use crate::system::System;
use crate::time::Time;
use crate::timeline::{ClockDomainId, Sequence, TimeMeaning};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// What a plugin gets while it runs on one system.
pub struct RunContext<'a> {
    pub system: &'a System,
    pub caps: Capabilities<'a>,
    /// The artifact kinds this system has (the artifact index, F21, fills this in).
    pub available: &'a BTreeSet<Kind>,
    /// This system's artifacts.
    pub artifacts: &'a [Artifact],
    /// Opens an artifact's bytes, where the source can be read.
    pub opener: Option<&'a dyn Opener>,
    /// Where the plugin puts what it produces.
    pub sink: &'a mut dyn Sink,
}

/// Opens the bytes of an artifact.
pub trait Opener {
    fn open(&self, artifact: &Artifact) -> std::io::Result<Box<dyn ByteSource>>;
}

/// An event a plugin produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent {
    pub id: EventId,
    pub source: SourceId,
    /// The record the event belongs to (events of one record share it).
    pub record: u128,
    pub kind: Kind,
    pub meaning: TimeMeaning,
    pub time: Time,
    pub clock: ClockDomainId,
    pub seq: Option<Sequence>,
}

/// A fact a plugin produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFact {
    pub id: FactId,
    pub source: SourceId,
    pub kind: Kind,
    pub subject: String,
    /// Attributes as JSON text.
    pub attrs: Option<String>,
}

/// A link a plugin produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLink {
    pub id: u128,
    pub kind: Kind,
    pub from: Endpoint,
    pub to: Endpoint,
}

/// Receives what plugins produce. The project's spool (C0b) is the real one; `emit` is the
/// plain form tests use, and the typed methods fall back to it.
pub trait Sink {
    fn emit(&mut self, plugin: &Kind, kind: &Kind, payload: String);

    fn event(&mut self, plugin: &Kind, _system: SystemId, e: NewEvent) {
        let kind = e.kind.clone();
        self.emit(plugin, &kind, format!("{e:?}"));
    }
    fn fact(&mut self, plugin: &Kind, _system: SystemId, f: NewFact) {
        let kind = f.kind.clone();
        self.emit(plugin, &kind, format!("{f:?}"));
    }
    fn link(&mut self, plugin: &Kind, l: NewLink) {
        let kind = l.kind.clone();
        self.emit(plugin, &kind, format!("{l:?}"));
    }
}

/// A compiled-in plugin. Each phase method runs only if the manifest lists that phase.
pub trait Plugin: Sync {
    fn manifest(&self) -> &Manifest;

    fn index(&self, _ctx: &mut RunContext<'_>) -> Outcome {
        Outcome::Ok(0)
    }
    fn extract(&self, _ctx: &mut RunContext<'_>) -> Outcome {
        Outcome::Ok(0)
    }
    fn correlate(&self, _ctx: &mut RunContext<'_>) -> Outcome {
        Outcome::Ok(0)
    }
}

/// The capability kind for the registry.
pub const CAPABILITY_REGISTRY: &str = "capability.registry";

/// One system to run on, with what it offers.
pub struct Target<'a> {
    pub system: &'a System,
    pub caps: Capabilities<'a>,
    pub available: BTreeSet<Kind>,
    /// Per artifact kind, a hash of what this system has of it (such as the sorted artifact
    /// hashes joined). A kind not listed counts as absent.
    pub input_hashes: BTreeMap<Kind, String>,
    /// This system's artifacts.
    pub artifacts: Vec<Artifact>,
    pub opener: Option<&'a dyn Opener>,
}

impl<'a> Target<'a> {
    /// A target from a system's artifacts: kinds present and per-kind hashes come from them.
    pub fn new(
        system: &'a System,
        caps: Capabilities<'a>,
        artifacts: Vec<Artifact>,
        opener: Option<&'a dyn Opener>,
    ) -> Self {
        let mut hashes: BTreeMap<Kind, Vec<String>> = BTreeMap::new();
        for a in &artifacts {
            hashes
                .entry(a.kind.clone())
                .or_default()
                .push(a.sha256.clone());
        }
        let input_hashes: BTreeMap<Kind, String> = hashes
            .into_iter()
            .map(|(k, mut v)| {
                v.sort();
                (k, v.join(","))
            })
            .collect();
        Self {
            system,
            caps,
            available: input_hashes.keys().cloned().collect(),
            input_hashes,
            artifacts,
            opener,
        }
    }
}

/// Which plugin version last extracted which inputs on which system.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunLog {
    done: BTreeMap<(Kind, SystemId), (u32, String)>,
}

impl RunLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this version already extracted inputs with this fingerprint on this system.
    pub fn is_current(&self, plugin: &Kind, version: u32, system: SystemId, inputs: &str) -> bool {
        self.done
            .get(&(plugin.clone(), system))
            .is_some_and(|(v, i)| *v == version && i == inputs)
    }

    pub fn record(&mut self, plugin: Kind, version: u32, system: SystemId, inputs: String) {
        self.done.insert((plugin, system), (version, inputs));
    }

    /// Every entry: plugin, system, version and input fingerprint.
    pub fn entries(&self) -> impl Iterator<Item = (&Kind, SystemId, u32, &str)> {
        self.done
            .iter()
            .map(|((p, s), (v, i))| (p, *s, *v, i.as_str()))
    }
}

/// The fingerprint of a plugin's inputs on a target: SHA-256 over each declared input kind and
/// its hash, in manifest order, length-prefixed.
pub fn input_fingerprint(m: &Manifest, t: &Target<'_>) -> String {
    let mut h = Sha256::new();
    for input in &m.inputs {
        for part in [
            input.kind.as_str(),
            t.input_hashes.get(&input.kind).map_or("", String::as_str),
        ] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part.as_bytes());
        }
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Runs `plugins` on `targets` through the three phases and records one outcome per plugin and
/// system in `log`. `runs` says what was already extracted and is updated. Returns the plugins
/// that extracted, per system, so their earlier output can be replaced.
pub fn run(
    plugins: &[&dyn Plugin],
    targets: &[Target<'_>],
    sink: &mut dyn Sink,
    log: &mut OutcomeLog,
    runs: &mut RunLog,
) -> Vec<(Kind, SystemId)> {
    let mut extracted: Vec<(Kind, SystemId)> = Vec::new();
    // Outcomes so far, by (plugin index, target index).
    let mut results: BTreeMap<(usize, usize), Outcome> = BTreeMap::new();
    // Extractions skipped because the run log is current.
    let mut skipped: BTreeSet<(usize, usize)> = BTreeSet::new();

    for (ti, t) in targets.iter().enumerate() {
        for (pi, p) in plugins.iter().enumerate() {
            let m = p.manifest();
            if m.applies_to(&t.system.family)
                && let Some(o) = missing_requirement(m, t)
            {
                results.insert((pi, ti), o);
            }
        }
    }

    for phase in [Phase::Index, Phase::Extract, Phase::Correlate] {
        for (ti, t) in targets.iter().enumerate() {
            for (pi, p) in plugins.iter().enumerate() {
                let m = p.manifest();
                if !m.applies_to(&t.system.family) || !m.phases.contains(&phase) {
                    continue;
                }
                if results
                    .get(&(pi, ti))
                    .is_some_and(|o| !matches!(o, Outcome::Ok(_)))
                {
                    continue;
                }
                let fingerprint = input_fingerprint(m, t);
                if phase == Phase::Extract
                    && runs.is_current(&m.id, m.version, t.system.id, &fingerprint)
                {
                    skipped.insert((pi, ti));
                    continue;
                }
                let mut ctx = RunContext {
                    system: t.system,
                    caps: t.caps,
                    available: &t.available,
                    artifacts: &t.artifacts,
                    opener: t.opener,
                    sink,
                };
                let outcome = catch_unwind(AssertUnwindSafe(|| match phase {
                    Phase::Index => p.index(&mut ctx),
                    Phase::Extract => p.extract(&mut ctx),
                    Phase::Correlate => p.correlate(&mut ctx),
                }))
                .unwrap_or_else(|e| Outcome::Failed(panic_text(e.as_ref(), phase)));
                if phase == Phase::Extract && matches!(outcome, Outcome::Ok(_)) {
                    runs.record(m.id.clone(), m.version, t.system.id, fingerprint);
                }
                if phase == Phase::Extract {
                    extracted.push((m.id.clone(), t.system.id));
                }
                let merged = match (results.remove(&(pi, ti)), outcome) {
                    (Some(Outcome::Ok(a)), Outcome::Ok(b)) => Outcome::Ok(a + b),
                    (_, other) => other,
                };
                results.insert((pi, ti), merged);
            }
        }
    }

    for ((pi, ti), outcome) in results {
        let m = plugins[pi].manifest();
        let system = targets[ti].system.id;
        // A skipped extraction keeps the outcome of the run that did it.
        if skipped.contains(&(pi, ti))
            && matches!(outcome, Outcome::Ok(_))
            && log.get(&m.id, system).is_some()
        {
            continue;
        }
        log.record(OutcomeRecord {
            plugin: m.id.clone(),
            version: m.version,
            system,
            outcome,
        });
    }
    extracted
}

/// Everything a run produced, in a canonical order: what plugins emitted (plugin, kind,
/// payload) and each plugin's outcome per system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub emitted: Vec<(String, String, String)>,
    pub outcomes: Vec<(String, u128, String)>,
}

#[derive(Default)]
struct Collect(Vec<(String, String, String)>);

impl Sink for Collect {
    fn emit(&mut self, plugin: &Kind, kind: &Kind, payload: String) {
        self.0
            .push((plugin.as_str().into(), kind.as_str().into(), payload));
    }
}

/// Runs `plugins` on `targets` once, fresh, and returns the result in canonical order.
pub fn run_collect(plugins: &[&dyn Plugin], targets: &[Target<'_>]) -> RunResult {
    let mut sink = Collect::default();
    let mut log = OutcomeLog::new();
    run(plugins, targets, &mut sink, &mut log, &mut RunLog::new());
    let mut emitted = sink.0;
    emitted.sort();
    let mut outcomes: Vec<(String, u128, String)> = log
        .all()
        .iter()
        .map(|r| {
            (
                r.plugin.as_str().into(),
                r.system.0,
                format!("{:?}", r.outcome),
            )
        })
        .collect();
    outcomes.sort();
    RunResult { emitted, outcomes }
}

/// The order test (F29): runs `plugins` on `targets` in `orders` shuffled orders of plugins and
/// systems (from `seed`), and returns the first order whose result differs from the first run,
/// as the plugin IDs in that order. Groups, links and facts must not depend on run order.
pub fn check_order_independence(
    plugins: &[&dyn Plugin],
    targets: &[Target<'_>],
    orders: usize,
    seed: u64,
) -> Result<(), Vec<String>> {
    let reference = run_collect(plugins, targets);
    let mut rng = seed | 1;
    let mut next = move || {
        // xorshift64: deterministic and good enough to shuffle a few dozen items.
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut ps: Vec<&dyn Plugin> = plugins.to_vec();
    let mut ts: Vec<usize> = (0..targets.len()).collect();
    for _ in 0..orders {
        for i in (1..ps.len()).rev() {
            ps.swap(i, (next() % (i as u64 + 1)) as usize);
        }
        for i in (1..ts.len()).rev() {
            ts.swap(i, (next() % (i as u64 + 1)) as usize);
        }
        let shuffled: Vec<Target<'_>> = ts
            .iter()
            .map(|&i| Target {
                system: targets[i].system,
                caps: targets[i].caps,
                available: targets[i].available.clone(),
                input_hashes: targets[i].input_hashes.clone(),
                artifacts: targets[i].artifacts.clone(),
                opener: targets[i].opener,
            })
            .collect();
        if run_collect(&ps, &shuffled) != reference {
            return Err(ps
                .iter()
                .map(|p| p.manifest().id.as_str().to_string())
                .collect());
        }
    }
    Ok(())
}

/// `not_acquired` if a required input or a needed capability is missing.
fn missing_requirement(m: &Manifest, t: &Target<'_>) -> Option<Outcome> {
    let input_missing = m.required_inputs().any(|i| !t.available.contains(&i.kind));
    let cap_missing = m
        .needs
        .iter()
        .any(|c| c.as_str() == CAPABILITY_REGISTRY && t.caps.registry.is_none());
    (input_missing || cap_missing).then_some(Outcome::NotAcquired)
}

fn panic_text(e: &(dyn std::any::Any + Send), phase: Phase) -> String {
    let msg = e
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| e.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into());
    format!("panicked in {phase:?}: {msg}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::SystemId;
    use crate::plugin::Input;
    use crate::system::Family;
    use std::sync::Mutex;

    fn k(s: &str) -> Kind {
        Kind::new(s).unwrap()
    }

    fn system(id: u128, family: Family) -> System {
        System {
            id: SystemId(id),
            family,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        }
    }

    #[derive(Default)]
    struct Trace(Vec<String>);

    impl Sink for Trace {
        fn emit(&mut self, plugin: &Kind, kind: &Kind, payload: String) {
            self.0.push(format!("{plugin} {kind} {payload}"));
        }
    }

    /// Emits one item per phase and keeps a log of the calls.
    struct TestPlugin {
        manifest: Manifest,
        calls: Mutex<Vec<String>>,
        panic_in: Option<Phase>,
    }

    impl TestPlugin {
        fn new(id: &str, families: Vec<Family>, inputs: &[&str], needs: &[&str]) -> Self {
            Self {
                manifest: Manifest {
                    id: k(id),
                    version: 1,
                    applies_to: families,
                    phases: vec![Phase::Index, Phase::Extract, Phase::Correlate],
                    inputs: inputs
                        .iter()
                        .map(|i| Input {
                            kind: k(i),
                            required: true,
                        })
                        .collect(),
                    needs: needs.iter().map(|n| k(n)).collect(),
                    produces: vec![k("test.item")],
                },
                calls: Mutex::new(Vec::new()),
                panic_in: None,
            }
        }

        fn step(&self, phase: Phase, ctx: &mut RunContext<'_>) -> Outcome {
            if self.panic_in == Some(phase) {
                panic!("broken on purpose");
            }
            let id = self.manifest.id.clone();
            self.calls
                .lock()
                .unwrap()
                .push(format!("{phase:?} {}", ctx.system.id.0));
            ctx.sink.emit(&id, &k("test.item"), format!("{phase:?}"));
            Outcome::Ok(1)
        }
    }

    impl Plugin for TestPlugin {
        fn manifest(&self) -> &Manifest {
            &self.manifest
        }
        fn index(&self, ctx: &mut RunContext<'_>) -> Outcome {
            self.step(Phase::Index, ctx)
        }
        fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
            self.step(Phase::Extract, ctx)
        }
        fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
            self.step(Phase::Correlate, ctx)
        }
    }

    fn target<'a>(s: &'a System, available: &[&str]) -> Target<'a> {
        Target {
            system: s,
            caps: Capabilities::default(),
            available: available.iter().map(|a| k(a)).collect(),
            input_hashes: available
                .iter()
                .map(|a| (k(a), format!("hash of {a}")))
                .collect(),
            artifacts: vec![],
            opener: None,
        }
    }

    #[test]
    fn a_test_plugin_runs_in_all_three_phases() {
        let p = TestPlugin::new("test.plugin", vec![], &[], &[]);
        let s = system(1, Family::Windows);
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        run(
            &[&p],
            &[target(&s, &[])],
            &mut sink,
            &mut log,
            &mut RunLog::new(),
        );
        assert_eq!(
            *p.calls.lock().unwrap(),
            ["Index 1", "Extract 1", "Correlate 1"]
        );
        assert_eq!(sink.0.len(), 3);
        assert_eq!(
            log.get(&k("test.plugin"), SystemId(1)).unwrap().outcome,
            Outcome::Ok(3)
        );
    }

    #[test]
    fn every_index_runs_before_any_extract() {
        let a = TestPlugin::new("test.a", vec![], &[], &[]);
        let b = TestPlugin::new("test.b", vec![], &[], &[]);
        let (s1, s2) = (system(1, Family::Windows), system(2, Family::None));
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        run(
            &[&a, &b],
            &[target(&s1, &[]), target(&s2, &[])],
            &mut sink,
            &mut log,
            &mut RunLog::new(),
        );
        let phases: Vec<&str> = sink
            .0
            .iter()
            .map(|l| l.rsplit(' ').next().unwrap())
            .collect();
        let first_extract = phases.iter().position(|p| *p == "Extract").unwrap();
        let last_index = phases.iter().rposition(|p| *p == "Index").unwrap();
        assert!(last_index < first_extract, "{phases:?}");
        assert_eq!(phases.len(), 12);
    }

    #[test]
    fn manifest_decides_what_runs() {
        let win_only = TestPlugin::new("test.win", vec![Family::Windows], &[], &[]);
        let needs_hive = TestPlugin::new("test.hive", vec![], &["windows.hive.system"], &[]);
        let needs_reg = TestPlugin::new("test.reg", vec![], &[], &[CAPABILITY_REGISTRY]);
        let stick = system(9, Family::None);
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        run(
            &[&win_only, &needs_hive, &needs_reg],
            &[target(&stick, &[])],
            &mut sink,
            &mut log,
            &mut RunLog::new(),
        );
        // Not for this family: not run, nothing recorded.
        assert!(win_only.calls.lock().unwrap().is_empty());
        assert!(log.get(&k("test.win"), SystemId(9)).is_none());
        // Missing input or capability: recorded as not acquired, not run.
        for id in ["test.hive", "test.reg"] {
            assert_eq!(
                log.get(&k(id), SystemId(9)).unwrap().outcome,
                Outcome::NotAcquired
            );
        }
        assert!(needs_hive.calls.lock().unwrap().is_empty());
        assert!(sink.0.is_empty());
    }

    #[test]
    fn a_panic_is_recorded_and_the_run_goes_on() {
        let mut broken = TestPlugin::new("test.broken", vec![], &[], &[]);
        broken.panic_in = Some(Phase::Extract);
        let fine = TestPlugin::new("test.fine", vec![], &[], &[]);
        let s = system(1, Family::Windows);
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        // Silence the panic message in test output.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        run(
            &[&broken, &fine],
            &[target(&s, &[])],
            &mut sink,
            &mut log,
            &mut RunLog::new(),
        );
        std::panic::set_hook(hook);
        let o = &log.get(&k("test.broken"), SystemId(1)).unwrap().outcome;
        assert_eq!(
            o,
            &Outcome::Failed("panicked in Extract: broken on purpose".into())
        );
        // It stopped after the failed phase; the other plugin ran fully.
        assert_eq!(*broken.calls.lock().unwrap(), ["Index 1"]);
        assert_eq!(
            log.get(&k("test.fine"), SystemId(1)).unwrap().outcome,
            Outcome::Ok(3)
        );
    }

    fn extracts(p: &TestPlugin) -> usize {
        p.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.starts_with("Extract"))
            .count()
    }

    #[test]
    fn a_second_run_extracts_nothing() {
        let p = TestPlugin::new("test.hive", vec![], &["windows.hive.system"], &[]);
        let s = system(1, Family::Windows);
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        let mut runs = RunLog::new();
        let t = target(&s, &["windows.hive.system"]);
        run(
            &[&p],
            std::slice::from_ref(&t),
            &mut sink,
            &mut log,
            &mut runs,
        );
        assert_eq!(extracts(&p), 1);
        assert_eq!(
            log.get(&k("test.hive"), SystemId(1)).unwrap().outcome,
            Outcome::Ok(3)
        );
        run(&[&p], &[t], &mut sink, &mut log, &mut runs);
        assert_eq!(extracts(&p), 1, "nothing changed, nothing extracted");
        assert_eq!(
            log.get(&k("test.hive"), SystemId(1)).unwrap().outcome,
            Outcome::Ok(3),
            "the earlier outcome stays"
        );
        // Index and correlate ran both times.
        assert_eq!(p.calls.lock().unwrap().len(), 5);
    }

    #[test]
    fn a_new_version_or_new_input_extracts_again() {
        let mut p = TestPlugin::new("test.hive", vec![], &["windows.hive.system"], &[]);
        let s = system(1, Family::Windows);
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        let mut runs = RunLog::new();
        run(
            &[&p],
            &[target(&s, &["windows.hive.system"])],
            &mut sink,
            &mut log,
            &mut runs,
        );
        // Another hive arrived: its hash changes the fingerprint.
        let mut t = target(&s, &["windows.hive.system"]);
        t.input_hashes
            .insert(k("windows.hive.system"), "two hives now".into());
        run(&[&p], &[t], &mut sink, &mut log, &mut runs);
        assert_eq!(extracts(&p), 2);
        // A new plugin version extracts again.
        p.manifest.version = 2;
        run(
            &[&p],
            &[target(&s, &["windows.hive.system"])],
            &mut sink,
            &mut log,
            &mut runs,
        );
        assert_eq!(extracts(&p), 3);
        assert_eq!(runs.entries().count(), 1);
    }

    #[test]
    fn a_failed_extraction_is_tried_again() {
        let mut p = TestPlugin::new("test.flaky", vec![], &[], &[]);
        p.panic_in = Some(Phase::Extract);
        let s = system(1, Family::Windows);
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        let mut runs = RunLog::new();
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        run(&[&p], &[target(&s, &[])], &mut sink, &mut log, &mut runs);
        std::panic::set_hook(hook);
        assert_eq!(runs.entries().count(), 0, "failures aren't logged");
        p.panic_in = None;
        run(&[&p], &[target(&s, &[])], &mut sink, &mut log, &mut runs);
        assert_eq!(extracts(&p), 1);
        assert_eq!(
            log.get(&k("test.flaky"), SystemId(1)).unwrap().outcome,
            Outcome::Ok(3)
        );
    }

    /// Correlates from what it was given, so its output can't depend on other plugins.
    struct Pure(Manifest);

    impl Plugin for Pure {
        fn manifest(&self) -> &Manifest {
            &self.0
        }
        fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
            let payload = format!("group of system {}", ctx.system.id.0);
            ctx.sink.emit(&self.0.id, &k("test.group"), payload);
            Outcome::Ok(1)
        }
    }

    /// Reads and bumps shared state: the bug the order test exists to catch.
    struct Racy(Manifest, &'static std::sync::atomic::AtomicU64);

    impl Plugin for Racy {
        fn manifest(&self) -> &Manifest {
            &self.0
        }
        fn index(&self, _ctx: &mut RunContext<'_>) -> Outcome {
            // Reset each run, so only the order within a run changes the output.
            self.1.store(0, std::sync::atomic::Ordering::SeqCst);
            Outcome::Ok(0)
        }
        fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
            let seen = self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let payload = format!("{} saw {seen} before it", self.0.id);
            ctx.sink.emit(&self.0.id, &k("test.link"), payload);
            Outcome::Ok(1)
        }
    }

    fn manifest(id: &str) -> Manifest {
        Manifest {
            id: k(id),
            version: 1,
            applies_to: vec![],
            phases: vec![Phase::Index, Phase::Extract, Phase::Correlate],
            inputs: vec![],
            needs: vec![],
            produces: vec![],
        }
    }

    #[test]
    fn same_result_across_10_random_orders() {
        let plugins: Vec<Box<dyn Plugin>> = vec![
            Box::new(Pure(manifest("test.a"))),
            Box::new(Pure(manifest("test.b"))),
            Box::new(TestPlugin::new("test.c", vec![], &[], &[])),
            Box::new(Pure(manifest("test.d"))),
        ];
        let refs: Vec<&dyn Plugin> = plugins.iter().map(|p| p.as_ref()).collect();
        let systems = [
            system(1, Family::Windows),
            system(2, Family::None),
            system(3, Family::Linux),
        ];
        let targets: Vec<Target<'_>> = systems.iter().map(|s| target(s, &[])).collect();
        assert_eq!(check_order_independence(&refs, &targets, 10, 42), Ok(()));
    }

    #[test]
    fn an_order_dependent_plugin_is_caught() {
        static SHARED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let (a, b) = (
            Racy(manifest("test.racy_a"), &SHARED),
            Racy(manifest("test.racy_b"), &SHARED),
        );
        let s = system(1, Family::Windows);
        let targets = [target(&s, &[])];
        // Same order, same result: the counter resets each run.
        assert_eq!(
            run_collect(&[&a, &b], &targets),
            run_collect(&[&a, &b], &targets)
        );
        // A flipped order changes who saw what, and some shuffle flips it.
        assert!(check_order_independence(&[&a, &b], &targets, 10, 7).is_err());
    }
}
