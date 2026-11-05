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

use crate::capability::Capabilities;
use crate::names::Kind;
use crate::plugin::{Manifest, Outcome, OutcomeLog, OutcomeRecord, Phase};
use crate::system::System;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// What a plugin gets while it runs on one system.
pub struct RunContext<'a> {
    pub system: &'a System,
    pub caps: Capabilities<'a>,
    /// The artifact kinds this system has (the artifact index, F21, fills this in).
    pub available: &'a BTreeSet<Kind>,
    /// Where the plugin puts what it produces.
    pub sink: &'a mut dyn Sink,
}

/// Receives what plugins produce. The project store (F16) is the real one.
pub trait Sink {
    fn emit(&mut self, plugin: &Kind, kind: &Kind, payload: String);
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
}

/// Runs `plugins` on `targets` through the three phases and records one outcome per plugin and
/// system in `log`.
pub fn run(
    plugins: &[&dyn Plugin],
    targets: &[Target<'_>],
    sink: &mut dyn Sink,
    log: &mut OutcomeLog,
) {
    // Outcomes so far, by (plugin index, target index).
    let mut results: BTreeMap<(usize, usize), Outcome> = BTreeMap::new();

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
                let mut ctx = RunContext {
                    system: t.system,
                    caps: t.caps,
                    available: &t.available,
                    sink,
                };
                let outcome = catch_unwind(AssertUnwindSafe(|| match phase {
                    Phase::Index => p.index(&mut ctx),
                    Phase::Extract => p.extract(&mut ctx),
                    Phase::Correlate => p.correlate(&mut ctx),
                }))
                .unwrap_or_else(|e| Outcome::Failed(panic_text(e.as_ref(), phase)));
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
        log.record(OutcomeRecord {
            plugin: m.id.clone(),
            version: m.version,
            system: targets[ti].system.id,
            outcome,
        });
    }
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
        }
    }

    #[test]
    fn a_test_plugin_runs_in_all_three_phases() {
        let p = TestPlugin::new("test.plugin", vec![], &[], &[]);
        let s = system(1, Family::Windows);
        let mut sink = Trace::default();
        let mut log = OutcomeLog::new();
        run(&[&p], &[target(&s, &[])], &mut sink, &mut log);
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
        run(&[&broken, &fine], &[target(&s, &[])], &mut sink, &mut log);
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
}
