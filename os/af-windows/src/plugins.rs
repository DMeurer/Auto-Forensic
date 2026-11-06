//! Windows plugins.
//!
//! [`HiveRootKeys`] (piece C0c) is the first: every hive's root keys as facts, and the root
//! key's last-written time as an event. It stands in for the registry plugins in the canaries
//! until those exist, using only the root-key reader.

use af_core::ids::{Endpoint, EventId, FactId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewLink};
use af_core::runner::{NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

/// The hive kinds it reads; all optional, so it runs on whatever hives a system has.
const HIVES: &[&str] = &[
    "windows.hive.system",
    "windows.hive.software",
    "windows.hive.ntuser",
    "windows.hive.usrclass",
    "windows.hive.security",
    "windows.hive.sam",
    "windows.hive.amcache",
    "windows.hive.unknown",
];

/// Every hive's root keys as facts of kind `windows.hive.root_key`.
pub struct HiveRootKeys;

impl Plugin for HiveRootKeys {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.hive.root_keys").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract, Phase::Correlate],
            inputs: HIVES
                .iter()
                .map(|k| Input {
                    kind: Kind::new(k).expect("valid kind"),
                    required: false,
                })
                .collect(),
            needs: vec![],
            produces: vec![
                Kind::new("windows.hive.root_key").expect("valid kind"),
                Kind::new("windows.hive.root_written").expect("valid kind"),
                Kind::new("windows.hive.root_key_of").expect("valid kind"),
            ],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let fact_kind = Kind::new("windows.hive.root_key").expect("valid kind");
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| HIVES.contains(&a.kind.as_str()))
        {
            let src = match opener.open(a) {
                Ok(s) => s,
                Err(e) => return Outcome::Failed(format!("{}: {e}", a.locator)),
            };
            let mut data = vec![0; src.len() as usize];
            if let Err(e) = src.read_exact_at(0, &mut data) {
                return Outcome::Failed(format!("{}: {e}", a.locator));
            }
            if let Ok(ticks) = af_fmt_regf::root_last_written(&data) {
                let kind = Kind::new("windows.hive.root_written").expect("valid kind");
                let meaning = TimeMeaning::new("registry.key.last_written").expect("valid meaning");
                ctx.sink.event(
                    &self.manifest().id,
                    ctx.system.id,
                    NewEvent {
                        id: EventId::derive(
                            &a.source.to_string(),
                            &a.locator,
                            None,
                            &kind,
                            &meaning,
                            0,
                        ),
                        source: a.source,
                        record: FactId::derive(&a.source.to_string(), &a.locator, &kind, "root").0,
                        kind,
                        meaning,
                        time: Time::from_ticks_1601(ticks),
                        clock: ClockDomainId("wall".into()),
                        seq: None,
                    },
                );
                n += 1;
            }
            let names = match af_fmt_regf::root_subkey_names(&data) {
                Ok(n) => n,
                Err(e) => return Outcome::UnsupportedSchema(format!("{}: {e}", a.locator)),
            };
            for name in names {
                let subject = format!("{}:{name}", a.kind);
                ctx.sink.fact(
                    &self.manifest().id,
                    ctx.system.id,
                    NewFact {
                        id: FactId::derive(&a.source.to_string(), &a.locator, &fact_kind, &subject),
                        source: a.source,
                        kind: fact_kind.clone(),
                        subject,
                        attrs: None,
                    },
                );
                n += 1;
            }
        }
        Outcome::Ok(n)
    }

    /// Links each root-key fact to its hive's last-written event. Links are made here, not in
    /// Extract: derived links are rebuilt every run (F25), while Extract is skipped for
    /// unchanged inputs (F24).
    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::Ok(0);
        };
        let fact_kind = Kind::new("windows.hive.root_key").expect("valid kind");
        let ev_kind = Kind::new("windows.hive.root_written").expect("valid kind");
        let meaning = TimeMeaning::new("registry.key.last_written").expect("valid meaning");
        let link_kind = Kind::new("windows.hive.root_key_of").expect("valid kind");
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| HIVES.contains(&a.kind.as_str()))
        {
            let Ok(src) = opener.open(a) else { continue };
            let mut data = vec![0; src.len() as usize];
            if src.read_exact_at(0, &mut data).is_err()
                || af_fmt_regf::root_last_written(&data).is_err()
            {
                continue;
            }
            let Ok(names) = af_fmt_regf::root_subkey_names(&data) else {
                continue;
            };
            let source = a.source.to_string();
            let event = EventId::derive(&source, &a.locator, None, &ev_kind, &meaning, 0);
            for name in names {
                let subject = format!("{}:{name}", a.kind);
                let fact = FactId::derive(&source, &a.locator, &fact_kind, &subject);
                ctx.sink.link(
                    &self.manifest().id,
                    NewLink {
                        id: FactId::derive(&source, &a.locator, &link_kind, &subject).0,
                        kind: link_kind.clone(),
                        from: Endpoint::Fact(fact),
                        to: Endpoint::Event(event),
                    },
                );
                n += 1;
            }
        }
        Outcome::Ok(n)
    }
}

/// One `windows.user_profile` fact per user profile folder that holds an NTUSER.DAT: the
/// Windows user key until SIDs come with the registry plugins. The subject is the folder name.
pub struct UserProfiles;

impl Plugin for UserProfiles {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.user_profiles").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: Kind::new("windows.hive.ntuser").expect("valid kind"),
                required: true,
            }],
            needs: vec![],
            produces: vec![Kind::new("windows.user_profile").expect("valid kind")],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let fact_kind = Kind::new("windows.user_profile").expect("valid kind");
        let mut n = 0;
        for a in ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "windows.hive.ntuser")
        {
            // A profile hive sits at Users/<name>/NTUSER.DAT; a loose NTUSER.DAT has no folder.
            let Some(step) = a.locator.steps().last() else {
                continue;
            };
            let parts: Vec<&str> = step.id.split('/').collect();
            let [.., users, name, _] = parts.as_slice() else {
                continue;
            };
            if !users.eq_ignore_ascii_case("users") {
                continue;
            }
            ctx.sink.fact(
                &self.manifest().id,
                ctx.system.id,
                NewFact {
                    id: FactId::derive(&a.source.to_string(), &a.locator, &fact_kind, name),
                    source: a.source,
                    kind: fact_kind.clone(),
                    subject: name.to_string(),
                    attrs: None,
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::artifact::Artifact;
    use af_core::bytes::{ByteSource, Locator, MemSource};
    use af_core::capability::Capabilities;
    use af_core::ids::{SourceId, SystemId};
    use af_core::runner::{Opener, Sink, Target, run};
    use af_core::system::System;
    use af_fmt_regf::build_test_hive;

    struct Hives(Vec<(Artifact, Vec<u8>)>);

    impl Opener for Hives {
        fn open(&self, a: &Artifact) -> std::io::Result<Box<dyn ByteSource>> {
            let (_, data) = self.0.iter().find(|(x, _)| x == a).expect("known artifact");
            Ok(Box::new(MemSource::new(data.clone(), a.locator.clone())))
        }
    }

    #[derive(Default)]
    struct Facts(Vec<String>);

    impl Sink for Facts {
        fn emit(&mut self, _: &Kind, _: &Kind, payload: String) {
            self.0.push(payload);
        }
        fn fact(&mut self, _: &Kind, _: SystemId, f: NewFact) {
            self.0.push(f.subject);
        }
        fn event(&mut self, _: &Kind, _: SystemId, e: af_core::runner::NewEvent) {
            self.0.push(format!("event {}", e.kind));
        }
        fn link(&mut self, _: &Kind, l: af_core::runner::NewLink) {
            self.0.push(format!("link {}", l.kind));
        }
    }

    #[test]
    fn root_keys_become_facts() {
        let hive = |kind: &str, src: u128, roots: &[&str]| {
            (
                Artifact {
                    kind: Kind::new(kind).unwrap(),
                    locator: Locator::root("source.loose", &src.to_string()),
                    source: SourceId(src),
                    system: Some(SystemId(1)),
                    sha256: format!("{src}"),
                },
                build_test_hive(roots, "lh"),
            )
        };
        let opener = Hives(vec![
            hive("windows.hive.system", 1, &["MountedDevices", "Select"]),
            hive("windows.hive.ntuser", 2, &["Control Panel", "Software"]),
        ]);
        let sys = System {
            id: SystemId(1),
            family: Family::Windows,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let artifacts = opener.0.iter().map(|(a, _)| a.clone()).collect();
        let targets = [Target::new(
            &sys,
            Capabilities::default(),
            artifacts,
            Some(&opener),
        )];
        let mut sink = Facts::default();
        let mut log = af_core::plugin::OutcomeLog::new();
        run(
            &[&HiveRootKeys],
            &targets,
            &mut sink,
            &mut log,
            &mut af_core::runner::RunLog::new(),
        );
        sink.0.sort();
        assert_eq!(
            sink.0,
            [
                "event windows.hive.root_written",
                "event windows.hive.root_written",
                "link windows.hive.root_key_of",
                "link windows.hive.root_key_of",
                "link windows.hive.root_key_of",
                "link windows.hive.root_key_of",
                "windows.hive.ntuser:Control Panel",
                "windows.hive.ntuser:Software",
                "windows.hive.system:MountedDevices",
                "windows.hive.system:Select",
            ]
        );
        assert_eq!(log.all()[0].outcome, Outcome::Ok(10));
    }
}
