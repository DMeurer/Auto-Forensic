//! Windows plugins.
//!
//! [`HiveRootKeys`] (piece C0c) is the first: every hive's root keys as facts, and the root
//! key's last-written time as an event. It stands in for the registry plugins in the canaries
//! until those exist, using only the root-key reader.

use af_core::artifact::Artifact;
use af_core::ids::{Endpoint, EventId, FactId, GroupId};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewGroup};
use af_core::runner::{NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

/// The hive kinds it reads; all optional, so it runs on whatever hives a system has.
pub(crate) const HIVES: &[&str] = &[
    "windows.hive.system",
    "windows.hive.software",
    "windows.hive.ntuser",
    "windows.hive.usrclass",
    "windows.hive.security",
    "windows.hive.sam",
    "windows.hive.amcache",
    "windows.hive.default",
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
                Kind::new("windows.hive.root").expect("valid kind"),
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

    /// Groups each hive's root-written event with its root-key facts (L6: a link per root key
    /// made 379 links to one UsrClass event). Made here, not in Extract: derived groups are
    /// rebuilt every run (F25), while Extract is skipped for unchanged inputs (F24).
    fn correlate(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::Ok(0);
        };
        let fact_kind = Kind::new("windows.hive.root_key").expect("valid kind");
        let ev_kind = Kind::new("windows.hive.root_written").expect("valid kind");
        let meaning = TimeMeaning::new("registry.key.last_written").expect("valid meaning");
        let group_kind = Kind::new("windows.hive.root").expect("valid kind");
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
            let facts = names.iter().map(|name| {
                let subject = format!("{}:{name}", a.kind);
                (
                    Endpoint::Fact(FactId::derive(&source, &a.locator, &fact_kind, &subject)),
                    format!("root key {name}"),
                )
            });
            ctx.sink.group(
                &self.manifest().id,
                NewGroup {
                    id: GroupId(FactId::derive(&source, &a.locator, &group_kind, "root").0),
                    kind: group_kind.clone(),
                    reason: format!(
                        "{} root key{} of {}, its root last written then",
                        names.len(),
                        if names.len() == 1 { "" } else { "s" },
                        a.kind
                    ),
                    members: std::iter::once((
                        Endpoint::Event(event),
                        "the root key's last write".to_string(),
                    ))
                    .chain(facts)
                    .collect(),
                },
            );
            n += 1;
        }
        Outcome::Ok(n)
    }
}

/// One `windows.user_profile` fact per user profile (I24), with the profile's hives. With the
/// registry, the profiles are SOFTWARE's ProfileList (subject: the SID), each with the
/// NTUSER.DAT and UsrClass.dat found in its folder. A folder with a hive but no ProfileList entry
/// is listed too, as `"in_profile_list": false` with the folder name as subject, except the
/// `Default` and `Public` templates ProfileList names. Without a registry every folder with a hive
/// is a profile. A loose user hive (no folder) is a profile of its own, named by the owner the
/// registry gave it (`unknown user 1`, R12).
pub struct UserProfiles;

pub(crate) const PROFILE_LIST: &str = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
const USRCLASS: &str = "/AppData/Local/Microsoft/Windows/UsrClass.dat";

/// The profile folder a user hive sits in, from its path below the volume. A loose hive has none.
pub(crate) fn home_of(a: &Artifact) -> Option<String> {
    let p = &a.locator.steps().last()?.id;
    match a.kind.as_str() {
        "windows.hive.ntuser" => p.rsplit_once('/').map(|(home, _)| home.to_string()),
        "windows.hive.usrclass" => {
            let cut = p.len().checked_sub(USRCLASS.len())?;
            (p.is_char_boundary(cut) && p[cut..].eq_ignore_ascii_case(USRCLASS))
                .then(|| p[..cut].to_string())
        }
        _ => None,
    }
}

/// A ProfileImagePath (`C:\Users\x`, `%SystemDrive%\Users\x`, `%systemroot%\...`) as a path
/// below the system volume, `/` between names.
pub(crate) fn volume_path(p: &str) -> Option<String> {
    let p = p.replace('\\', "/");
    let lower = p.to_ascii_lowercase();
    if lower.starts_with("%systemdrive%/") {
        return Some(p["%systemdrive%/".len()..].to_string());
    }
    if lower.starts_with("%systemroot%/") {
        return Some(format!("Windows/{}", &p["%systemroot%/".len()..]));
    }
    let b = p.as_bytes();
    (b.len() > 3 && b[0].is_ascii_alphabetic() && &b[1..3] == b":/").then(|| p[3..].to_string())
}

/// Whether a hive's folder is this profile folder; a KAPE drive folder (`C/`) may come first.
pub(crate) fn same_home(hive_home: &str, home: &str) -> bool {
    let (h, p) = (hive_home.to_ascii_lowercase(), home.to_ascii_lowercase());
    !p.is_empty() && (h == p || h.ends_with(&format!("/{p}")))
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Profile<'a> {
    subject: String,
    sid: Option<String>,
    home: String,
    listed: bool,
    /// A loose hive, the profile's only one.
    loose: Option<&'a Artifact>,
}

impl Plugin for UserProfiles {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.user_profiles").expect("valid kind"),
            version: 3,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: [
                "windows.hive.software",
                "windows.hive.ntuser",
                "windows.hive.usrclass",
            ]
            .into_iter()
            .map(|k| Input {
                kind: Kind::new(k).expect("valid kind"),
                // A system without a profile hive has no profiles to list.
                required: k == "windows.hive.ntuser",
            })
            .collect(),
            needs: vec![],
            produces: vec![Kind::new("windows.user_profile").expect("valid kind")],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let fact_kind = Kind::new("windows.user_profile").expect("valid kind");
        let hives: Vec<(String, &Artifact)> = ctx
            .artifacts
            .iter()
            .filter_map(|a| Some((home_of(a)?, a)))
            .collect();
        let software = ctx
            .artifacts
            .iter()
            .find(|a| a.kind.as_str() == "windows.hive.software");
        let hive_id =
            af_core::capability::HiveId::machine(Kind::new("windows.software").expect("valid"));
        let mut profiles: Vec<Profile> = Vec::new();
        let mut templates: Vec<String> = Vec::new();
        if let (Some(reg), Some(_)) = (ctx.caps.registry, software)
            && let Some(list) = reg.key(&hive_id, &crate::registry::path(PROFILE_LIST))
        {
            for t in ["Default", "Public"] {
                templates.extend(crate::registry::reg_sz(&list, t).and_then(|p| volume_path(&p)));
            }
            for sid in &list.subkeys {
                let home = reg
                    .key(&hive_id, &list.path.join(sid.clone()))
                    .and_then(|k| crate::registry::reg_sz(&k, "ProfileImagePath"))
                    .and_then(|p| volume_path(&p))
                    .unwrap_or_default();
                profiles.push(Profile {
                    subject: sid.display(),
                    sid: Some(sid.display()),
                    home,
                    listed: true,
                    loose: None,
                });
            }
        }
        for (home, _) in &hives {
            let known = profiles.iter().any(|p| same_home(home, &p.home))
                || templates.iter().any(|t| same_home(home, t));
            if !known {
                profiles.push(Profile {
                    subject: home.rsplit('/').next().unwrap_or(home).to_string(),
                    sid: None,
                    home: home.clone(),
                    listed: false,
                    loose: None,
                });
            }
        }
        if let Some(reg) = ctx.caps.registry {
            let owners: Vec<(
                Option<String>,
                (af_core::ids::SourceId, af_core::bytes::Locator),
            )> = reg
                .hives()
                .into_iter()
                .filter_map(|h| Some((h.owner.clone(), reg.origin(&h)?)))
                .collect();
            for a in ctx.artifacts.iter().filter(|a| home_of(a).is_none()) {
                let owner = owners
                    .iter()
                    .find(|(_, (s, l))| *s == a.source && *l == a.locator)
                    .and_then(|(o, _)| o.clone());
                if let Some(owner) = owner {
                    profiles.push(Profile {
                        subject: owner,
                        sid: None,
                        home: String::new(),
                        listed: false,
                        loose: Some(a),
                    });
                }
            }
        }
        let mut n = 0;
        for p in &profiles {
            let mine: Vec<&Artifact> = match p.loose {
                Some(a) => vec![a],
                None => hives
                    .iter()
                    .filter(|(h, _)| same_home(h, &p.home))
                    .map(|(_, a)| *a)
                    .collect(),
            };
            // The fact comes from ProfileList's hive, or else from the folder's first hive.
            let Some(from) = (if p.listed {
                software
            } else {
                mine.first().copied()
            }) else {
                continue;
            };
            let hive_list: Vec<String> = mine
                .iter()
                .map(|a| {
                    format!(
                        r#"{{"kind": {}, "path": {}}}"#,
                        json_str(a.kind.as_str()),
                        json_str(a.locator.steps().last().map_or("", |s| s.id.as_str()))
                    )
                })
                .collect();
            let attrs = format!(
                r#"{{"sid": {}, "name": {}, "home": {}, "in_profile_list": {}, "hives": [{}]}}"#,
                p.sid.as_deref().map_or("null".into(), json_str),
                p.home
                    .rsplit('/')
                    .next()
                    .filter(|n| !n.is_empty())
                    .map_or("null".into(), json_str),
                Some(p.home.as_str())
                    .filter(|h| !h.is_empty())
                    .map_or("null".into(), json_str),
                p.listed,
                hive_list.join(", ")
            );
            ctx.sink.fact(
                &self.manifest().id,
                ctx.system.id,
                NewFact {
                    id: FactId::derive(
                        &from.source.to_string(),
                        &from.locator,
                        &fact_kind,
                        &p.subject,
                    ),
                    source: from.source,
                    kind: fact_kind.clone(),
                    subject: p.subject.clone(),
                    attrs: Some(attrs),
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
        fn group(&mut self, _: &Kind, g: NewGroup) {
            self.0
                .push(format!("group {} of {}", g.reason, g.members.len()));
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
                "group 2 root keys of windows.hive.ntuser, its root last written then of 3",
                "group 2 root keys of windows.hive.system, its root last written then of 3",
                "windows.hive.ntuser:Control Panel",
                "windows.hive.ntuser:Software",
                "windows.hive.system:MountedDevices",
                "windows.hive.system:Select",
            ]
        );
        assert_eq!(log.all()[0].outcome, Outcome::Ok(8));
    }

    #[derive(Default)]
    struct Profiles(Vec<(String, String)>);

    impl Sink for Profiles {
        fn emit(&mut self, _: &Kind, _: &Kind, _: String) {}
        fn fact(&mut self, _: &Kind, _: SystemId, f: NewFact) {
            self.0.push((f.subject, f.attrs.unwrap_or_default()));
        }
        fn event(&mut self, _: &Kind, _: SystemId, _: af_core::runner::NewEvent) {}
        fn link(&mut self, _: &Kind, _: af_core::runner::NewLink) {}
    }

    #[test]
    fn profiles_come_from_profile_list_with_their_hives() {
        use crate::registry::tests::utf16z;
        use crate::registry::{REG_EXPAND_SZ, REG_SZ};
        let list = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
        let mut reg = af_core::capability::FakeRegistry::new();
        reg.set(
            "windows.software",
            list,
            "Default",
            REG_EXPAND_SZ,
            &utf16z("%SystemDrive%\\Users\\Default"),
        )
        .set(
            "windows.software",
            list,
            "Public",
            REG_EXPAND_SZ,
            &utf16z("%SystemDrive%\\Users\\Public"),
        )
        .set(
            "windows.software",
            &format!("{list}\\S-1-5-21-1-2-3-1001"),
            "ProfileImagePath",
            REG_EXPAND_SZ,
            &utf16z("C:\\Users\\jcloudy"),
        )
        .set(
            "windows.software",
            &format!("{list}\\S-1-5-19"),
            "ProfileImagePath",
            REG_SZ,
            &utf16z("%systemroot%\\ServiceProfiles\\LocalService"),
        );
        let art = |kind: &str, path: &str| Artifact {
            kind: Kind::new(kind).unwrap(),
            locator: Locator::root("source.image", "1")
                .child("volume.gpt", "4")
                .child("fs.path", path),
            source: SourceId(1),
            system: Some(SystemId(1)),
            sha256: path.into(),
        };
        let artifacts = vec![
            art("windows.hive.software", "Windows/System32/config/SOFTWARE"),
            art("windows.hive.ntuser", "Users/jcloudy/NTUSER.DAT"),
            art(
                "windows.hive.usrclass",
                "Users/jcloudy/AppData/Local/Microsoft/Windows/UsrClass.dat",
            ),
            art("windows.hive.ntuser", "Users/Default/NTUSER.DAT"),
            art("windows.hive.ntuser", "Users/old/NTUSER.DAT"),
            art(
                "windows.hive.ntuser",
                "Windows/ServiceProfiles/LocalService/NTUSER.DAT",
            ),
        ];
        let sys = System {
            id: SystemId(1),
            family: Family::Windows,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let caps = Capabilities {
            registry: Some(&reg),
        };
        let targets = [Target::new(&sys, caps, artifacts, None)];
        let mut sink = Profiles::default();
        run(
            &[&UserProfiles],
            &targets,
            &mut sink,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        sink.0.sort();
        let got: Vec<&str> = sink.0.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(
            got,
            ["S-1-5-19", "S-1-5-21-1-2-3-1001", "old"],
            "Default is the template"
        );
        assert_eq!(
            sink.0[1].1,
            r#"{"sid": "S-1-5-21-1-2-3-1001", "name": "jcloudy", "home": "Users/jcloudy", "in_profile_list": true, "hives": [{"kind": "windows.hive.ntuser", "path": "Users/jcloudy/NTUSER.DAT"}, {"kind": "windows.hive.usrclass", "path": "Users/jcloudy/AppData/Local/Microsoft/Windows/UsrClass.dat"}]}"#
        );
        assert!(
            sink.0[0]
                .1
                .contains(r#""home": "Windows/ServiceProfiles/LocalService""#)
        );
        assert!(
            sink.0[2].1.contains(r#""sid": null"#)
                && sink.0[2].1.contains(r#""in_profile_list": false"#)
        );
    }
}
