//! The Linux OS profile and Linux plugins (piece C1, the Linux canary).
//!
//! Added without changing core: a new crate, plus one line each in the `PROFILES` and
//! `PLUGINS` lists of `af`.
//!
//! - [`LinuxProfile`]: a volume with `etc/os-release` holds a Linux system. One view with `/`
//!   that keeps case. Identity from `etc/hostname` and `PRETTY_NAME` in `etc/os-release`.
//!   Artifacts: `etc/passwd`, `var/log/wtmp`, `var/log/btmp`.
//! - [`Wtmp`]: login records as events, in their file order as a sequence.
//! - [`Passwd`]: accounts as `unix.user` facts, keyed by user ID.

use af_core::ids::{EventId, FactId};
use af_core::names::Kind;
use af_core::path::{CasePolicy, PathStyle, ViewPath};
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::profile::{Identity, OsProfile, system_volumes};
use af_core::runner::{NewEvent, NewFact, Plugin, RunContext};
use af_core::system::{
    Detected, Detector, Family, MemVolume, Mount, System, View, ViewId, VolumeId, VolumeProbe,
};
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, Sequence, TimeMeaning};
use std::sync::OnceLock;

fn kind(k: &str) -> Kind {
    Kind::new(k).expect("valid kind")
}

/// The Linux profile.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxProfile;

impl Detector for LinuxProfile {
    fn detect(&self, volumes: &[&dyn VolumeProbe]) -> Vec<Detected> {
        let marker = MemVolume::path("etc/os-release");
        volumes
            .iter()
            .filter(|v| v.exists(&marker))
            .map(|v| Detected {
                family: Family::Linux,
                volumes: vec![v.id()],
                label: None,
                parent_volume: None,
                reason: "etc/os-release exists".into(),
            })
            .collect()
    }
}

impl OsProfile for LinuxProfile {
    fn family(&self) -> Family {
        Family::Linux
    }

    fn build_views(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
        new_id: &mut dyn FnMut() -> ViewId,
    ) -> Vec<View> {
        let mounts = system_volumes(system, volumes)
            .iter()
            .take(1)
            .map(|v| Mount {
                point: "/".into(),
                volume: v.id(),
            })
            .collect();
        vec![View {
            id: new_id(),
            system: system.id,
            style: PathStyle {
                separator: '/',
                case: CasePolicy::Exact,
            },
            mounts,
        }]
    }

    fn index(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
    ) -> Vec<(VolumeId, ViewPath, Kind)> {
        let Some(root) = system_volumes(system, volumes).into_iter().next() else {
            return Vec::new();
        };
        [
            ("etc/passwd", "linux.passwd"),
            ("var/log/wtmp", "linux.wtmp"),
            ("var/log/btmp", "linux.btmp"),
        ]
        .into_iter()
        .map(|(p, k)| (MemVolume::path(p), k))
        .filter(|(p, _)| root.exists(p))
        .map(|(p, k)| (root.id(), p, kind(k)))
        .collect()
    }

    fn identity(
        &self,
        system: &System,
        volumes: &[&dyn VolumeProbe],
        _caps: &af_core::capability::Capabilities<'_>,
    ) -> Identity {
        let Some(root) = system_volumes(system, volumes).into_iter().next() else {
            return Identity::default();
        };
        let mut facts = Vec::new();
        let hostname = root
            .read(&MemVolume::path("etc/hostname"))
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .filter(|h| !h.is_empty());
        if let Some(h) = &hostname {
            facts.push((kind("linux.hostname"), h.clone()));
        }
        if let Some(os) = root.read(&MemVolume::path("etc/os-release")) {
            let text = String::from_utf8_lossy(&os).into_owned();
            if let Some(name) = text
                .lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
            {
                facts.push((kind("linux.os_release"), name));
            }
        }
        Identity {
            note: hostname.is_none().then(|| "no etc/hostname".into()),
            label: hostname,
            facts,
        }
    }
}

/// Reads an artifact's bytes through the run's opener.
fn read_all(ctx: &RunContext<'_>, a: &af_core::artifact::Artifact) -> Result<Vec<u8>, Outcome> {
    let opener = ctx.opener.ok_or(Outcome::NotAcquired)?;
    opener
        .open(a)
        .and_then(|s| {
            let mut b = vec![0; s.len() as usize];
            s.read_exact_at(0, &mut b).map(|()| b)
        })
        .map_err(|e| Outcome::Failed(format!("{}: {e}", a.locator)))
}

/// Login records (wtmp, btmp) as events.
pub struct Wtmp;

impl Plugin for Wtmp {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: kind("linux.wtmp"),
            version: 1,
            applies_to: vec![Family::Linux],
            phases: vec![Phase::Extract],
            inputs: vec![
                Input {
                    kind: kind("linux.wtmp"),
                    required: true,
                },
                Input {
                    kind: kind("linux.btmp"),
                    required: false,
                },
            ],
            needs: vec![],
            produces: vec![
                kind("linux.wtmp.user_process"),
                kind("linux.btmp.login_process"),
            ],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let meaning = TimeMeaning::new("utmp.recorded").expect("valid meaning");
        let mut n = 0;
        let logs: Vec<_> = ctx
            .artifacts
            .iter()
            .filter(|a| matches!(a.kind.as_str(), "linux.wtmp" | "linux.btmp"))
            .cloned()
            .collect();
        for a in &logs {
            let data = match read_all(ctx, a) {
                Ok(d) => d,
                Err(o) => return o,
            };
            if data.is_empty() {
                continue;
            }
            let Some(size) = af_fmt_utmp::detect_size(&data) else {
                return Outcome::UnsupportedSchema(format!("{}: no utmp layout fits", a.locator));
            };
            for (i, r) in af_fmt_utmp::records(&data, size).iter().enumerate() {
                if r.kind == 0 {
                    continue;
                }
                let ev_kind = kind(&format!("{}.{}", a.kind, r.kind_name()));
                let time = r
                    .seconds
                    .checked_mul(1_000_000_000)
                    .and_then(|ns| ns.checked_add(r.microseconds.saturating_mul(1000)))
                    .map_or_else(|| Time::from_unix_seconds(r.seconds), Time::from_unix_nanos);
                let id = EventId::derive(
                    &a.source.to_string(),
                    &a.locator,
                    Some(r.offset),
                    &ev_kind,
                    &meaning,
                    0,
                );
                ctx.sink.event(
                    &self.manifest().id,
                    ctx.system.id,
                    NewEvent {
                        id,
                        source: a.source,
                        record: id.0,
                        kind: ev_kind,
                        meaning: meaning.clone(),
                        time,
                        clock: ClockDomainId("wall".into()),
                        seq: Some(Sequence {
                            domain: format!("{}#records", a.locator),
                            no: i as i64,
                        }),
                    },
                );
                n += 1;
            }
        }
        Outcome::Ok(n)
    }
}

/// Accounts from `etc/passwd` as `unix.user` facts, keyed by user ID.
pub struct Passwd;

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

impl Plugin for Passwd {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: kind("linux.passwd"),
            version: 1,
            applies_to: vec![Family::Linux],
            phases: vec![Phase::Extract],
            inputs: vec![Input {
                kind: kind("linux.passwd"),
                required: true,
            }],
            needs: vec![],
            produces: vec![kind("unix.user")],
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let fact_kind = kind("unix.user");
        let mut n = 0;
        let files: Vec<_> = ctx
            .artifacts
            .iter()
            .filter(|a| a.kind.as_str() == "linux.passwd")
            .cloned()
            .collect();
        for a in &files {
            let data = match read_all(ctx, a) {
                Ok(d) => d,
                Err(o) => return o,
            };
            for line in String::from_utf8_lossy(&data).lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() < 7 || f[2].parse::<u32>().is_err() {
                    continue;
                }
                let attrs = format!(
                    "{{\"name\": {}, \"home\": {}, \"shell\": {}}}",
                    json_str(f[0]),
                    json_str(f[5]),
                    json_str(f[6])
                );
                ctx.sink.fact(
                    &self.manifest().id,
                    ctx.system.id,
                    NewFact {
                        id: FactId::derive(&a.source.to_string(), &a.locator, &fact_kind, f[2]),
                        source: a.source,
                        kind: fact_kind.clone(),
                        subject: f[2].to_string(),
                        attrs: Some(attrs),
                    },
                );
                n += 1;
            }
        }
        Outcome::Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::capability::Capabilities;
    use af_core::ids::SystemId;
    use af_core::profile::{NoneProfile, build_systems};

    fn root() -> MemVolume {
        MemVolume::new(1, &["var/log/wtmp", "etc/passwd"])
            .with_case(CasePolicy::Exact)
            .with_file(
                "etc/os-release",
                b"NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 9 (stretch)\"\n",
            )
            .with_file("etc/hostname", b"logserver\n")
    }

    #[test]
    fn detects_identifies_and_indexes_a_linux_root() {
        let r = root();
        let (mut s, mut v) = (0, 0);
        let profiles: [&dyn OsProfile; 2] = [&LinuxProfile, &NoneProfile];
        let (systems, ids) = build_systems(
            &[&r],
            &profiles,
            &Capabilities::default(),
            || {
                s += 1;
                SystemId(s)
            },
            || {
                v += 1;
                ViewId(v)
            },
        );
        assert_eq!(systems.len(), 1);
        assert_eq!(systems[0].family, Family::Linux);
        assert_eq!(systems[0].label.as_deref(), Some("logserver"));
        assert_eq!(systems[0].views[0].style.case, CasePolicy::Exact);
        assert!(
            ids[0]
                .facts
                .iter()
                .any(|(k, v)| k.as_str() == "linux.os_release" && v.contains("stretch"))
        );
        let kinds: Vec<String> = LinuxProfile
            .index(&systems[0], &[&r])
            .into_iter()
            .map(|(_, _, k)| k.as_str().to_string())
            .collect();
        assert_eq!(kinds, ["linux.passwd", "linux.wtmp"]);
    }

    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }
}
