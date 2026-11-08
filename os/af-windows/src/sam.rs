//! Local accounts from the SAM hive (piece R14), as RECmd's UserAccounts plugin reads them: one
//! `windows.account` fact per user key under `SAM\Domains\Account\Users`, and its creation, last
//! login, last wrong password and password change as events.
//!
//! The `F` value holds the times and counters, `V` the names; an account was created when its
//! `Users\Names\<name>` key was last written. Deleted keys are not read: on the exam image,
//! RID 1000 (`000003E8`) exists only in free cells, which RECmd recovers and then trips over.

use crate::host::event;
use crate::registry::{REG_BINARY, path};
use crate::registry_timeline::key_locator;
use af_core::capability::{HiveId, RegKey};
use af_core::ids::FactId;
use af_core::names::Kind;
use af_core::path::Name;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{CAPABILITY_REGISTRY, NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use std::collections::HashMap;
use std::sync::OnceLock;

const USERS: &str = "SAM\\Domains\\Account\\Users";
/// `F` offsets: FILETIMEs, then the ACB flags and counters.
const LAST_LOGIN: usize = 0x08;
const PASSWORD_SET: usize = 0x18;
const LAST_FAILED: usize = 0x28;
const ACB: usize = 0x38;
const FAILED_COUNT: usize = 0x40;
const LOGIN_COUNT: usize = 0x42;
/// ACB flag: the account is disabled.
const ACB_DISABLED: u16 = 0x0001;

/// Each local account as a fact, with its times as events.
pub struct Sam;

impl Plugin for Sam {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("windows.sam").expect("valid kind"),
            version: 1,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: ["windows.hive.sam", "windows.hive.log"]
                .into_iter()
                .map(|k| Input {
                    kind: Kind::new(k).expect("valid kind"),
                    required: false,
                })
                .collect(),
            needs: vec![Kind::new(CAPABILITY_REGISTRY).expect("valid kind")],
            produces: [
                "windows.account",
                "windows.account.created",
                "windows.account.last_login",
                "windows.account.last_failed_login",
                "windows.account.password_set",
            ]
            .into_iter()
            .map(|k| Kind::new(k).expect("valid kind"))
            .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(reg) = ctx.caps.registry else {
            return Outcome::NotAcquired;
        };
        let sam = HiveId::machine(Kind::new("windows.sam").expect("valid kind"));
        let (Some((source, hive)), Some(users)) = (reg.origin(&sam), reg.key(&sam, &path(USERS)))
        else {
            return Outcome::Ok(0);
        };
        let id = self.manifest().id.clone();
        let domain = reg
            .key(&sam, &path("SAM\\Domains\\Account"))
            .and_then(|k| domain_sid(&k.value("V")?.data));
        // Users\Names\<name>: the default value's type is the RID.
        let mut names: HashMap<u32, RegKey> = HashMap::new();
        if let Some(list) = reg.key(&sam, &path(&format!("{USERS}\\Names"))) {
            for n in list.subkeys.iter().map(Name::display) {
                if let Some(k) = reg.key(&sam, &path(&format!("{USERS}\\Names\\{n}")))
                    && let Some(v) = k.value("")
                {
                    names.insert(v.value_type, k);
                }
            }
        }
        let mut n = 0;
        for key in list_rids(&users.subkeys) {
            let Some(k) = reg.key(&sam, &path(&format!("{USERS}\\{key}"))) else {
                continue;
            };
            let Some(f) = k
                .value("F")
                .filter(|v| v.value_type == REG_BINARY && v.data.len() >= 0x44)
                .map(|v| v.data.clone())
            else {
                continue;
            };
            let rid = u32::from_str_radix(&key, 16).expect("hex key name");
            let v = k.value("V").map(|v| v.data.clone()).unwrap_or_default();
            let name_key = names.get(&rid);
            let name = v_text(&v, 0x0C)
                .or_else(|| name_key.map(|k| k.path.names().last().expect("a name").display()));
            if name_key.is_none() {
                ctx.sink.note(
                    &id,
                    ctx.system.id,
                    format!("user key {key} (RID {rid}) has no name under Users\\Names"),
                );
            }
            let locator = key_locator(&hive, &k);
            let u16_at = |o: usize| u16::from_le_bytes([f[o], f[o + 1]]);
            let attrs = serde_json::json!({
                "rid": rid,
                "sid": domain.as_ref().map(|d| format!("{d}-{rid}")),
                "name": name,
                "full_name": v_text(&v, 0x18),
                "comment": v_text(&v, 0x24),
                "login_count": u16_at(LOGIN_COUNT),
                "failed_count": u16_at(FAILED_COUNT),
                "disabled": u16_at(ACB) & ACB_DISABLED != 0,
                "password_hint": k.value("UserPasswordHint").and_then(|h| utf16(&h.data)),
                "reset_data": k.value("ResetData").and_then(|h| utf16(&h.data)),
            });
            let kind = Kind::new("windows.account").expect("valid kind");
            ctx.sink.fact(
                &id,
                ctx.system.id,
                NewFact {
                    id: FactId::derive(&source.to_string(), &locator, &kind, &key),
                    source,
                    kind,
                    subject: name.unwrap_or_else(|| format!("RID {rid}")),
                    attrs: Some(attrs.to_string()),
                },
            );
            n += 1;
            for (at, kind) in [
                (LAST_LOGIN, "windows.account.last_login"),
                (LAST_FAILED, "windows.account.last_failed_login"),
                (PASSWORD_SET, "windows.account.password_set"),
            ] {
                let ticks = u64::from_le_bytes(f[at..at + 8].try_into().expect("eight bytes"));
                if ticks != 0 {
                    event(
                        ctx,
                        &id,
                        (source, &locator),
                        kind,
                        Time::from_ticks_1601(ticks),
                    );
                    n += 1;
                }
            }
            if let Some(t) = name_key.and_then(|k| k.last_written.clone()) {
                let at = key_locator(&hive, name_key.expect("just matched"));
                event(ctx, &id, (source, &at), "windows.account.created", t);
                n += 1;
            }
        }
        Outcome::Ok(n)
    }
}

/// The user keys: eight hex digits (`Names` is the other subkey).
fn list_rids(subkeys: &[Name]) -> Vec<String> {
    subkeys
        .iter()
        .map(Name::display)
        .filter(|s| s.len() == 8 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect()
}

/// A `V` entry: its offset (from 0xCC) and length at `at` and `at + 4`, as UTF-16 text.
fn v_text(v: &[u8], at: usize) -> Option<String> {
    let u32_at = |o: usize| Some(u32::from_le_bytes(v.get(o..o + 4)?.try_into().ok()?) as usize);
    let (off, len) = (0xCC + u32_at(at)?, u32_at(at + 4)?);
    utf16(v.get(off..off.checked_add(len)?)?).filter(|s| !s.is_empty())
}

/// UTF-16LE up to the first NUL.
pub(crate) fn utf16(b: &[u8]) -> Option<String> {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// The machine's SID (`S-1-5-21-a-b-c`): the last 24 bytes of `Domains\Account`'s `V`.
fn domain_sid(v: &[u8]) -> Option<String> {
    let sid = v.get(v.len().checked_sub(24)?..)?;
    if sid[..12] != [1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0] {
        return None;
    }
    let sub = |i: usize| u32::from_le_bytes(sid[12 + 4 * i..16 + 4 * i].try_into().expect("four"));
    Some(format!("S-1-5-21-{}-{}-{}", sub(0), sub(1), sub(2)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::bytes::Locator;
    use af_core::capability::{Capabilities, FakeRegistry};
    use af_core::ids::{SourceId, SystemId};
    use af_core::runner::{NewEvent, NewRecord, Sink, Target, run};
    use af_core::system::System;

    #[derive(Default)]
    struct Out(Vec<String>);

    impl Sink for Out {
        fn emit(&mut self, _: &Kind, _: &Kind, _: String) {}
        fn fact(&mut self, _: &Kind, _: SystemId, f: NewFact) {
            self.0
                .push(format!("fact {} {}", f.subject, f.attrs.unwrap()));
        }
        fn event(&mut self, _: &Kind, _: SystemId, e: NewEvent) {
            self.0.push(format!("{} {}", e.kind, e.time.display()));
        }
        fn record(&mut self, _: &Kind, _: SystemId, _: NewRecord) {}
        fn note(&mut self, _: &Kind, _: SystemId, text: String) {
            self.0.push(format!("note {text}"));
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `ich` from the exam image (F as stored; V built with the name), and a user key without
    /// a name under Names.
    #[test]
    fn ich_and_a_nameless_key() {
        let f = hex(
            "0300010000000000f10081cc713fdd010000000000000000159918574cd5dc01ffffffffffffff7fc8beebc8713fdd01e903000001020000140200000000000000002a00010000000000000000000000",
        );
        let mut v = vec![0u8; 0xCC];
        v[0x0C..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&6u32.to_le_bytes());
        v.extend("ich".encode_utf16().flat_map(u16::to_le_bytes));
        let mut domain = vec![0u8; 8];
        domain.extend(hex("0104000000000005150000008b3470859f3ae93978563106"));
        let names = format!("{USERS}\\Names\\ich");
        let mut r = FakeRegistry::new();
        r.set(
            "windows.sam",
            "SAM\\Domains\\Account",
            "V",
            REG_BINARY,
            &domain,
        )
        .set(
            "windows.sam",
            &format!("{USERS}\\000003E9"),
            "F",
            REG_BINARY,
            &f,
        )
        .set(
            "windows.sam",
            &format!("{USERS}\\000003E9"),
            "V",
            REG_BINARY,
            &v,
        )
        .set(
            "windows.sam",
            &format!("{USERS}\\000003E9"),
            "UserPasswordHint",
            REG_BINARY,
            &"geheim"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .set("windows.sam", &names, "", 1001, &[])
        .set(
            "windows.sam",
            &format!("{USERS}\\000003E8"),
            "F",
            REG_BINARY,
            &f,
        )
        .set_origin(
            "windows.sam",
            SourceId(1),
            Locator::root("source.loose", "SAM"),
        );
        let sys = System {
            id: SystemId(1),
            family: Family::Windows,
            label: None,
            parent: None,
            volumes: vec![],
            views: vec![],
        };
        let caps = Capabilities { registry: Some(&r) };
        let targets = [Target::new(&sys, caps, vec![], None)];
        let mut out = Out::default();
        run(
            &[&Sam],
            &targets,
            &mut out,
            &mut af_core::plugin::OutcomeLog::new(),
            &mut af_core::runner::RunLog::new(),
        );
        let has = |s: &str| out.0.iter().any(|l| l == s || l.starts_with(s));
        assert!(
            has("note user key 000003E8 (RID 1000) has no name under Users\\Names"),
            "{:#?}",
            out.0
        );
        assert!(has("fact RID 1000 "), "{:#?}", out.0);
        let ich = out
            .0
            .iter()
            .find(|l| l.starts_with("fact ich "))
            .expect("ich");
        for part in [
            r#""sid":"S-1-5-21-2238723211-971586207-103896696-1001""#,
            r#""login_count":42"#,
            r#""password_hint":"geheim""#,
            r#""disabled":false"#,
        ] {
            assert!(ich.contains(part), "{part} in {ich}");
        }
        for e in [
            "windows.account.last_login 2026-09-08 09:09:48.5843697 UTC",
            "windows.account.last_failed_login 2026-09-08 09:09:42.5730248 UTC",
            "windows.account.password_set 2026-04-26 07:14:36.9732885 UTC",
        ] {
            assert!(has(e), "{e} in {:#?}", out.0);
        }
    }
}
