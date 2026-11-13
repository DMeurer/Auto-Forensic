//! Facts (piece F30): data without a time of its own.
//!
//! Accounts, installed programs, network settings, Wi-Fi profiles, hashes: they hold for a
//! system, not at a moment. A fact has a kind, a subject (what it's about, such as a SID),
//! attributes as JSON text, its source, and who made it. Its ID is stable
//! ([`af_core::ids::FactId::derive`]), so a re-run gives the same fact, and links, group
//! memberships and tags on it survive. Facts link to events and join groups like events do.

use crate::{Error, Store};
use duckdb::params;

/// One fact row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactRow {
    pub id: u128,
    pub source: u128,
    pub system: u128,
    pub kind: String,
    pub subject: String,
    /// Attributes as JSON text.
    pub attrs: Option<String>,
    pub created_by: String,
}

impl Store {
    pub fn insert_facts(&mut self, rows: &[FactRow]) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        {
            let mut app = tx.appender("facts")?;
            for f in rows {
                app.append_row(params![
                    f.id,
                    f.source,
                    f.system,
                    f.kind,
                    f.subject,
                    f.attrs,
                    f.created_by
                ])?;
            }
        }
        tx.commit()
    }

    /// One fact (L8), or `None` when there is no such fact.
    pub fn fact_by_id(&self, id: u128) -> Result<Option<FactRow>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, source, system, kind, subject, attrs, created_by FROM facts WHERE id = ?",
        )?;
        let mut rows = stmt.query_map([id], |r| {
            Ok(FactRow {
                id: r.get(0)?,
                source: r.get(1)?,
                system: r.get(2)?,
                kind: r.get(3)?,
                subject: r.get(4)?,
                attrs: r.get(5)?,
                created_by: r.get(6)?,
            })
        })?;
        rows.next().transpose()
    }

    /// All facts, by kind then subject.
    pub fn facts(&self) -> Result<Vec<FactRow>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, source, system, kind, subject, attrs, created_by FROM facts \
             ORDER BY kind, subject, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(FactRow {
                id: r.get(0)?,
                source: r.get(1)?,
                system: r.get(2)?,
                kind: r.get(3)?,
                subject: r.get(4)?,
                attrs: r.get(5)?,
                created_by: r.get(6)?,
            })
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventRow;
    use crate::rebuild::USER;
    use af_core::bytes::Locator;
    use af_core::ids::{Endpoint, EventId, FactId, GroupId};
    use af_core::names::Kind;
    use af_core::time::Time;

    fn account(subject: &str) -> FactRow {
        let id = FactId::derive(
            "source-1",
            &Locator::root("source.loose", "SAM"),
            &Kind::new("windows.account").unwrap(),
            subject,
        );
        FactRow {
            id: id.0,
            source: 1,
            system: 7,
            kind: "windows.account".into(),
            subject: subject.into(),
            attrs: Some(r#"{"name": "ich"}"#.into()),
            created_by: "windows.registry.sam".into(),
        }
    }

    fn logon(id: u128) -> EventRow {
        EventRow {
            id,
            source: 1,
            record: id,
            system: 7,
            kind: "windows.sam.last_login".into(),
            meaning: "sam.last_login".into(),
            time: Time::from_unix_seconds(1_700_000_000).to_columns(),
            clock_domain: "wall".into(),
            seq_domain: None,
            seq_no: None,
            created_by: "windows.registry.sam".into(),
        }
    }

    #[test]
    fn a_fact_links_to_an_event_joins_a_group_and_keeps_its_id() {
        let mut s = Store::in_memory(256).unwrap();
        let fact = account("S-1-5-21-1-2-3-1001");
        s.insert_facts(std::slice::from_ref(&fact)).unwrap();
        s.insert_events(&[logon(50)]).unwrap();
        let f = Endpoint::Fact(FactId(fact.id));
        s.add_link(
            1,
            "windows.account_logon",
            &f,
            &Endpoint::Event(EventId(50)),
            "windows.registry.sam",
        )
        .unwrap();
        s.add_group(
            GroupId(9),
            &Kind::new("user.case").unwrap(),
            "the suspect's account",
            USER,
        )
        .unwrap();
        s.add_member(GroupId(9), &f, None, USER).unwrap();
        s.add_tag(&f, "suspect").unwrap();
        assert_eq!(s.groups_of(&f).unwrap(), [GroupId(9)]);

        // Re-run: the plugin's facts are rebuilt with the same ID; the group and tag still match.
        s.clear_plugin_output("windows.registry.sam", 7).unwrap();
        assert!(s.facts().unwrap().is_empty());
        s.insert_facts(&[account("S-1-5-21-1-2-3-1001")]).unwrap();
        assert_eq!(s.facts().unwrap()[0].id, fact.id);
        assert_eq!(s.groups_of(&f).unwrap(), [GroupId(9)]);
        assert_eq!(s.tags_of(&f).unwrap(), ["suspect"]);
    }
}
