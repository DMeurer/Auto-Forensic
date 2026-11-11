//! What a re-run replaces and what it keeps (piece F25).
//!
//! Everything a plugin made is rebuilt: before a plugin extracts again on a system, its earlier
//! records, events, entities and facts there go ([`Store::clear_plugin_output`]); before correlation,
//! every derived link goes ([`Store::clear_derived_links`]). What the analyst made stays: links,
//! tags (and later groups and lists) with `created_by = 'user'`. Because event IDs are stable
//! (F18), a tag or a user link on an event still points at the same event after the re-run.

use crate::{Error, Store};
use af_core::ids::Endpoint;
use af_core::runner::NewLink;

/// One link as `af explain` shows it, seen from one of its ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLine {
    pub id: u128,
    pub kind: String,
    pub tier: String,
    pub label: String,
    pub reason: String,
    pub key: String,
    pub description: Option<String>,
    pub created_by: String,
    /// From the end asked about to the other one.
    pub outgoing: bool,
    /// The other end: `event`, `fact`, `group` or `file`, and its ID (none for a file).
    pub other_kind: String,
    pub other_id: Option<u128>,
}
use duckdb::params;

/// The `created_by` of everything the analyst made by hand.
pub const USER: &str = "user";

impl Store {
    /// Deletes what `plugin` extracted on `system`: its records, events and entities. Returns
    /// how many events went.
    pub fn clear_plugin_output(&mut self, plugin: &str, system: u128) -> Result<u64, Error> {
        let tx = self.conn.transaction()?;
        let n = tx.execute(
            "DELETE FROM events WHERE created_by = ? AND system = ?",
            params![plugin, system],
        )?;
        for table in ["records", "entities", "facts", "system_notes"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE created_by = ? AND system = ?"),
                params![plugin, system],
            )?;
        }
        tx.commit()?;
        Ok(n as u64)
    }

    /// Deletes the links and groups `plugin` made, before it makes them again. With `system`
    /// (a plugin extracting again for that system), only those anchored on its own events and
    /// facts there: a link starting at one, a group with one as member. Without, all of them
    /// (a plugin that rebuilds its links and groups every run, in Index or Correlate). Run it
    /// before the plugin's events and facts are cleared.
    pub fn clear_links_and_groups_of(
        &mut self,
        plugin: &str,
        system: Option<u128>,
    ) -> Result<(), Error> {
        let mine = "(SELECT id FROM events WHERE created_by = $1 AND system = $2 \
                     UNION ALL SELECT id FROM facts WHERE created_by = $1 AND system = $2)";
        let (links, groups) = match system {
            Some(_) => (
                format!(
                    "DELETE FROM links WHERE created_by = $1 \
                     AND from_kind IN ('event', 'fact') AND from_id IN {mine}"
                ),
                format!(
                    "SELECT DISTINCT m.grp FROM group_members m JOIN groups g ON g.id = m.grp \
                     WHERE g.created_by = $1 AND m.member_kind IN ('event', 'fact') \
                     AND m.member_id IN {mine}"
                ),
            ),
            None => (
                "DELETE FROM links WHERE created_by = $1 AND $2::UHUGEINT IS NULL".to_string(),
                "SELECT id FROM groups WHERE created_by = $1 AND $2::UHUGEINT IS NULL".to_string(),
            ),
        };
        let tx = self.conn.transaction()?;
        tx.execute(&links, params![plugin, system])?;
        // The groups first, as deleting their members changes what the query finds.
        let doomed: Vec<u128> = tx
            .prepare(&groups)?
            .query_map(params![plugin, system], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for g in doomed {
            tx.execute(
                "DELETE FROM group_members WHERE grp = ? OR (member_kind = 'group' AND member_id = ?)",
                params![g, g],
            )?;
            tx.execute("DELETE FROM groups WHERE id = ?", params![g])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Deletes every link a plugin made. Links the analyst made stay. Returns how many went.
    pub fn clear_derived_links(&mut self) -> Result<u64, Error> {
        let n = self
            .conn
            .execute("DELETE FROM links WHERE created_by <> ?", [USER])?;
        Ok(n as u64)
    }

    /// Stores a link from `from` to `to`.
    pub fn add_link(
        &mut self,
        id: u128,
        kind: &str,
        from: &Endpoint,
        to: &Endpoint,
        created_by: &str,
    ) -> Result<(), Error> {
        let (f, t) = (from.to_columns(), to.to_columns());
        self.conn.execute(
            "INSERT INTO links VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
             NULL, NULL, NULL, NULL, NULL)",
            params![
                id,
                kind,
                f.kind,
                f.id,
                f.system,
                f.file_scheme,
                f.file_value,
                t.kind,
                t.id,
                t.system,
                t.file_scheme,
                t.file_value,
                created_by
            ],
        )?;
        Ok(())
    }

    /// Stores many links in one go, with their tier, label, reason, key and description:
    /// a plugin can make hundreds of thousands (M6, one per change journal event).
    pub fn add_links(&mut self, links: &[(NewLink, String)]) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        {
            let mut app = tx.appender("links")?;
            for (l, created_by) in links {
                let (f, t) = (l.from.to_columns(), l.to.to_columns());
                app.append_row(params![
                    l.id,
                    l.kind.as_str(),
                    f.kind,
                    f.id,
                    f.system,
                    f.file_scheme,
                    f.file_value,
                    t.kind,
                    t.id,
                    t.system,
                    t.file_scheme,
                    t.file_value,
                    created_by,
                    l.tier.as_str(),
                    l.label,
                    l.reason,
                    l.key,
                    l.description,
                ])?;
            }
        }
        tx.commit()
    }

    /// The links from and to `of`: strong before possible, then by label (L1).
    pub fn links_of(&self, of: &Endpoint) -> Result<Vec<LinkLine>, Error> {
        let c = of.to_columns();
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, coalesce(tier, 'strong'), coalesce(label, kind), \
             coalesce(reason, ''), coalesce(key, ''), description, created_by, \
             from_kind = ? AND from_id IS NOT DISTINCT FROM ?, \
             CASE WHEN from_kind = ? AND from_id IS NOT DISTINCT FROM ? THEN to_kind \
                  ELSE from_kind END, \
             CASE WHEN from_kind = ? AND from_id IS NOT DISTINCT FROM ? THEN to_id \
                  ELSE from_id END \
             FROM links \
             WHERE (from_kind = ? AND from_id IS NOT DISTINCT FROM ?) \
                OR (to_kind = ? AND to_id IS NOT DISTINCT FROM ?) \
             ORDER BY coalesce(tier, 'strong') = 'possible', 4, 1",
        )?;
        let k = c.kind;
        let rows = stmt.query_map(params![k, c.id, k, c.id, k, c.id, k, c.id, k, c.id], |r| {
            Ok(LinkLine {
                id: r.get(0)?,
                kind: r.get(1)?,
                tier: r.get(2)?,
                label: r.get(3)?,
                reason: r.get(4)?,
                key: r.get(5)?,
                description: r.get(6)?,
                created_by: r.get(7)?,
                outgoing: r.get(8)?,
                other_kind: r.get(9)?,
                other_id: r.get(10)?,
            })
        })?;
        rows.collect()
    }

    /// IDs and creators of all links, ordered by ID.
    pub fn links(&self) -> Result<Vec<(u128, String)>, Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, created_by FROM links ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    /// Tags an event, group, fact or file. Tags are always the analyst's.
    pub fn add_tag(&mut self, target: &Endpoint, tag: &str) -> Result<(), Error> {
        let c = target.to_columns();
        self.conn.execute(
            "INSERT INTO tags VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                c.kind,
                c.id,
                c.system,
                c.file_scheme,
                c.file_value,
                tag,
                USER
            ],
        )?;
        Ok(())
    }

    /// The tags on one event, group or fact, in order of name.
    pub fn tags_of(&self, target: &Endpoint) -> Result<Vec<String>, Error> {
        let c = target.to_columns();
        let mut stmt = self.conn.prepare(
            "SELECT tag FROM tags WHERE target_kind = ? AND target_id IS NOT DISTINCT FROM ? \
             AND target_system IS NOT DISTINCT FROM ? \
             AND target_file_scheme IS NOT DISTINCT FROM ? \
             AND target_file_value IS NOT DISTINCT FROM ? ORDER BY tag",
        )?;
        let rows = stmt.query_map(
            params![c.kind, c.id, c.system, c.file_scheme, c.file_value],
            |r| r.get(0),
        )?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventRow;
    use af_core::ids::EventId;
    use af_core::time::Time;

    fn event(id: u128, created_by: &str) -> EventRow {
        EventRow {
            id,
            source: 1,
            record: id,
            system: 7,
            kind: "test.event".into(),
            meaning: "test.written".into(),
            time: Time::from_unix_seconds(id as i64).to_columns(),
            clock_domain: "wall".into(),
            seq_domain: None,
            seq_no: None,
            created_by: created_by.into(),
        }
    }

    #[test]
    fn a_tag_survives_a_re_run() {
        let mut store = Store::in_memory(256).unwrap();
        let (a, b) = (Endpoint::Event(EventId(10)), Endpoint::Event(EventId(11)));
        // First run: a plugin extracts two events and links them.
        store
            .insert_events(&[event(10, "test.plugin"), event(11, "test.plugin")])
            .unwrap();
        store
            .add_link(100, "test.follows", &a, &b, "test.plugin")
            .unwrap();
        // The analyst tags one event and adds a link of their own.
        store.add_tag(&a, "suspicious").unwrap();
        store.add_link(200, "user.note", &b, &a, USER).unwrap();

        // Re-run: the plugin's output is rebuilt with the same stable IDs.
        assert_eq!(store.clear_plugin_output("test.plugin", 7).unwrap(), 2);
        assert_eq!(store.clear_derived_links().unwrap(), 1);
        store
            .insert_events(&[event(10, "test.plugin"), event(11, "test.plugin")])
            .unwrap();
        store
            .add_link(101, "test.follows", &a, &b, "test.plugin")
            .unwrap();

        assert_eq!(store.tags_of(&a).unwrap(), ["suspicious"]);
        assert!(store.tags_of(&b).unwrap().is_empty());
        assert_eq!(
            store.links().unwrap(),
            [(101, "test.plugin".to_string()), (200, USER.to_string())]
        );
        assert_eq!(
            store.events().unwrap().len(),
            2,
            "no duplicates after the re-run"
        );
    }

    #[test]
    fn clearing_one_plugin_leaves_the_others() {
        let mut store = Store::in_memory(256).unwrap();
        store
            .insert_events(&[event(1, "test.a"), event(2, "test.b")])
            .unwrap();
        store.clear_plugin_output("test.a", 7).unwrap();
        let left: Vec<String> = store
            .events()
            .unwrap()
            .into_iter()
            .map(|e| e.created_by)
            .collect();
        assert_eq!(left, ["test.b"]);
        // Another system's output of the same plugin stays too.
        assert_eq!(store.clear_plugin_output("test.b", 8).unwrap(), 0);
    }

    /// B2, found while building it: an Extract plugin's links and groups stay when another
    /// plugin extracts, go with its own re-extraction for that system only, and an every-run
    /// plugin's go each run. The analyst's stay.
    #[test]
    fn links_and_groups_follow_their_plugins_output() {
        use af_core::ids::GroupId;
        let mut store = Store::in_memory(256).unwrap();
        let on = |id: u128, system: u128| EventRow {
            system,
            ..event(id, "test.usn")
        };
        store.insert_events(&[on(1, 7), on(2, 8)]).unwrap();
        let (one, two) = (Endpoint::Event(EventId(1)), Endpoint::Event(EventId(2)));
        store
            .add_link(10, "test.file", &one, &two, "test.usn")
            .unwrap();
        store
            .add_link(20, "test.file", &two, &one, "test.usn")
            .unwrap();
        store.add_link(30, "user.note", &one, &two, USER).unwrap();
        let kind = af_core::names::Kind::new("test.session").unwrap();
        store
            .add_group(GroupId(40), &kind, "same site", "test.usn")
            .unwrap();
        store.add_member(GroupId(40), &one, "test.usn").unwrap();
        // test.usn extracts again for system 7 only.
        store
            .clear_links_and_groups_of("test.usn", Some(7))
            .unwrap();
        let ids: Vec<u128> = store.links().unwrap().into_iter().map(|(i, _)| i).collect();
        assert_eq!(ids, [20, 30]);
        assert!(store.groups_of(&one).unwrap().is_empty());
        // A plugin that rebuilds every run loses all of its own.
        store.clear_links_and_groups_of("test.usn", None).unwrap();
        let ids: Vec<u128> = store.links().unwrap().into_iter().map(|(i, _)| i).collect();
        assert_eq!(ids, [30]);
    }

    /// L1: an event's links, strong before possible, each with its label, reason and key.
    #[test]
    fn links_of_an_event_strong_first() {
        use af_core::names::Kind;
        use af_core::runner::LinkTier;
        let mut store = Store::in_memory(256).unwrap();
        let (a, b, c) = (
            Endpoint::Event(EventId(1)),
            Endpoint::Event(EventId(2)),
            Endpoint::Event(EventId(3)),
        );
        let link = |id, from: &Endpoint, to: &Endpoint, tier, label: &str| NewLink {
            id,
            kind: Kind::new("test.step").unwrap(),
            from: from.clone(),
            to: to.clone(),
            tier,
            label: label.into(),
            reason: "same path and size".into(),
            key: "x.exe (3 bytes)".into(),
            description: None,
        };
        store
            .add_links(&[
                (
                    link(10, &a, &b, LinkTier::Possible, "probably installed to"),
                    "p".into(),
                ),
                (
                    link(11, &c, &a, LinkTier::Strong, "saved as file"),
                    "p".into(),
                ),
            ])
            .unwrap();
        let got: Vec<(String, String, bool)> = store
            .links_of(&a)
            .unwrap()
            .into_iter()
            .map(|l| (l.label, l.tier, l.outgoing))
            .collect();
        assert_eq!(
            got,
            [
                ("saved as file".into(), "strong".into(), false),
                ("probably installed to".into(), "possible".into(), true),
            ]
        );
    }

    /// A project made before L1 gets the new link columns when it is opened for writing.
    #[test]
    fn an_older_links_table_gains_the_new_columns() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE links (id UHUGEINT NOT NULL, kind VARCHAR NOT NULL, \
             from_kind VARCHAR NOT NULL, from_id UHUGEINT, from_system UHUGEINT, \
             from_file_scheme VARCHAR, from_file_value BLOB, to_kind VARCHAR NOT NULL, \
             to_id UHUGEINT, to_system UHUGEINT, to_file_scheme VARCHAR, to_file_value BLOB, \
             created_by VARCHAR NOT NULL)",
        )
        .unwrap();
        let store = Store::setup(conn, 256).unwrap();
        let n: i64 = store
            .connection()
            .query_row(
                "SELECT count(*) FROM duckdb_columns() WHERE table_name = 'links'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 18);
    }
}
