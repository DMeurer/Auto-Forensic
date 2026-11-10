//! What a re-run replaces and what it keeps (piece F25).
//!
//! Everything a plugin made is rebuilt: before a plugin extracts again on a system, its earlier
//! records, events, entities and facts there go ([`Store::clear_plugin_output`]); before correlation,
//! every derived link goes ([`Store::clear_derived_links`]). What the analyst made stays: links,
//! tags (and later groups and lists) with `created_by = 'user'`. Because event IDs are stable
//! (F18), a tag or a user link on an event still points at the same event after the re-run.

use crate::{Error, Store};
use af_core::ids::Endpoint;
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
            "INSERT INTO links VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

    /// Stores many links in one go, as (id, kind, from, to, created by): a plugin can make
    /// hundreds of thousands (M6, one per change journal event).
    pub fn add_links<'a>(
        &mut self,
        links: impl IntoIterator<Item = (u128, &'a str, &'a Endpoint, &'a Endpoint, &'a str)>,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        {
            let mut app = tx.appender("links")?;
            for (id, kind, from, to, created_by) in links {
                let (f, t) = (from.to_columns(), to.to_columns());
                app.append_row(params![
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
                ])?;
            }
        }
        tx.commit()
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
}
