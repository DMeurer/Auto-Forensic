//! Timeline lists (piece F28): named lists of events and groups.
//!
//! Besides the full timeline, the analyst keeps lists such as "Exfiltration" or "Report". A list
//! holds references, never copies: copying an event into a list adds an entry and leaves the
//! event as it is. Every entry records who added it (`created_by`: `user` or a plugin ID) and
//! when. Lists are never rebuilt by a re-run.

use crate::{Error, Store};
use af_core::ids::{Endpoint, EventId, GroupId};
use duckdb::params;
use std::time::{SystemTime, UNIX_EPOCH};

/// One entry of a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub member: Endpoint,
    pub created_by: String,
    pub added_unix: i64,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Store {
    /// Creates a list, or returns the existing one with this name.
    pub fn create_list(&mut self, name: &str, created_by: &str) -> Result<u128, Error> {
        if let Some(id) = self.list_id(name)? {
            return Ok(id);
        }
        let id = uuid_like();
        self.conn.execute(
            "INSERT INTO lists VALUES (?, ?, ?, ?)",
            params![id, name, created_by, now()],
        )?;
        Ok(id)
    }

    pub fn list_id(&self, name: &str) -> Result<Option<u128>, Error> {
        let mut stmt = self.conn.prepare("SELECT id FROM lists WHERE name = ?")?;
        let mut rows = stmt.query_map([name], |r| r.get(0))?;
        rows.next().transpose()
    }

    /// The names of all lists, sorted.
    pub fn lists(&self) -> Result<Vec<String>, Error> {
        let mut stmt = self.conn.prepare("SELECT name FROM lists ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    /// Adds an event or group to a list. Adding one that's already there changes nothing.
    /// Returns whether an entry was added. Facts and files aren't timeline entries.
    pub fn add_to_list(
        &mut self,
        list: u128,
        member: &Endpoint,
        created_by: &str,
    ) -> Result<bool, Error> {
        let (kind, id) = match member {
            Endpoint::Event(e) => ("event", e.0),
            Endpoint::Group(g) => ("group", g.0),
            Endpoint::Fact(_) | Endpoint::File { .. } => return Ok(false),
        };
        let n = self.conn.execute(
            "INSERT INTO list_entries SELECT ?, ?, ?, ?, ?
             WHERE NOT EXISTS (SELECT 1 FROM list_entries
                               WHERE list = ? AND member_kind = ? AND member_id = ?)",
            params![list, kind, id, created_by, now(), list, kind, id],
        )?;
        Ok(n > 0)
    }

    /// Takes an event or group off a list. The event or group itself stays.
    pub fn remove_from_list(&mut self, list: u128, member: &Endpoint) -> Result<bool, Error> {
        let (kind, id) = match member {
            Endpoint::Event(e) => ("event", e.0),
            Endpoint::Group(g) => ("group", g.0),
            _ => return Ok(false),
        };
        let n = self.conn.execute(
            "DELETE FROM list_entries WHERE list = ? AND member_kind = ? AND member_id = ?",
            params![list, kind, id],
        )?;
        Ok(n > 0)
    }

    /// A list's entries, in the order they were added.
    pub fn list_entries(&self, list: u128) -> Result<Vec<ListEntry>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT member_kind, member_id, created_by, added_unix FROM list_entries
             WHERE list = ? ORDER BY added_unix, rowid",
        )?;
        let rows = stmt.query_map([list], |r| {
            let kind: String = r.get(0)?;
            let id: u128 = r.get(1)?;
            Ok(ListEntry {
                member: if kind == "group" {
                    Endpoint::Group(GroupId(id))
                } else {
                    Endpoint::Event(EventId(id))
                },
                created_by: r.get(2)?,
                added_unix: r.get(3)?,
            })
        })?;
        rows.collect()
    }
}

/// A random 128-bit ID (list IDs only need to be unique within a project).
fn uuid_like() -> u128 {
    af_core::ids::SourceId::new_random().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventRow;
    use crate::rebuild::USER;
    use af_core::time::Time;

    fn event(id: u128) -> EventRow {
        EventRow {
            id,
            source: 1,
            record: id,
            system: 7,
            kind: "test.event".into(),
            meaning: "test.written".into(),
            time: Time::from_unix_seconds(1_700_000_000).to_columns(),
            clock_domain: "wall".into(),
            seq_domain: None,
            seq_no: None,
            created_by: "test.plugin".into(),
        }
    }

    #[test]
    fn copying_an_event_to_a_list_leaves_the_event_unchanged() {
        let mut s = Store::in_memory(256).unwrap();
        s.insert_events(&[event(1), event(2)]).unwrap();
        let before = s.events().unwrap();
        let list = s.create_list("Exfiltration", USER).unwrap();
        assert!(
            s.add_to_list(list, &Endpoint::Event(EventId(1)), USER)
                .unwrap()
        );
        assert!(
            !s.add_to_list(list, &Endpoint::Event(EventId(1)), USER)
                .unwrap(),
            "once only"
        );
        assert!(
            s.add_to_list(list, &Endpoint::Group(GroupId(5)), "test.plugin")
                .unwrap()
        );
        assert_eq!(s.events().unwrap(), before, "events untouched");
        let entries = s.list_entries(list).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].member, Endpoint::Event(EventId(1)));
        assert_eq!(entries[0].created_by, USER);
        assert_eq!(entries[1].created_by, "test.plugin");
        // The same event can sit in several lists.
        let report = s.create_list("Report", USER).unwrap();
        s.add_to_list(report, &Endpoint::Event(EventId(1)), USER)
            .unwrap();
        assert_eq!(s.lists().unwrap(), ["Exfiltration", "Report"]);
        // Taking it off one list leaves the other and the event.
        assert!(
            s.remove_from_list(list, &Endpoint::Event(EventId(1)))
                .unwrap()
        );
        assert_eq!(s.list_entries(report).unwrap().len(), 1);
        assert_eq!(s.events().unwrap(), before);
        // Creating a list that exists returns it.
        assert_eq!(s.create_list("Report", USER).unwrap(), report);
    }

    #[test]
    fn lists_survive_a_re_run() {
        let mut s = Store::in_memory(256).unwrap();
        s.insert_events(&[event(1)]).unwrap();
        let list = s.create_list("Keep", USER).unwrap();
        s.add_to_list(list, &Endpoint::Event(EventId(1)), USER)
            .unwrap();
        s.clear_plugin_output("test.plugin", 7).unwrap();
        s.clear_derived_links().unwrap();
        s.clear_derived_groups().unwrap();
        s.insert_events(&[event(1)]).unwrap();
        assert_eq!(
            s.list_entries(list).unwrap()[0].member,
            Endpoint::Event(EventId(1))
        );
    }
}
