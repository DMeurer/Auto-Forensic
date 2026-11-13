//! Comments (piece O1): the analyst's dated notes on events, groups and facts. An item can have
//! several; each has a number for removing it, and none is edited in place. Like tags they are
//! the analyst's, so re-runs keep them.

use crate::rebuild::USER;
use crate::{Error, Store};
use af_core::ids::Endpoint;
use duckdb::params;

/// One comment.
#[derive(Debug, PartialEq, Eq)]
pub struct CommentRow {
    pub no: i64,
    /// `event`, `group`, `fact` or `file`, and its ID (none for a file).
    pub target_kind: String,
    pub target_id: Option<u128>,
    pub text: String,
    pub created_unix: i64,
}

impl Store {
    /// Adds a comment written at `created_unix` (seconds since 1970); returns its number.
    pub fn add_comment(
        &mut self,
        target: &Endpoint,
        text: &str,
        created_unix: i64,
    ) -> Result<i64, Error> {
        let c = target.to_columns();
        let tx = self.conn.transaction()?;
        let no: i64 = tx.query_row("SELECT coalesce(max(no), 0) + 1 FROM comments", [], |r| {
            r.get(0)
        })?;
        tx.execute(
            "INSERT INTO comments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                no,
                c.kind,
                c.id,
                c.system,
                c.file_scheme,
                c.file_value,
                text,
                created_unix,
                USER
            ],
        )?;
        tx.commit()?;
        Ok(no)
    }

    /// Removes comment `no`; returns whether there was one.
    pub fn remove_comment(&mut self, no: i64) -> Result<bool, Error> {
        Ok(self
            .conn
            .execute("DELETE FROM comments WHERE no = ?", [no])?
            > 0)
    }

    /// The comments on one target, or all of them, oldest first. A project made before O1
    /// that is opened read-only has none.
    pub fn comments(&self, target: Option<&Endpoint>) -> Result<Vec<CommentRow>, Error> {
        let exists: bool = self.conn.query_row(
            "SELECT count(*) > 0 FROM duckdb_tables() WHERE table_name = 'comments'",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            return Ok(vec![]);
        }
        let c = target.map(Endpoint::to_columns);
        let mut stmt = self.conn.prepare(
            "SELECT no, target_kind, target_id, text, created_unix FROM comments \
             WHERE ? OR (target_kind = ? AND target_id IS NOT DISTINCT FROM ? \
             AND target_system IS NOT DISTINCT FROM ? \
             AND target_file_scheme IS NOT DISTINCT FROM ? \
             AND target_file_value IS NOT DISTINCT FROM ?) ORDER BY no",
        )?;
        let c = c.as_ref();
        let rows = stmt.query_map(
            params![
                c.is_none(),
                c.map(|c| c.kind.clone()),
                c.and_then(|c| c.id),
                c.and_then(|c| c.system),
                c.and_then(|c| c.file_scheme.clone()),
                c.and_then(|c| c.file_value.clone()),
            ],
            |r| {
                Ok(CommentRow {
                    no: r.get(0)?,
                    target_kind: r.get(1)?,
                    target_id: r.get(2)?,
                    text: r.get(3)?,
                    created_unix: r.get(4)?,
                })
            },
        )?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::ids::{EventId, FactId};

    /// Two comments on an event and one on a fact; numbers keep counting after a removal.
    #[test]
    fn comments_are_numbered_dated_and_removable() {
        let mut s = Store::in_memory(256).unwrap();
        let (e, f) = (Endpoint::Event(EventId(1)), Endpoint::Fact(FactId(2)));
        assert_eq!(s.add_comment(&e, "first look", 100).unwrap(), 1);
        assert_eq!(s.add_comment(&f, "the stick", 200).unwrap(), 2);
        assert_eq!(s.add_comment(&e, "checked", 300).unwrap(), 3);
        let on_e: Vec<(i64, String)> = s
            .comments(Some(&e))
            .unwrap()
            .into_iter()
            .map(|c| (c.no, c.text))
            .collect();
        assert_eq!(on_e, [(1, "first look".into()), (3, "checked".into())]);
        assert!(s.remove_comment(3).unwrap());
        assert!(!s.remove_comment(3).unwrap());
        assert_eq!(s.add_comment(&e, "again", 400).unwrap(), 3);
        let all: Vec<(i64, String, i64)> = s
            .comments(None)
            .unwrap()
            .into_iter()
            .map(|c| (c.no, c.target_kind, c.created_unix))
            .collect();
        assert_eq!(
            all,
            [
                (1, "event".into(), 100),
                (2, "fact".into(), 200),
                (3, "event".into(), 400)
            ]
        );
    }

    /// Tags: added once, listed by tag, removed.
    #[test]
    fn tags_add_once_list_and_remove() {
        let mut s = Store::in_memory(256).unwrap();
        let (e, f) = (Endpoint::Event(EventId(1)), Endpoint::Fact(FactId(2)));
        assert!(s.add_tag(&e, "suspicious").unwrap());
        assert!(!s.add_tag(&e, "suspicious").unwrap());
        assert!(s.add_tag(&f, "suspicious").unwrap());
        assert!(s.add_tag(&f, "stick").unwrap());
        assert_eq!(
            s.tags(Some("suspicious")).unwrap(),
            [
                ("suspicious".to_string(), "event".to_string(), Some(1)),
                ("suspicious".to_string(), "fact".to_string(), Some(2))
            ]
        );
        assert_eq!(s.tags(None).unwrap().len(), 3);
        assert!(s.remove_tag(&f, "suspicious").unwrap());
        assert!(!s.remove_tag(&f, "suspicious").unwrap());
        assert_eq!(s.tags_of(&f).unwrap(), ["stick"]);
    }
}
