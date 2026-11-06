//! Groups (piece F27): entries with members, a start and an end, and always a reason.
//!
//! Members are events, groups or facts, many-to-many: an event can sit in several groups, and
//! groups nest. A group never contains itself, directly or through other groups. Start and end
//! come from the members ([`Store::refresh_group_ranges`]): events by their time key, nested
//! groups by their own range; members without a time (facts, events with no key) don't widen it.
//! Every group states why it exists, because grouping by time alone is not a reason.

use crate::rebuild::USER;
use crate::{Error, Store};
use af_core::ids::{Endpoint, GroupId};
use af_core::names::Kind;
use duckdb::params;
use std::fmt;

#[derive(Debug)]
pub enum GroupError {
    /// A group needs a reason.
    NoReason,
    /// Files aren't group members; their events are.
    FileMember,
    /// Adding this group would put a group inside itself.
    Loop {
        group: GroupId,
        member: GroupId,
    },
    Db(Error),
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReason => write!(f, "a group needs a reason"),
            Self::FileMember => write!(f, "a file can't be a group member; add its events"),
            Self::Loop { group, member } => {
                write!(
                    f,
                    "group {member} contains {group} already, so it can't go inside it"
                )
            }
            Self::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GroupError {}

impl From<Error> for GroupError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl Store {
    /// Creates a group. `reason` must say why it exists.
    pub fn add_group(
        &mut self,
        id: GroupId,
        kind: &Kind,
        reason: &str,
        created_by: &str,
    ) -> Result<(), GroupError> {
        if reason.trim().is_empty() {
            return Err(GroupError::NoReason);
        }
        self.conn.execute(
            "INSERT INTO groups VALUES (?, ?, ?, NULL, NULL, ?)",
            params![id.0, kind.as_str(), reason, created_by],
        )?;
        Ok(())
    }

    /// Adds a member. A group as member is refused if it is `group` or contains it.
    pub fn add_member(
        &mut self,
        group: GroupId,
        member: &Endpoint,
        created_by: &str,
    ) -> Result<(), GroupError> {
        let (kind, id) = match member {
            Endpoint::Event(e) => ("event", e.0),
            Endpoint::Fact(f) => ("fact", f.0),
            Endpoint::Group(g) => {
                let contains: bool = self.conn.query_row(
                    "WITH RECURSIVE inside(id) AS (
                         SELECT ?::UHUGEINT
                         UNION
                         SELECT m.member_id FROM group_members m JOIN inside ON m.grp = inside.id
                         WHERE m.member_kind = 'group')
                     SELECT count(*) > 0 FROM inside WHERE id = ?",
                    params![g.0, group.0],
                    |r| r.get(0),
                )?;
                if contains {
                    return Err(GroupError::Loop { group, member: *g });
                }
                ("group", g.0)
            }
            Endpoint::File { .. } => return Err(GroupError::FileMember),
        };
        self.conn.execute(
            "INSERT INTO group_members VALUES (?, ?, ?, ?)",
            params![group.0, kind, id, created_by],
        )?;
        Ok(())
    }

    /// Sets every group's start and end from its members: events by time key, nested groups by
    /// their range. Members without a time are ignored. Run after a batch of changes.
    pub fn refresh_group_ranges(&mut self) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "UPDATE groups SET ts_min = r.mn, ts_max = r.mx
             FROM (SELECT g.id, min(e.ts) AS mn, max(e.ts) AS mx
                   FROM groups g
                   LEFT JOIN group_members m ON m.grp = g.id AND m.member_kind = 'event'
                   LEFT JOIN events e ON e.id = m.member_id
                   GROUP BY g.id) r
             WHERE groups.id = r.id;",
        )?;
        // Nested groups: pass ranges up until nothing changes. Loops are impossible, so this
        // ends after at most as many rounds as the deepest nesting.
        loop {
            let changed = tx.execute(
                "UPDATE groups SET
                     ts_min = least(coalesce(groups.ts_min, c.mn), c.mn),
                     ts_max = greatest(coalesce(groups.ts_max, c.mx), c.mx)
                 FROM (SELECT m.grp, min(g.ts_min) AS mn, max(g.ts_max) AS mx
                       FROM group_members m JOIN groups g ON g.id = m.member_id
                       WHERE m.member_kind = 'group'
                       GROUP BY m.grp) c
                 WHERE groups.id = c.grp
                   AND (groups.ts_min IS DISTINCT FROM least(coalesce(groups.ts_min, c.mn), c.mn)
                     OR groups.ts_max IS DISTINCT FROM greatest(coalesce(groups.ts_max, c.mx), c.mx))",
                [],
            )?;
            if changed == 0 {
                break;
            }
        }
        tx.commit()
    }

    /// A group's start and end, as of the last [`refresh_group_ranges`](Self::refresh_group_ranges).
    pub fn group_range(&self, group: GroupId) -> Result<(Option<i64>, Option<i64>), Error> {
        self.conn.query_row(
            "SELECT ts_min, ts_max FROM groups WHERE id = ?",
            [group.0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
    }

    /// The groups an event, group or fact is a direct member of.
    pub fn groups_of(&self, member: &Endpoint) -> Result<Vec<GroupId>, Error> {
        let (kind, id) = match member {
            Endpoint::Event(e) => ("event", e.0),
            Endpoint::Group(g) => ("group", g.0),
            Endpoint::Fact(f) => ("fact", f.0),
            Endpoint::File { .. } => return Ok(Vec::new()),
        };
        let mut stmt = self.conn.prepare(
            "SELECT grp FROM group_members WHERE member_kind = ? AND member_id = ? ORDER BY grp",
        )?;
        let rows = stmt.query_map(params![kind, id], |r| Ok(GroupId(r.get(0)?)))?;
        rows.collect()
    }

    /// Deletes the groups plugins made, with their members (F25). The analyst's groups stay.
    pub fn clear_derived_groups(&mut self) -> Result<u64, Error> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM group_members WHERE grp IN (SELECT id FROM groups WHERE created_by <> ?)
                OR (member_kind = 'group'
                    AND member_id IN (SELECT id FROM groups WHERE created_by <> ?))",
            params![USER, USER],
        )?;
        let n = tx.execute("DELETE FROM groups WHERE created_by <> ?", [USER])?;
        tx.commit()?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventRow;
    use af_core::ids::FileId;
    use af_core::ids::{EventId, FactId, SystemId};
    use af_core::time::Time;

    fn event(id: u128, secs: Option<i64>) -> EventRow {
        EventRow {
            id,
            source: 1,
            record: id,
            system: 7,
            kind: "test.event".into(),
            meaning: "test.written".into(),
            time: secs
                .map_or(Time::from_ticks_1601(0), Time::from_unix_seconds)
                .to_columns(),
            clock_domain: "wall".into(),
            seq_domain: None,
            seq_no: None,
            created_by: "test.plugin".into(),
        }
    }

    fn kind() -> Kind {
        Kind::new("test.group").unwrap()
    }

    #[test]
    fn an_event_sits_in_two_groups() {
        let mut s = Store::in_memory(256).unwrap();
        s.insert_events(&[event(1, Some(100))]).unwrap();
        for g in [10, 11] {
            s.add_group(GroupId(g), &kind(), "same program run", "test.plugin")
                .unwrap();
            s.add_member(GroupId(g), &Endpoint::Event(EventId(1)), "test.plugin")
                .unwrap();
        }
        assert_eq!(
            s.groups_of(&Endpoint::Event(EventId(1))).unwrap(),
            [GroupId(10), GroupId(11)]
        );
    }

    #[test]
    fn a_group_inside_itself_is_rejected() {
        let mut s = Store::in_memory(256).unwrap();
        for g in [1, 2, 3] {
            s.add_group(GroupId(g), &kind(), "nested", USER).unwrap();
        }
        let g = |n| Endpoint::Group(GroupId(n));
        assert!(matches!(
            s.add_member(GroupId(1), &g(1), USER),
            Err(GroupError::Loop { .. })
        ));
        s.add_member(GroupId(1), &g(2), USER).unwrap();
        s.add_member(GroupId(2), &g(3), USER).unwrap();
        // 3 is inside 2 inside 1, so 1 can't go inside 3.
        assert!(matches!(
            s.add_member(GroupId(3), &g(1), USER),
            Err(GroupError::Loop { .. })
        ));
        // Files and reasonless groups are refused too.
        let file = Endpoint::File {
            system: SystemId(1),
            file: FileId {
                scheme: Kind::new("ntfs.file_ref").unwrap(),
                value: vec![1],
            },
        };
        assert!(matches!(
            s.add_member(GroupId(1), &file, USER),
            Err(GroupError::FileMember)
        ));
        assert!(matches!(
            s.add_group(GroupId(9), &kind(), "  ", USER),
            Err(GroupError::NoReason)
        ));
    }

    #[test]
    fn ranges_come_from_members_with_a_time() {
        let mut s = Store::in_memory(256).unwrap();
        s.insert_events(&[
            event(1, Some(100)),
            event(2, Some(300)),
            event(3, None),
            event(4, Some(50)),
        ])
        .unwrap();
        s.add_group(GroupId(1), &kind(), "outer", USER).unwrap();
        s.add_group(GroupId(2), &kind(), "inner", USER).unwrap();
        s.add_group(GroupId(3), &kind(), "only timeless members", USER)
            .unwrap();
        for e in [1, 2, 3] {
            s.add_member(GroupId(1), &Endpoint::Event(EventId(e)), USER)
                .unwrap();
        }
        s.add_member(GroupId(1), &Endpoint::Fact(FactId(9)), USER)
            .unwrap();
        s.add_member(GroupId(2), &Endpoint::Event(EventId(4)), USER)
            .unwrap();
        s.add_member(GroupId(3), &Endpoint::Event(EventId(3)), USER)
            .unwrap();
        s.refresh_group_ranges().unwrap();
        let key = |secs: i64| Time::from_unix_seconds(secs).key.unwrap().0;
        // The event without a time and the fact don't widen the range.
        assert_eq!(
            s.group_range(GroupId(1)).unwrap(),
            (Some(key(100)), Some(key(300)))
        );
        assert_eq!(s.group_range(GroupId(3)).unwrap(), (None, None));
        // Nesting passes the inner range up.
        s.add_member(GroupId(1), &Endpoint::Group(GroupId(2)), USER)
            .unwrap();
        s.refresh_group_ranges().unwrap();
        assert_eq!(
            s.group_range(GroupId(1)).unwrap(),
            (Some(key(50)), Some(key(300)))
        );
    }

    #[test]
    fn derived_groups_rebuild_and_the_analysts_stay() {
        let mut s = Store::in_memory(256).unwrap();
        s.add_group(GroupId(1), &kind(), "plugin's", "test.plugin")
            .unwrap();
        s.add_group(GroupId(2), &kind(), "mine", USER).unwrap();
        s.add_member(GroupId(2), &Endpoint::Group(GroupId(1)), USER)
            .unwrap();
        assert_eq!(s.clear_derived_groups().unwrap(), 1);
        assert!(
            s.groups_of(&Endpoint::Group(GroupId(1)))
                .unwrap()
                .is_empty()
        );
        assert_eq!(s.group_range(GroupId(2)).unwrap(), (None, None));
    }

    /// 220,000 groups of 3 events each, made in SQL like a plugin's bulk output. Lookups and a
    /// range refresh must stay quick. Timings are printed; the bounds are loose so a slow CI
    /// machine passes.
    #[test]
    fn holds_220000_groups() {
        let mut s = Store::in_memory(2048).unwrap();
        s.connection()
            .execute_batch(
                "INSERT INTO events SELECT i::UHUGEINT, 1, i // 3, 7, 'test.event', 'test.written',
                     130000000000000000 + i * 10000000 AS t, t, t, t, NULL, 'ticks_1601', 'ok', 1,
                     'utc', NULL, 1, 'wall', NULL, NULL, 'test.plugin'
                 FROM range(660000) r(i);
                 INSERT INTO groups SELECT i::UHUGEINT, 'test.group', 'same record', NULL, NULL,
                     'test.plugin' FROM range(220000) r(i);
                 INSERT INTO group_members SELECT (i // 3)::UHUGEINT, 'event', i::UHUGEINT,
                     'test.plugin' FROM range(660000) r(i);",
            )
            .unwrap();
        let t = std::time::Instant::now();
        s.refresh_group_ranges().unwrap();
        let refresh = t.elapsed();
        let t = std::time::Instant::now();
        let found = s.groups_of(&Endpoint::Event(EventId(400_001))).unwrap();
        let lookup = t.elapsed();
        assert_eq!(found, [GroupId(133_333)]);
        let (mn, mx) = s.group_range(GroupId(133_333)).unwrap();
        assert_eq!(mx.unwrap() - mn.unwrap(), 2 * 10_000_000);
        eprintln!("220,000 groups: range refresh {refresh:?}, member lookup {lookup:?}");
        assert!(refresh.as_secs() < 30 && lookup.as_secs() < 5);
    }
}
