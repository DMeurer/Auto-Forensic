//! The project store (piece F16): one DuckDB file per project.
//!
//! Tables:
//! - `project`: one row, the project's name, creation time and creating af version (F19).
//! - `sources` and `source_files`: what was added, with hashes and where its files are (F20).
//!   Records, events and entities carry their `source`, so removing a source removes them.
//! - `records`: what a source row is, shared by all its events (one `$MFT` record gives several
//!   time events). Typed columns every source has, plus `attrs`, JSON text for the rest.
//! - `events`: one row per timestamp, pointing at its record. The time columns are exactly
//!   [`TimeColumns`], never DuckDB timestamp types, so nothing is clamped or converted.
//! - `entities`: users, devices, interfaces and other things events refer to.
//! - `links`: directed links between endpoints, in the stored form of [`Endpoint`].
//!
//! Every row records who made it (`created_by`: a plugin ID or `user`). No primary keys or
//! indexes: they slow bulk loads, and F17 loads events sorted by time instead.
//!
//! [`Endpoint`]: af_core::ids::Endpoint

use af_core::time::TimeColumns;
use duckdb::{Connection, params};
use std::path::Path;

pub mod project;
pub mod source;

pub use duckdb::Error;

/// The tables. `attrs` is VARCHAR holding JSON text.
// shortcut: JSON as VARCHAR, not the JSON type, so the json extension isn't compiled in; switch when queries need json functions.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS project (
    name VARCHAR NOT NULL,
    created_unix BIGINT NOT NULL,
    created_by_version VARCHAR NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    id UHUGEINT NOT NULL,
    kind VARCHAR NOT NULL,
    label VARCHAR NOT NULL,
    size UBIGINT NOT NULL,
    sha256 VARCHAR NOT NULL,
    fingerprint VARCHAR NOT NULL,
    added_unix BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_files (
    source UHUGEINT NOT NULL,
    seq INTEGER NOT NULL,
    path VARCHAR NOT NULL,
    size UBIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id UHUGEINT NOT NULL,
    source UHUGEINT NOT NULL,
    system UHUGEINT NOT NULL,
    kind VARCHAR NOT NULL,
    locator VARCHAR NOT NULL,
    byte_offset UBIGINT,
    path_display VARCHAR,
    path_key VARCHAR,
    file_scheme VARCHAR,
    file_value BLOB,
    user_scheme VARCHAR,
    user_value VARCHAR,
    attrs VARCHAR,
    created_by VARCHAR NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id UHUGEINT NOT NULL,
    source UHUGEINT NOT NULL,
    record UHUGEINT NOT NULL,
    system UHUGEINT NOT NULL,
    kind VARCHAR NOT NULL,
    meaning VARCHAR NOT NULL,
    ts BIGINT,
    ts_min BIGINT,
    ts_max BIGINT,
    raw_i64 BIGINT,
    raw_text VARCHAR,
    raw_encoding VARCHAR NOT NULL,
    time_status VARCHAR NOT NULL,
    precision_ticks BIGINT NOT NULL,
    tz_status VARCHAR NOT NULL,
    tz_offset_min SMALLINT,
    conversion_version USMALLINT NOT NULL,
    clock_domain VARCHAR NOT NULL,
    seq_domain VARCHAR,
    seq_no BIGINT,
    created_by VARCHAR NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
    id UHUGEINT NOT NULL,
    source UHUGEINT NOT NULL,
    system UHUGEINT NOT NULL,
    kind VARCHAR NOT NULL,
    key VARCHAR NOT NULL,
    attrs VARCHAR,
    created_by VARCHAR NOT NULL
);
CREATE TABLE IF NOT EXISTS links (
    id UHUGEINT NOT NULL,
    kind VARCHAR NOT NULL,
    from_kind VARCHAR NOT NULL,
    from_id UHUGEINT,
    from_system UHUGEINT,
    from_file_scheme VARCHAR,
    from_file_value BLOB,
    to_kind VARCHAR NOT NULL,
    to_id UHUGEINT,
    to_system UHUGEINT,
    to_file_scheme VARCHAR,
    to_file_value BLOB,
    created_by VARCHAR NOT NULL
);
";

/// An open project store.
pub struct Store {
    conn: Connection,
}

/// One event row. The record and its attributes are stored separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub id: u128,
    /// The source it came from, so removing the source removes it (F20).
    pub source: u128,
    pub record: u128,
    pub system: u128,
    pub kind: String,
    pub meaning: String,
    pub time: TimeColumns,
    pub clock_domain: String,
    pub seq_domain: Option<String>,
    pub seq_no: Option<i64>,
    pub created_by: String,
}

impl Store {
    /// Opens or creates the store at `path` with the safe settings from stage 1: at most
    /// `memory_limit_mb`, 4 threads, and no insertion-order guarantee (which bulk loads need).
    pub fn open(path: &Path, memory_limit_mb: u32) -> Result<Self, Error> {
        Self::setup(Connection::open(path)?, memory_limit_mb)
    }

    /// An in-memory store, for tests.
    pub fn in_memory(memory_limit_mb: u32) -> Result<Self, Error> {
        Self::setup(Connection::open_in_memory()?, memory_limit_mb)
    }

    fn setup(conn: Connection, memory_limit_mb: u32) -> Result<Self, Error> {
        conn.execute_batch(&format!(
            "SET memory_limit = '{memory_limit_mb}MB'; SET threads = 4; \
             SET preserve_insertion_order = false;"
        ))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// The underlying connection, for queries not wrapped here yet.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn insert_events(&mut self, rows: &[EventRow]) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        {
            let mut app = tx.appender("events")?;
            for r in rows {
                let t = &r.time;
                app.append_row(params![
                    r.id,
                    r.source,
                    r.record,
                    r.system,
                    r.kind,
                    r.meaning,
                    t.ts,
                    t.ts_min,
                    t.ts_max,
                    t.raw_i64,
                    t.raw_text,
                    t.raw_encoding,
                    t.time_status,
                    t.precision_ticks,
                    t.tz_status,
                    t.tz_offset_min,
                    t.conversion_version,
                    r.clock_domain,
                    r.seq_domain,
                    r.seq_no,
                    r.created_by,
                ])?;
            }
        }
        tx.commit()
    }

    /// Loads spool files (stores written by plugins during a run, each opened with
    /// [`Store::open`] on its own temporary path) into this store. Events go in sorted by time
    /// (no time last), then ID; records, entities and links as they are. Returns the number of
    /// events loaded. Chosen over a Parquet spool by benchmark (F17, 50M rows): faster in both
    /// phases, less RAM and disk, and 128-bit IDs survive.
    pub fn load_spools(&mut self, spools: &[&Path]) -> Result<u64, Error> {
        if spools.is_empty() {
            return Ok(0);
        }
        for (i, p) in spools.iter().enumerate() {
            let path = p.to_string_lossy().replace('\'', "''");
            self.conn
                .execute_batch(&format!("ATTACH '{path}' AS spool{i} (READ_ONLY);"))?;
        }
        let union = |table: &str| {
            (0..spools.len())
                .map(|i| format!("SELECT * FROM spool{i}.{table}"))
                .collect::<Vec<_>>()
                .join(" UNION ALL ")
        };
        let result = (|| {
            let tx = self.conn.transaction()?;
            for table in ["records", "entities", "links"] {
                tx.execute_batch(&format!("INSERT INTO {table} {};", union(table)))?;
            }
            let n = tx.execute(
                &format!(
                    "INSERT INTO events SELECT * FROM ({}) ORDER BY ts NULLS LAST, id",
                    union("events")
                ),
                [],
            )?;
            tx.commit()?;
            Ok(n as u64)
        })();
        for i in 0..spools.len() {
            self.conn.execute_batch(&format!("DETACH spool{i};"))?;
        }
        result
    }

    /// All events, ordered by ID.
    pub fn events(&self) -> Result<Vec<EventRow>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, source, record, system, kind, meaning, ts, ts_min, ts_max, raw_i64, raw_text, \
             raw_encoding, time_status, precision_ticks, tz_status, tz_offset_min, \
             conversion_version, clock_domain, seq_domain, seq_no, created_by \
             FROM events ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(EventRow {
                id: r.get(0)?,
                source: r.get(1)?,
                record: r.get(2)?,
                system: r.get(3)?,
                kind: r.get(4)?,
                meaning: r.get(5)?,
                time: TimeColumns {
                    ts: r.get(6)?,
                    ts_min: r.get(7)?,
                    ts_max: r.get(8)?,
                    raw_i64: r.get(9)?,
                    raw_text: r.get(10)?,
                    raw_encoding: r.get(11)?,
                    time_status: r.get(12)?,
                    precision_ticks: r.get(13)?,
                    tz_status: r.get(14)?,
                    tz_offset_min: r.get(15)?,
                    conversion_version: r.get(16)?,
                },
                clock_domain: r.get(17)?,
                seq_domain: r.get(18)?,
                seq_no: r.get(19)?,
                created_by: r.get(20)?,
            })
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_core::time::{RawTime, RawValue, Time, TimeStatus};

    fn tricky_times() -> Vec<Time> {
        let dos_date = ((2026 - 1980) << 9) | (4 << 5) | 26;
        let mut text = Time::from_unix_seconds(0);
        text.key = None;
        text.min = None;
        text.max = None;
        text.raw = RawTime {
            encoding: "text".into(),
            value: RawValue::Text("Nov  5 14:30:20".into()),
        };
        text.status = TimeStatus::YearInferred;
        vec![
            Time::from_ticks_1601(0),
            Time::from_ticks_1601(i64::MAX as u64),
            Time::from_ticks_1601(u64::MAX),
            Time::from_unix_seconds(i64::MIN),
            Time::from_unix_nanos(-1),
            Time::from_dos_local(dos_date, 0x7400, Some(199)),
            Time::from_dos_local_date(dos_date).with_local_offset(-330, true),
            text,
        ]
    }

    #[test]
    fn time_columns_are_stored_unchanged() {
        let mut store = Store::in_memory(256).unwrap();
        let times = tricky_times();
        let rows: Vec<EventRow> = times
            .iter()
            .enumerate()
            .map(|(i, t)| EventRow {
                id: u128::MAX - i as u128,
                source: 3,
                record: 7,
                system: u128::MAX,
                kind: "test.event".into(),
                meaning: "test.written".into(),
                time: t.to_columns(),
                clock_domain: "wall".into(),
                seq_domain: (i % 2 == 0).then(|| "test.seq".into()),
                seq_no: (i % 2 == 0).then_some(i64::MIN + i as i64),
                created_by: "test.plugin".into(),
            })
            .collect();
        store.insert_events(&rows).unwrap();
        let mut back = store.events().unwrap();
        back.reverse(); // ordered by ID, which counts down
        assert_eq!(back, rows);
        for (row, t) in back.iter().zip(&times) {
            assert_eq!(&Time::from_columns(&row.time).unwrap(), t);
        }
    }

    fn event(id: u128, ts: Option<i64>) -> EventRow {
        let time = match ts {
            Some(t) => Time::from_ticks_1601(t as u64),
            None => Time::from_ticks_1601(0),
        };
        EventRow {
            id,
            source: 1,
            record: id,
            system: 1,
            kind: "test.event".into(),
            meaning: "test.written".into(),
            time: time.to_columns(),
            clock_domain: "wall".into(),
            seq_domain: None,
            seq_no: None,
            created_by: "test.plugin".into(),
        }
    }

    /// Whether the events table is stored in time order: `rowid` is the physical position.
    fn physically_sorted(store: &Store) -> bool {
        let back: i64 = store
            .connection()
            .query_row(
                "SELECT count(*) FROM (SELECT ts < lag(ts) OVER (ORDER BY rowid) AS back \
                 FROM events WHERE ts IS NOT NULL) WHERE back",
                [],
                |r| r.get(0),
            )
            .unwrap();
        back == 0
    }

    #[test]
    fn spools_load_sorted_by_time() {
        let dir = std::env::temp_dir().join(format!("af-spool-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("spool-a.duckdb"), dir.join("spool-b.duckdb"));
        // Two writers, each out of order, one with an event without time. u128 IDs above 2^64.
        let big = 1u128 << 100;
        Store::open(&a, 256)
            .unwrap()
            .insert_events(&[
                event(big + 3, Some(300)),
                event(big + 1, Some(100)),
                event(big + 9, None),
            ])
            .unwrap();
        Store::open(&b, 256)
            .unwrap()
            .insert_events(&[event(big + 2, Some(200)), event(big + 4, Some(50))])
            .unwrap();
        let mut project = Store::in_memory(256).unwrap();
        assert_eq!(project.load_spools(&[&a, &b]).unwrap(), 5);
        let ids: Vec<u128> = project
            .connection()
            .prepare("SELECT id FROM events ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(ids, [big + 4, big + 1, big + 2, big + 3, big + 9]);
        assert!(physically_sorted(&project));
        // Spools are detached again, so their files can be deleted.
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// F17's "done when": 100M synthetic rows load at the memory limit. About 15 GB of disk at
    /// peak and a few minutes; run by hand with `cargo test -p af-store --release -- --ignored`.
    #[test]
    #[ignore]
    fn load_100m_rows_at_the_memory_limit() {
        let dir = std::env::temp_dir().join(format!("af-spool-100m-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spools: Vec<_> = (0..4)
            .map(|w| dir.join(format!("spool-{w}.duckdb")))
            .collect();
        for (w, p) in spools.iter().enumerate() {
            // Generated in SQL: the appender's speed isn't what this test measures.
            Store::open(p, 1024)
                .unwrap()
                .connection()
                .execute_batch(&format!(
                    "INSERT INTO events SELECT ({w}::UHUGEINT << 64) + i::UHUGEINT, {w}, i // 8, {w}, \
                     'bench.event', 'bench.written', \
                     (130000000000000000 + hash(i, {w}) % 40000000000000000)::BIGINT AS t, t, t, t, \
                     NULL, 'ticks_1601', 'ok', 1, 'utc', NULL, 1, 'wall', NULL, NULL, 'bench' \
                     FROM range(25000000) r(i);"
                ))
                .unwrap();
        }
        let start = std::time::Instant::now();
        let mut project = Store::open(&dir.join("project.duckdb"), 5120).unwrap();
        let refs: Vec<&Path> = spools.iter().map(|p| p.as_path()).collect();
        assert_eq!(project.load_spools(&refs).unwrap(), 100_000_000);
        eprintln!("loaded 100M in {:?}", start.elapsed());
        assert!(physically_sorted(&project));
        drop(project);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn safe_settings_are_applied() {
        let store = Store::in_memory(512).unwrap();
        let get = |name: &str| -> String {
            store
                .connection()
                .query_row(
                    &format!("SELECT current_setting('{name}')::VARCHAR"),
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(get("threads"), "4");
        assert_eq!(get("preserve_insertion_order"), "false");
        assert!(
            get("memory_limit").contains("488") || get("memory_limit").contains("512"),
            "{}",
            get("memory_limit")
        );
    }

    #[test]
    fn schema_has_all_four_tables_and_reopens() {
        let dir = std::env::temp_dir().join(format!("af-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("project.duckdb");
        drop(Store::open(&path, 256).unwrap());
        let store = Store::open(&path, 256).unwrap(); // CREATE IF NOT EXISTS: reopening is fine
        let n: i64 = store
            .connection()
            .query_row(
                "SELECT count(*) FROM information_schema.tables \
                 WHERE table_name IN ('records', 'events', 'entities', 'links')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 4);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
