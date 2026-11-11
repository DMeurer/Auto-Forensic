//! Browser history from bytes (piece B1), read with SQLite (`rusqlite`, SQLite built in: the
//! user's choice). A database is loaded into memory from its bytes, so the evidence file is never
//! opened; a database in WAL mode (Firefox) is marked as a rollback-journal one in that copy,
//! since an in-memory SQLite can't open WAL mode. A WAL or journal beside it is not merged in
//! (the plugin reports one that isn't empty).
//!
//! Chromium (Chrome, Edge, WebView2) `History`: visits, downloads and keyword searches, with the
//! columns SQLECmd's maps read. Firefox (and Tor Browser) `places.sqlite`: visits and bookmarks.
//! Both: gaps in the row IDs of the URL and visit tables (Edge on the exam image starts at URL 14:
//! rows 1 to 13 expired).

use rusqlite::{Connection, MAIN_DB, Row};

/// FILETIME ticks from 1601 to 1970.
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// One page visit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Visit {
    pub visit_id: i64,
    /// When, in FILETIME ticks.
    pub time: Option<u64>,
    pub from_visit: Option<i64>,
    /// Chromium's `transition`, Firefox's `visit_type`.
    pub transition: Option<i64>,
    /// Chromium: how long the page was shown, in microseconds.
    pub duration_us: Option<i64>,
    pub url_id: Option<i64>,
    pub url: Option<String>,
    pub title: Option<String>,
    pub visit_count: Option<i64>,
    pub typed_count: Option<i64>,
    pub hidden: Option<i64>,
    /// The URL's last visit, in FILETIME ticks.
    pub last_visit: Option<u64>,
}

/// One Chromium download.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Download {
    pub id: i64,
    pub guid: Option<String>,
    pub current_path: Option<String>,
    pub target_path: Option<String>,
    pub mime_type: Option<String>,
    pub received_bytes: Option<i64>,
    pub total_bytes: Option<i64>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub opened: Option<i64>,
    pub last_access: Option<u64>,
    /// The server's `Last-Modified` header, as text.
    pub last_modified: Option<String>,
    pub state: Option<i64>,
    pub danger_type: Option<i64>,
    pub interrupt_reason: Option<i64>,
    pub referrer: Option<String>,
    pub site_url: Option<String>,
    pub tab_url: Option<String>,
    pub tab_referrer_url: Option<String>,
    /// Its URLs, from the first asked for to the last it was served from (redirects between).
    pub url_chain: Vec<String>,
}

/// One Chromium keyword search: the term typed and the result page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Search {
    pub keyword_id: i64,
    pub url_id: i64,
    pub term: Option<String>,
    pub url: Option<String>,
    pub title: Option<String>,
    /// The result page's last visit, in FILETIME ticks (SQLECmd's time for the search).
    pub last_visit: Option<u64>,
}

/// One Firefox bookmark (or folder, or separator).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bookmark {
    pub id: i64,
    pub parent: Option<i64>,
    /// 1 bookmark, 2 folder, 3 separator.
    pub kind: Option<i64>,
    pub title: Option<String>,
    pub url: Option<String>,
    pub added: Option<u64>,
    pub modified: Option<u64>,
    pub position: Option<i64>,
    pub place_id: Option<i64>,
}

/// A run of row IDs missing from a table: rows deleted or expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub table: String,
    pub from: i64,
    pub to: i64,
}

/// What a Chromium `History` holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chromium {
    pub visits: Vec<Visit>,
    pub downloads: Vec<Download>,
    pub searches: Vec<Search>,
    pub gaps: Vec<Gap>,
}

/// What a Firefox `places.sqlite` holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Firefox {
    pub visits: Vec<Visit>,
    pub bookmarks: Vec<Bookmark>,
    pub gaps: Vec<Gap>,
}

/// A Chromium `History` database from its bytes.
pub fn chromium(data: &[u8]) -> Result<Chromium, String> {
    let c = open(data)?;
    let webkit = |r: &Row, i: usize| -> rusqlite::Result<Option<u64>> {
        Ok(r.get::<_, Option<i64>>(i)?
            .filter(|&t| t > 0)
            .map(|t| t as u64 * 10))
    };
    let visits = query(
        &c,
        "SELECT v.id, v.visit_time, v.from_visit, v.transition, v.visit_duration, u.id, u.url, \
         u.title, u.visit_count, u.typed_count, u.hidden, u.last_visit_time \
         FROM visits v LEFT JOIN urls u ON v.url = u.id ORDER BY v.id",
        |r| {
            Ok(Visit {
                visit_id: r.get(0)?,
                time: webkit(r, 1)?,
                from_visit: r.get(2)?,
                transition: r.get(3)?,
                duration_us: r.get(4)?,
                url_id: r.get(5)?,
                url: r.get(6)?,
                title: r.get(7)?,
                visit_count: r.get(8)?,
                typed_count: r.get(9)?,
                hidden: r.get(10)?,
                last_visit: webkit(r, 11)?,
            })
        },
    )?;
    let downloads = query(
        &c,
        "SELECT d.id, d.guid, d.current_path, d.target_path, d.original_mime_type, \
         d.received_bytes, d.total_bytes, d.start_time, d.end_time, d.opened, \
         d.last_access_time, d.last_modified, d.state, d.danger_type, d.interrupt_reason, \
         d.referrer, d.site_url, d.tab_url, d.tab_referrer_url \
         FROM downloads d ORDER BY d.id",
        |r| {
            Ok(Download {
                id: r.get(0)?,
                guid: r.get(1)?,
                current_path: r.get(2)?,
                target_path: r.get(3)?,
                mime_type: r.get(4)?,
                received_bytes: r.get(5)?,
                total_bytes: r.get(6)?,
                start: webkit(r, 7)?,
                end: webkit(r, 8)?,
                opened: r.get(9)?,
                last_access: webkit(r, 10)?,
                last_modified: r.get(11)?,
                state: r.get(12)?,
                danger_type: r.get(13)?,
                interrupt_reason: r.get(14)?,
                referrer: r.get(15)?,
                site_url: r.get(16)?,
                tab_url: r.get(17)?,
                tab_referrer_url: r.get(18)?,
                url_chain: vec![],
            })
        },
    )?;
    let chains: Vec<(i64, String)> = query(
        &c,
        "SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index",
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut downloads = downloads;
    for (id, url) in chains {
        if let Some(d) = downloads.iter_mut().find(|d| d.id == id) {
            d.url_chain.push(url);
        }
    }
    let searches = query(
        &c,
        "SELECT k.keyword_id, k.url_id, k.term, u.url, u.title, u.last_visit_time \
         FROM keyword_search_terms k LEFT JOIN urls u ON k.url_id = u.id ORDER BY k.url_id",
        |r| {
            Ok(Search {
                keyword_id: r.get(0)?,
                url_id: r.get(1)?,
                term: r.get(2)?,
                url: r.get(3)?,
                title: r.get(4)?,
                last_visit: webkit(r, 5)?,
            })
        },
    )?;
    Ok(Chromium {
        visits,
        downloads,
        searches,
        gaps: [gaps(&c, "urls")?, gaps(&c, "visits")?].concat(),
    })
}

/// A Firefox `places.sqlite` database from its bytes.
pub fn firefox(data: &[u8]) -> Result<Firefox, String> {
    let c = open(data)?;
    // PRTime: microseconds since 1970.
    let prtime = |r: &Row, i: usize| -> rusqlite::Result<Option<u64>> {
        Ok(r.get::<_, Option<i64>>(i)?
            .filter(|&t| t > 0)
            .map(|t| t as u64 * 10 + UNIX_EPOCH_TICKS))
    };
    let visits = query(
        &c,
        "SELECT v.id, v.visit_date, v.from_visit, v.visit_type, p.id, p.url, p.title, \
         p.visit_count, p.typed, p.hidden, p.last_visit_date \
         FROM moz_historyvisits v LEFT JOIN moz_places p ON v.place_id = p.id ORDER BY v.id",
        |r| {
            Ok(Visit {
                visit_id: r.get(0)?,
                time: prtime(r, 1)?,
                from_visit: r.get(2)?,
                transition: r.get(3)?,
                duration_us: None,
                url_id: r.get(4)?,
                url: r.get(5)?,
                title: r.get(6)?,
                visit_count: r.get(7)?,
                typed_count: r.get(8)?,
                hidden: r.get(9)?,
                last_visit: prtime(r, 10)?,
            })
        },
    )?;
    let bookmarks = query(
        &c,
        "SELECT b.id, b.parent, b.type, b.title, p.url, b.dateAdded, b.lastModified, \
         b.position, b.fk FROM moz_bookmarks b LEFT JOIN moz_places p ON b.fk = p.id \
         ORDER BY b.id",
        |r| {
            Ok(Bookmark {
                id: r.get(0)?,
                parent: r.get(1)?,
                kind: r.get(2)?,
                title: r.get(3)?,
                url: r.get(4)?,
                added: prtime(r, 5)?,
                modified: prtime(r, 6)?,
                position: r.get(7)?,
                place_id: r.get(8)?,
            })
        },
    )?;
    Ok(Firefox {
        visits,
        bookmarks,
        gaps: [gaps(&c, "moz_places")?, gaps(&c, "moz_historyvisits")?].concat(),
    })
}

/// The database in memory, read-only.
fn open(data: &[u8]) -> Result<Connection, String> {
    if data.len() < 100 || !data.starts_with(b"SQLite format 3\0") {
        return Err("not an SQLite database".into());
    }
    let mut copy = data.to_vec();
    // Bytes 18 and 19 are the write and read format: 2 is WAL, which an in-memory database
    // can't open. 1 is the rollback journal; the pages are the same.
    if copy[18] == 2 || copy[19] == 2 {
        copy[18] = 1;
        copy[19] = 1;
    }
    let mut c = Connection::open_in_memory().map_err(|e| e.to_string())?;
    let len = copy.len();
    c.deserialize_read_exact(MAIN_DB, std::io::Cursor::new(copy), len, true)
        .map_err(|e| e.to_string())?;
    Ok(c)
}

fn query<T>(
    c: &Connection,
    sql: &str,
    row: impl FnMut(&Row) -> rusqlite::Result<T>,
) -> Result<Vec<T>, String> {
    let mut s = c.prepare(sql).map_err(|e| e.to_string())?;
    let rows = s.query_map([], row).map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<T>>>()
        .map_err(|e| e.to_string())
}

/// The runs of IDs missing from `table`, from 1 to the highest ID it has or, for an
/// AUTOINCREMENT table, ever had (`sqlite_sequence`).
fn gaps(c: &Connection, table: &str) -> Result<Vec<Gap>, String> {
    let ids: Vec<i64> = query(c, &format!("SELECT id FROM {table} ORDER BY id"), |r| {
        r.get(0)
    })?;
    let seq: Option<i64> = c
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = ?1",
            [table],
            |r| r.get(0),
        )
        .ok();
    let last = seq.max(ids.last().copied()).unwrap_or(0);
    let (mut out, mut next) = (vec![], 1);
    for id in ids.into_iter().chain(std::iter::once(last + 1)) {
        if id > next {
            out.push(Gap {
                table: table.into(),
                from: next,
                to: id - 1,
            });
        }
        next = next.max(id + 1);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small Chromium History built with SQLite, as bytes.
    fn history() -> Vec<u8> {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT,
               visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER,
               visit_time INTEGER, from_visit INTEGER, transition INTEGER,
               visit_duration INTEGER);
             CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT,
               target_path TEXT, original_mime_type TEXT, received_bytes INTEGER,
               total_bytes INTEGER, start_time INTEGER, end_time INTEGER, opened INTEGER,
               last_access_time INTEGER, last_modified TEXT, state INTEGER, danger_type INTEGER,
               interrupt_reason INTEGER, referrer TEXT, site_url TEXT, tab_url TEXT,
               tab_referrer_url TEXT);
             CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
             CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER,
               term TEXT, normalized_term TEXT);
             INSERT INTO urls VALUES (14, 'https://example.org/', 'Example', 2, 0,
               13421000000000000, 0);
             INSERT INTO urls VALUES (16, 'https://www.google.com/search?q=x', 'x', 1, 0,
               13421000500000000, 0);
             INSERT INTO visits VALUES (21, 14, 13421000000000000, 0, 805306368, 1500000);
             INSERT INTO downloads VALUES (1, 'g', 'C:\\d\\t.exe', 'C:\\d\\t.exe', '', 10, 10,
               13421000100000000, 13421000200000000, 0, 0, '', 1, 0, 0, '', '', '', '');
             INSERT INTO downloads_url_chains VALUES (1, 0, 'https://a/'), (1, 1, 'https://b/');
             INSERT INTO keyword_search_terms VALUES (2, 16, 'x', 'x');",
        )
        .unwrap();
        c.serialize(MAIN_DB).unwrap().to_vec()
    }

    #[test]
    fn chromium_history() {
        let h = chromium(&history()).unwrap();
        assert_eq!(h.visits.len(), 1);
        let v = &h.visits[0];
        // WebKit microseconds since 1601, as ticks.
        assert_eq!(v.time, Some(134_210_000_000_000_000));
        assert_eq!(
            (v.url.as_deref(), v.duration_us),
            (Some("https://example.org/"), Some(1_500_000))
        );
        assert_eq!(h.downloads[0].url_chain, ["https://a/", "https://b/"]);
        assert_eq!(h.searches[0].term.as_deref(), Some("x"));
        // URL rows 1 to 13 and 15 gone; visits 1 to 20.
        let gap = |t: &str, from, to| Gap {
            table: t.into(),
            from,
            to,
        };
        assert_eq!(
            h.gaps,
            [
                gap("urls", 1, 13),
                gap("urls", 15, 15),
                gap("visits", 1, 20)
            ]
        );
    }

    #[test]
    fn wal_mode_and_damage() {
        let mut h = history();
        h[18] = 2;
        h[19] = 2;
        assert_eq!(chromium(&h).unwrap().visits.len(), 1);
        assert!(chromium(b"MZ").is_err());
        let mut cut = history();
        cut.truncate(cut.len() / 2);
        assert!(chromium(&cut).is_err());
        // A database without the tables isn't a History.
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t (a);").unwrap();
        assert!(chromium(&c.serialize(MAIN_DB).unwrap()).is_err());
    }
}
