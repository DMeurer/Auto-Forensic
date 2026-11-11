//! Browser history (piece B1): every Chromium `History` (Chrome, Edge, WebView2) and Firefox
//! `places.sqlite` (Firefox, Tor Browser) the profile finds below the user profiles, read with
//! `af-fmt-browser` from its bytes. Visits, downloads, keyword searches and bookmarks become
//! records with their times as events; gaps in a database's row IDs become facts (rows deleted
//! or expired). A journal or WAL beside a database that isn't empty is a note: what it holds
//! isn't merged in.

use af_core::artifact::Artifact;
use af_core::bytes::Locator;
use af_core::ids::{Endpoint, EventId, FactId, GroupId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewFact, NewGroup, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

/// B2: a longer pause between a host's visits starts a new session (the user's choice).
const SESSION_PAUSE: u64 = 30 * 60 * 10_000_000;

const INPUTS: [&str; 3] = [
    "browser.chromium.history",
    "browser.firefox.places",
    "browser.sqlite.journal",
];

/// Every browser history database as records, events and gap facts.
pub struct BrowserHistory;

impl Plugin for BrowserHistory {
    fn manifest(&self) -> &Manifest {
        static M: OnceLock<Manifest> = OnceLock::new();
        M.get_or_init(|| Manifest {
            id: Kind::new("browser.history").expect("valid kind"),
            // 2: search terms as facts and session groups (B2).
            version: 2,
            applies_to: vec![Family::Windows],
            phases: vec![Phase::Extract],
            inputs: INPUTS
                .iter()
                .map(|k| Input {
                    kind: Kind::new(k).expect("valid kind"),
                    required: false,
                })
                .collect(),
            needs: vec![],
            produces: [
                "browser.visit",
                "browser.download",
                "browser.download.started",
                "browser.download.finished",
                "browser.search",
                "browser.bookmark",
                "browser.bookmark.added",
                "browser.bookmark.modified",
                "browser.history.gap",
                "browser.search_term",
                "browser.session",
            ]
            .into_iter()
            .map(|k| Kind::new(k).expect("valid kind"))
            .collect(),
        })
    }

    fn extract(&self, ctx: &mut RunContext<'_>) -> Outcome {
        let Some(opener) = ctx.opener else {
            return Outcome::NotAcquired;
        };
        let mut out = Out {
            ctx,
            id: self.manifest().id.clone(),
            n: 0,
            sites: vec![],
        };
        let artifacts: Vec<Artifact> = out
            .ctx
            .artifacts
            .iter()
            .filter(|a| INPUTS.contains(&a.kind.as_str()))
            .cloned()
            .collect();
        for a in &artifacts {
            let path = a
                .locator
                .steps()
                .last()
                .map_or("", |s| s.id.as_str())
                .to_string();
            let data = opener.open(a).and_then(|src| {
                let mut buf = vec![0; usize::try_from(src.len()).map_err(std::io::Error::other)?];
                src.read_exact_at(0, &mut buf).map(|()| buf)
            });
            let data = match data {
                Ok(d) => d,
                Err(e) => {
                    out.note(format!("browser file {path} wasn't read: {e}"));
                    continue;
                }
            };
            let browser = browser_of(&path);
            match a.kind.as_str() {
                "browser.sqlite.journal" if !data.is_empty() => out.note(format!(
                    "{path} holds {} bytes not merged into its database",
                    data.len()
                )),
                "browser.chromium.history" => match af_fmt_browser::chromium(&data) {
                    Ok(h) => {
                        for v in h.visits {
                            out.visit(a, browser, &v);
                        }
                        for d in h.downloads {
                            out.download(a, browser, &d);
                        }
                        for s in h.searches {
                            out.search(a, browser, &s);
                        }
                        for g in h.gaps {
                            out.gap(a, &g);
                        }
                        out.sessions(a);
                    }
                    Err(e) => out.note(format!("browser history {path} wasn't read: {e}")),
                },
                "browser.firefox.places" => match af_fmt_browser::firefox(&data) {
                    Ok(f) => {
                        for v in f.visits {
                            out.visit(a, browser, &v);
                        }
                        for b in f.bookmarks {
                            out.bookmark(a, browser, &b);
                        }
                        for g in f.gaps {
                            out.gap(a, &g);
                        }
                        out.sessions(a);
                    }
                    Err(e) => out.note(format!("browser history {path} wasn't read: {e}")),
                },
                _ => {}
            }
        }
        Outcome::Ok(out.n)
    }
}

/// The host of a web URL, lower case, without user or port; `None` for other URLs
/// (`file:`, `chrome:`, `about:`).
fn host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ftp"
    ) {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The browser a database belongs to, from its path.
fn browser_of(path: &str) -> &'static str {
    let p = path.to_lowercase();
    [
        ("tor browser", "tor"),
        ("ebwebview", "webview2"),
        ("microsoft/edge", "edge"),
        ("google/chrome", "chrome"),
        ("mozilla/firefox", "firefox"),
    ]
    .into_iter()
    .find(|(part, _)| p.contains(part))
    .map_or(
        if p.ends_with("places.sqlite") {
            "firefox-like"
        } else {
            "chromium-like"
        },
        |(_, b)| b,
    )
}

struct Out<'c, 'a> {
    ctx: &'c mut RunContext<'a>,
    id: Kind,
    n: u64,
    /// This database's events by host, for B2's session groups: (host, time, event).
    sites: Vec<(String, u64, EventId)>,
}

impl Out<'_, '_> {
    fn note(&mut self, text: String) {
        self.ctx.sink.note(&self.id, self.ctx.system.id, text);
    }

    /// A row as a record, and its times as events.
    fn row(
        &mut self,
        a: &Artifact,
        row: &str,
        kind: &str,
        attrs: serde_json::Value,
        times: &[(&str, Option<u64>)],
    ) -> Vec<(u64, EventId)> {
        let mut made = vec![];
        let locator = a.locator.child("sqlite.row", row);
        let source_text = a.source.to_string();
        let record = record_id(&source_text, &locator);
        self.ctx.sink.record(
            &self.id,
            self.ctx.system.id,
            af_core::runner::NewRecord {
                id: record,
                source: a.source,
                kind: Kind::new(kind).expect("valid kind"),
                locator: locator.clone(),
                attrs: Some(attrs.to_string()),
            },
        );
        for (k, t) in times {
            let Some(ticks) = t else { continue };
            let kind = Kind::new(k).expect("valid kind");
            let meaning = TimeMeaning::new(k).expect("valid meaning");
            let event = EventId::derive(&source_text, &locator, None, &kind, &meaning, 0);
            made.push((*ticks, event));
            self.ctx.sink.event(
                &self.id,
                self.ctx.system.id,
                NewEvent {
                    id: event,
                    source: a.source,
                    record,
                    kind,
                    meaning,
                    time: Time::from_ticks_1601(*ticks),
                    clock: ClockDomainId("wall".into()),
                    seq: None,
                },
            );
            self.n += 1;
        }
        made
    }

    fn visit(&mut self, a: &Artifact, browser: &str, v: &af_fmt_browser::Visit) {
        let attrs = serde_json::json!({
            "browser": browser,
            "url": v.url,
            "title": v.title,
            "visit_id": v.visit_id,
            "from_visit": v.from_visit,
            "transition": v.transition,
            "duration_us": v.duration_us,
            "url_id": v.url_id,
            "visit_count": v.visit_count,
            "typed_count": v.typed_count,
            "hidden": v.hidden,
        });
        let row = format!("visits/{}", v.visit_id);
        let made = self.row(
            a,
            &row,
            "browser.visit",
            attrs,
            &[("browser.visit", v.time)],
        );
        self.at_site(v.url.as_deref(), made);
    }

    fn download(&mut self, a: &Artifact, browser: &str, d: &af_fmt_browser::Download) {
        let attrs = serde_json::json!({
            "browser": browser,
            "target_path": d.target_path,
            "current_path": d.current_path,
            "url_chain": d.url_chain,
            "referrer": d.referrer,
            "tab_url": d.tab_url,
            "site_url": d.site_url,
            "mime_type": d.mime_type,
            "received_bytes": d.received_bytes,
            "total_bytes": d.total_bytes,
            "state": d.state,
            "danger_type": d.danger_type,
            "interrupt_reason": d.interrupt_reason,
            "opened": d.opened,
            "guid": d.guid,
        });
        let row = format!("downloads/{}", d.id);
        self.row(
            a,
            &row,
            "browser.download",
            attrs,
            &[
                ("browser.download.started", d.start),
                ("browser.download.finished", d.end),
            ],
        );
    }

    fn search(&mut self, a: &Artifact, browser: &str, s: &af_fmt_browser::Search) {
        let attrs = serde_json::json!({
            "browser": browser,
            "term": s.term,
            "url": s.url,
            "title": s.title,
            "keyword_id": s.keyword_id,
        });
        let row = format!("keyword_search_terms/{}", s.url_id);
        // The result page's last visit, as SQLECmd dates a search.
        let made = self.row(
            a,
            &row,
            "browser.search",
            attrs,
            &[("browser.search", s.last_visit)],
        );
        self.at_site(s.url.as_deref(), made);
        // B2: the term as a fact.
        if let Some(term) = s.term.as_deref().filter(|t| !t.is_empty()) {
            let kind = Kind::new("browser.search_term").expect("valid kind");
            let locator = a.locator.child("sqlite.row", &row);
            self.ctx.sink.fact(
                &self.id,
                self.ctx.system.id,
                NewFact {
                    id: FactId::derive(&a.source.to_string(), &locator, &kind, term),
                    source: a.source,
                    kind,
                    subject: term.to_string(),
                    attrs: Some(
                        serde_json::json!({ "browser": browser, "url": s.url }).to_string(),
                    ),
                },
            );
        }
    }

    /// Remembers events for the session groups of the URL's host.
    fn at_site(&mut self, url: Option<&str>, made: Vec<(u64, EventId)>) {
        if let Some(h) = url.and_then(host) {
            self.sites
                .extend(made.into_iter().map(|(t, e)| (h.clone(), t, e)));
        }
    }

    /// B2: one group per host and session (the user's choices): a host's visits and searches,
    /// until a pause of more than 30 minutes.
    fn sessions(&mut self, a: &Artifact) {
        let mut sites = std::mem::take(&mut self.sites);
        sites.sort();
        let kind = Kind::new("browser.session").expect("valid kind");
        let mut start = 0;
        for i in 1..=sites.len() {
            let ends = i == sites.len()
                || sites[i].0 != sites[i - 1].0
                || sites[i].1 - sites[i - 1].1 > SESSION_PAUSE;
            if !ends {
                continue;
            }
            let run = &sites[start..i];
            let (host, first) = (&run[0].0, run[0].2);
            let id = FactId::derive(
                &a.source.to_string(),
                &a.locator,
                &kind,
                &format!("{host} {}", first.0),
            );
            self.ctx.sink.group(
                &self.id,
                NewGroup {
                    id: GroupId(id.0),
                    kind: kind.clone(),
                    reason: format!(
                        "{} browser event{} at {host}, no pause over 30 minutes",
                        run.len(),
                        if run.len() == 1 { "" } else { "s" }
                    ),
                    members: run.iter().map(|(_, _, e)| Endpoint::Event(*e)).collect(),
                },
            );
            start = i;
        }
    }

    fn bookmark(&mut self, a: &Artifact, browser: &str, b: &af_fmt_browser::Bookmark) {
        let attrs = serde_json::json!({
            "browser": browser,
            "title": b.title,
            "url": b.url,
            "type": b.kind,
            "parent": b.parent,
            "position": b.position,
        });
        let row = format!("moz_bookmarks/{}", b.id);
        self.row(
            a,
            &row,
            "browser.bookmark",
            attrs,
            &[
                ("browser.bookmark.added", b.added),
                ("browser.bookmark.modified", b.modified),
            ],
        );
    }

    fn gap(&mut self, a: &Artifact, g: &af_fmt_browser::Gap) {
        let kind = Kind::new("browser.history.gap").expect("valid kind");
        let subject = format!("{} {}-{}", g.table, g.from, g.to);
        let locator: Locator = a.locator.clone();
        self.ctx.sink.fact(
            &self.id,
            self.ctx.system.id,
            NewFact {
                id: FactId::derive(&a.source.to_string(), &locator, &kind, &subject),
                source: a.source,
                kind,
                subject,
                attrs: Some(
                    serde_json::json!({ "table": g.table, "from": g.from, "to": g.to }).to_string(),
                ),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(
            host("https://www.Google.com/search?q=x").as_deref(),
            Some("www.google.com")
        );
        assert_eq!(
            host("http://192.168.2.57:8080/upload").as_deref(),
            Some("192.168.2.57")
        );
        assert_eq!(
            host("http://user@example.org").as_deref(),
            Some("example.org")
        );
        assert_eq!(host("http://[::1]:80/").as_deref(), Some("::1"));
        assert_eq!(host("file:///C:/x.html"), None);
        assert_eq!(host("chrome://settings"), None);
    }
}
