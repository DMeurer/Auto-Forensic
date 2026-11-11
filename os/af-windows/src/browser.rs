//! Browser history (piece B1): every Chromium `History` (Chrome, Edge, WebView2) and Firefox
//! `places.sqlite` (Firefox, Tor Browser) the profile finds below the user profiles, read with
//! `af-fmt-browser` from its bytes. Visits, downloads, keyword searches and bookmarks become
//! records with their times as events; gaps in a database's row IDs become facts (rows deleted
//! or expired). A journal or WAL beside a database that isn't empty is a note: what it holds
//! isn't merged in.

use af_core::artifact::Artifact;
use af_core::bytes::Locator;
use af_core::ids::{EventId, FactId, record_id};
use af_core::names::Kind;
use af_core::plugin::{Input, Manifest, Outcome, Phase};
use af_core::runner::{NewEvent, NewFact, Plugin, RunContext};
use af_core::system::Family;
use af_core::time::Time;
use af_core::timeline::{ClockDomainId, TimeMeaning};
use std::sync::OnceLock;

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
            version: 1,
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
                    }
                    Err(e) => out.note(format!("browser history {path} wasn't read: {e}")),
                },
                _ => {}
            }
        }
        Outcome::Ok(out.n)
    }
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
    ) {
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
            self.ctx.sink.event(
                &self.id,
                self.ctx.system.id,
                NewEvent {
                    id: EventId::derive(&source_text, &locator, None, &kind, &meaning, 0),
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
        self.row(
            a,
            &row,
            "browser.visit",
            attrs,
            &[("browser.visit", v.time)],
        );
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
        self.row(
            a,
            &row,
            "browser.search",
            attrs,
            &[("browser.search", s.last_visit)],
        );
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
