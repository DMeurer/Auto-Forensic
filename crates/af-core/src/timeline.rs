//! What a time means, which clock it came from, its sequence, and the timeline order (piece F5).
//!
//! An event's time is a [`Time`] plus:
//!
//! - a **meaning**, a namespaced name such as `ntfs.si.modified` or `ext4.crtime` instead of fixed
//!   MACB columns;
//! - a **clock domain**: wall clock, monotonic or logical, with an optional boot reference and skew
//!   estimate. Skew is applied when querying, never to stored values;
//! - an optional **sequence**: a number within a named domain (record numbers of one log file,
//!   update sequence numbers of one journal), for ordering where the clock fails.
//!
//! [`timeline_order`] sorts events by time, and an event without a time by its sequence: it
//! borrows the time of the nearest earlier event in its sequence that has one (or, if none, the
//! nearest later one) and sorts right next to it, marked as borrowed.

use crate::time::{Time, TimeKey};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

/// A namespaced time meaning: lowercase dotted segments of `a-z`, `0-9` and `_`, at least two,
/// such as `ntfs.si.modified`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TimeMeaning(String);

impl TimeMeaning {
    pub fn new(name: &str) -> Result<Self, NameError> {
        check_name(name).map(|()| Self(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A name that isn't a valid namespaced name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameError(pub String);

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not a namespaced name (lowercase dotted segments, at least two)",
            self.0
        )
    }
}

impl std::error::Error for NameError {}

fn check_name(name: &str) -> Result<(), NameError> {
    let segments: Vec<&str> = name.split('.').collect();
    let ok = segments.len() >= 2
        && segments.iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        });
    if ok {
        Ok(())
    } else {
        Err(NameError(name.to_string()))
    }
}

/// What kind of clock a time came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClockKind {
    /// Calendar time, comparable across sources once skew is known.
    Wall,
    /// Counts from a boot or another start; comparable only within that start.
    Monotonic,
    /// An order without a clock, such as change IDs.
    Logical,
}

/// The ID of a clock domain, unique within a project.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClockDomainId(pub String);

/// A clock that times come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockDomain {
    pub id: ClockDomainId,
    pub kind: ClockKind,
    /// For a monotonic clock: what it counts from, such as a boot ID.
    pub boot_ref: Option<String>,
    /// Estimated offset of this clock from true time, in ticks (positive: the clock runs ahead).
    /// Applied when querying, never to the stored values.
    pub skew_ticks: Option<i64>,
}

/// A position within a named sequence, such as record 812 of one log file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sequence {
    /// The sequence's name, unique within a project, for example a source ID plus `evtx.record`.
    pub domain: String,
    pub no: i64,
}

/// The full time of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTime {
    pub time: Time,
    pub meaning: TimeMeaning,
    pub clock: ClockDomainId,
    pub seq: Option<Sequence>,
}

/// Where an event sorts in the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    /// Index into the slice given to [`timeline_order`].
    pub index: usize,
    /// The time it sorts by: its own key, or one borrowed from its sequence. `None` sorts last.
    pub sort_key: Option<TimeKey>,
    /// Whether `sort_key` was borrowed from another event in the same sequence.
    pub borrowed: bool,
}

/// The timeline order of `events`: by time, with events without a time placed by their sequence.
/// Ties keep sequence order, then input order, so the result never depends on hash order.
pub fn timeline_order(events: &[EventTime]) -> Vec<Placed> {
    let mut placed: Vec<Placed> = events
        .iter()
        .enumerate()
        .map(|(index, e)| Placed {
            index,
            sort_key: e.time.key,
            borrowed: false,
        })
        .collect();

    // Group by sequence domain, each in sequence order.
    let mut domains: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        if let Some(s) = &e.seq {
            domains.entry(s.domain.as_str()).or_default().push(i);
        }
    }
    for members in domains.values_mut() {
        members.sort_by_key(|&i| (events[i].seq.as_ref().map(|s| s.no), i));
        // Nearest earlier key, then nearest later key, for members without one.
        let mut earlier: Option<TimeKey> = None;
        let mut from_earlier: Vec<Option<TimeKey>> = Vec::with_capacity(members.len());
        for &i in members.iter() {
            if let Some(k) = events[i].time.key {
                earlier = Some(k);
            }
            from_earlier.push(earlier);
        }
        let mut later: Option<TimeKey> = None;
        for (pos, &i) in members.iter().enumerate().rev() {
            if let Some(k) = events[i].time.key {
                later = Some(k);
                continue;
            }
            if let Some(k) = from_earlier[pos].or(later) {
                placed[i].sort_key = Some(k);
                placed[i].borrowed = true;
            }
        }
    }

    placed.sort_by(|a, b| compare(events, a, b));
    placed
}

/// A total order: time (none last), then sequence domain (none first) and number, then own time
/// before borrowed, then input order. A borrowed time shares its neighbour's key and domain, so
/// the sequence number puts it right next to that neighbour.
fn compare(events: &[EventTime], a: &Placed, b: &Placed) -> Ordering {
    let rank = |p: &Placed| {
        let seq = events[p.index].seq.as_ref();
        (
            p.sort_key.is_none(),
            p.sort_key,
            seq.map(|s| s.domain.as_str()),
            seq.map(|s| s.no),
            p.borrowed,
            p.index,
        )
    };
    rank(a).cmp(&rank(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(secs: Option<i64>, seq: Option<(&str, i64)>) -> EventTime {
        EventTime {
            // Zero ticks: a "not set" time without a key.
            time: secs.map_or(Time::from_ticks_1601(0), Time::from_unix_seconds),
            meaning: TimeMeaning::new("test.written").unwrap(),
            clock: ClockDomainId("wall".into()),
            seq: seq.map(|(d, no)| Sequence {
                domain: d.into(),
                no,
            }),
        }
    }

    fn order(events: &[EventTime]) -> Vec<(usize, bool)> {
        timeline_order(events)
            .into_iter()
            .map(|p| (p.index, p.borrowed))
            .collect()
    }

    #[test]
    fn untimed_event_sorts_after_its_earlier_neighbour_in_sequence() {
        let events = [
            ev(Some(100), Some(("log", 1))), // 0
            ev(None, Some(("log", 2))),      // 1: zeroed time
            ev(Some(300), Some(("log", 3))), // 2
            ev(Some(200), None),             // 3: another source in between
            ev(Some(100), None),             // 4: same time as record 1, other source
        ];
        // Record 2 borrows 100 from record 1 and sorts right after it. At equal times, events
        // without a sequence come first.
        assert_eq!(
            order(&events),
            [(4, false), (0, false), (1, true), (3, false), (2, false)]
        );
    }

    #[test]
    fn untimed_at_the_start_borrows_from_the_next_and_lonely_ones_go_last() {
        let events = [
            ev(None, Some(("log", 1))), // 0: nothing earlier, borrows 500 from record 2
            ev(Some(500), Some(("log", 2))), // 1
            ev(None, Some(("other", 7))), // 2: no timed event in its sequence
            ev(None, None),             // 3: no time, no sequence
            ev(Some(400), None),        // 4
        ];
        assert_eq!(
            order(&events),
            [(4, false), (0, true), (1, false), (3, false), (2, false)]
        );
        let p = timeline_order(&events);
        assert_eq!(p[1].sort_key, Time::from_unix_seconds(500).key);
        assert_eq!(p[3].sort_key, None);
    }

    #[test]
    fn sequence_order_breaks_ties_and_input_order_does_not_matter() {
        let a = [
            ev(Some(100), Some(("log", 2))),
            ev(Some(100), Some(("log", 1))),
            ev(None, Some(("log", 3))),
        ];
        assert_eq!(order(&a), [(1, false), (0, false), (2, true)]);
        // The same events in another input order give the same sequence of events.
        let b = [a[2].clone(), a[0].clone(), a[1].clone()];
        let seqs = |evs: &[EventTime]| -> Vec<i64> {
            timeline_order(evs)
                .iter()
                .map(|p| evs[p.index].seq.as_ref().unwrap().no)
                .collect()
        };
        assert_eq!(seqs(&a), seqs(&b));
        assert_eq!(seqs(&a), [1, 2, 3]);
    }

    /// Events from two sequences and none, at equal times: the order must be total (a cycle
    /// would make the sort panic) and independent of input order.
    #[test]
    fn order_is_total_across_sequences() {
        let events = [
            ev(Some(100), Some(("log", 2))),
            ev(Some(100), None),
            ev(Some(100), Some(("log", 1))),
            ev(Some(100), Some(("journal", 9))),
            ev(None, Some(("journal", 10))),
        ];
        assert_eq!(
            order(&events),
            [(1, false), (3, false), (4, true), (2, false), (0, false)]
        );
        let mut rev: Vec<EventTime> = events.to_vec();
        rev.reverse();
        let names = |evs: &[EventTime]| -> Vec<Option<(String, i64)>> {
            timeline_order(evs)
                .iter()
                .map(|p| evs[p.index].seq.as_ref().map(|s| (s.domain.clone(), s.no)))
                .collect()
        };
        assert_eq!(names(&events), names(&rev));
    }

    #[test]
    fn meanings_are_namespaced() {
        for ok in [
            "ntfs.si.modified",
            "ext4.crtime",
            "safari.tab.last_viewed",
            "a.b2",
        ] {
            assert!(TimeMeaning::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "modified", "Ntfs.si", "ntfs..si", ".a", "a.", "a.b-c", "a b.c", "",
        ] {
            assert!(TimeMeaning::new(bad).is_err(), "{bad:?}");
        }
    }
}
