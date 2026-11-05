//! The time type (piece F4).
//!
//! Every timestamp keeps four things:
//!
//! - **key**: the sort key, an `i64` of 100 ns ticks since 1601-01-01 00:00 UTC. It is empty when
//!   no sensible point in time exists (a "not set" marker, or a value that doesn't fit).
//! - **min and max**: the interval the true time lies in, for example every time zone for a local
//!   time without a zone, or the full second for a value stored in seconds.
//! - **raw value and encoding**: the bit pattern as stored in the evidence, and what it means, so
//!   the key can always be derived again ([`Time::from_raw`]).
//! - **status**: `ok`, `not_set`, `out_of_range`, `year_inferred`, `estimated` or `absent`.
//! - **precision, zone and conversion version** (F5): the step of the stored value (a date-only
//!   value has a precision of one day and is never shown as midnight), whether it is UTC or local
//!   and with which offset, and which version of the conversion derived key, min and max.
//!
//! Nothing is ever clamped or rejected. A value that can't become a key keeps its raw value
//! and gets a status, because odd values are evidence too.
//!
//! The encodings have neutral names here. Which file format or OS uses which encoding is
//! the business of the format and OS crates.

use std::fmt;

/// Ticks (100 ns) per second.
pub const TICKS_PER_SECOND: i64 = 10_000_000;
/// Ticks per day.
pub const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
/// The key of 1970-01-01 00:00 UTC.
pub const UNIX_EPOCH_KEY: i64 = 116_444_736_000_000_000;
/// Days from 1601-01-01 to 1970-01-01.
const DAYS_1601_TO_1970: i64 = 134_774;
/// Version of the conversions in this module. Raise it when a conversion changes, so stored
/// times with an older version can be derived again from their raw values.
pub const CONVERSION_VERSION: u16 = 1;
/// The widest offsets from UTC in use: local time lies between UTC-12 and UTC+14.
const MOST_WEST: i64 = 12 * 3600 * TICKS_PER_SECOND;
const MOST_EAST: i64 = 14 * 3600 * TICKS_PER_SECOND;

/// Names of the raw encodings that core can convert. Other crates may store other names; their
/// values are kept, but [`Time::from_raw`] can't derive a key for them.
pub mod encoding {
    /// Unsigned 64-bit count of 100 ns ticks since 1601-01-01 00:00 UTC.
    pub const TICKS_1601: &str = "ticks_1601";
    /// Signed seconds since 1970-01-01 00:00 UTC.
    pub const UNIX_S: &str = "unix_s";
    /// Signed nanoseconds since 1970-01-01 00:00 UTC.
    pub const UNIX_NS: &str = "unix_ns";
    /// DOS date and time words, local time with no zone, 2-second steps.
    /// Raw value: `date << 16 | time`.
    pub const DOS_LOCAL: &str = "dos_local";
    /// DOS date and time words plus a 10 ms count (0-199), local time with no zone.
    /// Raw value: `date << 24 | time << 8 | count`.
    pub const DOS_LOCAL_10MS: &str = "dos_local_10ms";
    /// A DOS date word alone, a local date with no zone. Raw value: the date word.
    pub const DOS_LOCAL_DATE: &str = "dos_local_date";
}

/// The sort key: 100 ns ticks since 1601-01-01 00:00 UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeKey(pub i64);

impl TimeKey {
    /// The key of a UTC calendar time, or `None` if the fields are invalid or don't fit.
    pub fn from_utc(
        year: i64,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Option<Self> {
        if !valid_date(year, month, day) || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        let days = days_from_civil(year, month, day).checked_add(DAYS_1601_TO_1970)?;
        let secs = i64::from(hour * 3600 + minute * 60 + second);
        days.checked_mul(TICKS_PER_DAY)?
            .checked_add(secs * TICKS_PER_SECOND)
            .map(TimeKey)
    }

    /// The UTC calendar fields of this key.
    pub fn to_utc(self) -> UtcParts {
        let days = self.0.div_euclid(TICKS_PER_DAY);
        let rest = self.0.rem_euclid(TICKS_PER_DAY);
        let (year, month, day) = civil_from_days(days - DAYS_1601_TO_1970);
        let secs = rest / TICKS_PER_SECOND;
        UtcParts {
            year,
            month,
            day,
            hour: (secs / 3600) as u32,
            minute: (secs / 60 % 60) as u32,
            second: (secs % 60) as u32,
            ticks: (rest % TICKS_PER_SECOND) as u32,
        }
    }
}

/// UTC calendar fields of a [`TimeKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcParts {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// 100 ns ticks within the second, 0 to 9,999,999.
    pub ticks: u32,
}

impl fmt::Display for UtcParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:07}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.ticks
        )
    }
}

/// How far a timestamp can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeStatus {
    Ok,
    /// The evidence holds a "not set" marker, such as zero.
    NotSet,
    /// The value can't be a point in time: too large, or invalid calendar fields.
    OutOfRange,
    /// The year was not stored and was inferred.
    YearInferred,
    /// The time was estimated from other evidence.
    Estimated,
    /// The source has no such time at all (unlike zero, which is a stored value).
    Absent,
}

impl TimeStatus {
    pub const ALL: [TimeStatus; 6] = [
        Self::Ok,
        Self::NotSet,
        Self::OutOfRange,
        Self::YearInferred,
        Self::Estimated,
        Self::Absent,
    ];

    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotSet => "not_set",
            Self::OutOfRange => "out_of_range",
            Self::YearInferred => "year_inferred",
            Self::Estimated => "estimated",
            Self::Absent => "absent",
        }
    }

    /// The status with this stored name.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// The step of a stored value, in ticks: 1 for 100 ns, a second for whole seconds, a day for a
/// date-only value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Precision(pub i64);

impl Precision {
    pub const TICK: Self = Self(1);
    pub const TEN_MS: Self = Self(TICKS_PER_SECOND / 100);
    pub const SECOND: Self = Self(TICKS_PER_SECOND);
    pub const TWO_SECONDS: Self = Self(2 * TICKS_PER_SECOND);
    pub const DAY: Self = Self(TICKS_PER_DAY);

    /// Whether the value is a date without a time of day.
    pub fn is_date(self) -> bool {
        self.0 >= TICKS_PER_DAY
    }

    /// Digits after the seconds worth showing, 0 to 7.
    fn fraction_digits(self) -> usize {
        let mut digits = 7;
        let mut step = self.0.max(1);
        while step >= 10 && digits > 0 {
            step /= 10;
            digits -= 1;
        }
        digits
    }
}

/// Whether a time is UTC or local, and the offset from UTC where known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Zone {
    /// Stored as UTC.
    Utc,
    /// Local time with a known offset, in minutes east of UTC (+60 for Berlin in winter).
    KnownLocal { offset_min: i16 },
    /// Local time with an assumed offset, for example the system's zone applied to a stick.
    AssumedLocal { offset_min: i16 },
    /// Local time in an unknown zone. The key reads the clock as UTC.
    Unknown,
    /// Zones don't apply, for example to a monotonic clock.
    NotApplicable,
}

impl Zone {
    /// The stored status name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utc => "utc",
            Self::KnownLocal { .. } => "known_local",
            Self::AssumedLocal { .. } => "assumed_local",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// The offset in minutes, for local zones with an offset.
    pub fn offset_min(self) -> Option<i16> {
        match self {
            Self::KnownLocal { offset_min } | Self::AssumedLocal { offset_min } => Some(offset_min),
            _ => None,
        }
    }

    /// From the stored status name and offset.
    pub fn parse(status: &str, offset_min: Option<i16>) -> Option<Self> {
        Some(match (status, offset_min) {
            ("utc", None) => Self::Utc,
            ("known_local", Some(o)) => Self::KnownLocal { offset_min: o },
            ("assumed_local", Some(o)) => Self::AssumedLocal { offset_min: o },
            ("unknown", None) => Self::Unknown,
            ("not_applicable", None) => Self::NotApplicable,
            _ => return None,
        })
    }

    fn is_local(self) -> bool {
        matches!(
            self,
            Self::KnownLocal { .. } | Self::AssumedLocal { .. } | Self::Unknown
        )
    }

    /// Ticks to add to the key to get the local clock reading (0 for an unknown zone, whose key
    /// already is the local reading).
    fn local_shift(self) -> i64 {
        i64::from(self.offset_min().unwrap_or(0)) * 60 * TICKS_PER_SECOND
    }
}

/// A raw value as stored in the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RawValue {
    /// Up to 64 bits. Unsigned and floating-point values keep their bit pattern.
    Int(i64),
    /// A time written as text.
    Text(String),
}

/// A raw value and the name of its encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawTime {
    pub encoding: String,
    pub value: RawValue,
}

impl RawTime {
    fn int(encoding: &str, value: i64) -> Self {
        Self {
            encoding: encoding.to_string(),
            value: RawValue::Int(value),
        }
    }
}

/// A timestamp: key, interval, raw value and status. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Time {
    pub key: Option<TimeKey>,
    pub min: Option<TimeKey>,
    pub max: Option<TimeKey>,
    pub raw: RawTime,
    pub status: TimeStatus,
    pub precision: Precision,
    pub zone: Zone,
    /// The [`CONVERSION_VERSION`] that derived key, min and max from the raw value.
    pub conversion: u16,
}

impl Time {
    /// A value without a key.
    fn without_key(raw: RawTime, status: TimeStatus, precision: Precision, zone: Zone) -> Self {
        Self {
            key: None,
            min: None,
            max: None,
            raw,
            status,
            precision,
            zone,
            conversion: CONVERSION_VERSION,
        }
    }

    /// A UTC value with key `k` and interval `[k, k + step - 1]`.
    fn utc(k: i64, precision: Precision, raw: RawTime) -> Self {
        Self {
            key: Some(TimeKey(k)),
            min: Some(TimeKey(k)),
            max: k.checked_add(precision.0 - 1).map(TimeKey),
            raw,
            status: TimeStatus::Ok,
            precision,
            zone: Zone::Utc,
            conversion: CONVERSION_VERSION,
        }
    }

    /// From an unsigned count of 100 ns ticks since 1601. Zero is "not set", and values above
    /// `i64::MAX` (year 30828) are out of range; both keep their raw value.
    pub fn from_ticks_1601(ticks: u64) -> Self {
        let raw = RawTime::int(encoding::TICKS_1601, ticks as i64);
        let p = Precision::TICK;
        match i64::try_from(ticks) {
            Ok(0) => Self::without_key(raw, TimeStatus::NotSet, p, Zone::Utc),
            Ok(t) => Self::utc(t, p, raw),
            Err(_) => Self::without_key(raw, TimeStatus::OutOfRange, p, Zone::Utc),
        }
    }

    /// From signed seconds since 1970. The interval covers the whole second.
    pub fn from_unix_seconds(secs: i64) -> Self {
        let raw = RawTime::int(encoding::UNIX_S, secs);
        let key = secs
            .checked_mul(TICKS_PER_SECOND)
            .and_then(|t| t.checked_add(UNIX_EPOCH_KEY));
        match key {
            Some(k) => Self::utc(k, Precision::SECOND, raw),
            None => Self::without_key(raw, TimeStatus::OutOfRange, Precision::SECOND, Zone::Utc),
        }
    }

    /// From signed nanoseconds since 1970. The key drops the last two digits; the raw value keeps
    /// them. The interval covers the 100 ns the key stands for.
    pub fn from_unix_nanos(nanos: i64) -> Self {
        // Every i64 of nanoseconds fits: about 292 years either side of 1970.
        let k = UNIX_EPOCH_KEY + nanos.div_euclid(100);
        Self::utc(k, Precision::TICK, RawTime::int(encoding::UNIX_NS, nanos))
    }

    /// From DOS date and time words (local time, no zone, 2-second steps), with the optional
    /// 10 ms count (0-199) that some entries add.
    ///
    /// The key reads the local clock as if it were UTC. The interval spans every time zone
    /// (UTC-12 to UTC+14) plus the step of the value. A date word of 0 is "not set", and invalid
    /// fields are out of range.
    pub fn from_dos_local(date: u16, time: u16, count_10ms: Option<u8>) -> Self {
        let (raw, step) = match count_10ms {
            None => (
                RawTime::int(
                    encoding::DOS_LOCAL,
                    (i64::from(date) << 16) | i64::from(time),
                ),
                Precision::TWO_SECONDS,
            ),
            Some(c) => (
                RawTime::int(
                    encoding::DOS_LOCAL_10MS,
                    (i64::from(date) << 24) | (i64::from(time) << 8) | i64::from(c),
                ),
                Precision::TEN_MS,
            ),
        };
        if date == 0 {
            return Self::without_key(raw, TimeStatus::NotSet, step, Zone::Unknown);
        }
        let (year, month, day) = dos_date_fields(date);
        let (hour, minute, second) = (
            u32::from(time >> 11),
            u32::from((time >> 5) & 0x3f),
            u32::from(time & 0x1f) * 2,
        );
        let extra = match count_10ms {
            Some(c) if c > 199 => {
                return Self::without_key(raw, TimeStatus::OutOfRange, step, Zone::Unknown);
            }
            Some(c) => i64::from(c) * (TICKS_PER_SECOND / 100),
            None => 0,
        };
        match TimeKey::from_utc(year, month, day, hour, minute, second) {
            Some(TimeKey(k)) => Self::local_unknown_zone(k + extra, step, raw),
            None => Self::without_key(raw, TimeStatus::OutOfRange, step, Zone::Unknown),
        }
    }

    /// From a DOS date word alone (a local date, no zone, such as a last-access date). The key
    /// is local midnight read as UTC, and the interval spans the whole day in every zone.
    pub fn from_dos_local_date(date: u16) -> Self {
        let raw = RawTime::int(encoding::DOS_LOCAL_DATE, i64::from(date));
        let p = Precision::DAY;
        if date == 0 {
            return Self::without_key(raw, TimeStatus::NotSet, p, Zone::Unknown);
        }
        let (year, month, day) = dos_date_fields(date);
        match TimeKey::from_utc(year, month, day, 0, 0, 0) {
            Some(TimeKey(k)) => Self::local_unknown_zone(k, p, raw),
            None => Self::without_key(raw, TimeStatus::OutOfRange, p, Zone::Unknown),
        }
    }

    /// A local reading `k` (taken as UTC) with a step of `step` ticks, in an unknown zone.
    fn local_unknown_zone(k: i64, step: Precision, raw: RawTime) -> Self {
        Self {
            key: Some(TimeKey(k)),
            min: Some(TimeKey(k - MOST_EAST)),
            max: Some(TimeKey(k + step.0 - 1 + MOST_WEST)),
            raw,
            status: TimeStatus::Ok,
            precision: step,
            zone: Zone::Unknown,
            conversion: CONVERSION_VERSION,
        }
    }

    /// The same local time with its UTC offset now known (or assumed), in minutes east of UTC.
    /// The key becomes the true UTC time and the interval shrinks to the value's own step.
    /// UTC times, times without a key and times where zones don't apply come back unchanged.
    pub fn with_local_offset(&self, offset_min: i16, assumed: bool) -> Self {
        let mut t = self.clone();
        let Some(TimeKey(k)) = self.key else {
            return t;
        };
        if !self.zone.is_local() {
            return t;
        }
        let local = k + self.zone.local_shift();
        let utc = local - i64::from(offset_min) * 60 * TICKS_PER_SECOND;
        t.key = Some(TimeKey(utc));
        t.min = Some(TimeKey(utc));
        t.max = Some(TimeKey(utc + self.precision.0 - 1));
        t.zone = if assumed {
            Zone::AssumedLocal { offset_min }
        } else {
            Zone::KnownLocal { offset_min }
        };
        t
    }

    /// Derives this time again from its raw value with the current conversions, keeping its
    /// known or assumed zone. `None` for encodings core doesn't know.
    pub fn rederive(&self) -> Option<Self> {
        let fresh = Self::from_raw(&self.raw)?;
        Some(match self.zone {
            Zone::KnownLocal { offset_min } => fresh.with_local_offset(offset_min, false),
            Zone::AssumedLocal { offset_min } => fresh.with_local_offset(offset_min, true),
            _ => fresh,
        })
    }

    /// The time as text for people. A date-only value shows as a date, never as midnight. A
    /// local time in an unknown zone says so. A time without a key shows its status and raw value.
    pub fn display(&self) -> String {
        let Some(TimeKey(k)) = self.key else {
            let raw = match &self.raw.value {
                RawValue::Int(v) => v.to_string(),
                RawValue::Text(s) => format!("{s:?}"),
            };
            return format!(
                "no time ({}), raw {raw} as {}",
                self.status.as_str(),
                self.raw.encoding
            );
        };
        let zone_note = |local_only: bool| match self.zone {
            Zone::Utc => "UTC".to_string(),
            Zone::Unknown => "local, zone unknown".to_string(),
            Zone::KnownLocal { offset_min } if local_only => {
                format!("local {}", offset(offset_min))
            }
            Zone::AssumedLocal { offset_min } if local_only => {
                format!("local {} assumed", offset(offset_min))
            }
            Zone::KnownLocal { offset_min } => format!("UTC, local {}", offset(offset_min)),
            Zone::AssumedLocal { offset_min } => {
                format!("UTC, local {} assumed", offset(offset_min))
            }
            Zone::NotApplicable => "no zone".to_string(),
        };
        let mut text = if self.precision.is_date() {
            // The date as written in the evidence: the local date for a local value.
            let p = TimeKey(k + self.zone.local_shift()).to_utc();
            format!(
                "{:04}-{:02}-{:02} (date, {})",
                p.year,
                p.month,
                p.day,
                zone_note(true)
            )
        } else {
            let p = TimeKey(k).to_utc();
            let mut s = format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                p.year, p.month, p.day, p.hour, p.minute, p.second
            );
            let digits = self.precision.fraction_digits();
            if digits > 0 {
                let frac = format!("{:07}", p.ticks);
                s.push('.');
                s.push_str(&frac[..digits]);
            }
            format!("{s} {}", zone_note(false))
        };
        if self.status != TimeStatus::Ok {
            text.push_str(&format!(" [{}]", self.status.as_str()));
        }
        text
    }

    /// Derives the time again from its raw value, for the encodings core knows. Returns `None` for
    /// other encodings, and for a raw value of the wrong kind.
    pub fn from_raw(raw: &RawTime) -> Option<Self> {
        let RawValue::Int(v) = raw.value else {
            return None;
        };
        let t = match raw.encoding.as_str() {
            encoding::TICKS_1601 => Self::from_ticks_1601(v as u64),
            encoding::UNIX_S => Self::from_unix_seconds(v),
            encoding::UNIX_NS => Self::from_unix_nanos(v),
            encoding::DOS_LOCAL if (0..1 << 32).contains(&v) => {
                Self::from_dos_local((v >> 16) as u16, v as u16, None)
            }
            encoding::DOS_LOCAL_10MS if (0..1 << 40).contains(&v) => {
                Self::from_dos_local((v >> 24) as u16, (v >> 8) as u16, Some(v as u8))
            }
            encoding::DOS_LOCAL_DATE if (0..1 << 16).contains(&v) => {
                Self::from_dos_local_date(v as u16)
            }
            _ => return None,
        };
        Some(t)
    }

    /// The stored form.
    pub fn to_columns(&self) -> TimeColumns {
        let (raw_i64, raw_text) = match &self.raw.value {
            RawValue::Int(v) => (Some(*v), None),
            RawValue::Text(s) => (None, Some(s.clone())),
        };
        TimeColumns {
            ts: self.key.map(|k| k.0),
            ts_min: self.min.map(|k| k.0),
            ts_max: self.max.map(|k| k.0),
            raw_i64,
            raw_text,
            raw_encoding: self.raw.encoding.clone(),
            time_status: self.status.as_str().to_string(),
            precision_ticks: self.precision.0,
            tz_status: self.zone.as_str().to_string(),
            tz_offset_min: self.zone.offset_min(),
            conversion_version: self.conversion,
        }
    }

    /// Back from the stored form. Fails only on columns this code didn't write.
    pub fn from_columns(c: &TimeColumns) -> Result<Self, ColumnError> {
        let value = match (c.raw_i64, &c.raw_text) {
            (Some(v), None) => RawValue::Int(v),
            (None, Some(s)) => RawValue::Text(s.clone()),
            _ => return Err(ColumnError::Raw),
        };
        let status = TimeStatus::parse(&c.time_status)
            .ok_or_else(|| ColumnError::Status(c.time_status.clone()))?;
        let zone = Zone::parse(&c.tz_status, c.tz_offset_min)
            .ok_or_else(|| ColumnError::Zone(c.tz_status.clone()))?;
        Ok(Self {
            key: c.ts.map(TimeKey),
            min: c.ts_min.map(TimeKey),
            max: c.ts_max.map(TimeKey),
            raw: RawTime {
                encoding: c.raw_encoding.clone(),
                value,
            },
            status,
            precision: Precision(c.precision_ticks),
            zone,
            conversion: c.conversion_version,
        })
    }
}

/// The time columns of an event row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeColumns {
    pub ts: Option<i64>,
    pub ts_min: Option<i64>,
    pub ts_max: Option<i64>,
    pub raw_i64: Option<i64>,
    pub raw_text: Option<String>,
    pub raw_encoding: String,
    pub time_status: String,
    pub precision_ticks: i64,
    pub tz_status: String,
    /// Set only for `known_local` and `assumed_local`.
    pub tz_offset_min: Option<i16>,
    pub conversion_version: u16,
}

/// Stored time columns that can't be read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnError {
    /// Not exactly one of `raw_i64` and `raw_text` is set.
    Raw,
    /// Unknown status name.
    Status(String),
    /// Unknown zone status, or an offset where none belongs (or none where one does).
    Zone(String),
}

impl fmt::Display for ColumnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw => write!(f, "exactly one of raw_i64 and raw_text must be set"),
            Self::Status(s) => write!(f, "unknown time status `{s}`"),
            Self::Zone(s) => write!(f, "zone status `{s}` doesn't match its offset"),
        }
    }
}

impl std::error::Error for ColumnError {}

fn dos_date_fields(date: u16) -> (i64, u32, u32) {
    (
        1980 + i64::from(date >> 9),
        u32::from((date >> 5) & 0x0f),
        u32::from(date & 0x1f),
    )
}

/// An offset as `UTC+02:00` or `UTC-05:30`.
fn offset(min: i16) -> String {
    let sign = if min < 0 { '-' } else { '+' };
    let m = i32::from(min).abs();
    format!("UTC{sign}{:02}:{:02}", m / 60, m % 60)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn valid_date(y: i64, m: u32, d: u32) -> bool {
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day count since 1970-01-01 (H. Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every conversion must survive both round trips: through the stored columns, and derived
    /// again from its raw value.
    fn round_trips(t: &Time) {
        let back = Time::from_columns(&t.to_columns()).expect("columns read back");
        assert_eq!(&back, t, "columns");
        if t.zone.offset_min().is_none() {
            // A zone set later isn't in the raw value; `rederive` below keeps it.
            assert_eq!(Time::from_raw(&t.raw).as_ref(), Some(t), "from raw");
        }
        assert_eq!(t.rederive().as_ref(), Some(t), "rederive");
    }

    fn utc(t: &Time) -> String {
        t.key.expect("has a key").to_utc().to_string()
    }

    #[test]
    fn ticks_zero_is_not_set_and_keeps_raw() {
        let t = Time::from_ticks_1601(0);
        assert_eq!(t.key, None);
        assert_eq!(t.status, TimeStatus::NotSet);
        assert_eq!(t.raw.value, RawValue::Int(0));
        round_trips(&t);
    }

    #[test]
    fn ticks_far_future_is_kept() {
        let t = Time::from_ticks_1601(i64::MAX as u64);
        assert_eq!(utc(&t), "30828-09-14 02:48:05.4775807");
        assert_eq!(t.status, TimeStatus::Ok);
        round_trips(&t);
        for v in [i64::MAX as u64 + 1, u64::MAX] {
            let t = Time::from_ticks_1601(v);
            assert_eq!((t.key, t.status), (None, TimeStatus::OutOfRange));
            assert_eq!(t.raw.value, RawValue::Int(v as i64), "bit pattern kept");
            round_trips(&t);
        }
    }

    #[test]
    fn ticks_known_values() {
        assert_eq!(
            utc(&Time::from_ticks_1601(UNIX_EPOCH_KEY as u64)),
            "1970-01-01 00:00:00.0000000"
        );
        assert_eq!(
            utc(&Time::from_ticks_1601(1)),
            "1601-01-01 00:00:00.0000001"
        );
        let t = Time::from_ticks_1601(134_064_720_000_000_000);
        assert_eq!(utc(&t), "2025-11-01 12:00:00.0000000");
    }

    #[test]
    fn unix_seconds_and_nanos() {
        let t = Time::from_unix_seconds(0);
        assert_eq!(utc(&t), "1970-01-01 00:00:00.0000000");
        assert_eq!(t.max, Some(TimeKey(UNIX_EPOCH_KEY + TICKS_PER_SECOND - 1)));
        round_trips(&t);
        let t = Time::from_unix_seconds(-1);
        assert_eq!(utc(&t), "1969-12-31 23:59:59.0000000");
        round_trips(&t);
        let t = Time::from_unix_seconds(i64::MAX);
        assert_eq!((t.key, t.status), (None, TimeStatus::OutOfRange));
        round_trips(&t);
        let t = Time::from_unix_nanos(1_762_351_200_123_456_789);
        assert_eq!(utc(&t), "2025-11-05 14:00:00.1234567");
        assert_eq!(t.raw.value, RawValue::Int(1_762_351_200_123_456_789));
        round_trips(&t);
        round_trips(&Time::from_unix_nanos(i64::MIN));
        round_trips(&Time::from_unix_nanos(i64::MAX));
    }

    fn dos_date(y: u16, m: u16, d: u16) -> u16 {
        ((y - 1980) << 9) | (m << 5) | d
    }

    fn dos_time(h: u16, m: u16, s: u16) -> u16 {
        (h << 11) | (m << 5) | (s / 2)
    }

    #[test]
    fn dos_local_reads_clock_as_utc_with_every_zone() {
        let t = Time::from_dos_local(dos_date(2026, 11, 5), dos_time(14, 30, 20), None);
        assert_eq!(utc(&t), "2026-11-05 14:30:20.0000000");
        let k = t.key.unwrap().0;
        assert_eq!(t.min, Some(TimeKey(k - 14 * 3600 * TICKS_PER_SECOND)));
        assert_eq!(
            t.max,
            Some(TimeKey(
                k + 2 * TICKS_PER_SECOND - 1 + 12 * 3600 * TICKS_PER_SECOND
            ))
        );
        assert_eq!(t.raw.encoding, encoding::DOS_LOCAL);
        round_trips(&t);

        let t = Time::from_dos_local(dos_date(2026, 11, 5), dos_time(14, 30, 20), Some(155));
        assert_eq!(utc(&t), "2026-11-05 14:30:21.5500000");
        round_trips(&t);
    }

    #[test]
    fn dos_local_edges() {
        // Not set.
        let t = Time::from_dos_local(0, 0, None);
        assert_eq!((t.key, t.status), (None, TimeStatus::NotSet));
        round_trips(&t);
        // The largest DOS date: 2107-12-31 23:58:58.
        let t = Time::from_dos_local(dos_date(2107, 12, 31), dos_time(23, 58, 58), None);
        assert_eq!(utc(&t), "2107-12-31 23:58:58.0000000");
        round_trips(&t);
        // Invalid fields keep their raw value: month 13, 30 February, hour 24, count 200.
        for t in [
            Time::from_dos_local(dos_date(2020, 13, 1), 0, None),
            Time::from_dos_local(dos_date(2021, 2, 30), 0, None),
            Time::from_dos_local(dos_date(2020, 1, 1), dos_time(24, 0, 0), None),
            Time::from_dos_local(dos_date(2020, 1, 1), 0, Some(200)),
            Time::from_dos_local_date(dos_date(2020, 0, 1)),
        ] {
            assert_eq!((t.key, t.status), (None, TimeStatus::OutOfRange), "{t:?}");
            round_trips(&t);
        }
        // 29 February only in leap years.
        assert_eq!(
            Time::from_dos_local(dos_date(2024, 2, 29), 0, None).status,
            TimeStatus::Ok
        );
    }

    #[test]
    fn dos_date_only_spans_the_day_in_every_zone() {
        let t = Time::from_dos_local_date(dos_date(2026, 4, 26));
        assert_eq!(utc(&t), "2026-04-26 00:00:00.0000000");
        assert_eq!(
            t.min.unwrap().to_utc().to_string(),
            "2026-04-25 10:00:00.0000000"
        );
        assert_eq!(
            t.max.unwrap().to_utc().to_string(),
            "2026-04-27 11:59:59.9999999"
        );
        round_trips(&t);
    }

    #[test]
    fn text_and_unknown_encodings_round_trip_through_columns() {
        let t = Time {
            key: None,
            min: None,
            max: None,
            raw: RawTime {
                encoding: "text".into(),
                value: RawValue::Text("Nov  5 14:30:20".into()),
            },
            status: TimeStatus::YearInferred,
            precision: Precision::SECOND,
            zone: Zone::Unknown,
            conversion: CONVERSION_VERSION,
        };
        assert_eq!(Time::from_columns(&t.to_columns()), Ok(t.clone()));
        assert_eq!(Time::from_raw(&t.raw), None);
    }

    #[test]
    fn bad_columns_are_errors() {
        let mut c = Time::from_unix_seconds(5).to_columns();
        c.time_status = "fine".into();
        assert_eq!(
            Time::from_columns(&c),
            Err(ColumnError::Status("fine".into()))
        );
        let mut c = Time::from_unix_seconds(5).to_columns();
        c.raw_text = Some("x".into());
        assert_eq!(Time::from_columns(&c), Err(ColumnError::Raw));
    }

    #[test]
    fn statuses_round_trip() {
        for s in TimeStatus::ALL {
            assert_eq!(TimeStatus::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn calendar_round_trip_over_many_days() {
        // Every 97th day from 1601 to 2500, through key and back.
        let mut d = 0;
        while d < 328_000 {
            let k = TimeKey(d * TICKS_PER_DAY + 12_345);
            let p = k.to_utc();
            let back = TimeKey::from_utc(p.year, p.month, p.day, p.hour, p.minute, p.second)
                .unwrap()
                .0
                + i64::from(p.ticks);
            assert_eq!(back, k.0, "{p}");
            d += 97;
        }
        // Before 1601, the key is negative and still works.
        let k = TimeKey::from_utc(1500, 3, 1, 0, 0, 0).unwrap();
        assert!(k.0 < 0);
        assert_eq!(k.to_utc().to_string(), "1500-03-01 00:00:00.0000000");
    }

    #[test]
    fn date_only_is_shown_as_a_date_never_as_midnight() {
        let t = Time::from_dos_local_date(dos_date(2026, 4, 26));
        assert!(t.precision.is_date());
        assert_eq!(t.display(), "2026-04-26 (date, local, zone unknown)");
        // With the zone known (Berlin, summer: UTC+2) the key is midnight Berlin in UTC, and the
        // shown date stays the local date, not 2026-04-25 22:00.
        let b = t.with_local_offset(120, false);
        assert_eq!(
            b.key.unwrap().to_utc().to_string(),
            "2026-04-25 22:00:00.0000000"
        );
        assert_eq!(b.display(), "2026-04-26 (date, local UTC+02:00)");
        for d in [t.display(), b.display()] {
            assert!(!d.contains("00:00") && !d.contains("22:00"), "{d}");
        }
        round_trips(&b);
    }

    #[test]
    fn known_offset_narrows_the_interval() {
        let t = Time::from_dos_local(dos_date(2026, 11, 5), dos_time(14, 30, 20), None);
        assert_eq!(t.display(), "2026-11-05 14:30:20 local, zone unknown");
        let b = t.with_local_offset(60, false);
        assert_eq!(b.display(), "2026-11-05 13:30:20 UTC, local UTC+01:00");
        assert_eq!(b.min, b.key);
        assert_eq!(
            b.max,
            Some(TimeKey(b.key.unwrap().0 + 2 * TICKS_PER_SECOND - 1))
        );
        round_trips(&b);
        // Changing an assumed offset starts from the local reading, not from the shifted key.
        let a = t.with_local_offset(-300, true).with_local_offset(60, false);
        assert_eq!(a, b);
        assert_eq!(
            t.with_local_offset(-330, true).display(),
            "2026-11-05 20:00:20 UTC, local UTC-05:30 assumed"
        );
        // A UTC value ignores offsets.
        let u = Time::from_unix_seconds(0);
        assert_eq!(u.with_local_offset(60, false), u);
    }

    #[test]
    fn display_follows_precision_and_status() {
        assert_eq!(
            Time::from_ticks_1601(134_064_720_001_234_567).display(),
            "2025-11-01 12:00:00.1234567 UTC"
        );
        assert_eq!(
            Time::from_unix_seconds(0).display(),
            "1970-01-01 00:00:00 UTC"
        );
        assert_eq!(
            Time::from_dos_local(dos_date(2026, 11, 5), dos_time(14, 30, 20), Some(155)).display(),
            "2026-11-05 14:30:21.55 local, zone unknown"
        );
        assert_eq!(
            Time::from_ticks_1601(0).display(),
            "no time (not_set), raw 0 as ticks_1601"
        );
        let mut e = Time::from_unix_seconds(60);
        e.status = TimeStatus::Estimated;
        assert_eq!(e.display(), "1970-01-01 00:01:00 UTC [estimated]");
    }

    #[test]
    fn zone_columns_must_match() {
        let mut c = Time::from_unix_seconds(5).to_columns();
        c.tz_offset_min = Some(60);
        assert_eq!(Time::from_columns(&c), Err(ColumnError::Zone("utc".into())));
        let mut c = Time::from_unix_seconds(5).to_columns();
        c.tz_status = "known_local".into();
        assert_eq!(
            Time::from_columns(&c),
            Err(ColumnError::Zone("known_local".into()))
        );
    }

    #[test]
    fn conversion_version_is_stored() {
        let t = Time::from_unix_seconds(5);
        assert_eq!(t.conversion, CONVERSION_VERSION);
        let mut c = t.to_columns();
        c.conversion_version = 0;
        let old = Time::from_columns(&c).unwrap();
        // An old version is derived again from the raw value, which gives the current one.
        assert_eq!(old.rederive(), Some(t));
    }
}
