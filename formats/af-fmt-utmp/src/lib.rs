//! Linux login records (utmp, wtmp, btmp), from bytes (piece C1).
//!
//! Layout from libyal's dtformats, "Utmp login records format" (rev. 0.0.4): a file is a run of
//! fixed-size records in the machine's byte order (little-endian here, as on x86). Two sizes
//! exist: 384 bytes for 32-bit builds and 64-bit builds with 32-bit compatibility, and 400 bytes
//! for 64-bit builds, where session, seconds and microseconds are 8 bytes each.
//!
//! | Field | 384 | 400 |
//! |---|---|---|
//! | type (i32) | 0 | 0 |
//! | PID (i32) | 4 | 4 |
//! | terminal (32) | 8 | 8 |
//! | terminal ID (4) | 40 | 40 |
//! | user name (32) | 44 | 44 |
//! | host name (256) | 76 | 76 |
//! | termination, exit status (2 × i16) | 332 | 332 |
//! | session | 336 (4) | 336 (8) |
//! | seconds | 340 (4) | 344 (8) |
//! | microseconds | 344 (4) | 352 (8) |
//! | IP address (16) | 348 | 360 |

/// One login record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Byte offset of the record in the file.
    pub offset: u64,
    pub kind: i32,
    pub pid: i32,
    pub line: String,
    pub id: [u8; 4],
    pub user: String,
    pub host: String,
    pub session: i64,
    pub seconds: i64,
    pub microseconds: i64,
    pub addr: [u8; 16],
}

impl Record {
    /// The record type's name, as in utmp.h (`user_process`, `boot_time`, ...).
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            0 => "empty",
            1 => "run_level",
            2 => "boot_time",
            3 => "new_time",
            4 => "old_time",
            5 => "init_process",
            6 => "login_process",
            7 => "user_process",
            8 => "dead_process",
            9 => "accounting",
            _ => "unknown",
        }
    }
}

/// The two record sizes.
pub const SIZES: [usize; 2] = [384, 400];

/// Reads every record of `size` bytes. A trailing part shorter than a record is ignored.
pub fn records(data: &[u8], size: usize) -> Vec<Record> {
    data.chunks_exact(size)
        .enumerate()
        .map(|(i, r)| parse(r, size, (i * size) as u64))
        .collect()
}

fn parse(r: &[u8], size: usize, offset: u64) -> Record {
    let i32_at = |o: usize| i32::from_le_bytes(r[o..o + 4].try_into().expect("four bytes"));
    let i64_at = |o: usize| i64::from_le_bytes(r[o..o + 8].try_into().expect("eight bytes"));
    let text = |o: usize, n: usize| {
        let b = &r[o..o + n];
        let end = b.iter().position(|&c| c == 0).unwrap_or(n);
        String::from_utf8_lossy(&b[..end]).into_owned()
    };
    let (session, seconds, micro, addr_at) = if size == 400 {
        (i64_at(336), i64_at(344), i64_at(352), 360)
    } else {
        (
            i64::from(i32_at(336)),
            i64::from(i32_at(340)),
            i64::from(i32_at(344)),
            348,
        )
    };
    Record {
        offset,
        kind: i32_at(0),
        pid: i32_at(4),
        line: text(8, 32),
        id: r[40..44].try_into().expect("four bytes"),
        user: text(44, 32),
        host: text(76, 256),
        session,
        seconds,
        microseconds: micro,
        addr: r[addr_at..addr_at + 16].try_into().expect("16 bytes"),
    }
}

/// The record size a file most likely uses: the one whose records most often have a known type
/// and a time between 1990 and 2100 (empty records count as neither). `None` for an empty file
/// or when neither layout gives plausible records.
pub fn detect_size(data: &[u8]) -> Option<usize> {
    let score = |size: usize| {
        records(data, size)
            .iter()
            .filter(|r| {
                (1..=9).contains(&r.kind)
                    && (631_152_000..4_102_444_800).contains(&r.seconds)
                    && (0..1_000_000).contains(&r.microseconds)
            })
            .count()
    };
    let (a, b) = (score(384), score(400));
    match (a, b) {
        (0, 0) => None,
        _ if a > b => Some(384),
        _ if b > a => Some(400),
        // A tie: the size that divides the file evenly.
        _ if data.len().is_multiple_of(400) => Some(400),
        _ => Some(384),
    }
}

/// Builds records for tests: (type, user, line, host, seconds, microseconds).
pub fn build_test_file(size: usize, records: &[(i32, &str, &str, &str, i64, i64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, &(kind, user, line, host, secs, usec)) in records.iter().enumerate() {
        let mut r = vec![0u8; size];
        r[0..4].copy_from_slice(&kind.to_le_bytes());
        r[4..8].copy_from_slice(&(1000 + i as i32).to_le_bytes());
        r[8..8 + line.len()].copy_from_slice(line.as_bytes());
        r[44..44 + user.len()].copy_from_slice(user.as_bytes());
        r[76..76 + host.len()].copy_from_slice(host.as_bytes());
        if size == 400 {
            r[344..352].copy_from_slice(&secs.to_le_bytes());
            r[352..360].copy_from_slice(&usec.to_le_bytes());
            r[360..364].copy_from_slice(&[192, 168, 2, 57]);
        } else {
            r[340..344].copy_from_slice(&(secs as i32).to_le_bytes());
            r[344..348].copy_from_slice(&(usec as i32).to_le_bytes());
            r[348..352].copy_from_slice(&[192, 168, 2, 57]);
        }
        out.extend_from_slice(&r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGINS: &[(i32, &str, &str, &str, i64, i64)] = &[
        (2, "reboot", "~", "4.15.0-29-generic", 1_531_143_874, 0),
        (7, "admin", "pts/0", "192.168.2.57", 1_531_143_900, 123_456),
        (8, "", "pts/0", "", 1_531_147_500, 654_321),
    ];

    #[test]
    fn both_layouts_parse_and_are_recognised() {
        for size in SIZES {
            let data = build_test_file(size, LOGINS);
            assert_eq!(detect_size(&data), Some(size), "{size}");
            let r = records(&data, size);
            assert_eq!(r.len(), 3);
            assert_eq!(r[1].kind_name(), "user_process");
            assert_eq!((r[1].user.as_str(), r[1].line.as_str()), ("admin", "pts/0"));
            assert_eq!(r[1].host, "192.168.2.57");
            assert_eq!((r[1].seconds, r[1].microseconds), (1_531_143_900, 123_456));
            assert_eq!(r[1].offset, size as u64);
            assert_eq!(&r[1].addr[..4], &[192, 168, 2, 57]);
            assert_eq!(r[0].kind_name(), "boot_time");
        }
    }

    #[test]
    fn junk_and_short_files() {
        assert_eq!(detect_size(&[]), None);
        assert_eq!(detect_size(&[0xff; 384 * 3]), None);
        let mut data = build_test_file(384, LOGINS);
        data.extend_from_slice(&[1, 2, 3]); // a torn last record
        assert_eq!(records(&data, 384).len(), 3);
        assert_eq!(detect_size(&data), Some(384));
    }
}
