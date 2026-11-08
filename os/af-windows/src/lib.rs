//! Windows OS profile and Windows artifact plugins.
//!
//! Windows names live here, not in core. Core's time encodings have neutral names; the Windows
//! ones map onto them:
//!
//! | Windows name | Core encoding |
//! |---|---|
//! | `FILETIME` (NTFS, registry, EVTX, Prefetch) | [`af_core::time::encoding::TICKS_1601`] |
//! | FAT date and time words | [`af_core::time::encoding::DOS_LOCAL`], `DOS_LOCAL_10MS`, `DOS_LOCAL_DATE` |
//! | `SYSTEMTIME` in local time (NetworkList dates) | [`af_core::time::encoding::LOCAL_CALENDAR`] |

pub mod autoruns;
pub mod bam;
pub mod evtx;
pub mod evtx_map;
pub mod host;
pub mod loose;
pub mod network;
pub mod plugins;
pub mod profile;
pub mod registry;
pub mod registry_timeline;
pub mod sam;

pub use profile::WindowsProfile;

#[cfg(test)]
mod tests {
    use af_core::time::{Time, TimeStatus, encoding};

    /// F4's "done when", in Windows words: FILETIME 0 and the largest FILETIME round-trip.
    #[test]
    fn filetime_zero_and_far_future_round_trip() {
        for filetime in [0u64, i64::MAX as u64, u64::MAX] {
            let t = Time::from_ticks_1601(filetime);
            assert_eq!(t.raw.encoding, encoding::TICKS_1601);
            assert_eq!(Time::from_raw(&t.raw), Some(t.clone()));
            assert_eq!(Time::from_columns(&t.to_columns()), Ok(t.clone()));
        }
        assert_eq!(Time::from_ticks_1601(0).status, TimeStatus::NotSet);
    }
}
