//! Block and loop devices as live sources (piece I28). They are read read-only through
//! [`crate::raw::RawImage`], not hashed (a live device can change), and a mounted device or a
//! mounted partition of it is reported, since the mount may write while af reads.

use std::path::Path;

/// Whether `path` is a block device: `/dev/sdb` or `/dev/loop0` on Unix, `\\.\PhysicalDrive1`
/// on Windows.
pub fn is_block_device(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path).is_ok_and(|m| m.file_type().is_block_device())
    }
    #[cfg(windows)]
    {
        let p = path.to_string_lossy().to_ascii_lowercase();
        p.strip_prefix(r"\\.\physicaldrive")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

/// A Windows physical drive's size. Seeking to its end doesn't work, so Windows is asked.
#[cfg(windows)]
#[allow(unsafe_code)] // one Windows call; `cargo xtask check` keeps such allows in af-host
pub(crate) fn drive_len(file: &std::fs::File) -> std::io::Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO};
    let mut info = GET_LENGTH_INFORMATION { Length: 0 };
    let mut got = 0u32;
    // SAFETY: the handle is open for the call's duration, and the out buffer is a live
    // GET_LENGTH_INFORMATION whose size is passed with it.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null(),
            0,
            (&raw mut info).cast(),
            size_of::<GET_LENGTH_INFORMATION>() as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    u64::try_from(info.Length).map_err(|_| std::io::Error::other("negative drive length"))
}

/// The mounts of `dev` or its partitions (`sdb1`, `loop0p1`, `nvme0n1p2`), as
/// `(mounted device, mount point)`, from `/proc/mounts`-style text.
// shortcut: matches device paths only, not /dev/mapper or by-uuid aliases; good enough for sticks.
pub fn mounts_of(dev: &str, mounts: &str) -> Vec<(String, String)> {
    mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?, f.next()?))
        })
        .filter(|(src, _)| {
            src.strip_prefix(dev).is_some_and(|rest| {
                let digits = rest.strip_prefix('p').unwrap_or(rest);
                rest.is_empty()
                    || (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            })
        })
        // /proc/mounts escapes spaces in mount points as \040.
        .map(|(s, m)| (s.to_string(), m.replace("\\040", " ")))
        .collect()
}

/// The current mounts of `dev` or its partitions on this machine; empty where unknown.
pub fn mounted(dev: &Path) -> Vec<(String, String)> {
    let text = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    mounts_of(&dev.to_string_lossy(), &text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_count_and_neighbours_dont() {
        let m = "/dev/sdb1 /media/ich/USB\\040STICK vfat rw 0 0\n/dev/sdb2 /mnt/b ext4 rw 0 0\n\
                 /dev/sdba1 /x ext4 rw 0 0\n/dev/loop0p1 /mnt/l vfat ro 0 0\n/dev/loop10 /y ext4 rw 0 0\n\
                 proc /proc proc rw 0 0\n";
        assert_eq!(
            mounts_of("/dev/sdb", m),
            [
                ("/dev/sdb1".to_string(), "/media/ich/USB STICK".to_string()),
                ("/dev/sdb2".to_string(), "/mnt/b".to_string())
            ]
        );
        assert_eq!(mounts_of("/dev/loop0", m).len(), 1, "loop0p1, not loop10");
        assert!(mounts_of("/dev/sdc", m).is_empty());
    }

    /// A device reads the same as its image through af's reader (the I28 check). Opt-in, since it
    /// needs a device: `AF_TEST_DEVICE=/dev/loop15 AF_TEST_IMAGE=fat32.img cargo test -p af-host`.
    #[test]
    fn a_device_reads_like_its_image() {
        let (Some(dev), Some(img)) = (
            std::env::var_os("AF_TEST_DEVICE"),
            std::env::var_os("AF_TEST_IMAGE"),
        ) else {
            return;
        };
        use crate::raw::RawImage;
        use af_core::bytes::{ByteSource, Locator};
        let open = |p: &std::ffi::OsStr| RawImage::open(&[p.into()], Locator::default()).unwrap();
        let (d, i) = (open(&dev), open(&img));
        assert!(is_block_device(Path::new(&dev)));
        assert_eq!(d.len(), i.len());
        let (mut a, mut b) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
        let mut at = 0;
        while at < d.len() {
            let n = d.read_at(at, &mut a).unwrap();
            assert!(n > 0);
            assert_eq!(i.read_at(at, &mut b[..n]).unwrap(), n);
            assert_eq!(a[..n], b[..n], "differs near {at}");
            at += n as u64;
        }
    }

    #[test]
    fn a_regular_file_is_no_device() {
        assert!(!is_block_device(Path::new(env!("CARGO_MANIFEST_DIR"))));
    }
}
