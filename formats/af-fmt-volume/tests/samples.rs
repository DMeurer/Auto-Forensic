//! I11's check on the dfVFS samples, where `cargo xtask evidence fetch dfvfs` has put them.
//! The expected answers are TSK's (`fsstat -t`), except `bdetogo.raw`, which TSK calls fat32.

use af_fmt_volume::{Content, HEAD_LEN, detect};
use std::io::Read;

#[test]
fn dfvfs_samples() {
    let dir = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("af-stage3/evidence/dfvfs");
    for (name, want) in [
        ("fat12.raw", Content::Fat12),
        ("ntfs.raw", Content::Ntfs),
        ("ext2.raw", Content::Ext),
        ("ext4.raw", Content::Ext),
        ("vss.raw", Content::Ntfs),
        ("bdetogo.raw", Content::BitLocker),
        // I2's generated sticks, made by mkfs and written by the Linux kernel.
        ("../../fixtures/fat16.img", Content::Fat16),
        ("../../fixtures/fat32.img", Content::Fat32),
        ("../../fixtures/exfat.img", Content::ExFat),
        ("../../fixtures/ntfs.img", Content::Ntfs),
    ] {
        let Ok(f) = std::fs::File::open(dir.join(name)) else {
            continue;
        };
        let mut head = Vec::new();
        f.take(HEAD_LEN as u64).read_to_end(&mut head).unwrap();
        assert_eq!(detect(&head), want, "{name}");
    }
}
