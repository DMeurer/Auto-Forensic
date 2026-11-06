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

/// I7, I8 and I10: the dfVFS tables match `mmls` (start and length in sectors).
#[test]
fn dfvfs_tables_match_mmls() {
    use af_fmt_volume::partition::{Scheme, read_table};
    let dir = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("af-stage3/evidence/dfvfs");
    for (name, scheme, want) in [
        ("mbr.raw", Scheme::Mbr, vec![(1, 1, 129), (5, 131, 129)]),
        ("gpt.raw", Scheme::Gpt, vec![(1, 2048, 128), (2, 4096, 128)]),
        // An MBR partition holding a GPT: the outer table here, the inner one in af-host.
        ("gpt_in_mbr.raw", Scheme::Mbr, vec![(1, 128, 8192)]),
        ("ext2.raw", Scheme::None, vec![]),
    ] {
        let Ok(data) = std::fs::read(dir.join(name)) else {
            continue;
        };
        let mut r = |off: u64, buf: &mut [u8]| {
            buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
            Ok(())
        };
        let t = read_table(&mut r, data.len() as u64).unwrap();
        assert_eq!(t.scheme, scheme, "{name}");
        let got: Vec<_> = t
            .partitions
            .iter()
            .map(|p| (p.number, p.start / 512, p.len / 512))
            .collect();
        assert_eq!(got, want, "{name}");
        assert!(t.notes.is_empty(), "{name}: {:?}", t.notes);
    }
}
