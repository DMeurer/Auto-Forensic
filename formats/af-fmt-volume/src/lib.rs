//! What a volume holds, judged from its first bytes (piece I11): a file system, an encrypted
//! volume, or unknown. Encrypted volumes are reported as locked, never as empty: a BitLocker To
//! Go stick looks like FAT32 to tools that only read the boot sector (TSK says `fat32`).
//!
//! FAT12, FAT16 and FAT32 are told apart by cluster count, as the FAT specification says, not by
//! the type string or the partition type, which lie (stage 1 found a "FAT32" card that is FAT16).

pub mod partition;

/// How many bytes [`detect`] wants: up to the ISO 9660 volume descriptor at 32 KiB.
pub const HEAD_LEN: usize = 32 * 1024 + 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    /// ext2, ext3 or ext4.
    Ext,
    Xfs,
    HfsPlus,
    Apfs,
    Iso9660,
    /// BitLocker, including BitLocker To Go: locked until a key is given.
    BitLocker,
    /// LUKS 1 or 2: locked until a key is given.
    Luks,
    Unknown,
}

impl Content {
    /// Whether the volume's content is encrypted, so "nothing found" would be wrong.
    pub fn is_locked(self) -> bool {
        matches!(self, Content::BitLocker | Content::Luks)
    }

    /// The name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            Content::Ntfs => "ntfs",
            Content::Fat12 => "fat12",
            Content::Fat16 => "fat16",
            Content::Fat32 => "fat32",
            Content::ExFat => "exfat",
            Content::Ext => "ext",
            Content::Xfs => "xfs",
            Content::HfsPlus => "hfsplus",
            Content::Apfs => "apfs",
            Content::Iso9660 => "iso9660",
            Content::BitLocker => "bitlocker (locked)",
            Content::Luks => "luks (locked)",
            Content::Unknown => "unknown",
        }
    }
}

/// BitLocker's identifier GUID (`4967d63b-2e29-4ad8-8399-f6a339e3d001`) as stored on disk.
const BITLOCKER_GUID: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01,
];

fn at(head: &[u8], off: usize, magic: &[u8]) -> bool {
    head.get(off..off + magic.len()) == Some(magic)
}

fn u16le(head: &[u8], off: usize) -> u64 {
    head.get(off..off + 2)
        .map_or(0, |b| u64::from(u16::from_le_bytes([b[0], b[1]])))
}

fn u32le(head: &[u8], off: usize) -> u64 {
    head.get(off..off + 4).map_or(0, |b| {
        u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    })
}

/// Judges a volume from its first bytes, [`HEAD_LEN`] of them or as many as it has.
pub fn detect(head: &[u8]) -> Content {
    // Encryption first: a BitLocker To Go volume is also a valid FAT32 boot sector.
    if at(head, 3, b"-FVE-FS-")
        || at(head, 0xa0, &BITLOCKER_GUID)
        || at(head, 0x1a8, &BITLOCKER_GUID)
    {
        return Content::BitLocker;
    }
    if at(head, 0, b"LUKS\xba\xbe") || at(head, 0, b"SKUL\xba\xbe") {
        return Content::Luks;
    }
    if at(head, 3, b"NTFS    ") {
        return Content::Ntfs;
    }
    if at(head, 3, b"EXFAT   ") {
        return Content::ExFat;
    }
    if let Some(fat) = fat_kind(head) {
        return fat;
    }
    if at(head, 0x438, &[0x53, 0xef]) {
        return Content::Ext;
    }
    if at(head, 0, b"XFSB") {
        return Content::Xfs;
    }
    if at(head, 1024, b"H+") || at(head, 1024, b"HX") {
        return Content::HfsPlus;
    }
    if at(head, 32, b"NXSB") {
        return Content::Apfs;
    }
    if at(head, 0x8001, b"CD001") {
        return Content::Iso9660;
    }
    Content::Unknown
}

/// A FAT boot sector's type by cluster count, or `None` if the BPB doesn't hold together.
fn fat_kind(head: &[u8]) -> Option<Content> {
    if !at(head, 510, &[0x55, 0xaa]) || !matches!(head.first(), Some(0xeb | 0xe9)) {
        return None;
    }
    let bytes_per_sector = u16le(head, 11);
    let per_cluster = u64::from(*head.get(13)?);
    let reserved = u16le(head, 14);
    let fats = u64::from(*head.get(16)?);
    let root_entries = u16le(head, 17);
    let total = match u16le(head, 19) {
        0 => u32le(head, 32),
        n => n,
    };
    let fat_size = match u16le(head, 22) {
        0 => u32le(head, 36),
        n => n,
    };
    let sane = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        && per_cluster.is_power_of_two()
        && reserved > 0
        && fats > 0
        && fat_size > 0;
    if !sane {
        return None;
    }
    let root_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
    let data = total.checked_sub(reserved + fats * fat_size + root_sectors)?;
    Some(match data / per_cluster {
        0..4085 => Content::Fat12,
        4085..65525 => Content::Fat16,
        _ => Content::Fat32,
    })
}

/// A FAT boot sector for tests: sizes in sectors of 512 bytes.
pub fn build_test_fat(total: u32, per_cluster: u8, fat_size: u32, root_entries: u16) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0] = 0xeb;
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = per_cluster;
    b[14..16].copy_from_slice(&32u16.to_le_bytes());
    b[16] = 2;
    b[17..19].copy_from_slice(&root_entries.to_le_bytes());
    b[32..36].copy_from_slice(&total.to_le_bytes());
    if root_entries == 0 {
        b[36..40].copy_from_slice(&fat_size.to_le_bytes());
    } else {
        b[22..24].copy_from_slice(&(fat_size as u16).to_le_bytes());
    }
    b[510] = 0x55;
    b[511] = 0xaa;
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat_type_follows_the_cluster_count_not_the_label() {
        // 64 MiB with 4 KiB clusters and a 32-bit FAT: about 16,000 clusters, so FAT16 by count.
        let mut b = build_test_fat(131_072, 8, 128, 0);
        b[82..90].copy_from_slice(b"FAT32   ");
        assert_eq!(detect(&b), Content::Fat16);
        assert_eq!(detect(&build_test_fat(4_000, 1, 12, 512)), Content::Fat12);
        assert_eq!(
            detect(&build_test_fat(4_000_000, 8, 4_000, 0)),
            Content::Fat32
        );
    }

    #[test]
    fn bitlocker_to_go_is_locked_although_it_looks_like_fat32() {
        let mut b = build_test_fat(4_000_000, 8, 4_000, 0);
        b[0x1a8..0x1b8].copy_from_slice(&BITLOCKER_GUID);
        let c = detect(&b);
        assert_eq!(c, Content::BitLocker);
        assert!(c.is_locked());
        let mut v = vec![0u8; 512];
        v[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(detect(&v), Content::BitLocker);
    }

    #[test]
    fn signatures() {
        let mut b = vec![0u8; HEAD_LEN];
        assert_eq!(detect(&b), Content::Unknown);
        assert_eq!(detect(&[]), Content::Unknown, "short input is no panic");
        b[0x438..0x43a].copy_from_slice(&[0x53, 0xef]);
        assert_eq!(detect(&b), Content::Ext);
        b[0..6].copy_from_slice(b"LUKS\xba\xbe");
        assert!(detect(&b).is_locked());
        let mut iso = vec![0u8; HEAD_LEN];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(detect(&iso), Content::Iso9660);
    }

    #[test]
    fn a_broken_bpb_is_not_fat() {
        let mut b = build_test_fat(131_072, 8, 128, 0);
        b[13] = 3; // sectors per cluster must be a power of two
        assert_eq!(detect(&b), Content::Unknown);
        let mut b = build_test_fat(10, 8, 128, 0); // FAT area bigger than the volume
        b[0] = 0xeb;
        assert_eq!(detect(&b), Content::Unknown);
    }
}
