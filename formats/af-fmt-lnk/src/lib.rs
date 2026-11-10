//! Windows shortcut (`.lnk`) files from bytes (piece X3), after Microsoft's MS-SHLLINK
//! specification. Our own reader (the user's choice): the published crates either read only
//! from a path or round the target times to seconds.
//!
//! Read: the header (target times as stored FILETIMEs, size, attributes), LinkInfo (volume
//! serial, drive type, label, local path, network share, path suffix), the string data (name,
//! relative path, working folder, arguments, icon location), the target's MFT record and
//! sequence number from the last file entry of the shell item list, the tracker block (machine
//! ID, droid IDs, and from the file droid the MAC address and when it was made) and the
//! environment variable target. Not read: the shell item list as a path (a shellbag parser's
//! job) and the other extra blocks. Every read is bounds-checked: damaged input is an error,
//! never a panic.

/// One shortcut file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    /// `LinkFlags`.
    pub flags: u32,
    /// The target's `FILE_ATTRIBUTE_*` flags.
    pub attributes: u32,
    /// The target's times as stored FILETIMEs (0: not set).
    pub created: u64,
    pub accessed: u64,
    pub modified: u64,
    /// The target's size (its low 32 bits).
    pub size: u32,
    pub icon_index: i32,
    pub show_command: u32,
    pub volume: Option<Volume>,
    /// Where the target was, on the local volume.
    pub local_path: Option<String>,
    pub network: Option<Network>,
    /// Appended to the local or network path.
    pub common_path: Option<String>,
    pub name: Option<String>,
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub arguments: Option<String>,
    pub icon_location: Option<String>,
    /// The target's MFT record and sequence number, from the shell item list.
    pub target_mft: Option<(u64, u16)>,
    pub tracker: Option<Tracker>,
    /// The target with environment variables (`%SystemRoot%\...`).
    pub environment: Option<String>,
}

/// The volume the target was on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// 0 unknown, 1 no root folder, 2 removable, 3 fixed, 4 network, 5 CD-ROM, 6 RAM disk.
    pub drive_type: u32,
    pub serial: u32,
    pub label: Option<String>,
}

/// The network share the target was on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub net_name: Option<String>,
    pub device_name: Option<String>,
}

/// The distributed link tracking data: where the target was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracker {
    /// The NetBIOS name of the machine the target was on.
    pub machine_id: String,
    pub volume_droid: String,
    pub file_droid: String,
    pub volume_droid_birth: String,
    pub file_droid_birth: String,
    /// From the file droid, when it is a time-based (version 1) GUID.
    pub mac: Option<String>,
    /// When the file droid was made, as a FILETIME.
    pub droid_created: Option<u64>,
}

const HEADER_SIZE: usize = 0x4C;
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
];
const HAS_ID_LIST: u32 = 0x1;
const HAS_LINK_INFO: u32 = 0x2;
const IS_UNICODE: u32 = 0x80;
/// `HasName` to `HasIconLocation`, in the order the strings follow.
const STRINGS: [u32; 5] = [0x4, 0x8, 0x10, 0x20, 0x40];
const TRACKER: u32 = 0xA000_0003;
const ENVIRONMENT: u32 = 0xA000_0001;
/// From the UUID epoch (1582-10-15) to the FILETIME epoch (1601-01-01), in 100 ns.
const UUID_TO_FILETIME: u64 = 5_748_192_000_000_000;

/// Reads a shortcut file.
pub fn read(data: &[u8]) -> Result<Link, String> {
    let b = Bytes(data);
    // Too short for a header is no shortcut either.
    if b.u32(0).ok() != Some(HEADER_SIZE as u32) || b.get(4, 16).ok() != Some(&LINK_CLSID[..]) {
        return Err("not a shortcut: no ShellLinkHeader".into());
    }
    let flags = b.u32(0x14)?;
    let mut link = Link {
        flags,
        attributes: b.u32(0x18)?,
        created: b.u64(0x1C)?,
        accessed: b.u64(0x24)?,
        modified: b.u64(0x2C)?,
        size: b.u32(0x34)?,
        icon_index: b.u32(0x38)? as i32,
        show_command: b.u32(0x3C)?,
        ..Link::default()
    };
    let mut at = HEADER_SIZE;
    if flags & HAS_ID_LIST != 0 {
        let size = usize::from(b.u16(at)?);
        link.target_mft = target_mft(b.get(at + 2, size)?);
        at += 2 + size;
    }
    if flags & HAS_LINK_INFO != 0 {
        let size = b.u32(at)? as usize;
        link_info(&mut link, Bytes(b.get(at, size)?))?;
        at += size;
    }
    let unicode = flags & IS_UNICODE != 0;
    let mut strings = [None, None, None, None, None];
    for (slot, flag) in strings.iter_mut().zip(STRINGS) {
        if flags & flag != 0 {
            let chars = usize::from(b.u16(at)?);
            let len = if unicode { chars * 2 } else { chars };
            let raw = b.get(at + 2, len)?;
            *slot = Some(if unicode { utf16(raw) } else { ansi(raw) });
            at += 2 + len;
        }
    }
    [
        link.name,
        link.relative_path,
        link.working_dir,
        link.arguments,
        link.icon_location,
    ] = strings;
    // Extra data blocks until a terminal block (size under 4) or the end.
    while let Ok(size) = b.u32(at) {
        let size = size as usize;
        if size < 8 {
            break;
        }
        let block = Bytes(b.get(at, size)?);
        match block.u32(4)? {
            TRACKER => link.tracker = Some(tracker(block)?),
            ENVIRONMENT => {
                let wide = utf16(block.get(268, 520).unwrap_or_default());
                link.environment = Some(if wide.is_empty() {
                    ansi(block.get(8, 260)?)
                } else {
                    wide
                });
            }
            _ => {}
        }
        at += size;
    }
    Ok(link)
}

/// The volume and paths of a LinkInfo structure.
fn link_info(link: &mut Link, b: Bytes<'_>) -> Result<(), String> {
    let header = b.u32(4)? as usize;
    let info_flags = b.u32(8)?;
    let offset = |at: usize| -> Result<usize, String> { Ok(b.u32(at)? as usize) };
    // Unicode offsets follow when the header is 0x24 bytes or more.
    let wide = |at: usize| -> Option<usize> {
        (header >= 0x24)
            .then(|| b.u32(at).ok().map(|o| o as usize))
            .flatten()
    };
    if info_flags & 0x1 != 0 {
        let v = offset(0x0C)?;
        let label_offset = b.u32(v + 0x0C)? as usize;
        let label = if label_offset == 0x14 {
            b.utf16z(v + b.u32(v + 0x10)? as usize)?
        } else {
            b.ansiz(v + label_offset)?
        };
        link.volume = Some(Volume {
            drive_type: b.u32(v + 4)?,
            serial: b.u32(v + 8)?,
            label: Some(label).filter(|l| !l.is_empty()),
        });
        link.local_path = Some(match wide(0x1C).filter(|&o| o > 0) {
            Some(o) => b.utf16z(o)?,
            None => b.ansiz(offset(0x10)?)?,
        });
    }
    if info_flags & 0x2 != 0 {
        let n = offset(0x14)?;
        let net = b.u32(n + 8)? as usize;
        let device = b.u32(n + 0x0C)? as usize;
        let (net, device) = if net > 0x14 {
            (
                b.utf16z(n + b.u32(n + 0x14)? as usize)?,
                b.u32(n + 0x18)
                    .ok()
                    .filter(|&o| o > 0)
                    .map(|o| b.utf16z(n + o as usize))
                    .transpose()?,
            )
        } else {
            (
                b.ansiz(n + net)?,
                (b.u32(n + 4)? & 0x1 != 0 && device > 0)
                    .then(|| b.ansiz(n + device))
                    .transpose()?,
            )
        };
        link.network = Some(Network {
            net_name: Some(net).filter(|s| !s.is_empty()),
            device_name: device.filter(|s| !s.is_empty()),
        });
    }
    let common = match wide(0x20).filter(|&o| o > 0) {
        Some(o) => b.utf16z(o)?,
        None => match offset(0x18)? {
            0 => String::new(),
            o => b.ansiz(o)?,
        },
    };
    link.common_path = Some(common).filter(|s| !s.is_empty());
    Ok(())
}

/// The MFT reference in the last file entry shell item that has one, delegate items included:
/// its `0xBEEF0004`
/// extension block, version 7 or later, holds it at offset 20.
fn target_mft(list: &[u8]) -> Option<(u64, u16)> {
    let b = Bytes(list);
    let (mut at, mut found) = (0, None);
    while let Ok(size) = b.u16(at) {
        let size = usize::from(size);
        if size < 3 {
            break;
        }
        let Ok(item) = b.get(at, size) else { break };
        // A file entry item (class type 0x30 to 0x3F), or a delegate item (0x74) wrapping one,
        // as under the "users files" root.
        if item[2] & 0x70 == 0x30 || item[2] == 0x74 {
            let sig = [0x04, 0x00, 0xEF, 0xBE];
            if let Some(p) = item.windows(4).position(|w| w == sig).filter(|&p| p >= 4) {
                let ext = Bytes(&item[p - 4..]);
                if ext.u16(2).is_ok_and(|v| v >= 7)
                    && let Ok(r) = ext.u64(20)
                    // Zero: no reference (a file on a FAT stick has none).
                    && r != 0
                {
                    found = Some((r & 0xFFFF_FFFF_FFFF, (r >> 48) as u16));
                }
            }
        }
        at += size;
    }
    found
}

fn tracker(b: Bytes<'_>) -> Result<Tracker, String> {
    let guid = |at: usize| -> Result<[u8; 16], String> {
        b.get(at, 16)?
            .try_into()
            .map_err(|_| "short GUID".to_string())
    };
    let file = guid(0x30)?;
    // A version 1 GUID: the time and the node (the MAC address) of the machine that made it.
    let v1 = file[7] >> 4 == 1;
    let time = u64::from(u32::from_le_bytes([file[0], file[1], file[2], file[3]]))
        | u64::from(u16::from_le_bytes([file[4], file[5]])) << 32
        | u64::from(u16::from_le_bytes([file[6], file[7]]) & 0x0FFF) << 48;
    Ok(Tracker {
        machine_id: ansi(b.get(0x10, 16)?),
        volume_droid: guid_text(&guid(0x20)?),
        file_droid: guid_text(&file),
        volume_droid_birth: guid_text(&guid(0x40)?),
        file_droid_birth: guid_text(&guid(0x50)?),
        mac: v1.then(|| {
            file[10..]
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        }),
        droid_created: v1.then(|| time.checked_sub(UUID_TO_FILETIME)).flatten(),
    })
}

/// A GUID as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, lowercase.
fn guid_text(g: &[u8; 16]) -> String {
    let hex = |r: &[u8]| r.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        hex(&g[8..10]),
        hex(&g[10..])
    )
}

/// UTF-16LE up to the first NUL.
fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The system's ANSI code page up to the first NUL, read as Latin-1.
// shortcut: Latin-1 differs from Windows-1252 in 0x80 to 0x9F, and other code pages more;
// read the code page from the image when a non-ASCII ANSI path turns up.
fn ansi(b: &[u8]) -> String {
    b.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| char::from(c))
        .collect()
}

/// Bounds-checked little-endian reads.
#[derive(Clone, Copy)]
struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn get(&self, at: usize, len: usize) -> Result<&'a [u8], String> {
        at.checked_add(len)
            .and_then(|end| self.0.get(at..end))
            .ok_or_else(|| format!("{len} bytes at {at} are past the end ({})", self.0.len()))
    }
    fn u16(&self, at: usize) -> Result<u16, String> {
        Ok(u16::from_le_bytes(
            self.get(at, 2)?.try_into().expect("two bytes"),
        ))
    }
    fn u32(&self, at: usize) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.get(at, 4)?.try_into().expect("four bytes"),
        ))
    }
    fn u64(&self, at: usize) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.get(at, 8)?.try_into().expect("eight bytes"),
        ))
    }
    fn ansiz(&self, at: usize) -> Result<String, String> {
        Ok(ansi(self.get(at, self.0.len().saturating_sub(at))?))
    }
    fn utf16z(&self, at: usize) -> Result<String, String> {
        Ok(utf16(self.get(at, self.0.len().saturating_sub(at))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u32) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_SIZE];
        h[0..4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        h[4..20].copy_from_slice(&LINK_CLSID);
        h[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
        h[0x1C..0x24].copy_from_slice(&131_674_911_875_724_698u64.to_le_bytes());
        h[0x34..0x38].copy_from_slice(&41_171_024u32.to_le_bytes());
        h
    }

    /// A LinkInfo with a volume (fixed, serial, label `OSDisk`) and an ANSI local path.
    fn link_info_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 0x10];
        v[0..4].copy_from_slice(&0x16u32.to_le_bytes()); // volume ID size
        v[4..8].copy_from_slice(&3u32.to_le_bytes());
        v[8..12].copy_from_slice(&0x74EE_2D73u32.to_le_bytes());
        v[12..16].copy_from_slice(&0x10u32.to_le_bytes());
        v.extend(b"OSDisk\0");
        let path = b"C:\\Users\\ich\\Downloads\\x.exe\0";
        let (v_at, p_at) = (0x1C, 0x1C + v.len());
        let mut i = vec![0u8; 0x1C];
        i[4..8].copy_from_slice(&0x1Cu32.to_le_bytes());
        i[8..12].copy_from_slice(&1u32.to_le_bytes());
        i[0x0C..0x10].copy_from_slice(&(v_at as u32).to_le_bytes());
        i[0x10..0x14].copy_from_slice(&(p_at as u32).to_le_bytes());
        i.extend(&v);
        i.extend(path);
        i.push(0); // the empty common path suffix
        let suffix = (i.len() - 1) as u32;
        i[0x18..0x1C].copy_from_slice(&suffix.to_le_bytes());
        let len = i.len() as u32;
        i[0..4].copy_from_slice(&len.to_le_bytes());
        i
    }

    /// stage 0's PowerShell link's tracker block (LECmd: leeholm16, 00:1c:c4:2d:f4:0b,
    /// 2012-11-20 23:23:58).
    fn tracker_bytes() -> Vec<u8> {
        let mut t = vec![0u8; 0x60];
        t[0..4].copy_from_slice(&0x60u32.to_le_bytes());
        t[4..8].copy_from_slice(&TRACKER.to_le_bytes());
        t[8..12].copy_from_slice(&0x58u32.to_le_bytes());
        t[0x10..0x19].copy_from_slice(b"leeholm16");
        let file = [
            0xd9, 0x07, 0x23, 0x5c, 0x69, 0x33, 0xe2, 0x11, 0xbe, 0x70, 0x00, 0x1c, 0xc4, 0x2d,
            0xf4, 0x0b,
        ];
        t[0x30..0x40].copy_from_slice(&file);
        t[0x50..0x60].copy_from_slice(&file);
        t
    }

    #[test]
    fn header_link_info_strings_and_tracker() {
        let mut b = header(HAS_LINK_INFO | 0x8 | IS_UNICODE);
        b.extend(link_info_bytes());
        let rel: Vec<u8> = "..\\x.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b.extend(8u16.to_le_bytes());
        b.extend(rel);
        b.extend(tracker_bytes());
        b.extend([0u8; 4]);
        let l = read(&b).unwrap();
        assert_eq!((l.created, l.size), (131_674_911_875_724_698, 41_171_024));
        assert_eq!(
            l.volume,
            Some(Volume {
                drive_type: 3,
                serial: 0x74EE_2D73,
                label: Some("OSDisk".into())
            })
        );
        assert_eq!(
            l.local_path.as_deref(),
            Some("C:\\Users\\ich\\Downloads\\x.exe")
        );
        assert_eq!(l.common_path, None);
        assert_eq!(l.relative_path.as_deref(), Some("..\\x.exe"));
        let t = l.tracker.unwrap();
        assert_eq!(t.machine_id, "leeholm16");
        assert_eq!(t.file_droid, "5c2307d9-3369-11e2-be70-001cc42df40b");
        assert_eq!(t.mac.as_deref(), Some("00:1c:c4:2d:f4:0b"));
        // 2012-11-20 23:23:58 UTC and some 100 ns.
        let secs = t.droid_created.unwrap() / 10_000_000 - 11_644_473_600;
        assert_eq!(secs, 1_353_453_838);
    }

    #[test]
    fn file_entry_shell_item_gives_the_mft_reference() {
        // One file entry item (class 0x32) with a version 9 BEEF0004 block: record 0xF9FF,
        // sequence 1.
        let mut ext = vec![0u8; 28];
        ext[0..2].copy_from_slice(&28u16.to_le_bytes());
        ext[2..4].copy_from_slice(&9u16.to_le_bytes());
        ext[4..8].copy_from_slice(&0xBEEF_0004u32.to_le_bytes());
        ext[20..28].copy_from_slice(&(0xF9FFu64 | 1 << 48).to_le_bytes());
        let mut item = vec![0u8, 0, 0x32, 0];
        item.extend(b"POWERS~1.EXE\0\0");
        item.extend(&ext);
        let len = item.len() as u16;
        item[0..2].copy_from_slice(&len.to_le_bytes());
        let mut list = item.clone();
        list.extend([0, 0]);
        let mut b = header(HAS_ID_LIST);
        b.extend((list.len() as u16).to_le_bytes());
        b.extend(&list);
        assert_eq!(read(&b).unwrap().target_mft, Some((0xF9FF, 1)));
    }

    #[test]
    fn damage_is_an_error_not_a_panic() {
        assert!(read(b"").is_err());
        assert!(read(&[0xFF; 200]).is_err());
        let mut b = header(HAS_ID_LIST | HAS_LINK_INFO | 0x7C | IS_UNICODE);
        b.extend([0xFF; 40]);
        assert!(read(&b).is_err());
        // Every cut of a good file reads or fails, never panics.
        let mut good = header(HAS_LINK_INFO | 0x8 | IS_UNICODE);
        good.extend(link_info_bytes());
        good.extend(tracker_bytes());
        for n in 0..good.len() {
            let _ = read(&good[..n]);
        }
    }
}
