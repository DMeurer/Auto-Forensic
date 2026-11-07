//! Zip and tar archives as file systems (piece I22): a KAPE collection or a `tar` of a Linux root,
//! read in place without unpacking.
//!
//! Both are parsed here rather than with the `zip` and `tar` crates, so every member keeps its
//! offset in the archive: a stored zip member or a tar member is a window of the archive, a
//! deflated zip member a [`DecodedSource`] over it. Folders that only show in member paths are
//! made up; a path that appears twice keeps the later member, as unpacking would; `.` names are
//! dropped (`tar -C dir .` writes `./etc/hostname`).
//!
//! Not read yet: member times, hard links in a tar, compressed tars (`.tar.gz`), split zips, and
//! encrypted or non-deflate zip members (listed, but opening them is an error).

use af_core::bytes::{ByteSource, DecodedSource, ExtentSource};
use af_core::fs::{Entry, EntryKind, EntryName, FileSystem, FsInfo, StreamInfo, StreamName};
use af_core::ids::FileId;
use af_core::names::Kind;
use af_core::path::{CasePolicy, Name};
use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::Arc;

/// A zip or tar archive read as a file system.
pub struct Archive {
    src: Arc<dyn ByteSource>,
    info: FsInfo,
    nodes: Vec<Node>,
}

struct Node {
    name: Vec<u8>,
    parent: usize,
    kind: EntryKind,
    data: Option<Member>,
}

/// Where a member's bytes lie in the archive.
#[derive(Debug, Clone, Copy)]
struct Member {
    offset: u64,
    packed: u64,
    size: u64,
    how: How,
}

#[derive(Debug, Clone, Copy)]
enum How {
    Stored,
    Deflate { crc: u32 },
    Method(u16),
    Encrypted,
}

type Members = Vec<(Vec<u8>, EntryKind, Option<Member>)>;

fn kind(name: &str) -> Kind {
    Kind::new(name).expect("a valid built-in name")
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

fn id(n: usize) -> FileId {
    FileId {
        scheme: kind("archive.member"),
        value: (n as u64).to_le_bytes().to_vec(),
    }
}

impl Archive {
    /// Opens `src` as a tar (a valid first header) or a zip (an end of central directory record).
    pub fn open(src: Arc<dyn ByteSource>) -> io::Result<Self> {
        let (fs_kind, members) = match tar(&*src)? {
            Some(m) => ("fs.tar", m),
            None => match zip(&*src)? {
                Some(m) => ("fs.zip", m),
                None => return Err(bad("neither a zip nor a tar")),
            },
        };
        Ok(Self {
            src,
            info: FsInfo {
                kind: kind(fs_kind),
                case: CasePolicy::Exact,
                label: None,
                serial: None,
                time_names: vec![],
                finds_deleted: false,
            },
            nodes: tree(members),
        })
    }

    fn node(&self, id: &FileId) -> Option<(usize, &Node)> {
        if id.scheme.as_str() != "archive.member" {
            return None;
        }
        let n = usize::try_from(u64::from_le_bytes(id.value.as_slice().try_into().ok()?)).ok()?;
        self.nodes.get(n).map(|node| (n, node))
    }

    fn entry_of(&self, n: usize) -> Entry {
        let node = &self.nodes[n];
        Entry {
            id: id(n),
            kind: node.kind,
            names: if n == 0 {
                vec![]
            } else {
                vec![EntryName {
                    parent: id(node.parent),
                    name: Name::from_bytes(&node.name),
                    kind: kind("fs.name"),
                    alias: false,
                }]
            },
            times: vec![],
            allocated: true,
            recovered: None,
            streams: node
                .data
                .map(|m| StreamInfo {
                    name: StreamName::Default,
                    kind: kind("fs.data"),
                    size: m.size,
                })
                .into_iter()
                .collect(),
            attrs: vec![],
        }
    }
}

impl FileSystem for Archive {
    fn info(&self) -> &FsInfo {
        &self.info
    }
    fn root(&self) -> FileId {
        id(0)
    }
    fn entry(&self, id: &FileId) -> io::Result<Option<Entry>> {
        Ok(self.node(id).map(|(n, _)| self.entry_of(n)))
    }
    fn list(&self, dir: &FileId) -> io::Result<Vec<(Name, FileId)>> {
        let Some((d, _)) = self.node(dir) else {
            return Ok(vec![]);
        };
        Ok((1..self.nodes.len())
            .filter(|&n| self.nodes[n].parent == d)
            .map(|n| (Name::from_bytes(&self.nodes[n].name), id(n)))
            .collect())
    }
    fn all(&self) -> Box<dyn Iterator<Item = io::Result<Entry>> + '_> {
        Box::new((0..self.nodes.len()).map(|n| Ok(self.entry_of(n))))
    }
    fn open(&self, id: &FileId, stream: &StreamName) -> io::Result<Option<Arc<dyn ByteSource>>> {
        let Some((_, Node { data: Some(m), .. })) = self.node(id) else {
            return Ok(None);
        };
        if *stream != StreamName::Default {
            return Ok(None);
        }
        let loc = self.src.locator().child("fs.file", &m.offset.to_string());
        match m.how {
            How::Stored => Ok(Some(Arc::new(ExtentSource::slice(
                self.src.clone(),
                m.offset,
                m.size,
                loc,
            )?))),
            How::Deflate { crc } => {
                // shortcut: a deflated member costs its packed and full size in memory; stream it
                // if big members (a KAPE `$MFT`) need it.
                let mut packed = vec![0; m.packed as usize];
                self.src.read_exact_at(m.offset, &mut packed)?;
                let mut data = Vec::new();
                flate2::read::DeflateDecoder::new(&packed[..])
                    .take(m.size.saturating_add(1))
                    .read_to_end(&mut data)?;
                let mut sum = flate2::Crc::new();
                sum.update(&data);
                if data.len() as u64 != m.size || sum.sum() != crc {
                    return Err(bad("a zip member doesn't match its size or CRC"));
                }
                Ok(Some(Arc::new(DecodedSource::new(
                    self.src.clone(),
                    data,
                    loc,
                ))))
            }
            How::Method(x) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("zip compression method {x} isn't read"),
            )),
            How::Encrypted => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "encrypted zip members aren't read",
            )),
        }
    }
}

/// Folders and files from member paths. Node 0 is the root.
fn tree(members: Members) -> Vec<Node> {
    let mut nodes = vec![Node {
        name: vec![],
        parent: 0,
        kind: EntryKind::Folder,
        data: None,
    }];
    let mut index: HashMap<(usize, Vec<u8>), usize> = HashMap::new();
    let mut child = |nodes: &mut Vec<Node>, parent: usize, name: &[u8]| {
        *index.entry((parent, name.to_vec())).or_insert_with(|| {
            nodes.push(Node {
                name: name.to_vec(),
                parent,
                kind: EntryKind::Folder,
                data: None,
            });
            nodes.len() - 1
        })
    };
    for (path, kind, data) in members {
        let parts: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty() && *p != b".")
            .collect();
        let Some((last, dirs)) = parts.split_last() else {
            continue;
        };
        let mut at = 0;
        for d in dirs {
            at = child(&mut nodes, at, d);
            nodes[at].kind = EntryKind::Folder;
        }
        let n = child(&mut nodes, at, last);
        nodes[n].kind = kind;
        nodes[n].data = data;
    }
    nodes
}

fn read(src: &dyn ByteSource, at: u64, len: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; usize::try_from(len).map_err(|_| bad("too long"))?];
    src.read_exact_at(at, &mut buf)?;
    Ok(buf)
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// `[at, at + len)` lies inside a source of `total` bytes.
fn inside(at: u64, len: u64, total: u64) -> bool {
    at.checked_add(len).is_some_and(|end| end <= total)
}

/// The members of a zip, from its central directory; `None` if there is no end record.
fn zip(src: &dyn ByteSource) -> io::Result<Option<Members>> {
    let len = src.len();
    let tail_len = len.min(22 + 0xFFFF);
    let tail = read(src, len - tail_len, tail_len)?;
    let Some(e) = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| tail[i..i + 4] == *b"PK\x05\x06")
    else {
        return Ok(None);
    };
    let eocd = &tail[e..];
    if le16(eocd, 4) != 0 || le16(eocd, 6) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "split zips aren't read",
        ));
    }
    let (mut count, mut cd_size, mut cd_at) = (
        u64::from(le16(eocd, 10)),
        u64::from(le32(eocd, 12)),
        u64::from(le32(eocd, 16)),
    );
    let eocd_at = len - tail_len + e as u64;
    if eocd_at >= 20 {
        let loc = read(src, eocd_at - 20, 20)?;
        if loc[..4] == *b"PK\x06\x07" {
            let z = read(src, le64(&loc, 8), 56)?;
            if z[..4] != *b"PK\x06\x06" {
                return Err(bad("the ZIP64 end record is missing"));
            }
            (count, cd_size, cd_at) = (le64(&z, 32), le64(&z, 40), le64(&z, 48));
        }
    }
    if !inside(cd_at, cd_size, len) {
        return Err(bad("the central directory lies outside the zip"));
    }
    let cd = read(src, cd_at, cd_size)?;
    let mut out = Vec::new();
    let mut at = 0usize;
    for _ in 0..count {
        let h = cd
            .get(at..at + 46)
            .filter(|h| h[..4] == *b"PK\x01\x02")
            .ok_or_else(|| bad("a broken central directory entry"))?;
        let (flags, method, crc) = (le16(h, 8), le16(h, 10), le32(h, 16));
        let (mut packed, mut size, mut local) = (
            u64::from(le32(h, 20)),
            u64::from(le32(h, 24)),
            u64::from(le32(h, 42)),
        );
        let (nl, xl, cl) = (
            usize::from(le16(h, 28)),
            usize::from(le16(h, 30)),
            usize::from(le16(h, 32)),
        );
        let name = cd
            .get(at + 46..at + 46 + nl)
            .ok_or_else(|| bad("a central directory name runs past its end"))?
            .to_vec();
        let extra = cd
            .get(at + 46 + nl..at + 46 + nl + xl)
            .ok_or_else(|| bad("a central directory extra field runs past its end"))?;
        let mut x = 0;
        while x + 4 <= extra.len() {
            let (tag, n) = (le16(extra, x), usize::from(le16(extra, x + 2)));
            if tag == 1 {
                // ZIP64: the 64-bit values, in this order, of the fields that hold 0xFFFFFFFF.
                let mut vals = extra
                    .get(x + 4..x + 4 + n)
                    .unwrap_or_default()
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|c| u64::from_le_bytes(*c));
                for v in [&mut size, &mut packed, &mut local] {
                    if *v == 0xFFFF_FFFF {
                        *v = vals.next().ok_or_else(|| bad("a short ZIP64 field"))?;
                    }
                }
            }
            x += 4 + n;
        }
        at += 46 + nl + xl + cl;
        if name.ends_with(b"/") {
            out.push((name, EntryKind::Folder, None));
            continue;
        }
        let lh = read(src, local, 30)?;
        if lh[..4] != *b"PK\x03\x04" {
            return Err(bad("a zip member has no local header"));
        }
        let offset = local + 30 + u64::from(le16(&lh, 26)) + u64::from(le16(&lh, 28));
        let how = match (flags & 1, method) {
            (1, _) => How::Encrypted,
            (_, 0) if packed != size => return Err(bad("a stored zip member changes size")),
            (_, 0) => How::Stored,
            (_, 8) => How::Deflate { crc },
            (_, m) => How::Method(m),
        };
        if !inside(offset, packed, len) {
            return Err(bad("a zip member runs past the end"));
        }
        out.push((
            name,
            EntryKind::File,
            Some(Member {
                offset,
                packed,
                size,
                how,
            }),
        ));
    }
    Ok(Some(out))
}

/// The members of a tar; `None` if the first header's checksum is wrong (not a tar).
fn tar(src: &dyn ByteSource) -> io::Result<Option<Members>> {
    let len = src.len();
    let mut out = Vec::new();
    let (mut long, mut pax_path, mut pax_size) = (None, None, None);
    let mut at = 0u64;
    while at + 512 <= len {
        let h = read(src, at, 512)?;
        if h.iter().all(|&b| b == 0) {
            break;
        }
        if !checksum_ok(&h) {
            if at == 0 {
                return Ok(None);
            }
            return Err(bad("a tar header's checksum is wrong"));
        }
        let size = match pax_size.take() {
            Some(s) => s,
            None => number(&h[124..136])?,
        };
        let data = at + 512;
        if !inside(data, size, len) {
            return Err(bad("a tar member runs past the end"));
        }
        match h[156] {
            b'L' => long = Some(until_nul(&read(src, data, size)?).to_vec()),
            b'x' => (pax_path, pax_size) = pax(&read(src, data, size)?),
            b'g' | b'K' => {}
            t => {
                let name = match (long.take(), pax_path.take()) {
                    (Some(n), _) | (None, Some(n)) => n,
                    (None, None) => ustar_name(&h),
                };
                let (kind, member) = match t {
                    b'0' | 0 | b'7' => (
                        EntryKind::File,
                        Some(Member {
                            offset: data,
                            packed: size,
                            size,
                            how: How::Stored,
                        }),
                    ),
                    b'5' => (EntryKind::Folder, None),
                    b'2' => (EntryKind::Symlink, None),
                    _ => (EntryKind::Other, None),
                };
                out.push((name, kind, member));
            }
        }
        at = data + size.div_ceil(512) * 512;
    }
    Ok((at > 0).then_some(out))
}

fn until_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn checksum_ok(h: &[u8]) -> bool {
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| u64::from(if (148..156).contains(&i) { b' ' } else { b }))
        .sum();
    number(&h[148..156]).is_ok_and(|want| want == sum)
}

/// A tar number: octal text, or base-256 when the top bit is set (GNU, for sizes over 8 GiB).
fn number(f: &[u8]) -> io::Result<u64> {
    if f[0] & 0x80 != 0 {
        return f[1..].iter().try_fold(u64::from(f[0] & 0x7F), |n, &b| {
            n.checked_mul(256)
                .map(|n| n + u64::from(b))
                .ok_or_else(|| bad("a tar number is too big"))
        });
    }
    let text = std::str::from_utf8(f).map_err(|_| bad("a tar number isn't text"))?;
    let text = text.trim_matches(|c| c == '\0' || c == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| bad("a tar number isn't octal"))
}

fn ustar_name(h: &[u8]) -> Vec<u8> {
    let name = until_nul(&h[0..100]);
    let prefix = until_nul(&h[345..500]);
    if &h[257..262] == b"ustar" && !prefix.is_empty() {
        [prefix, b"/", name].concat()
    } else {
        name.to_vec()
    }
}

/// `path` and `size` from pax records (`<len> <key>=<value>\n`).
fn pax(mut d: &[u8]) -> (Option<Vec<u8>>, Option<u64>) {
    let (mut path, mut size) = (None, None);
    while let Some(sp) = d.iter().position(|&b| b == b' ') {
        let Some(n) = std::str::from_utf8(&d[..sp])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > sp + 1 && n <= d.len())
        else {
            break;
        };
        let rec = &d[sp + 1..n - 1];
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            match &rec[..eq] {
                b"path" => path = Some(rec[eq + 1..].to_vec()),
                b"size" => {
                    size = std::str::from_utf8(&rec[eq + 1..])
                        .ok()
                        .and_then(|s| s.parse().ok())
                }
                _ => {}
            }
        }
        d = &d[n..];
    }
    (path, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_numbers_read_octal_and_base_256() {
        assert_eq!(number(b"00000001750\0").unwrap(), 1000);
        assert_eq!(number(b"     \0\0\0\0\0\0\0").unwrap(), 0);
        let mut big = [0u8; 12];
        big[0] = 0x80;
        big[7] = 0x02; // 2 << 32
        assert_eq!(number(&big).unwrap(), 2 << 32);
    }

    #[test]
    fn pax_records_give_path_and_size() {
        let d = b"29 path=a/very/long/name.bin\n17 size=12345678\n";
        assert_eq!(
            pax(d),
            (Some(b"a/very/long/name.bin".to_vec()), Some(12_345_678))
        );
    }
}
