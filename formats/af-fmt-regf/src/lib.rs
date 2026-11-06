//! Registry hive (regf) basics, from bytes (piece F22).
//!
//! Enough to tell what a loose hive is: the base block's signature and the names of the root
//! key's subkeys. Full parsing with transaction-log replay comes with the registry plugins.
//! Every offset is checked, so a broken or crafted hive gives an error, never a panic.
//!
//! Layout used: the base block (4096 bytes) starts with `regf` and holds the root cell offset at
//! 0x24, relative to the first hive bin at 0x1000. A cell starts with its size as i32 (negative
//! when allocated). A key cell (`nk`) has its subkey count at 0x14, its subkey list at 0x1C,
//! flags at 0x02 (0x0020: the name is Latin-1, otherwise UTF-16LE), name length at 0x48 and the
//! name at 0x4C. Subkey lists are `lf`/`lh` (offset and hash per entry), `li` (offsets) and `ri`
//! (offsets of further lists).

use std::fmt;

const BINS: usize = 0x1000;
const KEY_COMP_NAME: u16 = 0x0020;
/// `ri` lists point at lists; real hives nest them one level, so a few levels are plenty.
const MAX_LIST_DEPTH: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegfError {
    /// No `regf` signature at the start.
    NotRegf,
    /// An offset or length points outside the data.
    OutOfBounds(&'static str),
    /// A cell isn't what the structure says it should be.
    BadCell(&'static str),
}

impl fmt::Display for RegfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegf => write!(f, "not a registry hive (no regf signature)"),
            Self::OutOfBounds(what) => write!(f, "{what} points outside the hive"),
            Self::BadCell(what) => write!(f, "{what} isn't a valid cell"),
        }
    }
}

impl std::error::Error for RegfError {}

/// Whether the data starts like a registry hive.
pub fn is_regf(data: &[u8]) -> bool {
    data.starts_with(b"regf")
}

/// The names of the root key's subkeys, in list order.
pub fn root_subkey_names(data: &[u8]) -> Result<Vec<String>, RegfError> {
    if !is_regf(data) {
        return Err(RegfError::NotRegf);
    }
    let root = u32_at(data, 0x24, "root cell offset")?;
    let nk = cell(data, root, "root key")?;
    if nk.get(..2) != Some(b"nk") {
        return Err(RegfError::BadCell("root key"));
    }
    let count = u32_at(nk, 0x14, "subkey count")?;
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut keys = Vec::new();
    collect_list(data, u32_at(nk, 0x1C, "subkey list offset")?, 0, &mut keys)?;
    keys.iter().map(|&off| key_name(data, off)).collect()
}

/// Appends the key cell offsets of a subkey list.
fn collect_list(data: &[u8], offset: u32, depth: u32, out: &mut Vec<u32>) -> Result<(), RegfError> {
    if depth > MAX_LIST_DEPTH {
        return Err(RegfError::BadCell("subkey list nesting"));
    }
    let list = cell(data, offset, "subkey list")?;
    let n = usize::from(u16_at(list, 2, "subkey list count")?);
    let (step, nested) = match list.get(..2) {
        Some(b"lf") | Some(b"lh") => (8, false),
        Some(b"li") => (4, false),
        Some(b"ri") => (4, true),
        _ => return Err(RegfError::BadCell("subkey list")),
    };
    for i in 0..n {
        let entry = u32_at(list, 4 + i * step, "subkey list entry")?;
        if nested {
            collect_list(data, entry, depth + 1, out)?;
        } else {
            out.push(entry);
        }
    }
    Ok(())
}

fn key_name(data: &[u8], offset: u32) -> Result<String, RegfError> {
    let nk = cell(data, offset, "subkey")?;
    if nk.get(..2) != Some(b"nk") {
        return Err(RegfError::BadCell("subkey"));
    }
    let flags = u16_at(nk, 0x02, "key flags")?;
    let len = usize::from(u16_at(nk, 0x48, "key name length")?);
    let raw = nk
        .get(0x4C..0x4C + len)
        .ok_or(RegfError::OutOfBounds("key name"))?;
    Ok(if flags & KEY_COMP_NAME != 0 {
        raw.iter().map(|&b| char::from(b)).collect()
    } else {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    })
}

/// The body of the cell at `offset` (relative to the hive bins), without its size field.
fn cell<'a>(data: &'a [u8], offset: u32, what: &'static str) -> Result<&'a [u8], RegfError> {
    let start = BINS
        .checked_add(offset as usize)
        .ok_or(RegfError::OutOfBounds(what))?;
    let size = i32::from_le_bytes(
        data.get(start..start + 4)
            .ok_or(RegfError::OutOfBounds(what))?
            .try_into()
            .expect("four bytes"),
    );
    let len = size.unsigned_abs() as usize;
    if len < 8 {
        return Err(RegfError::BadCell(what));
    }
    data.get(start + 4..start + len)
        .ok_or(RegfError::OutOfBounds(what))
}

fn u32_at(b: &[u8], at: usize, what: &'static str) -> Result<u32, RegfError> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes(s.try_into().expect("four bytes")))
        .ok_or(RegfError::OutOfBounds(what))
}

fn u16_at(b: &[u8], at: usize, what: &'static str) -> Result<u16, RegfError> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes(s.try_into().expect("two bytes")))
        .ok_or(RegfError::OutOfBounds(what))
}

/// Builds a tiny hive whose root key has `names` as subkeys, for tests of this crate and others.
/// Names with a char above U+00FF are stored as UTF-16, others as Latin-1. `list` picks the
/// subkey list type: `lf`, `lh`, `li`, or `ri` (one `ri` holding one `lf`).
pub fn build_test_hive(names: &[&str], list: &str) -> Vec<u8> {
    let mut bins: Vec<u8> = b"hbin".to_vec();
    bins.resize(0x20, 0);
    let push_cell = |bins: &mut Vec<u8>, body: &[u8]| -> u32 {
        let offset = bins.len() as u32;
        let len = (4 + body.len()).div_ceil(8) * 8;
        bins.extend_from_slice(&(-(len as i32)).to_le_bytes());
        bins.extend_from_slice(body);
        bins.resize(offset as usize + len, 0);
        offset
    };
    let nk = |name: &str, subkeys: u32, list: u32| -> Vec<u8> {
        let latin1 = name.chars().all(|c| u32::from(c) <= 0xFF);
        let raw: Vec<u8> = if latin1 {
            name.chars().map(|c| c as u8).collect()
        } else {
            name.encode_utf16().flat_map(u16::to_le_bytes).collect()
        };
        let mut b = vec![0u8; 0x4C];
        b[..2].copy_from_slice(b"nk");
        let flags: u16 = if latin1 { KEY_COMP_NAME } else { 0 };
        b[2..4].copy_from_slice(&flags.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&subkeys.to_le_bytes());
        b[0x1C..0x20].copy_from_slice(&list.to_le_bytes());
        b[0x48..0x4A].copy_from_slice(&(raw.len() as u16).to_le_bytes());
        b.extend_from_slice(&raw);
        b
    };
    let children: Vec<u32> = names
        .iter()
        .map(|n| push_cell(&mut bins, &nk(n, 0, u32::MAX)))
        .collect();
    let list_cell = |sig: &[u8], entries: &[u32], step: usize| -> Vec<u8> {
        let mut b = sig.to_vec();
        b.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for e in entries {
            b.extend_from_slice(&e.to_le_bytes());
            b.resize(b.len() + step - 4, 0);
        }
        b
    };
    let list_offset = match list {
        "li" => push_cell(&mut bins, &list_cell(b"li", &children, 4)),
        "ri" => {
            let inner = push_cell(&mut bins, &list_cell(b"lf", &children, 8));
            push_cell(&mut bins, &list_cell(b"ri", &[inner], 4))
        }
        sig => push_cell(&mut bins, &list_cell(sig.as_bytes(), &children, 8)),
    };
    let root = push_cell(&mut bins, &nk("ROOT", names.len() as u32, list_offset));
    let mut hive = vec![0u8; BINS];
    hive[..4].copy_from_slice(b"regf");
    hive[0x24..0x28].copy_from_slice(&root.to_le_bytes());
    hive.extend_from_slice(&bins);
    hive
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_names_from_every_list_type() {
        let names = ["ControlSet001", "MountedDevices", "Select", "Setup"];
        for list in ["lf", "lh", "li", "ri"] {
            let hive = build_test_hive(&names, list);
            assert_eq!(root_subkey_names(&hive).unwrap(), names, "{list}");
        }
    }

    #[test]
    fn utf16_names_and_an_empty_root() {
        let hive = build_test_hive(&["Software", "Programme ünd Ω"], "lf");
        assert_eq!(
            root_subkey_names(&hive).unwrap(),
            ["Software", "Programme ünd Ω"]
        );
        assert!(
            root_subkey_names(&build_test_hive(&[], "lf"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn broken_data_is_an_error_not_a_panic() {
        assert_eq!(root_subkey_names(b"MZ\x90\x00"), Err(RegfError::NotRegf));
        let hive = build_test_hive(&["Select", "Setup"], "lf");
        // Every truncation, and every root offset pointing elsewhere.
        for cut in 0..hive.len() {
            let _ = root_subkey_names(&hive[..cut]);
        }
        for off in [0u32, 4, 0x1F, u32::MAX, u32::MAX - 3, 0x7FFF_FFFF] {
            let mut h = hive.clone();
            h[0x24..0x28].copy_from_slice(&off.to_le_bytes());
            assert!(root_subkey_names(&h).is_err(), "root at {off:#x}");
        }
        // Flipping each byte after the base block never panics.
        for i in BINS..hive.len() {
            let mut h = hive.clone();
            h[i] ^= 0xFF;
            let _ = root_subkey_names(&h);
        }
    }

    #[test]
    fn ri_lists_pointing_at_themselves_stop() {
        let mut hive = build_test_hive(&["A"], "ri");
        // Make the ri list's entry point at the ri list itself.
        let root_off = u32::from_le_bytes(hive[0x24..0x28].try_into().unwrap()) as usize;
        let list_off =
            u32::from_le_bytes(hive[BINS + root_off + 4 + 0x1C..][..4].try_into().unwrap());
        let entry = BINS + list_off as usize + 4 + 4;
        hive[entry..entry + 4].copy_from_slice(&list_off.to_le_bytes());
        assert_eq!(
            root_subkey_names(&hive),
            Err(RegfError::BadCell("subkey list nesting"))
        );
    }
}
