//! The path type (piece F6).
//!
//! A path is a list of names below the root of a view, never one string with separators in it.
//! Each name keeps three forms:
//!
//! - **raw**: the name exactly as stored, as UTF-16 code units (NTFS, FAT long names, the
//!   registry) or as bytes (Linux file systems). Invalid UTF-16 and non-UTF-8 bytes are kept.
//! - **display**: text for people. Characters that would be unclear are escaped, so two different
//!   names never look the same and the text can be typed back ([`Name::parse`]): a lone UTF-16
//!   surrogate or a control character as `\u{d800}`, a byte that isn't UTF-8 as `\xe9`, and a
//!   backslash or slash inside a name as `\u{5c}` and `\u{2f}`.
//! - **key**: the form lookups compare, by the view's [`CasePolicy`]. Case-insensitive views fold
//!   each character to its simple uppercase form, one to one, as NTFS does with its upcase table,
//!   so `Straße` and `STRASSE` stay different. Exact views compare the display form.
//!
//! Which separator a view shows and whether it ignores case is set by the OS profile that builds
//! the view ([`PathStyle`]). Drive letters are not part of a path; the Windows profile maps them.
//!
//! Typing a path back with a backslash separator has one blind spot: a folder whose real name
//! starts with `u{`, a hex number and `}` reads as an escape, and the typed path is refused as
//! not canonical. Names are never built from display text inside the tool, only from raw
//! values, so this only affects typed lookups.

use std::collections::HashMap;
use std::fmt::{self, Write};

/// How a view compares names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CasePolicy {
    /// `Foo` and `foo` are different names.
    Exact,
    /// `Foo` and `foo` are the same name for lookups (both are still kept).
    Insensitive,
}

/// How a view writes and compares paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathStyle {
    pub separator: char,
    pub case: CasePolicy,
}

/// What a name's raw form is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameKind {
    Utf16,
    Bytes,
}

/// One path component, exactly as stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Name {
    Utf16(Vec<u16>),
    Bytes(Vec<u8>),
}

impl Name {
    pub fn from_utf16(units: &[u16]) -> Self {
        Self::Utf16(units.to_vec())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::Bytes(bytes.to_vec())
    }

    /// A name of the given kind from plain text (no escapes).
    pub fn from_text(text: &str, kind: NameKind) -> Self {
        match kind {
            NameKind::Utf16 => Self::Utf16(text.encode_utf16().collect()),
            NameKind::Bytes => Self::Bytes(text.as_bytes().to_vec()),
        }
    }

    pub fn kind(&self) -> NameKind {
        match self {
            Self::Utf16(_) => NameKind::Utf16,
            Self::Bytes(_) => NameKind::Bytes,
        }
    }

    /// The display form, with escapes (see the module documentation).
    pub fn display(&self) -> String {
        self.render(false)
    }

    /// The form lookups compare under `case`.
    pub fn key(&self, case: CasePolicy) -> String {
        self.render(case == CasePolicy::Insensitive)
    }

    fn render(&self, fold: bool) -> String {
        let mut out = String::new();
        let put = |out: &mut String, c: char| push_char(out, if fold { fold_char(c) } else { c });
        match self {
            Self::Utf16(units) => {
                for r in char::decode_utf16(units.iter().copied()) {
                    match r {
                        Ok(c) => put(&mut out, c),
                        Err(e) => {
                            let _ = write!(out, "\\u{{{:x}}}", e.unpaired_surrogate());
                        }
                    }
                }
            }
            Self::Bytes(bytes) => {
                for chunk in bytes.utf8_chunks() {
                    for c in chunk.valid().chars() {
                        put(&mut out, c);
                    }
                    for b in chunk.invalid() {
                        let _ = write!(out, "\\x{b:02x}");
                    }
                }
            }
        }
        out
    }

    /// A name back from its display form. `kind` says which raw form to build.
    pub fn parse(text: &str, kind: NameKind) -> Result<Self, PathError> {
        let mut b = NameBuilder::new(kind);
        let mut rest = text;
        while let Some(c) = rest.chars().next() {
            if c == '\\' {
                let (piece, len) =
                    escape(rest, kind).ok_or_else(|| PathError::Escape(text.into()))?;
                b.push(piece);
                rest = &rest[len..];
            } else if c == '/' || c.is_control() {
                return Err(PathError::Unescaped(text.into()));
            } else {
                b.push(Piece::Char(c));
                rest = &rest[c.len_utf8()..];
            }
        }
        let name = b.finish();
        // Only the canonical spelling is accepted: `\u{41}` is not another way to write `A`.
        if name.display() != text {
            return Err(PathError::Escape(text.into()));
        }
        Ok(name)
    }
}

/// A path below the root of a view.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ViewPath {
    names: Vec<Name>,
}

impl ViewPath {
    pub fn new(names: Vec<Name>) -> Self {
        Self { names }
    }

    pub fn names(&self) -> &[Name] {
        &self.names
    }

    /// The path with one more name at the end.
    pub fn join(&self, name: Name) -> Self {
        let mut names = self.names.clone();
        names.push(name);
        Self { names }
    }

    /// The path without its last name, or `None` at the root.
    pub fn parent(&self) -> Option<Self> {
        let (_, rest) = self.names.split_last()?;
        Some(Self::new(rest.to_vec()))
    }

    /// The display form in `style`, starting with the separator (the view's root).
    pub fn display(&self, style: PathStyle) -> String {
        let mut out = String::new();
        for n in &self.names {
            out.push(style.separator);
            out.push_str(&n.display());
        }
        if out.is_empty() {
            out.push(style.separator);
        }
        out
    }

    /// The lookup key under `case`: the names' keys joined by `/`, which never occurs unescaped
    /// inside a key.
    pub fn key(&self, case: CasePolicy) -> String {
        let keys: Vec<String> = self.names.iter().map(|n| n.key(case)).collect();
        keys.join("/")
    }

    /// A path back from its display form in `style`. A leading separator is optional. Empty
    /// names (two separators in a row) are refused. `.` and `..` are names like any other.
    pub fn parse(text: &str, style: PathStyle, kind: NameKind) -> Result<Self, PathError> {
        let body = text.strip_prefix(style.separator).unwrap_or(text);
        if body.is_empty() {
            return Ok(Self::default());
        }
        let mut names = Vec::new();
        let mut b = NameBuilder::new(kind);
        let mut start = true;
        let mut rest = body;
        while let Some(c) = rest.chars().next() {
            if c == '\\'
                && let Some((piece, len)) = escape(rest, kind)
            {
                b.push(piece);
                start = false;
                rest = &rest[len..];
                continue;
            }
            if c == style.separator {
                if start {
                    return Err(PathError::EmptyName(text.into()));
                }
                names.push(std::mem::replace(&mut b, NameBuilder::new(kind)).finish());
                start = true;
            } else if c == '\\' || c == '/' || c.is_control() {
                return Err(PathError::Unescaped(text.into()));
            } else {
                b.push(Piece::Char(c));
                start = false;
            }
            rest = &rest[c.len_utf8()..];
        }
        if start {
            return Err(PathError::EmptyName(text.into()));
        }
        names.push(b.finish());
        let path = Self { names };
        // Only the canonical spelling is accepted. This also catches the blind spot named in the
        // module documentation: `dir\u{41}` gives `dirA`, which displays differently, so it is
        // refused rather than read as something else.
        let canonical = path.display(style);
        if canonical != text && canonical[style.separator.len_utf8()..] != *text {
            return Err(PathError::Escape(text.into()));
        }
        Ok(path)
    }
}

/// Paths and their values, looked up by a view's case policy. On a case-insensitive view, `Foo`
/// and `foo` find each other, and a lookup returns both if both exist (NTFS allows that in
/// case-sensitive folders).
#[derive(Debug, Clone)]
pub struct PathIndex<T> {
    case: CasePolicy,
    map: HashMap<String, Vec<(ViewPath, T)>>,
}

impl<T> PathIndex<T> {
    pub fn new(case: CasePolicy) -> Self {
        Self {
            case,
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, path: ViewPath, value: T) {
        self.map
            .entry(path.key(self.case))
            .or_default()
            .push((path, value));
    }

    /// Every stored path that matches `path` under the index's case policy, in insertion order.
    pub fn get(&self, path: &ViewPath) -> &[(ViewPath, T)] {
        self.map
            .get(&path.key(self.case))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Display text that can't be read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// A backslash that doesn't start a valid escape for this kind of name.
    Escape(String),
    /// A slash, backslash or control character that should have been escaped.
    Unescaped(String),
    /// Two separators in a row, or one at the end.
    EmptyName(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Escape(t) => write!(f, "`{t}` has an invalid escape"),
            Self::Unescaped(t) => write!(f, "`{t}` has a character that must be escaped"),
            Self::EmptyName(t) => write!(f, "`{t}` has an empty name"),
        }
    }
}

impl std::error::Error for PathError {}

/// Writes `c`, escaped if it would be unclear.
fn push_char(out: &mut String, c: char) {
    if c == '\\' || c == '/' || c.is_control() {
        let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
    } else {
        out.push(c);
    }
}

/// Simple one-to-one uppercase within the Basic Multilingual Plane, as NTFS compares names.
fn fold_char(c: char) -> char {
    if u32::from(c) > 0xffff {
        return c;
    }
    let mut up = c.to_uppercase();
    match (up.next(), up.next()) {
        (Some(u), None) if u32::from(u) <= 0xffff => u,
        _ => c,
    }
}

enum Piece {
    Char(char),
    /// A lone surrogate (UTF-16 names only).
    Unit(u16),
    /// A byte that isn't UTF-8 (byte names only).
    Byte(u8),
}

/// Reads an escape at the start of `s` (which starts with a backslash): `\u{hex}` or, for byte
/// names, `\xhh`. Returns the piece and the length of the escape.
fn escape(s: &str, kind: NameKind) -> Option<(Piece, usize)> {
    let rest = &s[1..];
    if let Some(hex) = rest.strip_prefix("u{") {
        let end = hex.find('}')?;
        let digits = &hex[..end];
        if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let v = u32::from_str_radix(digits, 16).ok()?;
        let piece = match (char::from_u32(v), kind) {
            (Some(c), _) => Piece::Char(c),
            (None, NameKind::Utf16) if (0xd800..=0xdfff).contains(&v) => Piece::Unit(v as u16),
            _ => return None,
        };
        return Some((piece, 1 + 2 + end + 1));
    }
    if kind == NameKind::Bytes
        && let Some(hex) = rest.strip_prefix('x')
    {
        let digits = hex.get(..2)?;
        if digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            let v = u8::from_str_radix(digits, 16).ok()?;
            return Some((Piece::Byte(v), 4));
        }
    }
    None
}

struct NameBuilder {
    units: Vec<u16>,
    bytes: Vec<u8>,
    kind: NameKind,
}

impl NameBuilder {
    fn new(kind: NameKind) -> Self {
        Self {
            units: Vec::new(),
            bytes: Vec::new(),
            kind,
        }
    }

    fn push(&mut self, piece: Piece) {
        match piece {
            Piece::Char(c) => {
                let mut buf = [0u16; 2];
                self.units.extend_from_slice(c.encode_utf16(&mut buf));
                let mut buf = [0u8; 4];
                self.bytes
                    .extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            Piece::Unit(u) => self.units.push(u),
            Piece::Byte(b) => self.bytes.push(b),
        }
    }

    fn finish(self) -> Name {
        match self.kind {
            NameKind::Utf16 => Name::Utf16(self.units),
            NameKind::Bytes => Name::Bytes(self.bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIN: PathStyle = PathStyle {
        separator: '\\',
        case: CasePolicy::Insensitive,
    };
    const LINUX: PathStyle = PathStyle {
        separator: '/',
        case: CasePolicy::Exact,
    };

    fn wpath(names: &[&str]) -> ViewPath {
        ViewPath::new(
            names
                .iter()
                .map(|n| Name::from_text(n, NameKind::Utf16))
                .collect(),
        )
    }

    fn lpath(names: &[&str]) -> ViewPath {
        ViewPath::new(
            names
                .iter()
                .map(|n| Name::from_text(n, NameKind::Bytes))
                .collect(),
        )
    }

    #[test]
    fn display_and_parse_per_style() {
        let p = wpath(&["Users", "ich", "NTUSER.DAT"]);
        assert_eq!(p.display(WIN), "\\Users\\ich\\NTUSER.DAT");
        assert_eq!(
            ViewPath::parse(&p.display(WIN), WIN, NameKind::Utf16),
            Ok(p.clone())
        );
        let l = lpath(&["home", "don", ".bashrc"]);
        assert_eq!(l.display(LINUX), "/home/don/.bashrc");
        assert_eq!(
            ViewPath::parse("home/don/.bashrc", LINUX, NameKind::Bytes),
            Ok(l)
        );
        assert_eq!(ViewPath::default().display(WIN), "\\");
        assert_eq!(
            ViewPath::parse("\\", WIN, NameKind::Utf16),
            Ok(ViewPath::default())
        );
    }

    #[test]
    fn lookup_ignores_case_on_insensitive_views_only() {
        let mut win = PathIndex::new(CasePolicy::Insensitive);
        win.insert(wpath(&["Windows", "System32", "config", "SYSTEM"]), 1);
        let found = win.get(&wpath(&["WINDOWS", "system32", "Config", "system"]));
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].0.display(WIN),
            "\\Windows\\System32\\config\\SYSTEM"
        );

        let mut linux = PathIndex::new(CasePolicy::Exact);
        linux.insert(lpath(&["etc", "passwd"]), 1);
        assert_eq!(linux.get(&lpath(&["etc", "passwd"])).len(), 1);
        assert!(linux.get(&lpath(&["etc", "Passwd"])).is_empty());
    }

    #[test]
    fn folding_is_one_to_one_like_ntfs() {
        let k = |s: &str| Name::from_text(s, NameKind::Utf16).key(CasePolicy::Insensitive);
        assert_eq!(k("straße"), "STRAßE");
        assert_ne!(k("straße"), k("STRASSE"));
        assert_eq!(k("äöü"), k("ÄÖÜ"));
        assert_eq!(k("ǆ"), "Ǆ");
        // Outside the Basic Multilingual Plane nothing folds (Deseret small letter stays).
        assert_eq!(k("\u{10428}"), "\u{10428}");
    }

    #[test]
    fn parent_and_join() {
        let p = wpath(&["a", "b"]);
        assert_eq!(p.parent(), Some(wpath(&["a"])));
        assert_eq!(wpath(&["a"]).join(Name::from_text("b", NameKind::Utf16)), p);
        assert_eq!(ViewPath::default().parent(), None);
    }

    #[test]
    fn parse_errors() {
        assert!(matches!(
            ViewPath::parse("a//b", LINUX, NameKind::Bytes),
            Err(PathError::EmptyName(_))
        ));
        assert!(matches!(
            ViewPath::parse("a/b/", LINUX, NameKind::Bytes),
            Err(PathError::EmptyName(_))
        ));
        assert!(matches!(
            ViewPath::parse("a\\qb", LINUX, NameKind::Bytes),
            Err(PathError::Unescaped(_))
        ));
        // Not the canonical spelling: `\u{41}` is just `A`.
        assert!(matches!(
            Name::parse("\\u{41}", NameKind::Utf16),
            Err(PathError::Escape(_))
        ));
        // Byte escapes don't exist in UTF-16 names.
        assert!(matches!(
            Name::parse("\\xe9", NameKind::Utf16),
            Err(PathError::Escape(_))
        ));
    }
}
