//! Namespaced names (piece F8): kinds like `windows.evtx.4624` instead of a bare `4624`, so two
//! sources can never mean different things by the same name.

use std::fmt;

/// A namespaced kind of event, fact, link or file ID: lowercase dotted segments of `a-z`, `0-9`
/// and `_`, at least two, such as `windows.evtx.4624` or `ntfs.file_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kind(String);

impl Kind {
    pub fn new(name: &str) -> Result<Self, NameError> {
        check_name(name).map(|()| Self(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first segment, such as `windows` in `windows.evtx.4624`.
    pub fn namespace(&self) -> &str {
        self.0.split('.').next().unwrap_or("")
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A name that isn't a valid namespaced name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameError(pub String);

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not a namespaced name (lowercase dotted segments, at least two)",
            self.0
        )
    }
}

impl std::error::Error for NameError {}

pub(crate) fn check_name(name: &str) -> Result<(), NameError> {
    let segments: Vec<&str> = name.split('.').collect();
    let ok = segments.len() >= 2
        && segments.iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        });
    if ok {
        Ok(())
    } else {
        Err(NameError(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_namespaced() {
        let k = Kind::new("windows.evtx.4624").unwrap();
        assert_eq!(k.namespace(), "windows");
        assert_eq!(k.to_string(), "windows.evtx.4624");
        for bad in [
            "4624",
            "Windows.evtx",
            "windows..4624",
            "windows.evtx.",
            "linux.wtmp-login",
        ] {
            assert!(Kind::new(bad).is_err(), "{bad}");
        }
    }
}
