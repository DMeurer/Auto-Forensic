//! IDs and link endpoints (piece F8).
//!
//! - [`SystemId`]: a random UUID per system. Every import gets its own system, and the ID is
//!   unique across projects, so projects can be merged later without renumbering.
//! - [`FileId`]: an opaque file identity within one system, with a namespaced scheme saying what
//!   the bytes are (an NTFS file reference, an inode number, a FAT directory entry position).
//!   Core never looks inside; the format and OS crates build and read them.
//! - [`EventId`], [`GroupId`], [`FactId`]: opaque 128-bit IDs, unique within a project. How they
//!   are derived (stable, from source, locator, offset and kind) is piece F18.
//! - [`Endpoint`]: what a link points at: an event, group, fact or file. A link may join two
//!   systems, for example a host's LNK file and the file on the stick it points to.

use crate::names::Kind;
use std::fmt;

/// The ID of a system: a random UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SystemId(pub u128);

impl SystemId {
    /// A new random ID (UUID version 4).
    pub fn new_random() -> Self {
        Self(uuid::Uuid::new_v4().as_u128())
    }

    /// From the usual hyphenated text form.
    pub fn parse(text: &str) -> Option<Self> {
        uuid::Uuid::try_parse(text).ok().map(|u| Self(u.as_u128()))
    }
}

impl fmt::Display for SystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        uuid::Uuid::from_u128(self.0).hyphenated().fmt(f)
    }
}

macro_rules! opaque_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u128);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:032x}", self.0)
            }
        }
    };
}

opaque_id!(
    /// The ID of an event, unique within a project.
    EventId
);
opaque_id!(
    /// The ID of a group, unique within a project.
    GroupId
);
opaque_id!(
    /// The ID of a fact, unique within a project.
    FactId
);

/// A file's identity within one system, opaque to core.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId {
    /// What the bytes are, such as `ntfs.file_ref` (record and sequence) or `ext4.inode`.
    pub scheme: Kind,
    pub value: Vec<u8>,
}

/// What a link points at.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Endpoint {
    Event(EventId),
    Group(GroupId),
    Fact(FactId),
    /// A file, which needs its system, because file IDs repeat across systems.
    File {
        system: SystemId,
        file: FileId,
    },
}

/// A directed link between two endpoints, of a namespaced kind. Labels, tiers and evidence come
/// with the link table (piece L1); this is the part every link has.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkRef {
    pub kind: Kind,
    pub from: Endpoint,
    pub to: Endpoint,
}

/// The stored form of one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointColumns {
    /// `event`, `group`, `fact` or `file`.
    pub kind: String,
    /// The event, group or fact ID; unset for files.
    pub id: Option<u128>,
    /// The file's system; unset for the others.
    pub system: Option<u128>,
    pub file_scheme: Option<String>,
    pub file_value: Option<Vec<u8>>,
}

impl Endpoint {
    pub fn to_columns(&self) -> EndpointColumns {
        let (kind, id) = match self {
            Self::Event(e) => ("event", Some(e.0)),
            Self::Group(g) => ("group", Some(g.0)),
            Self::Fact(f) => ("fact", Some(f.0)),
            Self::File { .. } => ("file", None),
        };
        let (system, file_scheme, file_value) = match self {
            Self::File { system, file } => (
                Some(system.0),
                Some(file.scheme.as_str().to_string()),
                Some(file.value.clone()),
            ),
            _ => (None, None, None),
        };
        EndpointColumns {
            kind: kind.to_string(),
            id,
            system,
            file_scheme,
            file_value,
        }
    }

    /// Back from the stored form. `None` for columns this code didn't write.
    pub fn from_columns(c: &EndpointColumns) -> Option<Self> {
        let only_id = c.system.is_none() && c.file_scheme.is_none() && c.file_value.is_none();
        Some(match (c.kind.as_str(), c.id) {
            ("event", Some(id)) if only_id => Self::Event(EventId(id)),
            ("group", Some(id)) if only_id => Self::Group(GroupId(id)),
            ("fact", Some(id)) if only_id => Self::Fact(FactId(id)),
            ("file", None) => Self::File {
                system: SystemId(c.system?),
                file: FileId {
                    scheme: Kind::new(c.file_scheme.as_deref()?).ok()?,
                    value: c.file_value.clone()?,
                },
            },
            _ => return None,
        })
    }

    /// The system of a file endpoint. Events, groups and facts carry their system in their own
    /// rows, not in the endpoint.
    pub fn file_system(&self) -> Option<SystemId> {
        match self {
            Self::File { system, .. } => Some(*system),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(system: SystemId, scheme: &str, value: &[u8]) -> Endpoint {
        Endpoint::File {
            system,
            file: FileId {
                scheme: Kind::new(scheme).unwrap(),
                value: value.to_vec(),
            },
        }
    }

    #[test]
    fn a_link_between_two_systems_is_stored() {
        let host = SystemId::new_random();
        let stick = SystemId::new_random();
        assert_ne!(host, stick);
        // The host's LNK file points at a file on the stick.
        let link = LinkRef {
            kind: Kind::new("link.points_to").unwrap(),
            from: file(host, "ntfs.file_ref", &[0x2a, 0, 0, 0, 0, 0, 3, 0]),
            to: file(stick, "fat.dir_entry", &[0, 0x40, 0, 0]),
        };
        let from = Endpoint::from_columns(&link.from.to_columns()).unwrap();
        let to = Endpoint::from_columns(&link.to.to_columns()).unwrap();
        assert_eq!((from, to), (link.from.clone(), link.to.clone()));
        assert_eq!(link.from.file_system(), Some(host));
        assert_eq!(link.to.file_system(), Some(stick));
    }

    #[test]
    fn same_file_id_on_two_systems_is_two_files() {
        let (a, b) = (SystemId::new_random(), SystemId::new_random());
        assert_ne!(
            file(a, "ntfs.file_ref", &[5, 0, 0, 0, 0, 0, 5, 0]),
            file(b, "ntfs.file_ref", &[5, 0, 0, 0, 0, 0, 5, 0])
        );
    }

    #[test]
    fn every_endpoint_kind_round_trips() {
        let s = SystemId::new_random();
        for e in [
            Endpoint::Event(EventId(1)),
            Endpoint::Group(GroupId(u128::MAX)),
            Endpoint::Fact(FactId(7)),
            file(s, "ext4.inode", &12u64.to_le_bytes()),
        ] {
            assert_eq!(Endpoint::from_columns(&e.to_columns()), Some(e));
        }
        // Columns that mix kinds are refused.
        let mut c = Endpoint::Event(EventId(1)).to_columns();
        c.system = Some(s.0);
        assert_eq!(Endpoint::from_columns(&c), None);
    }

    #[test]
    fn system_ids_print_and_parse_as_uuids() {
        let s = SystemId::new_random();
        let text = s.to_string();
        assert_eq!(text.len(), 36);
        assert_eq!(&text[14..15], "4", "version 4");
        assert_eq!(SystemId::parse(&text), Some(s));
        assert_eq!(SystemId::parse("not-a-uuid"), None);
        assert_eq!(EventId(255).to_string(), format!("{:032x}", 255));
    }
}
