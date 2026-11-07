//! File systems (piece I12): the read-only interface every file system adapter offers.
//!
//! An entry carries all its names (hard links, NTFS short names), named times, an allocated flag,
//! how a deleted entry was found, and its streams. Design notes, accepted 2026-11-06:
//!
//! - **One walk.** [`FileSystem::all`] gives every entry the file system can find, allocated or
//!   not; deleted entries are the ones with `allocated == false`. [`FileSystem::list`] sees only
//!   allocated entries, as path lookup does.
//! - **Named times.** Each file system names its own (`ntfs.si.modified`, `ext4.dtime`) and says
//!   in [`FsInfo::time_names`] which it can hold, each with a shared [`TimeRole`]. A name missing
//!   on an entry means this entry has no such time ([`TimeStatus::Absent`]); a stored zero is a
//!   time with status `NotSet`.
//! - **Paths are built here**, from names and parents ([`paths`]). A deleted entry whose folder
//!   is gone gets an orphan path, shown as `<orphan>/name`, like TSK's `$OrphanFiles`.
//! - **Every adapter passes [`check`]**, and so does [`FakeFs`].
//!
//! [`TimeStatus::Absent`]: crate::time::TimeStatus::Absent

use crate::bytes::{ByteSource, Locator, MemSource};
use crate::ids::FileId;
use crate::names::Kind;
use crate::path::{CasePolicy, Name, NameKind, ViewPath};
use crate::system::{VolumeId, VolumeProbe};
use crate::time::{Precision, Time, Zone};
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::sync::Arc;

/// One file system on a volume. Read-only, usable from several threads.
pub trait FileSystem: Send + Sync {
    fn info(&self) -> &FsInfo;

    /// The root folder.
    fn root(&self) -> FileId;

    /// One entry by its native ID, allocated or not. `None` if there is none, also when the ID's
    /// sequence number no longer matches (a reused NTFS record).
    fn entry(&self, id: &FileId) -> io::Result<Option<Entry>>;

    /// The allocated entries directly inside a folder, with the name each one has there.
    fn list(&self, dir: &FileId) -> io::Result<Vec<(Name, FileId)>>;

    /// Every entry the file system can find, allocated or not, in its own order. A broken entry
    /// is an `Err` item, not the end of the walk.
    fn all(&self) -> Box<dyn Iterator<Item = io::Result<Entry>> + '_>;

    /// One stream of an entry as bytes, `None` if the entry has no such stream.
    fn open(&self, id: &FileId, stream: &StreamName) -> io::Result<Option<Arc<dyn ByteSource>>>;
}

/// What a file system can tell at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInfo {
    /// `fs.ntfs`, `fs.fat32`, `fs.ext4`, ...
    pub kind: Kind,
    pub case: CasePolicy,
    pub label: Option<String>,
    pub serial: Option<String>,
    /// Every time this file system can hold. One listed here but missing on an entry means
    /// that entry has none; one not listed means this file system never has it.
    pub time_names: Vec<TimeName>,
    /// Whether [`FileSystem::all`] reaches unallocated entries at all (false for a zip).
    pub finds_deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeName {
    /// `ntfs.si.modified`, `ntfs.fn.created`, `fat.accessed`, `ext4.dtime`.
    pub name: Kind,
    pub role: TimeRole,
    pub precision: Precision,
    pub zone: Zone,
}

/// What a time means across file systems, for plugins that don't know the file system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeRole {
    Modified,
    Accessed,
    /// Metadata changed (NTFS MFT entry modified, ext4 ctime).
    Changed,
    Created,
    Deleted,
    /// Anything else (HFS+ backup time).
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    File,
    Folder,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: FileId,
    pub kind: EntryKind,
    /// Every name with its folder: hard links give several, NTFS a Win32 and a DOS name.
    pub names: Vec<EntryName>,
    /// Named times; see the module documentation for absent and zero.
    pub times: Vec<(Kind, Time)>,
    pub allocated: bool,
    /// For entries that aren't allocated: how they were found (`ntfs.mft.unused_record`,
    /// `fat.dir.deleted_entry`).
    pub recovered: Option<Kind>,
    pub streams: Vec<StreamInfo>,
    /// File-system specific values (attributes, owner, flags) as namespaced key and text.
    pub attrs: Vec<(Kind, String)>,
}

impl Entry {
    pub fn time(&self, name: &str) -> Option<&Time> {
        self.times
            .iter()
            .find(|(k, _)| k.as_str() == name)
            .map(|(_, t)| t)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryName {
    pub parent: FileId,
    pub name: Name,
    /// `ntfs.name.win32`, `ntfs.name.dos`, `fat.name.long`, `fs.name`.
    pub kind: Kind,
    /// A second spelling of another name in the same folder (an NTFS 8.3 short name): it is
    /// listed and found by lookup, but paths are built from the long names.
    pub alias: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StreamName {
    /// A file's data.
    Default,
    /// An alternate data stream, fork or extended attribute.
    Named(Name),
    /// What the disk still holds past a stream's initialized length, which normal reads give
    /// as zeros (NTFS `initialized_size`, later ext4 unwritten extents). `None` is the file's
    /// data, `Some` a named stream.
    Stale(Option<Name>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    pub name: StreamName,
    /// `fs.data`, `ntfs.ads`, `ntfs.stale_bytes`, `ext4.xattr`.
    pub kind: Kind,
    pub size: u64,
}

/// One path of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPath {
    /// The folder chain ended before the root: the path starts at `<orphan>`.
    pub orphan: bool,
    pub path: ViewPath,
}

impl EntryPath {
    pub fn display(&self) -> String {
        let style = crate::path::PathStyle {
            separator: '/',
            case: CasePolicy::Exact,
        };
        let p = self.path.display(style);
        if self.orphan {
            format!("<orphan>/{}", p.trim_start_matches('/'))
        } else {
            p
        }
    }
}

/// Folder chains longer than this are taken as loops.
const MAX_DEPTH: usize = 4096;

/// Every path of an entry, one per name that isn't an alias (hard links give several). Folders
/// on the way are named by their first long name. The root has one empty path.
pub fn paths(fs: &dyn FileSystem, entry: &Entry) -> io::Result<Vec<EntryPath>> {
    let root = fs.root();
    if entry.id == root {
        return Ok(vec![EntryPath {
            orphan: false,
            path: ViewPath::new(vec![]),
        }]);
    }
    let mut out = Vec::new();
    let long: Vec<&EntryName> = entry.names.iter().filter(|n| !n.alias).collect();
    let own = if long.is_empty() {
        entry.names.iter().collect()
    } else {
        long
    };
    for n in own {
        let (mut names, mut at, mut seen) =
            (vec![n.name.clone()], n.parent.clone(), HashSet::new());
        let orphan = loop {
            if at == root {
                break false;
            }
            if !seen.insert(at.clone()) || seen.len() > MAX_DEPTH {
                break true;
            }
            let parent = fs.entry(&at)?;
            let first_long = |p: &Entry| {
                p.names
                    .iter()
                    .find(|n| !n.alias)
                    .or(p.names.first())
                    .cloned()
            };
            match parent.as_ref().and_then(first_long) {
                Some(pn) if parent.as_ref().is_some_and(|p| p.kind == EntryKind::Folder) => {
                    names.push(pn.name.clone());
                    at = pn.parent.clone();
                }
                _ => break true,
            }
        };
        names.reverse();
        out.push(EntryPath {
            orphan,
            path: ViewPath::new(names),
        });
    }
    Ok(out)
}

/// What [`check`] found.
#[derive(Debug, Default)]
pub struct CheckReport {
    /// Broken promises of the interface. An adapter passes when this is empty.
    pub problems: Vec<String>,
    /// Entries the file system couldn't read (`Err` items of `all`): allowed, but counted.
    pub unreadable: Vec<String>,
    pub entries: usize,
    pub deleted: usize,
}

/// Checks that a file system keeps the promises of this interface: `entry`, `list` and `all`
/// agree, streams give as many bytes as they say, times are declared, and paths end at the root
/// or at an orphan.
pub fn check(fs: &dyn FileSystem) -> io::Result<CheckReport> {
    let mut r = CheckReport::default();
    let info = fs.info();
    let declared: HashSet<&str> = info.time_names.iter().map(|t| t.name.as_str()).collect();
    let root = fs.root();
    match fs.entry(&root)? {
        Some(e) if e.kind == EntryKind::Folder && e.allocated => {}
        other => r
            .problems
            .push(format!("the root is not an allocated folder: {other:?}")),
    }
    let mut all = BTreeMap::new();
    for item in fs.all() {
        let e = match item {
            Ok(e) => e,
            Err(err) => {
                r.unreadable.push(err.to_string());
                continue;
            }
        };
        let id = format!("{:?}", e.id);
        if all.contains_key(&e.id) {
            r.problems.push(format!("{id} appears twice in all()"));
        }
        if fs.entry(&e.id)?.as_ref() != Some(&e) {
            r.problems.push(format!("{id}: entry() differs from all()"));
        }
        for (name, _) in &e.times {
            if !declared.contains(name.as_str()) {
                r.problems
                    .push(format!("{id}: time {name} isn't in FsInfo::time_names"));
            }
        }
        if e.allocated == e.recovered.is_some() {
            r.problems.push(format!(
                "{id}: `recovered` must be set exactly when the entry isn't allocated"
            ));
        }
        if !e.allocated {
            r.deleted += 1;
            if !info.finds_deleted {
                r.problems
                    .push(format!("{id}: deleted, but finds_deleted is false"));
            }
        }
        for s in &e.streams {
            match fs.open(&e.id, &s.name)? {
                Some(src) if src.len() == s.size => {}
                Some(src) => r.problems.push(format!(
                    "{id}: stream {:?} says {} bytes, opens with {}",
                    s.name,
                    s.size,
                    src.len()
                )),
                None => r
                    .problems
                    .push(format!("{id}: stream {:?} doesn't open", s.name)),
            }
        }
        if e.id != root && e.names.is_empty() {
            r.problems.push(format!("{id} has no name"));
        }
        for p in paths(fs, &e)? {
            if p.orphan && e.allocated {
                r.problems.push(format!(
                    "{id}: allocated, but its path {} is an orphan",
                    p.display()
                ));
            }
        }
        all.insert(e.id.clone(), e);
    }
    r.entries = all.len();
    if !all.contains_key(&root) {
        r.problems.push("the root isn't in all()".into());
    }
    // `list` gives exactly the allocated names under each allocated folder.
    for dir in all
        .values()
        .filter(|e| e.kind == EntryKind::Folder && e.allocated)
    {
        let mut listed: Vec<(Name, FileId)> = fs.list(&dir.id)?;
        let mut want: Vec<(Name, FileId)> = all
            .values()
            .filter(|e| e.allocated && e.id != root)
            .flat_map(|e| {
                e.names
                    .iter()
                    .filter(|n| n.parent == dir.id)
                    .map(|n| (n.name.clone(), e.id.clone()))
            })
            .collect();
        let key = |x: &(Name, FileId)| (x.0.display(), x.1.clone());
        listed.sort_by_key(key);
        want.sort_by_key(key);
        if listed != want {
            r.problems.push(format!(
                "list({:?}) gives {} names, the entries say {}",
                dir.id,
                listed.len(),
                want.len()
            ));
        }
    }
    Ok(r)
}

/// A file system seen as a [`VolumeProbe`], so OS profiles detect and index systems on it.
pub struct FsVolume<'a> {
    pub id: VolumeId,
    pub fs: &'a dyn FileSystem,
}

/// [`VolumeProbe::read`] gives files up to this size; profiles read small settings files.
const PROBE_READ_MAX: u64 = 16 << 20;

impl FsVolume<'_> {
    /// The allocated entry at a path, comparing names by the file system's case rules.
    pub fn lookup(&self, path: &ViewPath) -> Option<FileId> {
        let case = self.fs.info().case;
        let mut at = self.fs.root();
        for want in path.names() {
            let key = want.key(case);
            at = self
                .fs
                .list(&at)
                .ok()?
                .into_iter()
                .find(|(n, _)| n.key(case) == key)?
                .1;
        }
        Some(at)
    }
}

impl VolumeProbe for FsVolume<'_> {
    fn id(&self) -> VolumeId {
        self.id
    }
    fn exists(&self, path: &ViewPath) -> bool {
        self.lookup(path).is_some()
    }
    fn label(&self) -> Option<String> {
        self.fs.info().label.clone()
    }
    fn case(&self) -> CasePolicy {
        self.fs.info().case
    }
    fn read(&self, path: &ViewPath) -> Option<Vec<u8>> {
        let src = self
            .fs
            .open(&self.lookup(path)?, &StreamName::Default)
            .ok()??;
        if src.len() > PROBE_READ_MAX {
            return None;
        }
        let mut buf = vec![0u8; src.len() as usize];
        src.read_exact_at(0, &mut buf).ok()?;
        Some(buf)
    }
    fn list(&self, dir: &ViewPath) -> Vec<Name> {
        self.lookup(dir)
            .and_then(|id| self.fs.list(&id).ok())
            .map(|v| v.into_iter().map(|(n, _)| n).collect())
            .unwrap_or_default()
    }
}

/// An entry of [`FakeFs`] with its streams' bytes.
type FakeEntry = (Entry, Vec<(StreamName, Vec<u8>)>);

/// An in-memory file system for tests and fixtures. Entries are numbered from 1 (the root);
/// times are named `fake.modified` and `fake.created`.
pub struct FakeFs {
    info: FsInfo,
    entries: BTreeMap<FileId, FakeEntry>,
    next: u64,
}

impl FakeFs {
    pub fn new(case: CasePolicy) -> Self {
        let tn = |name: &str, role| TimeName {
            name: kind(name),
            role,
            precision: Precision::TICK,
            zone: Zone::Utc,
        };
        let mut f = Self {
            info: FsInfo {
                kind: kind("fs.fake"),
                case,
                label: Some("FAKE".into()),
                serial: None,
                time_names: vec![
                    tn("fake.modified", TimeRole::Modified),
                    tn("fake.created", TimeRole::Created),
                ],
                finds_deleted: true,
            },
            entries: BTreeMap::new(),
            next: 1,
        };
        f.insert(EntryKind::Folder, vec![]);
        f
    }

    fn id(n: u64) -> FileId {
        FileId {
            scheme: kind("fake.entry"),
            value: n.to_le_bytes().to_vec(),
        }
    }

    fn insert(&mut self, kind_: EntryKind, names: Vec<EntryName>) -> FileId {
        let id = Self::id(self.next);
        self.next += 1;
        let entry = Entry {
            id: id.clone(),
            kind: kind_,
            names,
            times: vec![],
            allocated: true,
            recovered: None,
            streams: vec![],
            attrs: vec![],
        };
        self.entries.insert(id.clone(), (entry, vec![]));
        id
    }

    fn get(&mut self, id: &FileId) -> &mut FakeEntry {
        self.entries.get_mut(id).expect("an entry of this FakeFs")
    }

    fn name(parent: &FileId, name: &str) -> EntryName {
        EntryName {
            parent: parent.clone(),
            name: Name::from_text(name, NameKind::Utf16),
            kind: kind("fs.name"),
            alias: false,
        }
    }

    pub fn folder(&mut self, parent: &FileId, name: &str) -> FileId {
        self.insert(EntryKind::Folder, vec![Self::name(parent, name)])
    }

    pub fn file(&mut self, parent: &FileId, name: &str, data: &[u8]) -> FileId {
        let id = self.insert(EntryKind::File, vec![Self::name(parent, name)]);
        self.stream(&id, StreamName::Default, data);
        id
    }

    /// Adds a stream, such as an alternate data stream.
    pub fn stream(&mut self, id: &FileId, name: StreamName, data: &[u8]) {
        let kind_ = kind(match name {
            StreamName::Default => "fs.data",
            StreamName::Named(_) => "fake.ads",
            StreamName::Stale(_) => "fake.stale_bytes",
        });
        let (e, s) = self.get(id);
        e.streams.push(StreamInfo {
            name: name.clone(),
            kind: kind_,
            size: data.len() as u64,
        });
        s.push((name, data.to_vec()));
    }

    /// A second name for an entry (a hard link).
    pub fn link(&mut self, id: &FileId, parent: &FileId, name: &str) {
        self.get(id).0.names.push(Self::name(parent, name));
    }

    /// A short alias for an entry in the same folder as its first name (an 8.3 name).
    pub fn alias(&mut self, id: &FileId, name: &str) {
        let e = &mut self.get(id).0;
        let mut n = Self::name(&e.names[0].parent, name);
        n.alias = true;
        e.names.push(n);
    }

    /// Sets a time; `name` must be `fake.modified` or `fake.created`.
    pub fn time(&mut self, id: &FileId, name: &str, t: Time) {
        self.get(id).0.times.push((kind(name), t));
    }

    /// Marks an entry deleted: it leaves `list` but stays in `all`.
    pub fn delete(&mut self, id: &FileId) {
        let e = &mut self.get(id).0;
        e.allocated = false;
        e.recovered = Some(kind("fake.deleted"));
    }

    /// Forgets an entry entirely, as a reused record would, so its children become orphans.
    pub fn purge(&mut self, id: &FileId) {
        self.entries.remove(id);
    }

    /// For tests of [`check`]: lets an entry break the interface's rules.
    pub fn entry_mut(&mut self, id: &FileId) -> &mut Entry {
        &mut self.get(id).0
    }
}

fn kind(name: &str) -> Kind {
    Kind::new(name).expect("a valid built-in name")
}

impl FileSystem for FakeFs {
    fn info(&self) -> &FsInfo {
        &self.info
    }
    fn root(&self) -> FileId {
        Self::id(1)
    }
    fn entry(&self, id: &FileId) -> io::Result<Option<Entry>> {
        Ok(self.entries.get(id).map(|(e, _)| e.clone()))
    }
    fn list(&self, dir: &FileId) -> io::Result<Vec<(Name, FileId)>> {
        Ok(self
            .entries
            .values()
            .filter(|(e, _)| e.allocated)
            .flat_map(|(e, _)| {
                e.names
                    .iter()
                    .filter(|n| &n.parent == dir)
                    .map(|n| (n.name.clone(), e.id.clone()))
            })
            .collect())
    }
    fn all(&self) -> Box<dyn Iterator<Item = io::Result<Entry>> + '_> {
        Box::new(self.entries.values().map(|(e, _)| Ok(e.clone())))
    }
    fn open(&self, id: &FileId, stream: &StreamName) -> io::Result<Option<Arc<dyn ByteSource>>> {
        let Some((_, streams)) = self.entries.get(id) else {
            return Ok(None);
        };
        Ok(streams.iter().find(|(n, _)| n == stream).map(|(_, data)| {
            let loc = Locator::root("fs.file", &format!("{:?}", id.value));
            Arc::new(MemSource::new(data.clone(), loc)) as Arc<dyn ByteSource>
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::MemVolume;
    use crate::time::TimeStatus;

    /// A small tree with everything the interface must carry: a hard link, an alternate data
    /// stream, a time that is zero next to one that is absent, a deleted file and an orphan.
    fn sample() -> (FakeFs, [FileId; 6]) {
        let mut f = FakeFs::new(CasePolicy::Insensitive);
        let root = f.root();
        let users = f.folder(&root, "Users");
        let ntuser = f.file(&users, "NTUSER.DAT", b"regf....");
        f.time(
            &ntuser,
            "fake.modified",
            Time::from_ticks_1601(132_000_000_000_000_000),
        );
        f.time(&ntuser, "fake.created", Time::from_ticks_1601(0)); // stored zero
        f.link(&ntuser, &root, "hardlink.dat");
        f.alias(&users, "USERS~1");
        f.alias(&ntuser, "NTUSER~1.DAT");
        f.stream(
            &ntuser,
            StreamName::Named(Name::from_text("Zone.Identifier", NameKind::Utf16)),
            b"[ZoneTransfer]",
        );
        f.stream(&ntuser, StreamName::Stale(None), b"old bytes");
        let gone = f.file(&users, "deleted.txt", b"old");
        f.delete(&gone);
        let lost_dir = f.folder(&root, "Temp");
        let orphan = f.file(&lost_dir, "orphan.tmp", b"x");
        f.delete(&orphan);
        f.purge(&lost_dir);
        (f, [root, users, ntuser, gone, lost_dir, orphan])
    }

    /// I12's criterion: a fake file system passes the interface check.
    #[test]
    fn the_fake_file_system_passes_the_check() {
        let (f, _) = sample();
        let r = check(&f).unwrap();
        assert!(r.problems.is_empty(), "{:#?}", r.problems);
        assert_eq!((r.entries, r.deleted, r.unreadable.len()), (5, 2, 0));
    }

    #[test]
    fn absent_differs_from_zero() {
        let (f, [_, users, ntuser, ..]) = sample();
        let e = f.entry(&ntuser).unwrap().unwrap();
        assert_eq!(e.time("fake.created").unwrap().status, TimeStatus::NotSet);
        let u = f.entry(&users).unwrap().unwrap();
        assert!(u.time("fake.created").is_none(), "absent: no value at all");
        assert!(
            f.info()
                .time_names
                .iter()
                .any(|t| t.name.as_str() == "fake.created")
        );
    }

    #[test]
    fn hard_links_give_two_paths_and_orphans_are_marked() {
        let (f, [_, _, ntuser, gone, _, orphan]) = sample();
        let shown = |id: &FileId| -> Vec<String> {
            paths(&f, &f.entry(id).unwrap().unwrap())
                .unwrap()
                .iter()
                .map(EntryPath::display)
                .collect()
        };
        assert_eq!(shown(&ntuser), ["/Users/NTUSER.DAT", "/hardlink.dat"]);
        assert_eq!(
            shown(&gone),
            ["/Users/deleted.txt"],
            "deleted, folder still there"
        );
        assert_eq!(shown(&orphan), ["<orphan>/orphan.tmp"]);
    }

    #[test]
    fn deleted_entries_are_in_all_but_not_in_list() {
        let (f, [root, users, ntuser, gone, ..]) = sample();
        let listed: Vec<FileId> = f.list(&users).unwrap().into_iter().map(|x| x.1).collect();
        assert!(
            listed.contains(&ntuser) && !listed.contains(&gone),
            "{listed:?}"
        );
        assert!(f.all().any(|e| e.unwrap().id == gone));
        assert_eq!(
            f.list(&root).unwrap().len(),
            3,
            "Users, its 8.3 alias and the hard link; Temp is purged"
        );
    }

    #[test]
    fn the_check_catches_broken_promises() {
        let (mut f, [_, _, ntuser, gone, ..]) = sample();
        f.entry_mut(&ntuser)
            .times
            .push((kind("fake.accessed"), Time::from_ticks_1601(1)));
        f.entry_mut(&ntuser).streams[0].size = 99;
        f.entry_mut(&gone).recovered = None;
        let p = check(&f).unwrap().problems;
        assert!(p.iter().any(|x| x.contains("fake.accessed")), "{p:?}");
        assert!(p.iter().any(|x| x.contains("says 99 bytes")), "{p:?}");
        assert!(p.iter().any(|x| x.contains("recovered")), "{p:?}");
    }

    #[test]
    fn a_file_system_is_a_volume_probe_for_profiles() {
        let (f, _) = sample();
        let v = FsVolume {
            id: VolumeId(7),
            fs: &f,
        };
        let p = MemVolume::path;
        assert!(
            v.exists(&p("users/ntuser.dat")),
            "case-insensitive like the file system"
        );
        assert!(
            !v.exists(&p("Users/deleted.txt")),
            "deleted files aren't found by path"
        );
        assert_eq!(v.read(&p("Users/NTUSER.DAT")).unwrap(), b"regf....");
        assert_eq!(
            v.list(&p("Users")).len(),
            2,
            "the long name and the 8.3 alias"
        );
        assert!(
            v.exists(&p("USERS~1/NTUSER~1.DAT")),
            "aliases are found by lookup"
        );
        assert_eq!(v.label().as_deref(), Some("FAKE"));
    }
}
