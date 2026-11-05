//! Temporary folders.
//!
//! Temporary data belongs to the project it came from, so it lives in `<project>/tmp`: on the
//! same disk as the project, with the same access rights, and never in a RAM-backed `/tmp`.
//! Only commands without a project use the system temp folder ([`TempArea::system`]).
//!
//! Each run gets its own folder `run-*` inside the area. It holds an `owner.lock` file that is
//! locked for as long as the run lives. [`TempArea::clean_stale`] removes run folders whose lock
//! nobody holds, which are the leftovers of a crash, and leaves running ones alone.

use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Name of the lock file inside each run folder.
const LOCK_FILE: &str = "owner.lock";
/// Prefix of run folders.
const RUN_PREFIX: &str = "run-";
/// A run folder without a lock file is only treated as stale after this long, because a new run
/// creates its folder a moment before its lock file.
const UNLOCKED_GRACE: Duration = Duration::from_secs(60);

/// A folder that holds the temporary folders of runs.
#[derive(Debug, Clone)]
pub struct TempArea {
    root: PathBuf,
}

impl TempArea {
    /// The temp area of a project: `<project_dir>/tmp`, created if missing.
    pub fn in_project(project_dir: &Path) -> io::Result<Self> {
        Self::at(project_dir.join("tmp"))
    }

    /// The temp area for commands without a project: `af` inside the system temp folder.
    pub fn system() -> io::Result<Self> {
        Self::at(std::env::temp_dir().join("af"))
    }

    fn at(root: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The folder of this area.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates a new run folder with a unique name, locked until the returned [`RunDir`] drops.
    pub fn run_dir(&self) -> io::Result<RunDir> {
        let dir = tempfile::Builder::new()
            .prefix(RUN_PREFIX)
            .tempdir_in(&self.root)?;
        let lock = File::create(dir.path().join(LOCK_FILE))?;
        lock.lock()?;
        Ok(RunDir { _lock: lock, dir })
    }

    /// Removes run folders left by runs that ended without cleaning up, and returns them.
    /// A folder is left alone while another process (or this one) holds its lock.
    pub fn clean_stale(&self) -> io::Result<Vec<PathBuf>> {
        self.clean_stale_with_grace(UNLOCKED_GRACE)
    }

    fn clean_stale_with_grace(&self, grace: Duration) -> io::Result<Vec<PathBuf>> {
        let mut removed = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            let is_run = entry.file_type()?.is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(RUN_PREFIX));
            if is_run && is_stale(&path, grace)? {
                fs::remove_dir_all(&path)?;
                removed.push(path);
            }
        }
        removed.sort();
        Ok(removed)
    }
}

/// Whether a run folder belongs to no living run.
fn is_stale(dir: &Path, grace: Duration) -> io::Result<bool> {
    match File::options().write(true).open(dir.join(LOCK_FILE)) {
        Ok(lock) => match lock.try_lock() {
            // Nobody holds it. The handle closes, and so the lock ends, when `lock` drops here,
            // before the folder is removed (Windows can't remove an open file).
            Ok(()) => Ok(true),
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(e)) => Err(e),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let modified = fs::metadata(dir)?.modified()?;
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::ZERO);
            Ok(age >= grace)
        }
        Err(e) => Err(e),
    }
}

/// The temporary folder of one run. It is removed, with everything in it, when this drops.
#[derive(Debug)]
pub struct RunDir {
    // Field order matters: the lock file closes before the folder is removed.
    _lock: File,
    dir: tempfile::TempDir,
}

impl RunDir {
    /// The folder.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> tempfile::TempDir {
        tempfile::tempdir().expect("test folder")
    }

    #[test]
    fn project_area_is_inside_the_project() {
        let p = project();
        let area = TempArea::in_project(p.path()).unwrap();
        assert_eq!(area.root(), p.path().join("tmp"));
        assert!(area.root().is_dir());
    }

    #[test]
    fn run_dirs_are_unique_and_removed_on_drop() {
        let p = project();
        let area = TempArea::in_project(p.path()).unwrap();
        let a = area.run_dir().unwrap();
        let b = area.run_dir().unwrap();
        assert_ne!(a.path(), b.path());
        assert!(a.path().starts_with(area.root()));
        fs::write(a.path().join("extracted.bin"), b"data").unwrap();
        let (pa, pb) = (a.path().to_path_buf(), b.path().to_path_buf());
        drop(a);
        drop(b);
        assert!(!pa.exists() && !pb.exists());
    }

    #[test]
    fn stale_runs_are_cleaned_and_live_runs_kept() {
        let p = project();
        let area = TempArea::in_project(p.path()).unwrap();
        let live = area.run_dir().unwrap();

        // A crashed run: folder and lock file exist, but nobody holds the lock.
        let crashed = area.root().join("run-crashed");
        fs::create_dir(&crashed).unwrap();
        File::create(crashed.join(LOCK_FILE)).unwrap();
        fs::write(crashed.join("part.parquet"), b"x").unwrap();
        // A run that crashed before writing its lock file.
        let no_lock = area.root().join("run-nolock");
        fs::create_dir(&no_lock).unwrap();
        // Not a run folder: never touched.
        let other = area.root().join("keep-me");
        fs::create_dir(&other).unwrap();

        // With the normal grace time, the unlocked folder is too new to remove.
        assert_eq!(area.clean_stale().unwrap(), vec![crashed.clone()]);
        assert!(no_lock.exists());
        assert_eq!(
            area.clean_stale_with_grace(Duration::ZERO).unwrap(),
            vec![no_lock.clone()]
        );

        assert!(live.path().is_dir(), "a held lock keeps its folder");
        assert!(other.is_dir());
        assert!(!crashed.exists() && !no_lock.exists());
    }

    #[test]
    fn system_area_exists() {
        let area = TempArea::system().unwrap();
        assert!(area.root().is_dir());
        assert!(area.root().ends_with("af"));
    }
}
