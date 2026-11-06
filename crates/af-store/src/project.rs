//! Project folders (piece F19).
//!
//! A project is a folder:
//!
//! - `project.duckdb`: the store, including a `project` table of name, creation time and the af
//!   version that created it;
//! - `tmp/`: temporary run folders (F3), cleared of crash leftovers whenever the project opens.
//!
//! Creating never touches a folder that already has something in it.

use crate::{Error as DbError, Store};
use af_host::temp::TempArea;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The store file inside a project folder.
pub const STORE_FILE: &str = "project.duckdb";
/// The memory limit for a project's store, the safe setting from stage 1.
pub const MEMORY_LIMIT_MB: u32 = 5120;

/// An open project.
pub struct Project {
    pub dir: PathBuf,
    pub store: Store,
    pub temp: TempArea,
}

/// What the `project` table holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectInfo {
    pub name: String,
    /// Seconds since 1970, UTC.
    pub created_unix: i64,
    /// The af version that created the project.
    pub created_by_version: String,
}

#[derive(Debug)]
pub enum ProjectError {
    /// The folder exists and isn't empty, so creating would mix with other files.
    NotEmpty(PathBuf),
    /// The folder has no `project.duckdb`.
    NotAProject(PathBuf),
    /// The store has no project row.
    NoInfo(PathBuf),
    /// No source with this ID.
    NoSource(String),
    /// A relink target that isn't the same image, or a relink of a loose file.
    Mismatch(String),
    Io(std::io::Error),
    Db(DbError),
}

impl fmt::Display for ProjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEmpty(p) => write!(f, "{} exists and isn't empty", p.display()),
            Self::NotAProject(p) => write!(f, "{} has no {STORE_FILE}", p.display()),
            Self::NoInfo(p) => write!(f, "{} has no project information", p.display()),
            Self::NoSource(id) => write!(f, "no source {id}"),
            Self::Mismatch(m) => write!(f, "{m}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProjectError {}

impl From<std::io::Error> for ProjectError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<DbError> for ProjectError {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}

impl Project {
    /// Creates a project in `dir`, which must not exist or be empty.
    pub fn create(dir: &Path, name: &str) -> Result<Self, ProjectError> {
        if dir.exists() && std::fs::read_dir(dir)?.next().is_some() {
            return Err(ProjectError::NotEmpty(dir.to_path_buf()));
        }
        std::fs::create_dir_all(dir)?;
        let store = Store::open(&dir.join(STORE_FILE), MEMORY_LIMIT_MB)?;
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        store.connection().execute(
            "INSERT INTO project VALUES (?, ?, ?)",
            duckdb::params![name, created, af_core::VERSION],
        )?;
        let temp = TempArea::in_project(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            store,
            temp,
        })
    }

    /// Opens the project in `dir` and clears leftovers of crashed runs from its `tmp/`.
    pub fn open(dir: &Path) -> Result<Self, ProjectError> {
        let path = dir.join(STORE_FILE);
        if !path.is_file() {
            return Err(ProjectError::NotAProject(dir.to_path_buf()));
        }
        let store = Store::open(&path, MEMORY_LIMIT_MB)?;
        let temp = TempArea::in_project(dir)?;
        temp.clean_stale()?;
        let project = Self {
            dir: dir.to_path_buf(),
            store,
            temp,
        };
        project.info()?;
        Ok(project)
    }

    pub fn info(&self) -> Result<ProjectInfo, ProjectError> {
        self.store
            .connection()
            .query_row(
                "SELECT name, created_unix, created_by_version FROM project",
                [],
                |r| {
                    Ok(ProjectInfo {
                        name: r.get(0)?,
                        created_unix: r.get(1)?,
                        created_by_version: r.get(2)?,
                    })
                },
            )
            .map_err(|e| match e {
                DbError::QueryReturnedNoRows => ProjectError::NoInfo(self.dir.clone()),
                other => ProjectError::Db(other),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_reopen_keeps_state() {
        let parent = tempfile_dir();
        let dir = parent.join("case-1");
        let created = Project::create(&dir, "Exam case").unwrap();
        let info = created.info().unwrap();
        assert_eq!(info.name, "Exam case");
        assert_eq!(info.created_by_version, af_core::VERSION);
        assert!(dir.join("tmp").is_dir());
        drop(created);

        let reopened = Project::open(&dir).unwrap();
        assert_eq!(reopened.info().unwrap(), info);
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn never_creates_into_a_used_folder() {
        let parent = tempfile_dir();
        std::fs::write(parent.join("evidence.E01"), b"keep me").unwrap();
        assert!(matches!(
            Project::create(&parent, "x"),
            Err(ProjectError::NotEmpty(_))
        ));
        assert_eq!(
            std::fs::read(parent.join("evidence.E01")).unwrap(),
            b"keep me"
        );
        assert!(matches!(
            Project::open(&parent),
            Err(ProjectError::NotAProject(_))
        ));
        std::fs::remove_dir_all(&parent).unwrap();
    }

    fn tempfile_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "af-project-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
