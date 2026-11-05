//! AutoForensic core: the project model and the seams every plugin builds on.
//!
//! Core knows no operating system and no file format. OS-specific names and
//! format parsers live in `os/` and `formats/`, and `cargo xtask check` enforces that.

pub mod bytes;
pub mod capability;
pub mod concepts;
pub mod ids;
pub mod names;
pub mod path;
pub mod profile;
pub mod system;
pub mod time;
pub mod timeline;
pub mod unit;

/// The workspace version, shared by all crates.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
