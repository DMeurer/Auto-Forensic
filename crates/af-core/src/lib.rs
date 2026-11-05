//! AutoForensic core: the project model and the seams every plugin builds on.
//!
//! Core knows no operating system and no file format. Windows-specific names and
//! format parsers live in `os/` and `formats/`, and `cargo xtask check` enforces that.

/// The workspace version, shared by all crates.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
