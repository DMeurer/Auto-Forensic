//! Host services for AutoForensic: everything that touches the machine the tool runs on,
//! kept in one place and tested on Linux and Windows (piece F3).
//!
//! - [`temp`]: temporary folders inside the project (`<project>/tmp`), removed when a run
//!   ends, with leftovers of crashed runs cleared on the next start.
//! - [`browser`]: opening a URL in the default browser, without a shell.

pub mod browser;
pub mod temp;
