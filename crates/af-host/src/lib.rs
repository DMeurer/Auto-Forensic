//! Host services for AutoForensic: everything that touches the machine the tool runs on,
//! kept in one place and tested on Linux and Windows (piece F3).
//!
//! - [`temp`]: temporary folders inside the project (`<project>/tmp`), removed when a run
//!   ends, with leftovers of crashed runs cleared on the next start.
//! - [`browser`]: opening a URL in the default browser, without a shell.
//! - [`folder`]: a folder on this machine read in place as evidence (C0a).
//! - [`device`]: block and loop devices as live, unhashed sources (I28).
//! - [`ewf`]: E01 images through the `ewf` crate, and [`ewf::open_image`] for any image (I5).
//! - [`raw`]: raw and split raw images read as one stream (I4).
//! - [`volumes`]: partitions, gaps and partitionless disks as views (I7–I10).

pub mod browser;
pub mod device;
pub mod ewf;
pub mod folder;
pub mod raw;
pub mod temp;
pub mod volumes;
