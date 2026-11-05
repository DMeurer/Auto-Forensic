//! The `af` command. Only `--version` so far.

use af_core::runner::Plugin;
use std::io::Write;

/// Every compiled-in plugin, in the order the runner calls them within a phase. Adding a plugin
/// is one line here (the Linux canary, C2, checks that nothing else in core has to change).
const PLUGINS: &[&dyn Plugin] = &[];

fn main() -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "af {} ({} plugins)", af_core::VERSION, PLUGINS.len())
}
