//! The `af` command. Only `--version` so far.

use std::io::Write;

fn main() -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "af {}", af_core::VERSION)
}
