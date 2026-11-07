# Format crates

One crate per file format, named `af-fmt-<format>`. A format crate takes bytes (`&[u8]` or a `Read + Seek`) and knows no paths, files, environment or operating system: no `std::fs`, `std::path`, `std::env`, `std::process`, `std::os` or `std::net`, and no dependency on `af-core`, `af-host` or an `os/` crate. `cargo xtask check` enforces this.

## `af-fmt-regf` and our `notatin` fork

`af_fmt_regf::hive` uses `notatin` (Apache-2.0) from our fork, https://github.com/DMeurer/notatin, branch `af`, pinned by commit in `Cargo.toml`. The branch starts at upstream commit `ae3a706` (the one stage 1 tested) and carries only fixes meant to go upstream: one `fix:` commit each, with its test, formatted with `cargo fmt`. Upstream has no contributing guide; its recent commits use `fix:` and `chore:` messages.

| Patch | Why |
|---|---|
| `fix: skip subkey list offsets that overflow u32` | `lf`, `li` and `ri` lists added offsets with plain u32 addition; a crafted hive panicked (debug) or wrapped (release). `lh` already used `checked_add` |
| `fix: treat a negative or overflowing root cell offset as no root key` | `get_root_key` cast a negative i32 offset to usize and overflowed |

Both were found by the `regf` fuzz target (`fuzz/`, I25). To fix the next finding locally, add `[patch."https://github.com/DMeurer/notatin"] notatin = { path = "../../notatin" }` to `fuzz/Cargo.toml` while working, and don't commit it.
