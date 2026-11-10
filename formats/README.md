# Format crates

One crate per file format, named `af-fmt-<format>`. A format crate takes bytes (`&[u8]` or a `Read + Seek`) and knows no paths, files, environment or operating system: no `std::fs`, `std::path`, `std::env`, `std::process`, `std::os` or `std::net`, and no dependency on `af-core`, `af-host` or an `os/` crate. `cargo xtask check` enforces this.

## `af-fmt-regf` and our `notatin` fork

`af_fmt_regf::hive` uses `notatin` (Apache-2.0) from our fork, https://github.com/DMeurer/notatin, branch `af`, pinned by commit in `Cargo.toml`. The branch starts at upstream commit `ae3a706` (the one stage 1 tested) and carries only fixes meant to go upstream: one `fix:` commit each, with its test, formatted with `cargo fmt`. Upstream has no contributing guide; its recent commits use `fix:` and `chore:` messages.

| Patch | Why |
|---|---|
| `fix: skip subkey list offsets that overflow u32` | `lf`, `li` and `ri` lists added offsets with plain u32 addition; a crafted hive panicked (debug) or wrapped (release). `lh` already used `checked_add` |
| `fix: treat a negative or overflowing root cell offset as no root key` | `get_root_key` cast a negative i32 offset to usize and overflowed |
| `fix: search each key cell once per depth when looking up a key path` | A subkey list naming the same key cell many times made a failed lookup read repeats^depth keys: a 42 KB hive took 29 s |
| `fix: keep all stored bytes of fixed-size values` | A `REG_DWORD` stored in 8 bytes (or a `REG_QWORD` in 16) was cut to its type's size; yarp keeps the stored bytes, and the rest can hold data (R4) |

The first three were found by the `regf` fuzz target (`fuzz/`, I25), the last by comparing with yarp (R4). To fix the next finding locally, add `[patch."https://github.com/DMeurer/notatin"] notatin = { path = "../../notatin" }` to `fuzz/Cargo.toml` while working, and don't commit it.

## `af-fmt-usn`

The change journal (`$UsnJrnl:$J`) on `ntfs-core`'s reader from our fork (the same pin as `af-fs-ntfs`, see `fs/README.md`), plus parent paths rewound through the journal as MFTECmd does (M5). `ntfs-core` keeps no time it can't express (zero, negative, before 1970); such a record has no time here.

## `af-fmt-prefetch` and our `frnsc-prefetch` fork

`af_fmt_prefetch` uses `frnsc-prefetch` (MIT) from our fork, https://github.com/DMeurer/frnsc-prefetch, branch `af`, pinned by commit in `Cargo.toml`. The branch starts at upstream `main`, which is the published 0.13.4 that stage 1 compared with PECmd (T4). It carries only fixes meant to go upstream: one `fix:` commit each, with its test. Upstream has no contributing guide and isn't formatted with current `rustfmt`, so only changed lines are formatted. The fork's commits use the GitHub no-reply address; GitHub refuses pushes with the private one.

| Patch | Why |
|---|---|
| `fix: decode UTF-16 strings without unsafe transmutes` | A `&[u8]` transmuted to `&[u16]` keeps its element count, so names were read up to twice their length, past their slice. The crate now forbids unsafe code |
| `fix: don't print to stdout in the metrics anomaly check` | A leftover debug `println!` wrote file names into the output of whatever used the crate |
| `fix: cap the decompressed size instead of the file size` | Files over 1,000,000 bytes were refused (`NTOSBOOT-B00DFAAD.pf` on vss has 1.8 MB), while a compressed file's header could reserve up to 4 GiB. Both are capped at 32 MiB |
| `fix: read UTF-16 names by their character counts` | File names and device paths store character counts; the first fix had read them as bytes and halved every name |

An upstream pull request waits until after X1 (the user's choice). Before it, the fourth fix gets folded into the first, so that no commit halves names; that needs a force push to the fork.

