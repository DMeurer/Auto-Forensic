# Fuzz targets (I25)

libFuzzer targets for the parsers and file system adapters, in their own workspace because they need the nightly toolchain:

| Target | Reads |
|---|---|
| `archive` | zip and tar (`af-fs-archive`), then a walk of every entry and stream |
| `volumes` | partition tables and content detection (`af_host::volumes::list`) |
| `ntfs` | NTFS (`af-fs-ntfs` on our `ntfs-core` fork), then a walk |
| `regf` | hives: the own root-key reader and `notatin` (`af_fmt_regf::hive`) |

Setup, once: `rustup toolchain install nightly --profile minimal` and `cargo install cargo-fuzz --locked`.

Run one, from this folder, with memory caps so hostile sizes count as failures:

    cargo +nightly fuzz run ntfs corpus/ntfs -- -rss_limit_mb=2048 -malloc_limit_mb=512 -max_len=2097152

Seeds go in `corpus/<target>/` and are not committed: small cuts of the dfVFS samples (`cargo xtask evidence`), a 2 MiB `mkntfs` volume, a tiny zip and tar, and `notatin`'s test `NTUSER.DAT`. Never put course images or files from them there. A crash lands in `artifacts/<target>/`; `cargo +nightly fuzz run <target> <file>` replays it. Builds keep overflow checks on, so an overflow is a crash here even where a release build would wrap.
