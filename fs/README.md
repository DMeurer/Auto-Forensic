# File system crates

One crate per file system, named `af-fs-<fs>`, each implementing `af_core::fs::FileSystem` and passing `af_core::fs::check`. A crate reads its volume as an af-core `ByteSource` and knows no host: the same `std` limits as `formats/` apply, and it may depend on af-core, format crates and external crates, never on af-host, af-store or an `os/` crate. `cargo xtask check` enforces this. Tests in `tests/` may use af-host to open real images.

## `af-fs-ntfs` and our `ntfs-core` fork

`af-fs-ntfs` uses `ntfs-core` (Apache-2.0) from our fork, https://github.com/DMeurer/ntfs-forensic, branch `af`, pinned by commit in `Cargo.toml`. The branch starts at upstream's `main` and carries only patches meant to go upstream, made the way upstream's `CONTRIBUTING.md` asks: a failing-test commit, then a separate fix commit, conventional commit messages, `cargo fmt`, and `cargo clippy --all-targets -- -D warnings`.

| Patch | Commits | Why |
|---|---|---|
| Follow `$ATTRIBUTE_LIST` when listing a folder (`directory_entries_by_record`) | `test(fs)` + `fix(fs)` | Large folders keep their `$INDEX_ALLOCATION` in an extension record; on Jean four folders listed 0 to 3 of thousands of names |
| Make `NtfsFs::gather_records` public | `test(fs)` + `feat(fs)` | Names, sizes and streams in extension records (I13, I15) |

Before opening a pull request upstream, still to do: sign the commits with gitsign, run `cargo deny check`, `cargo llvm-cov --lib --show-missing-lines` (100 % line coverage) and the fuzz targets, none of which are installed here.

To take a newer upstream: on branch `af`, `git fetch https://github.com/SecurityRonin/ntfs-forensic main && git rebase FETCH_HEAD`, run upstream's tests, push, and update the pinned commit.

## `af-fs-archive`

Zip (with ZIP64) and tar (ustar, GNU long names, pax) as file systems, parsed by hand rather than with the `zip` and `tar` crates, so every member keeps its offset in the archive. A source added as `.zip` or `.tar` is referenced in place like an image and read through this crate (I22). Not read yet: member times, tar hard links, `.tar.gz`, split zips, encrypted or non-deflate zip members.
