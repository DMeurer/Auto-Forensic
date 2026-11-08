# AutoForensic

A forensic timeline tool for disk images, devices and loose files, with few, strong and labelled links between events. Early work: stage 2 (foundation) of the project plan.

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

The event log maps in `os/af-windows/maps/evtxecmd` are EvtxECmd's, by Eric R. Zimmerman, under the MIT licence in [that folder](os/af-windows/maps/evtxecmd/LICENSE); af compiles them in.

## Layout

| Folder | Layer | Rule |
|---|---|---|
| `crates/af-core` | Project model, time and path types, systems, plugin interface | No `os/` or `formats/` crate and no registry or EVTX crate in its dependencies, not even indirectly. Never names `HKLM`, `FILETIME` or a drive path like `C:\` |
| `crates/af-host` | Everything that touches the machine the tool runs on | The one place for temp paths and opening a browser |
| `crates/af-cli` | The `af` command | |
| `formats/af-fmt-*` | One crate per file format | Takes bytes. No `std::fs`, `std::path`, `std::env`, `std::process`, `std::os` or `std::net`, and no dependency outside `formats/` except external non-OS crates |
| `fs/af-fs-*` | One crate per file system, implementing af-core's `FileSystem` | Reads volumes as af-core byte sources. Same `std` limits as formats; may depend on af-core, format crates and external non-OS crates, never on af-host, af-store or an `os/` crate |
| `os/af-windows` | Windows profile and plugins | May name Windows things. Other `os/` crates may not |
| `xtask` | Repository checks | |

The folder a crate sits in decides its rules. `cargo xtask check` enforces them, and CI runs it on Linux and Windows.

## Build and check

```
cargo build
cargo test --workspace
cargo xtask check
```

The toolchain is pinned in `rust-toolchain.toml`; rustup installs it on first use.
