# Format crates

One crate per file format, named `af-fmt-<format>`. A format crate takes bytes (`&[u8]` or a `Read + Seek`) and knows no paths, files, environment or operating system: no `std::fs`, `std::path`, `std::env`, `std::process`, `std::os` or `std::net`, and no dependency on `af-core`, `af-host` or an `os/` crate. `cargo xtask check` enforces this.
