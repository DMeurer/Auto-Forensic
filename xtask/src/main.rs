//! `cargo xtask check [--root <workspace dir>]`
//!
//! Enforces the rules that keep the layers apart (pieces F1 and F2 of the plan):
//!
//! 1. **Format crates take bytes.** A crate under `formats/` uses no `std::fs`, `std::path`,
//!    `std::env`, `std::process`, `std::os` or `std::net` in `src/`, and depends on no workspace
//!    crate outside `formats/` and on no OS crate (`dirs`, `tempfile`, `windows`, ...).
//! 2. **Core knows no Windows formats.** `af-core` depends, directly or through others, on no
//!    `os/` or `formats/` crate and on no registry or EVTX crate.
//! 3. **Windows names stay in Windows and format crates.** `HKLM`, `HKEY_LOCAL_MACHINE`,
//!    `FILETIME` (any case) and drive paths like `C:\` appear only under `formats/` and in
//!    `os/af-windows*`. `xtask` itself is not scanned, because it names the words.
//! 4. **Unsafe code only in the host crate.** Only `af-host` may lift the workspace's
//!    `unsafe_code = "deny"`, for OS calls such as a Windows drive's size.
//!
//! Every violation is printed as `path:line: [rule] message`, and the exit code is 1 if any.

mod compare;
mod evidence;
mod fixtures;

use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, PackageId};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Standard library modules a format crate may not use.
const FORMAT_FORBIDDEN_STD: &[&str] = &["fs", "path", "env", "process", "os", "net"];

/// External crates that reach the OS. A format crate may not depend on them.
const OS_CRATES: &[&str] = &[
    "dirs",
    "dirs-sys",
    "directories",
    "tempfile",
    "walkdir",
    "notify",
    "libc",
    "nix",
    "rustix",
    "windows",
    "windows-sys",
    "winapi",
    "winreg",
];

/// Exact names of registry and EVTX crates that core may not depend on.
const CORE_FORBIDDEN_EXACT: &[&str] = &["notatin", "winreg", "nt_hive", "nt-hive", "nt_hive2"];
/// Name parts that mark a registry or EVTX crate (for example `evtx`, `frnsc-hive`, `regf`).
const CORE_FORBIDDEN_PARTS: &[&str] = &["evtx", "hive", "regf"];

/// File types scanned for Windows names.
const SCANNED_EXTENSIONS: &[&str] = &["rs", "toml", "sql", "yaml", "yml", "json"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layer {
    Core,
    Format,
    /// `fs/`: file system adapters, which read volumes as af-core byte sources.
    FileSystem,
    WindowsOs,
    OtherOs,
    Tool,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    path: String,
    line: usize,
    rule: &'static str,
    message: String,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    match args.first().map(String::as_str) {
        Some("check") => {}
        Some("compare") => return compare::run(&args),
        Some("fixtures") => return fixtures::run_cmd(&args),
        Some("evidence") => return evidence::run(&args),
        _ => {
            eprintln!(
                "usage: cargo xtask check [--root <workspace dir>]\n       \
                 cargo xtask compare IMAGE --af-folder DIR [--offset SECTORS] [--no-hash]\n       \
                 cargo xtask fixtures OUTDIR [fat16 fat32 exfat ntfs]\n       \
                 cargo xtask evidence [list] | fetch SET... [--dir DIR]"
            );
            return ExitCode::from(2);
        }
    }
    if let Some(i) = args.iter().position(|a| a == "--root") {
        match args.get(i + 1) {
            Some(r) => root = PathBuf::from(r),
            None => {
                eprintln!("--root needs a directory");
                return ExitCode::from(2);
            }
        }
    }
    match check(&root) {
        Ok(violations) => {
            let mut out = std::io::stderr().lock();
            for v in &violations {
                let _ = writeln!(out, "{}:{}: [{}] {}", v.path, v.line, v.rule, v.message);
            }
            if violations.is_empty() {
                let _ = writeln!(out, "xtask check: all rules hold");
                ExitCode::SUCCESS
            } else {
                let _ = writeln!(out, "xtask check: {} violation(s)", violations.len());
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("xtask check failed to run: {e}");
            ExitCode::from(2)
        }
    }
}

/// Runs every rule on the workspace at `root` and returns the violations, sorted.
fn check(root: &Path) -> Result<Vec<Violation>, Box<dyn std::error::Error>> {
    let meta = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .exec()?;
    let root = meta.workspace_root.clone().into_std_path_buf();
    let layers = classify(&meta, &root);
    let mut v = Vec::new();
    v.extend(dependency_rules(&meta, &root, &layers));
    for pkg in meta.workspace_packages() {
        let layer = layers[&pkg.id];
        let dir = pkg
            .manifest_path
            .parent()
            .map(|d| d.as_std_path().to_path_buf())
            .unwrap_or_default();
        let bytes_rule = match layer {
            Layer::Format => Some(("format-takes-bytes", "format crate")),
            Layer::FileSystem => Some(("fs-reads-sources", "file system crate")),
            _ => None,
        };
        if let Some((rule, what)) = bytes_rule {
            for file in files(&dir.join("src"), &["rs"]) {
                let text = std::fs::read_to_string(&file)?;
                for (line, module) in format_std_uses(&text) {
                    v.push(Violation {
                        path: rel(&root, &file),
                        line,
                        rule,
                        message: format!("{what} `{}` uses `std::{module}`", pkg.name),
                    });
                }
            }
        }
        if matches!(layer, Layer::Core | Layer::OtherOs | Layer::Other) {
            for file in files(&dir, SCANNED_EXTENSIONS) {
                let text = std::fs::read_to_string(&file)?;
                for (line, word) in windows_words(&text) {
                    v.push(Violation {
                        path: rel(&root, &file),
                        line,
                        rule: "windows-names",
                        message: format!(
                            "`{word}` outside the Windows and format crates (in `{}`)",
                            pkg.name
                        ),
                    });
                }
            }
        }
    }
    for pkg in meta.workspace_packages() {
        if pkg.name.as_str() == "af-host" || layers[&pkg.id] == Layer::Tool {
            continue;
        }
        let dir = pkg
            .manifest_path
            .parent()
            .map(|d| d.as_std_path().to_path_buf())
            .unwrap_or_default();
        for file in files(&dir, &["rs"]) {
            for line in unsafe_allows(&std::fs::read_to_string(&file)?) {
                v.push(Violation {
                    path: rel(&root, &file),
                    line,
                    rule: "unsafe-only-in-host",
                    message: format!(
                        "`{}` lifts the unsafe_code lint; only af-host may",
                        pkg.name
                    ),
                });
            }
        }
    }
    v.sort();
    v.dedup();
    Ok(v)
}

/// Lines that lift the unsafe_code lint (`allow`, `expect` or `warn`), by line number.
fn unsafe_allows(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            l.contains("unsafe_code")
                && ["allow(", "expect(", "warn("].iter().any(|a| l.contains(a))
        })
        .map(|(i, _)| i + 1)
        .collect()
}

/// The layer of each workspace crate, from the folder it sits in.
fn classify(meta: &Metadata, root: &Path) -> HashMap<PackageId, Layer> {
    meta.workspace_packages()
        .into_iter()
        .map(|p| {
            let dir = p
                .manifest_path
                .parent()
                .map(|d| d.as_std_path())
                .unwrap_or(root);
            let top = dir
                .strip_prefix(root)
                .ok()
                .and_then(|r| r.components().next())
                .and_then(|c| c.as_os_str().to_str())
                .unwrap_or("");
            let name = p.name.to_string();
            let layer = match top {
                "formats" => Layer::Format,
                "fs" => Layer::FileSystem,
                "os" if name.starts_with("af-windows") => Layer::WindowsOs,
                "os" => Layer::OtherOs,
                "xtask" => Layer::Tool,
                "crates" if name == "af-core" => Layer::Core,
                _ => Layer::Other,
            };
            (p.id.clone(), layer)
        })
        .collect()
}

/// Rules 1 (dependency part) and 2.
fn dependency_rules(
    meta: &Metadata,
    root: &Path,
    layers: &HashMap<PackageId, Layer>,
) -> Vec<Violation> {
    let mut v = Vec::new();
    let Some(resolve) = &meta.resolve else {
        return v;
    };
    let name_of: HashMap<&PackageId, String> = meta
        .packages
        .iter()
        .map(|p| (&p.id, p.name.to_string()))
        .collect();
    // Dependencies that end up in the built crate: normal and build, not dev.
    let deps: HashMap<&PackageId, Vec<&PackageId>> = resolve
        .nodes
        .iter()
        .map(|n| {
            let ds = n
                .deps
                .iter()
                .filter(|d| {
                    d.dep_kinds
                        .iter()
                        .any(|k| k.kind != DependencyKind::Development)
                })
                .map(|d| &d.pkg)
                .collect();
            (&n.id, ds)
        })
        .collect();
    let manifest = |id: &PackageId| {
        meta.packages
            .iter()
            .find(|p| &p.id == id)
            .map(|p| rel(root, p.manifest_path.as_std_path()))
            .unwrap_or_default()
    };
    for (id, layer) in layers {
        match layer {
            Layer::Format => {
                for d in deps.get(id).into_iter().flatten() {
                    let dname = &name_of[d];
                    let bad = match layers.get(*d) {
                        Some(Layer::Format) => false,
                        Some(_) => true,
                        None => OS_CRATES.contains(&dname.as_str()),
                    };
                    if bad {
                        v.push(Violation {
                            path: manifest(id),
                            line: 0,
                            rule: "format-takes-bytes",
                            message: format!("format crate `{}` depends on `{dname}`", name_of[id]),
                        });
                    }
                }
            }
            Layer::FileSystem => {
                // af-core, format crates and outside crates; never the host, the store or an OS.
                for d in deps.get(id).into_iter().flatten() {
                    let dname = &name_of[d];
                    let bad = match layers.get(*d) {
                        Some(Layer::Core | Layer::Format | Layer::FileSystem) => false,
                        Some(_) => true,
                        None => OS_CRATES.contains(&dname.as_str()),
                    };
                    if bad {
                        v.push(Violation {
                            path: manifest(id),
                            line: 0,
                            rule: "fs-reads-sources",
                            message: format!(
                                "file system crate `{}` depends on `{dname}`",
                                name_of[id]
                            ),
                        });
                    }
                }
            }
            Layer::Core => {
                // Everything core pulls in, directly or not.
                let mut seen: HashSet<&PackageId> = HashSet::new();
                let mut stack: Vec<&PackageId> = deps.get(id).cloned().unwrap_or_default();
                while let Some(d) = stack.pop() {
                    if seen.insert(d) {
                        stack.extend(deps.get(d).into_iter().flatten());
                    }
                }
                let mut bad: BTreeSet<String> = BTreeSet::new();
                for d in seen {
                    let dname = &name_of[d];
                    let forbidden = match layers.get(d) {
                        Some(Layer::Format | Layer::WindowsOs | Layer::OtherOs) => true,
                        _ => is_registry_or_evtx(dname),
                    };
                    if forbidden {
                        bad.insert(dname.clone());
                    }
                }
                for dname in bad {
                    v.push(Violation {
                        path: manifest(id),
                        line: 0,
                        rule: "core-no-formats",
                        message: format!(
                            "`af-core` depends on `{dname}`, directly or through another crate"
                        ),
                    });
                }
            }
            _ => {}
        }
    }
    v
}

fn is_registry_or_evtx(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    CORE_FORBIDDEN_EXACT.contains(&n.as_str()) || CORE_FORBIDDEN_PARTS.iter().any(|p| n.contains(p))
}

/// Lines of Rust source that use a forbidden std module, as (line number, module).
/// Catches `std::fs::File`, `use std::{io, path::Path}`, groups over several lines and
/// `::std::env`. Line comments are ignored.
fn format_std_uses(text: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    let mut in_group = false; // inside a `use std::{ ... }` that spans lines
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("");
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let mut hits: Vec<&'static str> = Vec::new();
        for m in FORMAT_FORBIDDEN_STD {
            if compact.contains(&format!("std::{m}::")) || compact.contains(&format!("std::{m};")) {
                hits.push(m);
            }
        }
        if in_group {
            hits.extend(group_items(&compact));
            if compact.contains('}') {
                in_group = false;
            }
        }
        let mut rest = compact.as_str();
        while let Some(p) = rest.find("std::{") {
            let group = &rest[p + "std::{".len()..];
            hits.extend(group_items(group));
            if !group.contains('}') {
                in_group = true;
            }
            rest = group;
        }
        for m in hits {
            if !found.contains(&(i + 1, m)) {
                found.push((i + 1, m));
            }
        }
    }
    found
}

/// Forbidden modules named in the items of a `std::{...}` group, up to its closing brace.
fn group_items(group: &str) -> Vec<&'static str> {
    let items = group.split('}').next().unwrap_or("");
    items
        .split(',')
        .filter_map(|item| {
            let head = item
                .split("::")
                .next()
                .unwrap_or("")
                .trim_start_matches('{');
            FORMAT_FORBIDDEN_STD.iter().copied().find(|m| *m == head)
        })
        .collect()
}

/// Windows names in a text, as (line number, word found).
fn windows_words(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let upper = line.to_ascii_uppercase();
        for w in ["HKEY_LOCAL_MACHINE", "HKLM", "FILETIME"] {
            if upper.contains(w) {
                found.push((i + 1, w.to_string()));
            }
        }
        // A drive path: an uppercase letter, a colon and a backslash, not inside a longer word.
        let b = line.as_bytes();
        for j in 0..b.len().saturating_sub(2) {
            let starts_word = j == 0 || !b[j - 1].is_ascii_alphanumeric();
            if starts_word && b[j].is_ascii_uppercase() && b[j + 1] == b':' && b[j + 2] == b'\\' {
                found.push((i + 1, format!("{}:\\", b[j] as char)));
                break;
            }
        }
    }
    found
}

/// All files under `dir` with one of `exts`, skipping `target` folders. Sorted for stable output.
fn files(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n != "target") {
                    stack.push(p);
                }
            } else if p
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| exts.contains(&x))
            {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// A path relative to the workspace root, with `/` separators on every host.
fn rel(root: &Path, p: &Path) -> String {
    let r = p.strip_prefix(root).unwrap_or(p);
    r.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {

    #[test]
    fn unsafe_allows_are_found() {
        let src =
            "#![allow(unsafe_code)]\nfn f() {}\n#[expect(unsafe_code)]\n// unsafe_code is denied\n";
        assert_eq!(unsafe_allows(src), [1, 3]);
    }
    use super::*;

    #[test]
    fn std_uses_in_all_forms() {
        let src = "use std::fs::File;\n\
                   use std::{io, path::Path};\n\
                   use std::{\n\
                   collections::HashMap,\n\
                   env,\n\
                   };\n\
                   let x = ::std::process::id();\n\
                   use std::io::Read; // std::fs:: in a comment is fine\n\
                   use std::os;\n";
        assert_eq!(
            format_std_uses(src),
            vec![
                (1, "fs"),
                (2, "path"),
                (5, "env"),
                (7, "process"),
                (9, "os")
            ]
        );
    }

    #[test]
    fn allowed_std_is_quiet() {
        let src =
            "use std::io::{Read, Seek};\nuse std::collections::BTreeMap;\nuse alloc::vec::Vec;\n";
        assert!(format_std_uses(src).is_empty());
    }

    #[test]
    fn windows_words_any_case_and_drive_paths() {
        let src = "let k = \"HKLM\\\\Software\";\n\
                   // a FileTime value\n\
                   let p = r\"C:\\Windows\";\n\
                   let q = \"ABC:\\\\x\";\n\
                   let ok = \"hklmx\";\n";
        assert_eq!(
            windows_words(src),
            vec![
                (1, "HKLM".to_string()),
                (2, "FILETIME".to_string()),
                (3, "C:\\".to_string()),
                (5, "HKLM".to_string()),
            ]
        );
    }

    #[test]
    fn registry_and_evtx_names() {
        for n in [
            "evtx",
            "notatin",
            "frnsc-hive",
            "nt_hive2",
            "regf-parser",
            "winreg",
        ] {
            assert!(is_registry_or_evtx(n), "{n}");
        }
        for n in ["mft", "duckdb", "serde"] {
            assert!(!is_registry_or_evtx(n), "{n}");
        }
    }

    /// The test workspace in `fixtures/bad` breaks every rule once and keeps each allowed case.
    /// This is the "a planted violation fails" check of F1 and F2, run in CI on both hosts.
    #[test]
    fn planted_violations_are_found() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("bad");
        let got: Vec<String> = check(&root)
            .expect("check runs")
            .into_iter()
            .map(|v| format!("{}:{}: [{}] {}", v.path, v.line, v.rule, v.message))
            .collect();
        let want = vec![
            "crates/af-core/Cargo.toml:0: [core-no-formats] `af-core` depends on `af-fmt-demo`, directly or through another crate",
            "crates/af-core/Cargo.toml:0: [core-no-formats] `af-core` depends on `evtx`, directly or through another crate",
            "crates/af-core/src/lib.rs:2: [windows-names] `HKLM` outside the Windows and format crates (in `af-core`)",
            "crates/af-host/src/lib.rs:2: [windows-names] `C:\\` outside the Windows and format crates (in `af-host`)",
            "formats/af-fmt-demo/Cargo.toml:0: [format-takes-bytes] format crate `af-fmt-demo` depends on `af-host`",
            "formats/af-fmt-demo/src/lib.rs:2: [format-takes-bytes] format crate `af-fmt-demo` uses `std::fs`",
            "formats/af-fmt-demo/src/lib.rs:3: [format-takes-bytes] format crate `af-fmt-demo` uses `std::path`",
            "fs/af-fs-demo/Cargo.toml:0: [fs-reads-sources] file system crate `af-fs-demo` depends on `af-host`",
            "fs/af-fs-demo/src/lib.rs:2: [fs-reads-sources] file system crate `af-fs-demo` uses `std::fs`",
        ];
        assert_eq!(got, want);
    }
}
