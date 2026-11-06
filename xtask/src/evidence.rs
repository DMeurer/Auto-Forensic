//! `cargo xtask evidence [list] | fetch SET... [--dir DIR]` (piece I3): the public evidence list.
//!
//! `list` (the default) prints the sets in `xtask/evidence.tsv` with their sizes and downloads
//! nothing. `fetch` downloads each file of the named sets with curl into `DIR/SET` (default
//! `~/af-stage3/evidence`), never into the repository, then checks its size and SHA-256. A file
//! already there is only checked. An unpinned hash (`-`) is printed so it can be pinned. The first
//! segment of an E01 is then checked with `ewfverify`, against the published media MD5 if any.
//! The exit code is 0 when everything checks, 1 when something doesn't, 2 on errors.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const LIST: &str = include_str!("../evidence.tsv");

#[derive(Debug, PartialEq, Eq)]
pub struct Item<'a> {
    pub set: &'a str,
    pub name: &'a str,
    pub size: u64,
    pub sha256: Option<&'a str>,
    pub media_md5: Option<&'a str>,
    pub url: &'a str,
}

pub fn parse(text: &str) -> Result<Vec<Item<'_>>, String> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
        .map(|(i, l)| {
            let f: Vec<&str> = l.split('\t').collect();
            let [set, name, size, sha, md5, url] = f[..] else {
                return Err(format!(
                    "evidence.tsv:{}: needs 6 tab-separated columns",
                    i + 1
                ));
            };
            // Names become paths below the evidence folder, so they may not leave it.
            if name.contains(['/', '\\']) || name.starts_with('.') || !url.starts_with("https://") {
                return Err(format!("evidence.tsv:{}: bad name or URL", i + 1));
            }
            let size = size
                .parse()
                .map_err(|_| format!("evidence.tsv:{}: bad size", i + 1))?;
            let opt = |s| (s != "-").then_some(s);
            Ok(Item {
                set,
                name,
                size,
                sha256: opt(sha),
                media_md5: opt(md5),
                url,
            })
        })
        .collect()
}

fn fetch_one(item: &Item, dir: &Path) -> Result<bool, String> {
    let path = dir.join(item.name);
    if !path.exists() {
        let part = dir.join(format!("{}.part", item.name));
        let ok = Command::new("curl")
            .args(["-fL", "--retry", "3", "-C", "-", "-sS", "-o"])
            .arg(&part)
            .arg(item.url)
            .status()
            .map_err(|e| format!("curl: {e}"))?
            .success();
        if !ok {
            return Err(format!(
                "{}: download failed (the .part file is kept for a resume)",
                item.name
            ));
        }
        std::fs::rename(&part, &path).map_err(|e| e.to_string())?;
    }
    let size = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
    if size != item.size {
        eprintln!("{}: size {size}, expected {}", item.name, item.size);
        return Ok(false);
    }
    let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    let (_, sha) = crate::compare::hash_stream(file).map_err(|e| e.to_string())?;
    match item.sha256 {
        None => eprintln!("{}: unpinned, sha256 {sha}", item.name),
        Some(p) if p != sha => {
            eprintln!("{}: sha256 {sha}, expected {p}", item.name);
            return Ok(false);
        }
        Some(_) => eprintln!("{}: ok", item.name),
    }
    Ok(true)
}

/// Checks a whole E01 image with ewfverify, given its first segment.
fn verify_e01(first: &Path, media_md5: Option<&str>) -> Result<bool, String> {
    let out = Command::new("ewfverify")
        .args(["-q", "-d", "md5"])
        .arg(first)
        .output()
        .map_err(|e| format!("ewfverify: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let md5_ok = media_md5.is_none_or(|m| text.contains(m));
    let name = first.display();
    if out.status.success() && md5_ok {
        eprintln!(
            "{name}: ewfverify ok{}",
            if media_md5.is_some() {
                ", published MD5 matches"
            } else {
                ""
            }
        );
        Ok(true)
    } else {
        eprintln!("{name}: ewfverify failed or MD5 differs:\n{text}");
        Ok(false)
    }
}

pub fn run(args: &[String]) -> ExitCode {
    let items = match parse(LIST) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut sets: Vec<&str> = items.iter().map(|i| i.set).collect();
    sets.dedup();
    let dir_flag = args
        .iter()
        .position(|a| a == "--dir")
        .and_then(|i| args.get(i + 1));
    match args.get(1).map(String::as_str) {
        None | Some("list") => {
            for s in &sets {
                let of: Vec<_> = items.iter().filter(|i| i.set == *s).collect();
                let bytes: u64 = of.iter().map(|i| i.size).sum();
                eprintln!("{s}: {} files, {:.1} MB", of.len(), bytes as f64 / 1e6);
                for i in of {
                    eprintln!("  {} ({} bytes) {}", i.name, i.size, i.url);
                }
            }
            ExitCode::SUCCESS
        }
        Some("fetch") => {
            let wanted: Vec<&str> = args[2..]
                .iter()
                .take_while(|a| *a != "--dir")
                .map(String::as_str)
                .collect();
            if wanted.is_empty() || wanted.iter().any(|w| !sets.contains(w)) {
                eprintln!(
                    "usage: cargo xtask evidence fetch SET... [--dir DIR]; sets: {}",
                    sets.join(", ")
                );
                return ExitCode::from(2);
            }
            let base = match dir_flag {
                Some(d) => PathBuf::from(d),
                None => match std::env::var_os("HOME") {
                    Some(h) => PathBuf::from(h).join("af-stage3/evidence"),
                    None => {
                        eprintln!("no HOME; pass --dir");
                        return ExitCode::from(2);
                    }
                },
            };
            let mut all_ok = true;
            for set in wanted {
                let dir = base.join(set);
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    eprintln!("{}: {e}", dir.display());
                    return ExitCode::from(2);
                }
                for item in items.iter().filter(|i| i.set == set) {
                    match fetch_one(item, &dir) {
                        Ok(ok) => all_ok &= ok,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    }
                }
                // ewfverify reads all segments from the first, so check only once each segment is in.
                for item in items
                    .iter()
                    .filter(|i| i.set == set && i.name.ends_with(".E01"))
                {
                    match verify_e01(&dir.join(item.name), item.media_md5) {
                        Ok(ok) => all_ok &= ok,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    }
                }
            }
            if all_ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some(other) => {
            eprintln!("unknown evidence command {other}; use list or fetch");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_list_parses() {
        let items = parse(LIST).unwrap();
        assert!(items.iter().any(|i| i.set == "jean"));
        assert!(items.iter().all(|i| i.size > 0));
    }

    #[test]
    fn bad_lines_are_refused() {
        assert!(parse("a\tb\t1\t-\t-\n").is_err(), "too few columns");
        assert!(
            parse("a\t../x\t1\t-\t-\thttps://e/x\n").is_err(),
            "name leaves the folder"
        );
        assert!(parse("a\tx\t1\t-\t-\thttp://e/x\n").is_err(), "not https");
        let ok = parse("# c\na\tx\t1\tab\t-\thttps://e/x\n").unwrap();
        assert_eq!((ok[0].sha256, ok[0].media_md5), (Some("ab"), None));
    }
}
