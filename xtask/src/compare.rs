//! `cargo xtask compare` (piece I1): af's view of an image against TSK's, file by file.
//!
//! Usage: `cargo xtask compare IMAGE --af-folder DIR [--offset SECTORS] [--no-hash]`
//!
//! The TSK side lists the file system with `fls -r -p` and hashes every allocated regular file
//! with `icat`. The af side, until af reads images itself (I4, I5, I13), lists and hashes a
//! folder in place, such as a `tsk_recover` export of the same image, which must then compare
//! clean. Differences are printed per file: only in TSK, only in af, other size, other hash.
//! TSK's own metadata entries (`$MFT`, `$OrphanFiles`, ...) are counted, not compared.
//! The exit code is 0 when nothing differs, 1 when something does, 2 on errors.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

/// One regular file as a side sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub size: u64,
    pub sha256: Option<String>,
}

/// One line of `fls -r -p`: type, inode address, deleted flag, path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlsLine {
    pub kind: String,
    pub inode: String,
    pub deleted: bool,
    pub path: String,
}

/// Parses `fls -r -p` output, such as `r/r 37-128-1:\tdir/file.txt` or
/// `r/r * 41(realloc):\tgone.txt`. Lines that don't fit are skipped.
pub fn parse_fls(text: &str) -> Vec<FlsLine> {
    text.lines()
        .filter_map(|line| {
            let (head, path) = line.split_once(":\t")?;
            let mut parts = head.split_whitespace();
            let kind = parts.next()?.to_string();
            let mut next = parts.next()?;
            let deleted = next == "*";
            if deleted {
                next = parts.next()?;
            }
            let inode = next.split('(').next()?.to_string();
            Some(FlsLine {
                kind,
                inode,
                deleted,
                path: path.to_string(),
            })
        })
        .collect()
}

/// Whether a path is TSK's own metadata rather than a file of the file system: NTFS system
/// files at the root, `$OrphanFiles`, and a FAT volume label, which `fls` lists as a file.
fn tsk_meta(path: &str) -> bool {
    path.starts_with('$') && !path.contains('/')
        || path.starts_with("$OrphanFiles")
        || path.ends_with("(Volume Label Entry)")
}

fn hash_stream(mut r: impl Read) -> std::io::Result<(u64, String)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        let k = r.read(&mut buf)?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        n += k as u64;
    }
    Ok((n, h.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}

/// TSK's allocated regular files, by path, plus the count of metadata and deleted entries left out.
pub fn tsk_listing(
    image: &Path,
    offset: Option<u64>,
    hash: bool,
) -> std::io::Result<(BTreeMap<String, Entry>, usize, usize)> {
    let off: Vec<String> = offset
        .map(|o| vec!["-o".into(), o.to_string()])
        .unwrap_or_default();
    let out = Command::new("fls")
        .args(["-r", "-p"])
        .args(&off)
        .arg(image)
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "fls failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let (mut files, mut meta, mut deleted) = (BTreeMap::new(), 0, 0);
    for l in parse_fls(&String::from_utf8_lossy(&out.stdout)) {
        if !l.kind.ends_with('r') {
            continue;
        }
        if tsk_meta(&l.path) {
            meta += 1;
            continue;
        }
        if l.deleted {
            deleted += 1;
            continue;
        }
        let mut child = Command::new("icat")
            .args(&off)
            .arg(image)
            .arg(&l.inode)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let (size, sha) = if hash {
            let (n, h) = hash_stream(child.stdout.take().expect("piped"))?;
            (n, Some(h))
        } else {
            let mut n = 0u64;
            let mut buf = vec![0u8; 1 << 20];
            let mut s = child.stdout.take().expect("piped");
            loop {
                let k = s.read(&mut buf)?;
                if k == 0 {
                    break;
                }
                n += k as u64;
            }
            (n, None)
        };
        child.wait()?;
        files.insert(l.path, Entry { size, sha256: sha });
    }
    Ok((files, meta, deleted))
}

/// The regular files of a folder, read in place, by path below it.
pub fn folder_listing(dir: &Path, hash: bool) -> std::io::Result<BTreeMap<String, Entry>> {
    let vol = af_host::folder::FolderVolume::new(af_core::system::VolumeId(0), dir);
    let style = af_core::path::PathStyle {
        separator: '/',
        case: af_core::path::CasePolicy::Exact,
    };
    let mut files = BTreeMap::new();
    for f in vol.files()? {
        let sha = if hash {
            Some(hash_stream(std::fs::File::open(&f.on_disk)?)?.1)
        } else {
            None
        };
        let path = f.path.display(style).trim_start_matches('/').to_string();
        files.insert(
            path,
            Entry {
                size: f.size,
                sha256: sha,
            },
        );
    }
    Ok(files)
}

/// The differences, one line per file, in path order.
pub fn diff(tsk: &BTreeMap<String, Entry>, af: &BTreeMap<String, Entry>) -> Vec<String> {
    let mut out = Vec::new();
    for (path, t) in tsk {
        match af.get(path) {
            None => out.push(format!("only in TSK: {path} ({} bytes)", t.size)),
            Some(a) if a.size != t.size => out.push(format!(
                "size differs: {path} (TSK {}, af {})",
                t.size, a.size
            )),
            Some(a) if a.sha256.is_some() && t.sha256.is_some() && a.sha256 != t.sha256 => {
                out.push(format!("hash differs: {path}"))
            }
            Some(_) => {}
        }
    }
    for (path, a) in af {
        if !tsk.contains_key(path) {
            out.push(format!("only in af: {path} ({} bytes)", a.size));
        }
    }
    out
}

pub fn run(args: &[String]) -> ExitCode {
    let image = args.get(1).filter(|a| !a.starts_with("--"));
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
    };
    let (Some(image), Some(folder)) = (image, flag("--af-folder")) else {
        eprintln!(
            "usage: cargo xtask compare IMAGE --af-folder DIR [--offset SECTORS] [--no-hash]"
        );
        return ExitCode::from(2);
    };
    let offset = match flag("--offset").map(|o| o.parse::<u64>()) {
        None => None,
        Some(Ok(o)) => Some(o),
        Some(Err(_)) => {
            eprintln!("--offset needs a sector number");
            return ExitCode::from(2);
        }
    };
    let hash = !args.iter().any(|a| a == "--no-hash");
    let (tsk, meta, deleted) = match tsk_listing(Path::new(image), offset, hash) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("TSK side: {e}");
            return ExitCode::from(2);
        }
    };
    let af = match folder_listing(Path::new(folder), hash) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("af side: {e}");
            return ExitCode::from(2);
        }
    };
    let lines = diff(&tsk, &af);
    eprintln!(
        "TSK: {} files ({meta} metadata and {deleted} deleted entries not compared); af: {} files; {} differences",
        tsk.len(),
        af.len(),
        lines.len()
    );
    for l in &lines {
        eprintln!("{l}");
    }
    if lines.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fls_lines_parse() {
        let text = "r/r 4-128-4:\t$AttrDef\nd/d 64-144-2:\tUsers\nr/r 70-128-2:\tUsers/ich/NTUSER.DAT\n\
                    r/r * 41(realloc):\tgone.txt\nr/r * 7:\timages/Bild.jpg\nV/V 1234:\t$OrphanFiles\nnot a line\n";
        let lines = parse_fls(text);
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[2].path, "Users/ich/NTUSER.DAT");
        assert_eq!(lines[2].inode, "70-128-2");
        assert!(!lines[2].deleted);
        assert_eq!((lines[3].inode.as_str(), lines[3].deleted), ("41", true));
        assert!(tsk_meta("$AttrDef") && tsk_meta("$OrphanFiles/x") && !tsk_meta("Users/$Recycle"));
        assert!(tsk_meta("USB DISK    (Volume Label Entry)"));
    }

    #[test]
    fn diff_reports_each_kind_of_difference() {
        let e = |size, h: &str| Entry {
            size,
            sha256: Some(h.into()),
        };
        let tsk = BTreeMap::from([
            ("a".to_string(), e(1, "x")),
            ("b".to_string(), e(2, "y")),
            ("c".to_string(), e(3, "z")),
            ("same".to_string(), e(4, "s")),
        ]);
        let af = BTreeMap::from([
            ("b".to_string(), e(5, "y")),
            ("c".to_string(), e(3, "other")),
            ("d".to_string(), e(6, "w")),
            ("same".to_string(), e(4, "s")),
        ]);
        assert_eq!(
            diff(&tsk, &af),
            [
                "only in TSK: a (1 bytes)",
                "size differs: b (TSK 2, af 5)",
                "hash differs: c",
                "only in af: d (6 bytes)",
            ]
        );
    }
}
