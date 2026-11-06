//! `cargo xtask fixtures OUTDIR [FS...]` (piece I2): small stick images with known contents.
//!
//! For each file system (`fat16`, `fat32`, `exfat`, `ntfs`; all by default) it makes a bare
//! image (no partition table), writes files through a real kernel mount (`udisksctl`, no root
//! needed), and sets up the cases stage 1 found on real sticks:
//!
//! - a photo deleted and left intact;
//! - a photo deleted, then its clusters reused by a later file (overwritten): a zero-filled
//!   `neu/filler.bin` first takes all free space (in a subfolder, so the root keeps the
//!   deleted entries), so the later file can only go where the
//!   photo was; it goes into a subfolder, so the photo's root entry stays;
//! - files moved into a folder (on FAT the old entries stay behind as deleted ones);
//! - long names with an umlaut, and an 8.3 name.
//!
//! It writes `<fs>.img`, `<fs>.E01` (via `ewfacquire`) and `<fs>.truth.json`: every file with
//! its final path, size, SHA-256 and state. Contents are generated, never taken from evidence.
//! Linux's drivers don't always leave deleted entries as Windows does (NTFS records lose their
//! names or get reused), so for each deleted file the truth also records whether TSK still
//! lists it by name (`tsk_lists_name`). The real Windows sticks cover Windows' own behaviour.
//! Needs `mkfs.vfat`, `mkfs.ntfs`, `mkfs.exfat` (exfatprogs), `udisksctl` and `ewfacquire`.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// One file in the truth file.
struct Truth {
    path: String,
    size: usize,
    sha256: String,
    /// `live`, `deleted_intact`, `deleted_overwritten` or `moved` (its old entry is gone).
    state: &'static str,
    note: &'static str,
    /// For deleted files: whether `fls -d` still lists the name.
    tsk_lists_name: Option<bool>,
}

/// Deterministic content: `len` bytes from a seed, with a JPEG-like start for photos.
fn content(seed: u8, len: usize, jpeg: bool) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len)
        .map(|i| {
            (i as u32)
                .wrapping_mul(2_654_435_761)
                .wrapping_add(u32::from(seed)) as u8
        })
        .collect();
    if jpeg && len > 4 {
        v[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
    }
    v
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Attaches `img` as a loop device, mounts it, runs `f` on the mount point, and always unmounts
/// and detaches again.
fn with_mount(img: &Path, f: impl FnOnce(&Path) -> Result<(), String>) -> Result<(), String> {
    let out = run(Command::new("udisksctl")
        .args(["loop-setup", "--no-user-interaction", "-f"])
        .arg(img))?;
    let dev = out
        .split_whitespace()
        .find(|w| w.starts_with("/dev/loop"))
        .map(|w| w.trim_end_matches('.').to_string())
        .ok_or_else(|| format!("no loop device in: {out}"))?;
    let result = (|| {
        let out =
            run(Command::new("udisksctl").args(["mount", "--no-user-interaction", "-b", &dev]))?;
        let at = out
            .split(" at ")
            .nth(1)
            .map(|s| s.trim().trim_end_matches('.').to_string())
            .ok_or_else(|| format!("no mount point in: {out}"))?;
        let r = f(Path::new(&at));
        run(Command::new("udisksctl").args(["unmount", "--no-user-interaction", "-b", &dev]))?;
        r
    })();
    let _ =
        run(Command::new("udisksctl").args(["loop-delete", "--no-user-interaction", "-b", &dev]));
    result
}

/// Builds one fixture and returns its truth.
fn build(fs: &str, dir: &Path) -> Result<Vec<Truth>, String> {
    let img = dir.join(format!("{fs}.img"));
    let _ = std::fs::remove_file(&img);
    let (size_mb, mkfs): (u64, Vec<&str>) = match fs {
        "fat16" => (48, vec!["mkfs.vfat", "-F", "16", "-n", "AFFAT16"]),
        "fat32" => (64, vec!["mkfs.vfat", "-F", "32", "-n", "AFFAT32"]),
        "exfat" => (64, vec!["mkfs.exfat", "-L", "AFEXFAT"]),
        "ntfs" => (64, vec!["mkfs.ntfs", "-F", "-Q", "-L", "AFNTFS"]),
        other => return Err(format!("unknown file system {other}")),
    };
    std::fs::File::create(&img)
        .and_then(|f| f.set_len(size_mb << 20))
        .map_err(|e| e.to_string())?;
    run(Command::new(mkfs[0]).args(&mkfs[1..]).arg(&img))?;

    let photo_a = content(1, 300_000, true); // several clusters
    let photo_b = content(2, 200_000, true);
    let notes = content(3, 5_000, false);
    let moved1 = content(4, 70_000, true);
    let moved2 = content(5, 40_000, true);
    let later = content(6, 280_000, false);
    let short = content(7, 1_234, false);
    let mut truth = Vec::new();
    let mut t = |path: &str, data: &[u8], state, note| {
        truth.push(Truth {
            path: path.into(),
            size: data.len(),
            sha256: sha(data),
            state,
            note,
            tsk_lists_name: None,
        })
    };
    let mut filler_len = 0usize;
    with_mount(&img, |m| {
        let w = |p: &str, d: &[u8]| -> Result<(), String> {
            let path = m.join(p);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&path, d).map_err(|e| format!("{p}: {e}"))
        };
        let sync = || run(&mut Command::new("sync")).map(|_| ());
        w("Urlaub Foto am Strand.jpg", &photo_a)?;
        w("Notizen für später.txt", &notes)?;
        w("README.TXT", &short)?;
        w("IMG_0001.JPG", &moved1)?;
        w("IMG_0002.JPG", &moved2)?;
        sync()?;
        // The later file's folder exists from the start, so its entry can't take the photo's
        // freed directory slots.
        std::fs::create_dir_all(m.join("neu")).map_err(|e| e.to_string())?;
        // Moved into a folder: a new entry there, the old one marked deleted (on FAT).
        std::fs::create_dir_all(m.join("images")).map_err(|e| e.to_string())?;
        for f in ["IMG_0001.JPG", "IMG_0002.JPG"] {
            std::fs::rename(m.join(f), m.join("images").join(f)).map_err(|e| e.to_string())?;
        }
        sync()?;
        // Deleted at the very end, so nothing can be written over it.
        w("Geburtstag.jpg", &photo_b)?;
        sync()?;
        // Deleted, then its clusters reused: zeros fill the disk until it is full, so after the
        // photo is deleted its clusters are the only free space for the later file.
        {
            use std::io::Write as _;
            let mut f =
                std::fs::File::create(m.join("neu/filler.bin")).map_err(|e| e.to_string())?;
            let chunk = vec![0u8; 64 << 10];
            while f.write_all(&chunk).is_ok() {}
            let _ = f.sync_all();
        }
        sync()?;
        filler_len = std::fs::metadata(m.join("neu/filler.bin"))
            .map_err(|e| e.to_string())?
            .len() as usize;
        std::fs::remove_file(m.join("Urlaub Foto am Strand.jpg")).map_err(|e| e.to_string())?;
        sync()?;
        w("neu/später geschrieben.bin", &later)?;
        sync()?;
        // Deleted, left intact: its clusters are free but nothing comes after.
        std::fs::remove_file(m.join("Geburtstag.jpg")).map_err(|e| e.to_string())?;
        sync()
    })?;
    t(
        "neu/filler.bin",
        &vec![0u8; filler_len],
        "live",
        "zeros taking the free space",
    );
    t(
        "Notizen für später.txt",
        &notes,
        "live",
        "long name with umlaut",
    );
    t("README.TXT", &short, "live", "8.3 name");
    t(
        "images/IMG_0001.JPG",
        &moved1,
        "moved",
        "moved from the root",
    );
    t(
        "images/IMG_0002.JPG",
        &moved2,
        "moved",
        "moved from the root",
    );
    t(
        "neu/später geschrieben.bin",
        &later,
        "live",
        "written after the deletions, into the photo's clusters",
    );
    t(
        "Geburtstag.jpg",
        &photo_b,
        "deleted_intact",
        "deleted, clusters not reused",
    );
    t(
        "Urlaub Foto am Strand.jpg",
        &photo_a,
        "deleted_overwritten",
        "deleted, then clusters reused by 'neu/später geschrieben.bin'",
    );
    // What TSK still lists by name after this driver's deletions.
    let listed = run(Command::new("fls").args(["-r", "-p", "-d"]).arg(&img))?;
    let names: Vec<&str> = listed
        .lines()
        .filter_map(|l| l.split_once(":\t").map(|x| x.1))
        .collect();
    for f in truth.iter_mut().filter(|f| f.state.starts_with("deleted")) {
        f.tsk_lists_name = Some(names.contains(&f.path.as_str()));
    }

    let mut json = String::from("{\n");
    let _ = writeln!(json, "  \"file_system\": \"{fs}\",");
    let _ = writeln!(json, "  \"image\": \"{fs}.img\",");
    let _ = writeln!(
        json,
        "  \"image_sha256\": \"{}\",",
        sha(&std::fs::read(&img).map_err(|e| e.to_string())?)
    );
    json.push_str("  \"files\": [\n");
    for (i, f) in truth.iter().enumerate() {
        let _ = writeln!(
            json,
            "    {{\"path\": \"{}\", \"size\": {}, \"sha256\": \"{}\", \"state\": \"{}\", \"note\": \"{}\"{}}}{}",
            f.path,
            f.size,
            f.sha256,
            f.state,
            f.note,
            f.tsk_lists_name
                .map(|b| format!(", \"tsk_lists_name\": {b}"))
                .unwrap_or_default(),
            if i + 1 < truth.len() { "," } else { "" }
        );
    }
    json.push_str("  ]\n}\n");
    std::fs::write(dir.join(format!("{fs}.truth.json")), json).map_err(|e| e.to_string())?;

    let target = dir.join(fs);
    let _ = std::fs::remove_file(dir.join(format!("{fs}.E01")));
    run(Command::new("ewfacquire")
        .args([
            "-u",
            "-q",
            "-c",
            "deflate:best",
            "-f",
            "encase6",
            "-d",
            "sha256",
        ])
        .args([
            "-C",
            "af-fixtures",
            "-E",
            fs,
            "-e",
            "af xtask",
            "-D",
            "generated fixture",
            "-N",
            "",
        ])
        .arg("-t")
        .arg(&target)
        .arg(&img))?;
    Ok(truth)
}

pub fn run_cmd(args: &[String]) -> ExitCode {
    let Some(out) = args.get(1) else {
        eprintln!("usage: cargo xtask fixtures OUTDIR [fat16 fat32 exfat ntfs]");
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(out);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("{}: {e}", dir.display());
        return ExitCode::from(2);
    }
    let wanted: Vec<&str> = if args.len() > 2 {
        args[2..].iter().map(String::as_str).collect()
    } else {
        vec!["fat16", "fat32", "exfat", "ntfs"]
    };
    let mut failed = false;
    for fs in wanted {
        match build(fs, &dir) {
            Ok(t) => eprintln!(
                "{fs}: {} files in the truth file, {}/{fs}.img and .E01",
                t.len(),
                dir.display()
            ),
            Err(e) => {
                eprintln!("{fs}: {e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_is_deterministic_and_photos_look_like_jpeg() {
        assert_eq!(content(1, 100, false), content(1, 100, false));
        assert_ne!(content(1, 100, false), content(2, 100, false));
        assert_eq!(&content(1, 10, true)[..3], &[0xFF, 0xD8, 0xFF]);
    }
}
