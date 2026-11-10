//! X1 on Prefetch files copied out of the test images in stages 0 and 1 (`~/af-stage1/<image>/
//! prefetch`, `~/af-stage0/extract/prefetch`); each check is skipped where its copy isn't.
//! PECmd and sccainfo agree with every value on all four images (~/af-stage3/x1, scripts
//! `t4_prefetch_compare.py` and `x1_scca_compare.py`).

use af_fmt_prefetch::{Error, read};
use std::path::PathBuf;

fn dir(rel: &str) -> Option<PathBuf> {
    let d = PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel);
    d.is_dir().then_some(d)
}

fn parse(d: &std::path::Path, name: &str) -> Result<af_fmt_prefetch::Prefetch, Error> {
    read(name, &std::fs::read(d.join(name)).unwrap())
}

#[test]
fn lonewolf_parses_or_was_never_written() {
    let Some(d) = dir("af-stage1/lonewolf/prefetch") else {
        return;
    };
    let mut names: Vec<String> = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 161);
    let failed: Vec<(String, Error)> = names
        .iter()
        .filter_map(|n| parse(&d, n).err().map(|e| (n.clone(), e)))
        .collect();
    // Its zeros are on disk: NTFS marks the data initialised.
    assert_eq!(
        failed,
        [("CHROME.EXE-CCF9F3F5.pf".to_string(), Error::NeverWritten)]
    );
    let cmd = parse(&d, "CMD.EXE-CD245F9E.pf").unwrap();
    assert_eq!(
        (cmd.version, cmd.name.as_str(), cmd.run_count),
        (30, "CMD.EXE", 6)
    );
    assert_eq!(cmd.run_times[0], 131_673_675_022_892_305); // 2018-04-05 02:05:02.2892305 UTC
    assert_eq!(cmd.files.len(), 12);
    assert_eq!(cmd.volumes[0].serial, 0xAA92_0881);
}

#[test]
fn exam_never_written_file() {
    let Some(d) = dir("af-stage0/extract/prefetch") else {
        return;
    };
    // Its NTFS data is uninitialised, so it reads as zeros.
    assert_eq!(
        parse(&d, "GETHELP.EXE-40796CE6.pf"),
        Err(Error::NeverWritten)
    );
}

#[test]
fn vss_boot_trace_over_one_megabyte() {
    let Some(d) = dir("af-stage1/vss/prefetch") else {
        return;
    };
    let boot = parse(&d, "NTOSBOOT-B00DFAAD.pf").unwrap();
    assert_eq!((boot.version, boot.name.as_str()), (23, "NTOSBOOT"));
}
