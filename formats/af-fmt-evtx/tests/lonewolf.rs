//! E1 on LoneWolf's 146 event logs, as stage 1 copied them out of the image with TSK
//! (`~/af-stage1/lonewolf/evtx`, not in the repository). Skips when they aren't there.

use std::path::PathBuf;

fn logs() -> Option<Vec<(String, Vec<u8>)>> {
    let dir =
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("af-stage1/lonewolf/evtx");
    let mut logs: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    logs.sort();
    Some(logs)
}

#[test]
fn every_lonewolf_log_reads_without_errors() {
    let Some(logs) = logs() else { return };
    assert_eq!(logs.len(), 146);
    let mut records = 0;
    for (name, data) in logs {
        let log = af_fmt_evtx::read(data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(log.errors.is_empty(), "{name}: {:?}", log.errors);
        assert!(!log.bad_header, "{name}");
        records += log.records.len();
    }
    // EvtxECmd 2026.10.2 gives 55,638 rows for these files too (stage 1, T3).
    assert_eq!(records, 55_638);
}

#[test]
fn a_damaged_log_reports_its_errors() {
    let Some(logs) = logs() else { return };
    let (_, mut data) = logs
        .into_iter()
        .find(|(n, _)| n == "Security.evtx")
        .unwrap();
    let whole = af_fmt_evtx::read(data.clone()).unwrap().records.len();
    // Scribble over the middle of the second chunk (chunks are 64 KiB after a 4 KiB header).
    let at = 0x1000 + 0x10000 + 0x4000;
    data[at..at + 0x2000].fill(0xA5);
    let log = af_fmt_evtx::read(data).unwrap();
    assert!(!log.errors.is_empty(), "the damage is reported");
    assert!(
        log.records.len() < whole,
        "{} of {whole}",
        log.records.len()
    );
    assert!(log.records.len() > whole / 2, "the rest still reads");
}
