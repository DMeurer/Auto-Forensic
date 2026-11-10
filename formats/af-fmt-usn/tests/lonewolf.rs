//! M5 on LoneWolf's `$J` and `$MFT`, copied out of the image (`~/af-stage3/m5/J`,
//! `~/af-stage1/lonewolf/MFT`); skipped where they aren't. MFTECmd agrees on every record and
//! every parent path (scratchpad `m5_compare.py`).

use af_fmt_usn::{Names, parent_paths, read};
use std::path::PathBuf;

#[test]
fn lonewolf_journal_with_rewound_paths() {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let (j, mft) = (
        home.join("af-stage3/m5/J"),
        home.join("af-stage1/lonewolf/MFT"),
    );
    if !j.is_file() || !mft.is_file() {
        return;
    }
    let records: Vec<_> = read(std::io::BufReader::new(std::fs::File::open(j).unwrap()))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(records.len(), 352_849);
    let mut now = Names::new((5, 5));
    af_fmt_mft::read(std::fs::read(mft).unwrap(), |r| {
        if let Some(n) = r
            .names
            .iter()
            .find(|n| n.namespace != 2)
            .filter(|_| r.in_use)
        {
            now.insert(
                (r.number, r.sequence),
                n.name.clone(),
                (n.parent, n.parent_sequence),
            );
        }
    })
    .unwrap();
    let paths = parent_paths(&records, now);
    assert!(paths.iter().all(Option::is_some));
    // Folder 144259 (sequence 37) is gone from the $MFT; the journal still names it.
    let r = &records[994];
    assert_eq!(
        (r.file, r.parent, r.name.as_str(), r.ticks),
        (
            (144_262, 4),
            (144_259, 37),
            "0.0.filtertrie.intermediate.txt",
            Some(131_670_472_822_046_441)
        )
    );
    assert_eq!(
        paths[994].as_deref(),
        Some(
            "/Users/jcloudy/AppData/Local/Packages/Microsoft.Windows.Cortana_cw5n1h2txyewy/\
             LocalState/ConstraintIndex/Apps_{aad03fac-d3f5-457e-ad19-87b2c84c2a13}"
        )
    );
}
