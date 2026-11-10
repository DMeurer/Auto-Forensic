//! M5: every record of a `$J` with its parent path, for comparison with MFTECmd.
//! Usage: `cargo run --release -p af-fmt-usn --example dump J MFT > out.tsv`
//! Lines: entry, sequence, parent entry, parent sequence, USN, FILETIME, reasons (hex), name,
//! parent path; tab between.

use af_fmt_usn::{Names, parent_paths, read};
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let j = std::fs::File::open(&args[0]).unwrap_or_else(|e| panic!("{}: {e}", args[0]));
    let records: Vec<_> = read(std::io::BufReader::new(j))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut now = Names::new((5, 5));
    let mft = std::fs::read(&args[1]).unwrap_or_else(|e| panic!("{}: {e}", args[1]));
    af_fmt_mft::read(mft, |r| {
        // The long name: Win32 (1), Win32 and DOS (3) or POSIX (0), not the DOS one (2).
        if let Some(n) = r
            .in_use
            .then_some(())
            .and_then(|()| r.names.iter().find(|n| n.namespace != 2))
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
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for (r, p) in records.iter().zip(&paths) {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{:x}\t{}\t{}",
            r.file.0,
            r.file.1,
            r.parent.0,
            r.parent.1,
            r.usn,
            r.ticks.map_or(String::new(), |t| t.to_string()),
            r.reasons,
            r.name,
            p.as_deref().unwrap_or("?")
        )
        .unwrap();
    }
}
