//! R4: every key and value of a hive as af reads it, for comparison with yarp.
//! Usage: `cargo run --release -p af-fmt-regf --example dump HIVE [LOG...] > out.tsv`
//! Lines: `key<TAB>path<TAB>last written (FILETIME)` and
//! `value<TAB>path<TAB>name<TAB>type<TAB>data as hex`; the root's path is empty.

use af_fmt_regf::hive::Hive;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let read = |p: &String| std::fs::read(p).unwrap_or_else(|e| panic!("{p}: {e}"));
    let mut hive = Hive::open(read(&args[0]), args[1..].iter().map(read).collect())
        .unwrap_or_else(|e| panic!("{}: {e}", args[0]));
    eprintln!("replay: {:?}", hive.replay());
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let mut todo = vec![String::new()];
    while let Some(path) = todo.pop() {
        let Some(k) = hive.key(&path) else {
            eprintln!("can't open key {path:?}");
            continue;
        };
        writeln!(out, "key\t{path}\t{}", k.last_written).unwrap();
        for v in &k.values {
            let hex: String = v.data.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(out, "value\t{path}\t{}\t{}\t{hex}", v.name, v.value_type).unwrap();
        }
        for s in k.subkeys.iter().rev() {
            todo.push(if path.is_empty() {
                s.clone()
            } else {
                format!("{path}\\{s}")
            });
        }
    }
}
