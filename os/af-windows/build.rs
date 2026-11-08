//! Compiles in EvtxECmd's maps (piece E3): writes the `include_str!` list of
//! `maps/evtxecmd/*.map` that `evtx_map::EVTXECMD` includes, so updating the maps is copying
//! files, not editing code.

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=maps/evtxecmd");
    let dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"))
        .join("maps/evtxecmd");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("maps/evtxecmd exists")
        .map(|e| {
            e.expect("readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".map"))
        .collect();
    names.sort();
    let mut out = String::from("&[\n");
    for n in names {
        out += &format!("    ({n:?}, include_str!({:?})),\n", dir.join(&n));
    }
    out += "]\n";
    let to =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("set by cargo")).join("evtxecmd_maps.rs");
    std::fs::write(to, out).expect("OUT_DIR is writable");
}
