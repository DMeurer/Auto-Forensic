//! Shared by the targets: bytes as a source, and reading every stream of a file system.

use af_core::bytes::{ByteSource, Locator, MemSource};
use af_core::fs::FileSystem;
use std::sync::Arc;

pub fn source(data: &[u8]) -> Arc<dyn ByteSource> {
    Arc::new(MemSource::new(data.to_vec(), Locator::root("source.fuzz", "input")))
}

/// Walks every entry, builds its paths and reads the start and end of every stream: what a
/// listing and a hash would touch, without reading gigabytes a hostile size claims.
pub fn walk(fs: &dyn FileSystem) {
    let mut buf = vec![0u8; 4096];
    for e in fs.all().take(10_000).flatten() {
        let _ = af_core::fs::paths(fs, &e);
        let _ = fs.list(&e.id);
        for s in &e.streams {
            if let Ok(Some(src)) = fs.open(&e.id, &s.name) {
                let _ = src.read_at(0, &mut buf);
                let _ = src.read_at(src.len().saturating_sub(4096), &mut buf);
            }
        }
    }
}
