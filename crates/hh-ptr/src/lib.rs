//! hh-ptr: pointer scanner (Cheat Engine style), pointer maps and rescans.
//!
//! Flow: [`PointerMap::collect`] takes one pass over the target's readable memory and keeps
//! every (address, value) pair whose value points into valid memory, sorted by value.
//! [`PointerMap::scan`] then searches backwards from a target address and streams every
//! path `base -> [+o1] -> ... -> target` into a [`ResultFile`] on disk. Maps can be saved
//! and loaded, so scans and comparisons work without the process. Result files are paged
//! with [`ResultFile::results`], filtered with [`ResultFile::rescan`] and sorted/merged
//! with [`merge`].
//!
//! File formats (little endian):
//! - pointer map: `b"HHPMAP01"`, u32 header length, JSON header (pointer size, regions,
//!   modules), u64 entry count, then `count` × (u64 value, u64 address) sorted by value.
//! - result file: `b"HHPTRS01"`, u32 header length, JSON [`ResultHeader`], then fixed-size
//!   records: u32 base index (`u32::MAX` = absolute address), i64 base offset, u8 level,
//!   `max_level` × i32 offsets (unused ones zero).
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use serde::{Deserialize, Serialize};

mod map;
mod path;
mod results;
mod scan;
#[cfg(test)]
mod tests;

pub use map::{CollectOptions, PointerMap};
pub use path::{PointerPath, resolve, to_table_entry};
pub use results::{RescanOptions, ResultFile, ResultHeader, ResultRow, Source, merge};
pub use scan::ScanOptions;

/// Longest path any file or scan supports.
pub const MAX_LEVEL: usize = 16;

/// Shared between a running operation and the thread that polls or cancels it.
/// Use a fresh one per operation.
#[derive(Debug, Default)]
pub struct Progress {
    done: AtomicU64,
    total: AtomicU64,
    found: AtomicU64,
    cancel: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    pub done: u64,
    pub total: u64,
    pub found: u64,
    pub cancelled: bool,
}

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }
    /// Asks the running operation to stop. Scans and rescans keep what they found so far;
    /// collecting a pointer map returns an error.
    pub fn cancel(&self) {
        self.cancel.store(true, Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Relaxed)
    }
    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            done: self.done.load(Relaxed),
            total: self.total.load(Relaxed),
            found: self.found.load(Relaxed),
            cancelled: self.is_cancelled(),
        }
    }
    fn start(&self, total: u64) {
        self.done.store(0, Relaxed);
        self.found.store(0, Relaxed);
        self.total.store(total, Relaxed);
    }
}

fn cancelled() -> hh_core::Error {
    hh_core::Error::Other("cancelled".into())
}
