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
//!   The JSON header may carry `stacks` (thread stack ranges, `THREADSTACK<n>` order).
//! - result file (v2, written since 1.0): `b"HHPTRS02"`, u32 header length, JSON
//!   [`ResultHeader`], records, index, trailer. A record is a varint base (0 = absolute
//!   address, else base index + 1), zigzag varint base offset, u8 level, then `level` zigzag
//!   varint offsets. The index is one u64 per 4096 records: the byte offset of record
//!   4096·k from the end of the header. The trailer is u64 record count, u64 index offset
//!   (also from the end of the header).
//! - result file (v1, read only): `b"HHPTRS01"`, u32 header length, JSON header, then
//!   fixed-size records: u32 base index (`u32::MAX` = absolute address), i64 base offset, u8
//!   level, `max_level` × i32 offsets (unused ones zero).
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

mod map;
mod path;
mod results;
mod scan;
mod script;
#[cfg(test)]
mod tests;

pub use map::{CollectOptions, PointerMap};
pub use path::{PointerPath, resolve, resolve_ex, thread_stacks, to_table_entry};
pub use script::{PointerScanJob, scan_process};
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
    paused: AtomicBool,
    /// (paused since, total time paused before that).
    pause_time: Mutex<(Option<Instant>, Duration)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    pub done: u64,
    pub total: u64,
    pub found: u64,
    pub cancelled: bool,
    #[serde(default)]
    pub paused: bool,
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
    /// Holds the running operation (collect, scan, rescan) at its next checkpoint until
    /// [`Progress::resume`]; cancel still ends it. Paused time does not count against a
    /// scan's time limit.
    pub fn pause(&self) {
        let mut t = self.pause_time.lock().unwrap_or_else(|e| e.into_inner());
        t.0.get_or_insert_with(Instant::now);
        self.paused.store(true, Relaxed);
    }
    pub fn resume(&self) {
        let mut t = self.pause_time.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(since) = t.0.take() {
            t.1 += since.elapsed();
        }
        self.paused.store(false, Relaxed);
    }
    pub fn is_paused(&self) -> bool {
        self.paused.load(Relaxed)
    }
    /// Total time spent paused.
    pub fn paused_for(&self) -> Duration {
        let t = self.pause_time.lock().unwrap_or_else(|e| e.into_inner());
        t.1 + t.0.map_or(Duration::ZERO, |s| s.elapsed())
    }
    pub(crate) fn wait_if_paused(&self) {
        while self.is_paused() && !self.is_cancelled() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            done: self.done.load(Relaxed),
            total: self.total.load(Relaxed),
            found: self.found.load(Relaxed),
            cancelled: self.is_cancelled(),
            paused: self.is_paused(),
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
