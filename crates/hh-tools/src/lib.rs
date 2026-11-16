//! HeapHook analysis tools: the engine behind Cheat Engine's secondary windows, as plain
//! library calls with serde-serializable inputs and outputs (addresses travel as `"0x..."`
//! strings, see [`hexaddr`]).
//!
//! - [`structure`]: structure dissector (definitions with bit fields and arrays, auto-guess
//!   with RTTI / symbol naming and an override hook, multi-address compare, lock and
//!   changed-field highlighting, structure spider, `.CT` `<Structures>` import/export, C / C#
//!   definitions, cheat-table entries with pointer paths).
//! - [`dissect`]: "Dissect code" (functions, cross references, referenced strings and
//!   functions, code caves) over whole modules, parallel, with paged queries; incremental
//!   modules, a code filter over caller-recorded execution sets, `.hhdis` save/load.
//! - [`memory`]: region view and statistics, save/load memory to a file (with a load plan to
//!   confirm first), search in saved files, fill, copy, snapshots, diffs and a page change
//!   map, "find what points to X".
//! - [`signature`]: unique AOB signatures with wildcarded relocatable operands.
//! - [`headers`]: PE / ELF header summaries.
//! - [`codelist`]: Cheat Engine's code list ("advanced options"): NOP / restore with
//!   original-byte verification.
//!
//! Long operations take a [`Progress`] that another thread can poll or cancel.
//! Files, cheat tables and target memory are untrusted: every format has caps and is
//! validated on load. Remote targets pass `local_files = false` where module files would be
//! read (headers, dissection, structure guessing) so a same-named local file is never parsed.
//! Skipped (need kernel support or a tracer): Ultimap 1/2, Intel PT, recording executed code.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use hh_core::{Addr, Error, Process, Region};
use serde::{Deserialize, Serialize};

pub mod codelist;
pub mod dissect;
pub mod headers;
pub mod memory;
pub mod signature;
pub mod structure;

pub use hh_scan::hexaddr;

/// Shared between a running operation and the thread that polls or cancels it.
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
    /// Asks the running operation to stop; it returns `Err(Other("cancelled"))`.
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
    pub(crate) fn start(&self, total: u64) {
        self.done.store(0, Relaxed);
        self.found.store(0, Relaxed);
        self.total.store(total, Relaxed);
    }
    pub(crate) fn add(&self, n: u64) {
        self.done.fetch_add(n, Relaxed);
    }
    pub(crate) fn add_found(&self, n: u64) {
        self.found.fetch_add(n, Relaxed);
    }
    pub(crate) fn check(&self) -> hh_core::Result<()> {
        if self.is_cancelled() {
            Err(Error::Other("cancelled".into()))
        } else {
            Ok(())
        }
    }
}

/// Serde helper for `Vec<Addr>` as hex strings.
pub mod hexvec {
    use hh_core::Addr;
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    #[derive(Deserialize)]
    struct H(#[serde(with = "crate::hexaddr")] Addr);

    pub fn serialize<S: Serializer>(v: &[Addr], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for a in v {
            seq.serialize_element(&format!("{a:#x}"))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Addr>, D::Error> {
        Ok(Vec::<H>::deserialize(d)?.into_iter().map(|h| h.0).collect())
    }
}

/// Serde helper: bytes as a hex string `"48 8B 05"`.
pub mod hexbytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn to_string(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
    }
    pub fn parse(s: &str) -> Option<Vec<u8>> {
        let h: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if !h.len().is_multiple_of(2) {
            return None;
        }
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok())
            .collect()
    }
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_string(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).ok_or_else(|| D::Error::custom(format!("bad hex bytes {s:?}")))
    }
}

/// Sorted readable address ranges, for "is this a valid pointer" checks.
#[derive(Debug, Clone, Default)]
pub(crate) struct Readable(Vec<(Addr, Addr)>);

impl Readable {
    pub fn of(p: &dyn Process) -> hh_core::Result<Self> {
        Ok(Self::from_regions(&p.regions()?))
    }
    pub fn from_regions(regions: &[Region]) -> Self {
        let mut v: Vec<_> = regions
            .iter()
            .filter(|r| r.prot.r)
            .map(|r| (r.start, r.start.saturating_add(r.size)))
            .collect();
        v.sort_unstable();
        Readable(v)
    }
    pub fn contains(&self, a: Addr) -> bool {
        let i = self.0.partition_point(|r| r.0 <= a);
        i > 0 && a < self.0[i - 1].1
    }
}

/// Reads up to `len` bytes; unreadable tails are cut off.
pub(crate) fn read_some(p: &dyn hh_core::Memory, addr: Addr, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    let n = p.read(addr, &mut b).unwrap_or(0);
    b.truncate(n);
    b
}

/// Text for an XML attribute value or element body. Markup characters and the whitespace an
/// attribute would normalise away become references; characters XML 1.0 cannot carry at all
/// (C0 controls other than tab / LF / CR, U+FFFE, U+FFFF) become U+FFFD, so the output always
/// parses back.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            '\t' => o.push_str("&#9;"),
            '\n' => o.push_str("&#10;"),
            '\r' => o.push_str("&#13;"),
            '\u{0}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}' => o.push('\u{fffd}'),
            c => o.push(c),
        }
    }
    o
}

/// Largest single buffer a request may ask for (bad input fails instead of allocating).
pub(crate) const MAX_BUF: u64 = 1 << 30;

pub(crate) fn check_len(len: u64) -> hh_core::Result<usize> {
    if len > MAX_BUF {
        return Err(Error::Other(format!("length {len:#x} too large")));
    }
    Ok(len as usize)
}
