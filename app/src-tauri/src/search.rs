//! Memory and disassembly search for the memory viewer, block allocation, pausing the whole
//! process, and trace files.
use std::path::Path;
use std::sync::atomic::Ordering::SeqCst;

use hh_core::{Addr, Prot};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::{App, R, hex_addr, lock, parse_addr, s};

/// Longest search pattern (bytes).
const MAX_PATTERN: usize = 4096;
/// Most matches one search returns.
const MAX_HITS: usize = 1000;
/// Bytes read per step while searching.
const CHUNK: usize = 1 << 20;
/// Largest range `disasm_search` decodes.
const MAX_DISASM_RANGE: u64 = 64 << 20;
/// Largest trace file read back.
const MAX_TRACE_FILE: u64 = 256 << 20;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SearchReq {
    pub start: String,
    /// Forward: matches below this; backward: matches at or above this. Empty = no bound.
    pub end: Option<String>,
    /// Hex bytes, `??` (or `?`) for any byte: `"48 8B ?? 05"`, `"488B05"`.
    pub pattern: String,
    pub backward: bool,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DisasmSearchReq {
    pub start: String,
    pub end: String,
    pub text: String,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmHit {
    pub addr: String,
    pub text: String,
}

/// `"48 8B ?? 05"` -> bytes with `None` for wildcards.
pub fn parse_pattern(p: &str) -> R<Vec<Option<u8>>> {
    let mut out = Vec::new();
    for tok in p.split_whitespace() {
        if tok.chars().all(|c| c == '?') {
            out.extend(std::iter::repeat_n(None, tok.len().div_ceil(2)));
            continue;
        }
        let t = tok.trim_start_matches("0x");
        if !t.len().is_multiple_of(2) {
            return Err(format!("bad byte {tok:?} in the pattern (two hex digits per byte)"));
        }
        for i in (0..t.len()).step_by(2) {
            let b = &t[i..i + 2];
            out.push(if b == "??" { None } else { Some(u8::from_str_radix(b, 16).map_err(|_| format!("bad byte {b:?} in the pattern"))?) });
        }
    }
    if out.is_empty() || out.iter().all(Option::is_none) {
        return Err("the pattern needs at least one byte that is not ??".into());
    }
    if out.len() > MAX_PATTERN {
        return Err(format!("the pattern is longer than {MAX_PATTERN} bytes"));
    }
    Ok(out)
}

/// Offsets in `hay` where `pat` matches.
fn matches(hay: &[u8], pat: &[Option<u8>]) -> impl Iterator<Item = usize> {
    // Anchor on the first fixed byte so most positions cost one compare.
    let (k, first) = pat.iter().enumerate().find_map(|(i, b)| b.map(|b| (i, b))).unwrap_or((0, 0));
    (0..hay.len().saturating_sub(pat.len() - 1))
        .filter(move |&i| hay[i + k] == first && pat.iter().zip(&hay[i..]).all(|(p, h)| p.is_none_or(|p| p == *h)))
}

impl App {
    /// Matches of a byte pattern in readable memory, from `start` forward (ascending) or
    /// below it (descending, `backward`).
    pub fn mem_search(&self, req: &SearchReq) -> R<Vec<String>> {
        let pat = parse_pattern(&req.pattern)?;
        let limit = req.limit.unwrap_or(1).clamp(1, MAX_HITS);
        let start = parse_addr(&req.start)?;
        let end = req.end.as_deref().filter(|e| !e.trim().is_empty()).map(parse_addr).transpose()?;
        let sess = self.session()?;
        let p = sess.proc.clone();
        let (lo, hi) = if req.backward { (end.unwrap_or(0), start) } else { (start, end.unwrap_or(u64::MAX)) };
        // (read up to, accept from, accept below): a match must start inside lo..hi but may run past hi.
        let n = pat.len();
        let mut regions: Vec<(Addr, Addr, Addr)> = p
            .regions()
            .map_err(s)?
            .into_iter()
            .filter(|r| r.prot.r)
            .map(|r| {
                let end = r.start.saturating_add(r.size);
                (end.min(hi.saturating_add(n as u64 - 1)), r.start.max(lo), end.min(hi))
            })
            .filter(|(_, a, b)| a < b)
            .collect();
        if req.backward {
            regions.reverse();
        }
        let mut hits = Vec::new();
        let mut buf = vec![0u8; CHUNK + n];
        for (re, a, b) in regions {
            // Chunks overlap by the pattern length so no match is split; backward walks them
            // from the region's end.
            let steps = ((b - a) as usize).div_ceil(CHUNK);
            for k in 0..steps {
                let i = if req.backward { steps - 1 - k } else { k };
                let at = a + (i * CHUNK) as u64;
                let want = ((re - at) as usize).min(CHUNK + n - 1);
                let got = match p.read(at, &mut buf[..want]) {
                    Ok(g) => g,
                    Err(hh_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionAborted => return Err(s(e)),
                    Err(_) => 0,
                };
                let below = (at + CHUNK as u64).min(b);
                let mut found: Vec<Addr> = matches(&buf[..got], &pat).map(|o| at + o as u64).filter(|&x| x < below).collect();
                if req.backward {
                    found.reverse();
                }
                for x in found {
                    hits.push(hex_addr(x));
                    if hits.len() >= limit {
                        return Ok(hits);
                    }
                }
            }
        }
        Ok(hits)
    }

    /// Instructions in `start..end` whose text contains `text` (case-insensitive), decoded
    /// linearly from `start`.
    pub fn disasm_search(&self, req: &DisasmSearchReq) -> R<Vec<DisasmHit>> {
        let needle = req.text.trim().to_lowercase();
        if needle.is_empty() {
            return Err("nothing to search for".into());
        }
        let (start, end) = (parse_addr(&req.start)?, parse_addr(&req.end)?);
        if end <= start {
            return Err("the range is empty".into());
        }
        if end - start > MAX_DISASM_RANGE {
            return Err(format!("the range is larger than {} MiB; search a module or a smaller range", MAX_DISASM_RANGE >> 20));
        }
        let limit = req.limit.unwrap_or(100).clamp(1, MAX_HITS);
        let sess = self.session()?;
        let syms = lock(&sess.syms).clone();
        let mut hits = Vec::new();
        let mut a = start;
        while a < end {
            let lines = hh_asm::disassemble(&*sess.proc, &syms, a, 4096).map_err(s)?;
            let Some(last) = lines.last() else { break };
            let next = last.addr + last.bytes.len().max(1) as u64;
            for l in &lines {
                if l.addr >= end {
                    break;
                }
                if l.text.to_lowercase().contains(&needle) {
                    hits.push(DisasmHit { addr: hex_addr(l.addr), text: l.text.clone() });
                    if hits.len() >= limit {
                        return Ok(hits);
                    }
                }
            }
            // Unreadable bytes decode one by one; skip to the next page instead.
            a = if lines.iter().all(|l| l.bytes.is_empty()) { (a | 0xfff) + 1 } else { next.max(a + 1) };
        }
        Ok(hits)
    }

    /// A new block in the target (page granular), e.g. for code caves.
    pub fn mem_alloc(&self, size: u64, prot: Prot) -> R<String> {
        if size == 0 || size > 1 << 32 {
            return Err("size must be between 1 byte and 4 GiB".into());
        }
        self.session()?.proc.alloc(size, prot, None).map(hex_addr).map_err(s)
    }

    pub fn mem_free(&self, addr: &str, size: u64) -> R<()> {
        self.session()?.proc.free(parse_addr(addr)?, size).map_err(s)
    }

    /// Suspends (or resumes) every thread of the target. Not while the debugger is attached
    /// (it stops the process itself: Break / Continue).
    pub fn process_pause(&self, pause: bool) -> R<()> {
        let sess = self.session()?;
        if pause && lock(&sess.dbg).is_some() {
            return Err("the debugger is attached: use Break (Shift F9) and Continue (F9) instead".into());
        }
        if pause { sess.raw.suspend() } else { sess.raw.resume() }.map_err(s)?;
        sess.paused.store(pause, SeqCst);
        Ok(())
    }

    /// Writes a trace (whatever the UI keeps of it) as JSON.
    pub fn trace_save(&self, path: &str, trace: &Value) -> R<()> {
        let t = serde_json::to_string(&serde_json::json!({ "heaphook_trace": 1, "trace": trace })).map_err(s)?;
        std::fs::write(path, t).map_err(|e| format!("{path}: {e}"))
    }

    /// A trace saved by `trace_save`.
    pub fn trace_load(&self, path: &str) -> R<Value> {
        let b = crate::table::read_capped(Path::new(path), MAX_TRACE_FILE)?;
        let mut v: Value = serde_json::from_slice(&b).map_err(|e| format!("{path}: not a HeapHook trace: {e}"))?;
        if v.get("heaphook_trace").and_then(Value::as_u64) != Some(1) {
            return Err(format!("{path}: not a HeapHook trace file"));
        }
        Ok(v["trace"].take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(parse_pattern("48 8B ?? 05").unwrap(), vec![Some(0x48), Some(0x8b), None, Some(5)]);
        assert_eq!(parse_pattern("488B05 ?").unwrap(), vec![Some(0x48), Some(0x8b), Some(5), None]);
        assert!(parse_pattern("?? ??").is_err());
        assert!(parse_pattern("4").is_err());
        assert!(parse_pattern("zz").is_err());
        let hay = [1, 2, 0x48, 0x8b, 7, 5, 0x48, 0x8b, 9, 5, 0x48];
        assert_eq!(matches(&hay, &parse_pattern("48 8B ?? 05").unwrap()).collect::<Vec<_>>(), [2, 6]);
        assert_eq!(matches(&hay, &parse_pattern("?? 8B").unwrap()).collect::<Vec<_>>(), [2, 6]);
    }
}
