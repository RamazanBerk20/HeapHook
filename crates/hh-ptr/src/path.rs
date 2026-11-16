//! Pointer paths: resolving, CE-style text, cheat-table export.
use std::fmt;
use std::str::FromStr;

use hh_core::{Addr, Error, Module, Process, Region, Result};
use serde::{Deserialize, Serialize};

/// `[[[base]+o1]+o2]+o3` where base is `module + base_offset`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PointerPath {
    /// Module name, `THREADSTACK<n>` (offset counts from the stack's top), or `None` when
    /// `base_offset` is an absolute address.
    pub module: Option<String>,
    pub base_offset: i64,
    /// In the order they are applied.
    pub offsets: Vec<i64>,
}

/// `THREADSTACK3` -> 3.
pub(crate) fn stack_index(name: &str) -> Option<usize> {
    let head = name.get(..11)?;
    head.eq_ignore_ascii_case("THREADSTACK")
        .then(|| name[11..].parse().ok())?
}

pub(crate) fn is_stack(r: &Region) -> bool {
    r.path.as_deref().is_some_and(|p| p.starts_with("[stack"))
}

/// Where each named base lives in one address space (a process or a pointer map).
pub(crate) struct Bases {
    modules: Vec<(String, Addr)>,
    stacks: Vec<Addr>,
}

impl Bases {
    pub fn new(modules: &[Module], regions: &[Region]) -> Self {
        Bases {
            modules: modules
                .iter()
                .map(|m| (m.name.to_ascii_lowercase(), m.base))
                .collect(),
            stacks: regions
                .iter()
                .filter(|r| is_stack(r))
                .map(|r| r.start.saturating_add(r.size))
                .collect(),
        }
    }
    pub fn of_process(p: &dyn Process) -> Result<Self> {
        Ok(Self::new(&p.modules()?, &p.regions()?))
    }
    /// Address a base name stands for; `None` name = absolute (0).
    pub fn addr_of(&self, name: Option<&str>) -> Option<Addr> {
        let Some(name) = name else { return Some(0) };
        if let Some(i) = stack_index(name) {
            return self.stacks.get(i).copied();
        }
        let lower = name.to_ascii_lowercase();
        self.modules.iter().find(|m| m.0 == lower).map(|m| m.1)
    }
}

/// Follows `offsets` from `base`, reading pointers with `read`.
pub(crate) fn walk(
    base: Addr,
    offsets: &[i64],
    mut read: impl FnMut(Addr) -> Option<Addr>,
) -> Option<Addr> {
    offsets
        .iter()
        .try_fold(base, |a, &o| Some(read(a)?.wrapping_add_signed(o)))
}

/// Resolves a path to its current address in a live process.
pub fn resolve(p: &dyn Process, path: &PointerPath) -> Result<Addr> {
    let bases = Bases::of_process(p)?;
    let base = bases
        .addr_of(path.module.as_deref())
        .ok_or_else(|| Error::Other(format!("unknown base {:?}", path.module)))?
        .wrapping_add_signed(path.base_offset);
    let mut a = base;
    for &o in &path.offsets {
        a = p.read_ptr(a)?.wrapping_add_signed(o);
    }
    Ok(a)
}

fn signed_hex(o: i64, width: usize) -> String {
    let sign = if o < 0 { '-' } else { '+' };
    format!("{sign}{:0width$X}", o.unsigned_abs())
}

impl PointerPath {
    /// The base as Cheat Engine writes it: `"game.exe"+001A2B3C`, `THREADSTACK0-00000128`,
    /// or a bare hex address.
    pub fn base_text(&self) -> String {
        match &self.module {
            None => format!("{:X}", self.base_offset as u64),
            Some(m) if stack_index(m).is_some() => {
                format!("{m}{}", signed_hex(self.base_offset, 8))
            }
            Some(m) => format!("\"{m}\"{}", signed_hex(self.base_offset, 8)),
        }
    }
}

/// `[[["game.exe"+001A2B3C]+10]+18]+8` — the same form `resolve_address` accepts.
impl fmt::Display for PointerPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&"[".repeat(self.offsets.len()))?;
        f.write_str(&self.base_text())?;
        for &o in &self.offsets {
            write!(f, "]{}", signed_hex(o, 0))?;
        }
        Ok(())
    }
}

fn bad(s: &str) -> Error {
    Error::Parse(format!("bad pointer path: {s}"))
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// `+1A`, `-8`, `1A`.
fn parse_signed(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, mag) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let v = i64::try_from(parse_hex(mag)?).ok()?;
    Some(if neg { -v } else { v })
}

fn parse_base(s: &str) -> Option<(Option<String>, i64)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        let tail = rest[end + 1..].trim();
        let off = if tail.is_empty() {
            0
        } else {
            parse_signed(tail)?
        };
        return Some((Some(rest[..end].to_owned()), off));
    }
    // Unquoted `name+off`: split at the last sign whose right side is a number.
    let (name, off) = match s.rfind(['+', '-']) {
        Some(i) if i > 0 && parse_signed(&s[i..]).is_some() => (&s[..i], parse_signed(&s[i..])?),
        _ => (s, 0),
    };
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    match parse_hex(name) {
        Some(a) => Some((None, (a as i64).wrapping_add(off))),
        None => Some((Some(name.to_owned()), off)),
    }
}

impl FromStr for PointerPath {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let t = s.trim();
        let n = t.bytes().take_while(|&b| b == b'[').count();
        let parts: Vec<&str> = t[n..].split(']').collect();
        if parts.len() != n + 1 {
            return Err(bad(s));
        }
        let (module, base_offset) = parse_base(parts[0]).ok_or_else(|| bad(s))?;
        let offsets = parts[1..]
            .iter()
            .map(|p| {
                let p = p.trim();
                (p.starts_with(['+', '-']))
                    .then(|| parse_signed(p))
                    .flatten()
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| bad(s))?;
        Ok(PointerPath {
            module,
            base_offset,
            offsets,
        })
    }
}

/// A cheat-table entry (shape from docs/CONTRACT.md) for this path.
pub fn to_table_entry(
    path: &PointerPath,
    id: u64,
    description: &str,
    vtype: &str,
) -> serde_json::Value {
    let offsets: Vec<String> = path
        .offsets
        .iter()
        .map(|&o| signed_hex(o, 0).trim_start_matches('+').to_owned())
        .collect();
    serde_json::json!({
        "id": id, "description": description, "addr": path.base_text(), "offsets": offsets,
        "vtype": vtype, "len": 0, "utf16": false, "signed": false, "hex": false,
        "frozen": false, "freeze_mode": "exact", "color": null, "dropdown": null,
        "hotkeys": [], "script": null, "children": [],
    })
}
