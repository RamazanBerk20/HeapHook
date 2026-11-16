//! Structure dissector: named structure definitions evaluated against memory, auto-guessed
//! layouts, pointer fields expanded on demand into child structures, side-by-side compare of
//! address groups, "find fields that match/differ", a structure spider, HeapHook JSON and
//! Cheat Engine `<Structures>` XML import/export, and cheat-table entries from fields.
//!
//! Structures refer to each other by name (`Element.child`), like Cheat Engine's global
//! structure list, so a set of definitions is a plain `Vec<Structure>`.
use std::collections::HashSet;

use hh_core::{Addr, Error, Process, Result};
use hh_scan::{Fmt, VType, format_value};
use serde::{Deserialize, Serialize};

use crate::{Progress, Readable, check_len, hexaddr, read_some};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElemType {
    Byte,
    #[serde(rename = "2bytes")]
    Bytes2,
    #[serde(rename = "4bytes")]
    Bytes4,
    #[serde(rename = "8bytes")]
    Bytes8,
    Float,
    Double,
    String,
    Aob,
    /// Pointer (target width); `child` names the structure it points to.
    Pointer,
    /// Structure embedded inline; `child` names it.
    Struct,
}

impl ElemType {
    fn vtype(self) -> Option<VType> {
        Some(match self {
            ElemType::Byte => VType::Byte,
            ElemType::Bytes2 => VType::Bytes2,
            ElemType::Bytes4 => VType::Bytes4,
            ElemType::Bytes8 => VType::Bytes8,
            ElemType::Float => VType::Float,
            ElemType::Double => VType::Double,
            ElemType::String => VType::String,
            ElemType::Aob => VType::Aob,
            ElemType::Pointer | ElemType::Struct => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Element {
    pub offset: u64,
    #[serde(default)]
    pub description: String,
    pub vtype: ElemType,
    /// Byte size. Fixed types ignore it; strings and aobs need it (0 = 16 bytes); for a
    /// nested structure 0 means the child's own size.
    #[serde(default)]
    pub size: usize,
    #[serde(default)]
    pub hex: bool,
    #[serde(default)]
    pub signed: bool,
    #[serde(default)]
    pub utf16: bool,
    /// Structure name: the pointee of a pointer (expandable), or the inline struct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child: Option<String>,
}

impl Element {
    pub fn new(offset: u64, vtype: ElemType) -> Self {
        Element {
            offset,
            description: String::new(),
            vtype,
            size: 0,
            hex: false,
            signed: false,
            utf16: false,
            child: None,
        }
    }
    fn fixed_size(&self, ptr: usize) -> usize {
        match self.vtype {
            ElemType::Byte => 1,
            ElemType::Bytes2 => 2,
            ElemType::Bytes4 | ElemType::Float => 4,
            ElemType::Bytes8 | ElemType::Double => 8,
            ElemType::Pointer => ptr,
            ElemType::String | ElemType::Aob | ElemType::Struct => {
                if self.size == 0 {
                    16
                } else {
                    self.size
                }
            }
        }
    }
    fn fmt(&self) -> Fmt {
        let chars = if self.utf16 { self.size / 2 } else { self.size };
        Fmt {
            len: Some(if self.vtype == ElemType::String {
                chars
            } else {
                self.size
            })
            .filter(|&n| n > 0),
            signed: self.signed,
            hex: self.hex,
            utf16: self.utf16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Structure {
    pub name: String,
    #[serde(default)]
    pub elements: Vec<Element>,
}

fn lookup<'a>(structs: &'a [Structure], name: &str) -> Result<&'a Structure> {
    structs
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| Error::Other(format!("no structure named {name:?}")))
}

/// Looks up a structure for evaluation, refusing ones that embed themselves (directly or
/// through other inline structures), which would have no finite size.
fn find<'a>(structs: &'a [Structure], name: &str) -> Result<&'a Structure> {
    fn visit<'a>(structs: &'a [Structure], name: &'a str, stack: &mut Vec<&'a str>) -> Result<()> {
        if stack.contains(&name) {
            return Err(Error::Other(format!("structure {name:?} embeds itself")));
        }
        let Ok(s) = lookup(structs, name) else { return Ok(()) };
        stack.push(name);
        for e in s.elements.iter().filter(|e| e.vtype == ElemType::Struct) {
            if let Some(c) = &e.child {
                visit(structs, c, stack)?;
            }
        }
        stack.pop();
        Ok(())
    }
    let s = lookup(structs, name)?;
    visit(structs, name, &mut Vec::new())?;
    Ok(s)
}

const MAX_NEST: usize = 16;

/// Byte size of an element; nested structures use the child's size.
fn elem_size(structs: &[Structure], e: &Element, ptr: usize, depth: usize) -> usize {
    if e.vtype == ElemType::Struct && e.size == 0 {
        return e
            .child
            .as_deref()
            .and_then(|c| lookup(structs, c).ok())
            .map_or(0, |s| struct_size_at(structs, s, ptr, depth + 1));
    }
    e.fixed_size(ptr)
}

fn struct_size_at(structs: &[Structure], s: &Structure, ptr: usize, depth: usize) -> usize {
    if depth > MAX_NEST {
        return 0;
    }
    s.elements
        .iter()
        .map(|e| (e.offset as usize).saturating_add(elem_size(structs, e, ptr, depth)))
        .max()
        .unwrap_or(0)
}

/// Size of a structure: the end of its last element.
pub fn struct_size(structs: &[Structure], name: &str, ptr_size: usize) -> Result<usize> {
    Ok(struct_size_at(structs, find(structs, name)?, ptr_size, 0))
}

// ------------------------------------------------------------------------------ evaluate

/// One evaluated element.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldValue {
    /// Offset from the evaluated structure's base (nested offsets are summed).
    pub offset: u64,
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub description: String,
    pub vtype: ElemType,
    pub size: usize,
    /// Formatted value; `None` when unreadable (and for nested structures).
    pub value: Option<String>,
    /// Pointer fields: the pointer value when it points into readable memory.
    #[serde(with = "hexaddr::opt")]
    pub target: Option<Addr>,
    pub child: Option<String>,
    /// Structure that defines this element and its index there (for [`expand_pointer`]).
    pub owner: String,
    pub index: usize,
    /// Fields of a nested structure.
    pub children: Vec<FieldValue>,
}

/// Reads every element of structure `name` at `base`.
pub fn evaluate(
    p: &dyn Process,
    structs: &[Structure],
    name: &str,
    base: Addr,
) -> Result<Vec<FieldValue>> {
    let s = find(structs, name)?;
    let ptr = p.pointer_size();
    let len = check_len(struct_size_at(structs, s, ptr, 0) as u64)?;
    let buf = read_some(p, base, len);
    let readable = Readable::of(p)?;
    Ok(eval_in(structs, s, base, 0, &buf, ptr, &readable, 0))
}

#[allow(clippy::too_many_arguments)]
fn eval_in(
    structs: &[Structure],
    s: &Structure,
    base: Addr,
    rel: u64,
    buf: &[u8],
    ptr: usize,
    readable: &Readable,
    depth: usize,
) -> Vec<FieldValue> {
    s.elements
        .iter()
        .enumerate()
        .map(|(index, e)| {
            let size = elem_size(structs, e, ptr, depth);
            let off = rel.wrapping_add(e.offset);
            let raw = buf.get(off as usize..(off as usize).saturating_add(size));
            let mut fv = FieldValue {
                offset: off,
                addr: base.wrapping_add(off),
                description: e.description.clone(),
                vtype: e.vtype,
                size,
                value: None,
                target: None,
                child: e.child.clone(),
                owner: s.name.clone(),
                index,
                children: Vec::new(),
            };
            match (e.vtype, raw) {
                (ElemType::Struct, _) if depth < MAX_NEST => {
                    if let Some(c) = e.child.as_deref().and_then(|c| lookup(structs, c).ok()) {
                        fv.children = eval_in(structs, c, base, off, buf, ptr, readable, depth + 1);
                    }
                }
                (ElemType::Pointer, Some(r)) => {
                    let v = le(r);
                    fv.value = Some(format!("{v:X}"));
                    fv.target = readable.contains(v).then_some(v);
                }
                (t, Some(r)) => fv.value = t.vtype().map(|vt| format_value(vt, r, &e.fmt())),
                _ => {}
            }
            fv
        })
        .collect()
}

fn le(b: &[u8]) -> u64 {
    let mut v = [0u8; 8];
    let n = b.len().min(8);
    v[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(v)
}

/// Expands the pointer element `index` of structure `owner` whose field lives at
/// `field_addr`: if the element has no child structure yet, one is auto-guessed at the
/// pointer target (`guess_size` bytes), added to `structs` and linked. Returns the child
/// structure name and the target address, ready for [`evaluate`].
pub fn expand_pointer(
    p: &dyn Process,
    structs: &mut Vec<Structure>,
    owner: &str,
    index: usize,
    field_addr: Addr,
    guess_size: usize,
) -> Result<(String, Addr)> {
    let e = lookup(structs, owner)?
        .elements
        .get(index)
        .ok_or_else(|| Error::Other(format!("{owner} has no element {index}")))?
        .clone();
    if e.vtype != ElemType::Pointer {
        return Err(Error::Other("element is not a pointer".into()));
    }
    let target = p.read_ptr(field_addr)?;
    if let Some(c) = e.child.filter(|c| structs.iter().any(|s| &s.name == c)) {
        return Ok((c, target));
    }
    let mut name = format!("{owner}_{:X}", e.offset);
    while structs.iter().any(|s| s.name == name) {
        name.push('_');
    }
    let child = guess_structure(p, &name, target, guess_size)?;
    structs.push(child);
    if let Some(s) = structs.iter_mut().find(|s| s.name == owner) {
        s.elements[index].child = Some(name.clone());
    }
    Ok((name, target))
}

// --------------------------------------------------------------------------------- guess

fn plausible_float(bits: u32) -> bool {
    let f = f32::from_bits(bits);
    f.is_finite() && (1e-4..=1e7).contains(&f.abs())
}

fn plausible_double(bits: u64) -> bool {
    let d = f64::from_bits(bits);
    d.is_finite() && (1e-6..=1e9).contains(&d.abs())
}

fn printable(c: u8) -> bool {
    c.is_ascii_graphic() || c == b' '
}

const MIN_STR: usize = 4;

/// Guesses an element layout for `size` bytes at `addr`, in the spirit of Cheat Engine's
/// auto-guess: pointer-aligned values into readable memory are pointers, then ASCII and
/// UTF-16 strings, doubles, floats, pairs of small 16-bit values, else 4-byte integers
/// (hex when they look like flags or handles).
pub fn guess_structure(p: &dyn Process, name: &str, addr: Addr, size: usize) -> Result<Structure> {
    let b = read_some(p, addr, check_len(size as u64)?);
    if b.is_empty() {
        return Err(Error::NoAccess { addr });
    }
    Ok(Structure {
        name: name.into(),
        elements: guess_elements(&b, p.pointer_size(), &Readable::of(p)?),
    })
}

pub(crate) fn guess_elements(b: &[u8], ptr: usize, readable: &Readable) -> Vec<Element> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let push = |out: &mut Vec<Element>, off: usize, t: ElemType, f: &dyn Fn(&mut Element)| {
        let mut e = Element::new(off as u64, t);
        f(&mut e);
        out.push(e);
    };
    while off + 4 <= b.len() {
        let rest = &b[off..];
        if off.is_multiple_of(ptr) && rest.len() >= ptr {
            let v = le(&rest[..ptr]);
            if v != 0 && readable.contains(v) {
                push(&mut out, off, ElemType::Pointer, &|e| e.hex = true);
                off += ptr;
                continue;
            }
        }
        let ascii = rest.iter().take_while(|&&c| printable(c)).count();
        if ascii >= MIN_STR {
            let n = (ascii + 1).min(rest.len()).next_multiple_of(4).min(rest.len());
            push(&mut out, off, ElemType::String, &|e| e.size = n);
            off += n;
            continue;
        }
        let wide = rest
            .chunks_exact(2)
            .take_while(|c| c[1] == 0 && printable(c[0]))
            .count();
        if wide >= MIN_STR {
            let n = ((wide + 1) * 2).next_multiple_of(4).min(rest.len());
            push(&mut out, off, ElemType::String, &|e| {
                e.size = n;
                e.utf16 = true
            });
            off += n;
            continue;
        }
        let d = le(&rest[..4]) as u32;
        let hi = rest.get(4..8).map(|h| le(h) as u32);
        if off.is_multiple_of(8)
            && let Some(hi) = hi
            && !(plausible_float(d) && plausible_float(hi))
            // A small integer in the low half is an int next to something, not a double.
            && !(d != 0 && d < 0x10000)
            && plausible_double(le(&rest[..8]))
        {
            push(&mut out, off, ElemType::Double, &|_| {});
            off += 8;
            continue;
        }
        if plausible_float(d) {
            push(&mut out, off, ElemType::Float, &|_| {});
        } else if d >> 16 != 0 && (d >> 16) < 0x1000 && (d & 0xffff) != 0 && (d & 0xffff) < 0x1000
        {
            push(&mut out, off, ElemType::Bytes2, &|_| {});
            push(&mut out, off + 2, ElemType::Bytes2, &|_| {});
        } else {
            let signed = (d as i32) < 0 && (d as i32) > -0x10000;
            push(&mut out, off, ElemType::Bytes4, &|e| {
                e.signed = signed;
                e.hex = !signed && d > 0x00ff_ffff;
            });
        }
        off += 4;
    }
    out
}

// ------------------------------------------------------------------------------- compare

/// How the values at one field compare across address groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Same everywhere.
    AllEqual,
    /// Equal within every group and different between every pair of groups (the
    /// interesting kind Cheat Engine highlights).
    GroupsDiffer,
    /// Anything else.
    Mixed,
    /// Some address could not be read.
    Unreadable,
}

/// `groups[g][i]` = raw bytes at address i of group g.
pub fn classify(groups: &[Vec<Option<&[u8]>>]) -> Class {
    let mut reps: Vec<&[u8]> = Vec::new();
    for g in groups {
        let Some(first) = g.first() else { continue };
        if g.iter().any(Option::is_none) {
            return Class::Unreadable;
        }
        let first = first.unwrap_or_default();
        if g.iter().any(|v| *v != Some(first)) {
            return Class::Mixed;
        }
        reps.push(first);
    }
    if reps.windows(2).all(|w| w[0] == w[1]) {
        return Class::AllEqual;
    }
    let distinct = reps
        .iter()
        .enumerate()
        .all(|(i, a)| reps[i + 1..].iter().all(|b| a != b));
    if distinct { Class::GroupsDiffer } else { Class::Mixed }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompareRow {
    pub offset: u64,
    pub description: String,
    pub vtype: ElemType,
    pub owner: String,
    pub index: usize,
    /// `values[group][address]`, formatted like [`evaluate`].
    pub values: Vec<Vec<Option<String>>>,
    pub class: Class,
}

/// Evaluates structure `name` at every address of every group (Cheat Engine's multi-column
/// view) and classifies each leaf field. Nested structures are flattened.
pub fn compare(
    p: &dyn Process,
    structs: &[Structure],
    name: &str,
    groups: &[Vec<Addr>],
) -> Result<Vec<CompareRow>> {
    let cols: Vec<Vec<Vec<FieldValue>>> = groups
        .iter()
        .map(|g| g.iter().map(|&a| evaluate(p, structs, name, a)).collect())
        .collect::<Result<_>>()?;
    let ptr = p.pointer_size();
    let len = check_len(struct_size(structs, name, ptr)? as u64)?;
    let bufs: Vec<Vec<Vec<u8>>> = groups
        .iter()
        .map(|g| g.iter().map(|&a| read_some(p, a, len)).collect())
        .collect();
    let Some(proto) = cols.iter().flatten().next() else {
        return Ok(Vec::new());
    };
    let leaves = flatten(proto);
    let flat: Vec<Vec<Vec<&FieldValue>>> = cols
        .iter()
        .map(|g| g.iter().map(|c| flatten(c)).collect())
        .collect();
    Ok(leaves
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let range = l.offset as usize..(l.offset as usize).saturating_add(l.size);
            let raw: Vec<Vec<Option<&[u8]>>> = bufs
                .iter()
                .map(|g| g.iter().map(|b| b.get(range.clone())).collect())
                .collect();
            CompareRow {
                offset: l.offset,
                description: l.description.clone(),
                vtype: l.vtype,
                owner: l.owner.clone(),
                index: l.index,
                values: flat
                    .iter()
                    .map(|g| g.iter().map(|c| c[i].value.clone()).collect())
                    .collect(),
                class: classify(&raw),
            }
        })
        .collect())
}

fn flatten(f: &[FieldValue]) -> Vec<&FieldValue> {
    let mut out = Vec::new();
    for v in f {
        if v.vtype == ElemType::Struct {
            out.extend(flatten(&v.children));
        } else {
            out.push(v);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldHit {
    pub offset: u64,
    pub class: Class,
    /// `values[group][address]` as hex bytes.
    pub values: Vec<Vec<Option<String>>>,
}

/// "Find fields that match / differ": without a structure definition, compares `width`-byte
/// values at every `width`-aligned offset in `[0, size)` and returns those of class `want`.
pub fn find_fields(
    p: &dyn Process,
    groups: &[Vec<Addr>],
    size: usize,
    width: usize,
    want: Class,
) -> Result<Vec<FieldHit>> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(Error::Other("width must be 1, 2, 4 or 8".into()));
    }
    let size = check_len(size as u64)?;
    let bufs: Vec<Vec<Vec<u8>>> = groups
        .iter()
        .map(|g| g.iter().map(|&a| read_some(p, a, size)).collect())
        .collect();
    let mut out = Vec::new();
    for off in (0..size.saturating_sub(width - 1)).step_by(width) {
        let raw: Vec<Vec<Option<&[u8]>>> = bufs
            .iter()
            .map(|g| g.iter().map(|b| b.get(off..off + width)).collect())
            .collect();
        let class = classify(&raw);
        if class == want {
            out.push(FieldHit {
                offset: off as u64,
                class,
                values: raw
                    .iter()
                    .map(|g| g.iter().map(|v| v.map(crate::hexbytes::to_string)).collect())
                    .collect(),
            });
        }
    }
    Ok(out)
}

// -------------------------------------------------------------------------------- spider

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SpiderOptions {
    /// Bytes scanned in each structure.
    pub size: usize,
    /// Pointer levels to follow (0 = only the given structures).
    pub max_depth: usize,
    /// Value width compared at every `width`-aligned offset.
    pub width: usize,
    pub max_results: usize,
}

impl Default for SpiderOptions {
    fn default() -> Self {
        SpiderOptions {
            size: 0x200,
            max_depth: 2,
            width: 4,
            max_results: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpiderHit {
    /// Offsets from the base, Cheat Engine pointer notation: the field is at
    /// `[[base+o0]+o1]+o2` for `path = [o0, o1, o2]` (one entry = the field offset itself).
    pub path: Vec<u64>,
    /// `values[group][address]` as hex bytes.
    pub values: Vec<Vec<String>>,
}

/// Structure spider: finds fields, following pointers up to `max_depth`, whose values are
/// equal within every group and differ between groups. Pointer slots that point into
/// readable memory for every address are followed rather than reported. Progress counts
/// structures visited; cancelling returns an error.
pub fn spider(
    p: &dyn Process,
    groups: &[Vec<Addr>],
    opts: &SpiderOptions,
    progress: &Progress,
) -> Result<Vec<SpiderHit>> {
    if !matches!(opts.width, 1 | 2 | 4 | 8) {
        return Err(Error::Other("width must be 1, 2, 4 or 8".into()));
    }
    check_len(opts.size as u64)?;
    let opts = &SpiderOptions { max_depth: opts.max_depth.min(MAX_NEST), ..opts.clone() };
    if groups.iter().all(Vec::is_empty) {
        return Ok(Vec::new());
    }
    progress.start(0);
    let mut s = Spider {
        p,
        opts,
        progress,
        readable: Readable::of(p)?,
        seen: HashSet::new(),
        out: Vec::new(),
    };
    s.walk(groups.to_vec(), &mut Vec::new(), 0)?;
    Ok(s.out)
}

struct Spider<'a> {
    p: &'a dyn Process,
    opts: &'a SpiderOptions,
    progress: &'a Progress,
    readable: Readable,
    seen: HashSet<Vec<Vec<Addr>>>,
    out: Vec<SpiderHit>,
}

impl Spider<'_> {
    fn walk(&mut self, addrs: Vec<Vec<Addr>>, path: &mut Vec<u64>, depth: usize) -> Result<()> {
        self.progress.check()?;
        if !self.seen.insert(addrs.clone()) {
            return Ok(());
        }
        self.progress.add(1);
        let ptr = self.p.pointer_size();
        let w = self.opts.width;
        let bufs: Vec<Vec<Vec<u8>>> = addrs
            .iter()
            .map(|g| g.iter().map(|&a| read_some(self.p, a, self.opts.size)).collect())
            .collect();
        let mut follow = Vec::new();
        let mut off = 0;
        while off + w.min(ptr) <= self.opts.size {
            // Pointer slots: follow when every address holds a readable pointer.
            if off % ptr == 0 {
                let ptrs: Option<Vec<Vec<Addr>>> = bufs
                    .iter()
                    .map(|g| {
                        g.iter()
                            .map(|b| {
                                let v = le(b.get(off..off + ptr)?);
                                (v != 0 && self.readable.contains(v)).then_some(v)
                            })
                            .collect()
                    })
                    .collect();
                if let Some(ptrs) = ptrs {
                    follow.push((off as u64, ptrs));
                    off += ptr;
                    continue;
                }
            }
            let raw: Vec<Vec<Option<&[u8]>>> = bufs
                .iter()
                .map(|g| g.iter().map(|b| b.get(off..off + w)).collect())
                .collect();
            if classify(&raw) == Class::GroupsDiffer {
                if self.out.len() >= self.opts.max_results {
                    return Ok(());
                }
                let mut hp = path.clone();
                hp.push(off as u64);
                self.out.push(SpiderHit {
                    path: hp,
                    values: raw
                        .iter()
                        .map(|g| g.iter().map(|v| crate::hexbytes::to_string(v.unwrap_or_default())).collect())
                        .collect(),
                });
                self.progress.add_found(1);
            }
            off += w;
        }
        if depth >= self.opts.max_depth {
            return Ok(());
        }
        for (off, ptrs) in follow {
            // Every column pointing at the same object tells nothing new.
            if ptrs.iter().flatten().all(|&a| a == ptrs[0].first().copied().unwrap_or(a)) {
                continue;
            }
            path.push(off);
            self.walk(ptrs, path, depth + 1)?;
            path.pop();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------- JSON / CT

/// HeapHook JSON: `{"structures": [...]}`.
pub fn to_json(structs: &[Structure]) -> String {
    serde_json::json!({ "structures": structs }).to_string()
}

/// Reads `{"structures": [...]}` or a bare array.
pub fn from_json(text: &str) -> Result<Vec<Structure>> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum In {
        Wrapped { structures: Vec<Structure> },
        Bare(Vec<Structure>),
    }
    match serde_json::from_str::<In>(text) {
        Ok(In::Wrapped { structures } | In::Bare(structures)) => Ok(structures),
        Err(e) => Err(Error::Parse(format!("structures JSON: {e}"))),
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            '\n' => o.push_str("&#10;"),
            c => o.push(c),
        }
    }
    o
}

fn ct_vartype(e: &Element) -> &'static str {
    match e.vtype {
        ElemType::Byte => "Byte",
        ElemType::Bytes2 => "2 Bytes",
        ElemType::Bytes4 => "4 Bytes",
        ElemType::Bytes8 => "8 Bytes",
        ElemType::Float => "Float",
        ElemType::Double => "Double",
        ElemType::String if e.utf16 => "Unicode String",
        ElemType::String => "String",
        ElemType::Aob | ElemType::Struct => "Array of Bytes",
        ElemType::Pointer => "Pointer",
    }
}

/// Cheat Engine `<Structures>` section. Inline nested structures, which Cheat Engine does not
/// have, are written as byte arrays of the same size tagged `HHNested="1"`.
pub fn to_ct_xml(structs: &[Structure], ptr_size: usize) -> String {
    let mut x = String::from("<Structures StructVersion=\"2\">\n");
    for s in structs {
        x += &format!(
            "  <Structure Name=\"{}\" AutoFill=\"0\" AutoCreate=\"1\" DefaultHex=\"0\" AutoDestroy=\"0\" DoNotSaveLocal=\"0\" RLECompression=\"1\" AutoCreateStructsize=\"4096\">\n    <Elements>\n",
            esc(&s.name)
        );
        for e in &s.elements {
            let size = elem_size(structs, e, ptr_size, 0);
            let disp = if e.hex {
                "Hexadecimal"
            } else if e.signed {
                "Signed Integer"
            } else {
                "Unsigned Integer"
            };
            x += &format!(
                "      <Element Offset=\"{}\" Vartype=\"{}\" Bytesize=\"{}\" OffsetHex=\"{:08X}\" Description=\"{}\" DisplayMethod=\"{}\"",
                e.offset,
                ct_vartype(e),
                size,
                e.offset,
                esc(&e.description),
                disp
            );
            if let Some(c) = &e.child {
                x += &format!(" ChildStruct=\"{}\"", esc(c));
            }
            if e.vtype == ElemType::Struct {
                x += " HHNested=\"1\"";
            }
            x += "/>\n";
        }
        x += "    </Elements>\n  </Structure>\n";
    }
    x + "</Structures>\n"
}

/// Reads the `<Structures>` section of a `.CT` file (whole file or just the section).
pub fn from_ct_xml(xml: &str) -> Result<Vec<Structure>> {
    let doc = roxmltree::Document::parse(xml.trim_start_matches('\u{feff}'))
        .map_err(|e| Error::Parse(format!("bad .CT XML: {e}")))?;
    let mut out = Vec::new();
    for s in doc.descendants().filter(|n| n.has_tag_name("Structure")) {
        // Old tables (StructVersion 1) keep the name in a child node.
        let name = s
            .attribute("Name")
            .map(str::to_string)
            .or_else(|| {
                s.children()
                    .find(|c| c.has_tag_name("Name"))
                    .and_then(|c| c.text())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let mut elements = Vec::new();
        for e in s.descendants().filter(|n| n.has_tag_name("Element")) {
            let offset = match (e.attribute("Offset"), e.attribute("OffsetHex")) {
                (Some(o), _) => o.trim().parse::<i64>().ok().map(|v| v as u64),
                (None, Some(h)) => u64::from_str_radix(h.trim(), 16).ok(),
                _ => None,
            }
            .ok_or_else(|| Error::Parse(format!("element without offset in {name:?}")))?;
            let size: usize = e
                .attribute("Bytesize")
                .and_then(|b| b.trim().parse().ok())
                .unwrap_or(0);
            let child = e.attribute("ChildStruct").map(str::to_string);
            let vt = e.attribute("Vartype").unwrap_or("4 Bytes");
            let (vtype, utf16) = match vt {
                "Byte" => (ElemType::Byte, false),
                "2 Bytes" => (ElemType::Bytes2, false),
                "4 Bytes" => (ElemType::Bytes4, false),
                "8 Bytes" => (ElemType::Bytes8, false),
                "Float" => (ElemType::Float, false),
                "Double" => (ElemType::Double, false),
                "String" => (ElemType::String, false),
                "Unicode String" => (ElemType::String, true),
                "Pointer" => (ElemType::Pointer, false),
                _ if e.attribute("HHNested") == Some("1") => (ElemType::Struct, false),
                _ => (ElemType::Aob, false),
            };
            let disp = e.attribute("DisplayMethod").unwrap_or("");
            elements.push(Element {
                offset,
                description: e.attribute("Description").unwrap_or("").to_string(),
                vtype,
                size: if matches!(vtype, ElemType::String | ElemType::Aob | ElemType::Struct) {
                    size
                } else {
                    0
                },
                hex: disp == "Hexadecimal",
                signed: disp == "Signed Integer",
                utf16,
                child,
            });
        }
        elements.sort_by_key(|e| e.offset);
        out.push(Structure { name, elements });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------- table entries

/// A cheat-table entry (subset of the contract's entry shape; the app fills the defaults).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableEntry {
    pub id: i64,
    pub description: String,
    pub addr: String,
    pub offsets: Vec<String>,
    pub vtype: VType,
    pub len: usize,
    pub utf16: bool,
    pub signed: bool,
    pub hex: bool,
    pub children: Vec<TableEntry>,
}

/// Cheat-table entries for the leaf fields of structure `name`. The structure lives at
/// address expression `addr` when `offsets` is empty, else at the end of the pointer path
/// `[[addr]+o0]+o1...` (Cheat Engine notation; `[0]` = "the structure `addr` points to").
/// `only` restricts to these top-level element indexes. Ids count up from `first_id`.
pub fn to_entries(
    structs: &[Structure],
    name: &str,
    addr: &str,
    offsets: &[u64],
    ptr_size: usize,
    only: Option<&[usize]>,
    first_id: i64,
) -> Result<Vec<TableEntry>> {
    let s = find(structs, name)?;
    let mut leaves = Vec::new();
    collect_leaves(structs, s, 0, &mut leaves, 0);
    let mut out = Vec::new();
    for (top, off, e) in leaves {
        if only.is_some_and(|o| !o.contains(&top)) {
            continue;
        }
        let (vtype, hex, len) = match e.vtype {
            ElemType::Pointer => (if ptr_size == 4 { VType::Bytes4 } else { VType::Bytes8 }, true, 0),
            ElemType::String => (VType::String, e.hex, if e.utf16 { e.size / 2 } else { e.size }),
            ElemType::Aob | ElemType::Struct => (VType::Aob, e.hex, e.size),
            t => (t.vtype().unwrap_or(VType::Bytes4), e.hex, 0),
        };
        let (a, offs) = match offsets.split_last() {
            None => (format!("{addr}+{off:X}"), Vec::new()),
            Some((last, head)) => (
                addr.to_string(),
                head.iter()
                    .copied()
                    .chain([last.wrapping_add(off)])
                    .map(|o| format!("{o:X}"))
                    .collect(),
            ),
        };
        let description = if e.description.is_empty() {
            format!("{name}+{off:X}")
        } else {
            e.description.clone()
        };
        out.push(TableEntry {
            id: first_id + out.len() as i64,
            description,
            addr: a,
            offsets: offs,
            vtype,
            len,
            utf16: e.utf16,
            signed: e.signed,
            hex,
            children: Vec::new(),
        });
    }
    Ok(out)
}

fn collect_leaves<'a>(
    structs: &'a [Structure],
    s: &'a Structure,
    rel: u64,
    out: &mut Vec<(usize, u64, &'a Element)>,
    depth: usize,
) {
    for (i, e) in s.elements.iter().enumerate() {
        let off = rel.wrapping_add(e.offset);
        let nested = (e.vtype == ElemType::Struct && depth < MAX_NEST)
            .then(|| e.child.as_deref().and_then(|c| lookup(structs, c).ok()))
            .flatten();
        match nested {
            Some(c) => {
                let start = out.len();
                collect_leaves(structs, c, off, out, depth + 1);
                // Leaves of a nested struct belong to the top-level element that embeds it.
                if depth == 0 {
                    for l in &mut out[start..] {
                        l.0 = i;
                    }
                }
            }
            None => out.push((i, off, e)),
        }
    }
}
