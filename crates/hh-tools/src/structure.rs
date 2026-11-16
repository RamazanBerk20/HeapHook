//! Structure dissector: named structure definitions evaluated against memory, auto-guessed
//! layouts, pointer fields expanded on demand into child structures, side-by-side compare of
//! address groups, "find fields that match/differ", a structure spider, HeapHook JSON and
//! Cheat Engine `<Structures>` XML import/export, and cheat-table entries from fields.
//! Also: bit fields and arrays of elements, RTTI class names (Itanium and MSVC layouts),
//! symbol-named pointers, a frozen "lock" copy and changed-field highlighting, C / C#
//! definitions, single-field table entries with the pointer path filled in, and an override
//! hook (Lua's structure dissect overrides) that runs before auto-guess.
//!
//! Structures refer to each other by name (`Element.child`), like Cheat Engine's global
//! structure list, so a set of definitions is a plain `Vec<Structure>`.
//!
//! Definitions are untrusted (tables, files, scripts): evaluation reads target memory in
//! 4 KiB chunks, at most [`MAX_EVAL_BYTES`] per call and [`MAX_ELEM_BYTES`] per element, and
//! produces at most [`MAX_FIELDS`] fields.
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use hh_core::{Addr, Error, Module, Process, Result};
use hh_scan::{CustomType, Fmt, VType, format_value};
use serde::{Deserialize, Serialize};

use crate::memory::{Block, Snapshot};
use crate::{Progress, Readable, hexaddr, read_some};

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
    /// Bit field inside an integer element (byte / 2 / 4 / 8 bytes): first bit, counted
    /// from the least significant, and width. `bit_len = 0` means the whole value.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bit_offset: u8,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bit_len: u8,
    /// Array: the element repeats `count` times back to back (0 or 1 = one element).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub count: usize,
    /// Pointers: the pointer points this many bytes past the start of the child structure
    /// (Cheat Engine's child structure start), so the child is at `pointer - child_start`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub child_start: u64,
}

fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// Most bytes one evaluation reads from the target (in 4 KiB chunks).
pub const MAX_EVAL_BYTES: u64 = 16 << 20;
/// Largest single element (strings and byte arrays included).
pub const MAX_ELEM_BYTES: usize = 1 << 20;
/// Most structures a definition set may hold.
pub const MAX_STRUCTS: usize = 100_000;

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
            bit_offset: 0,
            bit_len: 0,
            count: 0,
            child_start: 0,
        }
    }
    /// The bit field as an `hh_scan` custom type (format, write with masking).
    pub fn bits(&self) -> Option<CustomType> {
        let size = match self.vtype {
            ElemType::Byte => 1,
            ElemType::Bytes2 => 2,
            ElemType::Bytes4 => 4,
            ElemType::Bytes8 => 8,
            _ => return None,
        };
        (self.bit_len > 0).then(|| CustomType { bit_start: self.bit_offset, bit_len: self.bit_len, ..CustomType::int(size, self.signed) })
    }
    /// Rejects what evaluation cannot do safely: oversized strings / arrays, bit fields
    /// outside their integer or on non-integer types.
    pub fn check(&self) -> Result<()> {
        let bad = |m: String| Err(Error::Parse(format!("element at +{:X}: {m}", self.offset)));
        if matches!(self.vtype, ElemType::String | ElemType::Aob) && self.size > MAX_ELEM_BYTES {
            return bad(format!("size {} is over {MAX_ELEM_BYTES} bytes", self.size));
        }
        if self.count > MAX_FIELDS {
            return bad(format!("count {} is over {MAX_FIELDS}", self.count));
        }
        if self.bit_len > 0 || self.bit_offset > 0 {
            match self.bits() {
                Some(ct) => ct.validate()?,
                None => return bad("bit field outside an integer element".into()),
            }
        }
        Ok(())
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

const MAX_NEST: usize = 16;
/// Most fields one `evaluate` / `to_entries` call produces; nested structures repeat their
/// fields per reference, so a small hostile definition could otherwise expand exponentially.
pub const MAX_FIELDS: usize = 100_000;

/// One call's view of a definition set: name index, cached sizes and the field budget.
struct Defs<'a> {
    by_name: HashMap<&'a str, &'a Structure>,
    sizes: RefCell<HashMap<(&'a str, usize), usize>>,
    fields: Cell<usize>,
}

impl<'a> Defs<'a> {
    fn new(structs: &'a [Structure]) -> Self {
        let mut by_name = HashMap::new();
        for s in structs {
            // First definition wins, as with a linear search.
            by_name.entry(s.name.as_str()).or_insert(s);
        }
        Defs { by_name, sizes: RefCell::default(), fields: Cell::new(0) }
    }
    fn get(&self, name: &str) -> Option<&'a Structure> {
        self.by_name.get(name).copied()
    }
    /// Counts one produced field against [`MAX_FIELDS`].
    fn field(&self) -> Result<()> {
        self.fields.set(self.fields.get() + 1);
        if self.fields.get() > MAX_FIELDS {
            return Err(Error::Other(format!("structure expands to more than {MAX_FIELDS} fields")));
        }
        Ok(())
    }

    /// Looks up a structure for evaluation, refusing ones that embed themselves (directly or
    /// through other inline structures), which would have no finite size. Only the
    /// `MAX_NEST` levels that evaluation reaches are checked; each name is explored once.
    fn find(&self, name: &str) -> Result<&'a Structure> {
        fn visit<'a>(d: &Defs<'a>, name: &'a str, stack: &mut Vec<&'a str>, done: &mut HashSet<&'a str>) -> Result<()> {
            if stack.contains(&name) {
                return Err(Error::Other(format!("structure {name:?} embeds itself")));
            }
            if stack.len() > MAX_NEST || done.contains(name) {
                return Ok(());
            }
            let Some(s) = d.get(name) else { return Ok(()) };
            stack.push(&s.name);
            for e in s.elements.iter().filter(|e| e.vtype == ElemType::Struct) {
                if let Some(c) = &e.child {
                    visit(d, c, stack, done)?;
                }
            }
            stack.pop();
            done.insert(&s.name);
            Ok(())
        }
        let s = self.get(name).ok_or_else(|| Error::Other(format!("no structure named {name:?}")))?;
        visit(self, &s.name, &mut Vec::new(), &mut HashSet::new())?;
        Ok(s)
    }

    /// Byte size of one item of an element; nested structures use the child's size.
    fn item_size(&self, e: &Element, ptr: usize, depth: usize) -> usize {
        if e.vtype == ElemType::Struct && e.size == 0 {
            return e.child.as_deref().and_then(|c| self.get(c)).map_or(0, |s| self.struct_size_at(s, ptr, depth + 1));
        }
        e.fixed_size(ptr)
    }

    /// Byte size of an element, all array items included.
    fn elem_size(&self, e: &Element, ptr: usize, depth: usize) -> usize {
        self.item_size(e, ptr, depth).saturating_mul(e.count.max(1))
    }

    fn struct_size_at(&self, s: &'a Structure, ptr: usize, depth: usize) -> usize {
        if depth > MAX_NEST {
            return 0;
        }
        if let Some(&n) = self.sizes.borrow().get(&(s.name.as_str(), depth)) {
            return n;
        }
        let n = s
            .elements
            .iter()
            .map(|e| (e.offset as usize).saturating_add(self.elem_size(e, ptr, depth)))
            .max()
            .unwrap_or(0);
        self.sizes.borrow_mut().insert((s.name.as_str(), depth), n);
        n
    }
}

/// Size of a structure: the end of its last element.
pub fn struct_size(structs: &[Structure], name: &str, ptr_size: usize) -> Result<usize> {
    let d = Defs::new(structs);
    Ok(d.struct_size_at(d.find(name)?, ptr_size, 0))
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

/// Reads every element of structure `name` at `base`. Arrays become a field whose children
/// are the items; bit fields show the bits' value.
pub fn evaluate(
    p: &dyn Process,
    structs: &[Structure],
    name: &str,
    base: Addr,
) -> Result<Vec<FieldValue>> {
    let d = Defs::new(structs);
    let s = d.find(name)?;
    let read = |a: Addr, n: usize| read_some(p, a, n);
    Ok(run(&d, s, base, p.pointer_size(), &Readable::of(p)?, &read, false)?.0)
}

/// Structure lock: a frozen copy of the target memory that evaluating `name` at `base`
/// reads (the 4 KiB chunks its fields touch, at most [`MAX_EVAL_BYTES`]). Show it with
/// [`evaluate_locked`] and highlight live differences with [`changed_fields`].
pub fn lock_structure(p: &dyn Process, structs: &[Structure], name: &str, base: Addr) -> Result<Snapshot> {
    let d = Defs::new(structs);
    let s = d.find(name)?;
    let read = |a: Addr, n: usize| read_some(p, a, n);
    let (_, _, cache) = run(&d, s, base, p.pointer_size(), &Readable::default(), &read, false)?;
    let mut blocks: Vec<Block> = cache
        .into_iter()
        .filter(|(_, d)| !d.is_empty())
        .map(|(i, data)| Block { addr: i * EVAL_CHUNK, data })
        .collect();
    blocks.sort_by_key(|b| b.addr);
    Ok(Snapshot { blocks })
}

/// Evaluates `name` at `base` against a frozen copy (a [`lock_structure`] result or any
/// snapshot). Pointer fields have no `target` (readability is unknown offline).
pub fn evaluate_locked(snap: &Snapshot, structs: &[Structure], name: &str, base: Addr, ptr_size: usize) -> Result<Vec<FieldValue>> {
    if !matches!(ptr_size, 4 | 8) {
        return Err(Error::Other("pointer size must be 4 or 8".into()));
    }
    let d = Defs::new(structs);
    let s = d.find(name)?;
    let read = |a: Addr, n: usize| snap.read(a, n);
    Ok(run(&d, s, base, ptr_size, &Readable::default(), &read, false)?.0)
}

/// The leaf fields of an evaluation in order: nested structures and arrays are flattened.
/// Indexes into this list are what [`changed_fields`] returns.
pub fn leaves(fields: &[FieldValue]) -> Vec<&FieldValue> {
    flatten(fields)
}

/// Leaf indexes ([`leaves`] order) whose value differs between two evaluations of one
/// structure: two refreshes (highlight changes) or a locked copy and live memory.
pub fn changed_fields(old: &[FieldValue], new: &[FieldValue]) -> Vec<usize> {
    let (a, b) = (flatten(old), flatten(new));
    (0..a.len().max(b.len()))
        .filter(|&i| match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => x.value != y.value || x.offset != y.offset || x.vtype != y.vtype,
            _ => true,
        })
        .collect()
}

/// Writes `value` (text as typed in the dissector) to an evaluated leaf field: bit fields
/// keep the other bits, pointers take hex.
pub fn write_field(p: &dyn Process, structs: &[Structure], f: &FieldValue, value: &str) -> Result<()> {
    if f.vtype == ElemType::Struct || !f.children.is_empty() {
        return Err(Error::Other("not a single value; write one of its fields or items".into()));
    }
    let e = lookup(structs, &f.owner)?
        .elements
        .get(f.index)
        .ok_or_else(|| Error::Other(format!("{} has no element {}", f.owner, f.index)))?;
    e.check()?;
    if let Some(ct) = e.bits() {
        return hh_scan::write_custom(p, f.addr, &ct, value, &e.fmt());
    }
    match e.vtype.vtype() {
        None => {
            let t = value.trim();
            let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
            let v = u64::from_str_radix(t, 16).map_err(|_| Error::Parse(format!("bad pointer {value:?}")))?;
            let n = p.pointer_size();
            if n < 8 && v >> (8 * n) != 0 {
                return Err(Error::Parse(format!("pointer {value:?} does not fit {n} bytes")));
            }
            p.write(f.addr, &v.to_le_bytes()[..n])
        }
        Some(vt) => hh_scan::write_value(p, f.addr, vt, value, &e.fmt()),
    }
}

const EVAL_CHUNK: u64 = 0x1000;

/// Target memory read on demand in aligned chunks, charged against [`MAX_EVAL_BYTES`].
struct Chunks<'b> {
    read: &'b dyn Fn(Addr, usize) -> Vec<u8>,
    cache: ChunkCache,
    used: u64,
}

impl Chunks<'_> {
    /// `len` bytes at `addr`, `None` if any of them is unreadable.
    fn get(&mut self, addr: Addr, len: usize) -> Result<Option<Vec<u8>>> {
        let Some(end) = addr.checked_add(len as u64) else {
            return Err(Error::Other(format!("field at {addr:#x} wraps the address space")));
        };
        let mut out = Vec::with_capacity(len);
        let mut a = addr;
        while a < end {
            let idx = a / EVAL_CHUNK;
            if !self.cache.contains_key(&idx) {
                self.used += EVAL_CHUNK;
                if self.used > MAX_EVAL_BYTES {
                    return Err(Error::Other(format!("structure evaluation reads more than {MAX_EVAL_BYTES} bytes")));
                }
                self.cache.insert(idx, (self.read)(idx * EVAL_CHUNK, EVAL_CHUNK as usize));
            }
            let o = (a - idx * EVAL_CHUNK) as usize;
            let n = ((end - a) as usize).min(EVAL_CHUNK as usize - o);
            match self.cache.get(&idx).and_then(|c| c.get(o..o + n)) {
                Some(b) => out.extend_from_slice(b),
                None => return Ok(None),
            }
            a += n as u64;
        }
        Ok(Some(out))
    }
}

type Raw = Vec<Option<Vec<u8>>>;
/// Chunks read by one evaluation, by chunk index.
type ChunkCache = HashMap<u64, Vec<u8>>;

/// One evaluation: fields, the raw bytes of every leaf (when `keep_raw`, in [`leaves`]
/// order) and the chunks read.
fn run<'a>(
    d: &Defs<'a>,
    s: &'a Structure,
    base: Addr,
    ptr: usize,
    readable: &Readable,
    read: &dyn Fn(Addr, usize) -> Vec<u8>,
    keep_raw: bool,
) -> Result<(Vec<FieldValue>, Raw, ChunkCache)> {
    d.fields.set(0);
    let mut ev = Ev { d, ptr, readable, mem: Chunks { read, cache: HashMap::new(), used: 0 }, raw: keep_raw.then(Vec::new) };
    let f = ev.structure(s, base, 0, 0)?;
    Ok((f, ev.raw.unwrap_or_default(), ev.mem.cache))
}

struct Ev<'a, 'b> {
    d: &'b Defs<'a>,
    ptr: usize,
    readable: &'b Readable,
    mem: Chunks<'b>,
    raw: Option<Raw>,
}

impl Ev<'_, '_> {
    fn structure(&mut self, s: &Structure, base: Addr, rel: u64, depth: usize) -> Result<Vec<FieldValue>> {
        let mut out = Vec::with_capacity(s.elements.len().min(4096));
        for (index, e) in s.elements.iter().enumerate() {
            self.d.field()?;
            e.check()?;
            let item = self.d.item_size(e, self.ptr, depth);
            let off = rel.wrapping_add(e.offset);
            if e.count > 1 {
                let mut items = Vec::with_capacity(e.count.min(4096));
                for k in 0..e.count {
                    self.d.field()?;
                    let o = off.wrapping_add((k as u64).wrapping_mul(item as u64));
                    items.push(self.item(s, index, e, base, o, item, depth, format!("{}[{k}]", e.description))?);
                }
                out.push(FieldValue {
                    offset: off,
                    addr: base.wrapping_add(off),
                    description: e.description.clone(),
                    vtype: e.vtype,
                    size: item.saturating_mul(e.count),
                    value: None,
                    target: None,
                    child: e.child.clone(),
                    owner: s.name.clone(),
                    index,
                    children: items,
                });
            } else {
                out.push(self.item(s, index, e, base, off, item, depth, e.description.clone())?);
            }
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn item(&mut self, s: &Structure, index: usize, e: &Element, base: Addr, off: u64, size: usize, depth: usize, description: String) -> Result<FieldValue> {
        let mut fv = FieldValue {
            offset: off,
            addr: base.wrapping_add(off),
            description,
            vtype: e.vtype,
            size,
            value: None,
            target: None,
            child: e.child.clone(),
            owner: s.name.clone(),
            index,
            children: Vec::new(),
        };
        if e.vtype == ElemType::Struct {
            if depth < MAX_NEST
                && let Some(c) = e.child.as_deref().and_then(|c| self.d.get(c))
            {
                fv.children = self.structure(c, base, off, depth + 1)?;
            }
            return Ok(fv);
        }
        if size > MAX_ELEM_BYTES {
            return Err(Error::Other(format!("element at +{off:X} is over {MAX_ELEM_BYTES} bytes")));
        }
        let raw = self.mem.get(fv.addr, size)?;
        if let Some(r) = &raw {
            if e.vtype == ElemType::Pointer {
                let v = le(r);
                fv.value = Some(format!("{v:X}"));
                fv.target = (v != 0 && self.readable.contains(v)).then_some(v);
            } else if let Some(ct) = e.bits() {
                fv.value = Some(ct.format(r, &e.fmt()));
            } else {
                fv.value = e.vtype.vtype().map(|vt| format_value(vt, r, &e.fmt()));
            }
        }
        if let Some(v) = &mut self.raw {
            v.push(raw);
        }
        Ok(fv)
    }
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
/// structure name and its address (the target minus the element's `child_start`), ready
/// for [`evaluate`].
pub fn expand_pointer(
    p: &dyn Process,
    structs: &mut Vec<Structure>,
    owner: &str,
    index: usize,
    field_addr: Addr,
    guess_size: usize,
) -> Result<(String, Addr)> {
    expand_pointer_with(p, structs, owner, index, field_addr, guess_size, &GuessOptions::plain(), None)
}

/// [`expand_pointer`] with guess options (RTTI / symbol naming) and the override hook: a new
/// child is named after the object's RTTI class when known, and `override_` may supply the
/// child structure before auto-guess runs (an existing structure of that name is linked,
/// not replaced).
#[allow(clippy::too_many_arguments)]
pub fn expand_pointer_with(
    p: &dyn Process,
    structs: &mut Vec<Structure>,
    owner: &str,
    index: usize,
    field_addr: Addr,
    guess_size: usize,
    opts: &GuessOptions,
    override_: Option<&StructOverride>,
) -> Result<(String, Addr)> {
    let e = lookup(structs, owner)?
        .elements
        .get(index)
        .ok_or_else(|| Error::Other(format!("{owner} has no element {index}")))?
        .clone();
    if e.vtype != ElemType::Pointer {
        return Err(Error::Other("element is not a pointer".into()));
    }
    let target = p.read_ptr(field_addr)?.wrapping_sub(e.child_start);
    if let Some(c) = e.child.filter(|c| structs.iter().any(|s| &s.name == c)) {
        return Ok((c, target));
    }
    let given = override_.and_then(|f| f(target, guess_size));
    let child = match given {
        Some(c) => {
            validate_structures(std::slice::from_ref(&c))?;
            c
        }
        None => {
            let mut name = opts
                .rtti
                .then(|| rtti_class_name(p, target))
                .flatten()
                .unwrap_or_else(|| format!("{owner}_{:X}", e.offset));
            while structs.iter().any(|s| s.name == name) {
                name.push('_');
            }
            guess_structure_with(p, &name, target, guess_size, opts, None)?
        }
    };
    let name = child.name.clone();
    if !structs.iter().any(|s| s.name == name) {
        if structs.len() >= MAX_STRUCTS {
            return Err(Error::Other(format!("more than {MAX_STRUCTS} structures")));
        }
        structs.push(child);
    }
    if let Some(s) = structs.iter_mut().find(|s| s.name == owner) {
        s.elements[index].child = Some(name.clone());
    }
    Ok((name, target))
}

/// Auto-guess options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuessOptions {
    /// Name structures after the C++ class of the object (RTTI) and describe pointer fields
    /// after the class they point to (`Player*`).
    pub rtti: bool,
    /// Describe pointers into a module after the symbol there (a function, a global).
    pub symbols: bool,
    /// Module files may be read from the local disk (symbols). Set false for a remote target:
    /// its module paths name files on another machine.
    pub local_files: bool,
}

impl Default for GuessOptions {
    fn default() -> Self {
        GuessOptions { rtti: true, symbols: true, local_files: true }
    }
}

impl GuessOptions {
    /// No naming: what [`guess_structure`] and [`expand_pointer`] do.
    pub fn plain() -> Self {
        GuessOptions { rtti: false, symbols: false, local_files: true }
    }
}

/// Structure dissect override (Lua `registerStructureDissectOverride`): called with the
/// address and the requested size before auto-guess; `Some` is used instead of guessing.
pub type StructOverride<'a> = dyn Fn(Addr, usize) -> Option<Structure> + 'a;

/// [`guess_structure`] with naming options and the override hook. An empty `name` becomes
/// the RTTI class name when there is one; the element at offset 0 of an object with RTTI
/// is described as `vtable`.
pub fn guess_structure_with(
    p: &dyn Process,
    name: &str,
    addr: Addr,
    size: usize,
    opts: &GuessOptions,
    override_: Option<&StructOverride>,
) -> Result<Structure> {
    if let Some(s) = override_.and_then(|f| f(addr, size)) {
        validate_structures(std::slice::from_ref(&s))?;
        return Ok(s);
    }
    if size as u64 > MAX_EVAL_BYTES {
        return Err(Error::Other(format!("guess size {size:#x} is over {MAX_EVAL_BYTES:#x}")));
    }
    let b = read_some(p, addr, size);
    if b.is_empty() {
        return Err(Error::NoAccess { addr });
    }
    let ptr = p.pointer_size();
    let mut elements = guess_elements(&b, ptr, &Readable::of(p)?);
    let mut namer = Namer { p, opts, mods: if opts.symbols { p.modules().unwrap_or_default() } else { Vec::new() }, syms: HashMap::new() };
    for e in elements.iter_mut().filter(|e| e.vtype == ElemType::Pointer) {
        let v = le(b.get(e.offset as usize..).unwrap_or_default().get(..ptr).unwrap_or_default());
        if let Some(n) = namer.name(v) {
            e.description = n;
        }
    }
    let class = opts.rtti.then(|| rtti_class_name(p, addr)).flatten();
    if class.is_some()
        && let Some(e) = elements.first_mut().filter(|e| e.offset == 0 && e.vtype == ElemType::Pointer)
    {
        e.description = "vtable".into();
    }
    let name = match (name, class) {
        ("", Some(c)) => c,
        (n, _) => n.to_string(),
    };
    Ok(Structure { name, elements })
}

/// Names pointer values: RTTI class of the object, else the module symbol there.
struct Namer<'a> {
    p: &'a dyn Process,
    opts: &'a GuessOptions,
    mods: Vec<Module>,
    syms: HashMap<usize, Vec<hh_asm::Symbol>>,
}

impl Namer<'_> {
    fn name(&mut self, v: Addr) -> Option<String> {
        if self.opts.rtti
            && let Some(c) = rtti_class_name(self.p, v)
        {
            return Some(format!("{c}*"));
        }
        // shortcut: hh-asm at this crate's start commit only loads symbols through files, so a
        // remote target gets no symbol names; use its memory-only switch once it exists.
        if !self.opts.symbols || !self.opts.local_files {
            return None;
        }
        let i = self.mods.iter().position(|m| v >= m.base && v - m.base < m.size)?;
        let (p, mods) = (self.p, &self.mods);
        let syms = self.syms.entry(i).or_insert_with(|| hh_asm::module_symbols(p, &mods[i]));
        let s = &syms[syms.partition_point(|s| s.addr <= v).checked_sub(1)?];
        let off = v - s.addr;
        if off != 0 && off >= s.size {
            return None;
        }
        let n = hh_asm::demangle(&s.name).unwrap_or_else(|| s.name.clone());
        Some(if off == 0 { n } else { format!("{n}+{off:X}") })
    }
}

// ---------------------------------------------------------------------------------- RTTI

/// Longest RTTI type name read.
const MAX_RTTI_NAME: usize = 1024;

fn ptr_at(p: &dyn Process, a: Addr) -> Option<Addr> {
    let n = p.pointer_size().min(8);
    let mut b = [0u8; 8];
    p.read_exact(a, &mut b[..n]).ok()?;
    Some(u64::from_le_bytes(b))
}

/// A NUL-terminated printable ASCII string of 1..MAX_RTTI_NAME bytes.
fn c_string(p: &dyn Process, a: Addr) -> Option<String> {
    let b = read_some(p, a, MAX_RTTI_NAME);
    let n = b.iter().position(|&c| c == 0)?;
    (n > 0 && b[..n].iter().all(u8::is_ascii_graphic)).then(|| String::from_utf8_lossy(&b[..n]).into_owned())
}

/// C++ class name of the object at `obj` from its RTTI: object -> vtable -> type info ->
/// name. Tries the Itanium ABI (GCC / Clang: `vtable[-1]` is the `type_info`, whose second
/// word points to the mangled name, demangled through hh-asm) and then MSVC (`vtable[-1]` is
/// the complete object locator; 64-bit locators hold image-relative offsets). `None` when the
/// chain does not hold up.
pub fn rtti_class_name(p: &dyn Process, obj: Addr) -> Option<String> {
    let ps = p.pointer_size() as u64;
    let vt = ptr_at(p, obj)?;
    if vt == 0 || !vt.is_multiple_of(ps) {
        return None;
    }
    let meta = ptr_at(p, vt.checked_sub(ps)?)?;
    if meta == 0 {
        return None;
    }
    rtti_itanium(p, meta, ps).or_else(|| rtti_msvc(p, meta, ps))
}

fn rtti_itanium(p: &dyn Process, type_info: Addr, ps: u64) -> Option<String> {
    let name = c_string(p, ptr_at(p, type_info.checked_add(ps)?)?)?;
    // Type names are <length><id>, N...E (nested) or St... (std); the name of a typeinfo name
    // symbol demangles to "typeinfo name for <type>".
    if !name.starts_with(|c: char| c.is_ascii_digit() || c == 'N' || c == 'S') {
        return None;
    }
    let d = hh_asm::demangle(&format!("_ZTS{name}"))?;
    Some(d.strip_prefix("typeinfo name for ").unwrap_or(&d).to_string())
}

fn rtti_msvc(p: &dyn Process, col: Addr, ps: u64) -> Option<String> {
    let mut h = [0u8; 24];
    p.read_exact(col, &mut h).ok()?;
    let u = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) as u64;
    let td = match (ps, u(0)) {
        // 64-bit: signature 1, offsets relative to the image base, which is the locator's
        // address minus its own offset (pSelf).
        (8, 1) => col.checked_sub(u(20))?.checked_add(u(12))?,
        (4, 0) => u(12),
        _ => return None,
    };
    // TypeDescriptor: vftable pointer, spare pointer, then the decorated name ".?AVName@@".
    let raw = c_string(p, td.checked_add(2 * ps)?)?;
    let body = raw.strip_prefix(".?AV").or_else(|| raw.strip_prefix(".?AU"))?.strip_suffix("@@")?;
    if body.is_empty() {
        return None;
    }
    if body.contains(['?', '$']) {
        // Templates and other special names: shown decorated rather than guessed at.
        return Some(body.to_string());
    }
    Some(body.split('@').rev().collect::<Vec<_>>().join("::"))
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
    guess_structure_with(p, name, addr, size, &GuessOptions::plain(), None)
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
    let d = Defs::new(structs);
    let s = d.find(name)?;
    let (ptr, readable) = (p.pointer_size(), Readable::of(p)?);
    let read = |a: Addr, n: usize| read_some(p, a, n);
    let mut kept = 0u64;
    let mut cols: Vec<Vec<(Vec<FieldValue>, Raw)>> = Vec::with_capacity(groups.len());
    for g in groups {
        let mut col = Vec::with_capacity(g.len());
        for &a in g {
            let (f, raw, _) = run(&d, s, a, ptr, &readable, &read, true)?;
            kept += raw.iter().flatten().map(|r| r.len() as u64).sum::<u64>();
            if kept > 4 * MAX_EVAL_BYTES {
                return Err(Error::Other(format!("compare holds more than {} bytes; use fewer addresses", 4 * MAX_EVAL_BYTES)));
            }
            col.push((f, raw));
        }
        cols.push(col);
    }
    let Some(proto) = cols.iter().flatten().next() else {
        return Ok(Vec::new());
    };
    let leaves = flatten(&proto.0);
    let flat: Vec<Vec<Vec<&FieldValue>>> = cols
        .iter()
        .map(|g| g.iter().map(|c| flatten(&c.0)).collect())
        .collect();
    Ok(leaves
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let raw: Vec<Vec<Option<&[u8]>>> = cols
                .iter()
                .map(|g| g.iter().map(|c| c.1.get(i).and_then(|r| r.as_deref())).collect())
                .collect();
            CompareRow {
                offset: l.offset,
                description: l.description.clone(),
                vtype: l.vtype,
                owner: l.owner.clone(),
                index: l.index,
                values: flat
                    .iter()
                    .map(|g| g.iter().map(|c| c.get(i).and_then(|f| f.value.clone())).collect())
                    .collect(),
                class: classify(&raw),
            }
        })
        .collect())
}

fn flatten(f: &[FieldValue]) -> Vec<&FieldValue> {
    let mut out = Vec::new();
    for v in f {
        if v.vtype == ElemType::Struct || !v.children.is_empty() {
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
    if size as u64 > MAX_EVAL_BYTES {
        return Err(Error::Other(format!("size {size:#x} is over {MAX_EVAL_BYTES:#x}")));
    }
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
    if opts.size as u64 > MAX_EVAL_BYTES {
        return Err(Error::Other(format!("size {:#x} is over {MAX_EVAL_BYTES:#x}", opts.size)));
    }
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

/// Checks a definition set from an untrusted source: at most [`MAX_STRUCTS`] structures of
/// at most [`MAX_FIELDS`] elements, each passing [`Element::check`]. Imports call it.
pub fn validate_structures(structs: &[Structure]) -> Result<()> {
    if structs.len() > MAX_STRUCTS {
        return Err(Error::Parse(format!("more than {MAX_STRUCTS} structures")));
    }
    for s in structs {
        if s.elements.len() > MAX_FIELDS {
            return Err(Error::Parse(format!("structure {:?} has more than {MAX_FIELDS} elements", s.name)));
        }
        for e in &s.elements {
            e.check().map_err(|err| Error::Parse(format!("structure {:?}: {err}", s.name)))?;
        }
    }
    Ok(())
}

/// HeapHook JSON: `{"structures": [...]}`.
pub fn to_json(structs: &[Structure]) -> String {
    serde_json::json!({ "structures": structs }).to_string()
}

/// Reads `{"structures": [...]}` or a bare array (validated, see [`validate_structures`]).
pub fn from_json(text: &str) -> Result<Vec<Structure>> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum In {
        Wrapped { structures: Vec<Structure> },
        Bare(Vec<Structure>),
    }
    match serde_json::from_str::<In>(text) {
        Ok(In::Wrapped { structures } | In::Bare(structures)) => {
            validate_structures(&structures)?;
            Ok(structures)
        }
        Err(e) => Err(Error::Parse(format!("structures JSON: {e}"))),
    }
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
/// have, are written as byte arrays of the same size tagged `HHNested="1"`; bit fields and
/// arrays carry `HHBitOffset` / `HHBitLength` / `HHCount`. Names and descriptions are
/// escaped; characters XML cannot hold become U+FFFD.
pub fn to_ct_xml(structs: &[Structure], ptr_size: usize) -> String {
    let esc = crate::xml_escape;
    let d = Defs::new(structs);
    let mut x = String::from("<Structures StructVersion=\"2\">\n");
    for s in structs {
        x += &format!(
            "  <Structure Name=\"{}\" AutoFill=\"0\" AutoCreate=\"1\" DefaultHex=\"0\" AutoDestroy=\"0\" DoNotSaveLocal=\"0\" RLECompression=\"1\" AutoCreateStructsize=\"4096\">\n    <Elements>\n",
            esc(&s.name)
        );
        for e in &s.elements {
            let size = d.item_size(e, ptr_size, 0);
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
            if e.child_start != 0 {
                x += &format!(" ChildStructStart=\"{}\"", e.child_start);
            }
            if e.vtype == ElemType::Struct {
                x += " HHNested=\"1\"";
            }
            if e.bit_len != 0 {
                x += &format!(" HHBitOffset=\"{}\" HHBitLength=\"{}\"", e.bit_offset, e.bit_len);
            }
            if e.count > 1 {
                x += &format!(" HHCount=\"{}\"", e.count);
            }
            x += "/>\n";
        }
        x += "    </Elements>\n  </Structure>\n";
    }
    x + "</Structures>\n"
}

/// Reads the `<Structures>` section of a `.CT` file (whole file or just the section);
/// validated like [`from_json`].
pub fn from_ct_xml(xml: &str) -> Result<Vec<Structure>> {
    let doc = roxmltree::Document::parse(xml.trim_start_matches('\u{feff}'))
        .map_err(|e| Error::Parse(format!("bad .CT XML: {e}")))?;
    // Each <Element> belongs to its nearest <Structure> ancestor, found in one pre-order pass
    // (scanning every structure's descendants is quadratic on hostile nesting).
    let mut owner: Vec<Option<roxmltree::NodeId>> = vec![None; doc.descendants().map(|n| n.id().get_usize() + 1).max().unwrap_or(0)];
    let mut elems: HashMap<roxmltree::NodeId, Vec<roxmltree::Node>> = HashMap::new();
    for n in doc.descendants() {
        let up = n.parent().and_then(|p| if p.has_tag_name("Structure") { Some(p.id()) } else { owner[p.id().get_usize()] });
        owner[n.id().get_usize()] = up;
        if n.has_tag_name("Element") && let Some(s) = up {
            elems.entry(s).or_default().push(n);
        }
    }
    let mut out = Vec::new();
    for s in doc.descendants().filter(|n| n.has_tag_name("Structure")) {
        if out.len() >= MAX_STRUCTS {
            return Err(Error::Parse(format!("more than {MAX_STRUCTS} structures")));
        }
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
        let list = elems.get(&s.id()).map_or(&[][..], Vec::as_slice);
        if list.len() > MAX_FIELDS {
            return Err(Error::Parse(format!("structure {name:?} has more than {MAX_FIELDS} elements")));
        }
        let mut elements = Vec::with_capacity(list.len());
        for &e in list {
            let offset = match (e.attribute("Offset"), e.attribute("OffsetHex")) {
                (Some(o), _) => o.trim().parse::<i64>().ok().map(|v| v as u64),
                (None, Some(h)) => u64::from_str_radix(h.trim(), 16).ok(),
                _ => None,
            }
            .ok_or_else(|| Error::Parse(format!("element without offset in {name:?}")))?;
            let num = |attr: &str| -> Result<u64> {
                e.attribute(attr).map_or(Ok(0), |v| v.trim().parse().map_err(|_| Error::Parse(format!("bad {attr} {v:?} in {name:?}"))))
            };
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
            let narrow = |v: u64, max: u64, attr: &str| {
                if v > max { Err(Error::Parse(format!("{attr} {v} out of range in {name:?}"))) } else { Ok(v) }
            };
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
                bit_offset: narrow(num("HHBitOffset")?, 63, "HHBitOffset")? as u8,
                bit_len: narrow(num("HHBitLength")?, 64, "HHBitLength")? as u8,
                count: narrow(num("HHCount")?, MAX_FIELDS as u64, "HHCount")? as usize,
                child_start: num("ChildStructStart")?,
            });
        }
        elements.sort_by_key(|e| e.offset);
        out.push(Structure { name, elements });
    }
    // Nested structures exported from HeapHook carry their real size in Bytesize; only
    // strings and byte arrays are checked against the element cap.
    validate_structures(&out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------- C / C# export

fn ident(s: &str, fallback: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "auto", "base", "bool", "break", "byte", "case", "char", "class", "const", "default", "do", "double", "else", "enum", "event",
        "extern", "fixed", "float", "for", "goto", "if", "int", "long", "new", "object", "out", "params", "private", "public", "ref",
        "register", "return", "short", "signed", "sizeof", "static", "string", "struct", "switch", "this", "typedef", "uint",
        "ulong", "union", "unsigned", "ushort", "void", "volatile", "while",
    ];
    let mut o: String = s.chars().take(128).map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    if o.trim_matches('_').is_empty() {
        o = fallback.to_string();
    }
    if o.starts_with(|c: char| c.is_ascii_digit()) || KEYWORDS.contains(&o.as_str()) {
        o.insert(0, '_');
    }
    o
}

/// Language-independent view of one structure for the code generators.
struct Layout<'a> {
    name: String,
    size: usize,
    /// (offset, field name, element) sorted by offset then bit offset.
    fields: Vec<(u64, String, &'a Element)>,
}

/// Structures in definition order, inline children first, with unique identifiers.
fn layouts<'a>(d: &Defs<'a>, structs: &'a [Structure], ptr: usize) -> (Vec<Layout<'a>>, HashMap<&'a str, String>) {
    let mut names: HashMap<&str, String> = HashMap::new();
    let mut used = HashSet::new();
    for (i, s) in structs.iter().enumerate() {
        if names.contains_key(s.name.as_str()) {
            continue;
        }
        let mut n = ident(&s.name, &format!("Struct{i}"));
        while !used.insert(n.clone()) {
            n.push('_');
        }
        names.insert(&s.name, n);
    }
    let mut order: Vec<&Structure> = Vec::new();
    let mut seen = HashSet::new();
    fn visit<'a>(d: &Defs<'a>, s: &'a Structure, seen: &mut HashSet<&'a str>, order: &mut Vec<&'a Structure>, depth: usize) {
        if depth > MAX_NEST || !seen.insert(s.name.as_str()) {
            return;
        }
        for e in s.elements.iter().filter(|e| e.vtype == ElemType::Struct) {
            if let Some(c) = e.child.as_deref().and_then(|c| d.get(c)) {
                visit(d, c, seen, order, depth + 1);
            }
        }
        order.push(s);
    }
    for s in structs {
        if let Some(s) = d.get(&s.name) {
            visit(d, s, &mut seen, &mut order, 0);
        }
    }
    let out = order
        .into_iter()
        .map(|s| {
            let mut els: Vec<&Element> = s.elements.iter().collect();
            els.sort_by_key(|e| (e.offset, e.bit_offset));
            let mut taken = HashSet::new();
            let fields = els
                .into_iter()
                .map(|e| {
                    let mut n = ident(&e.description, &format!("f_{:X}", e.offset));
                    if !taken.insert(n.clone()) {
                        n = format!("{n}_{:X}", e.offset);
                        while !taken.insert(n.clone()) {
                            n.push('_');
                        }
                    }
                    (e.offset, n, e)
                })
                .collect();
            Layout { name: names[s.name.as_str()].clone(), size: d.struct_size_at(s, ptr, 0), fields }
        })
        .collect();
    (out, names)
}

/// C definitions (`#pragma pack(1)`, `<stdint.h>` types, explicit padding, bit fields,
/// arrays) for every structure, nested ones first. Pointers are typed `struct X*` for
/// 8-byte targets and `uint32_t` for 4-byte ones (so the layout holds on a 64-bit host);
/// fields that overlap an earlier one are kept as comments.
pub fn to_c(structs: &[Structure], ptr_size: usize) -> String {
    let d = Defs::new(structs);
    let (lays, names) = layouts(&d, structs, ptr_size);
    let cname = |c: &Option<String>| c.as_deref().and_then(|c| names.get(c)).cloned();
    let int = |e: &Element| {
        let bits = match e.vtype {
            ElemType::Byte => 8,
            ElemType::Bytes2 => 16,
            ElemType::Bytes4 => 32,
            _ => 64,
        };
        format!("{}int{bits}_t", if e.signed { "" } else { "u" })
    };
    let mut x = String::from("/* Generated by HeapHook. */\n#include <stdint.h>\n\n");
    for l in &lays {
        x += &format!("struct {};\n", l.name);
    }
    x += "\n#pragma pack(push, 1)\n";
    for l in &lays {
        x += &format!("struct {} {{ /* size 0x{:X} */\n", l.name, l.size);
        let mut cur = 0u64;
        let mut i = 0;
        while i < l.fields.len() {
            let (off, ref name, e) = l.fields[i];
            if off < cur {
                x += &format!("    /* 0x{off:X}: {name} overlaps the field before */\n");
                i += 1;
                continue;
            }
            if off > cur {
                x += &format!("    uint8_t _pad_{cur:X}[0x{:X}];\n", off - cur);
                cur = off;
            }
            if e.bits().is_some() {
                // One storage unit: the consecutive bit fields at this offset of this type.
                let storage = 8 * d.item_size(e, ptr_size, 0) as u32;
                let mut bit = 0u32;
                while let Some(&(o2, ref n2, e2)) = l.fields.get(i)
                    && o2 == off
                    && e2.vtype == e.vtype
                    && e2.bit_len > 0
                {
                    let b0 = e2.bit_offset as u32;
                    if b0 < bit {
                        x += &format!("    /* 0x{off:X}: {n2} overlaps the bits before */\n");
                    } else {
                        if b0 > bit {
                            x += &format!("    {} : {};\n", int(e2), b0 - bit);
                        }
                        x += &format!("    /* 0x{off:X} */ {} {n2} : {};\n", int(e2), e2.bit_len);
                        bit = b0 + e2.bit_len as u32;
                    }
                    i += 1;
                }
                if bit < storage {
                    x += &format!("    {} : {};\n", int(e), storage - bit);
                }
                cur = cur.saturating_add((storage / 8) as u64);
                continue;
            }
            let item = d.item_size(e, ptr_size, 0);
            let (ty, inner) = match e.vtype {
                ElemType::Byte | ElemType::Bytes2 | ElemType::Bytes4 | ElemType::Bytes8 => (int(e), None),
                ElemType::Float => ("float".into(), None),
                ElemType::Double => ("double".into(), None),
                ElemType::String if e.utf16 => ("uint16_t".into(), Some(item / 2)),
                ElemType::String => ("char".into(), Some(item)),
                ElemType::Aob => ("uint8_t".into(), Some(item)),
                ElemType::Pointer if ptr_size == 4 => ("uint32_t".into(), None),
                ElemType::Pointer => (cname(&e.child).map_or("void*".into(), |c| format!("struct {c}*")), None),
                ElemType::Struct => match cname(&e.child) {
                    Some(c) if e.size == 0 => (format!("struct {c}"), None),
                    _ => ("uint8_t".into(), Some(item)),
                },
            };
            let mut dims = String::new();
            if e.count > 1 {
                dims += &format!("[{}]", e.count);
            }
            if let Some(n) = inner {
                dims += &format!("[{n}]");
            }
            let note = match (&e.vtype, ptr_size, cname(&e.child)) {
                (ElemType::Pointer, 4, Some(c)) => format!(" /* {c}* */"),
                _ => String::new(),
            };
            x += &format!("    /* 0x{off:X} */ {ty} {name}{dims};{note}\n");
            cur = off.saturating_add(d.elem_size(e, ptr_size, 0) as u64);
            i += 1;
        }
        x += "};\n\n";
    }
    x + "#pragma pack(pop)\n"
}

/// C# definitions: `[StructLayout(LayoutKind.Explicit)] unsafe struct`s with a
/// `[FieldOffset]` per field. Strings and primitive arrays are `fixed` buffers, pointers
/// `IntPtr` (valid when the C# process has the target's pointer width), bit fields share one
/// storage field whose comment lists the bits, and arrays of structures list their first
/// items (at most 64).
pub fn to_csharp(structs: &[Structure], ptr_size: usize) -> String {
    let d = Defs::new(structs);
    let (lays, names) = layouts(&d, structs, ptr_size);
    let prim = |e: &Element| -> &'static str {
        match (e.vtype, e.signed) {
            (ElemType::Byte, false) => "byte",
            (ElemType::Byte, true) => "sbyte",
            (ElemType::Bytes2, false) => "ushort",
            (ElemType::Bytes2, true) => "short",
            (ElemType::Bytes4, false) => "uint",
            (ElemType::Bytes4, true) => "int",
            (ElemType::Bytes8, false) => "ulong",
            (ElemType::Bytes8, true) => "long",
            (ElemType::Float, _) => "float",
            (ElemType::Double, _) => "double",
            (ElemType::Pointer, _) if ptr_size == 4 => "uint",
            (ElemType::Pointer, _) => "ulong",
            _ => "byte",
        }
    };
    let mut x = String::from("// Generated by HeapHook.\nusing System;\nusing System.Runtime.InteropServices;\n\n");
    for l in &lays {
        x += &format!("[StructLayout(LayoutKind.Explicit, Size = 0x{:X})]\npublic unsafe struct {}\n{{\n", l.size.max(1), l.name);
        let mut i = 0;
        while i < l.fields.len() {
            let (off, ref name, e) = l.fields[i];
            let at = format!("    [FieldOffset(0x{off:X})] public");
            if e.bits().is_some() {
                let mut bits = Vec::new();
                while let Some(&(o2, ref n2, e2)) = l.fields.get(i)
                    && o2 == off
                    && e2.vtype == e.vtype
                    && e2.bit_len > 0
                {
                    bits.push(format!("{n2}: bits {}..{}", e2.bit_offset, e2.bit_offset as u32 + e2.bit_len as u32 - 1));
                    i += 1;
                }
                x += &format!("{at} {} {name}; // {}\n", prim(e), bits.join(", "));
                continue;
            }
            let item = d.item_size(e, ptr_size, 0);
            let n = e.count.max(1);
            let child = e.child.as_deref().and_then(|c| names.get(c));
            match e.vtype {
                // Sizes from nested definitions can be huge: saturate, never overflow.
                ElemType::String if e.utf16 => x += &format!("{at} fixed char {name}[{}];\n", (item / 2).max(1).saturating_mul(n)),
                ElemType::String | ElemType::Aob => x += &format!("{at} fixed byte {name}[{}];\n", item.max(1).saturating_mul(n)),
                ElemType::Struct => match child {
                    Some(c) if e.size == 0 => {
                        for k in 0..n.min(64) {
                            let nm = if n > 1 { format!("{name}_{k}") } else { name.clone() };
                            x += &format!("    [FieldOffset(0x{:X})] public {c} {nm};\n", off.saturating_add(k.saturating_mul(item) as u64));
                        }
                        if n > 64 {
                            x += &format!("    // {name}: {} more items not listed\n", n - 64);
                        }
                    }
                    _ => x += &format!("{at} fixed byte {name}[{}];\n", item.max(1).saturating_mul(n)),
                },
                ElemType::Pointer if n == 1 => {
                    let note = child.map(|c| format!(" // {c}*")).unwrap_or_default();
                    x += &format!("{at} IntPtr {name};{note}\n");
                }
                _ if n > 1 => x += &format!("{at} fixed {} {name}[{n}];\n", prim(e)),
                _ => x += &format!("{at} {} {name};\n", prim(e)),
            }
            i += 1;
        }
        x += "}\n\n";
    }
    x
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
    /// Bit fields: the custom type that selects the bits (overrides `vtype`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<CustomType>,
}

/// Cheat-table entries for the leaf fields of structure `name`. The structure lives at
/// address expression `addr` when `offsets` is empty, else at the end of the pointer path
/// `[[addr]+o0]+o1...` (Cheat Engine notation; `[0]` = "the structure `addr` points to").
/// `only` restricts to these top-level element indexes. Ids count up from `first_id`.
/// Arrays give one entry per item (`desc[i]`), bit fields carry a `custom` type.
pub fn to_entries(
    structs: &[Structure],
    name: &str,
    addr: &str,
    offsets: &[u64],
    ptr_size: usize,
    only: Option<&[usize]>,
    first_id: i64,
) -> Result<Vec<TableEntry>> {
    let d = Defs::new(structs);
    let s = d.find(name)?;
    let mut leaves = Vec::new();
    collect_leaves(&d, s, 0, ptr_size, &mut leaves, 0)?;
    let mut out = Vec::new();
    for (top, off, e, item) in leaves {
        if only.is_some_and(|o| !o.contains(&top)) {
            continue;
        }
        let description = match (e.description.is_empty(), item) {
            (true, _) => format!("{name}+{off:X}"),
            (false, Some(k)) => format!("{}[{k}]", e.description),
            (false, None) => e.description.clone(),
        };
        let (a, offs) = place(addr, offsets.iter().map(|o| format!("{o:X}")).collect(), offsets.last().copied(), off);
        out.push(leaf_entry(e, description, a, offs, ptr_size, first_id + out.len() as i64));
    }
    Ok(out)
}

/// Address expression and offsets of the field `off` bytes into a structure at `addr` /
/// `offsets` (the last offset, when there is one, is `last`).
fn place(addr: &str, mut offs: Vec<String>, last: Option<u64>, off: u64) -> (String, Vec<String>) {
    match last {
        None => (format!("{addr}+{off:X}"), offs),
        Some(l) => {
            offs.pop();
            offs.push(hex_signed(l.wrapping_add(off)));
            (addr.to_string(), offs)
        }
    }
}

fn hex_signed(v: u64) -> String {
    let i = v as i64;
    if i < 0 { format!("-{:X}", i.unsigned_abs()) } else { format!("{v:X}") }
}

fn leaf_entry(e: &Element, description: String, addr: String, offsets: Vec<String>, ptr_size: usize, id: i64) -> TableEntry {
    let (vtype, hex, len) = match e.vtype {
        ElemType::Pointer => (if ptr_size == 4 { VType::Bytes4 } else { VType::Bytes8 }, true, 0),
        ElemType::String => (VType::String, e.hex, if e.utf16 { e.size / 2 } else { e.size }),
        ElemType::Aob | ElemType::Struct => (VType::Aob, e.hex, e.size),
        t => (t.vtype().unwrap_or(VType::Bytes4), e.hex, 0),
    };
    TableEntry {
        id,
        description,
        addr,
        offsets,
        vtype,
        len,
        utf16: e.utf16,
        signed: e.signed,
        hex,
        children: Vec::new(),
        custom: e.bits(),
    }
}

/// Pointer auto-fill: the table entry for one field of structure `name` (at `addr` /
/// `offsets` as in [`to_entries`]) reached through `path`: element indexes, where an array
/// element is followed by the item index, and a nested-structure or pointer element by the
/// path inside its child. Pointer hops become pointer offsets (minus the element's
/// `child_start`), so the entry follows the pointers when the table is evaluated. The
/// description joins the steps with dots.
pub fn field_entry(
    structs: &[Structure],
    name: &str,
    addr: &str,
    offsets: &[u64],
    path: &[usize],
    ptr_size: usize,
    id: i64,
) -> Result<TableEntry> {
    let bad = |m: &str| Error::Other(format!("field path: {m}"));
    if path.len() > 4 * MAX_NEST {
        return Err(bad("too long"));
    }
    let d = Defs::new(structs);
    let mut s = d.find(name)?;
    let mut base = addr.to_string();
    let mut offs: Vec<String> = offsets.iter().map(|o| format!("{o:X}")).collect();
    let mut last = offsets.last().copied();
    let mut rel = 0u64;
    let mut labels = vec![s.name.clone()];
    let mut steps = path.iter().copied();
    while let Some(i) = steps.next() {
        let e = s.elements.get(i).ok_or_else(|| bad(&format!("{} has no element {i}", s.name)))?;
        e.check()?;
        let mut off = rel.wrapping_add(e.offset);
        let mut label = if e.description.is_empty() { format!("{:X}", e.offset) } else { e.description.clone() };
        if e.count > 1 {
            let k = steps.next().ok_or_else(|| bad("an array element needs an item index"))?;
            if k >= e.count {
                return Err(bad(&format!("item {k} of {}", e.count)));
            }
            off = off.wrapping_add((k as u64).wrapping_mul(d.item_size(e, ptr_size, 0) as u64));
            label += &format!("[{k}]");
        }
        labels.push(label);
        if steps.len() == 0 {
            let (a, o) = place(&base, offs, last, off);
            return Ok(leaf_entry(e, labels.join("."), a, o, ptr_size, id));
        }
        let child = e.child.as_deref().and_then(|c| d.get(c)).ok_or_else(|| bad("element has no child structure"));
        match e.vtype {
            ElemType::Struct => {
                s = child?;
                rel = off;
            }
            ElemType::Pointer => {
                s = child?;
                // Dereference the pointer at base+off; the child starts child_start before.
                (base, offs) = place(&base, offs, last, off);
                let hop = 0u64.wrapping_sub(e.child_start);
                offs.push(hex_signed(hop));
                last = Some(hop);
                rel = 0;
            }
            _ => return Err(bad("only nested structures and pointers have fields")),
        }
    }
    Err(bad("the path ends at a structure, not a field"))
}

/// (top-level element index, offset, element, array item) of every leaf.
type Leaf<'a> = (usize, u64, &'a Element, Option<usize>);

fn collect_leaves<'a>(d: &Defs<'a>, s: &'a Structure, rel: u64, ptr: usize, out: &mut Vec<Leaf<'a>>, depth: usize) -> Result<()> {
    for (i, e) in s.elements.iter().enumerate() {
        d.field()?;
        e.check()?;
        let off = rel.wrapping_add(e.offset);
        let item = d.item_size(e, ptr, depth) as u64;
        let n = e.count.max(1);
        let nested = (e.vtype == ElemType::Struct && depth < MAX_NEST)
            .then(|| e.child.as_deref().and_then(|c| d.get(c)))
            .flatten();
        for k in 0..n {
            if n > 1 {
                d.field()?;
            }
            let o = off.wrapping_add((k as u64).wrapping_mul(item));
            match nested {
                Some(c) => {
                    let start = out.len();
                    collect_leaves(d, c, o, ptr, out, depth + 1)?;
                    // Leaves of a nested struct belong to the top-level element that embeds it.
                    if depth == 0 {
                        for l in &mut out[start..] {
                            l.0 = i;
                        }
                    }
                }
                None => out.push((i, o, e, (n > 1).then_some(k))),
            }
        }
    }
    Ok(())
}
