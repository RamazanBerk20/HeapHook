//! The rest of the CE memory/process API, string and file helpers, structures (on
//! `hh_tools::structure`) and dissect code (on `hh_tools::dissect`).
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hh_core::{Addr, Module, Prot, RegionKind};
use hh_scan::{Fmt, VType};
use hh_tools::dissect::{DissectOptions, Dissection, RefKind};
use hh_tools::structure::{ElemType, Element, Structure};
use mlua::{Table, Value, Variadic};

use crate::State;
use crate::api::{B, addr, arg, int_of, need_proc, rt, str_of};

type LR<T> = mlua::Result<T>;

#[derive(Default)]
pub(crate) struct ExtState {
    structs: Mutex<StructStore>,
    dissect: Mutex<Option<Dissection>>,
}

#[derive(Default)]
struct StructStore {
    next: i64,
    items: BTreeMap<i64, Item>,
    /// The global list when the table host keeps none.
    internal: Vec<Structure>,
}

/// A structure handle: the structure, whether it is in the global list, and a stable id per
/// element (Lua element objects survive re-sorting by offset).
struct Item {
    s: Structure,
    global: bool,
    uids: Vec<i64>,
}

fn err(m: impl Into<String>) -> mlua::Error {
    mlua::Error::runtime(m.into())
}

// ---------------------------------------------------------------- memory / process

/// Windows `PAGE_*` value of a protection (CE scripts compare against these).
fn page_prot(p: Prot, cow: bool) -> i64 {
    match (p.r, p.w, p.x) {
        (_, true, true) if cow => 0x80,
        (_, true, false) if cow => 0x08,
        (_, true, true) => 0x40,
        (_, true, false) => 0x04,
        (true, false, true) | (false, false, true) => 0x20,
        (true, false, false) => 0x02,
        (false, false, false) => 0x01,
    }
}

fn install_memory(b: &B) -> LR<()> {
    // copyMemory(source, size, dest OPTIONAL, method OPTIONAL): 0 target->target, 1 target->CE,
    // 2 CE->target, 3 CE->CE. Without dest, memory is allocated in the destination.
    b.f("copyMemory", |_, st, (src, size, dst, method): (Value, i64, Option<Value>, Option<i64>)| {
        let method = method.unwrap_or(0);
        let (sl, dl) = (matches!(method, 2 | 3), matches!(method, 1 | 3));
        let (sp, dp) = (need_proc(st, sl)?, need_proc(st, dl)?);
        let size = u64::try_from(size).ok().filter(|&s| s > 0 && s <= 1 << 30).ok_or_else(|| err("copyMemory: bad size"))?;
        let src = addr(st, &src, sl).map_err(rt)?;
        let dst = match dst.filter(|v| !v.is_nil()) {
            Some(v) => addr(st, &v, dl).map_err(rt)?,
            None if dl => {
                let v = vec![0u8; size as usize].into_boxed_slice();
                Box::leak(v).as_ptr() as Addr
            }
            None => {
                let a = dp.alloc(size, Prot { r: true, w: true, x: true }, None).map_err(rt)?;
                st.allocs.lock().unwrap().insert(a, size);
                a
            }
        };
        if !sl && !dl {
            hh_tools::memory::copy(&*sp, src, dst, size).map_err(rt)?;
        } else {
            let mut buf = vec![0u8; size as usize];
            sp.read_exact(src, &mut buf).map_err(rt)?;
            dp.write(dst, &buf).map_err(rt)?;
        }
        Ok(dst as i64)
    })?;
    // compareMemory(a1, a2, size, method OPTIONAL): 0 target/target, 1 target/CE, 2 CE/CE.
    // Returns true, or false and the index of the first difference.
    b.f("compareMemory", |_, st, (a1, a2, size, method): (Value, Value, i64, Option<i64>)| {
        let method = method.unwrap_or(0);
        let (l1, l2) = (method == 2, method >= 1);
        let size = usize::try_from(size).ok().filter(|&s| s <= 1 << 30).ok_or_else(|| err("compareMemory: bad size"))?;
        let (p1, p2) = (need_proc(st, l1)?, need_proc(st, l2)?);
        let (mut x, mut y) = (vec![0u8; size], vec![0u8; size]);
        p1.read_exact(addr(st, &a1, l1).map_err(rt)?, &mut x).map_err(rt)?;
        p2.read_exact(addr(st, &a2, l2).map_err(rt)?, &mut y).map_err(rt)?;
        Ok(match x.iter().zip(&y).position(|(a, b)| a != b) {
            None => (true, None),
            Some(i) => (false, Some(i as i64)),
        })
    })?;
    b.f("enumMemoryRegions", |lua, st, ()| {
        let p = need_proc(st, false)?;
        let t = lua.create_table()?;
        for r in p.regions().map_err(rt)? {
            let e = lua.create_table()?;
            let prot = page_prot(r.prot, crate::api::is_cow(&r));
            e.set("BaseAddress", r.start as i64)?;
            e.set("AllocationBase", r.start as i64)?;
            e.set("AllocationProtect", prot)?;
            e.set("RegionSize", r.size as i64)?;
            e.set("State", 0x1000)?; // MEM_COMMIT
            e.set("Protect", prot)?;
            e.set(
                "Type",
                match r.kind {
                    RegionKind::Image => 0x100_0000,
                    RegionKind::Mapped => 0x4_0000,
                    RegionKind::Private => 0x2_0000,
                },
            )?;
            e.set("Path", r.path)?;
            t.push(e)?;
        }
        Ok(t)
    })?;
    b.f("getMemoryProtection", |lua, st, a: Value| {
        let p = need_proc(st, false)?;
        let a = addr(st, &a, false).map_err(rt)?;
        let Some(r) = p.regions().map_err(rt)?.into_iter().find(|r| a >= r.start && a - r.start < r.size) else {
            return Ok(Value::Nil);
        };
        let t = lua.create_table()?;
        t.set("R", r.prot.r)?;
        t.set("W", r.prot.w)?;
        t.set("X", r.prot.x)?;
        Ok(Value::Table(t))
    })?;
    b.f("setMemoryProtection", |_, st, (a, size, prot): (Value, i64, Table)| {
        let p = need_proc(st, false)?;
        let Ok(a) = addr(st, &a, false) else { return Ok(false) };
        let get = |k: &str| prot.get::<Option<bool>>(k).ok().flatten().unwrap_or(false);
        Ok(p.protect(a, size.max(1) as u64, Prot { r: get("R"), w: get("W"), x: get("X") }).is_ok())
    })?;
    b.f("getPointerSize", |_, st, ()| Ok(st.proc().map_or(8, |p| p.pointer_size())))?;
    b.f("readRegionFromFile", |_, st, (path, a): (String, Value)| {
        if !st.allow_os {
            return Err(err("readRegionFromFile: file access is disabled"));
        }
        let p = need_proc(st, false)?;
        let a = addr(st, &a, false).map_err(rt)?;
        let data = std::fs::read(&path).map_err(|e| err(format!("{path}: {e}")))?;
        p.write(a, &data).map_err(rt)?;
        Ok(data.len() as i64)
    })?;
    b.f("writeRegionToFile", |_, st, (path, a, size): (String, Value, i64)| {
        if !st.allow_os {
            return Err(err("writeRegionToFile: file access is disabled"));
        }
        let p = need_proc(st, false)?;
        let a = addr(st, &a, false).map_err(rt)?;
        let size = usize::try_from(size).ok().filter(|&s| s <= 1 << 30).ok_or_else(|| err("writeRegionToFile: bad size"))?;
        let mut buf = vec![0u8; size];
        p.read_exact(a, &mut buf).map_err(rt)?;
        std::fs::write(&path, &buf).map_err(|e| err(format!("{path}: {e}")))?;
        Ok(size as i64)
    })?;
    Ok(())
}

fn find_module(st: &State, v: &Value) -> Option<Module> {
    let mods = st.proc()?.modules().ok()?;
    match v {
        Value::String(s) if int_of(v).is_none() => {
            let n = s.to_string_lossy();
            mods.into_iter().find(|m| m.name.eq_ignore_ascii_case(&n))
        }
        v => {
            let a = int_of(v)? as u64;
            mods.into_iter().find(|m| a >= m.base && a - m.base < m.size)
        }
    }
}

fn install_symbols(b: &B, h: &B) -> LR<()> {
    // getSymbolInfo(name) -> {modulename, searchkey, address, symbolsize}
    b.f("getSymbolInfo", |lua, st, name: String| {
        let Ok(a) = crate::api::resolve(st, &name, false) else { return Ok(Value::Nil) };
        let p = need_proc(st, false)?;
        let mods = p.modules().unwrap_or_default();
        let m = mods.iter().find(|m| a >= m.base && a - m.base < m.size);
        let size = m
            .map(|m| hh_asm::module_symbols(&*p, m))
            .and_then(|syms| syms.into_iter().find(|s| s.addr == a).map(|s| s.size))
            .unwrap_or(0);
        let t = lua.create_table()?;
        t.set("modulename", m.map(|m| m.name.clone()).unwrap_or_default())?;
        let key = name.rsplit_once('.').filter(|_| m.is_some_and(|m| name.len() > m.name.len())).map_or(name.as_str(), |x| x.1);
        t.set("searchkey", key)?;
        t.set("address", a as i64)?;
        t.set("symbolsize", size as i64)?;
        Ok(Value::Table(t))
    })?;
    // enumExports(module name or address) -> {name = address}
    b.f("enumExports", |lua, st, v: Value| {
        let p = need_proc(st, false)?;
        let m = find_module(st, &v).ok_or_else(|| err("enumExports: module not found"))?;
        let t = lua.create_table()?;
        for s in hh_asm::module_symbols(&*p, &m) {
            t.set(s.name, s.addr as i64)?;
        }
        Ok(t)
    })?;
    h.f("threads", |lua, st, ()| {
        let p = need_proc(st, false)?;
        lua.create_sequence_from(p.threads().map_err(rt)?)
    })?;
    Ok(())
}

// ---------------------------------------------------------------- host-backed

fn install_host(b: &B, h: &B) -> LR<()> {
    b.f("createProcess", |lua, st, (path, params, debug, brk): (String, Option<String>, Option<bool>, Option<bool>)| {
        let pid = st.host().create_process(&path, &params.unwrap_or_default(), debug.unwrap_or(false), brk.unwrap_or(false)).map_err(rt)?;
        if let Ok(f) = lua.globals().get::<mlua::Function>("onOpenProcess") {
            f.call::<()>(pid)?;
        }
        Ok(pid)
    })?;
    b.f("loadTable", |_, st, (path, merge): (String, Option<bool>)| {
        st.host().load_table(&path, merge.unwrap_or(false)).map_err(rt)
    })?;
    b.f("saveTable", |_, st, (path, protect): (String, Option<bool>)| {
        st.host().save_table(&path, protect.unwrap_or(false)).map_err(rt)
    })?;
    b.f("isKeyPressed", |_, st, k: Value| Ok(int_of(&k).is_some_and(|k| st.host().is_key_pressed(k))))?;
    // The host's memscan registered like createMemScan's; returns its id.
    h.f("ms_host", |_, st, ()| {
        let Some(s) = st.host().current_memscan() else { return Ok(None) };
        let mut scans = st.scans.lock().unwrap();
        if let Some((id, _)) = scans.iter().find(|(_, x)| Arc::ptr_eq(x, &s)) {
            return Ok(Some(*id));
        }
        let id = st.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        scans.insert(id, s);
        Ok(Some(id))
    })?;
    Ok(())
}

// ---------------------------------------------------------------- strings / files

/// MD5 (RFC 1321).
pub(crate) fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4,
        11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
    let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    for chunk in msg.chunks_exact(64) {
        let m: Vec<u32> = chunk.chunks_exact(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        let [mut a, mut b, mut c, mut d] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 16];
    for (i, w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Characters 0x80..=0x9F of Windows-1252 (`\0` = undefined).
const CP1252: [char; 32] = [
    '€', '\0', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\0', 'Ž', '\0', '\0', '‘', '’', '“', '”', '•', '–', '—',
    '˜', '™', 'š', '›', 'œ', '\0', 'ž', 'Ÿ',
];

fn ansi_to_utf8(b: &[u8]) -> String {
    b.iter()
        .map(|&x| match x {
            0x80..=0x9f => Some(CP1252[x as usize - 0x80]).filter(|&c| c != '\0').unwrap_or('?'),
            _ => x as char,
        })
        .collect()
}

fn utf8_to_ansi(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match u8::try_from(c as u32) {
            Ok(b) if !(0x80..0xa0).contains(&b) => b,
            _ => CP1252.iter().position(|&x| x == c && x != '\0').map_or(b'?', |i| 0x80 + i as u8),
        })
        .collect()
}

fn split_path(p: &str) -> (&str, &str) {
    match p.rfind(['/', '\\']) {
        Some(i) => (&p[..=i], &p[i + 1..]),
        None => ("", p),
    }
}

fn install_strings(b: &B) -> LR<()> {
    b.f("stringToMD5String", |_, _, s: mlua::LuaString| Ok(hex(&md5(&s.as_bytes()))))?;
    b.f("md5memory", |_, st, (a, size): (Value, i64)| {
        let p = need_proc(st, false)?;
        let size = usize::try_from(size).ok().filter(|&s| s <= 1 << 30).ok_or_else(|| err("md5memory: bad size"))?;
        let mut buf = vec![0u8; size];
        p.read_exact(addr(st, &a, false).map_err(rt)?, &mut buf).map_err(rt)?;
        Ok(hex(&md5(&buf)))
    })?;
    b.f("md5file", |_, st, path: String| {
        if !st.allow_os {
            return Err(err("md5file: file access is disabled"));
        }
        let data = std::fs::read(&path).map_err(|e| err(format!("{path}: {e}")))?;
        Ok(hex(&md5(&data)))
    })?;
    b.f("ansiToUtf8", |_, _, s: mlua::LuaString| Ok(ansi_to_utf8(&s.as_bytes())))?;
    b.f("utf8ToAnsi", |lua, _, s: String| lua.create_string(utf8_to_ansi(&s)))?;
    b.f("extractFilePath", |_, _, p: String| Ok(split_path(&p).0.to_string()))?;
    b.f("extractFileName", |_, _, p: String| Ok(split_path(&p).1.to_string()))?;
    b.f("extractFileExt", |_, _, p: String| {
        let n = split_path(&p).1;
        Ok(n.rfind('.').map_or(String::new(), |i| n[i..].to_string()))
    })?;
    b.f("extractFileNameWithoutExt", |_, _, p: String| {
        let n = split_path(&p).1;
        Ok(n.rfind('.').map_or(n, |i| &n[..i]).to_string())
    })?;
    b.f("fileExists", |_, st, p: String| Ok(st.allow_os && std::path::Path::new(&p).is_file()))?;
    b.f("directoryExists", |_, st, p: String| Ok(st.allow_os && std::path::Path::new(&p).is_dir()))?;
    b.f("getTempFolder", |_, _, ()| {
        let mut d = std::env::temp_dir().display().to_string();
        if !d.ends_with(std::path::MAIN_SEPARATOR) {
            d.push(std::path::MAIN_SEPARATOR);
        }
        Ok(d)
    })?;
    // shellExecute(command, parameters OPTIONAL, folder OPTIONAL, showcommand OPTIONAL): starts
    // a program, or opens a document / URL with the desktop's default handler.
    b.f("shellExecute", |_, st, (cmd, params, folder, _show): (String, Option<String>, Option<String>, Option<Value>)| {
        if !st.allow_os {
            return Err(err("shellExecute: OS access is disabled"));
        }
        let params = params.unwrap_or_default();
        let path = std::path::Path::new(&cmd);
        let program = cmd.contains("://") || (path.exists() && !is_executable(path));
        let mut c = if program {
            let mut c = if cfg!(windows) {
                let mut c = std::process::Command::new("cmd");
                c.args(["/C", "start", ""]);
                c
            } else if cfg!(target_os = "macos") {
                std::process::Command::new("open")
            } else {
                std::process::Command::new("xdg-open")
            };
            c.arg(&cmd);
            c
        } else {
            let mut c = std::process::Command::new(&cmd);
            c.args(params.split_whitespace());
            c
        };
        if let Some(f) = folder.filter(|f| !f.is_empty()) {
            c.current_dir(f);
        }
        c.spawn().map(|_| true).map_err(|e| err(format!("shellExecute {cmd}: {e}")))
    })?;
    Ok(())
}

fn is_executable(p: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.extension().is_some_and(|e| ["exe", "bat", "cmd", "com"].iter().any(|x| e.eq_ignore_ascii_case(x)))
    }
}

// ---------------------------------------------------------------- structures

/// CE `vt*` <-> structure element type.
fn elem_type(vt: i64) -> Option<(ElemType, bool)> {
    Some(match vt {
        0 => (ElemType::Byte, false),
        1 => (ElemType::Bytes2, false),
        2 => (ElemType::Bytes4, false),
        3 => (ElemType::Bytes8, false),
        4 => (ElemType::Float, false),
        5 => (ElemType::Double, false),
        6 => (ElemType::String, false),
        7 => (ElemType::String, true),
        8 => (ElemType::Aob, false),
        12 => (ElemType::Pointer, false),
        _ => return None,
    })
}

fn ce_elem_type(e: &Element) -> i64 {
    match e.vtype {
        ElemType::Byte => 0,
        ElemType::Bytes2 => 1,
        ElemType::Bytes4 => 2,
        ElemType::Bytes8 => 3,
        ElemType::Float => 4,
        ElemType::Double => 5,
        ElemType::String if e.utf16 => 7,
        ElemType::String => 6,
        ElemType::Aob => 8,
        ElemType::Pointer | ElemType::Struct => 12,
    }
}

impl StructStore {
    fn globals(&self, st: &State) -> Vec<Structure> {
        st.table().structures().unwrap_or_else(|| self.internal.clone())
    }
    fn put_globals(&mut self, st: &State, list: Vec<Structure>) {
        if !st.table().set_structures(list.clone()) {
            self.internal = list;
        }
    }
    fn uid(&mut self) -> i64 {
        self.next += 1;
        self.next
    }
    fn add(&mut self, s: Structure, global: bool) -> i64 {
        let uids = (0..s.elements.len()).map(|_| self.uid()).collect();
        let id = self.uid();
        self.items.insert(id, Item { s, global, uids });
        id
    }
    fn get(&self, id: i64) -> LR<&Item> {
        self.items.get(&id).ok_or_else(|| err("structure was destroyed"))
    }
    /// The element with stable id `uid`.
    fn elem(&self, id: i64, uid: i64) -> LR<Element> {
        let it = self.get(id)?;
        let i = it.uids.iter().position(|&u| u == uid).ok_or_else(|| err("structure element was destroyed"))?;
        Ok(it.s.elements[i].clone())
    }
    /// Applies `f` to structure `id` (elements with their ids), re-sorts by offset, then
    /// writes it back to the global list if it is in it.
    fn modify<T>(&mut self, st: &State, id: i64, f: impl FnOnce(&mut Structure, &mut Vec<i64>, &mut i64) -> LR<T>) -> LR<T> {
        let mut next = self.next;
        let it = self.items.get_mut(&id).ok_or_else(|| err("structure was destroyed"))?;
        let old = it.s.name.clone();
        let r = f(&mut it.s, &mut it.uids, &mut next)?;
        let mut pairs: Vec<(Element, i64)> = std::mem::take(&mut it.s.elements).into_iter().zip(it.uids.drain(..)).collect();
        pairs.sort_by_key(|p| p.0.offset);
        (it.s.elements, it.uids) = pairs.into_iter().unzip();
        let (global, s) = (it.global, it.s.clone());
        self.next = next;
        if global {
            let mut list = self.globals(st);
            match list.iter_mut().find(|x| x.name == old) {
                Some(slot) => *slot = s,
                None => list.push(s),
            }
            self.put_globals(st, list);
        }
        Ok(r)
    }
}

fn elem_fmt(e: &Element) -> (Option<VType>, Fmt) {
    let vt = match e.vtype {
        ElemType::Byte => Some(VType::Byte),
        ElemType::Bytes2 => Some(VType::Bytes2),
        ElemType::Bytes4 => Some(VType::Bytes4),
        ElemType::Bytes8 => Some(VType::Bytes8),
        ElemType::Float => Some(VType::Float),
        ElemType::Double => Some(VType::Double),
        ElemType::String => Some(VType::String),
        ElemType::Aob => Some(VType::Aob),
        ElemType::Pointer | ElemType::Struct => None,
    };
    let size = if e.size == 0 { 16 } else { e.size };
    let len = if e.vtype == ElemType::String && e.utf16 { size / 2 } else { size };
    (vt, Fmt { len: Some(len), signed: e.signed, hex: e.hex, utf16: e.utf16 })
}

fn ptr_size(st: &State) -> u64 {
    st.proc().map_or(8, |p| p.pointer_size()) as u64
}

fn install_structures(h: &B) -> LR<()> {
    h.f("st_new", |_, st, name: String| Ok(st.ext.structs.lock().unwrap().add(Structure { name, elements: Vec::new() }, false)))?;
    h.f("st_count", |_, st, ()| Ok(st.ext.structs.lock().unwrap().globals(st).len() as i64))?;
    // Handle of the i-th global structure (0-based), refreshed from the global list.
    h.f("st_global", |_, st, i: i64| {
        let mut s = st.ext.structs.lock().unwrap();
        let list = s.globals(st);
        let Some(g) = usize::try_from(i).ok().and_then(|i| list.get(i)).cloned() else { return Ok(None) };
        if let Some(id) = s.items.iter().find(|(_, it)| it.global && it.s.name == g.name).map(|(id, _)| *id) {
            let fresh: Vec<i64> = (0..g.elements.len()).map(|_| s.uid()).collect();
            let it = s.items.get_mut(&id).unwrap();
            if it.s.elements.len() != g.elements.len() {
                it.uids = fresh;
            }
            it.s = g;
            return Ok(Some(id));
        }
        Ok(Some(s.add(g, true)))
    })?;
    h.f("st_find", |_, st, name: String| {
        let s = st.ext.structs.lock().unwrap();
        Ok(s.globals(st).iter().position(|x| x.name == name).map(|i| i as i64))
    })?;
    h.f("st_get", |lua, st, (id, key): (i64, String)| {
        let s = st.ext.structs.lock().unwrap();
        let it = s.get(id)?;
        Ok(match key.as_str() {
            "Name" => Value::String(lua.create_string(&it.s.name)?),
            "Count" => Value::Integer(it.s.elements.len() as i64),
            "Size" => {
                let mut all = s.globals(st);
                all.retain(|g| g.name != it.s.name);
                all.push(it.s.clone());
                Value::Integer(hh_tools::structure::struct_size(&all, &it.s.name, ptr_size(st) as usize).unwrap_or(0) as i64)
            }
            _ => Value::Nil,
        })
    })?;
    h.f("st_set_name", |_, st, (id, name): (i64, String)| {
        st.ext.structs.lock().unwrap().modify(st, id, |s, _, _| {
            s.name = name;
            Ok(())
        })
    })?;
    h.f("st_global_set", |_, st, (id, on): (i64, bool)| {
        let mut s = st.ext.structs.lock().unwrap();
        let it = s.items.get_mut(&id).ok_or_else(|| err("structure was destroyed"))?;
        if it.global == on {
            return Ok(());
        }
        it.global = on;
        let x = it.s.clone();
        let mut list = s.globals(st);
        list.retain(|y| y.name != x.name);
        if on {
            list.push(x);
        }
        s.put_globals(st, list);
        Ok(())
    })?;
    h.f("st_destroy", |_, st, id: i64| {
        let mut s = st.ext.structs.lock().unwrap();
        if let Some(it) = s.items.remove(&id).filter(|it| it.global) {
            let mut list = s.globals(st);
            list.retain(|y| y.name != it.s.name);
            s.put_globals(st, list);
        }
        Ok(())
    })?;
    // New 4-byte element after the last one; returns its id.
    h.f("st_add", |_, st, id: i64| {
        let ptr = ptr_size(st);
        st.ext.structs.lock().unwrap().modify(st, id, |s, uids, next| {
            let off = s.elements.iter().map(|e| e.offset + elem_len(e, ptr)).max().unwrap_or(0);
            s.elements.push(Element::new(off, ElemType::Bytes4));
            *next += 1;
            uids.push(*next);
            Ok(*next)
        })
    })?;
    h.f("st_uid_at", |_, st, (id, i): (i64, i64)| {
        let s = st.ext.structs.lock().unwrap();
        Ok(usize::try_from(i).ok().and_then(|i| s.get(id).ok()?.uids.get(i).copied()))
    })?;
    h.f("st_index_of", |_, st, (id, uid): (i64, i64)| {
        let s = st.ext.structs.lock().unwrap();
        Ok(s.get(id)?.uids.iter().position(|&u| u == uid).map(|i| i as i64))
    })?;
    // getElementByOffset: the element containing the offset.
    h.f("st_uid_by_offset", |_, st, (id, off): (i64, i64)| {
        let ptr = ptr_size(st);
        let s = st.ext.structs.lock().unwrap();
        let it = s.get(id)?;
        let off = off as u64;
        let i = it.s.elements.iter().rposition(|e| e.offset <= off && off < e.offset + elem_len(e, ptr).max(1));
        Ok(i.map(|i| it.uids[i]))
    })?;
    h.f("st_elem_get", |lua, st, (id, uid, key): (i64, i64, String)| {
        let e = st.ext.structs.lock().unwrap().elem(id, uid)?;
        Ok(match key.as_str() {
            "Offset" => Value::Integer(e.offset as i64),
            "Name" => Value::String(lua.create_string(&e.description)?),
            "Vartype" => Value::Integer(ce_elem_type(&e)),
            "Bytesize" => Value::Integer(elem_len(&e, ptr_size(st)) as i64),
            "ChildStruct" => e.child.as_deref().map(|c| lua.create_string(c).map(Value::String)).transpose()?.unwrap_or(Value::Nil),
            "DisplayMethod" => Value::String(lua.create_string(if e.hex {
                "dtHexadecimal"
            } else if e.signed {
                "dtSignedInteger"
            } else {
                "dtUnsignedInteger"
            })?),
            _ => Value::Nil,
        })
    })?;
    h.f("st_elem_set", |_, st, (id, uid, key, v): (i64, i64, String, Value)| {
        st.ext.structs.lock().unwrap().modify(st, id, |s, uids, _| {
            let i = uids.iter().position(|&u| u == uid).ok_or_else(|| err("structure element was destroyed"))?;
            let e = &mut s.elements[i];
            let bad = || err(format!("invalid value for {key}"));
            match key.as_str() {
                "Offset" => e.offset = int_of(&v).filter(|&o| o >= 0).ok_or_else(bad)? as u64,
                "Name" => e.description = str_of(&v).unwrap_or_default(),
                "Vartype" => {
                    let (t, utf16) = elem_type(int_of(&v).ok_or_else(bad)?).ok_or_else(bad)?;
                    e.vtype = t;
                    e.utf16 = utf16;
                }
                "Bytesize" => e.size = int_of(&v).filter(|&n| n >= 0).ok_or_else(bad)? as usize,
                "ChildStruct" => {
                    e.child = str_of(&v);
                    if e.child.is_some() && e.vtype != ElemType::Struct {
                        e.vtype = ElemType::Pointer;
                    }
                }
                "DisplayMethod" => {
                    let m = str_of(&v).unwrap_or_default();
                    e.hex = m == "dtHexadecimal";
                    e.signed = m == "dtSignedInteger";
                }
                _ => return Err(err(format!("unknown structure element property {key}"))),
            }
            Ok(())
        })
    })?;
    h.f("st_elem_del", |_, st, (id, uid): (i64, i64)| {
        st.ext.structs.lock().unwrap().modify(st, id, |s, uids, _| {
            if let Some(i) = uids.iter().position(|&u| u == uid) {
                s.elements.remove(i);
                uids.remove(i);
            }
            Ok(())
        })
    })?;
    // (id, uid, base address) -> formatted value or nil
    h.f("st_elem_value", |_, st, (id, uid, base): (i64, i64, Value)| {
        let p = need_proc(st, false)?;
        let base = addr(st, &base, false).map_err(rt)?;
        let e = st.ext.structs.lock().unwrap().elem(id, uid)?;
        let a = base.wrapping_add(e.offset);
        let (vt, fmt) = elem_fmt(&e);
        Ok(match vt {
            None => p.read_ptr(a).ok().map(|v| format!("{v:X}")),
            Some(vt) => {
                let mut buf = vec![0u8; hh_scan::value_size(vt, &fmt).map_err(rt)?];
                p.read_exact(a, &mut buf).ok().map(|_| hh_scan::format_value(vt, &buf, &fmt))
            }
        })
    })?;
    h.f("st_elem_setvalue", |_, st, (id, uid, base, v): (i64, i64, Value, Value)| {
        let p = need_proc(st, false)?;
        let base = addr(st, &base, false).map_err(rt)?;
        let e = st.ext.structs.lock().unwrap().elem(id, uid)?;
        let a = base.wrapping_add(e.offset);
        let v = str_of(&v).ok_or_else(|| err("setValue: value must be a string or number"))?;
        let (vt, fmt) = elem_fmt(&e);
        let r = match vt {
            None => {
                let n = hh_asm::parse_num(&v).ok_or_else(|| err("setValue: bad pointer value"))?;
                p.write(a, &n.to_le_bytes()[..p.pointer_size()])
            }
            Some(vt) => hh_scan::write_value(&*p, a, vt, &v, &fmt),
        };
        Ok(r.is_ok())
    })?;
    h.f("st_autoguess", |_, st, (id, base, offset, size): (i64, Value, Option<i64>, Option<i64>)| {
        let p = need_proc(st, false)?;
        let base = addr(st, &base, false).map_err(rt)?;
        let off = offset.unwrap_or(0).max(0) as u64;
        let size = size.unwrap_or(4096).clamp(1, 1 << 20) as usize;
        let name = st.ext.structs.lock().unwrap().get(id)?.s.name.clone();
        let g = hh_tools::structure::guess_structure(&*p, &name, base.wrapping_add(off), size).map_err(rt)?;
        st.ext.structs.lock().unwrap().modify(st, id, |s, uids, next| {
            let end = off + size as u64;
            let keep: Vec<bool> = s.elements.iter().map(|e| e.offset < off || e.offset >= end).collect();
            let mut k = keep.iter();
            s.elements.retain(|_| *k.next().unwrap());
            let mut k = keep.iter();
            uids.retain(|_| *k.next().unwrap());
            for mut e in g.elements {
                e.offset += off;
                s.elements.push(e);
                *next += 1;
                uids.push(*next);
            }
            Ok(())
        })
    })?;
    Ok(())
}

fn elem_len(e: &Element, ptr: u64) -> u64 {
    match e.vtype {
        ElemType::Byte => 1,
        ElemType::Bytes2 => 2,
        ElemType::Bytes4 | ElemType::Float => 4,
        ElemType::Bytes8 | ElemType::Double => 8,
        ElemType::Pointer => ptr,
        ElemType::String | ElemType::Aob | ElemType::Struct => {
            if e.size == 0 {
                16
            } else {
                e.size as u64
            }
        }
    }
}

// ---------------------------------------------------------------- dissect code

/// CE `jt*` reference types: 0 call, 1 unconditional jump, 2 conditional jump, 3 memory.
fn ref_type(k: RefKind) -> i64 {
    match k {
        RefKind::Call => 0,
        RefKind::Jump => 1,
        RefKind::CondJump => 2,
        RefKind::Data => 3,
    }
}

fn install_dissect(h: &B) -> LR<()> {
    // dissect(module name) or dissect(base, size)
    h.f("dc_dissect", |_, st, a: Variadic<Value>| {
        let p = need_proc(st, false)?;
        let m = match (arg(&a, 0), arg(&a, 1)) {
            (v, Value::Nil) => find_module(st, &v).ok_or_else(|| err("dissect: module not found"))?,
            (b, s) => Module {
                name: "region".into(),
                path: String::new(),
                base: addr(st, &b, false).map_err(rt)?,
                size: int_of(&s).filter(|&s| s > 0).ok_or_else(|| err("dissect: bad size"))? as u64,
            },
        };
        let d = hh_tools::dissect::dissect(&*p, &[m], &DissectOptions::default(), &hh_tools::Progress::new()).map_err(rt)?;
        *st.ext.dissect.lock().unwrap() = Some(d);
        Ok(true)
    })?;
    h.f("dc_clear", |_, st, ()| {
        *st.ext.dissect.lock().unwrap() = None;
        Ok(())
    })?;
    h.f("dc_refs", |lua, st, a: Value| {
        let a = addr(st, &a, false).map_err(rt)?;
        let g = st.ext.dissect.lock().unwrap();
        let t = lua.create_table()?;
        if let Some(d) = &*g {
            for x in d.xrefs_to(a, a.saturating_add(1), &[], 0, usize::MAX) {
                t.set(x.from as i64, ref_type(x.kind))?;
            }
        }
        Ok(t)
    })?;
    h.f("dc_strings", |lua, st, ()| {
        let g = st.ext.dissect.lock().unwrap();
        let t = lua.create_table()?;
        if let Some(d) = &*g {
            for s in d.strings(None, 0, usize::MAX) {
                t.set(s.addr as i64, s.text)?;
            }
        }
        Ok(t)
    })?;
    h.f("dc_funcs", |lua, st, ()| {
        let g = st.ext.dissect.lock().unwrap();
        let t = lua.create_table()?;
        if let Some(d) = &*g {
            for f in d.referenced_functions(0, usize::MAX) {
                t.push(f.addr as i64)?;
            }
        }
        Ok(t)
    })?;
    Ok(())
}

pub(crate) fn install(b: &B, h: &B) -> LR<()> {
    install_memory(b)?;
    install_symbols(b, h)?;
    install_host(b, h)?;
    install_strings(b)?;
    install_structures(h)?;
    install_dissect(h)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6");
        assert_eq!(hex(&md5(&[b'a'; 1000])), "cabe45dcc9ae5b66ba86600cca6b8ba8");
    }

    #[test]
    fn ansi_round_trip() {
        assert_eq!(ansi_to_utf8(&[0x80, b'a', 0xE9]), "€aé");
        assert_eq!(utf8_to_ansi("€aé✓"), vec![0x80, b'a', 0xE9, b'?']);
        assert_eq!(split_path("C:\\x\\y.txt"), ("C:\\x\\", "y.txt"));
    }

    #[test]
    fn page_protection_values() {
        assert_eq!(page_prot(Prot { r: true, w: true, x: false }, false), 0x04);
        assert_eq!(page_prot(Prot { r: true, w: false, x: true }, false), 0x20);
        assert_eq!(page_prot(Prot { r: true, w: true, x: true }, true), 0x80);
    }
}
