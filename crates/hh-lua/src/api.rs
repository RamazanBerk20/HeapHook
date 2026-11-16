//! Rust side of the Cheat Engine Lua API. Object wrappers (timers, memory records, memscan,
//! string lists, ...) live in `prelude.lua` on top of these primitives.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use hh_asm::{AaHooks, AaState, Ctx, SymbolTable};
use hh_core::{Addr, Error, Process, Prot, Region, RegionKind, Result};
use hh_scan::{CustomType, FirstScan, NextScan, NextScanEx, Rounding, ScanOptions, ScanType, Scanner, Tri, VType};
use mlua::{AnyUserData, FromLuaMulti, Function, IntoLuaMulti, Lua, MultiValue, Table, Value, Variadic};

use crate::{Internals, RecId, Record, STUBS, State, guard, stub_message};

type LR<T> = mlua::Result<T>;

const PRELUDE: &str = include_str!("prelude.lua");

/// Plain message of an mlua error (no "runtime error:" / "callback error" wrapping).
pub(crate) fn err_text(e: &mlua::Error) -> String {
    match e {
        mlua::Error::CallbackError { cause, .. } => err_text(cause),
        mlua::Error::RuntimeError(m) => m.clone(),
        mlua::Error::WithContext { context, cause } => format!("{context}: {}", err_text(cause)),
        e => e.to_string(),
    }
}

/// Text of a Lua error value.
pub(crate) fn value_text(lua: &Lua, v: &Value) -> String {
    match v {
        Value::String(s) => s.to_string_lossy(),
        Value::Error(e) => err_text(e),
        v => lua
            .globals()
            .get::<Function>("tostring")
            .and_then(|f| f.call::<String>(v.clone()))
            .unwrap_or_default(),
    }
}

pub(crate) fn rt(e: Error) -> mlua::Error {
    mlua::Error::runtime(e.to_string())
}

/// CE `mb*` button -> the `mr*` result clicking it gives (for [`crate::Host::message_dialog`]
/// implementations).
pub fn button_result(mb: i64) -> i64 {
    match mb {
        0 => 6,
        1 => 7,
        2 => 1,
        3 => 2,
        4 => 3,
        5 => 4,
        6 => 5,
        7 => 8,
        8 => 9,
        9 => 10,
        11 => 11,
        _ => 0,
    }
}

pub(crate) struct B<'a> {
    pub(crate) lua: &'a Lua,
    pub(crate) t: Table,
    pub(crate) st: &'a Arc<State>,
    pub(crate) names: std::cell::RefCell<Vec<String>>,
}

impl B<'_> {
    pub(crate) fn f<A, R, F>(&self, name: &str, f: F) -> LR<()>
    where
        A: FromLuaMulti,
        R: IntoLuaMulti,
        F: Fn(&Lua, &Arc<State>, A) -> LR<R> + Send + 'static,
    {
        let st = self.st.clone();
        self.names.borrow_mut().push(name.to_string());
        self.t.set(name, self.lua.create_function(move |lua, a: A| f(lua, &st, a))?)
    }
}

// ---------------------------------------------------------------- argument helpers

pub(crate) fn int_of(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => Some(*i),
        Value::Number(n) if n.is_finite() => Some(*n as i64),
        Value::Boolean(b) => Some(*b as i64),
        Value::String(s) => {
            let s = s.to_str().ok()?;
            let t = s.trim();
            match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok().map(|u| u as i64),
                None => t.parse::<i64>().ok().or_else(|| t.parse::<f64>().ok().map(|f| f as i64)),
            }
        }
        _ => None,
    }
}

pub(crate) fn num_of(v: &Value) -> Option<f64> {
    match v {
        Value::Integer(i) => Some(*i as f64),
        Value::Number(n) => Some(*n),
        Value::String(s) => s.to_str().ok()?.trim().parse().ok(),
        _ => None,
    }
}

pub(crate) fn str_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.to_string_lossy()),
        Value::Integer(i) => Some(i.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub(crate) fn truthy(v: &Value) -> bool {
    !matches!(v, Value::Nil | Value::Boolean(false))
}

pub(crate) fn arg(a: &[Value], i: usize) -> Value {
    a.get(i).cloned().unwrap_or(Value::Nil)
}

pub(crate) fn resolve(st: &State, expr: &str, local: bool) -> Result<Addr> {
    let syms = if local { SymbolTable::default() } else { st.syms.lock().unwrap().clone() };
    match st.target(local) {
        Some(p) => hh_asm::resolve_address(&*p, &syms, expr),
        None => {
            let lookup = |n: &str| syms.get(n);
            hh_asm::eval(expr, &Ctx { lookup: &lookup, mem: None })
        }
    }
}

/// CE functions take an address as a number or as an address expression string.
pub(crate) fn addr(st: &State, v: &Value, local: bool) -> Result<Addr> {
    match v {
        Value::Integer(i) => Ok(*i as u64),
        Value::Number(n) if n.is_finite() => Ok(*n as i64 as u64),
        Value::String(s) => resolve(st, &s.to_string_lossy(), local),
        _ => Err(Error::Parse("invalid address".into())),
    }
}

pub(crate) fn need_proc(st: &State, local: bool) -> LR<Arc<dyn Process>> {
    st.target(local).ok_or_else(|| {
        mlua::Error::runtime(if local && !st.allow_os { "access to HeapHook's own memory is disabled" } else { "no process opened" })
    })
}

pub(crate) fn bytes_table(lua: &Lua, b: &[u8]) -> LR<Table> {
    lua.create_sequence_from(b.iter().copied())
}

// ---------------------------------------------------------------- process

pub(crate) fn set_process(lua: &Lua, st: &State, p: Option<Arc<dyn Process>>) -> LR<()> {
    let name = p.as_ref().and_then(|p| {
        let pid = p.pid();
        hh_core::list_processes().ok()?.into_iter().find(|i| i.pid == pid).map(|i| i.name)
    });
    *st.proc.write().unwrap() = p;
    st.allocs.lock().unwrap().clear();
    lua.globals().set("process", name)
}

fn install_process(b: &B) -> LR<()> {
    let list = |lua: &Lua, _: &Arc<State>, _: MultiValue| {
        let t = lua.create_table()?;
        for p in hh_core::list_processes().map_err(rt)? {
            t.set(p.pid, p.name)?;
        }
        Ok(t)
    };
    b.f("getProcessList", list)?;
    b.f("getProcesslist", list)?;
    b.f("openProcess", |lua, st, v: Value| {
        let pid = match &v {
            Value::String(s) if int_of(&v).is_none() => {
                let name = s.to_string_lossy();
                let Some(pid) = pid_of(&name) else { return Ok(false) };
                pid
            }
            v => match int_of(v) {
                Some(p) => p as u32,
                None => return Ok(false),
            },
        };
        let Ok(p) = hh_core::open(pid) else { return Ok(false) };
        set_process(lua, st, Some(p))?;
        if let Ok(f) = lua.globals().get::<Function>("onOpenProcess") {
            f.call::<()>(pid)?;
        }
        Ok(true)
    })?;
    b.f("getOpenedProcessID", |_, st, ()| Ok(st.proc().map_or(0, |p| p.pid())))?;
    b.f("getProcessIDFromProcessName", |_, _, name: String| Ok(pid_of(&name)))?;
    b.f("targetIs64Bit", |_, st, ()| Ok(st.proc().is_none_or(|p| p.pointer_size() == 8)))?;
    b.f("enumModules", |lua, st, _: MultiValue| {
        let p = need_proc(st, false)?;
        let t = lua.create_table()?;
        for m in p.modules().unwrap_or_default() {
            let e = lua.create_table()?;
            e.set("Name", m.name)?;
            e.set("Address", m.base as i64)?;
            e.set("Size", m.size as i64)?;
            e.set("Is64Bit", p.pointer_size() == 8)?;
            e.set("PathToFile", m.path)?;
            t.push(e)?;
        }
        Ok(t)
    })?;
    b.f("getAddress", |_, st, (v, local): (Value, Option<bool>)| {
        addr(st, &v, local.unwrap_or(false)).map(|a| a as i64).map_err(|_| {
            mlua::Error::runtime(format!("Failure determining what {} means", str_of(&v).unwrap_or_default()))
        })
    })?;
    b.f("getAddressSafe", |_, st, (v, local): (Value, Option<bool>)| {
        Ok(addr(st, &v, local.unwrap_or(false)).ok().map(|a| a as i64))
    })?;
    b.f("getNameFromAddress", |_, st, (v, mods, syms): (Value, Option<bool>, Option<bool>)| {
        let a = addr(st, &v, false).map_err(rt)?;
        if syms.unwrap_or(true)
            && let Some((n, _)) = st.syms.lock().unwrap().iter().find(|(_, x)| *x == a)
        {
            return Ok(n.to_string());
        }
        if mods.unwrap_or(true)
            && let Some(p) = st.proc()
            && let Some(s) = hh_asm::module_offset(&p.modules().unwrap_or_default(), a)
        {
            return Ok(s);
        }
        Ok(format!("{a:X}"))
    })?;
    b.f("inModule", |_, st, v: Value| {
        let Ok(a) = addr(st, &v, false) else { return Ok(false) };
        let mods = st.proc().and_then(|p| p.modules().ok()).unwrap_or_default();
        Ok(mods.iter().any(|m| a >= m.base && a - m.base < m.size))
    })?;
    b.f("getModuleSize", |_, st, name: String| {
        let mods = st.proc().and_then(|p| p.modules().ok()).unwrap_or_default();
        Ok(mods.iter().find(|m| m.name.eq_ignore_ascii_case(&name)).map(|m| m.size as i64))
    })?;
    b.f("registerSymbol", |_, st, (name, v, _nosave): (String, Value, Option<bool>)| {
        let a = addr(st, &v, false).map_err(rt)?;
        st.syms.lock().unwrap().register(&name, a);
        Ok(())
    })?;
    b.f("unregisterSymbol", |_, st, name: String| {
        st.syms.lock().unwrap().unregister(&name);
        Ok(())
    })?;
    b.f("pause", |_, st, ()| Ok(need_proc(st, false)?.suspend().is_ok()))?;
    b.f("unpause", |_, st, ()| Ok(need_proc(st, false)?.resume().is_ok()))?;
    Ok(())
}

fn pid_of(name: &str) -> Option<u32> {
    hh_core::list_processes()
        .ok()?
        .into_iter()
        .filter(|p| p.name.eq_ignore_ascii_case(name))
        .map(|p| p.pid)
        .next_back()
}

// ---------------------------------------------------------------- memory

/// Most values `readBytes` returns as separate results (the table form has no limit).
const MAX_MULTI: usize = 8000;

fn install_memory(b: &B) -> LR<()> {
    for local in [false, true] {
        let sfx = if local { "Local" } else { "" };
        // size 0 = pointer size
        for (name, size) in [
            ("readByte", 1usize),
            ("readShortInteger", 1),
            ("readSmallInteger", 2),
            ("readInteger", 4),
            ("readQword", 8),
            ("readPointer", 0),
        ] {
            b.f(&format!("{name}{sfx}"), move |_, st, (a, signed): (Value, Option<bool>)| {
                let Some(p) = st.target(local) else { return Ok(None) };
                let Ok(a) = addr(st, &a, local) else { return Ok(None) };
                let n = if size == 0 { p.pointer_size() } else { size };
                let mut b = [0u8; 8];
                if p.read_exact(a, &mut b[..n]).is_err() {
                    return Ok(None);
                }
                let u = u64::from_le_bytes(b);
                let sh = 64 - 8 * n as u32;
                Ok(Some(if signed.unwrap_or(false) && n < 8 { ((u << sh) as i64) >> sh } else { u as i64 }))
            })?;
        }
        for (name, size) in [
            ("writeByte", 1usize),
            ("writeShortInteger", 1),
            ("writeSmallInteger", 2),
            ("writeInteger", 4),
            ("writeQword", 8),
            ("writePointer", 0),
        ] {
            b.f(&format!("{name}{sfx}"), move |_, st, (a, v): (Value, Value)| {
                let (Some(p), Some(v)) = (st.target(local), int_of(&v)) else { return Ok(false) };
                let Ok(a) = addr(st, &a, local) else { return Ok(false) };
                let n = if size == 0 { p.pointer_size() } else { size };
                Ok(p.write(a, &v.to_le_bytes()[..n]).is_ok())
            })?;
        }
        b.f(&format!("readFloat{sfx}"), move |_, st, a: Value| {
            let mut b = [0u8; 4];
            Ok(read_into(st, &a, local, &mut b).then(|| f32::from_le_bytes(b) as f64))
        })?;
        b.f(&format!("readDouble{sfx}"), move |_, st, a: Value| {
            let mut b = [0u8; 8];
            Ok(read_into(st, &a, local, &mut b).then(|| f64::from_le_bytes(b)))
        })?;
        b.f(&format!("writeFloat{sfx}"), move |_, st, (a, v): (Value, Value)| {
            Ok(num_of(&v).is_some_and(|v| write_at(st, &a, local, &(v as f32).to_le_bytes())))
        })?;
        b.f(&format!("writeDouble{sfx}"), move |_, st, (a, v): (Value, Value)| {
            Ok(num_of(&v).is_some_and(|v| write_at(st, &a, local, &v.to_le_bytes())))
        })?;
        b.f(&format!("readBytes{sfx}"), move |lua, st, (a, n, as_table): (Value, Option<i64>, Option<bool>)| {
            let mut b = vec![0u8; n.unwrap_or(1).clamp(0, 1 << 26) as usize];
            if !read_into(st, &a, local, &mut b) {
                return Ok(MultiValue::from_iter([Value::Nil]));
            }
            if as_table.unwrap_or(false) {
                return Ok(MultiValue::from_iter([Value::Table(bytes_table(lua, &b)?)]));
            }
            if b.len() > MAX_MULTI {
                return Err(mlua::Error::runtime(format!(
                    "readBytes: {} values is too many to return separately (max {MAX_MULTI}); pass true as the third argument to get a table",
                    b.len()
                )));
            }
            Ok(b.into_iter().map(|x| Value::Integer(x as i64)).collect())
        })?;
        b.f(&format!("writeBytes{sfx}"), move |_, st, args: Variadic<Value>| {
            let mut data = Vec::new();
            for v in args.iter().skip(1) {
                match v {
                    Value::Table(t) => {
                        for x in t.sequence_values::<Value>() {
                            data.push(int_of(&x?).unwrap_or(0) as u8);
                        }
                    }
                    v => data.push(int_of(v).unwrap_or(0) as u8),
                }
            }
            Ok(write_at(st, &arg(&args, 0), local, &data))
        })?;
        b.f(&format!("readString{sfx}"), move |lua, st, (a, max, wide): (Value, Option<i64>, Option<bool>)| {
            let (Some(p), Ok(a)) = (st.target(local), addr(st, &a, local)) else { return Ok(None) };
            let wide = wide.unwrap_or(false);
            let max = max.unwrap_or(50000).clamp(0, 1 << 24) as usize;
            let mut b = vec![0u8; if wide { max * 2 } else { max }];
            let Ok(n) = p.read(a, &mut b) else { return Ok(None) };
            b.truncate(n);
            if wide {
                let u: Vec<u16> =
                    b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
                return Ok(Some(lua.create_string(String::from_utf16_lossy(&u))?));
            }
            let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            Ok(Some(lua.create_string(&b[..end])?))
        })?;
        b.f(&format!("writeString{sfx}"), move |_, st, (a, s, wide): (Value, mlua::LuaString, Option<bool>)| {
            let data: Vec<u8> = if wide.unwrap_or(false) {
                s.to_string_lossy().encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
            } else {
                s.as_bytes().to_vec()
            };
            Ok(write_at(st, &a, local, &data))
        })?;
    }
    b.f("allocateMemory", |_, st, (size, base, prot): (i64, Option<Value>, Option<i64>)| {
        let p = need_proc(st, false)?;
        let near = base.and_then(|v| addr(st, &v, false).ok()).filter(|&a| a != 0);
        // CE protection constants are Windows PAGE_* values; only "no execute" is honoured.
        let x = !matches!(prot, Some(0x02 | 0x04));
        let size = size.max(1) as u64;
        match p.alloc(size, Prot { r: true, w: true, x }, near) {
            Ok(a) => {
                st.allocs.lock().unwrap().insert(a, size);
                Ok(Some(a as i64))
            }
            Err(_) => Ok(None),
        }
    })?;
    b.f("deAlloc", |_, st, (a, size): (Value, Option<i64>)| {
        let p = need_proc(st, false)?;
        let Ok(a) = addr(st, &a, false) else { return Ok(false) };
        let known = st.allocs.lock().unwrap().remove(&a);
        let size = known.or(size.map(|s| s as u64)).unwrap_or(0x1000);
        Ok(p.free(a, size).is_ok())
    })?;
    b.f("fullAccess", |_, st, (a, size): (Value, i64)| {
        let p = need_proc(st, false)?;
        let Ok(a) = addr(st, &a, false) else { return Ok(false) };
        Ok(p.protect(a, size.max(1) as u64, Prot { r: true, w: true, x: true }).is_ok())
    })?;
    Ok(())
}

pub(crate) fn read_into(st: &State, a: &Value, local: bool, buf: &mut [u8]) -> bool {
    let (Some(p), Ok(a)) = (st.target(local), addr(st, a, local)) else { return false };
    p.read_exact(a, buf).is_ok()
}

pub(crate) fn write_at(st: &State, a: &Value, local: bool, data: &[u8]) -> bool {
    let (Some(p), Ok(a)) = (st.target(local), addr(st, a, local)) else { return false };
    p.write(a, data).is_ok()
}

// ---------------------------------------------------------------- scanning

/// `"+W-C*X"`: + must have, - must not have, * don't care. Returns (W, X, C).
pub(crate) fn prot_flags(s: Option<&str>) -> (Tri, Tri, Tri) {
    let (mut w, mut x, mut c) = (Tri::Any, Tri::Any, Tri::Any);
    let mut sign = Tri::Yes;
    for ch in s.unwrap_or("").chars() {
        match ch.to_ascii_uppercase() {
            '+' => sign = Tri::Yes,
            '-' => sign = Tri::No,
            '*' => sign = Tri::Any,
            'W' => w = sign,
            'X' => x = sign,
            'C' => c = sign,
            _ => {}
        }
    }
    (w, x, c)
}

pub(crate) fn tri_ok(t: Tri, v: bool) -> bool {
    match t {
        Tri::Yes => v,
        Tri::No => !v,
        Tri::Any => true,
    }
}

pub(crate) fn is_cow(r: &Region) -> bool {
    r.prot.w && !r.shared && matches!(r.kind, RegionKind::Image | RegionKind::Mapped)
}

/// fsmNotAligned = 0, fsmAligned = 1 (param = hex alignment), fsmLastDigits = 2.
fn align_ok(a: Addr, kind: i64, param: &str) -> bool {
    let n = u64::from_str_radix(param.trim(), 16).unwrap_or(1);
    match kind {
        1 => n == 0 || a.is_multiple_of(n),
        2 => {
            let digits = param.trim().len() as u32;
            digits == 0 || a % 16u64.pow(digits.min(15)) == n
        }
        _ => true,
    }
}

struct AobReq<'a> {
    pattern: &'a str,
    flags: Option<String>,
    align: i64,
    param: String,
    range: (Addr, Addr),
}

fn aob(st: &State, r: &AobReq, max: usize) -> Result<Vec<Addr>> {
    let p = st.proc().ok_or(Error::Other("no process opened".into()))?;
    let (w, x, c) = prot_flags(r.flags.as_deref());
    let mut hits = Vec::new();
    for reg in p.regions()? {
        if !reg.prot.r || !tri_ok(w, reg.prot.w) || !tri_ok(x, reg.prot.x) || !tri_ok(c, is_cow(&reg)) {
            continue;
        }
        let (lo, hi) = (reg.start.max(r.range.0), reg.start.saturating_add(reg.size).min(r.range.1));
        if lo >= hi {
            continue;
        }
        let found = hh_asm::aob_scan(&*p, lo, hi, r.pattern, usize::MAX)?;
        hits.extend(found.into_iter().filter(|&a| align_ok(a, r.align, &r.param)));
        if hits.len() >= max {
            hits.truncate(max);
            break;
        }
    }
    Ok(hits)
}

fn module_range(st: &State, name: &str) -> Option<(Addr, Addr)> {
    let p = st.proc()?;
    let mods = p.modules().ok()?;
    let m = mods.iter().find(|m| m.name.eq_ignore_ascii_case(name))?;
    Some((m.base, m.base + m.size))
}

pub(crate) fn ce_vtype(n: i64) -> Option<(VType, bool)> {
    Some(match n {
        0 => (VType::Byte, false),
        1 => (VType::Bytes2, false),
        2 => (VType::Bytes4, false),
        3 => (VType::Bytes8, false),
        4 => (VType::Float, false),
        5 => (VType::Double, false),
        6 => (VType::String, false),
        7 => (VType::String, true),
        8 => (VType::Aob, false),
        9 => (VType::Binary, false),
        10 => (VType::All, false),
        14 => (VType::Grouped, false),
        _ => return None,
    })
}

fn ce_scan_type(n: i64) -> LR<ScanType> {
    Ok(match n {
        0 => ScanType::Unknown,
        1 => ScanType::Exact,
        2 => ScanType::Between,
        3 => ScanType::Bigger,
        4 => ScanType::Smaller,
        5 => ScanType::Increased,
        6 => ScanType::IncreasedBy,
        7 => ScanType::Decreased,
        8 => ScanType::DecreasedBy,
        9 => ScanType::Changed,
        10 => ScanType::Unchanged,
        n => return Err(mlua::Error::runtime(format!("invalid scan option {n}"))),
    })
}

/// A custom type from a preset name (`'4 byte big endian'`) or a table with
/// `hh_scan::CustomType`'s fields (`size`, `big_endian`, `float`, `signed`, `scale`, `offset`,
/// `bit_start`, `bit_len`, `binary`).
fn custom_type(v: &Value) -> LR<CustomType> {
    let ct = match v {
        Value::String(s) => {
            let n = s.to_string_lossy();
            CustomType::preset(&n).ok_or_else(|| mlua::Error::runtime(format!("unknown custom type {n}")))?
        }
        Value::Table(t) => {
            let g = |k: &str| t.get::<Value>(k).unwrap_or(Value::Nil);
            let mut ct = CustomType::int(int_of(&g("size")).unwrap_or(4).clamp(0, 255) as u8, truthy(&g("signed")));
            ct.big_endian = truthy(&g("big_endian"));
            ct.float = truthy(&g("float"));
            ct.scale = num_of(&g("scale")).unwrap_or(1.0);
            ct.offset = num_of(&g("offset")).unwrap_or(0.0);
            ct.bit_start = int_of(&g("bit_start")).unwrap_or(0).clamp(0, 255) as u8;
            ct.bit_len = int_of(&g("bit_len")).unwrap_or(0).clamp(0, 255) as u8;
            ct.binary = truthy(&g("binary"));
            ct
        }
        _ => return Err(mlua::Error::runtime("vtCustom scan: set memscan.CustomType first")),
    };
    ct.validate().map_err(rt)?;
    Ok(ct)
}

pub(crate) fn scanner(st: &State, id: i64) -> LR<Arc<Scanner>> {
    st.scans.lock().unwrap().get(&id).cloned().ok_or_else(|| mlua::Error::runtime("memscan was destroyed"))
}

fn install_scan(b: &B, h: &B) -> LR<()> {
    h.f("aobscan", |lua, st, a: Variadic<Value>| {
        let Some(pattern) = str_of(&arg(&a, 0)) else { return Ok(None) };
        let req = AobReq {
            pattern: &pattern,
            flags: str_of(&arg(&a, 1)),
            align: int_of(&arg(&a, 2)).unwrap_or(0),
            param: str_of(&arg(&a, 3)).unwrap_or_default(),
            range: (0, u64::MAX),
        };
        let hits = aob(st, &req, usize::MAX).map_err(rt)?;
        Ok(Some(lua.create_sequence_from(hits.into_iter().map(|a| a as i64))?))
    })?;
    b.f("AOBScanUnique", |_, st, a: Variadic<Value>| {
        let Some(pattern) = str_of(&arg(&a, 0)) else { return Ok(None) };
        let req = AobReq {
            pattern: &pattern,
            flags: str_of(&arg(&a, 1)),
            align: int_of(&arg(&a, 2)).unwrap_or(0),
            param: str_of(&arg(&a, 3)).unwrap_or_default(),
            range: (0, u64::MAX),
        };
        let hits = aob(st, &req, 2).map_err(rt)?;
        Ok((hits.len() == 1).then(|| hits[0] as i64))
    })?;
    b.f("AOBScanModuleUnique", |_, st, a: Variadic<Value>| {
        let (Some(module), Some(pattern)) = (str_of(&arg(&a, 0)), str_of(&arg(&a, 1))) else { return Ok(None) };
        let Some(range) = module_range(st, &module) else { return Ok(None) };
        let req = AobReq {
            pattern: &pattern,
            flags: str_of(&arg(&a, 2)),
            align: int_of(&arg(&a, 3)).unwrap_or(0),
            param: str_of(&arg(&a, 4)).unwrap_or_default(),
            range,
        };
        let hits = aob(st, &req, 2).map_err(rt)?;
        Ok((hits.len() == 1).then(|| hits[0] as i64))
    })?;

    h.f("ms_new", |_, st, ()| {
        let p = need_proc(st, false)?;
        let id = st.next_id.fetch_add(1, Ordering::SeqCst);
        st.scans.lock().unwrap().insert(id, Arc::new(Scanner::new(p)));
        Ok(id)
    })?;
    h.f("ms_free", |_, st, id: i64| {
        st.scans.lock().unwrap().remove(&id);
        Ok(())
    })?;
    h.f("ms_newscan", |_, st, id: i64| {
        scanner(st, id)?.new_scan();
        Ok(())
    })?;
    h.f("ms_count", |_, st, id: i64| Ok(scanner(st, id)?.count() as i64))?;
    // (id, scanoption, vartype, roundingtype, input1, input2, start, stop, protectionflags,
    //  alignmenttype, alignmentparam, isHex, isNotABinaryString, isUnicode, isCaseSensitive,
    //  customtype, not)
    h.f("ms_first", |_, st, a: Variadic<Value>| {
        let s = scanner(st, int_of(&arg(&a, 0)).unwrap_or(0))?;
        let vt = int_of(&arg(&a, 2)).unwrap_or(2);
        let custom = if vt == 13 { Some(custom_type(&arg(&a, 15))?) } else { None };
        let (vtype, utf16) = if custom.is_some() {
            (VType::Bytes4, false)
        } else {
            ce_vtype(vt).ok_or_else(|| mlua::Error::runtime("unsupported variable type"))?
        };
        let (w, x, c) = prot_flags(str_of(&arg(&a, 8)).as_deref());
        let param = str_of(&arg(&a, 10)).unwrap_or_default();
        let atype = int_of(&arg(&a, 9)).unwrap_or(1);
        let start = int_of(&arg(&a, 6)).map(|v| v as u64);
        let stop = int_of(&arg(&a, 7)).map(|v| v as u64).filter(|&v| v != 0);
        let opts = ScanOptions {
            start,
            stop,
            writable: w,
            executable: x,
            copy_on_write: c,
            alignment: match atype {
                0 => Some(1),
                1 => u64::from_str_radix(param.trim(), 16).ok().filter(|&n| n > 0),
                _ => None,
            },
            last_digits: (atype == 2).then(|| param.clone()),
            hex: truthy(&arg(&a, 11)),
            utf16: utf16 || truthy(&arg(&a, 13)),
            case_sensitive: truthy(&arg(&a, 14)),
            rounding: match int_of(&arg(&a, 3)).unwrap_or(0) {
                1 => Rounding::Extreme,
                2 => Rounding::Truncated,
                _ => Rounding::Rounded,
            },
            custom,
            ..ScanOptions::default()
        };
        let req = FirstScan {
            vtype,
            scan_type: ce_scan_type(int_of(&arg(&a, 1)).unwrap_or(1))?,
            value: str_of(&arg(&a, 4)),
            value2: str_of(&arg(&a, 5)),
            not: truthy(&arg(&a, 16)),
            opts,
        };
        Ok(s.first_scan(&req).map_err(rt)?.count as i64)
    })?;
    // (id, scanoption, roundingtype, input1, input2, isHex, isNotABinaryString, isUnicode,
    //  isCaseSensitive, isPercentage, savedResultName, not)
    h.f("ms_next", |_, st, a: Variadic<Value>| {
        let s = scanner(st, int_of(&arg(&a, 0)).unwrap_or(0))?;
        let req = NextScanEx {
            scan: NextScan {
                scan_type: ce_scan_type(int_of(&arg(&a, 1)).unwrap_or(1))?,
                value: str_of(&arg(&a, 3)),
                value2: str_of(&arg(&a, 4)),
                not: truthy(&arg(&a, 11)),
                percent: Some(truthy(&arg(&a, 9))),
            },
            compare_to: str_of(&arg(&a, 10)).filter(|n| !n.is_empty()),
        };
        Ok(s.next_scan_ex(&req).map_err(rt)?.count as i64)
    })?;
    h.f("ms_save", |_, st, (id, name): (i64, String)| scanner(st, id)?.save_scan(&name).map_err(rt))?;
    h.f("ms_saved", |_, st, id: i64| Ok(scanner(st, id)?.saved_scans()))?;
    h.f("ms_delsaved", |_, st, (id, name): (i64, String)| scanner(st, id)?.delete_saved_scan(&name).map_err(rt))?;
    h.f("ms_row", |_, st, (id, i): (i64, i64)| {
        let rows = scanner(st, id)?.results(i.max(0) as u64, 1).map_err(rt)?;
        Ok(match rows.into_iter().next() {
            Some(r) => (Some(r.addr as i64), r.value),
            None => (None, None),
        })
    })?;
    Ok(())
}

// ---------------------------------------------------------------- assembler

/// Runs an AA script with `{$lua}` support, merging symbol changes into the shared table
/// (the shared table cannot stay locked while Lua blocks run).
fn aa_run(
    lua: &Lua,
    st: &Arc<State>,
    p: &dyn Process,
    script: &str,
    enable: bool,
    prev: Option<&AaState>,
    memrec: Option<RecId>,
) -> Result<AaState> {
    let before = st.syms.lock().unwrap().clone();
    let mut work = before.clone();
    let mut hooks = AaHooks {
        lua: Some(lua_block_hook(lua.clone(), st.clone(), memrec, false)),
        ..Default::default()
    };
    let r = hh_asm::aa_execute(p, &mut work, script, enable, prev, &mut hooks);
    let mut cur = st.syms.lock().unwrap();
    for (n, a) in work.iter() {
        if before.get(n) != Some(a) {
            cur.register(n, a);
        }
    }
    let gone: Vec<String> = before.iter().filter(|(n, _)| work.get(n).is_none()).map(|(n, _)| n.to_string()).collect();
    for n in gone {
        cur.unregister(&n);
    }
    r
}

pub(crate) fn lua_block_hook(
    lua: Lua,
    st: Arc<State>,
    memrec: Option<RecId>,
    check: bool,
) -> Box<dyn FnMut(String) -> Result<String>> {
    Box::new(move |src: String| {
        let _g = guard(&st);
        let run = || -> LR<Value> {
            let g = lua.globals();
            let old: (Value, Value) = (g.get("memrec")?, g.get("syntaxcheck")?);
            let mr = match memrec {
                Some(id) => lua.named_registry_value::<Function>("hh_mr")?.call::<Value>(id)?,
                None => Value::Nil,
            };
            g.set("memrec", mr)?;
            g.set("syntaxcheck", check)?;
            let r = lua.load(&src).set_name("={$lua}").set_mode(mlua::chunk::ChunkMode::Text).into_function().and_then(|f| f.call::<Value>(())); // call, not eval: `eval` would turn a bare call statement into `return call()`
            g.set("memrec", old.0)?;
            g.set("syntaxcheck", old.1)?;
            r
        };
        match run() {
            Ok(Value::Nil) => Ok(String::new()),
            Ok(v) => str_of(&v).ok_or_else(|| Error::Other("{$lua} block must return a string or nil".into())),
            Err(e) => Err(Error::Other(format!("lua: {}", err_text(&e)))),
        }
    })
}

fn install_asm(b: &B) -> LR<()> {
    b.f("autoAssemble", |lua, st, (text, a2, a3): (String, Value, Value)| {
        let (local, info) = match (a2, a3) {
            (Value::Boolean(l), i) => (l, i),
            (i @ Value::Table(_), _) => (false, i),
            (_, i) => (false, i),
        };
        let p = match need_proc(st, local) {
            Ok(p) => p,
            Err(e) => return (false, err_text(&e)).into_lua_multi(lua),
        };
        let prev = match &info {
            Value::Table(t) => Some(t.get::<AnyUserData>("__state")?.borrow::<AaState>()?.clone()),
            _ => None,
        };
        let enable = prev.is_none();
        match aa_run(lua, st, &*p, &text, enable, prev.as_ref(), None) {
            Ok(s) if enable => {
                let t = lua.create_table()?;
                let allocs = lua.create_table()?;
                for a in &s.allocs {
                    let e = lua.create_table()?;
                    e.set("address", a.addr as i64)?;
                    e.set("size", a.size as i64)?;
                    allocs.set(a.name.as_str(), e)?;
                }
                t.set("allocs", allocs)?;
                t.set("registeredsymbols", lua.create_sequence_from(s.registered.iter().map(|r| r.0.clone()))?)?;
                t.set("__state", lua.create_any_userdata(s)?)?;
                (true, t).into_lua_multi(lua)
            }
            Ok(_) => true.into_lua_multi(lua),
            Err(e) => (false, e.to_string()).into_lua_multi(lua),
        }
    })?;
    b.f("autoAssembleCheck", |lua, st, (text, _enable, local): (String, Option<bool>, Option<bool>)| {
        let local = local.unwrap_or(false);
        let Some(p) = st.target(local).or_else(|| st.target(true)) else {
            return (false, "no process opened").into_lua_multi(lua);
        };
        let syms = st.syms.lock().unwrap().clone();
        let mut hooks = AaHooks {
            lua: Some(lua_block_hook(lua.clone(), st.clone(), None, true)),
            ..Default::default()
        };
        match hh_asm::aa_check(&*p, &syms, &text, &mut hooks) {
            None => true.into_lua_multi(lua),
            Some(e) => (false, format!("line {}: {}", e.line, e.message)).into_lua_multi(lua),
        }
    })?;
    b.f("assemble", |lua, st, (text, a): (String, Option<Value>)| {
        let p = need_proc(st, false)?;
        let at = match a {
            Some(v) => addr(st, &v, false).map_err(rt)?,
            None => 0,
        };
        let syms = st.syms.lock().unwrap().clone();
        match hh_asm::assemble(&*p, &syms, at, &text) {
            Ok(b) => (bytes_table(lua, &b)?).into_lua_multi(lua),
            Err(e) => (Value::Nil, e.to_string()).into_lua_multi(lua),
        }
    })?;
    b.f("disassemble", |_, st, v: Value| {
        let p = need_proc(st, false)?;
        let a = addr(st, &v, false).map_err(rt)?;
        let syms = st.syms.lock().unwrap().clone();
        let l = hh_asm::disassemble(&*p, &syms, a, 1).map_err(rt)?.remove(0);
        let bytes: Vec<String> = l.bytes.iter().map(|b| format!("{b:02X}")).collect();
        let mut s = format!("{:X} - {} - {}", l.addr, bytes.join(" "), l.text);
        if !l.comment.is_empty() {
            s.push_str(" : ");
            s.push_str(&l.comment);
        }
        Ok(s)
    })?;
    b.f("getInstructionSize", |_, st, v: Value| {
        let p = need_proc(st, false)?;
        let a = addr(st, &v, false).map_err(rt)?;
        let l = hh_asm::disassemble(&*p, &SymbolTable::default(), a, 1).map_err(rt)?.remove(0);
        Ok((!l.bytes.is_empty()).then_some(l.bytes.len() as i64))
    })?;
    b.f("getPreviousOpcode", |_, st, v: Value| {
        let p = need_proc(st, false)?;
        let a = addr(st, &v, false).map_err(rt)?;
        Ok(hh_asm::previous_instruction(&*p, a).ok().map(|a| a as i64))
    })?;
    Ok(())
}

// ---------------------------------------------------------------- memory records

pub(crate) fn rec_addr(st: &State, r: &Record) -> Result<Addr> {
    let p = st.proc().ok_or(Error::Other("no process opened".into()))?;
    let mut a = resolve(st, &r.address, false)?;
    for o in &r.offsets {
        a = p.read_ptr(a)?.wrapping_add(*o as u64);
    }
    Ok(a)
}

pub(crate) fn rec_value(st: &State, r: &Record) -> Result<String> {
    if r.group_header {
        return Ok(String::new());
    }
    if r.script.is_some() {
        return Ok("<script>".into());
    }
    let p = st.proc().ok_or(Error::Other("no process opened".into()))?;
    let a = rec_addr(st, r)?;
    let n = hh_scan::value_size(r.vtype, &r.fmt)?;
    let mut buf = vec![0u8; n];
    let got = p.read(a, &mut buf)?;
    if got < n && r.vtype != VType::String {
        return Err(Error::NoAccess { addr: a + got as u64 });
    }
    Ok(hh_scan::format_value(r.vtype, &buf[..got], &r.fmt))
}

fn rec_type(r: &Record) -> i64 {
    if r.script.is_some() && !r.group_header {
        return 11;
    }
    match r.vtype {
        VType::Byte => 0,
        VType::Bytes2 => 1,
        VType::Bytes4 => 2,
        VType::Bytes8 => 3,
        VType::Float => 4,
        VType::Double => 5,
        VType::String => 6,
        VType::Aob => 8,
        VType::Binary => 9,
        VType::All => 10,
        VType::Grouped => 14,
    }
}

fn has_opt(r: &Record, o: &str) -> bool {
    r.options.iter().any(|x| x.eq_ignore_ascii_case(o))
}

fn children(t: &dyn crate::TableHost, id: RecId) -> Vec<RecId> {
    t.ids().into_iter().filter(|&c| t.get(c).is_some_and(|c| c.parent == Some(id))).collect()
}

/// moRecursiveSetValue: a group (or script) entry passes a set value to its value children.
fn set_value_rec(st: &State, t: &dyn crate::TableHost, id: RecId, v: &str, depth: usize) -> Result<()> {
    if depth > 64 {
        return Ok(());
    }
    for c in children(t, id) {
        let Some(mut r) = t.get(c) else { continue };
        if r.group_header || r.script.is_some() {
            if has_opt(&r, "moRecursiveSetValue") {
                set_value_rec(st, t, c, v, depth + 1)?;
            }
            continue;
        }
        let p = st.proc().ok_or(Error::Other("no process opened".into()))?;
        hh_scan::write_value(&*p, rec_addr(st, &r)?, r.vtype, v, &r.fmt)?;
        if r.active {
            r.frozen_value = Some(v.to_string());
            t.set(r)?;
        }
    }
    Ok(())
}

/// `"[moA,moB]"`, `"moA, moB"` or a table of names.
fn parse_options(v: &Value) -> LR<Vec<String>> {
    Ok(match v {
        Value::Table(t) => t.sequence_values::<String>().collect::<LR<_>>()?,
        v => str_of(v)
            .unwrap_or_default()
            .split(|c: char| c == ',' || c == '[' || c == ']' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

fn lines_of(v: &Value) -> LR<Vec<String>> {
    Ok(match v {
        Value::Table(t) => t.sequence_values::<Value>().map(|x| x.map(|x| str_of(&x).unwrap_or_default())).collect::<LR<_>>()?,
        v => str_of(v).unwrap_or_default().lines().map(str::to_string).collect(),
    })
}

fn install_records(h: &B) -> LR<()> {
    h.f("mr_ids", |_, st, ()| Ok(st.table().ids()))?;
    h.f("al_selected", |_, st, ()| Ok(st.table().selected()))?;
    h.f("al_select", |_, st, ids: Vec<RecId>| {
        st.table().set_selected(&ids);
        Ok(())
    })?;
    h.f("mr_create", |_, st, parent: Option<RecId>| Ok(st.table().create(parent)))?;
    h.f("mr_delete", |_, st, id: RecId| {
        st.table().delete(id);
        Ok(())
    })?;
    h.f("mr_get", |lua, st, (id, key): (RecId, String)| {
        let t = st.table();
        let Some(r) = t.get(id) else { return Ok(Value::Nil) };
        let s = |s: &str| lua.create_string(s).map(Value::String);
        Ok(match key.as_str() {
            "Description" => s(&r.description)?,
            "Address" => s(&r.address)?,
            "Type" => Value::Integer(rec_type(&r)),
            "Value" => s(&rec_value(st, &r).unwrap_or_else(|_| "??".into()))?,
            "Script" => r.script.as_deref().map(s).transpose()?.unwrap_or(Value::Nil),
            "Color" => Value::Integer(r.color as i64),
            "Active" => Value::Boolean(r.active),
            "Parent" => r.parent.map_or(Value::Nil, |p| Value::Integer(p as i64)),
            "Offsets" => Value::Table(lua.create_sequence_from(r.offsets.iter().copied())?),
            "CurrentAddress" => Value::Integer(rec_addr(st, &r).unwrap_or(0) as i64),
            "ShowAsHex" => Value::Boolean(r.fmt.hex),
            "ShowAsSigned" => Value::Boolean(r.fmt.signed),
            "StringSize" | "AobSize" => Value::Integer(r.fmt.len.unwrap_or(16) as i64),
            "Unicode" => Value::Boolean(r.fmt.utf16),
            "Children" => Value::Table(lua.create_sequence_from(children(&*t, id))?),
            "IsGroupHeader" => Value::Boolean(r.group_header),
            "Options" => s(&format!("[{}]", r.options.join(",")))?,
            "OptionList" => Value::Table(lua.create_sequence_from(r.options.iter().cloned())?),
            "Collapsed" => Value::Boolean(r.collapsed),
            "IsReadable" => Value::Boolean(r.group_header || r.script.is_some() || rec_value(st, &r).is_ok()),
            "DropDownList" => Value::Table(lua.create_sequence_from(r.dropdown.iter().cloned())?),
            "DropDownReadOnly" => Value::Boolean(r.dropdown_readonly),
            "DropDownDescriptionOnly" => Value::Boolean(r.dropdown_description_only),
            "DisplayAsDropDownListItem" => Value::Boolean(r.dropdown_display_as_item),
            "Index" => t.ids().iter().position(|&x| x == id).map_or(Value::Nil, |i| Value::Integer(i as i64)),
            "Hotkeys" => {
                let out = lua.create_table()?;
                for hk in &r.hotkeys {
                    let e = lua.create_table()?;
                    e.set("ID", hk.id)?;
                    e.set("Keys", lua.create_sequence_from(hk.keys.iter().copied())?)?;
                    e.set("Action", hk.action)?;
                    e.set("Value", hk.value.as_str())?;
                    e.set("Description", hk.description.as_str())?;
                    out.push(e)?;
                }
                Value::Table(out)
            }
            _ => Value::Nil,
        })
    })?;
    h.f("mr_set", |_, st, (id, key, v): (RecId, String, Value)| {
        let t = st.table();
        let mut r = t.get(id).ok_or_else(|| mlua::Error::runtime("memory record was deleted"))?;
        let bad = || mlua::Error::runtime(format!("invalid value for {key}"));
        match key.as_str() {
            "Description" => r.description = str_of(&v).unwrap_or_default(),
            "Address" => {
                r.address = match v {
                    Value::Integer(i) => format!("{:X}", i as u64),
                    v => str_of(&v).ok_or_else(bad)?,
                }
            }
            "Type" => {
                let n = int_of(&v).ok_or_else(bad)?;
                if n == 11 {
                    r.script.get_or_insert_with(String::new);
                } else {
                    let (vt, utf16) = ce_vtype(n).ok_or_else(bad)?;
                    r.vtype = vt;
                    r.fmt.utf16 = utf16;
                    r.script = None;
                }
            }
            "Value" => {
                let s = str_of(&v).ok_or_else(bad)?;
                if r.group_header || r.script.is_some() {
                    if has_opt(&r, "moRecursiveSetValue") {
                        set_value_rec(st, &*t, id, &s, 0).map_err(rt)?;
                    }
                    return Ok(());
                }
                let p = need_proc(st, false)?;
                let a = rec_addr(st, &r).map_err(rt)?;
                hh_scan::write_value(&*p, a, r.vtype, &s, &r.fmt).map_err(rt)?;
                if r.active {
                    r.frozen_value = Some(s);
                }
            }
            "Script" => r.script = str_of(&v),
            "Color" => r.color = int_of(&v).ok_or_else(bad)? as u32,
            "Parent" => r.parent = int_of(&v).map(|p| p as RecId),
            "Offsets" => {
                let Value::Table(tb) = v else { return Err(bad()) };
                r.offsets = tb.sequence_values::<Value>().map(|x| x.map(|x| int_of(&x).unwrap_or(0))).collect::<LR<_>>()?;
            }
            "ShowAsHex" => r.fmt.hex = truthy(&v),
            "ShowAsSigned" => r.fmt.signed = truthy(&v),
            "StringSize" | "AobSize" => r.fmt.len = int_of(&v).map(|n| n.max(0) as usize),
            "Unicode" => r.fmt.utf16 = truthy(&v),
            "IsGroupHeader" => {
                r.group_header = truthy(&v);
                if r.group_header {
                    r.script = None;
                }
            }
            "Options" => r.options = parse_options(&v)?,
            "Collapsed" => r.collapsed = truthy(&v),
            "DropDownList" => r.dropdown = lines_of(&v)?,
            "DropDownReadOnly" => r.dropdown_readonly = truthy(&v),
            "DropDownDescriptionOnly" => r.dropdown_description_only = truthy(&v),
            "DisplayAsDropDownListItem" => r.dropdown_display_as_item = truthy(&v),
            "Hotkeys" => {
                let Value::Table(tb) = v else { return Err(bad()) };
                let mut out = Vec::new();
                for e in tb.sequence_values::<Table>() {
                    let e = e?;
                    out.push(crate::RecordHotkey {
                        id: e.get::<Option<u32>>("ID")?.unwrap_or(0),
                        keys: e.get::<Option<Vec<i64>>>("Keys")?.unwrap_or_default(),
                        action: e.get::<Option<i64>>("Action")?.unwrap_or(0),
                        value: e.get::<Value>("Value").map(|v| str_of(&v).unwrap_or_default())?,
                        description: e.get::<Value>("Description").map(|v| str_of(&v).unwrap_or_default())?,
                    });
                }
                r.hotkeys = out;
            }
            _ => return Err(mlua::Error::runtime(format!("unknown memory record property {key}"))),
        }
        t.set(r).map_err(rt)
    })?;
    // (id, active, execute) -> ok, err. Callbacks are handled by the prelude around this.
    h.f("mr_apply", |lua, st, (id, active, execute): (RecId, bool, bool)| {
        let t = st.table();
        let r = t.get(id).ok_or_else(|| mlua::Error::runtime("memory record was deleted"))?;
        if r.active == active {
            return Ok((true, None));
        }
        let mut new_state = None;
        let mut frozen = None;
        if r.group_header {
            // A header only changes state; its children follow the group options.
        } else if let Some(script) = &r.script {
            if execute && !script.trim().is_empty() {
                let Some(p) = st.proc() else { return Ok((false, Some("no process opened".to_string()))) };
                match aa_run(lua, st, &*p, script, active, r.aa_state.as_ref(), Some(id)) {
                    Ok(s) => new_state = active.then_some(s),
                    Err(e) => return Ok((false, Some(format!("{}: {e}", r.description)))),
                }
            }
        } else if active {
            match rec_value(st, &r) {
                Ok(v) => frozen = Some(v),
                Err(e) => return Ok((false, Some(format!("{}: {e}", r.description)))),
            }
        }
        // Re-read: a {$lua} block may have changed the record meanwhile.
        let mut r = t.get(id).ok_or_else(|| mlua::Error::runtime("memory record was deleted"))?;
        r.active = active;
        r.aa_state = new_state;
        r.frozen_value = frozen;
        t.set(r).map_err(rt)?;
        Ok((true, None))
    })?;
    Ok(())
}

// ---------------------------------------------------------------- host / misc

fn install_misc(b: &B, h: &B) -> LR<()> {
    b.f("print", |lua, st, a: Variadic<Value>| {
        let parts: Vec<String> = a.iter().map(|v| value_text(lua, v)).collect();
        st.host().print(&parts.join(" "));
        Ok(())
    })?;
    b.f("showMessage", |lua, st, v: Value| {
        st.host().show_message(&value_text(lua, &v));
        Ok(())
    })?;
    b.f("messageDialog", |lua, st, a: Variadic<Value>| {
        let (title, rest) = match (arg(&a, 0), arg(&a, 1)) {
            (Value::String(t), Value::String(_)) => (t.to_string_lossy(), &a[1..]),
            _ => (String::new(), &a[..]),
        };
        let text = value_text(lua, &arg(rest, 0));
        let kind = int_of(&arg(rest, 1)).unwrap_or(2);
        let mut buttons: Vec<i64> = rest.iter().skip(2).filter_map(int_of).collect();
        if buttons.is_empty() {
            buttons.push(2);
        }
        Ok(st.host().message_dialog(&title, &text, kind, &buttons))
    })?;
    b.f("inputQuery", |_, st, (c, p, i): (Option<String>, Option<String>, Option<String>)| {
        Ok(st.host().input_query(&c.unwrap_or_default(), &p.unwrap_or_default(), &i.unwrap_or_default()))
    })?;
    b.f("playSound", |lua, st, v: Value| {
        let s = matches!(v, Value::String(_)).then(|| value_text(lua, &v));
        st.host().play_sound(s.as_deref());
        Ok(())
    })?;
    b.f("beep", |_, st, ()| {
        st.host().play_sound(None);
        Ok(())
    })?;
    b.f("speedhack_setSpeed", |_, st, v: f64| {
        let ok = st.host().set_speed(v).is_ok();
        if ok {
            *st.speed.lock().unwrap() = v;
        }
        Ok(ok)
    })?;
    b.f("speedhack_getSpeed", |_, st, ()| Ok(*st.speed.lock().unwrap()))?;
    b.f("getCheatEngineDir", |_, _, ()| {
        let exe = std::env::current_exe().ok();
        let dir = exe.as_ref().and_then(|e| e.parent()).map(|d| d.display().to_string()).unwrap_or_default();
        Ok(format!("{dir}{}", std::path::MAIN_SEPARATOR))
    })?;
    b.f("getCPUCount", |_, _, ()| Ok(std::thread::available_parallelism().map_or(1, |n| n.get())))?;
    let now = |_: &Lua, st: &Arc<State>, ()| Ok(st.start.elapsed().as_millis() as i64);
    b.f("getTickCount", now)?;
    h.f("now", now)?;
    h.f("sleep", |_, st, ms: f64| {
        // NaN and negatives sleep 0; huge values (math.huge) sleep until the budget or an
        // interrupt ends them.
        let ms = if ms.is_nan() { 0.0 } else { ms.clamp(0.0, 1e15) };
        let end = std::time::Instant::now().checked_add(Duration::from_secs_f64(ms / 1000.0));
        loop {
            st.check()?;
            let Some(end) = end else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            let left = end.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Ok(());
            }
            std::thread::sleep(left.min(Duration::from_millis(10)));
        }
    })?;
    h.f("report", |_, st, msg: String| {
        st.host().error(&msg);
        Ok(())
    })?;
    h.f("hotkey_register", |_, st, (id, keys): (u32, Vec<i64>)| st.host().register_hotkey(id, &keys).map_err(rt))?;
    h.f("hotkey_unregister", |_, st, id: u32| {
        st.host().unregister_hotkey(id);
        Ok(())
    })?;
    h.f("errtext", |lua, _, v: Value| Ok(value_text(lua, &v)))?;
    h.f("traceback", |lua, _, (msg, level): (Value, Option<usize>)| {
        let text = match &msg {
            Value::Nil => None,
            Value::String(_) | Value::Error(_) => Some(value_text(lua, &msg)),
            _ => return Ok(msg),
        };
        Ok(Value::String(lua.traceback(text.as_deref(), level.unwrap_or(1))?))
    })?;
    Ok(())
}

pub(crate) fn install(lua: &Lua, st: &Arc<State>, allow_os: bool) -> LR<Internals> {
    let b = B { lua, t: lua.globals(), st, names: Default::default() };
    let h = B { lua, t: lua.create_table()?, st, names: Default::default() };
    install_process(&b)?;
    install_memory(&b)?;
    install_scan(&b, &h)?;
    install_asm(&b)?;
    install_records(&h)?;
    install_misc(&b, &h)?;
    crate::ext::install(&b, &h)?;
    crate::debug::install(&h)?;
    crate::ui::install(&h)?;
    h.f("aborted", |_, st, ()| Ok(st.aborted()))?;

    let stubs = lua.create_table()?;
    for (cat, names) in STUBS {
        for n in *names {
            stubs.push(lua.create_sequence_from([n.to_string(), stub_message(cat, n)])?)?;
        }
    }
    let out: Table = lua.load(PRELUDE).set_name("=hh-prelude").call((h.t.clone(), stubs, allow_os, b.names.take()))?;
    lua.set_named_registry_value("hh_mr", out.get::<Function>("mr")?)?;
    Ok(Internals {
        xcall: out.get("xcall")?,
        tick: out.get("tick")?,
        setactive: out.get("setactive")?,
        hotkey: out.get("hotkey")?,
        rechotkey: out.get("rechotkey")?,
        clear: out.get("clear")?,
        uievent: out.get("uievent")?,
        uiinput: out.get("uiinput")?,
        breakpoint: out.get("breakpoint")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_and_alignment() {
        assert_eq!(prot_flags(Some("+W-C*X")), (Tri::Yes, Tri::Any, Tri::No));
        assert!(align_ok(0x1004, 1, "4") && !align_ok(0x1006, 1, "4"));
        assert!(align_ok(0x12A0, 2, "A0") && !align_ok(0x12A4, 2, "A0"));
        assert_eq!(button_result(0), 6);
    }
}
