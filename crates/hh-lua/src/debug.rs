//! The `debug_*` functions over a host-provided debugger ([`DebugHost`]).
//!
//! The engine keeps the breakpoints set from Lua and their functions; the host's debugger
//! reports hits through [`crate::Engine::on_breakpoint`], which runs the function inside the
//! engine with the registers as globals (`RAX`..`R15`, `RIP`, `EFLAGS` and the 32-bit names
//! `EAX`..`EDI`, `EBP`, `ESP`, `EIP`).
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use hh_core::{Addr, Error, Result};
use mlua::{Lua, Value};
use serde::{Deserialize, Serialize};

use crate::State;
use crate::api::{B, int_of, rt};

/// CE `bptExecute` (0), `bptAccess` (1), `bptWrite` (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BpTrigger {
    Execute,
    Access,
    Write,
}

/// CE `bpmInt3` (0), `bpmDebugRegister` (1), `bpmException` (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BpMethod {
    Int3,
    DebugRegister,
    Exception,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakpointSpec {
    pub address: Addr,
    /// Bytes watched (1, 2, 4 or 8 for data breakpoints).
    pub size: u32,
    pub trigger: BpTrigger,
    pub method: BpMethod,
}

/// CE `co_run` (0), `co_stepinto` (1), `co_stepover` (2), `co_runtill` (3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinueMode {
    Run,
    StepInto,
    StepOver,
    RunTill,
}

/// General purpose registers of the broken thread (x86-64 names; 32-bit targets use the
/// low halves).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RegContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl RegContext {
    /// (64-bit global, 32-bit global or "", field)
    fn regs(&mut self) -> [(&'static str, &'static str, &mut u64); 18] {
        [
            ("RAX", "EAX", &mut self.rax),
            ("RBX", "EBX", &mut self.rbx),
            ("RCX", "ECX", &mut self.rcx),
            ("RDX", "EDX", &mut self.rdx),
            ("RSI", "ESI", &mut self.rsi),
            ("RDI", "EDI", &mut self.rdi),
            ("RBP", "EBP", &mut self.rbp),
            ("RSP", "ESP", &mut self.rsp),
            ("R8", "", &mut self.r8),
            ("R9", "", &mut self.r9),
            ("R10", "", &mut self.r10),
            ("R11", "", &mut self.r11),
            ("R12", "", &mut self.r12),
            ("R13", "", &mut self.r13),
            ("R14", "", &mut self.r14),
            ("R15", "", &mut self.r15),
            ("RIP", "EIP", &mut self.rip),
            ("EFLAGS", "", &mut self.rflags),
        ]
    }
}

/// A thread stopped on a breakpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakEvent {
    pub thread_id: u32,
    /// The breakpoint's address (for data breakpoints the watched address, not RIP).
    pub address: Addr,
    pub context: RegContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakResult {
    /// Resume the thread (the function returned non-zero / true). False: the thread stays
    /// broken; the script or the user continues it later.
    pub resume: bool,
    /// Registers the script changed (apply before resuming).
    pub context: Option<RegContext>,
}

/// The debugger behind the `debug_*` functions. Every method has a default that reports
/// that no debugger is available.
pub trait DebugHost: Send + Sync {
    /// `debugProcess(interface)`: attach the debugger to the opened process. `interface` is
    /// CE's (0 default, 1 windows, 2 VEH, 3 kernel); hosts may ignore it.
    fn start(&self, _interface: i64) -> Result<()> {
        Err(no_debugger())
    }
    fn is_debugging(&self) -> bool {
        false
    }
    /// `debug_setBreakpoint`; the host attaches first if needed (CE does). Hits are reported
    /// through [`crate::Engine::on_breakpoint`].
    fn set_breakpoint(&self, _bp: &BreakpointSpec) -> Result<()> {
        Err(no_debugger())
    }
    fn remove_breakpoint(&self, _address: Addr) -> Result<()> {
        Err(no_debugger())
    }
    /// `debug_continueFromBreakpoint`: resume the broken thread, applying `context` (registers
    /// the script changed with `debug_setContext`) first.
    fn continue_from_breakpoint(&self, _thread_id: u32, _mode: ContinueMode, _context: Option<&RegContext>) -> Result<()> {
        Err(no_debugger())
    }
    /// `debug_breakThread(tid)`.
    fn break_thread(&self, _thread_id: u32) -> Result<()> {
        Err(no_debugger())
    }
}

fn no_debugger() -> Error {
    Error::Unsupported("debugger: no debugger is attached to the Lua engine")
}

struct NullDebug;
impl DebugHost for NullDebug {}

pub(crate) struct DebugState {
    pub(crate) host: RwLock<Arc<dyn DebugHost>>,
    pub(crate) broken: Mutex<Option<BreakEvent>>,
    /// The registers the host last saw for the broken thread.
    pub(crate) known: Mutex<Option<RegContext>>,
    bps: Mutex<BTreeMap<Addr, BreakpointSpec>>,
}

impl Default for DebugState {
    fn default() -> Self {
        DebugState {
            host: RwLock::new(Arc::new(NullDebug)),
            broken: Mutex::new(None),
            known: Mutex::new(None),
            bps: Mutex::new(BTreeMap::new()),
        }
    }
}

impl DebugState {
    fn host(&self) -> Arc<dyn DebugHost> {
        self.host.read().unwrap().clone()
    }
}

/// Sets the register globals.
pub(crate) fn write_context(lua: &Lua, ctx: &RegContext) -> mlua::Result<()> {
    let g = lua.globals();
    let mut c = *ctx;
    for (r, e, v) in c.regs() {
        g.set(r, *v as i64)?;
        if !e.is_empty() {
            g.set(e, (*v & 0xffff_ffff) as i64)?;
        }
    }
    Ok(())
}

/// Reads the register globals back: a changed 64-bit name wins, else a changed 32-bit name
/// replaces the register (zero-extended, like a 32-bit write on x86-64).
pub(crate) fn read_context(lua: &Lua, base: &RegContext) -> RegContext {
    let g = lua.globals();
    let mut c = *base;
    for (r, e, v) in c.regs() {
        let wide = g.get::<Value>(r).ok().and_then(|x| int_of(&x)).map(|x| x as u64);
        let narrow = (!e.is_empty()).then(|| g.get::<Value>(e).ok().and_then(|x| int_of(&x))).flatten();
        if let Some(w) = wide.filter(|w| w != v) {
            *v = w;
        } else if let Some(n) = narrow.map(|n| n as u64 & 0xffff_ffff).filter(|n| *n != *v & 0xffff_ffff) {
            *v = n;
        }
    }
    c
}

fn trigger(n: i64) -> BpTrigger {
    match n {
        1 => BpTrigger::Access,
        2 => BpTrigger::Write,
        _ => BpTrigger::Execute,
    }
}

fn method(n: i64) -> BpMethod {
    match n {
        0 => BpMethod::Int3,
        2 => BpMethod::Exception,
        _ => BpMethod::DebugRegister,
    }
}

pub(crate) fn install(h: &B) -> mlua::Result<()> {
    h.f("dbg_start", |_, st, i: Option<i64>| st.dbg.host().start(i.unwrap_or(0)).map_err(rt))?;
    h.f("dbg_is", |_, st, ()| Ok(st.dbg.host().is_debugging()))?;
    h.f("dbg_set", |_, st, (a, size, t, m): (i64, Option<i64>, Option<i64>, Option<i64>)| {
        let bp = BreakpointSpec {
            address: a as Addr,
            size: size.unwrap_or(1).clamp(1, 8) as u32,
            trigger: trigger(t.unwrap_or(0)),
            method: method(m.unwrap_or(1)),
        };
        st.dbg.host().set_breakpoint(&bp).map_err(rt)?;
        st.dbg.bps.lock().unwrap().insert(bp.address, bp);
        Ok(())
    })?;
    h.f("dbg_remove", |_, st, a: i64| {
        let known = st.dbg.bps.lock().unwrap().remove(&(a as Addr)).is_some();
        match st.dbg.host().remove_breakpoint(a as Addr) {
            Err(_) if known => Ok(true), // the host lost it already
            r => r.map(|_| true).map_err(rt),
        }
    })?;
    h.f("dbg_list", |lua, st, ()| lua.create_sequence_from(st.dbg.bps.lock().unwrap().keys().map(|&a| a as i64)))?;
    h.f("dbg_broken", |_, st, ()| Ok(st.dbg.broken.lock().unwrap().is_some()))?;
    h.f("dbg_continue", |_, st, mode: Option<i64>| {
        let Some(ev) = st.dbg.broken.lock().unwrap().take() else { return Ok(false) };
        let known = st.dbg.known.lock().unwrap().take().unwrap_or(ev.context);
        let mode = match mode.unwrap_or(0) {
            1 => ContinueMode::StepInto,
            2 => ContinueMode::StepOver,
            3 => ContinueMode::RunTill,
            _ => ContinueMode::Run,
        };
        let changed = (ev.context != known).then_some(ev.context);
        st.dbg.host().continue_from_breakpoint(ev.thread_id, mode, changed.as_ref()).map_err(rt)?;
        Ok(true)
    })?;
    h.f("dbg_getctx", |lua, st, ()| {
        let ctx = st.dbg.broken.lock().unwrap().as_ref().map(|b| b.context);
        match ctx {
            Some(c) => write_context(lua, &c).map(|_| true),
            None => Ok(false),
        }
    })?;
    h.f("dbg_setctx", |lua, st, ()| {
        let mut b = st.dbg.broken.lock().unwrap();
        let Some(ev) = b.as_mut() else { return Ok(false) };
        ev.context = read_context(lua, &ev.context);
        Ok(true)
    })?;
    h.f("dbg_break", |_, st, tid: u32| st.dbg.host().break_thread(tid).map_err(rt))?;
    h.f("dbg_clear", |_, st, ()| {
        clear(st);
        Ok(())
    })?;
    Ok(())
}

/// Removes every breakpoint set from Lua (table switch).
pub(crate) fn clear(st: &State) {
    let bps: Vec<Addr> = std::mem::take(&mut *st.dbg.bps.lock().unwrap()).into_keys().collect();
    let h = st.dbg.host();
    for a in bps {
        let _ = h.remove_breakpoint(a);
    }
}
