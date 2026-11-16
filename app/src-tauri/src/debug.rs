//! Debugger commands over hh-debug. One debugger per session, attached and detached
//! explicitly; while attached every other command reaches the target through
//! `Debugger::process()` (the session's `Switch`).
//!
//! Breakpoint ids are hh-debug's: enable/disable, conditions and hit options change in
//! place, so hits and records survive. Breakpoints set from Lua (`debug_setBreakpoint`) are
//! listed too, marked as script-owned; their hits run the script's function (see
//! [`App::dispatch_lua_break`]).
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use hh_core::{Addr, Process};
use hh_debug::{Action, AddressOf, BpId, BpKind, BpMethod, BpOptions, BreakReason, Breakpoint, Context, Debugger, Event, Hooks, SignalAction, State, ThreadInfo, Tid};
use iced_x86::{Decoder, DecoderOptions, OpKind, Register};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::commands::{App, R, Session, hex_addr, hex_bytes, lock, parse_addr, s};

/// Most trace steps returned with full registers (the UI shows one at a time).
const MAX_TRACE: usize = 100_000;
/// Debugger log lines kept.
const LOG_CAP: usize = 500;

pub struct Dbg {
    d: Debugger,
    /// Last break: (tid, reason text).
    last: Option<(Tid, String)>,
    exit_code: Option<Option<i32>>,
    bps: Vec<AppBp>,
    /// Instruction address -> (its bytes, text), for record lists.
    insns: HashMap<Addr, (Vec<u8>, String)>,
    log: VecDeque<LogLine>,
    log_seq: u64,
    /// A break the Lua engine handles before the UI sees it: (tid, breakpoint, registers).
    lua_break: Option<(Tid, BpId, Box<Context>)>,
}

/// What the app adds to an hh-debug breakpoint.
struct AppBp {
    id: BpId,
    addr: Addr,
    /// Record the effective address the instruction accesses.
    ea: bool,
    /// Condition over registers; hits where it is false are ignored.
    cond: Option<String>,
    /// Set from Lua (`debug_setBreakpoint`).
    script: bool,
    /// Why the engine disabled it (exec, one-shot, max hits, overwritten).
    note: Option<String>,
    /// Trace: break at the first traced step where this holds.
    stop: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub seq: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugLog {
    pub lines: Vec<LogLine>,
    /// Pass back as `since`.
    pub next: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BpReq {
    pub addr: String,
    /// `execute` / `write` / `access`.
    pub kind: String,
    /// 1, 2, 4 or 8; shrunk until the address is aligned to it.
    pub size: u8,
    /// `software` / `hardware`; execute defaults to software, watches are always hardware.
    pub method: String,
    /// `break` / `record` / `trace`.
    pub action: String,
    pub steps: u32,
    pub step_over_calls: bool,
    /// Record the address the instruction accesses ("what addresses this instruction accesses").
    pub ea: bool,
    /// Break only when this holds, e.g. `rax==5 && rcx>0x100` (see [`Cond`]); empty = always.
    pub condition: String,
    /// Ignore the first N hits ("break after N hits").
    pub skip_hits: u64,
    /// Disable after the action ran once.
    pub one_shot: bool,
    /// Disable once the hit count reaches this (recorders: stop recording after N hits).
    pub max_hits: Option<u64>,
    /// Trace only: break at the first traced instruction where this holds (condition syntax).
    pub stop_when: String,
}

/// `debug_watch_range`: a page-protection watch of any length.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RangeReq {
    pub addr: String,
    pub len: u64,
    /// `write` / `access`.
    pub kind: String,
    pub max_hits: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugStatus {
    pub attached: bool,
    /// `detached` / `running` / `broken` / `suspended` / `exited`.
    pub state: &'static str,
    pub tid: Option<Tid>,
    pub reason: Option<String>,
    pub rip: Option<String>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BpOut {
    pub id: u32,
    pub addr: String,
    pub kind: &'static str,
    pub size: u8,
    /// Watched length (`size`, or the length of a range watch).
    pub len: u64,
    /// `software` / `hardware` / `page`.
    pub method: &'static str,
    pub action: &'static str,
    pub ea: bool,
    pub enabled: bool,
    pub hits: u64,
    pub slot: Option<u8>,
    pub condition: Option<String>,
    /// Trace stop condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_when: Option<String>,
    pub options: BpOptions,
    /// Hits not recorded because the record list is full.
    pub records_dropped: u64,
    /// `user` or `script` (set from Lua).
    pub owner: &'static str,
    /// Why it is disabled, when the debugger disabled it.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordOut {
    /// Start of the instruction that accessed (watch) or executed (execute breakpoint).
    pub addr: String,
    /// Raw trap ip.
    pub ip: String,
    pub bytes: String,
    pub text: String,
    pub count: u64,
    /// Accessed address, for `ea` breakpoints and range watches.
    pub address: Option<String>,
    pub context: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceOut {
    pub addr: String,
    pub text: String,
    pub context: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackOut {
    pub addr: String,
    pub value: String,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FrameOut {
    pub addr: String,
    pub module: Option<String>,
    pub symbol: Option<String>,
}

/// Editable 64-bit registers, in display order.
pub const REGS: [&str; 20] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags", "fs_base",
    "gs_base",
];

fn reg_mut<'a>(c: &'a mut Context, name: &str) -> Option<&'a mut u64> {
    Some(match name {
        "rax" => &mut c.rax,
        "rbx" => &mut c.rbx,
        "rcx" => &mut c.rcx,
        "rdx" => &mut c.rdx,
        "rsi" => &mut c.rsi,
        "rdi" => &mut c.rdi,
        "rbp" => &mut c.rbp,
        "rsp" => &mut c.rsp,
        "r8" => &mut c.r8,
        "r9" => &mut c.r9,
        "r10" => &mut c.r10,
        "r11" => &mut c.r11,
        "r12" => &mut c.r12,
        "r13" => &mut c.r13,
        "r14" => &mut c.r14,
        "r15" => &mut c.r15,
        "rip" => &mut c.rip,
        "rflags" => &mut c.rflags,
        "fs_base" => &mut c.fs_base,
        "gs_base" => &mut c.gs_base,
        _ => return None,
    })
}

type RegSet = Box<dyn FnOnce(&mut Context) -> R<()>>;

/// Parses `value` for register `name` (see `debug_set_register`) into a setter.
fn set_reg(name: &str, value: &str) -> R<RegSet> {
    let idx = |p: &str, n: usize| name.strip_prefix(p).and_then(|i| i.parse::<usize>().ok()).filter(|&i| i < n);
    if let Some(i) = idx("st", 8) {
        let v: f64 = value.trim().parse().map_err(|_| format!("{name}: {value:?} is not a number"))?;
        return Ok(Box::new(move |c| {
            c.fpu.st[i] = to_f80(v);
            Ok(())
        }));
    }
    if let Some(i) = idx("xmm", 16) {
        let h: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        let h = h.trim_start_matches("0x");
        if h.len() != 32 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("{name}: give 32 hex digits"));
        }
        let mut b = [0u8; 16];
        for (k, x) in b.iter_mut().enumerate() {
            *x = u8::from_str_radix(&h[2 * k..2 * k + 2], 16).unwrap_or(0);
        }
        return Ok(Box::new(move |c| {
            c.fpu.xmm[i] = b;
            Ok(())
        }));
    }
    let v = parse_addr(value)?;
    let name = name.to_string();
    Ok(Box::new(move |c| {
        let small = |max: u64| u32::try_from(v).ok().filter(|&x| x as u64 <= max).ok_or_else(|| format!("{name}: {v:#x} is too large"));
        match name.as_str() {
            "mxcsr" => c.fpu.mxcsr = small(u32::MAX as u64)?,
            "fcw" => c.fpu.fcw = small(0xffff)? as u16,
            "fsw" => c.fpu.fsw = small(0xffff)? as u16,
            n => *reg_mut(c, n).ok_or_else(|| format!("unknown register {n:?}"))? = v,
        }
        Ok(())
    }))
}

/// f64 -> x87 80-bit extended (exact: every f64 fits).
fn to_f80(v: f64) -> [u8; 10] {
    let bits = v.to_bits();
    let sign = ((bits >> 63) as u16) << 15;
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & ((1 << 52) - 1);
    let (e, m): (u16, u64) = match exp {
        0 if frac == 0 => (0, 0),
        0 => {
            // Subnormal double: normalize the fraction.
            let shift = frac.leading_zeros() - 11;
            (((1 - 1023 + 16383) - shift as i32) as u16, (frac << shift) << 11)
        }
        0x7ff => (0x7fff, (1 << 63) | (frac << 11)),
        _ => ((exp - 1023 + 16383) as u16, (1 << 63) | (frac << 11)),
    };
    let mut out = [0u8; 10];
    out[..8].copy_from_slice(&m.to_le_bytes());
    out[8..].copy_from_slice(&(sign | e).to_le_bytes());
    out
}

/// x87 80-bit extended -> f64 (approximate, for display).
fn f80(b: &[u8; 10]) -> f64 {
    let mant = u64::from_le_bytes(b[..8].try_into().unwrap_or_default());
    let se = u16::from_le_bytes([b[8], b[9]]);
    let (sign, exp) = (if se & 0x8000 != 0 { -1.0 } else { 1.0 }, (se & 0x7fff) as i32);
    match exp {
        0 if mant == 0 => 0.0 * sign,
        0x7fff if mant << 1 == 0 => sign * f64::INFINITY,
        0x7fff => f64::NAN,
        _ => sign * (mant as f64 / (1u64 << 63) as f64) * 2f64.powi(exp - 16383),
    }
}

/// Registers as JSON with hex-string values (JS numbers lose precision above 2^53).
pub fn ctx_json(c: &Context, fpu: bool) -> Value {
    let mut m = Map::new();
    let mut c2 = c.clone();
    for n in REGS {
        m.insert(n.into(), json!(hex_addr(*reg_mut(&mut c2, n).unwrap_or(&mut 0))));
    }
    for (n, v) in [("cs", c.cs), ("ds", c.ds), ("es", c.es), ("fs", c.fs), ("gs", c.gs), ("ss", c.ss)] {
        m.insert(n.into(), json!(format!("{v:04X}")));
    }
    if fpu {
        let f = &c.fpu;
        m.insert(
            "fpu".into(),
            json!({
                "fcw": format!("{:04X}", f.fcw), "fsw": format!("{:04X}", f.fsw), "ftw": format!("{:04X}", f.ftw),
                "fop": format!("{:04X}", f.fop), "fip": hex_addr(f.fip), "fdp": hex_addr(f.fdp), "mxcsr": format!("{:08X}", f.mxcsr),
                "st": f.st.iter().map(|b| json!({"hex": hex_bytes(&b.iter().rev().copied().collect::<Vec<_>>(), ""), "value": f80(b).to_string()})).collect::<Vec<_>>(),
                // Little-endian byte order; the UI renders hex and lanes.
                "xmm": f.xmm.iter().map(|b| hex_bytes(b, "").to_lowercase()).collect::<Vec<_>>(),
            }),
        );
    }
    Value::Object(m)
}

fn kind_str(k: BpKind) -> &'static str {
    match k {
        BpKind::Execute => "execute",
        BpKind::Write => "write",
        BpKind::Access => "access",
    }
}

/// Register value for iced's effective-address callback, truncated to the operand's size.
fn reg_value(c: &Context, r: Register) -> Option<u64> {
    let v = match r.full_register() {
        Register::RAX => c.rax,
        Register::RBX => c.rbx,
        Register::RCX => c.rcx,
        Register::RDX => c.rdx,
        Register::RSI => c.rsi,
        Register::RDI => c.rdi,
        Register::RBP => c.rbp,
        Register::RSP => c.rsp,
        Register::R8 => c.r8,
        Register::R9 => c.r9,
        Register::R10 => c.r10,
        Register::R11 => c.r11,
        Register::R12 => c.r12,
        Register::R13 => c.r13,
        Register::R14 => c.r14,
        Register::R15 => c.r15,
        Register::RIP => c.rip,
        Register::FS => return Some(c.fs_base),
        Register::GS => return Some(c.gs_base),
        Register::ES | Register::CS | Register::SS | Register::DS => return Some(0),
        _ => return None,
    };
    Some(match r.size() {
        1 => v & 0xff,
        2 => v & 0xffff,
        4 => v & 0xffff_ffff,
        _ => v,
    })
}

/// "What addresses does this instruction access": the memory operand's effective address.
fn ea_hook(p: &dyn Process, addr: Addr) -> R<AddressOf> {
    let mut buf = [0u8; 15];
    let n = p.read(addr, &mut buf).map_err(s)?;
    let bits = if p.pointer_size() == 8 { 64 } else { 32 };
    let ins = Decoder::with_ip(bits, &buf[..n], addr, DecoderOptions::NONE).decode();
    let op = (0..ins.op_count())
        .find(|&i| ins.op_kind(i) == OpKind::Memory)
        .ok_or_else(|| format!("the instruction at {addr:#x} does not access memory"))?;
    Ok(Arc::new(move |c: &Context| ins.virtual_address(op, 0, |r, _, _| reg_value(c, r))))
}

fn reason_text(r: &BreakReason) -> String {
    match r {
        BreakReason::Breakpoint(id) => format!("breakpoint {id}"),
        BreakReason::Step => "step".into(),
        BreakReason::Pause => "paused".into(),
        BreakReason::Signal { code, address: Some(a) } => format!("signal {code} at {a:#x}"),
        BreakReason::Signal { code, address: None } => format!("signal {code}"),
        BreakReason::TraceStop(id) => format!("trace stop, breakpoint {id}"),
    }
}

fn condition_hook(cond: &Option<String>) -> R<Option<hh_debug::Predicate>> {
    Ok(match cond {
        Some(c) => {
            let c = Arc::new(Cond::parse(c)?);
            Some(Arc::new(move |x: &Context| c.eval(x) != 0) as hh_debug::Predicate)
        }
        None => None,
    })
}

fn opts_of(req: &BpReq) -> BpOptions {
    BpOptions { skip_hits: req.skip_hits, one_shot: req.one_shot, max_hits: req.max_hits.filter(|&m| m > 0) }
}

/// Registers as hh-lua's breakpoint functions see them.
fn reg_ctx(c: &Context) -> hh_lua::RegContext {
    hh_lua::RegContext {
        rax: c.rax, rbx: c.rbx, rcx: c.rcx, rdx: c.rdx, rsi: c.rsi, rdi: c.rdi, rbp: c.rbp, rsp: c.rsp, r8: c.r8, r9: c.r9,
        r10: c.r10, r11: c.r11, r12: c.r12, r13: c.r13, r14: c.r14, r15: c.r15, rip: c.rip, rflags: c.rflags,
    }
}

/// `r` written over the general registers of `c`.
fn merge_ctx(c: &mut Context, r: &hh_lua::RegContext) {
    (c.rax, c.rbx, c.rcx, c.rdx, c.rsi, c.rdi, c.rbp, c.rsp) = (r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp);
    (c.r8, c.r9, c.r10, c.r11, c.r12, c.r13, c.r14, c.r15) = (r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15);
    (c.rip, c.rflags) = (r.rip, r.rflags);
}

impl Dbg {
    fn new(d: Debugger) -> Dbg {
        Dbg { d, last: None, exit_code: None, bps: Vec::new(), insns: HashMap::new(), log: VecDeque::new(), log_seq: 0, lua_break: None }
    }

    fn note(&mut self, text: String) {
        self.log_seq += 1;
        self.log.push_back(LogLine { seq: self.log_seq, text });
        while self.log.len() > LOG_CAP {
            self.log.pop_front();
        }
    }

    fn bp(&self, id: u32) -> R<&AppBp> {
        self.bps.iter().find(|b| b.id == id).ok_or_else(|| format!("no breakpoint {id}"))
    }

    fn bp_mut(&mut self, id: u32) -> R<&mut AppBp> {
        self.bps.iter_mut().find(|b| b.id == id).ok_or_else(|| format!("no breakpoint {id}"))
    }

    fn hooks(&self, b: &AppBp, proc: &dyn Process) -> R<Hooks> {
        Ok(Hooks { address_of: if b.ea { Some(ea_hook(proc, b.addr)?) } else { None }, condition: condition_hook(&b.cond)?, stop_when: condition_hook(&b.stop)?, ..Hooks::default() })
    }

    /// Drains debugger events into the session state and the log. `lua_onbp`: the script
    /// defines `debugger_onBreakpoint`, so every breakpoint hit goes to Lua first.
    fn pump(&mut self, lua_onbp: bool) {
        for e in self.d.events() {
            self.handle(e, lua_onbp);
        }
    }

    /// Resumed: the next break brings its own reason.
    fn resumed(&mut self) {
        self.last = None;
        self.lua_break = None;
    }

    fn handle(&mut self, e: Event, lua_onbp: bool) {
        {
            match e {
                Event::Break { tid, reason, context } => {
                    if let BreakReason::Breakpoint(id) = reason
                        && (lua_onbp || self.bps.iter().any(|b| b.id == id && b.script))
                    {
                        self.lua_break = Some((tid, id, context));
                    }
                    self.last = Some((tid, reason_text(&reason)));
                }
                Event::ProcessExited { code } => {
                    self.exit_code = Some(code);
                    self.note(match code {
                        Some(c) => format!("the process exited with code {c}"),
                        None => "the process was killed by a signal".into(),
                    });
                }
                Event::Exec => {
                    for b in &mut self.bps {
                        b.note = Some("the process replaced its program (exec); enable it to arm it at this address in the new program".into());
                    }
                    self.insns.clear();
                    self.note("the process ran exec: every breakpoint is disabled (hits and records kept)".into());
                }
                Event::Forked { child } => self.note(format!("the process forked: child {child} runs undebugged (breakpoints removed from it)")),
                Event::BreakpointDisabled { bp } => {
                    let info = self.d.breakpoints().unwrap_or_default().into_iter().find(|i| i.id == bp);
                    let why = match info {
                        Some(i) if i.options.one_shot => "one-shot: it ran once".to_string(),
                        Some(i) if i.options.max_hits.is_some_and(|m| i.hits >= m) => format!("stopped after {} hits", i.hits),
                        _ => "code was written over it".to_string(),
                    };
                    self.note(format!("breakpoint {bp} disabled: {why}"));
                    if let Ok(b) = self.bp_mut(bp) {
                        b.note = Some(why);
                    }
                }
                _ => {}
            }
        }
    }

    /// Instruction at `at`, cached while its bytes stay the same.
    fn insn(&mut self, sess: &Session, at: Addr) -> (Vec<u8>, String) {
        let p = &*sess.proc;
        if let Some(c) = self.insns.get(&at) {
            let mut b = vec![0u8; c.0.len()];
            if p.read_exact(at, &mut b).is_ok() && b == c.0 {
                return c.clone();
            }
        }
        let syms = lock(&sess.syms).clone();
        let v = match hh_asm::disassemble(p, &syms, at, 1).ok().and_then(|l| l.into_iter().next()) {
            Some(l) => (l.bytes, l.text),
            None => (Vec::new(), "??".into()),
        };
        self.insns.insert(at, v.clone());
        v
    }
}

impl App {
    fn with_dbg<T>(&self, f: impl FnOnce(&mut Dbg, &Session) -> R<T>) -> R<T> {
        let sess = self.session()?;
        let mut g = lock(&sess.dbg);
        let d = g.as_mut().ok_or("the debugger is not attached")?;
        f(d, &sess)
    }

    /// Attaches the debugger to the opened process; from now on all memory access goes
    /// through it.
    /// hh-debug's recent events, commands and stolen-stop recoveries (diagnostics).
    pub fn debug_history(&self) -> R<Vec<String>> {
        let sess = self.session()?;
        let g = lock(&sess.dbg);
        g.as_ref().ok_or("the debugger is not attached")?.d.history().map_err(s)
    }

    pub fn debug_attach(&self) -> R<DebugStatus> {
        let sess = self.session()?;
        self.local_only("The debugger")?;
        // A process paused from the UI runs again: the debugger stops it its own way.
        if sess.paused.swap(false, std::sync::atomic::Ordering::SeqCst) {
            sess.raw.resume().map_err(s)?;
        }
        {
            let mut g = lock(&sess.dbg);
            if g.is_none() {
                let d = Debugger::attach(sess.info.pid).map_err(s)?;
                sess.switch.set(d.process());
                apply_signals(&d, &lock(&self.x.settings).signals);
                *g = Some(Dbg::new(d));
            }
        }
        self.debug_status()
    }

    /// Removes every breakpoint, detaches (the target keeps running) and switches memory
    /// access back to the plain process.
    pub fn debug_detach(&self) -> R<()> {
        let sess = self.session()?;
        // Detach while holding the lock: `reap_children` must not wait on a pid that is
        // still traced.
        let mut g = lock(&sess.dbg);
        let d = g.take();
        sess.switch.set(sess.raw.clone());
        let r = match d {
            Some(d) => d.d.detach().map_err(s),
            None => Ok(()),
        };
        drop(g);
        self.x.lua.engine.debug_resumed();
        r
    }

    /// Current state; drains debugger events (break reasons, exit, notices).
    pub fn debug_status(&self) -> R<DebugStatus> {
        let sess = self.session()?;
        let onbp = self.x.lua.onbp.load(std::sync::atomic::Ordering::SeqCst);
        let mut g = lock(&sess.dbg);
        let Some(d) = g.as_mut() else {
            return Ok(DebugStatus { attached: false, state: "detached", tid: None, reason: None, rip: None, exit_code: None });
        };
        d.pump(onbp);
        let st = if d.exit_code.is_some() { State::Exited } else { d.d.state().unwrap_or(State::Exited) };
        let mut out = DebugStatus { attached: true, state: "running", tid: None, reason: None, rip: None, exit_code: d.exit_code.flatten() };
        match st {
            State::Running => {}
            // A Lua breakpoint function is about to run (or running): not a stop for the UI.
            State::Broken { tid } if d.lua_break.as_ref().is_some_and(|l| l.0 == tid) => {}
            State::Suspended => out.state = "suspended",
            State::Exited => out.state = "exited",
            State::Broken { tid } => {
                // The stop can be visible before its event arrives.
                if d.last.is_none()
                    && let Some(e) = d.d.next_event(std::time::Duration::from_millis(200))
                {
                    d.handle(e, onbp);
                    d.pump(onbp);
                }
                if d.lua_break.as_ref().is_some_and(|l| l.0 == tid) {
                    return Ok(out);
                }
                out.state = "broken";
                out.tid = Some(tid);
                out.reason = d.last.as_ref().filter(|l| l.0 == tid).map(|l| l.1.clone()).or(Some("break".into()));
                out.rip = d.d.context(tid).ok().map(|c| hex_addr(c.rip));
            }
        }
        Ok(out)
    }

    /// Debugger notices (exec, fork, breakpoints the debugger disabled, exit) after `since`.
    pub fn debug_log(&self, since: u64) -> R<DebugLog> {
        let onbp = self.x.lua.onbp.load(std::sync::atomic::Ordering::SeqCst);
        self.with_dbg(|d, _| {
            d.pump(onbp);
            Ok(DebugLog { lines: d.log.iter().filter(|l| l.seq > since).cloned().collect(), next: d.log_seq })
        })
    }

    /// Adds a breakpoint/watchpoint; returns its id.
    pub fn debug_add_breakpoint(&self, req: &BpReq) -> R<u32> {
        self.add_bp(req, false)
    }

    fn add_bp(&self, req: &BpReq, script: bool) -> R<u32> {
        let address = parse_addr(&req.addr)?;
        let kind = match req.kind.as_str() {
            "" | "execute" => BpKind::Execute,
            "write" => BpKind::Write,
            "access" => BpKind::Access,
            k => return Err(format!("unknown breakpoint kind {k:?}")),
        };
        let method = match (kind, req.method.as_str()) {
            (BpKind::Execute, "" | "software") => BpMethod::Software,
            (_, "" | "hardware") => BpMethod::Hardware,
            (_, "software") => return Err("software breakpoints only break on execute; use hardware".into()),
            (_, "page") => return Err("page watches take a range: use debug_watch_range".into()),
            (_, m) => return Err(format!("unknown breakpoint method {m:?}")),
        };
        let action = match req.action.as_str() {
            "" | "break" => Action::Break,
            "record" => Action::Record,
            "trace" => Action::Trace { steps: req.steps.clamp(1, MAX_TRACE as u32), step_over_calls: req.step_over_calls },
            a => return Err(format!("unknown breakpoint action {a:?}")),
        };
        let mut size = if kind == BpKind::Execute { 1 } else { req.size.clamp(1, 8).next_power_of_two() };
        // Hardware ranges must be aligned: watch the aligned part that holds the address.
        while method == BpMethod::Hardware && !address.is_multiple_of(size as u64) {
            size /= 2;
        }
        let cond = Some(req.condition.trim().to_string()).filter(|c| !c.is_empty());
        let stop = Some(req.stop_when.trim().to_string()).filter(|c| !c.is_empty() && matches!(action, Action::Trace { .. }));
        self.with_dbg(|d, sess| {
            let mut b = AppBp { id: 0, addr: address, ea: req.ea, cond, script, note: None, stop };
            let hooks = d.hooks(&b, &*sess.proc)?;
            b.id = d.d.add_breakpoint_with(Breakpoint { address, kind, size, method, action }, hooks, opts_of(req)).map_err(s)?;
            let id = b.id;
            d.bps.push(b);
            Ok(id)
        })
    }

    /// "Find out what writes / accesses this range": a page-protection watch that records.
    /// Refuses stack memory (every call and local variable would fault).
    pub fn debug_watch_range(&self, req: &RangeReq) -> R<u32> {
        let start = parse_addr(&req.addr)?;
        if req.len == 0 {
            return Err("the range is empty".into());
        }
        let kind = match req.kind.as_str() {
            "" | "write" => BpKind::Write,
            "access" => BpKind::Access,
            k => return Err(format!("unknown watch kind {k:?}")),
        };
        let end = start.checked_add(req.len).ok_or("the range wraps around")?;
        self.check_not_stack(start, end)?;
        self.with_dbg(|d, _| {
            let opts = BpOptions { max_hits: req.max_hits.filter(|&m| m > 0), ..BpOptions::default() };
            let id = d.d.add_watch_range(start, req.len, kind, Action::Record, Hooks::default(), opts).map_err(s)?;
            d.bps.push(AppBp { id, addr: start, ea: false, cond: None, script: false, note: None, stop: None });
            Ok(id)
        })
    }

    /// Errors when `start..end` touches a stack: the `[stack]` region, or the region holding
    /// a thread's stack pointer (thread stacks are anonymous mappings).
    fn check_not_stack(&self, start: Addr, end: Addr) -> R<()> {
        let sess = self.session()?;
        let regions = sess.proc.regions().map_err(s)?;
        let mut sps = thread_stack_pointers(sess.info.pid);
        if let Some(d) = lock(&sess.dbg).as_ref() {
            for t in d.d.threads().unwrap_or_default() {
                if let Ok(c) = d.d.context(t.tid) {
                    sps.push(c.rsp);
                }
            }
        }
        for r in regions.iter().filter(|r| r.start < end && start < r.start + r.size) {
            let tagged = r.path.as_deref().is_some_and(|p| p.starts_with("[stack"));
            if tagged || sps.iter().any(|&sp| sp >= r.start && sp < r.start + r.size) {
                return Err(format!(
                    "{start:#x}..{end:#x} is on a thread's stack ({:#x}..{:#x}): a page watch there would fault on every call and local variable. Watch it with a hardware watchpoint (8 bytes or less) instead",
                    r.start,
                    r.start + r.size
                ));
            }
        }
        Ok(())
    }

    pub fn debug_remove_breakpoint(&self, id: u32) -> R<()> {
        self.with_dbg(|d, _| {
            let i = d.bps.iter().position(|b| b.id == id).ok_or_else(|| format!("no breakpoint {id}"))?;
            d.d.remove_breakpoint(id).map_err(s)?;
            d.bps.remove(i);
            Ok(())
        })
    }

    /// In place: hits, records and trace are kept.
    pub fn debug_set_enabled(&self, id: u32, enabled: bool) -> R<()> {
        self.with_dbg(|d, _| {
            d.bp(id)?;
            d.d.set_enabled(id, enabled).map_err(s)?;
            if enabled {
                d.bp_mut(id)?.note = None;
            }
            Ok(())
        })
    }

    /// Sets (empty = clears) a breakpoint's condition, in place.
    pub fn debug_set_condition(&self, id: u32, condition: &str) -> R<()> {
        let cond = Some(condition.trim().to_string()).filter(|c| !c.is_empty());
        let hook = condition_hook(&cond)?;
        self.with_dbg(|d, _| {
            d.bp(id)?;
            d.d.set_condition(id, hook).map_err(s)?;
            d.bp_mut(id)?.cond = cond;
            Ok(())
        })
    }

    /// Replaces the hit options (`skip_hits`, `one_shot`, `max_hits`); hits so far count.
    pub fn debug_set_options(&self, id: u32, opts: BpOptions) -> R<()> {
        self.with_dbg(|d, _| {
            d.bp(id)?;
            d.d.set_options(id, BpOptions { max_hits: opts.max_hits.filter(|&m| m > 0), ..opts }).map_err(s)
        })
    }

    /// Re-applies the signal settings to an attached debugger.
    pub(crate) fn apply_signal_settings(&self) {
        let sig = lock(&self.x.settings).signals.clone();
        let _ = self.with_dbg(|d, _| {
            apply_signals(&d.d, &sig);
            Ok(())
        });
    }

    pub fn debug_breakpoints(&self) -> R<Vec<BpOut>> {
        let onbp = self.x.lua.onbp.load(std::sync::atomic::Ordering::SeqCst);
        self.with_dbg(|d, _| {
            d.pump(onbp);
            let live = d.d.breakpoints().map_err(s)?;
            Ok(d.bps
                .iter()
                .filter_map(|b| {
                    let i = live.iter().find(|i| i.id == b.id)?;
                    Some(BpOut {
                        id: b.id,
                        addr: hex_addr(i.bp.address),
                        kind: kind_str(i.bp.kind),
                        size: i.bp.size,
                        len: i.len.max(i.bp.size as u64),
                        method: match i.bp.method {
                            BpMethod::Software => "software",
                            BpMethod::Hardware => "hardware",
                            BpMethod::Page => "page",
                        },
                        action: match i.bp.action {
                            Action::Break => "break",
                            Action::Record => "record",
                            Action::Trace { .. } => "trace",
                        },
                        ea: b.ea,
                        enabled: i.enabled,
                        hits: i.hits,
                        slot: i.slot,
                        condition: b.cond.clone(),
                        stop_when: b.stop.clone(),
                        options: i.options.clone(),
                        records_dropped: i.records_dropped,
                        owner: if b.script { "script" } else { "user" },
                        note: if i.enabled { None } else { b.note.clone() },
                    })
                })
                .collect())
        })
    }

    /// Hit records of a `record` breakpoint, one row per (instruction, accessed address).
    pub fn debug_records(&self, id: u32) -> R<Vec<RecordOut>> {
        self.with_dbg(|d, sess| {
            d.bp(id)?;
            let recs = d.d.records(id).map_err(s)?;
            Ok(recs
                .into_iter()
                .map(|r| {
                    let at = r.insn.unwrap_or(r.ip);
                    let (bytes, text) = d.insn(sess, at);
                    RecordOut {
                        addr: hex_addr(at),
                        ip: hex_addr(r.ip),
                        bytes: hex_bytes(&bytes, " "),
                        text,
                        count: r.count,
                        address: r.address.map(hex_addr),
                        context: ctx_json(&r.context, true),
                    }
                })
                .collect())
        })
    }

    pub fn debug_clear_records(&self, id: u32) -> R<()> {
        self.with_dbg(|d, _| {
            d.bp(id)?;
            d.d.clear_records(id).map_err(s)
        })
    }

    /// Steps of the last trace of a `trace` breakpoint.
    pub fn debug_trace(&self, id: u32) -> R<Vec<TraceOut>> {
        self.with_dbg(|d, sess| {
            d.bp(id)?;
            let log = d.d.trace(id).map_err(s)?;
            Ok(log
                .iter()
                .take(MAX_TRACE)
                .map(|c| {
                    let (_, text) = d.insn(sess, c.rip);
                    TraceOut { addr: hex_addr(c.rip), text, context: ctx_json(c, false) }
                })
                .collect())
        })
    }

    pub fn debug_threads(&self) -> R<Vec<ThreadInfo>> {
        self.with_dbg(|d, _| d.d.threads().map_err(s))
    }

    pub fn debug_suspend_thread(&self, tid: Tid, suspend: bool) -> R<()> {
        self.with_dbg(|d, _| if suspend { d.d.suspend_thread(tid) } else { d.d.resume_thread(tid) }.map_err(s))
    }

    /// Registers of a stopped thread, values as hex strings (see `ctx_json`).
    pub fn debug_context(&self, tid: Tid) -> R<Value> {
        self.with_dbg(|d, _| d.d.context(tid).map(|c| ctx_json(&c, true)).map_err(s))
    }

    /// Sets one register of `REGS` (hex value) of a stopped thread.
    /// Also `st0`..`st7` (a decimal number), `xmm0`..`xmm15` (32 hex digits, the byte order
    /// `debug_context` shows) and `mxcsr`, `fcw`, `fsw` (hex).
    pub fn debug_set_register(&self, tid: Tid, name: &str, value: &str) -> R<()> {
        let name = name.trim().to_ascii_lowercase();
        let set = set_reg(&name, value)?;
        self.with_dbg(|d, _| {
            let mut c = d.d.context(tid).map_err(s)?;
            set(&mut c)?;
            d.d.set_context(tid, c).map_err(s)
        })
    }

    /// `count` stack slots from the thread's stack pointer, with module+offset comments.
    pub fn debug_stack(&self, tid: Tid, count: usize) -> R<Vec<StackOut>> {
        self.with_dbg(|d, sess| {
            let rsp = d.d.context(tid).map_err(s)?.rsp;
            let slots = d.d.read_stack(tid, count.min(4096)).map_err(s)?;
            let mods = sess.proc.modules().unwrap_or_default();
            Ok(slots
                .into_iter()
                .enumerate()
                .map(|(i, v)| StackOut {
                    addr: hex_addr(rsp + 8 * i as u64),
                    value: hex_addr(v),
                    comment: hh_asm::module_offset(&mods, v).unwrap_or_default(),
                })
                .collect())
        })
    }

    /// The thread's call chain (frame-pointer walk) with module and symbol names.
    pub fn debug_backtrace(&self, tid: Tid, max: usize) -> R<Vec<FrameOut>> {
        self.with_dbg(|d, _| {
            let f = d.d.backtrace_frames(tid, max.clamp(1, 256)).map_err(s)?;
            Ok(f.into_iter().map(|f| FrameOut { addr: hex_addr(f.addr), module: f.module, symbol: f.symbol }).collect())
        })
    }

    pub fn debug_continue(&self, pass_signal: bool) -> R<()> {
        self.with_dbg(|d, _| {
            d.d.cont(pass_signal).map_err(s)?;
            d.resumed();
            Ok(())
        })?;
        self.x.lua.engine.debug_resumed();
        Ok(())
    }

    pub fn debug_pause(&self) -> R<()> {
        self.with_dbg(|d, _| d.d.pause().map_err(s))
    }

    /// `kind`: `into` / `over` / `out`.
    pub fn debug_step(&self, tid: Tid, kind: &str) -> R<()> {
        self.with_dbg(|d, _| {
            match kind {
                "into" => d.d.step_into(tid),
                "over" => d.d.step_over(tid),
                "out" => d.d.step_out(tid),
                k => return Err(format!("unknown step kind {k:?}")),
            }
            .map_err(s)?;
            d.resumed();
            Ok(())
        })?;
        self.x.lua.engine.debug_resumed();
        Ok(())
    }

    /// Continues until a thread reaches `addr`: any thread, or only `tid` (others pass it).
    pub fn debug_run_to(&self, addr: &str, tid: Option<Tid>) -> R<()> {
        let a = parse_addr(addr)?;
        self.with_dbg(|d, _| {
            match tid {
                Some(t) => d.d.run_to_thread(t, a),
                None => d.d.run_to(a),
            }
            .map_err(s)?;
            d.resumed();
            Ok(())
        })?;
        self.x.lua.engine.debug_resumed();
        Ok(())
    }

    /// Replaces the instruction at `addr` with NOPs; returns its original bytes (hex) for
    /// restoring with `write_bytes`.
    pub fn nop_instruction(&self, addr: &str) -> R<String> {
        let sess = self.session()?;
        let p = hh_asm::nop_instruction(&*sess.proc, parse_addr(addr)?).map_err(s)?;
        Ok(hex_bytes(&p.original, "").to_lowercase())
    }

    // ------------------------------------------------------------ Lua (hh-lua DebugHost)

    /// Breakpoint for `debug_setBreakpoint`; attaches first like CE. Returns its id.
    pub(crate) fn lua_set_breakpoint(&self, spec: &hh_lua::BreakpointSpec) -> R<u32> {
        self.debug_attach()?;
        let addr = hex_addr(spec.address);
        // The same address set again replaces the old one.
        let _ = self.lua_remove_breakpoint(spec.address);
        use hh_lua::{BpMethod as M, BpTrigger as T};
        if spec.trigger != T::Execute && spec.method == M::Exception {
            let kind = if spec.trigger == T::Write { "write" } else { "access" };
            let start = spec.address;
            self.check_not_stack(start, start + spec.size.max(1) as u64)?;
            return self.with_dbg(|d, _| {
                let k = if kind == "write" { BpKind::Write } else { BpKind::Access };
                let id = d.d.add_watch_range(start, spec.size.max(1) as u64, k, Action::Break, Hooks::default(), BpOptions::default()).map_err(s)?;
                d.bps.push(AppBp { id, addr: start, ea: false, cond: None, script: true, note: None, stop: None });
                Ok(id)
            });
        }
        let (kind, method) = match (spec.trigger, spec.method) {
            (T::Execute, M::DebugRegister) => ("execute", "hardware"),
            (T::Execute, _) => ("execute", "software"),
            (T::Write, _) => ("write", "hardware"),
            (T::Access, _) => ("access", "hardware"),
        };
        let req = BpReq { addr, kind: kind.into(), size: spec.size.clamp(1, 8) as u8, method: method.into(), action: "break".into(), ..BpReq::default() };
        self.add_bp(&req, true)
    }

    /// Removes the script-owned breakpoint at `addr`.
    pub(crate) fn lua_remove_breakpoint(&self, addr: Addr) -> R<()> {
        let id = self.with_dbg(|d, _| d.bps.iter().find(|b| b.script && b.addr == addr).map(|b| b.id).ok_or_else(|| format!("no breakpoint at {addr:#x}")))?;
        self.debug_remove_breakpoint(id)
    }

    pub(crate) fn lua_continue(&self, tid: Tid, mode: hh_lua::ContinueMode, ctx: Option<&hh_lua::RegContext>) -> R<()> {
        self.with_dbg(|d, _| {
            if let Some(r) = ctx {
                let mut c = d.d.context(tid).map_err(s)?;
                merge_ctx(&mut c, r);
                d.d.set_context(tid, c).map_err(s)?;
            }
            match mode {
                hh_lua::ContinueMode::StepInto => d.d.step_into(tid),
                hh_lua::ContinueMode::StepOver => d.d.step_over(tid),
                _ => d.d.cont(false),
            }
            .map_err(s)?;
            d.resumed();
            Ok(())
        })
    }

    pub(crate) fn lua_debugging(&self) -> bool {
        self.session().is_ok_and(|s| lock(&s.dbg).is_some())
    }

    /// Runs the Lua function of a breakpoint hit (driver thread): sets the register globals,
    /// applies the registers the function changed and resumes when it returned true.
    pub(crate) fn dispatch_lua_break(&self) {
        let Ok(sess) = self.session() else { return };
        let onbp = self.x.lua.onbp.load(std::sync::atomic::Ordering::SeqCst);
        let ev = {
            let mut g = lock(&sess.dbg);
            let Some(d) = g.as_mut() else { return };
            d.pump(onbp);
            d.lua_break.as_ref().and_then(|(tid, id, c)| Some((*tid, d.bp(*id).ok()?.addr, reg_ctx(c))))
        };
        let Some((tid, addr, context)) = ev else { return };
        let r = {
            let _g = self.x.lua.enter();
            let r = self.x.lua.engine.on_breakpoint(&hh_lua::BreakEvent { thread_id: tid, address: addr, context });
            self.x.lua.refresh_onbp();
            r
        };
        let mut g = lock(&sess.dbg);
        let Some(d) = g.as_mut() else { return };
        // The function may have continued the thread itself (debug_continueFromBreakpoint).
        let still = d.lua_break.take().is_some() && matches!(d.d.state(), Ok(State::Broken { tid: t }) if t == tid);
        match r {
            Ok(res) if still => {
                if let Some(rc) = res.context
                    && let Ok(mut c) = d.d.context(tid)
                {
                    merge_ctx(&mut c, &rc);
                    if let Err(e) = d.d.set_context(tid, c) {
                        self.x.lua.console.push("err", &format!("breakpoint at {addr:#x}: setting registers: {e}"));
                    }
                }
                if res.resume {
                    match d.d.cont(false) {
                        Ok(()) => d.resumed(),
                        Err(e) => self.x.lua.console.push("err", &format!("breakpoint at {addr:#x}: {e}")),
                    }
                }
            }
            Ok(_) => {}
            Err(e) => self.x.lua.console.push("err", &format!("breakpoint at {addr:#x}: {e}")),
        }
    }
}

/// Stack pointers of threads blocked in a system call (`/proc/<pid>/task/*/syscall`).
fn thread_stack_pointers(pid: u32) -> Vec<Addr> {
    let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/task")) else { return Vec::new() };
    dir.filter_map(|t| {
        let txt = std::fs::read_to_string(t.ok()?.path().join("syscall")).ok()?;
        // `nr arg1..arg6 sp pc`, or `running` / `-1 sp pc`.
        let f: Vec<&str> = txt.split_whitespace().collect();
        (f.len() >= 3).then(|| parse_addr(f[f.len() - 2]).ok()).flatten()
    })
    .collect()
}

impl App {
    /// Signals the debugger knows: (code, name, default action, action the attached
    /// debugger uses now or `None` when detached).
    pub fn debug_signals(&self) -> R<Vec<SignalRow>> {
        let live = self.with_dbg(|d, _| d.d.signal_actions().map_err(s)).unwrap_or_default();
        Ok(hh_debug::signal_table()
            .into_iter()
            .map(|i| (i.code, i.name, action_str(i.default), live.iter().find(|l| l.0 == i.code).map(|l| action_str(l.1))))
            .collect())
    }
}

/// (code, name, default action, current action when attached).
pub type SignalRow = (u32, &'static str, &'static str, Option<&'static str>);

fn action_str(a: SignalAction) -> &'static str {
    match a {
        SignalAction::Pass => "pass",
        SignalAction::Ignore => "ignore",
        SignalAction::Break => "break",
    }
}

/// Settings `signals` (code -> pass/ignore/break) over the debugger's defaults: everything
/// is reset to the defaults first, so a removed override takes effect.
fn apply_signals(d: &Debugger, set: &std::collections::BTreeMap<String, String>) {
    let _ = d.reset_signal_actions();
    for (code, a) in set {
        let Ok(code) = code.parse::<u32>() else { continue };
        let a = match a.as_str() {
            "ignore" => SignalAction::Ignore,
            "break" => SignalAction::Break,
            _ => SignalAction::Pass,
        };
        let _ = d.set_signal_action(code, a);
    }
}

/// Breakpoint condition: integers (decimal, `0x` hex), registers (`rax`..`r15`, `rip`,
/// `rflags`, 32-bit `eax`..`r15d`), `+ - * & | ^`, comparisons `== != < <= > >=`, `!`,
/// `&& ||` and parentheses. Unsigned 64-bit arithmetic; comparisons give 0 or 1.
#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    Num(u64),
    Reg(String),
    Not(Box<Cond>),
    Bin(String, Box<Cond>, Box<Cond>),
}

fn reg_of(c: &Context, n: &str) -> Option<u64> {
    let mut c = c.clone();
    if let Some(v) = reg_mut(&mut c, n) {
        return Some(*v);
    }
    let full = match n {
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" => format!("r{}", &n[1..]),
        _ => n.strip_suffix('d').filter(|r| r.starts_with('r') && r[1..].parse::<u8>().is_ok())?.to_string(),
    };
    reg_mut(&mut c, &full).map(|v| *v & 0xffff_ffff)
}

impl Cond {
    pub fn parse(src: &str) -> R<Cond> {
        let toks = Self::lex(src)?;
        let mut i = 0;
        let e = Self::level(&toks, &mut i, 0)?;
        if i != toks.len() {
            return Err(format!("condition: unexpected {:?}", toks[i]));
        }
        Ok(e)
    }

    fn lex(src: &str) -> R<Vec<String>> {
        let b = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let c = b[i] as char;
            if c.is_whitespace() {
                i += 1;
            } else if c.is_ascii_alphanumeric() || c == '_' {
                let s = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push(src[s..i].to_lowercase());
            } else {
                let two = src.get(i..i + 2).unwrap_or("");
                if ["==", "!=", "<=", ">=", "&&", "||"].contains(&two) {
                    out.push(two.into());
                    i += 2;
                } else if "+-*&|^<>!()".contains(c) {
                    out.push(c.into());
                    i += 1;
                } else {
                    return Err(format!("condition: unexpected {c:?}"));
                }
            }
        }
        Ok(out)
    }

    /// Precedence climbing; level 0 = `||` (loosest).
    fn level(t: &[String], i: &mut usize, lvl: usize) -> R<Cond> {
        const OPS: [&[&str]; 8] = [&["||"], &["&&"], &["|"], &["^"], &["&"], &["==", "!=", "<", "<=", ">", ">="], &["+", "-"], &["*"]];
        if lvl == OPS.len() {
            return Self::atom(t, i);
        }
        let mut l = Self::level(t, i, lvl + 1)?;
        while let Some(op) = t.get(*i).filter(|o| OPS[lvl].contains(&o.as_str())) {
            let op = op.clone();
            *i += 1;
            let r = Self::level(t, i, lvl + 1)?;
            l = Cond::Bin(op, Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn atom(t: &[String], i: &mut usize) -> R<Cond> {
        let tok = t.get(*i).ok_or("condition: unexpected end")?.clone();
        *i += 1;
        match tok.as_str() {
            "!" => Ok(Cond::Not(Box::new(Self::atom(t, i)?))),
            "(" => {
                let e = Self::level(t, i, 0)?;
                if t.get(*i).map(String::as_str) != Some(")") {
                    return Err("condition: missing )".into());
                }
                *i += 1;
                Ok(e)
            }
            s if s.starts_with("0x") => u64::from_str_radix(&s[2..], 16).map(Cond::Num).map_err(|_| format!("condition: bad number {s}")),
            s if s.as_bytes()[0].is_ascii_digit() => s.parse().map(Cond::Num).map_err(|_| format!("condition: bad number {s}")),
            s if reg_of(&Context::default(), s).is_some() => Ok(Cond::Reg(s.into())),
            s => Err(format!("condition: unknown name {s:?}")),
        }
    }

    pub fn eval(&self, c: &Context) -> u64 {
        match self {
            Cond::Num(n) => *n,
            Cond::Reg(r) => reg_of(c, r).unwrap_or(0),
            Cond::Not(e) => (e.eval(c) == 0) as u64,
            Cond::Bin(op, a, b) => {
                let (x, y) = (a.eval(c), b.eval(c));
                match op.as_str() {
                    "||" => (x != 0 || y != 0) as u64,
                    "&&" => (x != 0 && y != 0) as u64,
                    "|" => x | y,
                    "^" => x ^ y,
                    "&" => x & y,
                    "==" => (x == y) as u64,
                    "!=" => (x != y) as u64,
                    "<" => (x < y) as u64,
                    "<=" => (x <= y) as u64,
                    ">" => (x > y) as u64,
                    ">=" => (x >= y) as u64,
                    "+" => x.wrapping_add(y),
                    "-" => x.wrapping_sub(y),
                    _ => x.wrapping_mul(y),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f80_round_trip() {
        // Subnormal doubles become normal extended numbers (f80, a display helper, rounds them to 0).
        assert_eq!(to_f80(5e-324), [0, 0, 0, 0, 0, 0, 0, 0x80, 0xcd, 0x3b]);
        for v in [0.0, -0.0, 1.0, -1.5, 3.25e10, 1e-300, 2.2250738585072014e-308, f64::MAX, f64::INFINITY, -f64::INFINITY] {
            assert_eq!(f80(&to_f80(v)).to_bits(), v.to_bits(), "{v}");
        }
        assert!(f80(&to_f80(f64::NAN)).is_nan());
        // 1.0 is the textbook encoding: exponent 0x3fff, explicit integer bit.
        assert_eq!(to_f80(1.0), [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]);
        assert!(set_reg("xmm0", "12").is_err());
        assert!(set_reg("st0", "x").is_err());
    }

    #[test]
    fn conditions() {
        let c = Context { rax: 5, rcx: 0x101, rdx: 0x1_0000_0002, ..Context::default() };
        let t = |s: &str| Cond::parse(s).unwrap().eval(&c);
        assert_eq!(t("rax==5 && rcx>0x100"), 1);
        assert_eq!(t("rax==5 && rcx>0x200"), 0);
        assert_eq!(t("RAX == 4 || !(rcx < 0x100)"), 1);
        assert_eq!(t("edx == 2 && rdx != 2"), 1);
        assert_eq!(t("rax + 1 == 6 && (rcx & 0xff) == 1"), 1);
        assert_eq!(t("1 + 2 * 3"), 7);
        assert!(Cond::parse("rax ==").is_err() && Cond::parse("foo == 1").is_err() && Cond::parse("rax = 1").is_err());
    }

    #[test]
    fn f80_values() {
        // 1.0: exponent 16383, explicit integer bit.
        let mut b = [0u8; 10];
        b[7] = 0x80;
        b[8..].copy_from_slice(&16383u16.to_le_bytes());
        assert_eq!(f80(&b), 1.0);
        b[9] |= 0x80;
        assert_eq!(f80(&b), -1.0);
        assert_eq!(f80(&[0; 10]), 0.0);
    }

    #[test]
    fn effective_address_from_registers() {
        // mov [rdi+rcx*4+10], eax
        let p = hh_core::MockProcess::new(0x1000, vec![0x89, 0x44, 0x8f, 0x10, 0, 0, 0, 0]);
        let f = ea_hook(&p, 0x1000).unwrap();
        let c = Context { rdi: 0x5000, rcx: 2, ..Context::default() };
        assert_eq!(f(&c), Some(0x5000 + 8 + 0x10));
        let ctx = ctx_json(&c, true);
        assert_eq!(ctx["rdi"], "0x5000");
        assert_eq!(ctx["fpu"]["xmm"].as_array().unwrap().len(), 16);
    }
}
