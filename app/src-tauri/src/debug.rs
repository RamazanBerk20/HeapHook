//! Debugger commands over hh-debug. One debugger per session, attached and detached
//! explicitly; while attached every other command reaches the target through
//! `Debugger::process()` (the session's `Switch`).
//!
//! Breakpoints get app-level ids so they survive disable/enable (hh-debug has no disable:
//! a disabled breakpoint is removed from the engine and re-added on enable).
use std::collections::HashMap;
use std::sync::Arc;

use hh_core::{Addr, Process};
use hh_debug::{Action, AddressOf, BpId, BpKind, BpMethod, BreakReason, Breakpoint, Context, Debugger, Event, Hooks, SignalAction, State, ThreadInfo, Tid};
use iced_x86::{Decoder, DecoderOptions, OpKind, Register};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::commands::{App, R, Session, hex_addr, hex_bytes, lock, parse_addr, s};

/// Most trace steps returned with full registers (the UI shows one at a time).
const MAX_TRACE: usize = 100_000;

pub struct Dbg {
    d: Debugger,
    /// Last break: (tid, reason text).
    last: Option<(Tid, String)>,
    exit_code: Option<Option<i32>>,
    bps: Vec<AppBp>,
    next_id: u32,
    /// Trap ip -> (instruction address, its bytes, text), for record lists.
    insns: HashMap<(Addr, bool), (Addr, Vec<u8>, String)>,
}

struct AppBp {
    id: u32,
    bp: Breakpoint,
    /// Record the effective address the instruction accesses.
    ea: bool,
    /// Condition over registers; hits where it is false are ignored.
    cond: Option<String>,
    engine: Option<BpId>,
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
    pub method: &'static str,
    pub action: &'static str,
    pub ea: bool,
    pub enabled: bool,
    pub hits: u64,
    pub slot: Option<u8>,
    pub condition: Option<String>,
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
    /// Accessed address, for `ea` breakpoints.
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

fn reason_text(r: &BreakReason, bps: &[AppBp]) -> String {
    let app_id = |e: BpId| bps.iter().find(|b| b.engine == Some(e)).map_or(e, |b| b.id);
    match r {
        BreakReason::Breakpoint(id) => format!("breakpoint {}", app_id(*id)),
        BreakReason::Step => "step".into(),
        BreakReason::Pause => "paused".into(),
        BreakReason::Signal { code, address: Some(a) } => format!("signal {code} at {a:#x}"),
        BreakReason::Signal { code, address: None } => format!("signal {code}"),
        BreakReason::TraceStop(id) => format!("trace stop, breakpoint {}", app_id(*id)),
    }
}

impl Dbg {
    fn add_engine(&self, b: &AppBp, proc: &dyn Process) -> R<BpId> {
        let condition = match &b.cond {
            Some(c) => {
                let c = Arc::new(Cond::parse(c)?);
                Some(Arc::new(move |x: &Context| c.eval(x) != 0) as hh_debug::Predicate)
            }
            None => None,
        };
        let hooks = Hooks { address_of: if b.ea { Some(ea_hook(proc, b.bp.address)?) } else { None }, condition, ..Hooks::default() };
        self.d.add_breakpoint(b.bp.clone(), hooks).map_err(s)
    }

    fn bp(&self, id: u32) -> R<&AppBp> {
        self.bps.iter().find(|b| b.id == id).ok_or_else(|| format!("no breakpoint {id}"))
    }

    /// Instruction for a record: the one ending at `ip` (`before`, data watchpoints trap after
    /// the access) or the one at `ip`. Cached while its bytes stay the same.
    fn insn(&mut self, sess: &Session, ip: Addr, before: bool) -> (Addr, Vec<u8>, String) {
        let p = &*sess.proc;
        if let Some(c) = self.insns.get(&(ip, before)) {
            let mut b = vec![0u8; c.1.len()];
            if p.read_exact(c.0, &mut b).is_ok() && b == c.1 {
                return c.clone();
            }
        }
        let at = if before { hh_asm::previous_instruction(p, ip).unwrap_or(ip) } else { ip };
        let syms = lock(&sess.syms).clone();
        let v = match hh_asm::disassemble(p, &syms, at, 1).ok().and_then(|l| l.into_iter().next()) {
            Some(l) => (at, l.bytes, l.text),
            None => (at, Vec::new(), "??".into()),
        };
        self.insns.insert((ip, before), v.clone());
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
    pub fn debug_attach(&self) -> R<DebugStatus> {
        let sess = self.session()?;
        {
            let mut g = lock(&sess.dbg);
            if g.is_none() {
                let d = Debugger::attach(sess.info.pid).map_err(s)?;
                sess.switch.set(d.process());
                apply_signals(&d, &lock(&self.x.settings).signals);
                *g = Some(Dbg { d, last: None, exit_code: None, bps: Vec::new(), next_id: 1, insns: HashMap::new() });
            }
        }
        self.debug_status()
    }

    /// Removes every breakpoint, detaches (the target keeps running) and switches memory
    /// access back to the plain process.
    pub fn debug_detach(&self) -> R<()> {
        let sess = self.session()?;
        let d = lock(&sess.dbg).take();
        sess.switch.set(sess.raw.clone());
        match d {
            Some(d) => d.d.detach().map_err(s),
            None => Ok(()),
        }
    }

    /// Current state; drains debugger events (break reasons, exit).
    pub fn debug_status(&self) -> R<DebugStatus> {
        let sess = self.session()?;
        let mut g = lock(&sess.dbg);
        let Some(d) = g.as_mut() else {
            return Ok(DebugStatus { attached: false, state: "detached", tid: None, reason: None, rip: None, exit_code: None });
        };
        for e in d.d.events() {
            match e {
                Event::Break { tid, reason, .. } => d.last = Some((tid, reason_text(&reason, &d.bps))),
                Event::ProcessExited { code } => d.exit_code = Some(code),
                _ => {}
            }
        }
        let st = if d.exit_code.is_some() { State::Exited } else { d.d.state().unwrap_or(State::Exited) };
        let mut out = DebugStatus { attached: true, state: "running", tid: None, reason: None, rip: None, exit_code: d.exit_code.flatten() };
        match st {
            State::Running => {}
            State::Suspended => out.state = "suspended",
            State::Exited => out.state = "exited",
            State::Broken { tid } => {
                out.state = "broken";
                out.tid = Some(tid);
                out.reason = d.last.as_ref().filter(|l| l.0 == tid).map(|l| l.1.clone()).or(Some("break".into()));
                out.rip = d.d.context(tid).ok().map(|c| hex_addr(c.rip));
            }
        }
        Ok(out)
    }

    /// Adds a breakpoint/watchpoint; returns its id.
    pub fn debug_add_breakpoint(&self, req: &BpReq) -> R<u32> {
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
        self.with_dbg(|d, sess| {
            let id = d.next_id;
            let cond = Some(req.condition.trim().to_string()).filter(|c| !c.is_empty());
            let mut b = AppBp { id, bp: Breakpoint { address, kind, size, method, action }, ea: req.ea, cond, engine: None };
            b.engine = Some(d.add_engine(&b, &*sess.proc)?);
            d.next_id += 1;
            d.bps.push(b);
            Ok(id)
        })
    }

    pub fn debug_remove_breakpoint(&self, id: u32) -> R<()> {
        self.with_dbg(|d, _| {
            let i = d.bps.iter().position(|b| b.id == id).ok_or_else(|| format!("no breakpoint {id}"))?;
            if let Some(e) = d.bps[i].engine {
                d.d.remove_breakpoint(e).map_err(s)?;
            }
            d.bps.remove(i);
            Ok(())
        })
    }

    pub fn debug_set_enabled(&self, id: u32, enabled: bool) -> R<()> {
        self.with_dbg(|d, sess| {
            let b = d.bp(id)?;
            match (enabled, b.engine) {
                (true, None) => {
                    let e = d.add_engine(b, &*sess.proc)?;
                    d.bps.iter_mut().filter(|b| b.id == id).for_each(|b| b.engine = Some(e));
                }
                (false, Some(e)) => {
                    d.d.remove_breakpoint(e).map_err(s)?;
                    d.bps.iter_mut().filter(|b| b.id == id).for_each(|b| b.engine = None);
                }
                _ => {}
            }
            Ok(())
        })
    }

    /// Sets (empty = clears) a breakpoint's condition. The engine has no way to change a
    /// hook in place, so an enabled breakpoint is re-added (its hit count restarts).
    pub fn debug_set_condition(&self, id: u32, condition: &str) -> R<()> {
        let cond = Some(condition.trim().to_string()).filter(|c| !c.is_empty());
        if let Some(c) = &cond {
            Cond::parse(c)?;
        }
        self.with_dbg(|d, sess| {
            let i = d.bps.iter().position(|b| b.id == id).ok_or_else(|| format!("no breakpoint {id}"))?;
            d.bps[i].cond = cond;
            if let Some(e) = d.bps[i].engine.take() {
                d.d.remove_breakpoint(e).map_err(s)?;
                let n = d.add_engine(&d.bps[i], &*sess.proc)?;
                d.bps[i].engine = Some(n);
            }
            Ok(())
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
        self.with_dbg(|d, _| {
            let live = d.d.breakpoints().map_err(s)?;
            Ok(d.bps
                .iter()
                .map(|b| {
                    let info = live.iter().find(|i| Some(i.id) == b.engine);
                    BpOut {
                        id: b.id,
                        addr: hex_addr(b.bp.address),
                        kind: kind_str(b.bp.kind),
                        size: b.bp.size,
                        method: if b.bp.method == BpMethod::Software { "software" } else { "hardware" },
                        action: match b.bp.action {
                            Action::Break => "break",
                            Action::Record => "record",
                            Action::Trace { .. } => "trace",
                        },
                        ea: b.ea,
                        enabled: b.engine.is_some(),
                        hits: info.map_or(0, |i| i.hits),
                        slot: info.and_then(|i| i.slot),
                        condition: b.cond.clone(),
                    }
                })
                .collect())
        })
    }

    /// Hit records of a `record` breakpoint, one row per (instruction, accessed address).
    pub fn debug_records(&self, id: u32) -> R<Vec<RecordOut>> {
        self.with_dbg(|d, sess| {
            let b = d.bp(id)?;
            let Some(e) = b.engine else { return Ok(Vec::new()) };
            let before = b.bp.kind != BpKind::Execute;
            let recs = d.d.records(e).map_err(s)?;
            Ok(recs
                .into_iter()
                .map(|r| {
                    let (at, bytes, text) = d.insn(sess, r.ip, before);
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
        self.with_dbg(|d, _| match d.bp(id)?.engine {
            Some(e) => d.d.clear_records(e).map_err(s),
            None => Ok(()),
        })
    }

    /// Steps of the last trace of a `trace` breakpoint.
    pub fn debug_trace(&self, id: u32) -> R<Vec<TraceOut>> {
        self.with_dbg(|d, sess| {
            let Some(e) = d.bp(id)?.engine else { return Ok(Vec::new()) };
            let log = d.d.trace(e).map_err(s)?;
            Ok(log
                .iter()
                .take(MAX_TRACE)
                .map(|c| {
                    let (_, _, text) = d.insn(sess, c.rip, false);
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
    pub fn debug_set_register(&self, tid: Tid, name: &str, value: &str) -> R<()> {
        let v = parse_addr(value)?;
        self.with_dbg(|d, _| {
            let mut c = d.d.context(tid).map_err(s)?;
            *reg_mut(&mut c, name).ok_or_else(|| format!("unknown register {name:?}"))? = v;
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

    pub fn debug_continue(&self, pass_signal: bool) -> R<()> {
        self.with_dbg(|d, _| d.d.cont(pass_signal).map_err(s))
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
            .map_err(s)
        })
    }

    pub fn debug_run_to(&self, addr: &str) -> R<()> {
        let a = parse_addr(addr)?;
        self.with_dbg(|d, _| d.d.run_to(a).map_err(s))
    }

    /// Replaces the instruction at `addr` with NOPs; returns its original bytes (hex) for
    /// restoring with `write_bytes`.
    pub fn nop_instruction(&self, addr: &str) -> R<String> {
        let sess = self.session()?;
        let p = hh_asm::nop_instruction(&*sess.proc, parse_addr(addr)?).map_err(s)?;
        Ok(hex_bytes(&p.original, "").to_lowercase())
    }
}

/// Linux signals the UI offers, with hh-debug's default action.
pub const SIGNALS: [(u32, &str, &str); 14] = [
    (2, "SIGINT", "pass"), (4, "SIGILL", "break"), (6, "SIGABRT", "pass"), (7, "SIGBUS", "break"), (8, "SIGFPE", "break"),
    (10, "SIGUSR1", "pass"), (11, "SIGSEGV", "break"), (12, "SIGUSR2", "pass"), (13, "SIGPIPE", "pass"), (14, "SIGALRM", "pass"),
    (15, "SIGTERM", "pass"), (17, "SIGCHLD", "pass"), (28, "SIGWINCH", "pass"), (29, "SIGIO", "pass"),
];

/// Settings `signals` (signal number -> pass/ignore/break) over the defaults of [`SIGNALS`].
// shortcut: Linux signal numbers only; Windows exception codes keep hh-debug's defaults.
fn apply_signals(d: &Debugger, set: &std::collections::BTreeMap<String, String>) {
    if cfg!(not(target_os = "linux")) {
        return;
    }
    for (code, _, dflt) in SIGNALS {
        let a = set.get(&code.to_string()).map_or(dflt, String::as_str);
        let a = match a {
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
