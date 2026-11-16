//! OS-independent debugger logic, run on the dedicated debugger thread. The OS backend
//! (`crate::os`) only knows how to wait for, stop and resume threads and how to access
//! registers; breakpoints, stepping, recording and tracing live here.
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::time::Duration;

use hh_core::{Addr, Error, Module, Pid, Process, Result};

use crate::os::Os;
use crate::{
    Action, BpId, BpKind, BpMethod, BreakReason, Breakpoint, BreakpointInfo, Context, Event,
    HitRecord, Hooks, Shared, SignalAction, State, ThreadInfo, Tid,
};

/// What the backend saw. `Trap` is any debug trap (int3, single-step, debug register);
/// the engine works out which.
pub(crate) enum Raw {
    Trap {
        code: u32,
        /// The OS says it may be an int3 (only then is rip-1 checked for our breakpoints).
        int3: bool,
    },
    Signal {
        code: u32,
        addr: Option<Addr>,
        first_chance: bool,
    },
    /// Reported by the parent (Linux) or the new thread itself (Windows).
    ThreadCreated(Tid),
    ThreadExited,
    ProcessExited {
        code: Option<i32>,
    },
    // Linux finds modules through the loader breakpoint instead.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    ModuleLoaded(Module),
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    ModuleUnloaded(Addr),
    /// The image was replaced (Linux execve): all int3 patches are gone.
    #[cfg_attr(windows, allow(dead_code))]
    Exec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Stay,
    Cont,
    Step,
}

pub(crate) enum StepKind {
    Into,
    Over,
    Out,
}

enum Stop {
    Trap {
        stepped: bool,
        hw: u8,
        sw: Option<Addr>,
    },
    Signal {
        code: u32,
        addr: Option<Addr>,
        first_chance: bool,
    },
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Goal {
    #[default]
    Idle,
    Step,
    Over,
    Out(u32),
    Trace {
        bp: BpId,
        left: u32,
        over: bool,
    },
}

enum Reinsert {
    Sw(Addr),
    Hw,
}

#[derive(Default)]
struct Th {
    suspended: bool,
    goal: Goal,
    /// A goal step is in flight: (rip, rsp, step over calls) before it.
    step_pre: Option<(Addr, u64, bool)>,
    /// Single-step on the next resume.
    want_step: bool,
    /// The last resume single-stepped (so the next trap is that step).
    stepped: bool,
    /// Stopped on an execute breakpoint it reported; resuming must step past it first.
    at_bp: bool,
    /// Breakpoint temporarily removed to step past it.
    reinsert: Option<Reinsert>,
    /// The instruction being stepped (step out) is a `ret`.
    was_ret: bool,
}

struct Temp {
    addr: Addr,
    /// Only this thread, and only once the stack is back at `min_sp` (recursion).
    tid: Option<Tid>,
    min_sp: u64,
    run_to: bool,
}

struct Bp {
    info: BreakpointInfo,
    hooks: Hooks,
    records: BTreeMap<(Addr, Option<Addr>), HitRecord>,
    trace: Vec<Context>,
}

const STEP_OUT_LIMIT: u32 = 1_000_000;

thread_local! {
    static ENGINE_THREAD: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn on_engine_thread() -> bool {
    ENGINE_THREAD.with(|c| c.get())
}

/// User callbacks may panic; a panic must not kill the thread that holds the tracee.
fn guard<R>(default: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

type Cmd = Box<dyn FnOnce(&mut Engine) + Send>;

pub(crate) fn run(
    pid: Pid,
    mem: Arc<dyn Process>,
    shared: Arc<Shared>,
    events: Sender<Event>,
    rx: Receiver<Cmd>,
    ok: SyncSender<Result<()>>,
) {
    ENGINE_THREAD.with(|c| c.set(true));
    let mut e = match Engine::start(pid, mem, shared, events) {
        Ok(e) => e,
        Err(err) => {
            let _ = ok.send(Err(err));
            return;
        }
    };
    let _ = ok.send(Ok(()));
    if catch_unwind(AssertUnwindSafe(|| e.main_loop(&rx))).is_err() {
        // A bug, not bad input: at least leave the target running without our int3s.
        let _ = catch_unwind(AssertUnwindSafe(|| e.detach()));
    }
}

pub(crate) struct Engine {
    os: Os,
    mem: Arc<dyn Process>,
    shared: Arc<Shared>,
    events: Sender<Event>,
    bps: BTreeMap<BpId, Bp>,
    next_id: BpId,
    /// Armed int3 addresses with reference counts (user, temporary, loader breakpoints).
    sw: HashMap<Addr, u32>,
    slots: [Option<BpId>; 4],
    threads: BTreeMap<Tid, Th>,
    broken: Option<(Tid, bool)>,
    suspended: bool,
    /// Only this thread may run (a user single-step).
    exclusive: Option<Tid>,
    /// Stops that arrived while halting, handled before anything resumes.
    deferred: VecDeque<(Tid, Stop)>,
    temps: Vec<Temp>,
    policy: HashMap<u32, SignalAction>,
    alive: bool,
    done: bool,
    loader: Option<Addr>,
    modules: Vec<Module>,
}

impl Engine {
    fn start(
        pid: Pid,
        mem: Arc<dyn Process>,
        shared: Arc<Shared>,
        events: Sender<Event>,
    ) -> Result<Engine> {
        let (os, raws) = Os::attach(pid, &*mem)?;
        let mut e = Engine {
            threads: os.tids().into_iter().map(|t| (t, Th::default())).collect(),
            os,
            mem,
            shared,
            events,
            bps: BTreeMap::new(),
            next_id: 1,
            sw: HashMap::new(),
            slots: [None; 4],
            broken: None,
            suspended: false,
            exclusive: None,
            deferred: VecDeque::new(),
            temps: Vec::new(),
            policy: Os::default_policy().into_iter().collect(),
            alive: true,
            done: false,
            loader: None,
            modules: Vec::new(),
        };
        let r = e.init(raws);
        if r.is_err() {
            let _ = e.detach();
        }
        r.map(|_| e)
    }

    fn init(&mut self, raws: Vec<(Tid, Raw)>) -> Result<()> {
        for (t, raw) in raws {
            self.on_raw(t, raw, true)?;
        }
        if let Some(a) = self.os.loader_hook(&*self.mem) {
            self.modules = self.mem.modules().unwrap_or_default();
            if self.arm_sw(a).is_ok() {
                self.loader = Some(a);
            }
        }
        self.resume_all()
    }

    fn main_loop(&mut self, rx: &Receiver<Cmd>) {
        while !self.done {
            let mut busy = false;
            if self.alive {
                for _ in 0..64 {
                    match self.os.poll() {
                        Ok(Some((t, raw))) => {
                            busy = true;
                            if self.on_raw(t, raw, false).is_err() {
                                let _ = self.resume_all();
                            }
                            if !self.alive {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
            // shortcut: neither ptrace nor the Win32 debug API can be waited on together with a
            // channel, so idle polling costs up to 1 ms of event latency.
            let first = if busy {
                rx.try_recv().map_err(|e| e == TryRecvError::Disconnected)
            } else {
                let wait = Duration::from_millis(if self.alive { 1 } else { 50 });
                rx.recv_timeout(wait)
                    .map_err(|e| e == RecvTimeoutError::Disconnected)
            };
            match first {
                Ok(c) => {
                    c(self);
                    while !self.done {
                        let Ok(c) = rx.try_recv() else { break };
                        c(self);
                    }
                }
                Err(true) => {
                    let _ = self.detach();
                    return;
                }
                Err(false) => {}
            }
        }
    }

    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    fn live(&self) -> Result<()> {
        if self.alive {
            Ok(())
        } else {
            Err(Error::ProcessGone)
        }
    }

    // ---- events -------------------------------------------------------------------------

    fn on_raw(&mut self, tid: Tid, raw: Raw, defer: bool) -> Result<()> {
        let stop = match raw {
            Raw::Trap { code, int3 } => self.classify(tid, code, int3)?,
            Raw::Signal {
                code,
                addr,
                first_chance,
            } => Stop::Signal {
                code,
                addr,
                first_chance,
            },
            Raw::ThreadCreated(new) => {
                self.threads.entry(new).or_default();
                self.emit(Event::ThreadCreated { tid: new });
                return if defer { Ok(()) } else { self.resume_all() };
            }
            Raw::ThreadExited => {
                self.threads.remove(&tid);
                self.deferred.retain(|d| d.0 != tid);
                let (gone, keep) = std::mem::take(&mut self.temps)
                    .into_iter()
                    .partition(|t| t.tid == Some(tid));
                self.temps = keep;
                for t in gone {
                    let _ = self.disarm_sw(t.addr);
                }
                if self.exclusive == Some(tid) {
                    self.exclusive = None;
                }
                self.emit(Event::ThreadExited { tid });
                return if defer { Ok(()) } else { self.resume_all() };
            }
            Raw::ProcessExited { code } => {
                self.alive = false;
                self.emit(Event::ProcessExited { code });
                return Ok(());
            }
            Raw::ModuleLoaded(m) => {
                self.emit(Event::ModuleLoaded(m));
                return if defer { Ok(()) } else { self.resume_all() };
            }
            Raw::ModuleUnloaded(base) => {
                self.emit(Event::ModuleUnloaded { base });
                return if defer { Ok(()) } else { self.resume_all() };
            }
            Raw::Exec => {
                // shortcut: breakpoints are not re-armed in the new image; hardware ones stay.
                self.sw.clear();
                self.shared.lock().clear();
                self.loader = None;
                return if defer { Ok(()) } else { self.resume_all() };
            }
        };
        if defer {
            self.deferred.push_back((tid, stop));
            Ok(())
        } else {
            self.handle(tid, stop)
        }
    }

    fn classify(&mut self, tid: Tid, code: u32, int3: bool) -> Result<Stop> {
        let th = self.threads.entry(tid).or_default();
        let stepped = std::mem::take(&mut th.stepped);
        if stepped {
            th.want_step = false;
        }
        let hw = (self.os.take_dr6(tid)? & 0xf) as u8;
        let mut sw = None;
        if !stepped && int3 {
            // int3 traps after itself: rewind onto the breakpoint.
            let (pc, _) = self.os.pc_sp(tid)?;
            if let Some(a) = pc.checked_sub(1)
                && self.sw.contains_key(&a)
            {
                self.os.set_pc(tid, a)?;
                sw = Some(a);
            }
        }
        if !stepped && hw == 0 && sw.is_none() {
            // Not ours: the program's own int3 / SIGTRAP.
            return Ok(Stop::Signal {
                code,
                addr: None,
                first_chance: true,
            });
        }
        Ok(Stop::Trap { stepped, hw, sw })
    }

    fn handle(&mut self, tid: Tid, stop: Stop) -> Result<()> {
        match stop {
            Stop::Signal {
                code,
                addr,
                first_chance,
            } => {
                let action = match first_chance {
                    true => self
                        .policy
                        .get(&code)
                        .copied()
                        .unwrap_or(SignalAction::Pass),
                    false => SignalAction::Break,
                };
                if action == SignalAction::Break {
                    self.os.set_pass(tid, true);
                    return self.enter_break(
                        tid,
                        BreakReason::Signal {
                            code,
                            address: addr,
                        },
                    );
                }
                let passed = action == SignalAction::Pass;
                self.os.set_pass(tid, passed);
                self.emit(Event::Signal {
                    tid,
                    code,
                    address: addr,
                    passed,
                });
                self.resume_all()
            }
            Stop::Trap { stepped, hw, sw } => {
                if stepped
                    && let Some(r) = self.threads.get_mut(&tid).and_then(|t| t.reinsert.take())
                {
                    self.rearm(tid, r)?;
                }
                let ctx = self.os.context(tid)?;
                let mut brk = None;
                for slot in 0..4 {
                    if hw & (1 << slot) == 0 {
                        continue;
                    }
                    let Some(id) = self.slots[slot] else { continue };
                    if self
                        .bps
                        .get(&id)
                        .is_some_and(|b| b.info.bp.kind == BpKind::Execute)
                    {
                        self.th(tid).at_bp = true;
                    }
                    self.hit(id, tid, &ctx, &mut brk)?;
                }
                if let Some(a) = sw {
                    self.th(tid).at_bp = true;
                    let ids: Vec<BpId> = self
                        .bps
                        .values()
                        .filter(|b| {
                            b.info.bp.method == BpMethod::Software && b.info.bp.address == a
                        })
                        .map(|b| b.info.id)
                        .collect();
                    for id in ids {
                        self.hit(id, tid, &ctx, &mut brk)?;
                    }
                    if let Some(i) = self.temps.iter().position(|t| {
                        t.addr == a && t.tid.is_none_or(|x| x == tid) && ctx.rsp >= t.min_sp
                    }) {
                        let t = self.temps.remove(i);
                        self.disarm_sw(t.addr)?;
                        if t.run_to {
                            brk.get_or_insert(BreakReason::Step);
                        } else {
                            self.advanced(tid, &ctx, &mut brk)?;
                        }
                    }
                    if self.loader == Some(a) {
                        self.modules_changed();
                    }
                }
                if stepped {
                    self.after_step(tid, &ctx, &mut brk)?;
                }
                match brk {
                    Some(r) => self.enter_break(tid, r),
                    None => self.resume_all(),
                }
            }
        }
    }

    fn th(&mut self, tid: Tid) -> &mut Th {
        self.threads.entry(tid).or_default()
    }

    fn hit(
        &mut self,
        id: BpId,
        tid: Tid,
        ctx: &Context,
        brk: &mut Option<BreakReason>,
    ) -> Result<()> {
        let Some(bp) = self.bps.get_mut(&id) else {
            return Ok(());
        };
        if let Some(c) = &bp.hooks.condition
            && !guard(false, || c(ctx))
        {
            return Ok(());
        }
        bp.info.hits += 1;
        match bp.info.bp.action.clone() {
            Action::Break => {
                brk.get_or_insert(BreakReason::Breakpoint(id));
            }
            Action::Record => {
                let address = bp
                    .hooks
                    .address_of
                    .as_ref()
                    .and_then(|f| guard(None, || f(ctx)));
                let ip = ctx.rip;
                if let Some(r) = bp.records.get_mut(&(ip, address)) {
                    r.count += 1;
                    r.context = ctx.clone();
                    return Ok(());
                }
                let code_at = match bp.info.bp.kind {
                    BpKind::Execute => ip,
                    _ => ip.saturating_sub(16),
                };
                let mut code = vec![0u8; 16];
                let n = self
                    .shared
                    .read(&*self.mem, code_at, &mut code)
                    .unwrap_or(0);
                code.truncate(n);
                let rec = HitRecord {
                    ip,
                    address,
                    count: 1,
                    context: ctx.clone(),
                    code_at,
                    code,
                };
                if let Some(bp) = self.bps.get_mut(&id) {
                    bp.records.insert((ip, address), rec);
                }
            }
            Action::Trace {
                steps,
                step_over_calls,
            } => {
                if self.th(tid).goal != Goal::Idle || steps == 0 {
                    return Ok(());
                }
                if let Some(bp) = self.bps.get_mut(&id) {
                    bp.trace.clear();
                }
                let goal = Goal::Trace {
                    bp: id,
                    left: steps,
                    over: step_over_calls,
                };
                self.th(tid).goal = goal;
                self.trace_step(tid, ctx, brk)?;
            }
        }
        Ok(())
    }

    /// Records `ctx` for the thread's trace and issues the next step, or finishes.
    fn trace_step(&mut self, tid: Tid, ctx: &Context, brk: &mut Option<BreakReason>) -> Result<()> {
        let Goal::Trace { bp, left, over } = self.th(tid).goal else {
            return Ok(());
        };
        let Some(b) = self.bps.get_mut(&bp) else {
            self.th(tid).goal = Goal::Idle;
            return Ok(());
        };
        b.trace.push(ctx.clone());
        let steps = b.trace.len() as u32;
        let stop = b.hooks.stop_when.clone();
        if stop.is_some_and(|f| guard(false, || f(ctx))) {
            self.th(tid).goal = Goal::Idle;
            brk.get_or_insert(BreakReason::TraceStop(bp));
        } else if left <= 1 {
            self.th(tid).goal = Goal::Idle;
            self.emit(Event::TraceDone { bp, steps });
        } else {
            self.th(tid).goal = Goal::Trace {
                bp,
                left: left - 1,
                over,
            };
            self.issue_step(tid, ctx.rip, ctx.rsp, over);
        }
        Ok(())
    }

    fn issue_step(&mut self, tid: Tid, pc: Addr, sp: u64, over: bool) {
        let th = self.th(tid);
        th.step_pre = Some((pc, sp, over));
        th.want_step = true;
    }

    /// A goal step finished. If it stepped into a call we were told to step over, run to
    /// the return address instead.
    fn after_step(&mut self, tid: Tid, ctx: &Context, brk: &mut Option<BreakReason>) -> Result<()> {
        let Some((pc0, sp0, over)) = self.th(tid).step_pre.take() else {
            return Ok(());
        };
        if over && ctx.rsp == sp0.wrapping_sub(8) {
            // Decoder-free call detection: one slot pushed, holding an address just past the
            // old rip, and we are not at that address.
            let ret = self.mem.read_ptr(ctx.rsp).unwrap_or(0);
            if ret > pc0 && ret <= pc0 + 15 && ctx.rip != ret {
                self.arm_sw(ret)?;
                self.temps.push(Temp {
                    addr: ret,
                    tid: Some(tid),
                    min_sp: sp0,
                    run_to: false,
                });
                self.exclusive = None;
                return Ok(());
            }
        }
        self.advanced(tid, ctx, brk)
    }

    /// The thread completed one (possibly stepped-over) instruction of its goal.
    fn advanced(&mut self, tid: Tid, ctx: &Context, brk: &mut Option<BreakReason>) -> Result<()> {
        match self.th(tid).goal {
            Goal::Idle => {}
            Goal::Step | Goal::Over => {
                self.th(tid).goal = Goal::Idle;
                brk.get_or_insert(BreakReason::Step);
            }
            Goal::Out(n) => {
                if self.th(tid).was_ret || n >= STEP_OUT_LIMIT {
                    self.th(tid).goal = Goal::Idle;
                    brk.get_or_insert(BreakReason::Step);
                } else {
                    let was_ret = self.is_ret(ctx.rip);
                    let th = self.th(tid);
                    th.goal = Goal::Out(n + 1);
                    th.was_ret = was_ret;
                    self.issue_step(tid, ctx.rip, ctx.rsp, true);
                }
            }
            Goal::Trace { .. } => self.trace_step(tid, ctx, brk)?,
        }
        Ok(())
    }

    fn is_ret(&self, pc: Addr) -> bool {
        let mut b = [0u8; 2];
        if self.shared.read(&*self.mem, pc, &mut b).is_err() {
            return false;
        }
        let op = if matches!(b[0], 0xf2 | 0xf3) {
            b[1]
        } else {
            b[0]
        };
        matches!(op, 0xc3 | 0xc2 | 0xcb | 0xca)
    }

    fn modules_changed(&mut self) {
        let Ok(now) = self.mem.modules() else { return };
        for m in &now {
            if !self.modules.iter().any(|o| o.base == m.base) {
                self.emit(Event::ModuleLoaded(m.clone()));
            }
        }
        for o in &self.modules {
            if !now.iter().any(|m| m.base == o.base) {
                self.emit(Event::ModuleUnloaded { base: o.base });
            }
        }
        self.modules = now;
    }

    // ---- stopping and resuming ------------------------------------------------------------

    fn halt(&mut self) -> Result<()> {
        for (t, raw) in self.os.halt_all()? {
            self.on_raw(t, raw, true)?;
        }
        Ok(())
    }

    fn running(&self) -> bool {
        self.alive && self.broken.is_none() && !self.suspended
    }

    /// Lets every stopped thread go on according to its state, unless the process is
    /// broken or suspended. Deferred stops are handled first.
    fn resume_all(&mut self) -> Result<()> {
        if !self.running() {
            return Ok(());
        }
        if let Some((tid, stop)) = self.deferred.pop_front() {
            return self.handle(tid, stop);
        }
        let mut modes = HashMap::new();
        let tids: Vec<Tid> = self.threads.keys().copied().collect();
        for t in tids {
            if !self.os.is_stopped(t) {
                continue;
            }
            let excl = self.exclusive.is_some_and(|x| x != t);
            let th = &self.threads[&t];
            if th.suspended || excl {
                modes.insert(t, Mode::Stay);
                continue;
            }
            if th.reinsert.is_none() && (th.want_step || th.at_bp) {
                self.step_past_bp(t)?;
            }
            let th = self.threads.get_mut(&t).unwrap();
            th.at_bp = false;
            th.stepped = th.want_step || th.reinsert.is_some();
            modes.insert(t, if th.stepped { Mode::Step } else { Mode::Cont });
        }
        self.os
            .resume(&|t| modes.get(&t).copied().unwrap_or(Mode::Stay))
    }

    /// If the thread sits on one of our execute breakpoints, disarm it for one step.
    fn step_past_bp(&mut self, t: Tid) -> Result<()> {
        let (pc, _) = self.os.pc_sp(t)?;
        if self.sw.contains_key(&pc) {
            let orig = self.shared.lock().get(&pc).copied();
            if let Some(b) = orig {
                self.mem.write(pc, &[b])?;
                self.th(t).reinsert = Some(Reinsert::Sw(pc));
            }
            return Ok(());
        }
        let (addrs, dr7) = self.dr_config();
        for (i, a) in addrs.iter().enumerate() {
            let exec =
                self.slots[i].is_some_and(|id| self.bps[&id].info.bp.kind == BpKind::Execute);
            if exec && *a == pc {
                self.os.set_dr(Some(t), addrs, dr7 & !(3 << (2 * i)))?;
                self.th(t).reinsert = Some(Reinsert::Hw);
                return Ok(());
            }
        }
        Ok(())
    }

    fn rearm(&mut self, tid: Tid, r: Reinsert) -> Result<()> {
        match r {
            Reinsert::Sw(a) => {
                let _lock = self.shared.lock();
                if self.sw.contains_key(&a) {
                    self.mem.write(a, &[0xcc])?;
                }
                Ok(())
            }
            Reinsert::Hw => {
                let (addrs, dr7) = self.dr_config();
                self.os.set_dr(Some(tid), addrs, dr7)
            }
        }
    }

    fn enter_break(&mut self, tid: Tid, reason: BreakReason) -> Result<()> {
        self.halt()?;
        for th in self.threads.values_mut() {
            th.goal = Goal::Idle;
            th.step_pre = None;
            th.want_step = false;
        }
        for t in std::mem::take(&mut self.temps) {
            self.disarm_sw(t.addr)?;
        }
        self.exclusive = None;
        let signal = matches!(reason, BreakReason::Signal { .. });
        self.broken = Some((tid, signal));
        let context = Box::new(self.os.context(tid).unwrap_or_default());
        self.emit(Event::Break {
            tid,
            reason,
            context,
        });
        Ok(())
    }

    /// Runs `f` with every thread stopped, restoring the previous run state afterwards.
    fn with_halted<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        self.live()?;
        let running = self.running();
        if running {
            self.halt()?;
        }
        let r = f(self);
        if running {
            self.resume_all()?;
        }
        r
    }

    // ---- breakpoints ----------------------------------------------------------------------

    fn arm_sw(&mut self, addr: Addr) -> Result<()> {
        if let Some(n) = self.sw.get_mut(&addr) {
            *n += 1;
            return Ok(());
        }
        let mut orig = self.shared.lock();
        let mut b = [0u8];
        self.mem.read_exact(addr, &mut b)?;
        self.mem.write(addr, &[0xcc])?;
        orig.insert(addr, b[0]);
        self.sw.insert(addr, 1);
        Ok(())
    }

    fn disarm_sw(&mut self, addr: Addr) -> Result<()> {
        let Some(n) = self.sw.get_mut(&addr) else {
            return Ok(());
        };
        *n -= 1;
        if *n > 0 {
            return Ok(());
        }
        self.sw.remove(&addr);
        let mut orig = self.shared.lock();
        if let Some(b) = orig.remove(&addr) {
            self.mem.write(addr, &[b])?;
        }
        Ok(())
    }

    fn dr_config(&self) -> ([u64; 4], u64) {
        let mut addrs = [0u64; 4];
        let mut dr7 = 0u64;
        for (i, slot) in self.slots.iter().enumerate() {
            let Some(bp) = slot.and_then(|id| self.bps.get(&id)) else {
                continue;
            };
            let bp = &bp.info.bp;
            let rw = match bp.kind {
                BpKind::Execute => 0,
                BpKind::Write => 1,
                BpKind::Access => 3,
            };
            let len = match (bp.kind, bp.size) {
                (BpKind::Execute, _) | (_, 1) => 0,
                (_, 2) => 1,
                (_, 8) => 2,
                _ => 3,
            };
            addrs[i] = bp.address;
            dr7 |= (1 << (2 * i)) | (rw << (16 + 4 * i)) | (len << (18 + 4 * i));
        }
        (addrs, dr7)
    }

    fn apply_dr(&mut self) -> Result<()> {
        let (addrs, dr7) = self.dr_config();
        self.with_halted(|e| e.os.set_dr(None, addrs, dr7))
    }

    pub(crate) fn add_bp(&mut self, mut bp: Breakpoint, hooks: Hooks) -> Result<BpId> {
        self.live()?;
        if bp.kind == BpKind::Execute {
            bp.size = 1;
        }
        if !matches!(bp.size, 1 | 2 | 4 | 8) {
            return Err(Error::Other(format!(
                "breakpoint size must be 1, 2, 4 or 8, not {}",
                bp.size
            )));
        }
        let id = self.next_id;
        let mut slot = None;
        match bp.method {
            BpMethod::Software => {
                if bp.kind != BpKind::Execute {
                    return Err(Error::Unsupported(
                        "software breakpoints only break on execute; use a hardware watchpoint",
                    ));
                }
                self.arm_sw(bp.address)?;
            }
            BpMethod::Hardware => {
                if !bp.address.is_multiple_of(bp.size as u64) {
                    return Err(Error::Other(format!(
                        "hardware breakpoint address {:#x} is not aligned to its size {}",
                        bp.address, bp.size
                    )));
                }
                let free = self
                    .slots
                    .iter()
                    .position(|s| s.is_none())
                    .ok_or_else(|| Error::Other("all 4 debug registers are in use".into()))?;
                slot = Some(free as u8);
            }
        }
        self.next_id += 1;
        self.bps.insert(
            id,
            Bp {
                info: BreakpointInfo {
                    id,
                    bp,
                    hits: 0,
                    slot,
                },
                hooks,
                records: BTreeMap::new(),
                trace: Vec::new(),
            },
        );
        if let Some(s) = slot {
            self.slots[s as usize] = Some(id);
            if let Err(e) = self.apply_dr() {
                self.slots[s as usize] = None;
                self.bps.remove(&id);
                let _ = self.apply_dr();
                return Err(e);
            }
        }
        Ok(id)
    }

    pub(crate) fn remove_bp(&mut self, id: BpId) -> Result<()> {
        let bp = self
            .bps
            .remove(&id)
            .ok_or_else(|| Error::Other(format!("no breakpoint {id}")))?;
        if !self.alive {
            return Ok(());
        }
        match bp.info.slot {
            Some(s) => {
                self.slots[s as usize] = None;
                self.apply_dr()
            }
            None => self.disarm_sw(bp.info.bp.address),
        }
    }

    pub(crate) fn bp_list(&self) -> Vec<BreakpointInfo> {
        self.bps.values().map(|b| b.info.clone()).collect()
    }

    fn bp(&mut self, id: BpId) -> Result<&mut Bp> {
        self.bps
            .get_mut(&id)
            .ok_or_else(|| Error::Other(format!("no breakpoint {id}")))
    }

    pub(crate) fn records(&mut self, id: BpId) -> Result<Vec<crate::HitRecord>> {
        Ok(self.bp(id)?.records.values().cloned().collect())
    }

    pub(crate) fn clear_records(&mut self, id: BpId) -> Result<()> {
        self.bp(id)?.records.clear();
        Ok(())
    }

    pub(crate) fn trace_log(&mut self, id: BpId) -> Result<Vec<Context>> {
        Ok(self.bp(id)?.trace.clone())
    }

    pub(crate) fn set_policy(&mut self, code: u32, a: SignalAction) {
        self.policy.insert(code, a);
    }

    // ---- user commands ----------------------------------------------------------------------

    pub(crate) fn state(&self) -> State {
        match (self.alive, self.broken, self.suspended) {
            (false, ..) => State::Exited,
            (_, Some((tid, _)), _) => State::Broken { tid },
            (_, _, true) => State::Suspended,
            _ => State::Running,
        }
    }

    pub(crate) fn thread_list(&self) -> Vec<ThreadInfo> {
        self.threads
            .iter()
            .map(|(&tid, t)| ThreadInfo {
                tid,
                suspended: t.suspended,
            })
            .collect()
    }

    fn stopped(&self, tid: Tid) -> Result<()> {
        self.live()?;
        let th = self
            .threads
            .get(&tid)
            .ok_or_else(|| Error::Other(format!("no thread {tid}")))?;
        if !self.os.is_stopped(tid) || (self.running() && !th.suspended) {
            return Err(Error::Other(format!(
                "thread {tid} is running; pause or suspend it first"
            )));
        }
        Ok(())
    }

    pub(crate) fn context(&mut self, tid: Tid) -> Result<Context> {
        self.stopped(tid)?;
        self.os.context(tid)
    }

    pub(crate) fn set_context(&mut self, tid: Tid, ctx: &Context) -> Result<()> {
        self.stopped(tid)?;
        self.os.set_context(tid, ctx)
    }

    pub(crate) fn suspend_thread(&mut self, tid: Tid, on: bool) -> Result<()> {
        self.live()?;
        let th = self
            .threads
            .get_mut(&tid)
            .ok_or_else(|| Error::Other(format!("no thread {tid}")))?;
        th.suspended = on;
        // Halting and resuming applies the new state (resume leaves suspended threads alone).
        self.with_halted(|_| Ok(()))
    }

    pub(crate) fn suspend_process(&mut self, on: bool) -> Result<()> {
        self.live()?;
        if on && !self.suspended {
            if self.running() {
                self.halt()?;
            }
            self.suspended = true;
        } else if !on && self.suspended {
            self.suspended = false;
            self.resume_all()?;
        }
        Ok(())
    }

    pub(crate) fn pause(&mut self) -> Result<()> {
        self.live()?;
        if self.broken.is_some() {
            return Ok(());
        }
        let pid = self.os.pid();
        let tid = match self.threads.contains_key(&pid) {
            true => pid,
            false => *self.threads.keys().next().ok_or(Error::ProcessGone)?,
        };
        self.enter_break(tid, BreakReason::Pause)
    }

    fn take_break(&mut self) -> Result<(Tid, bool)> {
        self.live()?;
        self.broken
            .take()
            .ok_or_else(|| Error::Other("the process is not stopped at a break".into()))
    }

    pub(crate) fn cont(&mut self, pass: bool) -> Result<()> {
        let (tid, signal) = self.take_break()?;
        if signal {
            self.os.set_pass(tid, pass);
        }
        self.resume_all()
    }

    pub(crate) fn step(&mut self, tid: Tid, kind: StepKind) -> Result<()> {
        if self.broken.is_none() {
            self.live()?;
            return Err(Error::Other("the process is not stopped at a break".into()));
        }
        self.stopped(tid)?;
        let (pc, sp) = self.os.pc_sp(tid)?;
        let was_ret = self.is_ret(pc);
        let th = self.th(tid);
        th.goal = match kind {
            StepKind::Into => Goal::Step,
            StepKind::Over => Goal::Over,
            StepKind::Out => Goal::Out(0),
        };
        th.was_ret = was_ret;
        self.issue_step(tid, pc, sp, !matches!(kind, StepKind::Into));
        self.take_break()?;
        self.exclusive = Some(tid);
        self.resume_all()
    }

    pub(crate) fn run_to(&mut self, addr: Addr) -> Result<()> {
        if self.broken.is_none() {
            self.live()?;
            return Err(Error::Other("the process is not stopped at a break".into()));
        }
        self.arm_sw(addr)?;
        self.temps.push(Temp {
            addr,
            tid: None,
            min_sp: 0,
            run_to: true,
        });
        self.take_break()?;
        self.resume_all()
    }

    /// Runs `f` (an OS-level operation needing a stopped thread, e.g. a remote syscall)
    /// with the process halted.
    #[cfg(target_os = "linux")]
    pub(crate) fn remote<R>(
        &mut self,
        f: impl FnOnce(&mut Os, &dyn Process) -> Result<R>,
    ) -> Result<R> {
        let mem = self.mem.clone();
        self.with_halted(|e| f(&mut e.os, &*mem))
    }

    pub(crate) fn detach(&mut self) -> Result<()> {
        self.done = true;
        if !self.alive {
            return Ok(());
        }
        // Halting classifies pending int3 hits, which rewinds their rip.
        let halted = self.halt();
        self.alive = false;
        let mut orig = self.shared.lock();
        for (a, b) in std::mem::take(&mut *orig) {
            let _ = self.mem.write(a, &[b]);
        }
        drop(orig);
        self.sw.clear();
        let _ = self.os.set_dr(None, [0; 4], 0);
        halted?;
        self.os.detach()
    }
}
