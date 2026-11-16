//! OS-independent debugger logic, run on the dedicated debugger thread. The OS backend
//! (`crate::os`) only knows how to wait for, stop and resume threads, access registers and
//! change page protection; breakpoints, stepping, recording and tracing live here.
//!
//! Stepping past a breakpoint ("lifting" it): a thread that must execute the instruction
//! under one of our int3s (or a faulting access on a watched page) gets the original byte
//! (or protection) back for exactly one single-step. While such a lift is in flight every
//! other thread is held stopped, except for instructions that may block in the kernel and
//! after [`LIFT_WAIT`], so nothing runs past a breakpoint unseen.
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::time::{Duration, Instant};

use hh_asm::{FlowKind, MemAccess};
use hh_core::{Addr, Error, Module, Pid, Process, Prot, Result};

use crate::os::Os;
use crate::{
    Action, BpId, BpKind, BpMethod, BpOptions, BreakReason, Breakpoint, BreakpointInfo, Context,
    Event, HitRecord, Hooks, LIFT_WAIT, Live, MAX_RECORDS, Masked, Predicate, Shared, SignalAction,
    State, ThreadInfo, Tid,
};

const PAGE: u64 = 4096;

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
    /// A child process sharing our memory (vfork / `CLONE_VM`), traced only so it can step
    /// over our breakpoints until it execs or exits. Never reported to the user.
    #[cfg_attr(windows, allow(dead_code))]
    GuestCreated(Tid),
    /// A forked child (own copy of memory, stopped, traced): remove our patches, detach.
    #[cfg_attr(windows, allow(dead_code))]
    Forked(Pid),
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

/// A fault on a watched page, waiting for its single-step to finish.
struct PageHit {
    ip: Addr,
    accesses: Vec<MemAccess>,
    fault: Option<Addr>,
}

#[derive(Default)]
struct Th {
    suspended: bool,
    /// A vfork / CLONE_VM child, not one of our threads.
    guest: bool,
    goal: Goal,
    /// A goal single-step is in flight.
    goal_step: bool,
    /// Single-step on the next resume.
    want_step: bool,
    /// The last resume single-stepped (so the next trap is that step).
    stepped: bool,
    /// Stopped on an execute breakpoint it reported; resuming must step past it first.
    at_bp: bool,
    /// Lifts in flight for this thread's step: int3 byte, its DR7 execute slot, pages.
    lift_sw: Option<Addr>,
    lift_hw: bool,
    lift_pages: Vec<Addr>,
    /// Some lift of this thread needs the other threads held.
    lift_excl: bool,
    /// Watched pages it faulted on, to lift on the next resume.
    want_pages: Vec<Addr>,
    page_hit: Option<PageHit>,
    /// The instruction being stepped (step out) is a `ret`.
    was_ret: bool,
}

impl Th {
    fn lifting(&self) -> bool {
        self.lift_sw.is_some() || self.lift_hw || !self.lift_pages.is_empty()
    }
}

struct Plan {
    sw: Option<(Addr, bool)>,
    hw: Option<usize>,
    pages: Vec<Addr>,
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

impl Bp {
    /// Page-aligned span of a page watch.
    fn pages(&self) -> (Addr, Addr) {
        let s = self.info.bp.address;
        let e = s.saturating_add(self.info.len.max(1));
        (s & !(PAGE - 1), e.next_multiple_of(PAGE))
    }
}

/// A page we changed the protection of.
struct Page {
    orig: Prot,
    applied: Prot,
    /// Threads stepping with the original protection back in place.
    lifts: u32,
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
    mem: Arc<Live>,
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

fn default_policy() -> HashMap<u32, SignalAction> {
    crate::os::SIGNALS
        .iter()
        .filter(|s| s.2 != SignalAction::Pass)
        .map(|&(c, _, a)| (c, a))
        .collect()
}

pub(crate) struct Engine {
    os: Os,
    live: Arc<Live>,
    mem: Arc<dyn Process>,
    /// `mem` with int3 bytes hidden, for decoding.
    view: Arc<dyn Process>,
    shared: Arc<Shared>,
    events: Sender<Event>,
    bps: BTreeMap<BpId, Bp>,
    next_id: BpId,
    /// Armed int3 addresses with reference counts (user, temporary, loader breakpoints).
    sw: HashMap<Addr, u32>,
    slots: [Option<BpId>; 4],
    pages: BTreeMap<Addr, Page>,
    threads: BTreeMap<Tid, Th>,
    broken: Option<(Tid, bool)>,
    suspended: bool,
    /// Only this thread may run (a user single-step).
    exclusive: Option<Tid>,
    /// Stops that arrived while halting, handled before anything resumes.
    deferred: VecDeque<(Tid, Stop)>,
    temps: Vec<Temp>,
    policy: HashMap<u32, SignalAction>,
    /// Breakpoints that disabled themselves during the current event.
    to_disable: Vec<BpId>,
    /// An exclusive lift holds the other threads since then; `released` lets them go.
    lift_since: Option<Instant>,
    lift_released: bool,
    alive: bool,
    done: bool,
    loader: Option<Addr>,
    /// Entry point of a freshly exec'd image (the loader hook is set up there).
    entry: Option<Addr>,
    modules: Vec<Module>,
    /// Recently disarmed int3 addresses: a thread that executed one just before it was
    /// removed traps at A+1 and must be rewound, not treated as the program's own SIGTRAP.
    recent: VecDeque<Addr>,
    /// Last time an event came in: right after one, poll without sleeping for a while.
    last_event: Instant,
}

impl Engine {
    fn start(
        pid: Pid,
        live: Arc<Live>,
        shared: Arc<Shared>,
        events: Sender<Event>,
    ) -> Result<Engine> {
        let mem: Arc<dyn Process> = live.clone();
        let (os, raws) = Os::attach(pid, &*mem)?;
        let view: Arc<dyn Process> = Arc::new(Masked {
            inner: mem.clone(),
            shared: shared.clone(),
        });
        let mut e = Engine {
            threads: os.tids().into_iter().map(|t| (t, Th::default())).collect(),
            os,
            live,
            mem,
            view,
            shared,
            events,
            bps: BTreeMap::new(),
            next_id: 1,
            sw: HashMap::new(),
            slots: [None; 4],
            pages: BTreeMap::new(),
            broken: None,
            suspended: false,
            exclusive: None,
            deferred: VecDeque::new(),
            temps: Vec::new(),
            policy: default_policy(),
            to_disable: Vec::new(),
            lift_since: None,
            lift_released: false,
            alive: true,
            done: false,
            loader: None,
            entry: None,
            modules: Vec::new(),
            recent: VecDeque::new(),
            last_event: Instant::now(),
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
        self.modules = self.mem.modules().unwrap_or_default();
        self.hook_loader();
        self.resume_all()
    }

    fn hook_loader(&mut self) {
        if let Some(a) = self.os.loader_hook(&*self.view)
            && self.arm_sw(a).is_ok()
        {
            self.loader = Some(a);
        }
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
                self.take_dropped();
                if let Some(t0) = self.lift_since
                    && !self.lift_released
                    && t0.elapsed() > LIFT_WAIT
                {
                    // A step that blocks (e.g. in the kernel) must not freeze the others.
                    self.lift_released = true;
                    let _ = self.resume_all();
                }
            }
            // shortcut: neither ptrace nor the Win32 debug API can be waited on together with a
            // channel, so idle polling costs up to 1 ms of event latency; right after an event
            // (a hot breakpoint) the loop spins instead.
            if busy {
                self.last_event = Instant::now();
            }
            let spin = self.alive && self.last_event.elapsed() < Duration::from_millis(2);
            let first = if busy || spin {
                if !busy {
                    std::thread::yield_now();
                }
                rx.try_recv().map_err(|e| e == TryRecvError::Disconnected)
            } else {
                let wait = Duration::from_millis(if self.alive { 1 } else { 50 });
                rx.recv_timeout(wait)
                    .map_err(|e| e == RecvTimeoutError::Disconnected)
            };
            match first {
                Ok(c) => {
                    self.take_dropped();
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

    fn is_guest(&self, tid: Tid) -> bool {
        self.threads.get(&tid).is_some_and(|t| t.guest)
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
            Raw::GuestCreated(new) => {
                self.threads.entry(new).or_default().guest = true;
                return if defer { Ok(()) } else { self.resume_all() };
            }
            Raw::Forked(child) => {
                self.clean_child(child);
                self.emit(Event::Forked { child });
                return if defer { Ok(()) } else { self.resume_all() };
            }
            Raw::ThreadExited => {
                self.thread_gone(tid, defer);
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
                let stepping = self.on_exec();
                if stepping && !defer {
                    return self.enter_break(self.os.pid(), BreakReason::Step);
                }
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

    fn thread_gone(&mut self, tid: Tid, defer: bool) {
        let th = self.threads.remove(&tid);
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
        let Some(th) = th else { return };
        // It died mid-step: put its lifted breakpoints back.
        if let Some(a) = th.lift_sw {
            let _ = self.unlift_sw(a);
        }
        if !th.lift_pages.is_empty() && !defer && self.running() {
            let _ = self.halt(); // the remote mprotect needs a stopped thread
        }
        for p in th.lift_pages {
            let _ = self.unlift_page(p);
        }
        self.lift_done();
        if !th.guest {
            self.emit(Event::ThreadExited { tid });
        }
    }

    /// Breakpoints a process-wrapper write landed inside of were dropped from the patch
    /// table (their int3 is already overwritten): forget them here and disable their users.
    fn take_dropped(&mut self) {
        let dropped = std::mem::take(&mut self.shared.lock().dropped);
        for a in dropped {
            self.sw.remove(&a);
            self.temps.retain(|t| t.addr != a);
            if self.loader == Some(a) {
                self.loader = None;
            }
            if self.entry == Some(a) {
                self.entry = None;
            }
            let ids: Vec<BpId> = self
                .bps
                .values()
                .filter(|b| {
                    b.info.enabled
                        && b.info.bp.method == BpMethod::Software
                        && b.info.bp.address == a
                })
                .map(|b| b.info.id)
                .collect();
            for id in ids {
                if let Some(b) = self.bps.get_mut(&id) {
                    b.info.enabled = false;
                }
                self.emit(Event::BreakpointDisabled { bp: id });
            }
        }
    }

    /// The process exec'd. Returns whether a user step was in flight.
    fn on_exec(&mut self) -> bool {
        // The old image is gone: forget every patch without writing into the new one.
        self.live.reopen();
        self.sw.clear();
        {
            let mut p = self.shared.lock();
            p.orig.clear();
            p.lifted.clear();
        }
        self.pages.clear();
        self.slots = [None; 4];
        for b in self.bps.values_mut() {
            b.info.enabled = false;
            b.info.slot = None;
        }
        // The kernel cleared the debug registers; reset the backend's copy.
        let _ = self.os.set_dr(None, [0; 4], 0);
        self.temps.clear();
        self.loader = None;
        self.entry = None;
        self.lift_since = None;
        self.lift_released = false;
        let stepping = self.exclusive.take().is_some();
        let pid = self.os.pid();
        let gone: Vec<Tid> = self
            .threads
            .iter()
            .filter(|(t, th)| **t != pid && !th.guest)
            .map(|(t, _)| *t)
            .collect();
        for t in gone {
            self.threads.remove(&t);
            self.emit(Event::ThreadExited { tid: t });
        }
        let suspended = self.threads.get(&pid).is_some_and(|t| t.suspended);
        self.threads.insert(
            pid,
            Th {
                suspended,
                ..Th::default()
            },
        );
        let threads = &self.threads;
        self.deferred
            .retain(|d| d.0 != pid && threads.contains_key(&d.0));
        self.emit(Event::Exec);
        self.modules_changed();
        if let Some(e) = self.os.exec_entry()
            && self.arm_sw(e).is_ok()
        {
            self.entry = Some(e);
        }
        stepping
    }

    /// Removes our int3 bytes and page protections from a forked child and detaches it.
    fn clean_child(&mut self, child: Pid) {
        let bytes: Vec<(Addr, u8)> = self
            .shared
            .lock()
            .orig
            .iter()
            .map(|(&a, &b)| (a, b))
            .collect();
        for (a, b) in bytes {
            let _ = self.os.write_child(child, a, &[b]);
        }
        let pages: Vec<(Addr, Prot)> = self
            .pages
            .iter()
            .filter(|(_, p)| p.applied != p.orig)
            .map(|(&a, p)| (a, p.orig))
            .collect();
        for (a, prot) in pages {
            let _ = self.os.mprotect_child(child, &*self.mem, a, PAGE, prot);
        }
        let _ = self.os.detach_child(child);
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
        if !stepped && hw == 0 && sw.is_none() && int3 {
            let (pc, _) = self.os.pc_sp(tid)?;
            let mut b = [0u8];
            if let Some(a) = pc.checked_sub(1)
                && self.recent.contains(&a)
                && self.mem.read(a, &mut b).is_ok_and(|_| b[0] != 0xcc)
            {
                // Hit a breakpoint of ours that is gone now: run the real instruction.
                self.os.set_pc(tid, a)?;
                return Ok(Stop::Trap {
                    stepped: false,
                    hw: 0,
                    sw: None,
                });
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
                if code == Os::PAGE_FAULT
                    && let Some(page) = addr.and_then(|a| self.watched_fault(a))
                {
                    self.page_fault(tid, page, addr)?;
                    return self.resume_all();
                }
                if self.is_guest(tid) {
                    self.os.set_pass(tid, true);
                    return self.resume_all();
                }
                let action = match first_chance {
                    true => self.policy(code),
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
                let (page_hit, lifted) = if stepped {
                    self.rearm(tid)?
                } else {
                    (None, None)
                };
                // Still on the lifted int3 after its step: a `rep` iteration. Step it on
                // without counting another hit.
                if let Some(a) = lifted
                    && self.os.pc_sp(tid)?.0 == a
                {
                    self.th(tid).at_bp = true;
                }
                if self.is_guest(tid) {
                    if sw.is_some() {
                        self.th(tid).at_bp = true;
                    }
                    return self.resume_all();
                }
                let ctx = self.os.context(tid)?;
                let mut brk = None;
                if let Some(ph) = page_hit {
                    self.page_hits(tid, &ctx, ph, &mut brk)?;
                }
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
                    self.hit(id, tid, &ctx, &mut brk, None, None)?;
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
                        self.hit(id, tid, &ctx, &mut brk, Some(a), None)?;
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
                    if self.entry == Some(a) {
                        self.entry = None;
                        self.disarm_sw(a)?;
                        self.hook_loader();
                        self.modules_changed();
                    }
                }
                if stepped {
                    self.after_step(tid, &ctx, &mut brk)?;
                }
                self.flush_disables()?;
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

    /// `insn`: the instruction that hit, when known. `accessed`: the address a page watch saw.
    fn hit(
        &mut self,
        id: BpId,
        tid: Tid,
        ctx: &Context,
        brk: &mut Option<BreakReason>,
        insn: Option<Addr>,
        accessed: Option<Addr>,
    ) -> Result<()> {
        let Some(bp) = self.bps.get_mut(&id) else {
            return Ok(());
        };
        if !bp.info.enabled {
            return Ok(());
        }
        if let Some(c) = &bp.hooks.condition
            && !guard(false, || c(ctx))
        {
            return Ok(());
        }
        bp.info.hits += 1;
        let o = &bp.info.options;
        let acting = bp.info.hits > o.skip_hits;
        if (acting && o.one_shot) || o.max_hits.is_some_and(|m| bp.info.hits >= m) {
            self.to_disable.push(id);
        }
        if !acting {
            return Ok(());
        }
        match bp.info.bp.action.clone() {
            Action::Break => {
                brk.get_or_insert(BreakReason::Breakpoint(id));
            }
            Action::Record => {
                let address = match &bp.hooks.address_of {
                    Some(f) => guard(None, || f(ctx)),
                    None => accessed,
                };
                let ip = ctx.rip;
                if let Some(r) = bp.records.get_mut(&(ip, address)) {
                    r.count += 1;
                    r.context = ctx.clone();
                    return Ok(());
                }
                if bp.records.len() >= MAX_RECORDS {
                    bp.info.records_dropped += 1;
                    return Ok(());
                }
                let kind = bp.info.bp.kind;
                let (code_at, insn) = match kind {
                    BpKind::Execute => (ip, Some(ip)),
                    _ => (
                        ip.saturating_sub(16),
                        insn.or_else(|| {
                            hh_asm::instruction_before(&*self.view, ip)
                                .ok()
                                .map(|i| i.addr)
                        }),
                    ),
                };
                let mut code = vec![0u8; 16];
                let n = self.view.read(code_at, &mut code).unwrap_or(0);
                code.truncate(n);
                let rec = HitRecord {
                    ip,
                    address,
                    count: 1,
                    context: ctx.clone(),
                    code_at,
                    code,
                    insn,
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

    /// Applies the auto-disables of this event (all threads stopped first: debug registers
    /// and page protections need that).
    fn flush_disables(&mut self) -> Result<()> {
        if self.to_disable.is_empty() {
            return Ok(());
        }
        let mut ids = std::mem::take(&mut self.to_disable);
        ids.sort_unstable();
        ids.dedup();
        if self.running() {
            self.halt()?;
        }
        for id in ids {
            if self.set_enabled_raw(id, false).is_ok() {
                self.emit(Event::BreakpointDisabled { bp: id });
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
            self.issue_step(tid, ctx.rip, ctx.rsp, over)?;
        }
        Ok(())
    }

    /// Where a step over `pc` should stop instead of single-stepping: after a call (unless
    /// it calls the next instruction, the get-rip idiom) or after a `rep` string
    /// instruction (which single-steps one iteration at a time).
    fn step_over_target(&self, pc: Addr) -> Option<Addr> {
        let i = hh_asm::analyze_instruction(&*self.view, pc, None).ok()?;
        let skip = match i.kind {
            FlowKind::Call => i.target != Some(i.next()),
            FlowKind::Normal => i.text.starts_with("rep"),
            _ => false,
        };
        skip.then(|| i.next())
    }

    /// Advances a goal by one instruction: a single-step, or for a call / rep stepped over,
    /// a temporary breakpoint after it (this thread, stack back where it was).
    fn issue_step(&mut self, tid: Tid, pc: Addr, sp: u64, over: bool) -> Result<()> {
        if over && let Some(next) = self.step_over_target(pc) {
            self.arm_sw(next)?;
            self.temps.push(Temp {
                addr: next,
                tid: Some(tid),
                min_sp: sp,
                run_to: false,
            });
            // The other threads run while the call does.
            if self.exclusive == Some(tid) {
                self.exclusive = None;
            }
            return Ok(());
        }
        let th = self.th(tid);
        th.goal_step = true;
        th.want_step = true;
        Ok(())
    }

    fn after_step(&mut self, tid: Tid, ctx: &Context, brk: &mut Option<BreakReason>) -> Result<()> {
        if std::mem::take(&mut self.th(tid).goal_step) {
            self.advanced(tid, ctx, brk)?;
        }
        Ok(())
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
                    self.issue_step(tid, ctx.rip, ctx.rsp, true)?;
                }
            }
            Goal::Trace { .. } => self.trace_step(tid, ctx, brk)?,
        }
        Ok(())
    }

    fn is_ret(&self, pc: Addr) -> bool {
        hh_asm::analyze_instruction(&*self.view, pc, None).is_ok_and(|i| i.kind == FlowKind::Ret)
    }

    /// The instruction may block in the kernel, so stepping it must not hold other threads.
    fn may_block(&self, pc: Addr) -> bool {
        hh_asm::analyze_instruction(&*self.view, pc, None)
            .is_ok_and(|i| i.kind == FlowKind::Interrupt)
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

    // ---- page watches ---------------------------------------------------------------------

    /// The watched page of a fault at `addr`, if the fault is ours (page protected by us and
    /// not lifted right now; a fault on a lifted page is the program's own).
    fn watched_fault(&self, addr: Addr) -> Option<Addr> {
        let page = addr & !(PAGE - 1);
        let p = self.pages.get(&page)?;
        (p.lifts == 0 && p.applied != p.orig).then_some(page)
    }

    fn page_fault(&mut self, tid: Tid, page: Addr, fault: Option<Addr>) -> Result<()> {
        let guest = self.is_guest(tid);
        let ctx = match guest || self.th(tid).page_hit.is_some() {
            true => None,
            false => Some(self.os.context(tid)?),
        };
        let th = self.th(tid);
        if !th.want_pages.contains(&page) {
            th.want_pages.push(page);
        }
        if let Some(ctx) = ctx {
            let accesses = hh_asm::memory_accesses(&*self.view, ctx.rip, &crate::registers(&ctx))
                .unwrap_or_default();
            self.th(tid).page_hit = Some(PageHit {
                ip: ctx.rip,
                accesses,
                fault,
            });
        }
        self.os.set_pass(tid, false);
        Ok(())
    }

    /// The faulting instruction completed: filter its accesses to each page watch's range.
    fn page_hits(
        &mut self,
        tid: Tid,
        ctx: &Context,
        ph: PageHit,
        brk: &mut Option<BreakReason>,
    ) -> Result<()> {
        let watches: Vec<(BpId, Addr, Addr, BpKind)> = self
            .bps
            .values()
            .filter(|b| b.info.enabled && b.info.bp.method == BpMethod::Page)
            .map(|b| {
                let s = b.info.bp.address;
                (b.info.id, s, s.saturating_add(b.info.len), b.info.bp.kind)
            })
            .collect();
        for (id, s, e, kind) in watches {
            let hit = match ph.accesses.is_empty() {
                // Could not decode: trust the fault address.
                true => ph.fault.filter(|&f| f >= s && f < e),
                false => ph
                    .accesses
                    .iter()
                    .find(|m| {
                        m.addr < e
                            && m.addr.saturating_add(m.size.max(1) as u64) > s
                            && (kind != BpKind::Write || m.write)
                    })
                    .map(|m| m.addr),
            };
            if let Some(a) = hit {
                self.hit(id, tid, ctx, brk, Some(ph.ip), Some(a))?;
            }
        }
        Ok(())
    }

    /// Protection a page should have for the enabled page watches covering it.
    fn page_want(&self, page: Addr, orig: Prot) -> Prot {
        let mut want = orig;
        for b in self.bps.values() {
            if !b.info.enabled || b.info.bp.method != BpMethod::Page {
                continue;
            }
            let (s, e) = b.pages();
            if page >= s && page < e {
                match b.info.bp.kind {
                    BpKind::Write => want.w = false,
                    _ => want = Prot::default(),
                }
            }
        }
        want
    }

    /// Brings the protection of every page in `span` in line with the page watches. Needs a
    /// stopped thread (the remote mprotect runs in one).
    fn sync_pages(&mut self, (s, e): (Addr, Addr)) -> Result<()> {
        let mut regions = None;
        let mut page = s;
        while page < e {
            let (orig, applied, lifts) = match self.pages.get(&page) {
                Some(p) => (p.orig, p.applied, p.lifts),
                None => {
                    let rs = match &regions {
                        Some(r) => r,
                        None => regions.insert(self.mem.regions()?),
                    };
                    let r = rs
                        .iter()
                        .find(|r| page >= r.start && page - r.start < r.size)
                        .ok_or(Error::NoAccess { addr: page })?;
                    (r.prot, r.prot, 0)
                }
            };
            let want = self.page_want(page, orig);
            if lifts == 0 && want != applied {
                self.os.mprotect(&*self.mem, page, PAGE, want)?;
            }
            let applied = if lifts == 0 { want } else { applied };
            if applied == orig && lifts == 0 {
                self.pages.remove(&page);
            } else {
                self.pages.insert(
                    page,
                    Page {
                        orig,
                        applied,
                        lifts,
                    },
                );
            }
            page += PAGE;
        }
        Ok(())
    }

    fn lift_page(&mut self, page: Addr) -> Result<()> {
        let Some(p) = self.pages.get(&page) else {
            return Ok(());
        };
        if p.lifts == 0 && p.applied != p.orig {
            self.os.mprotect(&*self.mem, page, PAGE, p.orig)?;
        }
        if let Some(p) = self.pages.get_mut(&page) {
            p.applied = p.orig;
            p.lifts += 1;
        }
        Ok(())
    }

    fn unlift_page(&mut self, page: Addr) -> Result<()> {
        let Some(p) = self.pages.get_mut(&page) else {
            return Ok(());
        };
        p.lifts = p.lifts.saturating_sub(1);
        if p.lifts == 0 {
            self.sync_pages((page, page + PAGE))?;
        }
        Ok(())
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

    /// Held by the user: suspended, or not the thread of a user single-step.
    fn held(&self, t: Tid) -> bool {
        let th = &self.threads[&t];
        th.suspended || (!th.guest && self.exclusive.is_some_and(|x| x != t))
    }

    /// What the thread must lift for its next resume, if anything.
    fn lift_plan(&self, t: Tid) -> Result<Option<Plan>> {
        let th = &self.threads[&t];
        let mut plan = Plan {
            sw: None,
            hw: None,
            pages: th.want_pages.clone(),
        };
        if !th.lifting() && (th.want_step || th.at_bp) {
            let (pc, _) = self.os.pc_sp(t)?;
            if self.sw.contains_key(&pc) {
                plan.sw = Some((pc, !self.may_block(pc)));
            } else {
                let (addrs, _) = self.dr_config();
                plan.hw = (0..4).find(|&i| {
                    addrs[i] == pc
                        && self.slots[i]
                            .is_some_and(|id| self.bps[&id].info.bp.kind == BpKind::Execute)
                });
            }
        }
        Ok((plan.sw.is_some() || plan.hw.is_some() || !plan.pages.is_empty()).then_some(plan))
    }

    fn lift(&mut self, t: Tid, p: Plan) -> Result<()> {
        if let Some((a, excl)) = p.sw {
            self.lift_sw(a)?;
            let th = self.th(t);
            th.lift_sw = Some(a);
            th.lift_excl |= excl;
        }
        if let Some(i) = p.hw {
            let (addrs, dr7) = self.dr_config();
            self.os.set_dr(Some(t), addrs, dr7 & !(3 << (2 * i)))?;
            self.th(t).lift_hw = true;
        }
        for page in p.pages {
            self.lift_page(page)?;
            let th = self.th(t);
            th.want_pages.retain(|&x| x != page);
            th.lift_pages.push(page);
            th.lift_excl = true;
        }
        Ok(())
    }

    fn excl_lift(&self) -> bool {
        self.threads.values().any(|t| t.lifting() && t.lift_excl)
    }

    /// Ends the hold timer once no exclusive lift is left.
    fn lift_done(&mut self) {
        if !self.excl_lift() {
            self.lift_since = None;
            self.lift_released = false;
        }
    }

    /// A lifting thread finished its step: put back what it lifted. Returns its page hit.
    fn rearm(&mut self, tid: Tid) -> Result<(Option<PageHit>, Option<Addr>)> {
        let Some(th) = self.threads.get_mut(&tid) else {
            return Ok((None, None));
        };
        let sw = th.lift_sw.take();
        let hw = std::mem::take(&mut th.lift_hw);
        let pages = std::mem::take(&mut th.lift_pages);
        th.lift_excl = false;
        let hit = match pages.is_empty() {
            true => None,
            false => th.page_hit.take(),
        };
        let mut r = Ok(());
        if let Some(a) = sw {
            r = r.and(self.unlift_sw(a));
        }
        if hw {
            let (addrs, dr7) = self.dr_config();
            r = r.and(self.os.set_dr(Some(tid), addrs, dr7));
        }
        for p in pages {
            r = r.and(self.unlift_page(p));
        }
        self.lift_done();
        r.map(|_| (hit, sw))
    }

    fn lift_sw(&mut self, a: Addr) -> Result<()> {
        let mut p = self.shared.lock();
        let first = !p.lifted.contains_key(&a);
        if first && let Some(&b) = p.orig.get(&a) {
            self.mem.write(a, &[b])?;
        }
        *p.lifted.entry(a).or_insert(0) += 1;
        Ok(())
    }

    fn unlift_sw(&mut self, a: Addr) -> Result<()> {
        let mut p = self.shared.lock();
        let Some(n) = p.lifted.get_mut(&a) else {
            return Ok(());
        };
        *n -= 1;
        if *n == 0 {
            p.lifted.remove(&a);
            if p.orig.contains_key(&a) {
                self.mem.write(a, &[0xcc])?;
            }
        }
        Ok(())
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
        let tids: Vec<Tid> = self
            .threads
            .keys()
            .copied()
            .filter(|&t| self.os.is_stopped(t))
            .collect();
        let mut plans = Vec::new();
        for &t in &tids {
            if !self.held(t)
                && let Some(p) = self.lift_plan(t)?
            {
                plans.push((t, p));
            }
        }
        let excl = |p: &Plan| p.sw.is_some_and(|s| s.1) || !p.pages.is_empty();
        if !self.lift_released
            && plans.iter().any(|(_, p)| excl(p))
            && self.threads.keys().any(|&t| self.os.is_running(t))
        {
            // Nobody may run past (or into) what is about to be lifted: stop them first.
            self.halt()?;
            return self.resume_all();
        }
        for (t, p) in plans {
            self.lift(t, p)?;
        }
        let hold = !self.lift_released && self.excl_lift();
        if hold {
            self.lift_since.get_or_insert_with(Instant::now);
        }
        let mut modes = HashMap::new();
        for t in tids {
            let held = self.held(t);
            let th = self.threads.get_mut(&t).unwrap();
            // A user single-step goes ahead even while another thread's lift is pending
            // (that thread is held by the step itself).
            if held || (hold && !th.lifting() && self.exclusive != Some(t)) {
                modes.insert(t, Mode::Stay);
                continue;
            }
            th.at_bp = false;
            th.stepped = th.want_step || th.lifting();
            modes.insert(t, if th.stepped { Mode::Step } else { Mode::Cont });
        }
        self.os
            .resume(&|t| modes.get(&t).copied().unwrap_or(Mode::Stay))
    }

    fn enter_break(&mut self, tid: Tid, reason: BreakReason) -> Result<()> {
        self.halt()?;
        for th in self.threads.values_mut() {
            th.goal = Goal::Idle;
            th.goal_step = false;
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
        // Re-armed while threads still step over it with the byte lifted: they re-arm it.
        let stepping = self
            .threads
            .values()
            .filter(|t| t.lift_sw == Some(addr))
            .count() as u32;
        let mut p = self.shared.lock();
        let mut b = [0u8];
        self.mem.read_exact(addr, &mut b)?;
        if stepping == 0 {
            self.mem.write(addr, &[0xcc])?;
        } else {
            p.lifted.insert(addr, stepping);
        }
        p.orig.insert(addr, b[0]);
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
        self.recent.push_back(addr);
        if self.recent.len() > 256 {
            self.recent.pop_front();
        }
        let mut p = self.shared.lock();
        let lifted = p.lifted.remove(&addr).is_some();
        if let Some(b) = p.orig.remove(&addr)
            && !lifted
        {
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

    /// Arms or disarms a breakpoint. Hardware and page watches need the process halted.
    fn set_enabled_raw(&mut self, id: BpId, on: bool) -> Result<()> {
        let b = self.bp(id)?;
        if b.info.enabled == on {
            return Ok(());
        }
        let (method, addr) = (b.info.bp.method, b.info.bp.address);
        match method {
            BpMethod::Software => {
                if on {
                    self.arm_sw(addr)?;
                } else {
                    self.disarm_sw(addr)?;
                }
                self.bp(id)?.info.enabled = on;
            }
            BpMethod::Hardware => {
                let slot =
                    match on {
                        true => self.slots.iter().position(|s| s.is_none()).ok_or_else(|| {
                            Error::Other("all 4 debug registers are in use".into())
                        })?,
                        false => self.bp(id)?.info.slot.map_or(0, usize::from),
                    };
                let set = |e: &mut Self, on: bool| {
                    e.slots[slot] = on.then_some(id);
                    if let Some(b) = e.bps.get_mut(&id) {
                        b.info.slot = on.then_some(slot as u8);
                        b.info.enabled = on;
                    }
                };
                set(self, on);
                let (addrs, dr7) = self.dr_config();
                if let Err(e) = self.os.set_dr(None, addrs, dr7) {
                    set(self, !on);
                    let (addrs, dr7) = self.dr_config();
                    let _ = self.os.set_dr(None, addrs, dr7);
                    return Err(e);
                }
            }
            BpMethod::Page => {
                let span = self.bps[&id].pages();
                self.bp(id)?.info.enabled = on;
                if let Err(e) = self.sync_pages(span) {
                    self.bp(id)?.info.enabled = !on;
                    let _ = self.sync_pages(span);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn add_bp(
        &mut self,
        mut bp: Breakpoint,
        hooks: Hooks,
        options: BpOptions,
        len: Option<u64>,
    ) -> Result<BpId> {
        self.live()?;
        if bp.kind == BpKind::Execute {
            bp.size = 1;
        }
        let len = len.unwrap_or(bp.size as u64);
        match bp.method {
            BpMethod::Software if bp.kind != BpKind::Execute => {
                return Err(Error::Unsupported(
                    "software breakpoints only break on execute; use a hardware watchpoint",
                ));
            }
            BpMethod::Hardware | BpMethod::Software if !matches!(bp.size, 1 | 2 | 4 | 8) => {
                return Err(Error::Other(format!(
                    "breakpoint size must be 1, 2, 4 or 8, not {}",
                    bp.size
                )));
            }
            BpMethod::Hardware if !bp.address.is_multiple_of(bp.size as u64) => {
                return Err(Error::Other(format!(
                    "hardware breakpoint address {:#x} is not aligned to its size {}",
                    bp.address, bp.size
                )));
            }
            BpMethod::Page if !Os::PAGE_WATCH => {
                return Err(Error::Unsupported("page watches on this platform"));
            }
            BpMethod::Page if bp.kind == BpKind::Execute => {
                return Err(Error::Unsupported(
                    "page watches are for write / access; use an execute breakpoint",
                ));
            }
            BpMethod::Page if len == 0 || bp.address.checked_add(len).is_none() => {
                return Err(Error::Other("watch range is empty or wraps around".into()));
            }
            _ => {}
        }
        let id = self.next_id;
        self.next_id += 1;
        self.bps.insert(
            id,
            Bp {
                info: BreakpointInfo {
                    id,
                    bp,
                    hits: 0,
                    slot: None,
                    enabled: false,
                    options,
                    len,
                    records_dropped: 0,
                },
                hooks,
                records: BTreeMap::new(),
                trace: Vec::new(),
            },
        );
        if let Err(e) = self.with_halted(|e| e.set_enabled_raw(id, true)) {
            self.bps.remove(&id);
            return Err(e);
        }
        Ok(id)
    }

    pub(crate) fn remove_bp(&mut self, id: BpId) -> Result<()> {
        self.bp(id)?;
        let r = match self.alive {
            true => self.with_halted(|e| e.set_enabled_raw(id, false)),
            false => Ok(()),
        };
        self.bps.remove(&id);
        r
    }

    pub(crate) fn set_enabled(&mut self, id: BpId, on: bool) -> Result<()> {
        self.bp(id)?;
        self.with_halted(|e| e.set_enabled_raw(id, on))
    }

    pub(crate) fn set_hooks(&mut self, id: BpId, hooks: Hooks) -> Result<()> {
        self.bp(id)?.hooks = hooks;
        Ok(())
    }

    pub(crate) fn set_condition(&mut self, id: BpId, c: Option<Predicate>) -> Result<()> {
        self.bp(id)?.hooks.condition = c;
        Ok(())
    }

    pub(crate) fn set_options(&mut self, id: BpId, o: BpOptions) -> Result<()> {
        self.bp(id)?.info.options = o;
        Ok(())
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

    // ---- signal policy --------------------------------------------------------------------

    pub(crate) fn set_policy(&mut self, code: u32, a: SignalAction) {
        self.policy.insert(code, a);
    }

    pub(crate) fn policy(&self, code: u32) -> SignalAction {
        self.policy
            .get(&code)
            .copied()
            .unwrap_or(SignalAction::Pass)
    }

    pub(crate) fn policy_list(&self) -> Vec<(u32, SignalAction)> {
        let mut codes: Vec<u32> = crate::os::SIGNALS.iter().map(|s| s.0).collect();
        codes.extend(self.policy.keys());
        codes.sort_unstable();
        codes.dedup();
        codes.into_iter().map(|c| (c, self.policy(c))).collect()
    }

    pub(crate) fn reset_policy(&mut self, code: Option<u32>) {
        let dflt = default_policy();
        match code {
            None => self.policy = dflt,
            Some(c) => match dflt.get(&c) {
                Some(&a) => {
                    self.policy.insert(c, a);
                }
                None => {
                    self.policy.remove(&c);
                }
            },
        }
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
            .filter(|(_, t)| !t.guest)
            .map(|(&tid, t)| ThreadInfo {
                tid,
                suspended: t.suspended,
            })
            .collect()
    }

    fn user_thread(&mut self, tid: Tid) -> Result<&mut Th> {
        self.threads
            .get_mut(&tid)
            .filter(|t| !t.guest)
            .ok_or_else(|| Error::Other(format!("no thread {tid}")))
    }

    fn stopped(&mut self, tid: Tid) -> Result<()> {
        self.live()?;
        let suspended = self.user_thread(tid)?.suspended;
        if !self.os.is_stopped(tid) || (self.running() && !suspended) {
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
        self.user_thread(tid)?.suspended = on;
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
        let users: Vec<Tid> = self
            .threads
            .iter()
            .filter(|(_, t)| !t.guest)
            .map(|(&t, _)| t)
            .collect();
        let tid = match users.contains(&pid) {
            true => pid,
            false => *users.first().ok_or(Error::ProcessGone)?,
        };
        self.enter_break(tid, BreakReason::Pause)
    }

    fn take_break(&mut self) -> Result<(Tid, bool)> {
        self.live()?;
        self.broken
            .take()
            .ok_or_else(|| Error::Other("the process is not stopped at a break".into()))
    }

    fn broken_tid(&self) -> Result<Tid> {
        self.live()?;
        self.broken
            .map(|b| b.0)
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
        self.broken_tid()?;
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
        self.exclusive = Some(tid);
        if let Err(e) = self.issue_step(tid, pc, sp, !matches!(kind, StepKind::Into)) {
            self.exclusive = None;
            self.th(tid).goal = Goal::Idle;
            return Err(e);
        }
        self.take_break()?;
        self.resume_all()
    }

    pub(crate) fn run_to(&mut self, addr: Addr, tid: Option<Tid>) -> Result<()> {
        let btid = self.broken_tid()?;
        if let Some(t) = tid {
            self.user_thread(t)?;
        }
        self.arm_sw(addr)?;
        self.temps.push(Temp {
            addr,
            tid,
            min_sp: 0,
            run_to: true,
        });
        // A thread already sitting at `addr` would only hit it again: step it past first.
        for t in [Some(btid), tid].into_iter().flatten() {
            if self.os.pc_sp(t).is_ok_and(|(pc, _)| pc == addr) {
                self.th(t).at_bp = true;
            }
        }
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

    /// Restores every patch and detaches. Whatever fails on the way, the remaining steps
    /// still run so the target ends up running, untraced and unpatched.
    pub(crate) fn detach(&mut self) -> Result<()> {
        self.done = true;
        if !self.alive {
            return Ok(());
        }
        // Halting classifies pending int3 hits, which rewinds their rip.
        let halted = self.halt();
        // Faults on our watched pages must not reach the target as real signals.
        let ours: Vec<Tid> = self
            .deferred
            .iter()
            .filter(|(_, s)| {
                matches!(s, Stop::Signal { code, addr: Some(a), .. }
                    if *code == Os::PAGE_FAULT && self.watched_fault(*a).is_some())
            })
            .map(|d| d.0)
            .collect();
        for t in ours {
            self.os.set_pass(t, false);
        }
        for (a, p) in std::mem::take(&mut self.pages) {
            if p.applied != p.orig || p.lifts > 0 {
                let _ = self.os.mprotect(&*self.mem, a, PAGE, p.orig);
            }
        }
        self.alive = false;
        let mut p = self.shared.lock();
        for (a, b) in std::mem::take(&mut p.orig) {
            let _ = self.mem.write(a, &[b]);
        }
        p.lifted.clear();
        drop(p);
        self.sw.clear();
        let _ = self.os.set_dr(None, [0; 4], 0);
        let detached = self.os.detach();
        halted.and(detached)
    }
}
