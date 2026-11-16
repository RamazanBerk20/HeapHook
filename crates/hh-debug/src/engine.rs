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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use hh_asm::{FlowKind, MemAccess};
use hh_core::{Addr, Error, Module, Pid, Process, Prot, Result};

use crate::os::Os;
use crate::{
    Action, BpExtra, BpId, BpKind, BpMethod, BpOptions, BreakOn, BreakReason, Breakpoint,
    BreakpointInfo, Context, DataHit, Event, HitRecord, Hooks, LIFT_WAIT, LaunchOptions,
    LaunchStop, Live, MAX_COVERAGE, MAX_LOG_RATE, MAX_RECORDS, MAX_TRACE_STEPS, Masked, Predicate,
    Shared, SignalAction, State, StepKind, StepOptions, ThreadInfo, Tid, TraceAccess, TraceStep,
    Trigger, module_matches,
};

/// How a session begins.
pub(crate) enum Start {
    Attach(Pid),
    Launch(Box<LaunchOptions>),
}

const PAGE: u64 = 4096;

/// What the backend saw. `Trap` is any debug trap (int3, single-step, debug register);
/// the engine works out which.
#[derive(Debug)]
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

#[derive(Debug)]
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
    /// A debug event the user wants to break on ([`BreakOn`]).
    Trigger(Trigger),
}

/// Code a step or trace runs through at full speed instead of single-stepping.
#[derive(Clone, Default)]
struct Fence {
    skip: Vec<(Addr, Addr)>,
    stay: Option<(Addr, Addr)>,
}

impl Fence {
    fn fenced(&self, a: Addr) -> bool {
        self.skip.iter().any(|&(s, e)| a >= s && a < e)
            || self.stay.is_some_and(|(s, e)| a < s || a >= e)
    }
}

/// State of a running break-and-trace beyond its [`Goal::Trace`].
#[derive(Clone, Copy)]
struct TraceRun {
    base_sp: u64,
    deadline: Option<Instant>,
    until_return: bool,
    capture: bool,
    /// The function the trace started in is returning (its `ret` is being stepped).
    ret_done: bool,
}

/// "Executed instruction set" recording ([`crate::Debugger::coverage_start`]).
#[derive(Default)]
struct Cov {
    armed: HashSet<Addr>,
    hit: BTreeSet<Addr>,
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
    /// Value of each access before the instruction ran (`DataHit::old`).
    before: Vec<Option<u64>>,
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
    /// The address of the hardware execute breakpoint disabled for this thread's step.
    lift_hw: Option<Addr>,
    lift_pages: Vec<Addr>,
    /// Some lift of this thread needs the other threads held.
    lift_excl: bool,
    /// Watched pages it faulted on, to lift on the next resume.
    want_pages: Vec<Addr>,
    page_hit: Option<PageHit>,
    /// The instruction being stepped (step out) is a `ret`.
    was_ret: bool,
    /// Where it last re-ran an instruction that faulted on a page we had just unprotected.
    page_retry: Option<Addr>,
    /// Code its step / trace runs through at full speed.
    fence: Option<Fence>,
    trace: Option<TraceRun>,
}

impl Th {
    fn lifting(&self) -> bool {
        self.lift_sw.is_some() || self.lift_hw.is_some() || !self.lift_pages.is_empty()
    }
}

struct Plan {
    sw: Option<(Addr, bool)>,
    hw: Option<(usize, Addr)>,
    pages: Vec<Addr>,
}

struct Temp {
    addr: Addr,
    /// Only this thread, and only once the stack is back at `min_sp` (recursion).
    tid: Option<Tid>,
    min_sp: u64,
    run_to: bool,
    /// Qualifying hits left before it acts (run to the N-th hit).
    count: u64,
}

struct Bp {
    info: BreakpointInfo,
    hooks: Hooks,
    records: BTreeMap<(Addr, Option<Addr>), HitRecord>,
    trace: Vec<TraceStep>,
    /// A pending breakpoint the user disabled: not armed when it resolves.
    parked: bool,
    /// Hardware data watch: the watched value at the last hit (or when armed).
    last_val: Option<u64>,
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
    how: Start,
    shared: Arc<Shared>,
    events: Sender<Event>,
    rx: Receiver<Cmd>,
    ok: SyncSender<Result<Arc<Live>>>,
) {
    ENGINE_THREAD.with(|c| c.set(true));
    let mut e = match Engine::start(how, shared, events) {
        Ok(e) => e,
        Err(err) => {
            let _ = ok.send(Err(err));
            return;
        }
    };
    let _ = ok.send(Ok(e.live.clone()));
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
    /// Pages recently given back their protection: a fault on one that was already queued
    /// is ours, not the program's.
    recent_pages: VecDeque<Addr>,
    /// Watchdog: last run, and since when the process looks stalled.
    last_dog: Instant,
    stall_since: Option<Instant>,
    /// Last time an event came in: right after one, poll without sleeping for a while.
    last_event: Instant,
    /// Recent events, commands and recoveries, for diagnostics ([`crate::Debugger::history`]).
    history: VecDeque<String>,
    started: Instant,
    /// Times the watchdog had to repair a stall (see `watchdog`).
    recoveries: u64,
    pub(crate) break_on: BreakOn,
    /// Why the coming break happens, when a debug event asked for it.
    trigger: Option<Trigger>,
    /// Breakpoints are ignored until the current step completes.
    quiet: bool,
    cov: Option<Cov>,
    /// A launched process breaks at its entry point.
    break_entry: bool,
    /// Tracepoint rate limit: window start, lines sent in it, lines dropped since the last.
    log_rate: (Instant, u32, u64),
}

/// Entries kept in the event history.
const HISTORY: usize = 512;
/// How often the watchdog looks for threads left stopped while the process runs (one
/// PTRACE_GETSIGINFO per running thread, which fails at once for a running one).
const DOG_EVERY: Duration = Duration::from_millis(10);
/// How long a thread may stay stopped by our bookkeeping, while it should run, before the
/// watchdog resumes it.
const STALL: Duration = Duration::from_millis(250);

impl Engine {
    fn start(how: Start, shared: Arc<Shared>, events: Sender<Event>) -> Result<Engine> {
        let live = |pid: Pid| -> Result<Arc<Live>> {
            Ok(Arc::new(Live {
                pid,
                cur: RwLock::new(hh_core::open(pid)?),
            }))
        };
        let (os, raws, live, launch) = match how {
            Start::Attach(pid) => {
                let live = live(pid)?;
                let (os, raws) = Os::attach(pid, &*live)?;
                (os, raws, live, None)
            }
            Start::Launch(o) => {
                let mut os = Os::launch(&o)?;
                match live(os.pid()) {
                    Ok(l) => (os, Vec::new(), l, Some(o.stop)),
                    Err(e) => {
                        os.kill();
                        return Err(e);
                    }
                }
            }
        };
        let mem: Arc<dyn Process> = live.clone();
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
            recent_pages: VecDeque::new(),
            last_dog: Instant::now(),
            stall_since: None,
            last_event: Instant::now(),
            history: VecDeque::with_capacity(HISTORY),
            started: Instant::now(),
            recoveries: 0,
            break_on: BreakOn::default(),
            trigger: None,
            quiet: false,
            cov: None,
            break_entry: false,
            log_rate: (Instant::now(), 0, 0),
        };
        let r = match launch {
            None => e.init(raws),
            Some(stop) => e.init_launch(stop),
        };
        if let Err(err) = r {
            let _ = e.detach();
            if launch.is_some() {
                e.os.kill();
            }
            return Err(err);
        }
        Ok(e)
    }

    fn init(&mut self, raws: Vec<(Tid, Raw)>) -> Result<()> {
        for (t, raw) in raws {
            self.on_raw(t, raw, true)?;
        }
        self.modules = self.mem.modules().unwrap_or_default();
        self.hook_loader();
        self.resume_all()
    }

    /// A launched process stopped before its first instruction: hook its entry point (the
    /// loader breakpoint is set up from there), then stop or run as asked.
    fn init_launch(&mut self, stop: LaunchStop) -> Result<()> {
        self.modules = self.mem.modules().unwrap_or_default();
        if let Some(e) = self.os.exec_entry()
            && self.arm_sw(e).is_ok()
        {
            self.entry = Some(e);
        }
        let stop = match stop {
            LaunchStop::Entry if self.entry.is_none() => LaunchStop::FirstInstruction,
            s => s,
        };
        match stop {
            LaunchStop::FirstInstruction => {
                self.trigger = Some(Trigger::Start);
                self.enter_break(self.os.pid(), BreakReason::Pause)
            }
            LaunchStop::Entry => {
                self.break_entry = true;
                self.resume_all()
            }
            LaunchStop::Run => self.resume_all(),
        }
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
                if self.last_dog.elapsed() >= DOG_EVERY {
                    self.last_dog = Instant::now();
                    self.watchdog();
                }
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

    /// Appends to the bounded event history.
    pub(crate) fn note(&mut self, what: String) {
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        let t = self.started.elapsed().as_secs_f64();
        self.history.push_back(format!("{t:9.3} {what}"));
    }

    /// A summary line, then the history oldest first.
    pub(crate) fn history(&self) -> Vec<String> {
        let summary = format!(
            "summary: state={:?} recoveries={} threads={:?} deferred={}",
            self.state(),
            self.recoveries,
            self.threads.keys().collect::<Vec<_>>(),
            self.deferred.len()
        );
        std::iter::once(summary)
            .chain(self.history.iter().cloned())
            .collect()
    }

    /// Last resort against a stalled target (a bug, or a stop another waitpid took):
    /// 1. threads that sit in a ptrace stop the backend never saw get that stop handled;
    /// 2. threads stopped for longer than `STALL` while the process runs, nothing is deferred
    ///    and no step-over holds them, are resumed. Each repair is counted and logged.
    fn watchdog(&mut self) {
        match self.os.watchdog() {
            Ok(raws) if !raws.is_empty() => {
                // Deferred, like a halt's: handling one resumes threads whose stop is still
                // in this batch otherwise.
                for (t, raw) in raws {
                    let _ = self.on_raw(t, raw, true);
                }
                if self.resume_all().is_err() {
                    let _ = self.resume_all();
                }
            }
            Ok(_) => {}
            Err(e) => self.note(format!("watchdog: {e}")),
        }
        self.drain_notes();
        for t in self.os.tids() {
            if !self.threads.contains_key(&t) && self.os.is_stopped(t) {
                // Known to the backend only (its creation event is still queued): adopt it
                // so it gets resumed.
                self.threads.insert(t, Th::default());
            }
        }
        let holding = self.lift_since.is_some() && !self.lift_released;
        let stalled = self.running()
            && !holding
            && (!self.deferred.is_empty()
                || self
                    .threads
                    .keys()
                    .any(|&t| self.os.is_stopped(t) && !self.held(t)));
        if !stalled {
            self.stall_since = None;
            return;
        }
        let since = *self.stall_since.get_or_insert_with(Instant::now);
        if since.elapsed() < STALL {
            return;
        }
        self.stall_since = None;
        self.recoveries += 1;
        self.note("watchdog: stopped threads while running, resuming them".into());
        if let Err(e) = self.resume_all() {
            self.note(format!(
                "watchdog: resume failed ({e}), continuing them plainly"
            ));
            let free: Vec<Tid> = self
                .threads
                .keys()
                .copied()
                .filter(|&t| !self.held(t))
                .collect();
            let _ = self.os.resume(&|t| match free.contains(&t) {
                true => Mode::Cont,
                false => Mode::Stay,
            });
        }
    }

    /// Moves the backend's recovery notes into the history.
    pub(crate) fn drain_notes(&mut self) {
        for n in self.os.take_notes() {
            self.recoveries += 1;
            self.note(format!("watchdog: {n}"));
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
        self.note(format!(
            "event {tid} {raw:?}{}",
            if defer { " (deferred)" } else { "" }
        ));
        let stop = match raw {
            Raw::Trap { code, int3 } => Some(self.classify(tid, code, int3)?),
            Raw::Signal {
                code,
                addr,
                first_chance,
            } => Some(Stop::Signal {
                code,
                addr,
                first_chance,
            }),
            Raw::ThreadCreated(new) => {
                self.threads.entry(new).or_default();
                self.emit(Event::ThreadCreated { tid: new });
                if self.break_on.thread_created {
                    return self.fire(new, Trigger::ThreadCreated { tid: new }, defer);
                }
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
                if self.thread_gone(tid, defer) && self.break_on.thread_exited {
                    return self.fire(tid, Trigger::ThreadExited { tid }, defer);
                }
                return if defer { Ok(()) } else { self.resume_all() };
            }
            Raw::ProcessExited { code } => {
                self.alive = false;
                self.emit(Event::ProcessExited { code });
                return Ok(());
            }
            Raw::ModuleLoaded(m) => {
                self.emit(Event::ModuleLoaded(m.clone()));
                self.modules.retain(|o| o.base != m.base);
                if module_matches(&self.break_on.module_loaded, &m) {
                    self.trigger.get_or_insert(Trigger::ModuleLoaded(m.clone()));
                }
                self.modules.push(m);
                self.resolve_pending();
                None
            }
            Raw::ModuleUnloaded(base) => {
                self.emit(Event::ModuleUnloaded { base });
                if let Some(i) = self.modules.iter().position(|m| m.base == base) {
                    let m = self.modules.remove(i);
                    self.forget_range(m.base, m.base.saturating_add(m.size.max(1)));
                    if module_matches(&self.break_on.module_unloaded, &m) {
                        self.trigger.get_or_insert(Trigger::ModuleUnloaded(m));
                    }
                }
                self.flush_disables()?;
                None
            }
            Raw::Exec => {
                let stepping = self.on_exec();
                if stepping && !defer {
                    return self.enter_break(self.os.pid(), BreakReason::Step);
                }
                None
            }
        };
        let stop = match stop {
            Some(s) => s,
            None => {
                return match self.trigger.take() {
                    Some(t) => self.fire(tid, t, defer),
                    None if defer => Ok(()),
                    None => self.resume_all(),
                };
            }
        };
        if defer {
            self.deferred.push_back((tid, stop));
            Ok(())
        } else {
            self.handle(tid, stop)
        }
    }

    /// Forgets an exited task; true when it was one of the user's threads.
    fn thread_gone(&mut self, tid: Tid, defer: bool) -> bool {
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
        let Some(th) = th else { return false };
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
        !th.guest
    }

    /// Breakpoints a process-wrapper write landed inside of were dropped from the patch
    /// table (their int3 is already overwritten): forget them here and disable their users.
    fn take_dropped(&mut self) {
        let dropped = std::mem::take(&mut self.shared.lock().dropped);
        for a in dropped {
            self.sw.remove(&a);
            self.temps.retain(|t| t.addr != a);
            if let Some(c) = &mut self.cov {
                c.armed.remove(&a);
            }
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
            b.info.resolved = false;
        }
        if let Some(c) = &mut self.cov {
            c.armed.clear();
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
        let mut hw = (self.os.take_dr6(tid)? & 0xf) as u8;
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
        if !stepped {
            // One execution of an instruction under both an int3 and a debug register traps
            // once (the debug register first, or the int3 when RF suppressed it): count it for
            // both, so each kind sees every execution exactly once and breaks once.
            let (pc, _) = self.os.pc_sp(tid)?;
            let exec_here = self.hw_exec_slots(pc).fold(0u8, |m, i| m | 1 << i);
            if sw.is_some() {
                hw |= exec_here;
            } else if hw & exec_here != 0 && self.sw.contains_key(&pc) {
                sw = Some(pc);
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
            Stop::Trigger(t) => {
                let tid = match self.threads.get(&tid).is_some_and(|t| !t.guest) {
                    true => tid,
                    false => self.user_tid()?,
                };
                self.trigger = Some(t);
                self.enter_break(tid, BreakReason::Pause)
            }
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
                if code == Os::PAGE_FAULT && self.stale_fault(tid, addr)? {
                    // Queued before the page got its protection back: just run it again.
                    self.note(format!("stale fault of {tid} at {addr:x?}: re-run"));
                    self.os.set_pass(tid, false);
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
                if let Ok((pc, _)) = self.os.pc_sp(tid) {
                    self.note(format!(
                        "trap {tid} at {pc:#x} stepped={stepped} hw={hw:#x} sw={sw:x?}"
                    ));
                }
                let (page_hit, lifted) = if stepped {
                    self.rearm(tid)?
                } else {
                    (None, None)
                };
                // Still on the lifted int3 after its step: a `rep` iteration. Step it on
                // without counting another hit.
                let mut hw = hw;
                if let Some(a) = lifted
                    && self.os.pc_sp(tid)?.0 == a
                {
                    self.th(tid).at_bp = true;
                    // Nor count the debug register on it again.
                    for i in self.hw_exec_slots(a).collect::<Vec<_>>() {
                        hw &= !(1 << i);
                    }
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
                    let Some(b) = self.bps.get(&id) else { continue };
                    let data = match b.info.bp.kind {
                        BpKind::Execute => {
                            self.th(tid).at_bp = true;
                            None
                        }
                        _ => {
                            let (a, n) = (b.info.bp.address, b.info.bp.size);
                            let new = self.value_at(a, n as usize);
                            let b = self.bps.get_mut(&id).expect("checked");
                            let old = std::mem::replace(&mut b.last_val, new);
                            Some(DataHit {
                                address: a,
                                size: n,
                                old,
                                new,
                            })
                        }
                    };
                    self.hit(id, tid, &ctx, &mut brk, None, None, data)?;
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
                        self.hit(id, tid, &ctx, &mut brk, Some(a), None, None)?;
                    }
                    if let Some(i) = self.temps.iter().position(|t| {
                        t.addr == a && t.tid.is_none_or(|x| x == tid) && ctx.rsp >= t.min_sp
                    }) {
                        if self.temps[i].count > 1 {
                            self.temps[i].count -= 1;
                        } else {
                            let t = self.temps.remove(i);
                            self.disarm_sw(t.addr)?;
                            if t.run_to {
                                brk.get_or_insert(BreakReason::Step);
                            } else {
                                self.advanced(tid, &ctx, &mut brk)?;
                            }
                        }
                    }
                    if let Some(c) = &mut self.cov
                        && c.armed.remove(&a)
                    {
                        if c.hit.len() < MAX_COVERAGE {
                            c.hit.insert(a);
                        }
                        self.disarm_sw(a)?;
                    }
                    if self.loader == Some(a) {
                        self.modules_changed();
                    }
                    if self.entry == Some(a) {
                        self.entry = None;
                        self.disarm_sw(a)?;
                        self.hook_loader();
                        self.modules_changed();
                        if std::mem::take(&mut self.break_entry) {
                            self.trigger.get_or_insert(Trigger::Entry);
                        }
                    }
                }
                if stepped {
                    self.after_step(tid, &ctx, &mut brk)?;
                }
                if self.trigger.is_some() {
                    brk.get_or_insert(BreakReason::Pause);
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

    /// `insn`: the instruction that hit, when known. `accessed`: the address a page watch
    /// saw. `data`: the value of a data breakpoint around the access.
    #[allow(clippy::too_many_arguments)]
    fn hit(
        &mut self,
        id: BpId,
        tid: Tid,
        ctx: &Context,
        brk: &mut Option<BreakReason>,
        insn: Option<Addr>,
        accessed: Option<Addr>,
        data: Option<DataHit>,
    ) -> Result<()> {
        if self.quiet {
            return Ok(());
        }
        let Some(bp) = self.bps.get(&id) else {
            return Ok(());
        };
        if !bp.info.enabled || bp.info.extra.thread.is_some_and(|t| t != tid) {
            return Ok(());
        }
        if let Some(m) = &bp.info.extra.outside_module {
            let at = match (insn, bp.info.bp.kind) {
                (Some(a), _) => a,
                (None, BpKind::Execute) => ctx.rip,
                // Data traps report the next instruction; the accessing one ends at rip.
                (None, _) => ctx.rip.saturating_sub(1),
            };
            let inside = self
                .modules
                .iter()
                .any(|x| x.name.eq_ignore_ascii_case(m) && at >= x.base && at - x.base < x.size);
            if inside {
                return Ok(());
            }
        }
        let bp = self.bps.get_mut(&id).expect("checked");
        if let Some(c) = &bp.hooks.condition
            && !guard(false, || c(ctx))
        {
            return Ok(());
        }
        if let (Some(c), Some(d)) = (&bp.hooks.value_condition, &data)
            && !guard(false, || c(ctx, d))
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
        let log_only = bp.info.extra.log_only;
        if log_only {
            let text = match bp.hooks.message.clone() {
                Some(f) => guard(String::from("(message hook panicked)"), || {
                    f(ctx, data.as_ref())
                }),
                None => format!("bp {id} hit by thread {tid} at {:#x}", ctx.rip),
            };
            self.log(id, tid, text);
        }
        let Some(bp) = self.bps.get_mut(&id) else {
            return Ok(());
        };
        match bp.info.bp.action.clone() {
            Action::Break => {
                if !log_only {
                    brk.get_or_insert(BreakReason::Breakpoint(id));
                }
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
                let opts = bp.info.extra.trace.clone();
                if self.th(tid).goal != Goal::Idle || steps == 0 {
                    return Ok(());
                }
                if let Some(bp) = self.bps.get_mut(&id) {
                    bp.trace.clear();
                }
                let fence = self.fence(&opts.skip_modules, opts.stay_in);
                let run = TraceRun {
                    base_sp: ctx.rsp,
                    deadline: (opts.max_ms > 0)
                        .then(|| Instant::now() + Duration::from_millis(opts.max_ms)),
                    until_return: opts.until_return,
                    capture: opts.capture_memory,
                    ret_done: false,
                };
                let th = self.th(tid);
                th.goal = Goal::Trace {
                    bp: id,
                    left: steps,
                    over: step_over_calls,
                };
                th.trace = Some(run);
                th.fence = fence;
                self.trace_step(tid, ctx, brk)?;
            }
        }
        Ok(())
    }

    /// Sends a tracepoint line, at most [`MAX_LOG_RATE`] a second.
    fn log(&mut self, bp: BpId, tid: Tid, mut text: String) {
        let (since, sent, dropped) = &mut self.log_rate;
        if since.elapsed() >= Duration::from_secs(1) {
            (*since, *sent) = (Instant::now(), 0);
        }
        if *sent >= MAX_LOG_RATE {
            *dropped += 1;
            return;
        }
        *sent += 1;
        if text.len() > 4096 {
            let mut n = 4096;
            while !text.is_char_boundary(n) {
                n -= 1;
            }
            text.truncate(n);
        }
        let dropped = std::mem::take(dropped);
        self.emit(Event::Log {
            bp,
            tid,
            text,
            dropped,
        });
    }

    /// Little-endian value of `n` (1..=8) bytes at `a`.
    fn value_at(&self, a: Addr, n: usize) -> Option<u64> {
        let mut b = [0u8; 8];
        let n = n.clamp(1, 8);
        self.view.read_exact(a, &mut b[..n]).ok()?;
        Some(u64::from_le_bytes(b))
    }

    /// The fence for module patterns / a range, from the current module list.
    fn fence(&self, modules: &[String], stay: Option<(Addr, Addr)>) -> Option<Fence> {
        let skip: Vec<(Addr, Addr)> = self
            .modules
            .iter()
            .filter(|m| crate::module_matches(modules, m))
            .map(|m| (m.base, m.base.saturating_add(m.size)))
            .collect();
        (!skip.is_empty() || stay.is_some()).then_some(Fence { skip, stay })
    }

    /// The thread sits in fenced code: where to run to instead of stepping (the return
    /// address on top of the stack, when it is plausibly one and not fenced itself).
    fn fence_return(&self, tid: Tid, ctx: &Context) -> Option<Addr> {
        let f = self.threads.get(&tid)?.fence.as_ref()?;
        if !f.fenced(ctx.rip) {
            return None;
        }
        let ret = self.view.read_ptr(ctx.rsp).ok()?;
        (!f.fenced(ret) && crate::after_call(&*self.view, ret)).then_some(ret)
    }

    /// The instruction is a call into fenced code.
    fn fenced_call(&self, tid: Tid, ctx: &Context) -> bool {
        let Some(f) = self.threads.get(&tid).and_then(|t| t.fence.as_ref()) else {
            return false;
        };
        let regs = crate::registers(ctx);
        hh_asm::analyze_instruction(&*self.view, ctx.rip, Some(&regs)).is_ok_and(|i| {
            i.kind == FlowKind::Call && i.target.is_some_and(|t| f.fenced(t))
        })
    }

    /// Memory the instruction at `ctx.rip` is about to touch, with its current bytes.
    fn capture(&self, ctx: &Context) -> Vec<TraceAccess> {
        let acc = hh_asm::memory_accesses(&*self.view, ctx.rip, &crate::registers(ctx))
            .unwrap_or_default();
        acc.into_iter()
            .take(16)
            .map(|m| {
                let mut before = vec![0u8; m.size.min(64)];
                if self.view.read_exact(m.addr, &mut before).is_err() {
                    before.clear();
                }
                TraceAccess {
                    addr: m.addr,
                    size: m.size as u32,
                    read: m.read,
                    write: m.write,
                    before,
                    after: None,
                }
            })
            .collect()
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
        let run = self.th(tid).trace;
        if !self.bps.contains_key(&bp) {
            self.end_trace(tid);
            return Ok(());
        }
        // Fenced code is not traced: run it until it returns, or end the trace when it was
        // left some other way (e.g. by returning out of `stay_in`).
        let fenced = self.threads[&tid]
            .fence
            .as_ref()
            .is_some_and(|f| f.fenced(ctx.rip));
        if fenced && !run.is_some_and(|r| r.ret_done) {
            // Entered by a call or jump (not by returning out of the traced code).
            let by_ret = self.bps[&bp]
                .trace
                .last()
                .is_some_and(|s| self.is_ret(s.context.rip));
            if !by_ret && self.fence_return(tid, ctx).is_some() {
                return self.issue_step(tid, ctx, over);
            }
            self.end_trace(tid);
            let steps = self.bps[&bp].trace.len() as u32;
            self.emit(Event::TraceDone { bp, steps });
            return Ok(());
        }
        if let Some(c) = &mut self.cov
            && c.hit.len() < MAX_COVERAGE
        {
            c.hit.insert(ctx.rip);
        }
        let capture = run.is_some_and(|r| r.capture);
        let accesses = match capture {
            true => self.capture(ctx),
            false => Vec::new(),
        };
        // What the previous instruction wrote, now that it ran.
        let prev: Vec<(usize, Addr, usize)> = self.bps[&bp]
            .trace
            .last()
            .map(|s| {
                s.accesses
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| a.write)
                    .map(|(i, a)| (i, a.addr, (a.size as usize).min(64)))
                    .collect()
            })
            .unwrap_or_default();
        let afters: Vec<(usize, Option<Vec<u8>>)> = prev
            .into_iter()
            .map(|(i, a, n)| {
                let mut b = vec![0u8; n];
                (i, self.view.read_exact(a, &mut b).ok().map(|_| b))
            })
            .collect();
        let b = self.bps.get_mut(&bp).expect("checked");
        if let Some(last) = b.trace.last_mut() {
            for (i, v) in afters {
                last.accesses[i].after = v;
            }
        }
        b.trace.push(TraceStep {
            context: ctx.clone(),
            accesses,
        });
        let steps = b.trace.len();
        let stop = b.hooks.stop_when.clone();
        let done = left <= 1
            || steps >= MAX_TRACE_STEPS
            || run.is_some_and(|r| r.ret_done || r.deadline.is_some_and(|d| Instant::now() >= d));
        if stop.is_some_and(|f| guard(false, || f(ctx))) {
            self.end_trace(tid);
            brk.get_or_insert(BreakReason::TraceStop(bp));
        } else if done {
            self.end_trace(tid);
            self.emit(Event::TraceDone {
                bp,
                steps: steps as u32,
            });
        } else {
            let returning =
                run.is_some_and(|r| r.until_return && ctx.rsp >= r.base_sp) && self.is_ret(ctx.rip);
            let th = self.th(tid);
            th.goal = Goal::Trace {
                bp,
                left: left - 1,
                over,
            };
            if returning && let Some(r) = &mut th.trace {
                r.ret_done = true;
            }
            self.issue_step(tid, ctx, over)?;
        }
        Ok(())
    }

    fn end_trace(&mut self, tid: Tid) {
        let th = self.th(tid);
        th.goal = Goal::Idle;
        th.trace = None;
        th.fence = None;
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
    /// a temporary breakpoint after it (this thread, stack back where it was). In fenced
    /// code it runs to the return address instead, and a call into fenced code is stepped
    /// over.
    fn issue_step(&mut self, tid: Tid, ctx: &Context, over: bool) -> Result<()> {
        let (pc, sp) = (ctx.rip, ctx.rsp);
        let target = match self.fence_return(tid, ctx) {
            Some(ret) => Some((ret, sp.wrapping_add(self.mem.pointer_size() as u64))),
            None if over || self.fenced_call(tid, ctx) => {
                self.step_over_target(pc).map(|next| (next, sp))
            }
            None => None,
        };
        if let Some((next, min_sp)) = target {
            self.arm_sw(next)?;
            self.temps.push(Temp {
                addr: next,
                tid: Some(tid),
                min_sp,
                run_to: false,
                count: 1,
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
        let goal = self.th(tid).goal;
        match goal {
            Goal::Idle => {}
            // A step into fenced code (a jump through a PLT stub) runs on until it returns.
            Goal::Step | Goal::Over if self.fence_return(tid, ctx).is_some() => {
                self.issue_step(tid, ctx, false)?;
            }
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
                    self.issue_step(tid, ctx, true)?;
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

    /// Reports loaded / unloaded modules, forgets our patches in unloaded ones, arms pending
    /// breakpoints that resolve now and sets the trigger of a [`BreakOn`] match.
    fn modules_changed(&mut self) {
        let Ok(now) = self.mem.modules() else { return };
        for m in &now {
            if !self.modules.iter().any(|o| o.base == m.base) {
                self.emit(Event::ModuleLoaded(m.clone()));
                if module_matches(&self.break_on.module_loaded, m) {
                    self.trigger.get_or_insert(Trigger::ModuleLoaded(m.clone()));
                }
            }
        }
        let gone: Vec<Module> = self
            .modules
            .iter()
            .filter(|o| !now.iter().any(|m| m.base == o.base))
            .cloned()
            .collect();
        for o in gone {
            self.emit(Event::ModuleUnloaded { base: o.base });
            self.forget_range(o.base, o.base.saturating_add(o.size.max(1)));
            if module_matches(&self.break_on.module_unloaded, &o) {
                self.trigger.get_or_insert(Trigger::ModuleUnloaded(o));
            }
        }
        self.modules = now;
        self.resolve_pending();
    }

    /// Memory `[start, end)` is unmapped (a module unloaded): drop our int3s there without
    /// writing (the bytes are gone, and something else may be mapped there next), forget
    /// page protections, and disable the breakpoints in it. Pending ones wait for the next
    /// resolve.
    fn forget_range(&mut self, start: Addr, end: Addr) {
        let inside = |a: Addr| a >= start && a < end;
        let addrs: Vec<Addr> = self.sw.keys().copied().filter(|&a| inside(a)).collect();
        if !addrs.is_empty() {
            let mut p = self.shared.lock();
            for a in &addrs {
                p.orig.remove(a);
                p.lifted.remove(a);
            }
        }
        for a in &addrs {
            self.sw.remove(a);
        }
        self.temps.retain(|t| !inside(t.addr));
        if self.loader.is_some_and(inside) {
            self.loader = None;
        }
        if self.entry.is_some_and(inside) {
            self.entry = None;
        }
        if let Some(c) = &mut self.cov {
            c.armed.retain(|&a| !inside(a));
        }
        for th in self.threads.values_mut() {
            if th.lift_sw.is_some_and(inside) {
                th.lift_sw = None;
            }
        }
        let pages: Vec<Addr> = self.pages.range(start & !(PAGE - 1)..end).map(|(&a, _)| a).collect();
        for p in pages {
            if p >= start & !(PAGE - 1) && p + PAGE <= end.next_multiple_of(PAGE) {
                self.pages.remove(&p);
            }
        }
        let hit: Vec<(BpId, BpMethod, bool)> = self
            .bps
            .values()
            .filter(|b| {
                let (s, e) = match b.info.bp.method {
                    BpMethod::Page => b.pages(),
                    _ => (b.info.bp.address, b.info.bp.address.saturating_add(b.info.len.max(1))),
                };
                s < end && e > start && (b.info.enabled || b.info.resolved)
            })
            .map(|b| (b.info.id, b.info.bp.method, b.info.pending.is_some()))
            .collect();
        for (id, method, pending) in hit {
            let was = self.bps[&id].info.enabled;
            if let Some(b) = self.bps.get_mut(&id) {
                b.info.resolved = false;
            }
            match method {
                BpMethod::Software => {
                    if let Some(b) = self.bps.get_mut(&id) {
                        b.info.enabled = false;
                    }
                    if was && !pending {
                        self.emit(Event::BreakpointDisabled { bp: id });
                    }
                }
                // Debug registers and the protection of pages outside the range need the
                // process halted: disabled with this event's other auto-disables.
                _ if was => self.to_disable.push(id),
                _ => {}
            }
        }
    }

    // ---- page watches ---------------------------------------------------------------------

    /// The watched page of a fault at `addr`, if the fault is ours (page protected by us and
    /// not lifted right now; a fault on a lifted page is the program's own).
    fn watched_fault(&self, addr: Addr) -> Option<Addr> {
        let page = addr & !(PAGE - 1);
        let p = self.pages.get(&page)?;
        (p.lifts == 0 && p.applied != p.orig).then_some(page)
    }

    /// A fault on a page we unprotected a moment ago (its watch was disabled while this fault
    /// was already queued) is ours: re-run the instruction once. A second fault at the same
    /// instruction is the program's own, even on a page that is read-write again (protection
    /// keys, or a genuine fault), so it cannot loop.
    fn stale_fault(&mut self, tid: Tid, addr: Option<Addr>) -> Result<bool> {
        let Some(page) = addr.map(|a| a & !(PAGE - 1)) else {
            return Ok(false);
        };
        if !self.recent_pages.contains(&page) || self.pages.contains_key(&page) {
            return Ok(false);
        }
        let (pc, _) = self.os.pc_sp(tid)?;
        let th = self.th(tid);
        if th.page_retry == Some(pc) {
            th.page_retry = None;
            return Ok(false);
        }
        th.page_retry = Some(pc);
        Ok(true)
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
            // Read through /proc (not the instruction): the page's protection does not matter.
            let before = accesses
                .iter()
                .map(|m| self.value_at(m.addr, m.size))
                .collect();
            self.th(tid).page_hit = Some(PageHit {
                ip: ctx.rip,
                accesses,
                fault,
                before,
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
                true => ph.fault.filter(|&f| f >= s && f < e).map(|f| (f, 1, None)),
                false => ph
                    .accesses
                    .iter()
                    .zip(&ph.before)
                    .find(|(m, _)| {
                        m.addr < e
                            && m.addr.saturating_add(m.size.max(1) as u64) > s
                            && (kind != BpKind::Write || m.write)
                    })
                    .map(|(m, &old)| (m.addr, m.size, old)),
            };
            if let Some((a, size, old)) = hit {
                let data = DataHit {
                    address: a,
                    size: size.clamp(1, 8) as u8,
                    old,
                    new: self.value_at(a, size),
                };
                self.hit(id, tid, ctx, brk, Some(ph.ip), Some(a), Some(data))?;
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
                    match rs.iter().find(|r| page >= r.start && page - r.start < r.size) {
                        Some(r) => (r.prot, r.prot, 0),
                        // Unmapped (e.g. its module unloaded): nothing to restore there, but a
                        // watch cannot be armed on it.
                        None => {
                            let all = Prot {
                                r: true,
                                w: true,
                                x: true,
                            };
                            if self.page_want(page, all) != all {
                                return Err(Error::NoAccess { addr: page });
                            }
                            page += PAGE;
                            continue;
                        }
                    }
                }
            };
            let want = self.page_want(page, orig);
            if lifts == 0 && want != applied {
                self.os.mprotect(&*self.mem, page, PAGE, want)?;
            }
            let applied = if lifts == 0 { want } else { applied };
            if applied == orig && lifts == 0 {
                if self.pages.remove(&page).is_some() {
                    self.recent_pages.push_back(page);
                    if self.recent_pages.len() > 64 {
                        self.recent_pages.pop_front();
                    }
                }
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
        let raws = self
            .os
            .halt_all()
            .inspect_err(|e| self.note(format!("halt failed: {e}")))?;
        self.defer_all(raws)
    }

    /// Records every event as deferred; one failing does not drop the rest.
    fn defer_all(&mut self, raws: Vec<(Tid, Raw)>) -> Result<()> {
        let mut r = Ok(());
        for (t, raw) in raws {
            r = r.and(self.on_raw(t, raw, true));
        }
        r
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
            // Both an int3 and a debug register may sit on one instruction: lift both, or
            // the step would trap again on the one left armed.
            let (pc, _) = self.os.pc_sp(t)?;
            if self.sw.contains_key(&pc) {
                plan.sw = Some((pc, !self.may_block(pc)));
            }
            plan.hw = self.hw_exec_slots(pc).next().map(|i| (i, pc));
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
        if let Some((i, a)) = p.hw {
            let (addrs, dr7) = self.dr_config();
            self.os.set_dr(Some(t), addrs, dr7 & !(3 << (2 * i)))?;
            self.th(t).lift_hw = Some(a);
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
        let hw = th.lift_hw.take();
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
        if hw.is_some() {
            let (addrs, dr7) = self.dr_config();
            r = r.and(self.os.set_dr(Some(tid), addrs, dr7));
        }
        for p in pages {
            r = r.and(self.unlift_page(p));
        }
        self.lift_done();
        r.map(|_| (hit, sw.or(hw)))
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
        let mut list: Vec<String> = modes.iter().map(|(t, m)| format!("{t}:{m:?}")).collect();
        list.sort();
        self.note(format!("resume {}", list.join(" ")));
        self.os
            .resume(&|t| modes.get(&t).copied().unwrap_or(Mode::Stay))
    }

    fn enter_break(&mut self, tid: Tid, reason: BreakReason) -> Result<()> {
        self.note(format!("break {tid} {reason:?}"));
        self.halt()?;
        for th in self.threads.values_mut() {
            th.goal = Goal::Idle;
            th.goal_step = false;
            th.want_step = false;
            th.fence = None;
            th.trace = None;
        }
        self.quiet = false;
        for t in std::mem::take(&mut self.temps) {
            self.disarm_sw(t.addr)?;
        }
        self.exclusive = None;
        let signal = matches!(reason, BreakReason::Signal { .. });
        self.broken = Some((tid, signal));
        if let Some(why) = self.trigger.take() {
            self.emit(Event::Stopped { tid, why });
        }
        let context = Box::new(self.os.context_full(tid).unwrap_or_default());
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

    /// Debug register slots holding an enabled execute breakpoint at `pc`.
    fn hw_exec_slots(&self, pc: Addr) -> impl Iterator<Item = usize> + '_ {
        (0..4).filter(move |&i| {
            self.slots[i]
                .and_then(|id| self.bps.get(&id))
                .is_some_and(|b| b.info.bp.kind == BpKind::Execute && b.info.bp.address == pc)
        })
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
                let (kind, size) = (self.bps[&id].info.bp.kind, self.bps[&id].info.bp.size);
                if on && kind != BpKind::Execute {
                    let v = self.value_at(addr, size as usize);
                    if let Some(b) = self.bps.get_mut(&id) {
                        b.last_val = v;
                    }
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
        extra: BpExtra,
        pending: Option<String>,
    ) -> Result<BpId> {
        self.live()?;
        if bp.kind == BpKind::Execute {
            bp.size = 1;
        }
        if pending.is_some() {
            bp.address = 0;
        }
        let len = len.unwrap_or(bp.size as u64);
        self.note(format!(
            "cmd add {bp:?} {options:?} len={len} {extra:?} pending={pending:?}"
        ));
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
            BpMethod::Hardware if !bp.address.is_multiple_of(bp.size as u64) && pending.is_none() => {
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
                    extra,
                    resolved: false,
                    pending: pending.clone(),
                },
                hooks,
                records: BTreeMap::new(),
                trace: Vec::new(),
                parked: false,
                last_val: None,
            },
        );
        let r = match pending {
            Some(_) => self.with_halted(|e| {
                e.resolve_pending();
                Ok(())
            }),
            None => self.with_halted(|e| e.set_enabled_raw(id, true)),
        };
        if let Err(e) = r {
            self.bps.remove(&id);
            return Err(e);
        }
        Ok(id)
    }

    /// Arms the pending breakpoints whose expression resolves now (to mapped memory, and
    /// executable memory for execute breakpoints). Halts the process for debug registers
    /// and page watches when it runs; the caller resumes.
    fn resolve_pending(&mut self) {
        let ids: Vec<BpId> = self
            .bps
            .values()
            .filter(|b| b.info.pending.is_some() && !b.info.resolved && !b.parked)
            .map(|b| b.info.id)
            .collect();
        if ids.is_empty() || !self.alive {
            return;
        }
        let syms = hh_asm::SymbolTable::default();
        let regions = self.mem.regions().unwrap_or_default();
        for id in ids {
            let b = &self.bps[&id];
            let (expr, kind, method, size) = (
                b.info.pending.clone().unwrap_or_default(),
                b.info.bp.kind,
                b.info.bp.method,
                b.info.bp.size,
            );
            let Ok(a) = hh_asm::resolve_address(&*self.view, &syms, &expr) else {
                continue;
            };
            let ok = regions.iter().any(|r| {
                a >= r.start && a - r.start < r.size && (r.prot.x || kind != BpKind::Execute)
            }) && (method != BpMethod::Hardware || a.is_multiple_of(size as u64));
            if !ok {
                continue;
            }
            if method != BpMethod::Software && self.running() && self.halt().is_err() {
                continue;
            }
            if let Some(b) = self.bps.get_mut(&id) {
                b.info.bp.address = a;
                b.info.resolved = true;
            }
            match self.set_enabled_raw(id, true) {
                Ok(()) => {
                    self.note(format!("pending {id} ({expr}) armed at {a:#x}"));
                    self.emit(Event::BreakpointResolved { bp: id, address: a });
                }
                Err(e) => {
                    self.note(format!("pending {id} ({expr}) at {a:#x}: {e}"));
                    if let Some(b) = self.bps.get_mut(&id) {
                        b.info.resolved = false;
                    }
                }
            }
        }
    }

    pub(crate) fn remove_bp(&mut self, id: BpId) -> Result<()> {
        self.note(format!("cmd remove {id}"));
        self.bp(id)?;
        let r = match self.alive {
            true => self.with_halted(|e| e.set_enabled_raw(id, false)),
            false => Ok(()),
        };
        self.bps.remove(&id);
        r
    }

    pub(crate) fn set_enabled(&mut self, id: BpId, on: bool) -> Result<()> {
        self.note(format!("cmd enable {id} {on}"));
        let b = self.bp(id)?;
        if b.info.pending.is_some() {
            b.parked = !on;
            if !b.info.resolved {
                return match on {
                    true => self.with_halted(|e| {
                        e.resolve_pending();
                        Ok(())
                    }),
                    false => Ok(()),
                };
            }
        }
        self.with_halted(|e| e.set_enabled_raw(id, on))
    }

    pub(crate) fn set_extra(&mut self, id: BpId, extra: BpExtra) -> Result<()> {
        self.bp(id)?.info.extra = extra;
        Ok(())
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
        Ok(self.bp(id)?.trace.iter().map(|s| s.context.clone()).collect())
    }

    pub(crate) fn trace_steps(&mut self, id: BpId) -> Result<Vec<TraceStep>> {
        Ok(self.bp(id)?.trace.clone())
    }

    // ---- coverage ("executed instruction set") ---------------------------------------------

    pub(crate) fn cov_start(&mut self, entries: Vec<Addr>) -> Result<usize> {
        self.note(format!("cmd coverage start ({} entries)", entries.len()));
        self.live()?;
        if entries.len() > MAX_COVERAGE {
            return Err(Error::Other(format!(
                "at most {MAX_COVERAGE} coverage addresses"
            )));
        }
        let regions = self.mem.regions()?;
        let exec = |a: Addr| {
            regions
                .iter()
                .any(|r| r.prot.x && a >= r.start && a - r.start < r.size)
        };
        let mut entries: Vec<Addr> = entries.into_iter().filter(|&a| exec(a)).collect();
        entries.sort_unstable();
        entries.dedup();
        self.with_halted(|e| {
            if let Some(old) = e.cov.take() {
                for a in old.armed {
                    e.disarm_sw(a)?;
                }
            }
            let mut cov = Cov::default();
            for a in entries {
                if e.arm_sw(a).is_ok() {
                    cov.armed.insert(a);
                }
            }
            let n = cov.armed.len();
            e.cov = Some(cov);
            Ok(n)
        })
    }

    pub(crate) fn cov_hits(&self) -> Vec<Addr> {
        self.cov
            .as_ref()
            .map(|c| c.hit.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn cov_stop(&mut self) -> Result<Vec<Addr>> {
        self.note("cmd coverage stop".into());
        let Some(c) = self.cov.take() else {
            return Ok(Vec::new());
        };
        let hits = c.hit.iter().copied().collect();
        if self.alive && !c.armed.is_empty() {
            // Halted, so a hit already queued is classified (and rewound) while still ours.
            self.with_halted(|e| {
                for &a in &c.armed {
                    e.disarm_sw(a)?;
                }
                Ok(())
            })?;
        }
        Ok(hits)
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
            .map(|(&tid, t)| {
                let (name, state, user_ms, kernel_ms) = self.os.thread_info(tid);
                ThreadInfo {
                    tid,
                    suspended: t.suspended,
                    name,
                    state,
                    user_ms,
                    kernel_ms,
                }
            })
            .collect()
    }

    /// A live user thread to report a break on (the main one if it still runs).
    fn user_tid(&self) -> Result<Tid> {
        let pid = self.os.pid();
        let users: Vec<Tid> = self
            .threads
            .iter()
            .filter(|(_, t)| !t.guest)
            .map(|(&t, _)| t)
            .collect();
        match users.contains(&pid) {
            true => Ok(pid),
            false => users.first().copied().ok_or(Error::ProcessGone),
        }
    }

    /// Breaks for a debug event now, or queues it behind the stops of a halt in progress.
    fn fire(&mut self, tid: Tid, t: Trigger, defer: bool) -> Result<()> {
        if defer {
            self.deferred.push_back((tid, Stop::Trigger(t)));
            return Ok(());
        }
        self.handle(tid, Stop::Trigger(t))
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
        self.os.context_full(tid)
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
        self.note(format!("cmd suspend {on}"));
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
        self.note("cmd pause".into());
        self.live()?;
        if self.broken.is_some() {
            return Ok(());
        }
        let tid = self.user_tid()?;
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
        self.note(format!("cmd cont pass={pass} state={:?}", self.state()));
        let (tid, signal) = self.take_break()?;
        if signal {
            self.os.set_pass(tid, pass);
        }
        self.resume_all()
    }

    pub(crate) fn step(&mut self, tid: Tid, kind: StepKind, opts: StepOptions) -> Result<()> {
        self.note(format!("cmd step {tid} {kind:?} {opts:?}"));
        self.broken_tid()?;
        self.stopped(tid)?;
        let ctx = self.os.context(tid)?;
        let was_ret = self.is_ret(ctx.rip);
        let fence = self.fence(&opts.over_modules, None);
        let th = self.th(tid);
        th.goal = match kind {
            StepKind::Into => Goal::Step,
            StepKind::Over => Goal::Over,
            StepKind::Out => Goal::Out(0),
        };
        th.was_ret = was_ret;
        th.fence = fence;
        self.exclusive = Some(tid);
        if let Err(e) = self.issue_step(tid, &ctx, kind != StepKind::Into) {
            self.exclusive = None;
            let th = self.th(tid);
            th.goal = Goal::Idle;
            th.fence = None;
            return Err(e);
        }
        self.quiet = opts.skip_breakpoints;
        self.take_break()?;
        self.resume_all()
    }

    pub(crate) fn run_to(&mut self, addr: Addr, tid: Option<Tid>, count: u64) -> Result<()> {
        self.note(format!("cmd run_to {addr:#x} {tid:?} x{count}"));
        let btid = self.broken_tid()?;
        if let Some(t) = tid {
            self.user_thread(t)?;
        }
        if count == 0 {
            return Err(Error::Other("run to: the hit count must be at least 1".into()));
        }
        self.arm_sw(addr)?;
        self.temps.push(Temp {
            addr,
            tid,
            min_sp: 0,
            run_to: true,
            count,
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

    pub(crate) fn run_until_return(&mut self, tid: Tid, frame: usize) -> Result<()> {
        self.note(format!("cmd run_until_return {tid} frame {frame}"));
        self.broken_tid()?;
        self.stopped(tid)?;
        let ctx = self.os.context(tid)?;
        let chain = crate::frame_chain(&*self.view, ctx.rbp, frame.saturating_add(1).min(4096));
        let Some(&(ret, slot)) = chain.get(frame) else {
            return Err(Error::Other(format!(
                "frame {frame} is beyond the frame-pointer walk ({} frames)",
                chain.len() + 1
            )));
        };
        self.arm_sw(ret)?;
        self.temps.push(Temp {
            addr: ret,
            tid: Some(tid),
            // After the return the slot holding the return address has been popped.
            min_sp: slot.wrapping_add(self.mem.pointer_size() as u64),
            run_to: true,
            count: 1,
        });
        if self.os.pc_sp(tid).is_ok_and(|(pc, _)| pc == ret) {
            self.th(tid).at_bp = true;
        }
        self.take_break()?;
        self.resume_all()
    }

    pub(crate) fn set_ip(&mut self, tid: Tid, addr: Addr) -> Result<()> {
        self.note(format!("cmd set_ip {tid} {addr:#x}"));
        self.stopped(tid)?;
        let exec = self
            .mem
            .regions()?
            .iter()
            .any(|r| r.prot.x && addr >= r.start && addr - r.start < r.size);
        if !exec {
            return Err(Error::Other(format!(
                "{addr:#x} is not in executable memory"
            )));
        }
        hh_asm::analyze_instruction(&*self.view, addr, None)
            .map_err(|e| Error::Other(format!("no instruction at {addr:#x}: {e}")))?;
        let mut ctx = self.os.context(tid)?;
        if ctx.rip == addr {
            return Ok(());
        }
        ctx.rip = addr;
        self.os.set_context(tid, &ctx)?;
        // Continuing runs the instruction there, breakpoint or not.
        self.th(tid).at_bp = true;
        Ok(())
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
        self.note("cmd detach".into());
        self.done = true;
        if !self.alive {
            return Ok(());
        }
        // Halting classifies pending int3 hits, which rewinds their rip. A halt that timed out
        // (a thread in uninterruptible sleep) leaves what it collected in the backlog: rewind
        // those hits and release forked children too.
        let halted = self.halt();
        let backlog = self.os.take_backlog();
        let _ = self.defer_all(backlog);
        // Faults on our watched pages must not reach the target as real signals.
        let ours: Vec<Tid> = self
            .deferred
            .iter()
            .filter(|(_, s)| {
                matches!(s, Stop::Signal { code, addr: Some(a), .. }
                    if *code == Os::PAGE_FAULT && (self.watched_fault(*a).is_some()
                        || self.recent_pages.contains(&(*a & !(PAGE - 1)))))
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
