//! HeapHook debugger: attach to a running process, software/hardware breakpoints and
//! watchpoints, page-protection watches over large ranges, "find out what writes/accesses
//! this address", "find out what addresses this instruction accesses", break-and-inspect
//! (registers, stepping), break-and-trace, threads and debug events.
//!
//! Threading model: [`Debugger::attach`] starts one dedicated thread that owns every
//! ptrace / Win32 debug API call (both require the thread that attached). All methods send a
//! command to it and wait for the answer, so a `Debugger` can be driven from any thread.
//! Debug events arrive through [`Debugger::next_event`].
//!
//! [`Debugger::process`] hands out an `Arc<dyn Process>` that behaves like `hh_core::open`
//! but works while attached: reads hide int3 bytes, writes keep breakpoints armed, and on
//! Linux alloc/free/protect run their remote syscall through the attached tracer thread
//! (the normal implementation's own ptrace seize would fail).
//!
//! Safety of the target: stepping a thread over a software breakpoint (original byte back
//! in place for one instruction) or over a page watch (protection lifted for one
//! instruction) holds every other thread stopped, so none can run past unseen. Only
//! instructions that may block in the kernel (`syscall`, `int`) are stepped without holding
//! the others, and a step that has not finished after [`LIFT_WAIT`] releases them, so a
//! blocked thread cannot freeze the process. On Linux, forked children get our int3 bytes
//! and page protections removed and are detached; vfork / `CLONE_VM` children (which share
//! our memory) stay traced until they exec or exit, only to step them over breakpoints.
//! After an `execve` every breakpoint is disabled (kept, with its hits and records) and
//! nothing is written into the new image.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use hh_core::{Addr, Error, Memory, Module, Pid, Process, Prot, Region, Result};
use serde::{Deserialize, Serialize};

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", windows)))]
mod engine;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[path = "linux.rs"]
mod os;
#[cfg(all(target_arch = "x86_64", windows))]
#[path = "windows.rs"]
mod os;

pub type Tid = u32;
pub type BpId = u32;

/// How long a breakpoint step-over may hold the other threads before they are let go.
pub const LIFT_WAIT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BpKind {
    /// Break when the instruction at the address is about to execute.
    Execute,
    /// Break after an instruction wrote to the watched range.
    Write,
    /// Break after an instruction read or wrote the watched range.
    Access,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BpMethod {
    /// int3 patched into the code. Execute only, unlimited count.
    Software,
    /// CPU debug register (4 slots, applied to every thread).
    Hardware,
    /// Page protection ("exception" breakpoint): `Write` / `Access` watches of any length.
    /// The pages holding the range lose write (or all) access; each fault on them is
    /// single-stepped with the protection lifted and then filtered to the range.
    ///
    /// Cost: *every* access of the kind to *any* byte of those pages (not just the range)
    /// costs a fault, all threads stopped, two remote `mprotect` calls and a single-step:
    /// expect a hot page to run thousands of times slower. System calls that write into a
    /// write-watched page (or touch an access-watched one) fail with `EFAULT` instead of
    /// being seen, and the target changing the protection itself breaks the watch. Use
    /// [`Debugger::add_watch_range`] for ranges longer than 255 bytes.
    Page,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Stop the whole process and report [`Event::Break`].
    Break,
    /// Do not stop; count hits per distinct (instruction, accessed address) with the last
    /// register snapshot. Read them with [`Debugger::records`].
    Record,
    /// Do not stop; single-step `steps` instructions from the hit recording registers
    /// ([`Debugger::trace`]), then continue. [`Hooks::stop_when`] turns it into a break.
    Trace { steps: u32, step_over_calls: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Breakpoint {
    pub address: Addr,
    pub kind: BpKind,
    /// 1, 2, 4 or 8; hardware ranges must be aligned to it. Ignored for `Execute`. For
    /// `Page` it is the length of the range (1..=255).
    pub size: u8,
    pub method: BpMethod,
    pub action: Action,
}

impl Breakpoint {
    /// Software execute breakpoint that breaks.
    pub fn execute(address: Addr) -> Self {
        Self {
            address,
            kind: BpKind::Execute,
            size: 1,
            method: BpMethod::Software,
            action: Action::Break,
        }
    }
    /// Hardware watchpoint that records ("find out what writes/accesses this address").
    pub fn watch(address: Addr, size: u8, kind: BpKind) -> Self {
        Self {
            address,
            kind,
            size,
            method: BpMethod::Hardware,
            action: Action::Record,
        }
    }
}

/// Hit counting options of a breakpoint ([`Debugger::add_breakpoint_with`],
/// [`Debugger::set_options`]). Hits are only counted when [`Hooks::condition`] holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BpOptions {
    /// Ignore the first `skip_hits` hits ("break after N hits"); they are still counted.
    pub skip_hits: u64,
    /// Disable the breakpoint after its action ran once.
    pub one_shot: bool,
    /// Disable the breakpoint once `hits` reaches this (auto-stop for recorders).
    pub max_hits: Option<u64>,
}

/// Callbacks run on the debugger thread with the hitting thread's registers. They must be
/// quick and must not call back into the `Debugger` (that returns an error).
pub type Predicate = Arc<dyn Fn(&Context) -> bool + Send + Sync>;
pub type AddressOf = Arc<dyn Fn(&Context) -> Option<Addr> + Send + Sync>;
/// [`Hooks::value_condition`]: registers and the watched value before / after the access.
pub type ValuePredicate = Arc<dyn Fn(&Context, &DataHit) -> bool + Send + Sync>;
/// [`Hooks::message`]: the line a tracepoint logs.
pub type Formatter = Arc<dyn Fn(&Context, Option<&DataHit>) -> String + Send + Sync>;

/// The value a data breakpoint saw (little endian, at most 8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataHit {
    /// The accessed address (hardware watch: the watched address).
    pub address: Addr,
    pub size: u8,
    /// Before the access. Page watches read it right before the instruction runs (exact);
    /// debug registers trap after the access, so it is the value seen at the previous hit
    /// of this breakpoint, or when it was armed (a write the CPU does not report, e.g. by a
    /// system call, makes it stale). `None` when unknown.
    pub old: Option<u64>,
    /// After the access; `None` when unreadable.
    pub new: Option<u64>,
}

/// Per-breakpoint filters and options beyond [`BpOptions`]
/// ([`Debugger::add_breakpoint_ext`], [`Debugger::set_extra`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BpExtra {
    /// Only hits by this thread count; other threads run past it silently.
    pub thread: Option<Tid>,
    /// Only hits whose instruction lies outside this module (name, case-insensitive), e.g.
    /// "break on access from outside module X".
    pub outside_module: Option<String>,
    /// Tracepoint: each acting hit sends [`Event::Log`] (text from [`Hooks::message`]) and
    /// an [`Action::Break`] does not stop. `Record` / `Trace` still do their work.
    pub log_only: bool,
    /// Options of an [`Action::Trace`] breakpoint.
    pub trace: TraceOptions,
}

/// Break-and-trace options ([`BpExtra::trace`]). The step count of [`Action::Trace`] is the
/// instruction limit (capped at [`MAX_TRACE_STEPS`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceOptions {
    /// Module name patterns (`*`, `?`, case-insensitive): code in them is not traced. A call
    /// into one (or a jump into one, e.g. through a PLT stub) runs at full speed until it
    /// returns.
    pub skip_modules: Vec<String>,
    /// Only trace inside `[start, end)`; code outside it runs until it returns into it.
    pub stay_in: Option<(Addr, Addr)>,
    /// End the trace once the function it started in returns.
    pub until_return: bool,
    /// End the trace after this many milliseconds (0 = no limit; checked per instruction).
    pub max_ms: u64,
    /// Record what each instruction reads and writes ([`TraceStep::accesses`]).
    pub capture_memory: bool,
}

/// Longest trace kept per breakpoint (and accepted by [`read_trace`]).
pub const MAX_TRACE_STEPS: usize = 262_144;

/// One traced instruction: the registers before it ran and the memory it touched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    pub context: Context,
    #[serde(default)]
    pub accesses: Vec<TraceAccess>,
}

/// A memory operand of a traced instruction (from hh-asm's `memory_accesses`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceAccess {
    pub addr: Addr,
    pub size: u32,
    pub read: bool,
    pub write: bool,
    /// Bytes before the instruction ran (at most 64; empty when unreadable).
    pub before: Vec<u8>,
    /// Bytes after it ran, for writes (filled in when the next step is recorded).
    #[serde(default)]
    pub after: Option<Vec<u8>>,
}

/// Debug events that stop the process ([`Debugger::set_break_on`]). Every one of them is
/// reported as an event anyway ("notify"); these make it break too.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BreakOn {
    pub thread_created: bool,
    pub thread_exited: bool,
    /// Module name patterns (`*`, `?`, case-insensitive); a pattern with a `/` or `\` is
    /// matched against the path instead.
    pub module_loaded: Vec<String>,
    pub module_unloaded: Vec<String>,
}

/// Why the process stopped for a debug event ([`Event::Stopped`], right before its
/// `Event::Break { reason: Pause }`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Trigger {
    ThreadCreated { tid: Tid },
    ThreadExited { tid: Tid },
    ModuleLoaded(Module),
    ModuleUnloaded(Module),
    /// A launched process, before its first instruction ([`LaunchStop::FirstInstruction`]).
    Start,
    /// A launched process at its entry point ([`LaunchStop::Entry`]).
    Entry,
}

/// Where [`Debugger::launch`] stops the new process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LaunchStop {
    /// At the main executable's entry point: libraries loaded, program code not run yet.
    #[default]
    Entry,
    /// Before the first instruction (Linux: the dynamic loader's; Windows: the loader
    /// breakpoint, before the main executable's code).
    FirstInstruction,
    /// Do not stop (pending breakpoints still arm as modules load).
    Run,
}

/// A program started under the debugger ([`Debugger::launch`]).
///
/// The process is a child of the host process: dropping or detaching the `Debugger`
/// releases it (it runs on, untraced and unpatched, from wherever it was, even if it was
/// never continued); the host must reap it after it exits, as for any child.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LaunchOptions {
    /// A path, or a name looked up in `PATH`.
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    /// The whole environment; `None` inherits the host's.
    pub env: Option<Vec<(String, String)>>,
    pub stop: LaunchStop,
    /// Linux: file descriptors of the host given to the child as stdin / stdout / stderr;
    /// `None` inherits. Windows: must be `None`.
    pub stdin: Option<i32>,
    pub stdout: Option<i32>,
    pub stderr: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    Into,
    Over,
    Out,
}

/// Options of [`Debugger::step_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StepOptions {
    /// Breakpoints are ignored (neither counted nor acted on) until the step completes or
    /// the process breaks for another reason.
    pub skip_breakpoints: bool,
    /// Module name patterns: stepping into a call into one of them steps over it, and a
    /// step that lands in one (a jump through a PLT stub) runs until it returns.
    pub over_modules: Vec<String>,
}

/// Most addresses [`Debugger::coverage_start`] takes.
pub const MAX_COVERAGE: usize = 1 << 20;

/// What [`Debugger::coverage_start_checked`] armed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageArm {
    pub armed: usize,
    /// Entries refused (not an instruction start in a live executable mapping of one of the
    /// given modules), sorted.
    pub rejected: Vec<Addr>,
}

#[derive(Clone, Default)]
pub struct Hooks {
    /// Conditional breakpoint: hits where this returns false are ignored entirely.
    pub condition: Option<Predicate>,
    /// For `Record`: the address the instruction accesses (e.g. its effective address
    /// decoded by hh-asm). Records are keyed by (ip, this), which gives "find out what
    /// addresses this instruction accesses" on an execute breakpoint. Page watches record
    /// the accessed address themselves when this is not set.
    pub address_of: Option<AddressOf>,
    /// For `Trace`: break (with [`BreakReason::TraceStop`]) at the first traced step for
    /// which this returns true.
    pub stop_when: Option<Predicate>,
    /// Data breakpoints (`Write` / `Access`): hits where this returns false for the value
    /// before / after the access are ignored entirely, like [`Hooks::condition`].
    pub value_condition: Option<ValuePredicate>,
    /// Tracepoints ([`BpExtra::log_only`]): the logged line (at most 4096 bytes kept).
    /// Default: `bp <id> hit by thread <tid> at <rip>`.
    pub message: Option<Formatter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointInfo {
    pub id: BpId,
    pub bp: Breakpoint,
    pub hits: u64,
    /// Debug register slot for enabled hardware breakpoints.
    pub slot: Option<u8>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub options: BpOptions,
    /// Length of the watched range (`bp.size`, or the length of a range watch).
    #[serde(default)]
    pub len: u64,
    /// Hits not recorded because the breakpoint already had [`MAX_RECORDS`] distinct
    /// (instruction, address) records.
    #[serde(default)]
    pub records_dropped: u64,
    #[serde(default)]
    pub extra: BpExtra,
    /// Pending breakpoint ([`Debugger::add_pending_breakpoint`]): its address expression.
    #[serde(default)]
    pub pending: Option<String>,
    /// A pending breakpoint's expression resolved in the current modules (`bp.address`).
    #[serde(default)]
    pub resolved: bool,
}

/// Most distinct hit records kept per breakpoint (a memcpy-like instruction on an
/// execute breakpoint with `address_of` would otherwise grow without bound).
pub const MAX_RECORDS: usize = 65_536;

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitRecord {
    /// The instruction pointer at the trap. x86 reports data watchpoints *after* the access,
    /// so for `Write`/`Access` this is the instruction following the one that accessed —
    /// that instruction ends exactly at `ip` (see `insn`). For `Execute` it is the
    /// breakpoint address itself.
    pub ip: Addr,
    /// From [`Hooks::address_of`] (page watches: the accessed address).
    pub address: Option<Addr>,
    pub count: u64,
    /// Registers at the most recent hit.
    pub context: Context,
    /// Code bytes starting at `code_at` (original bytes, int3 hidden): the 16 bytes ending
    /// at `ip` for watchpoints, the 16 bytes from `ip` for execute breakpoints.
    pub code_at: Addr,
    pub code: Vec<u8>,
    /// Start of the instruction that accessed (watchpoints; exact for page watches,
    /// decoded backwards from `ip` for debug registers) or executed (`ip`). `None` when it
    /// could not be decoded.
    #[serde(default)]
    pub insn: Option<Addr>,
}

/// What to do with a signal (Linux) / exception code (Windows) the target raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalAction {
    /// Deliver it to the target and keep running.
    Pass,
    /// Swallow it and keep running.
    Ignore,
    /// Stop with [`BreakReason::Signal`]; [`Debugger::cont`] decides pass or ignore.
    Break,
}

/// A signal / exception code with its name and default action ([`signal_table`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SignalInfo {
    pub code: u32,
    pub name: &'static str,
    pub default: SignalAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakReason {
    Breakpoint(BpId),
    /// A step / step over / step out / run-to finished.
    Step,
    /// [`Debugger::pause`].
    Pause,
    /// Signal number on Linux, exception code on Windows. `address` is the faulting address
    /// when the OS reports one.
    Signal {
        code: u32,
        address: Option<Addr>,
    },
    TraceStop(BpId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// The whole process is stopped. Inspect, then `cont` / `step_*` / `run_to`.
    Break {
        tid: Tid,
        reason: BreakReason,
        context: Box<Context>,
    },
    ThreadCreated {
        tid: Tid,
    },
    ThreadExited {
        tid: Tid,
    },
    ModuleLoaded(Module),
    ModuleUnloaded {
        base: Addr,
    },
    /// A signal/exception that was passed or ignored without stopping.
    Signal {
        tid: Tid,
        code: u32,
        address: Option<Addr>,
        passed: bool,
    },
    TraceDone {
        bp: BpId,
        steps: u32,
    },
    /// Exit code, `None` when killed by a signal. The session is over; records stay readable.
    ProcessExited {
        code: Option<i32>,
    },
    /// The process replaced its image (Linux `execve`). Every breakpoint is now disabled
    /// (hits and records kept); enabling one arms it at its address in the new image.
    Exec,
    /// The process forked; the child got our breakpoints removed and was detached.
    Forked {
        child: Pid,
    },
    /// A breakpoint disabled itself ([`BpOptions::one_shot`] / [`BpOptions::max_hits`]), or
    /// a write through [`Debugger::process`] covered it from before its first byte.
    BreakpointDisabled {
        bp: BpId,
    },
    /// The next `Break { reason: Pause }` is for this debug event ([`BreakOn`], launch).
    Stopped {
        tid: Tid,
        why: Trigger,
    },
    /// A tracepoint hit ([`BpExtra::log_only`]). At most [`MAX_LOG_RATE`] lines a second
    /// are sent; `dropped` counts the ones left out since the previous line.
    Log {
        bp: BpId,
        tid: Tid,
        text: String,
        dropped: u64,
    },
    /// A pending breakpoint's expression resolved and the breakpoint is armed at `address`.
    BreakpointResolved {
        bp: BpId,
        address: Addr,
    },
}

/// Most [`Event::Log`] lines sent per second.
pub const MAX_LOG_RATE: u32 = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Running,
    Broken {
        tid: Tid,
    },
    /// Stopped by [`Process::suspend`] on the session's process.
    Suspended,
    Exited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: Tid,
    pub suspended: bool,
    /// Linux: `/proc/<pid>/task/<tid>/comm`; Windows: the thread description (Windows 10
    /// 1607+). Empty when unknown.
    #[serde(default)]
    pub name: String,
    /// Linux: the kernel's state letter (`R`, `S`, `D`, `t` = stopped by the debugger, ...);
    /// Windows: `suspended` or `running`.
    #[serde(default)]
    pub state: String,
    /// CPU time spent in user / kernel mode, milliseconds.
    #[serde(default)]
    pub user_ms: u64,
    #[serde(default)]
    pub kernel_ms: u64,
}

/// One frame of [`Debugger::backtrace_frames`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub addr: Addr,
    /// Name of the module holding `addr`.
    pub module: Option<String>,
    /// `module.symbol+off` (or `module+off`), from hh-asm's `symbol_at`.
    pub symbol: Option<String>,
}

/// x86-64 thread registers (32-bit targets: the low halves, `r8`..`r15` zero).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
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
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    /// Windows: read-only (TEB addresses; `fs_base` is the 32-bit TEB of WOW64 threads).
    pub fs_base: u64,
    pub gs_base: u64,
    /// DR0..DR7 (4 and 5 are always 0). Read-only: `set_context` ignores them, breakpoints
    /// own the debug registers.
    pub dr: [u64; 8],
    pub fpu: Fpu,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fpu {
    pub fcw: u16,
    pub fsw: u16,
    /// Abridged (FXSAVE) tag word.
    pub ftw: u16,
    pub fop: u16,
    pub fip: u64,
    pub fdp: u64,
    pub mxcsr: u32,
    /// ST0..ST7, 80-bit little endian.
    pub st: [[u8; 10]; 8],
    pub xmm: [[u8; 16]; 16],
    /// Upper halves of YMM0..15 (AVX), valid when `has_ymm`. Only [`Debugger::context`]
    /// fills them (hit records and break events do not); [`Debugger::set_context`] writes
    /// them when `has_ymm` is set.
    #[serde(default)]
    pub ymm_hi: [[u8; 16]; 16],
    #[serde(default)]
    pub has_ymm: bool,
}

/// Registers as hh-asm's analysis wants them.
#[cfg_attr(
    not(all(target_arch = "x86_64", any(target_os = "linux", windows))),
    allow(dead_code)
)]
fn registers(c: &Context) -> hh_asm::Registers {
    [
        ("rax", c.rax),
        ("rbx", c.rbx),
        ("rcx", c.rcx),
        ("rdx", c.rdx),
        ("rsi", c.rsi),
        ("rdi", c.rdi),
        ("rbp", c.rbp),
        ("rsp", c.rsp),
        ("r8", c.r8),
        ("r9", c.r9),
        ("r10", c.r10),
        ("r11", c.r11),
        ("r12", c.r12),
        ("r13", c.r13),
        ("r14", c.r14),
        ("r15", c.r15),
        ("rip", c.rip),
        ("eflags", c.rflags),
        ("fs_base", c.fs_base),
        ("gs_base", c.gs_base),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// Armed int3s: original bytes, and the ones temporarily put back for a thread to step over
/// (with how many threads are stepping). Shared between the debugger thread and the process
/// wrapper so readers never see 0xCC and writers never re-arm a byte mid-step.
#[derive(Default)]
struct Patches {
    orig: BTreeMap<Addr, u8>,
    lifted: BTreeMap<Addr, u32>,
    /// Breakpoints a write landed inside of (no longer an instruction start): dropped
    /// here, the debugger thread disables them.
    dropped: Vec<Addr>,
}

#[derive(Default)]
struct Shared {
    patches: Mutex<Patches>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Patches> {
        self.patches.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn read(&self, mem: &dyn Process, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        let n = mem.read(addr, buf)?;
        for (&a, &b) in self.lock().orig.range(addr..addr.saturating_add(n as u64)) {
            buf[(a - addr) as usize] = b;
        }
        Ok(n)
    }

    /// Writes `data`, keeping armed int3s in place and updating their saved originals.
    /// Writes `data`. An armed int3 at the first byte stays armed (its saved original
    /// becomes the new byte); armed int3s strictly inside the written range are dropped,
    /// since new code there need not start an instruction at them (e.g. a jmp hook).
    fn write(&self, mem: &dyn Process, addr: Addr, data: &[u8]) -> Result<()> {
        let mut p = self.lock();
        let p = &mut *p;
        let Some(&new_first) = data.first() else {
            return mem.write(addr, data);
        };
        let end = addr.saturating_add(data.len() as u64);
        let armed_first = p.orig.contains_key(&addr);
        let mut out = data.to_vec();
        if armed_first && !p.lifted.contains_key(&addr) {
            out[0] = 0xcc;
        }
        mem.write(addr, &out)?;
        // Only now (the write succeeded) update what we remember.
        if armed_first {
            p.orig.insert(addr, new_first);
        }
        let inside: Vec<Addr> = p.orig.range(addr + 1..end).map(|(&a, _)| a).collect();
        for a in inside {
            p.orig.remove(&a);
            p.lifted.remove(&a);
            p.dropped.push(a);
        }
        Ok(())
    }
}

/// The target's `hh_core` process, reopened after an exec (the old handle keeps pointing
/// at the old image's memory).
struct Live {
    pid: Pid,
    cur: RwLock<Arc<dyn Process>>,
}

impl Live {
    fn get(&self) -> Arc<dyn Process> {
        self.cur.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    #[cfg_attr(
        not(all(target_arch = "x86_64", target_os = "linux")),
        allow(dead_code)
    )]
    fn reopen(&self) {
        if let Ok(p) = hh_core::open(self.pid) {
            *self.cur.write().unwrap_or_else(|e| e.into_inner()) = p;
        }
    }
}

impl Memory for Live {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        self.get().read(addr, buf)
    }
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        self.get().write(addr, data)
    }
    fn pointer_size(&self) -> usize {
        self.get().pointer_size()
    }
}

impl Process for Live {
    fn pid(&self) -> Pid {
        self.pid
    }
    fn is_alive(&self) -> bool {
        self.get().is_alive()
    }
    fn regions(&self) -> Result<Vec<Region>> {
        self.get().regions()
    }
    fn modules(&self) -> Result<Vec<Module>> {
        self.get().modules()
    }
    fn threads(&self) -> Result<Vec<u32>> {
        self.get().threads()
    }
    fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> Result<Addr> {
        self.get().alloc(size, prot, near)
    }
    fn free(&self, addr: Addr, size: u64) -> Result<()> {
        self.get().free(addr, size)
    }
    fn protect(&self, addr: Addr, size: u64, prot: Prot) -> Result<Prot> {
        self.get().protect(addr, size, prot)
    }
    fn suspend(&self) -> Result<()> {
        self.get().suspend()
    }
    fn resume(&self) -> Result<()> {
        self.get().resume()
    }
}

/// The target as the debugger thread sees it: reads hide int3 bytes.
#[cfg_attr(
    not(all(target_arch = "x86_64", any(target_os = "linux", windows))),
    allow(dead_code)
)]
struct Masked {
    inner: Arc<dyn Process>,
    shared: Arc<Shared>,
}

impl Memory for Masked {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        self.shared.read(&*self.inner, addr, buf)
    }
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        self.shared.write(&*self.inner, addr, data)
    }
    fn pointer_size(&self) -> usize {
        self.inner.pointer_size()
    }
}

impl Process for Masked {
    fn pid(&self) -> Pid {
        self.inner.pid()
    }
    fn regions(&self) -> Result<Vec<Region>> {
        self.inner.regions()
    }
    fn modules(&self) -> Result<Vec<Module>> {
        self.inner.modules()
    }
}

fn detached() -> Error {
    Error::Other("debugger is detached".into())
}

/// A call instruction ends exactly at `ret` (frame-pointer walk validation).
#[cfg_attr(
    not(all(target_arch = "x86_64", any(target_os = "linux", windows))),
    allow(dead_code)
)]
fn after_call(p: &dyn Process, ret: Addr) -> bool {
    (2..=9u64).filter_map(|n| ret.checked_sub(n)).any(|a| {
        hh_asm::analyze_instruction(p, a, None)
            .is_ok_and(|i| i.kind == hh_asm::FlowKind::Call && i.next() == ret)
    })
}

/// Frame-pointer walk from (`rip`, `rbp`): return addresses must sit in executable memory
/// right after a call instruction, frames must be readable and grow upwards.
#[cfg_attr(
    not(all(target_arch = "x86_64", any(target_os = "linux", windows))),
    allow(dead_code)
)]
fn walk_frames(p: &dyn Process, rip: Addr, rbp: Addr, max: usize) -> Vec<Addr> {
    let chain = frame_chain(p, rbp, max.saturating_sub(1));
    std::iter::once(rip)
        .chain(chain.into_iter().map(|f| f.0))
        .take(max)
        .collect()
}

/// The frame-pointer walk of [`walk_frames`] as (return address, stack slot holding it):
/// entry `k` is where frame `k` returns to.
#[cfg_attr(
    not(all(target_arch = "x86_64", any(target_os = "linux", windows))),
    allow(dead_code)
)]
fn frame_chain(p: &dyn Process, rbp: Addr, max: usize) -> Vec<(Addr, Addr)> {
    let ps = p.pointer_size() as u64;
    let regions = p.regions().unwrap_or_default();
    let has = |a: Addr, f: fn(&Prot) -> bool| {
        regions
            .iter()
            .any(|r| f(&r.prot) && a >= r.start && a - r.start < r.size)
    };
    let mut out = Vec::new();
    let mut bp = rbp;
    while out.len() < max && bp != 0 && bp.is_multiple_of(ps) && has(bp, |p| p.r) {
        let (Ok(next), Ok(ret)) = (p.read_ptr(bp), p.read_ptr(bp + ps)) else {
            break;
        };
        if !has(ret, |p| p.x) || !after_call(p, ret) {
            break;
        }
        out.push((ret, bp + ps));
        if next <= bp {
            break;
        }
        bp = next;
    }
    out
}

/// `*` / `?` wildcard match, ASCII case-insensitive.
#[cfg_attr(
    not(all(target_arch = "x86_64", any(target_os = "linux", windows))),
    allow(dead_code)
)]
fn glob(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut i, mut j, mut star, mut mark) = (0, 0, None, 0);
    while j < s.len() {
        if i < p.len() && (p[i] == b'?' || p[i].eq_ignore_ascii_case(&s[j])) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if let Some(st) = star {
            i = st + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|&c| c == b'*')
}

/// A module matches one of `pats` ([`BreakOn`], [`TraceOptions::skip_modules`]).
#[cfg_attr(
    not(all(target_arch = "x86_64", any(target_os = "linux", windows))),
    allow(dead_code)
)]
fn module_matches(pats: &[String], m: &Module) -> bool {
    pats.iter().any(|p| match p.contains(['/', '\\']) {
        true => glob(p, &m.path),
        false => glob(p, &m.name),
    })
}

const TRACE_MAGIC: &str = "heaphook-trace";
/// Largest trace file [`read_trace`] reads.
pub const MAX_TRACE_FILE: u64 = 512 << 20;

#[derive(Serialize, Deserialize)]
struct TraceFile {
    format: String,
    version: u32,
    steps: Vec<TraceStep>,
}

/// Writes a trace as JSON: `{"format": "heaphook-trace", "version": 1, "steps": [...]}`
/// where each step is a [`TraceStep`] (registers as numbers, byte arrays as arrays).
pub fn write_trace(w: &mut dyn std::io::Write, steps: &[TraceStep]) -> Result<()> {
    if steps.len() > MAX_TRACE_STEPS {
        return Err(Error::Other(format!(
            "a trace holds at most {MAX_TRACE_STEPS} steps"
        )));
    }
    let f = TraceFile {
        format: TRACE_MAGIC.into(),
        version: 1,
        steps: steps.to_vec(),
    };
    serde_json::to_writer(std::io::BufWriter::new(w), &f)
        .map_err(|e| Error::Other(format!("writing trace: {e}")))
}

/// Reads a trace written by [`write_trace`]. Refuses files over [`MAX_TRACE_FILE`] bytes,
/// more than [`MAX_TRACE_STEPS`] steps, more than 64 accesses per step or access values
/// over 64 bytes.
pub fn read_trace(r: &mut dyn std::io::Read) -> Result<Vec<TraceStep>> {
    use std::io::Read;
    let mut buf = Vec::new();
    r.take(MAX_TRACE_FILE + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_TRACE_FILE {
        return Err(Error::Parse(format!(
            "trace file larger than {MAX_TRACE_FILE} bytes"
        )));
    }
    let f: TraceFile =
        serde_json::from_slice(&buf).map_err(|e| Error::Parse(format!("trace file: {e}")))?;
    if f.format != TRACE_MAGIC || f.version != 1 {
        return Err(Error::Parse("not a HeapHook trace (version 1)".into()));
    }
    if f.steps.len() > MAX_TRACE_STEPS {
        return Err(Error::Parse(format!(
            "trace has more than {MAX_TRACE_STEPS} steps"
        )));
    }
    for s in &f.steps {
        let bad = s.accesses.len() > 64
            || s.accesses.iter().any(|a| {
                a.before.len() > 64 || a.after.as_ref().is_some_and(|v| v.len() > 64)
            });
        if bad {
            return Err(Error::Parse("trace step out of bounds".into()));
        }
    }
    Ok(f.steps)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", windows)))]
pub use session::*;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", windows)))]
mod session {
    use super::*;
    use crate::engine::Engine;

    type Cmd = Box<dyn FnOnce(&mut Engine) + Send>;

    /// Signals (Linux) / exception codes (Windows) the debugger knows by name, with the
    /// action a new session uses for them. Codes not listed default to `Pass`.
    pub fn signal_table() -> Vec<SignalInfo> {
        crate::os::SIGNALS
            .iter()
            .map(|&(code, name, default)| SignalInfo {
                code,
                name,
                default,
            })
            .collect()
    }

    fn call<R: Send + 'static>(
        tx: &mpsc::Sender<Cmd>,
        f: impl FnOnce(&mut Engine) -> Result<R> + Send + 'static,
    ) -> Result<R> {
        if engine::on_engine_thread() {
            return Err(Error::Other("debugger called from its own callback".into()));
        }
        let (rtx, rrx) = mpsc::sync_channel(1);
        tx.send(Box::new(move |e| {
            let _ = rtx.send(f(e));
        }))
        .map_err(|_| detached())?;
        rrx.recv().map_err(|_| detached())?
    }

    /// An attached debugging session. Dropping it detaches.
    pub struct Debugger {
        pid: Pid,
        cmd: mpsc::Sender<Cmd>,
        events: Mutex<mpsc::Receiver<Event>>,
        process: Arc<dyn Process>,
        thread: Option<JoinHandle<()>>,
    }

    impl Debugger {
        /// Attaches to a running process without stopping it for longer than the attach.
        pub fn attach(pid: Pid) -> Result<Debugger> {
            Self::start(engine::Start::Attach(pid))
        }

        /// Starts a program under the debugger ("create process"), stopped where
        /// `opts.stop` says so breakpoints can be set before its code runs. When it stops,
        /// [`Event::Stopped`] (`Trigger::Start` / `Trigger::Entry`) and a `Break` with
        /// [`BreakReason::Pause`] are reported. A program that cannot be started is a clean
        /// error (nothing left behind). Read [`LaunchOptions`] on what drop / detach do.
        pub fn launch(opts: &LaunchOptions) -> Result<Debugger> {
            Self::start(engine::Start::Launch(Box::new(opts.clone())))
        }

        fn start(how: engine::Start) -> Result<Debugger> {
            let shared = Arc::new(Shared::default());
            let (cmd, cmd_rx) = mpsc::channel::<Cmd>();
            let (ev_tx, ev_rx) = mpsc::channel();
            let (ok_tx, ok_rx) = mpsc::sync_channel(1);
            let s = shared.clone();
            let thread = std::thread::Builder::new()
                .name("hh-debug".into())
                .spawn(move || engine::run(how, s, ev_tx, cmd_rx, ok_tx))?;
            let live = match ok_rx.recv() {
                Ok(Ok(live)) => live,
                Ok(Err(e)) => {
                    let _ = thread.join();
                    return Err(e);
                }
                Err(_) => {
                    let _ = thread.join();
                    return Err(Error::Other("debugger thread died".into()));
                }
            };
            let pid = live.pid;
            let inner: Arc<dyn Process> = live;
            let process = Arc::new(DbgProcess {
                inner,
                shared,
                cmd: cmd.clone(),
            });
            Ok(Debugger {
                pid,
                cmd,
                events: Mutex::new(ev_rx),
                process,
                thread: Some(thread),
            })
        }

        pub fn pid(&self) -> Pid {
            self.pid
        }

        /// The target as an `hh_core::Process` that is safe to use while attached.
        pub fn process(&self) -> Arc<dyn Process> {
            self.process.clone()
        }

        /// Removes every breakpoint and detaches; the target keeps running.
        pub fn detach(mut self) -> Result<()> {
            self.shutdown()
        }

        fn shutdown(&mut self) -> Result<()> {
            let Some(t) = self.thread.take() else {
                return Ok(());
            };
            let r = call(&self.cmd, |e| e.detach());
            let _ = t.join();
            match r {
                Err(Error::Other(m)) if m == "debugger is detached" => Ok(()),
                r => r,
            }
        }

        fn call<R: Send + 'static>(
            &self,
            f: impl FnOnce(&mut Engine) -> Result<R> + Send + 'static,
        ) -> Result<R> {
            call(&self.cmd, f)
        }

        /// Next event, waiting up to `timeout`.
        pub fn next_event(&self, timeout: Duration) -> Option<Event> {
            let rx = self.events.lock().unwrap_or_else(|e| e.into_inner());
            rx.recv_timeout(timeout).ok()
        }

        /// All events queued right now.
        pub fn events(&self) -> Vec<Event> {
            let rx = self.events.lock().unwrap_or_else(|e| e.into_inner());
            rx.try_iter().collect()
        }

        pub fn state(&self) -> Result<State> {
            self.call(|e| Ok(e.state()))
        }

        /// The most recent raw events, commands, resumes and recoveries of this session,
        /// oldest first, one line each (bounded). For diagnostics and bug reports.
        pub fn history(&self) -> Result<Vec<String>> {
            self.call(|e| {
                e.drain_notes();
                Ok(e.history())
            })
        }

        pub fn add_breakpoint(&self, bp: Breakpoint, hooks: Hooks) -> Result<BpId> {
            self.add_breakpoint_with(bp, hooks, BpOptions::default())
        }

        /// [`Debugger::add_breakpoint`] with hit counting options.
        pub fn add_breakpoint_with(
            &self,
            bp: Breakpoint,
            hooks: Hooks,
            opts: BpOptions,
        ) -> Result<BpId> {
            self.call(move |e| e.add_bp(bp, hooks, opts, None, BpExtra::default(), None))
        }

        /// Page-protection watch ([`BpMethod::Page`]) of `len` bytes from `start`, for
        /// ranges the debug registers cannot cover (whole structures, buffers). Read its
        /// cost on [`BpMethod::Page`] first. Windows: not supported.
        pub fn add_watch_range(
            &self,
            start: Addr,
            len: u64,
            kind: BpKind,
            action: Action,
            hooks: Hooks,
            opts: BpOptions,
        ) -> Result<BpId> {
            let bp = Breakpoint {
                address: start,
                kind,
                size: len.min(255) as u8,
                method: BpMethod::Page,
                action,
            };
            self.call(move |e| e.add_bp(bp, hooks, opts, Some(len), BpExtra::default(), None))
        }

        pub fn remove_breakpoint(&self, id: BpId) -> Result<()> {
            self.call(move |e| e.remove_bp(id))
        }

        /// Disables (unpatches / frees the debug register / restores page protection) or
        /// re-enables a breakpoint in place. Hits, records and trace are kept. Enabling a
        /// hardware breakpoint fails when all 4 debug registers are taken.
        pub fn set_enabled(&self, id: BpId, enabled: bool) -> Result<()> {
            self.call(move |e| e.set_enabled(id, enabled))
        }

        /// Replaces all hooks of a breakpoint in place.
        pub fn set_hooks(&self, id: BpId, hooks: Hooks) -> Result<()> {
            self.call(move |e| e.set_hooks(id, hooks))
        }

        /// Replaces only the condition (`None` clears it).
        pub fn set_condition(&self, id: BpId, condition: Option<Predicate>) -> Result<()> {
            self.call(move |e| e.set_condition(id, condition))
        }

        /// Replaces the hit counting options. Hits so far count towards them.
        pub fn set_options(&self, id: BpId, opts: BpOptions) -> Result<()> {
            self.call(move |e| e.set_options(id, opts))
        }

        pub fn breakpoints(&self) -> Result<Vec<BreakpointInfo>> {
            self.call(|e| Ok(e.bp_list()))
        }

        /// Live hit records of a `Record` breakpoint, sorted by (ip, address).
        pub fn records(&self, id: BpId) -> Result<Vec<HitRecord>> {
            self.call(move |e| e.records(id))
        }

        pub fn clear_records(&self, id: BpId) -> Result<()> {
            self.call(move |e| e.clear_records(id))
        }

        /// Registers of each step of the last trace of a `Trace` breakpoint, starting with
        /// the hit itself.
        pub fn trace(&self, id: BpId) -> Result<Vec<Context>> {
            self.call(move |e| e.trace_log(id))
        }

        pub fn set_signal_action(&self, code: u32, action: SignalAction) -> Result<()> {
            self.call(move |e| {
                e.set_policy(code, action);
                Ok(())
            })
        }

        /// The action currently used for `code`.
        pub fn signal_action(&self, code: u32) -> Result<SignalAction> {
            self.call(move |e| Ok(e.policy(code)))
        }

        /// Current action of every code in [`signal_table`] plus every code set explicitly,
        /// sorted by code.
        pub fn signal_actions(&self) -> Result<Vec<(u32, SignalAction)>> {
            self.call(|e| Ok(e.policy_list()))
        }

        /// Puts `code` back to its [`signal_table`] default.
        pub fn reset_signal_action(&self, code: u32) -> Result<()> {
            self.call(move |e| {
                e.reset_policy(Some(code));
                Ok(())
            })
        }

        /// Puts every code back to its [`signal_table`] default.
        pub fn reset_signal_actions(&self) -> Result<()> {
            self.call(|e| {
                e.reset_policy(None);
                Ok(())
            })
        }

        pub fn threads(&self) -> Result<Vec<ThreadInfo>> {
            self.call(|e| Ok(e.thread_list()))
        }

        /// Registers of a stopped thread (process broken/suspended, or thread suspended),
        /// YMM upper halves included where the CPU and OS have them.
        pub fn context(&self, tid: Tid) -> Result<Context> {
            self.call(move |e| e.context(tid))
        }

        /// Writes general, flag, segment, x87, MXCSR and SSE registers, and the YMM upper
        /// halves when `ctx.fpu.has_ymm` (debug registers are ignored; use
        /// [`Debugger::set_ip`] for a checked instruction pointer change).
        pub fn set_context(&self, tid: Tid, ctx: Context) -> Result<()> {
            self.call(move |e| e.set_context(tid, &ctx))
        }

        pub fn suspend_thread(&self, tid: Tid) -> Result<()> {
            self.call(move |e| e.suspend_thread(tid, true))
        }

        pub fn resume_thread(&self, tid: Tid) -> Result<()> {
            self.call(move |e| e.suspend_thread(tid, false))
        }

        /// Stops the whole process and reports `Break { reason: Pause }`.
        pub fn pause(&self) -> Result<()> {
            self.call(|e| e.pause())
        }

        /// Continues from a break. `pass_signal` delivers the signal/exception the break was
        /// about (ignored for other breaks).
        pub fn cont(&self, pass_signal: bool) -> Result<()> {
            self.call(move |e| e.cont(pass_signal))
        }

        /// Executes one instruction of `tid` (others stay stopped), then breaks again.
        pub fn step_into(&self, tid: Tid) -> Result<()> {
            self.step_with(tid, StepKind::Into, StepOptions::default())
        }

        /// Like `step_into`, but runs a `call` (recursion included) or a whole `rep` string
        /// instruction to completion; other threads run meanwhile.
        pub fn step_over(&self, tid: Tid) -> Result<()> {
            self.step_with(tid, StepKind::Over, StepOptions::default())
        }

        /// Runs until the current function returns (stepping over calls), then breaks.
        pub fn step_out(&self, tid: Tid) -> Result<()> {
            self.step_with(tid, StepKind::Out, StepOptions::default())
        }

        /// A step with options (skip breakpoints, modules to step over).
        pub fn step_with(&self, tid: Tid, kind: StepKind, opts: StepOptions) -> Result<()> {
            self.call(move |e| e.step(tid, kind, opts))
        }

        /// Continues until *any* thread reaches `addr`, then breaks with that thread.
        pub fn run_to(&self, addr: Addr) -> Result<()> {
            self.call(move |e| e.run_to(addr, None, 1))
        }

        /// Continues until `tid` reaches `addr`; other threads pass `addr` unhindered.
        pub fn run_to_thread(&self, tid: Tid, addr: Addr) -> Result<()> {
            self.call(move |e| e.run_to(addr, Some(tid), 1))
        }

        /// Continues until `addr` has been reached `count` times (by `tid` only, or by any
        /// thread), then breaks.
        pub fn run_to_count(&self, addr: Addr, count: u64, tid: Option<Tid>) -> Result<()> {
            self.call(move |e| e.run_to(addr, tid, count))
        }

        /// "Execute till return" of frame `frame` of [`Debugger::backtrace`] (0 = the
        /// current function): continues until that function returns to its caller, on this
        /// thread and with the stack back above that frame, then breaks. Needs the
        /// frame-pointer walk to reach that frame.
        pub fn run_until_return(&self, tid: Tid, frame: usize) -> Result<()> {
            self.call(move |e| e.run_until_return(tid, frame))
        }

        /// Moves the instruction pointer of a stopped thread. The target must be in
        /// executable memory and decode as an instruction. Continuing executes the
        /// instruction there even if a breakpoint sits on it.
        pub fn set_ip(&self, tid: Tid, addr: Addr) -> Result<()> {
            self.call(move |e| e.set_ip(tid, addr))
        }

        /// Which debug events break the process (thread / module events).
        pub fn set_break_on(&self, b: BreakOn) -> Result<()> {
            self.call(move |e| {
                e.break_on = b;
                Ok(())
            })
        }

        pub fn break_on(&self) -> Result<BreakOn> {
            self.call(|e| Ok(e.break_on.clone()))
        }

        /// [`Debugger::add_breakpoint_with`] plus [`BpExtra`] (thread filter, outside-module
        /// filter, tracepoint, trace options).
        pub fn add_breakpoint_ext(
            &self,
            bp: Breakpoint,
            hooks: Hooks,
            opts: BpOptions,
            extra: BpExtra,
        ) -> Result<BpId> {
            self.call(move |e| e.add_bp(bp, hooks, opts, None, extra, None))
        }

        /// A breakpoint at an address expression (`module+offset`, `module.symbol`, a
        /// symbol; hh-asm's `resolve_address`), armed as soon as it resolves and re-resolved
        /// whenever modules load, unload or the process execs. `bp.address` is ignored.
        /// Until it resolves, `enabled` is false and `resolved` false.
        pub fn add_pending_breakpoint(
            &self,
            expr: &str,
            bp: Breakpoint,
            hooks: Hooks,
            opts: BpOptions,
            extra: BpExtra,
        ) -> Result<BpId> {
            let expr = expr.trim().to_string();
            if expr.is_empty() || expr.len() > 4096 {
                return Err(Error::Other("bad breakpoint expression".into()));
            }
            self.call(move |e| e.add_bp(bp, hooks, opts, None, extra, Some(expr)))
        }

        /// Replaces the [`BpExtra`] of a breakpoint (hits and records kept).
        pub fn set_extra(&self, id: BpId, extra: BpExtra) -> Result<()> {
            self.call(move |e| e.set_extra(id, extra))
        }

        /// The last trace of a `Trace` breakpoint with the memory accesses of each step.
        pub fn trace_steps(&self, id: BpId) -> Result<Vec<TraceStep>> {
            self.call(move |e| e.trace_steps(id))
        }

        /// Starts recording which of `entries` (e.g. function entries) execute, with a
        /// one-shot int3 on each (removed at its first hit), and the instruction of every
        /// traced step. Entries outside executable memory or not at an instruction start (see
        /// [`Debugger::coverage_start_checked`]) are skipped; returns how many were armed.
        /// Restarting drops the previous set.
        pub fn coverage_start(&self, entries: Vec<Addr>) -> Result<usize> {
            self.call(move |e| e.cov_start(entries, None).map(|c| c.armed))
        }

        /// [`Debugger::coverage_start`] for addresses taken from elsewhere (a saved code
        /// dissection): an entry is armed only inside one of `modules` that is still loaded
        /// with the same path, base and size, and only where decoding its executable mapping
        /// linearly from the mapping's start reaches it as the start of a valid instruction
        /// that overlaps no armed int3. [`Debugger::coverage_start`] makes the same
        /// instruction checks.
        pub fn coverage_start_checked(&self, entries: Vec<Addr>, modules: Vec<Module>) -> Result<CoverageArm> {
            self.call(move |e| e.cov_start(entries, Some(modules)))
        }

        /// Addresses executed since `coverage_start`, sorted.
        pub fn coverage_hits(&self) -> Result<Vec<Addr>> {
            self.call(|e| Ok(e.cov_hits()))
        }

        /// Removes the remaining coverage int3s and returns the executed set, sorted.
        pub fn coverage_stop(&self) -> Result<Vec<Addr>> {
            self.call(|e| e.cov_stop())
        }

        /// `count` stack slots starting at the thread's stack pointer.
        pub fn read_stack(&self, tid: Tid, count: usize) -> Result<Vec<u64>> {
            let rsp = self.context(tid)?.rsp;
            let ps = self.process.pointer_size();
            let mut buf = vec![0u8; count * ps];
            let n = self.process.read(rsp, &mut buf)?;
            Ok(buf[..n - n % ps]
                .chunks_exact(ps)
                .map(|c| {
                    let mut b = [0u8; 8];
                    b[..ps].copy_from_slice(c);
                    u64::from_le_bytes(b)
                })
                .collect())
        }

        /// The instruction pointer followed by return addresses from a frame-pointer walk
        /// (`[rbp+8]`, `rbp = [rbp]`). The walk stops at the first return address that is
        /// not in executable memory right after a call, so code built without frame
        /// pointers gives a short chain rather than garbage.
        pub fn backtrace(&self, tid: Tid, max: usize) -> Result<Vec<Addr>> {
            let ctx = self.context(tid)?;
            Ok(walk_frames(&*self.process, ctx.rip, ctx.rbp, max))
        }

        /// [`Debugger::backtrace`] annotated with module and symbol names.
        pub fn backtrace_frames(&self, tid: Tid, max: usize) -> Result<Vec<Frame>> {
            let p = &*self.process;
            let mods = p.modules().unwrap_or_default();
            let syms = hh_asm::SymbolTable::default();
            Ok(self
                .backtrace(tid, max)?
                .into_iter()
                .map(|addr| Frame {
                    addr,
                    module: mods
                        .iter()
                        .find(|m| addr >= m.base && addr - m.base < m.size)
                        .map(|m| m.name.clone()),
                    symbol: hh_asm::symbol_at(p, &syms, addr),
                })
                .collect())
        }
    }

    impl Drop for Debugger {
        fn drop(&mut self) {
            let _ = self.shutdown();
        }
    }

    struct DbgProcess {
        inner: Arc<dyn Process>,
        shared: Arc<Shared>,
        cmd: mpsc::Sender<Cmd>,
    }

    impl DbgProcess {
        /// Runs `f` on the debugger thread; after detach, falls back to the plain process.
        fn via<R: Send + 'static>(
            &self,
            f: impl FnOnce(&mut Engine) -> Result<R> + Send + 'static,
            fallback: impl FnOnce(&dyn Process) -> Result<R>,
        ) -> Result<R> {
            match call(&self.cmd, f) {
                Err(Error::Other(m)) if m == "debugger is detached" => fallback(&*self.inner),
                r => r,
            }
        }
    }

    impl Memory for DbgProcess {
        fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
            self.shared.read(&*self.inner, addr, buf)
        }
        fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
            self.shared.write(&*self.inner, addr, data)
        }
        fn pointer_size(&self) -> usize {
            self.inner.pointer_size()
        }
    }

    impl Process for DbgProcess {
        fn pid(&self) -> Pid {
            self.inner.pid()
        }
        fn is_alive(&self) -> bool {
            self.inner.is_alive()
        }
        fn regions(&self) -> Result<Vec<Region>> {
            self.inner.regions()
        }
        fn modules(&self) -> Result<Vec<Module>> {
            self.inner.modules()
        }
        fn threads(&self) -> Result<Vec<u32>> {
            self.inner.threads()
        }
        #[cfg(windows)]
        fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> Result<Addr> {
            self.inner.alloc(size, prot, near)
        }
        #[cfg(windows)]
        fn free(&self, addr: Addr, size: u64) -> Result<()> {
            self.inner.free(addr, size)
        }
        #[cfg(windows)]
        fn protect(&self, addr: Addr, size: u64, prot: Prot) -> Result<Prot> {
            self.inner.protect(addr, size, prot)
        }
        #[cfg(target_os = "linux")]
        fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> Result<Addr> {
            self.via(
                move |e| e.remote(move |os, mem| os.alloc(mem, size, prot, near)),
                |p| p.alloc(size, prot, near),
            )
        }
        #[cfg(target_os = "linux")]
        fn free(&self, addr: Addr, size: u64) -> Result<()> {
            self.via(
                move |e| e.remote(move |os, mem| os.free(mem, addr, size)),
                |p| p.free(addr, size),
            )
        }
        #[cfg(target_os = "linux")]
        fn protect(&self, addr: Addr, size: u64, prot: Prot) -> Result<Prot> {
            self.via(
                move |e| e.remote(move |os, mem| os.protect(mem, addr, size, prot)),
                |p| p.protect(addr, size, prot),
            )
        }
        /// Stops every thread without reporting a break.
        fn suspend(&self) -> Result<()> {
            self.via(|e| e.suspend_process(true), |p| p.suspend())
        }
        fn resume(&self) -> Result<()> {
            self.via(|e| e.suspend_process(false), |p| p.resume())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hh_core::MockProcess;

    #[test]
    fn shared_masks_int3() {
        let p = MockProcess::new(0x1000, vec![0x90; 16]);
        let s = Shared::default();
        p.write(0x1004, &[0xcc]).unwrap();
        s.lock().orig.insert(0x1004, 0x90);
        let mut b = [0u8; 8];
        s.read(&p, 0x1000, &mut b).unwrap();
        assert_eq!(b, [0x90; 8]);
        // A write starting at the breakpoint updates the saved byte and keeps the int3.
        s.write(&p, 0x1004, &[2, 3]).unwrap();
        assert_eq!(s.lock().orig[&0x1004], 2);
        p.read(0x1003, &mut b[..3]).unwrap();
        assert_eq!(b[..3], [0x90, 0xcc, 3]);
        s.read(&p, 0x1003, &mut b[..3]).unwrap();
        assert_eq!(b[..3], [0x90, 2, 3]);
        // A failed write changes nothing.
        assert!(s.write(&p, 0x1004, &[9; 64]).is_err());
        assert_eq!(s.lock().orig[&0x1004], 2);
        // While a thread steps over it (byte lifted) a write must not re-arm it.
        p.write(0x1004, &[2]).unwrap();
        s.lock().lifted.insert(0x1004, 1);
        s.write(&p, 0x1004, &[7]).unwrap();
        p.read(0x1004, &mut b[..1]).unwrap();
        assert_eq!((b[0], s.lock().orig[&0x1004]), (7, 7));
        // A write that covers it from before (a jmp hook) drops it: no 0xCC in the new code.
        s.lock().lifted.clear();
        s.write(&p, 0x1003, &[0xe9, 1, 2, 3, 4]).unwrap();
        p.read(0x1003, &mut b[..5]).unwrap();
        assert_eq!(b[..5], [0xe9, 1, 2, 3, 4]);
        assert!(s.lock().orig.is_empty());
        assert_eq!(s.lock().dropped, [0x1004]);
    }

    #[test]
    fn frame_walk_stops_at_garbage() {
        // 0x1000: call 0x1010 (e8 0b 00 00 00), so 0x1005 is a valid return address.
        let mut mem = vec![0u8; 0x100];
        mem[..5].copy_from_slice(&[0xe8, 0x0b, 0, 0, 0]);
        // Frames at 0x1080 -> 0x1090 -> garbage return address 0x1003 (not after a call).
        mem[0x80..0x88].copy_from_slice(&0x1090u64.to_le_bytes());
        mem[0x88..0x90].copy_from_slice(&0x1005u64.to_le_bytes());
        mem[0x90..0x98].copy_from_slice(&0x10a0u64.to_le_bytes());
        mem[0x98..0xa0].copy_from_slice(&0x1003u64.to_le_bytes());
        struct X(MockProcess);
        impl Memory for X {
            fn read(&self, a: Addr, b: &mut [u8]) -> Result<usize> {
                self.0.read(a, b)
            }
            fn write(&self, a: Addr, d: &[u8]) -> Result<()> {
                self.0.write(a, d)
            }
        }
        impl Process for X {
            fn pid(&self) -> Pid {
                0
            }
            fn regions(&self) -> Result<Vec<Region>> {
                let mut r = self.0.regions()?;
                r[0].prot.x = true;
                Ok(r)
            }
        }
        let p = X(MockProcess::new(0x1000, mem));
        assert_eq!(walk_frames(&p, 0x1010, 0x1080, 10), [0x1010, 0x1005]);
        assert_eq!(walk_frames(&p, 0x1010, 0x1081, 10), [0x1010]);
    }

    #[test]
    fn glob_patterns() {
        assert!(glob("libc.so*", "libc.so.6"));
        assert!(glob("LIB?.dll", "libm.DLL"));
        assert!(glob("*", ""));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(!glob("a*b*c", "aXXbYY"));
        assert!(!glob("libc", "libc.so.6"));
        let m = Module {
            name: "libz.so.1".into(),
            path: "/usr/lib/libz.so.1".into(),
            base: 0,
            size: 1,
        };
        assert!(module_matches(&["/usr/*/libz*".into()], &m));
        assert!(!module_matches(&["/opt/*".into(), "libc*".into()], &m));
    }

    #[test]
    fn serde_roundtrip() {
        let e = Event::Break {
            tid: 1,
            reason: BreakReason::Signal {
                code: 11,
                address: Some(0x10),
            },
            context: Box::default(),
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(matches!(
            serde_json::from_str::<Event>(&j).unwrap(),
            Event::Break { tid: 1, .. }
        ));
        // Older serialized infos (without the new fields) still load.
        let old = r#"{"id":1,"bp":{"address":16,"kind":"Execute","size":1,"method":"Software","action":"Break"},"hits":2,"slot":null}"#;
        let i: BreakpointInfo = serde_json::from_str(old).unwrap();
        assert!(i.enabled && i.options == BpOptions::default());
    }
}
