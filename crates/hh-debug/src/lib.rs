//! HeapHook debugger: attach to a running process, software/hardware breakpoints and
//! watchpoints, "find out what writes/accesses this address", "find out what addresses this
//! instruction accesses", break-and-inspect (registers, stepping), break-and-trace, threads
//! and debug events.
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
use std::sync::{Arc, Mutex, mpsc};
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
    /// 1, 2, 4 or 8; hardware ranges must be aligned to it. Ignored for `Execute`.
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

/// Callbacks run on the debugger thread with the hitting thread's registers. They must be
/// quick and must not call back into the `Debugger` (that returns an error).
pub type Predicate = Arc<dyn Fn(&Context) -> bool + Send + Sync>;
pub type AddressOf = Arc<dyn Fn(&Context) -> Option<Addr> + Send + Sync>;

#[derive(Clone, Default)]
pub struct Hooks {
    /// Conditional breakpoint: hits where this returns false are ignored entirely.
    pub condition: Option<Predicate>,
    /// For `Record`: the address the instruction accesses (e.g. its effective address
    /// decoded by hh-asm). Records are keyed by (ip, this), which gives "find out what
    /// addresses this instruction accesses" on an execute breakpoint.
    pub address_of: Option<AddressOf>,
    /// For `Trace`: break (with [`BreakReason::TraceStop`]) at the first traced step for
    /// which this returns true.
    pub stop_when: Option<Predicate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointInfo {
    pub id: BpId,
    pub bp: Breakpoint,
    pub hits: u64,
    /// Debug register slot for hardware breakpoints.
    pub slot: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitRecord {
    /// The instruction pointer at the trap. x86 reports data watchpoints *after* the access,
    /// so for `Write`/`Access` this is the instruction following the one that accessed —
    /// that instruction ends exactly at `ip` (decode backwards in `code`). For `Execute` it
    /// is the breakpoint address itself.
    pub ip: Addr,
    /// From [`Hooks::address_of`].
    pub address: Option<Addr>,
    pub count: u64,
    /// Registers at the most recent hit.
    pub context: Context,
    /// Code bytes starting at `code_at` (original bytes, int3 hidden): the 16 bytes ending
    /// at `ip` for watchpoints, the 16 bytes from `ip` for execute breakpoints.
    pub code_at: Addr,
    pub code: Vec<u8>,
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
}

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
}

/// x86-64 thread registers.
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
    /// 0 on Windows (not part of CONTEXT).
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
}

/// Original bytes under armed int3s, shared between the debugger thread and the
/// process wrapper so readers never see 0xCC.
#[derive(Default)]
struct Shared {
    orig: Mutex<std::collections::BTreeMap<Addr, u8>>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<Addr, u8>> {
        self.orig.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn read(&self, mem: &dyn Process, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        let n = mem.read(addr, buf)?;
        for (&a, &b) in self.lock().range(addr..addr.saturating_add(n as u64)) {
            buf[(a - addr) as usize] = b;
        }
        Ok(n)
    }

    /// Writes `data`, keeping armed int3s in place and updating their saved originals.
    fn write(&self, mem: &dyn Process, addr: Addr, data: &[u8]) -> Result<()> {
        let mut orig = self.lock();
        let mut data = data.to_vec();
        for (&a, b) in orig.range_mut(addr..addr.saturating_add(data.len() as u64)) {
            let i = (a - addr) as usize;
            *b = data[i];
            data[i] = 0xcc;
        }
        mem.write(addr, &data)
    }
}

fn detached() -> Error {
    Error::Other("debugger is detached".into())
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", windows)))]
pub use session::*;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", windows)))]
mod session {
    use super::*;
    use crate::engine::Engine;

    type Cmd = Box<dyn FnOnce(&mut Engine) + Send>;

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
            let inner = hh_core::open(pid)?;
            let shared = Arc::new(Shared::default());
            let (cmd, cmd_rx) = mpsc::channel::<Cmd>();
            let (ev_tx, ev_rx) = mpsc::channel();
            let (ok_tx, ok_rx) = mpsc::sync_channel(1);
            let (m, s) = (inner.clone(), shared.clone());
            let thread = std::thread::Builder::new()
                .name("hh-debug".into())
                .spawn(move || engine::run(pid, m, s, ev_tx, cmd_rx, ok_tx))?;
            match ok_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let _ = thread.join();
                    return Err(e);
                }
                Err(_) => return Err(Error::Other("debugger thread died".into())),
            }
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

        pub fn add_breakpoint(&self, bp: Breakpoint, hooks: Hooks) -> Result<BpId> {
            self.call(move |e| e.add_bp(bp, hooks))
        }

        pub fn remove_breakpoint(&self, id: BpId) -> Result<()> {
            self.call(move |e| e.remove_bp(id))
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

        pub fn threads(&self) -> Result<Vec<ThreadInfo>> {
            self.call(|e| Ok(e.thread_list()))
        }

        /// Registers of a stopped thread (process broken/suspended, or thread suspended).
        pub fn context(&self, tid: Tid) -> Result<Context> {
            self.call(move |e| e.context(tid))
        }

        /// Writes general, flag, segment and FPU/SSE registers (debug registers are ignored).
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
            self.call(move |e| e.step(tid, engine::StepKind::Into))
        }

        /// Like `step_into`, but runs a `call` to completion.
        pub fn step_over(&self, tid: Tid) -> Result<()> {
            self.call(move |e| e.step(tid, engine::StepKind::Over))
        }

        /// Runs until the current function returns (stepping over calls), then breaks.
        pub fn step_out(&self, tid: Tid) -> Result<()> {
            self.call(move |e| e.step(tid, engine::StepKind::Out))
        }

        /// Continues until any thread reaches `addr`, then breaks.
        pub fn run_to(&self, addr: Addr) -> Result<()> {
            self.call(move |e| e.run_to(addr))
        }

        /// `count` stack slots starting at the thread's stack pointer.
        pub fn read_stack(&self, tid: Tid, count: usize) -> Result<Vec<u64>> {
            let rsp = self.context(tid)?.rsp;
            let mut buf = vec![0u8; count * 8];
            let n = self.process.read(rsp, &mut buf)?;
            Ok(buf[..n - n % 8]
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect())
        }

        /// The instruction pointer followed by return addresses from a naive frame-pointer
        /// walk (`[rbp+8]`, `rbp = [rbp]`). Code built without frame pointers gives a short or
        /// wrong chain.
        pub fn backtrace(&self, tid: Tid, max: usize) -> Result<Vec<Addr>> {
            let ctx = self.context(tid)?;
            let mut out = vec![ctx.rip];
            let mut bp = ctx.rbp;
            while out.len() < max && bp != 0 && bp % 8 == 0 {
                let Ok(ret) = self.process.read_ptr(bp + 8) else {
                    break;
                };
                let Ok(next) = self.process.read_ptr(bp) else {
                    break;
                };
                if ret == 0 {
                    break;
                }
                out.push(ret);
                if next <= bp {
                    break;
                }
                bp = next;
            }
            Ok(out)
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
        s.lock().insert(0x1004, 0x90);
        let mut b = [0u8; 8];
        s.read(&p, 0x1000, &mut b).unwrap();
        assert_eq!(b, [0x90; 8]);
        // A write over the breakpoint updates the saved byte and keeps the int3.
        s.write(&p, 0x1003, &[1, 2, 3]).unwrap();
        assert_eq!(s.lock()[&0x1004], 2);
        p.read(0x1003, &mut b[..3]).unwrap();
        assert_eq!(b[..3], [1, 0xcc, 3]);
        s.read(&p, 0x1003, &mut b[..3]).unwrap();
        assert_eq!(b[..3], [1, 2, 3]);
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
    }
}
