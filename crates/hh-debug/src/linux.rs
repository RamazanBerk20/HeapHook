//! Linux backend: every thread is PTRACE_SEIZEd (new threads via PTRACE_O_TRACECLONE) and
//! polled with waitpid(tid, WNOHANG | __WALL). waitpid(-1) is never used, so other children
//! of the host process are left alone. All calls happen on the debugger thread.
//!
//! Forks are followed just far enough to keep children alive: a child with its own memory
//! gets our int3 bytes and page protections removed and is detached at once; a child that
//! shares our memory (vfork, `CLONE_VM`) stays traced as a "guest" until it execs or exits.
//! PTRACE_O_TRACEEXIT tells us when a thread (notably the main one) is on its way out, so a
//! zombie leader is never waited for.
use std::collections::BTreeMap;
use std::io;
use std::mem::{offset_of, zeroed};

use hh_core::{Addr, Error, Pid, Process, Prot, Result};

use crate::engine::{Mode, Raw};
use crate::{Context, Fpu, SignalAction, Tid};

const OPTS: usize = (libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACEVFORKDONE
    | libc::PTRACE_O_TRACEEXIT) as usize;
const PAGE: u64 = 4096;
const DR_OFF: usize = offset_of!(libc::user, u_debugreg);

#[derive(Default)]
struct T {
    stopped: bool,
    /// Auto-attached clone that has not reported its initial stop yet.
    fresh: bool,
    /// Stopped in a job-control group stop: resume with PTRACE_LISTEN to keep it stopped.
    group: bool,
    /// Signal of the current signal-delivery-stop, and whether to deliver it on resume.
    sig: i32,
    pass: bool,
    /// The last resume was a single-step.
    step: bool,
    /// A child process sharing our memory (not one of our threads).
    guest: bool,
    /// Past PTRACE_EVENT_EXIT: it only gets to finish dying (a leader stays a zombie).
    exiting: bool,
    /// Blocked in vfork until the child execs or exits: cannot be stopped, runs no user code.
    vforking: bool,
    /// Stopped by our PTRACE_INTERRUPT (a SIGTRAP may still be queued behind that stop).
    interrupted: bool,
}

/// The thread has a SIGTRAP queued (e.g. it executed an int3 just before our interrupt).
fn trap_pending(pid: Pid, tid: Tid) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status"))
        .ok()
        .and_then(|s| {
            let l = s.lines().find(|l| l.starts_with("SigPnd:"))?;
            u64::from_str_radix(l[7..].trim(), 16).ok()
        })
        .is_some_and(|m| m & (1 << (libc::SIGTRAP - 1)) != 0)
}

pub(crate) struct Os {
    pid: Pid,
    th: BTreeMap<Tid, T>,
    /// Debug registers every thread should have.
    dr: ([u64; 4], u64),
    gadget: Option<Addr>,
    /// Round-robin start for poll, so a busy thread cannot starve the others.
    cursor: Tid,
    /// Events a timed-out halt collected, delivered by `poll`.
    backlog: Vec<(Tid, Raw)>,
    /// Stops recovered after someone else's waitpid took them (see `stolen`), for the
    /// engine's history.
    notes: Vec<String>,
}

/// waitpid status of a ptrace stop rebuilt from its siginfo: event stops carry
/// `SIGTRAP | event << 8` (or the stop signal for group stops) in `si_code`.
fn status_of(si: &libc::siginfo_t) -> i32 {
    let (sig, code) = (si.si_signo, si.si_code);
    let ev = if code > 0 && code >> 8 != 0 && code & 0xff == sig {
        code >> 8
    } else {
        0
    };
    0x7f | (sig << 8) | (ev << 16)
}

const HALT_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

fn pt(req: libc::c_uint, tid: Tid, addr: usize, data: usize) -> io::Result<i64> {
    // PEEK requests return data, so -1 is only an error when errno says so.
    unsafe { *libc::__errno_location() = 0 };
    let r = unsafe { libc::ptrace(req, tid as libc::pid_t, addr, data) };
    if r == -1 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(0) {
            return Err(e);
        }
    }
    Ok(r)
}

fn perr(e: io::Error) -> Error {
    match e.raw_os_error() {
        Some(libc::ESRCH) => Error::ProcessGone,
        Some(libc::EPERM | libc::EACCES) => Error::Permission(format!(
            "ptrace: {e}. With kernel.yama.ptrace_scope=1 only descendants can be debugged; set \
             it to 0 (`sysctl kernel.yama.ptrace_scope=0`) or give HeapHook CAP_SYS_PTRACE"
        )),
        _ => Error::Io(e),
    }
}

fn is_esrch(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ESRCH)
}

/// waitpid on one thread; Ok(None) when WNOHANG found nothing.
fn wait(tid: Tid, flags: i32) -> io::Result<Option<i32>> {
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(tid as i32, &mut st, flags | libc::__WALL) };
        if r > 0 {
            return Ok(Some(st));
        }
        if r == 0 {
            return Ok(None);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// XSTATE_BV of an XSAVE image (header at 512).
fn xstate_bv(buf: &[u8]) -> u64 {
    buf.get(512..520)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn words_to_bytes(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn bytes_to_words(b: &[u8], w: &mut [u32]) {
    for (d, c) in w.iter_mut().zip(b.chunks_exact(4)) {
        *d = u32::from_le_bytes(c.try_into().unwrap());
    }
}

use SignalAction::{Break, Pass};

/// Standard signals and the default action of a new session (crash signals break).
pub(crate) const SIGNALS: &[(u32, &str, SignalAction)] = &[
    (1, "SIGHUP", Pass),
    (2, "SIGINT", Pass),
    (3, "SIGQUIT", Pass),
    (4, "SIGILL", Break),
    (5, "SIGTRAP", Break),
    (6, "SIGABRT", Pass),
    (7, "SIGBUS", Break),
    (8, "SIGFPE", Break),
    (10, "SIGUSR1", Pass),
    (11, "SIGSEGV", Break),
    (12, "SIGUSR2", Pass),
    (13, "SIGPIPE", Pass),
    (14, "SIGALRM", Pass),
    (15, "SIGTERM", Pass),
    (16, "SIGSTKFLT", Pass),
    (17, "SIGCHLD", Pass),
    (18, "SIGCONT", Pass),
    (19, "SIGSTOP", Pass),
    (20, "SIGTSTP", Pass),
    (21, "SIGTTIN", Pass),
    (22, "SIGTTOU", Pass),
    (23, "SIGURG", Pass),
    (24, "SIGXCPU", Pass),
    (25, "SIGXFSZ", Pass),
    (26, "SIGVTALRM", Pass),
    (27, "SIGPROF", Pass),
    (28, "SIGWINCH", Pass),
    (29, "SIGIO", Pass),
    (30, "SIGPWR", Pass),
    (31, "SIGSYS", Pass),
];

impl Os {
    /// The signal a fault on a protected page raises.
    pub const PAGE_FAULT: u32 = libc::SIGSEGV as u32;
    pub const PAGE_WATCH: bool = true;

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn tids(&self) -> Vec<Tid> {
        self.th.keys().copied().collect()
    }

    /// Seizes every thread and returns with all of them stopped.
    pub fn attach(pid: Pid, _mem: &dyn Process) -> Result<(Os, Vec<(Tid, Raw)>)> {
        let mut os = Os {
            pid,
            th: BTreeMap::new(),
            dr: ([0; 4], 0),
            gadget: None,
            cursor: 0,
            backlog: Vec::new(),
            notes: Vec::new(),
        };
        // Threads may appear while we seize; clones of seized threads are traced automatically,
        // the rest show up on the next listing.
        loop {
            let tids: Vec<Tid> = std::fs::read_dir(format!("/proc/{pid}/task"))
                .map_err(|_| Error::ProcessGone)?
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect();
            let mut new = false;
            for t in tids {
                if os.th.contains_key(&t) {
                    continue;
                }
                match pt(libc::PTRACE_SEIZE, t, 0, OPTS) {
                    Ok(_) => {
                        os.th.insert(t, T::default());
                        new = true;
                    }
                    Err(e) if is_esrch(&e) => {}
                    // Permission is per process: once one thread was seized, EPERM means this
                    // one is exiting (the kernel refuses tasks with an exit state).
                    Err(e) if e.raw_os_error() == Some(libc::EPERM) && !os.th.is_empty() => {}
                    Err(e) => {
                        let _ = os.halt_all();
                        let _ = os.detach();
                        return Err(perr(e));
                    }
                }
            }
            if !new {
                break;
            }
        }
        if os.th.is_empty() {
            return Err(Error::ProcessGone);
        }
        match os.halt_all() {
            Ok(raws) => Ok((os, raws)),
            Err(e) => {
                let _ = os.detach();
                Err(e)
            }
        }
    }

    /// Starts `o.program` as a traced child, stopped at its exec (before the loader's first
    /// instruction). The child waits on a pipe until it is seized, so nothing runs untraced
    /// after the fork but async-signal-safe setup; a failure anywhere leaves no child
    /// behind (it is killed and reaped).
    pub fn launch(o: &crate::LaunchOptions) -> Result<Os> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = find_program(&o.program)?;
        let cstr = |b: &[u8]| {
            CString::new(b).map_err(|_| Error::Other("launch: argument contains a NUL byte".into()))
        };
        let cpath = cstr(path.as_os_str().as_bytes())?;
        let mut args = vec![cstr(o.program.as_bytes())?];
        for a in &o.args {
            args.push(cstr(a.as_bytes())?);
        }
        let env: Vec<CString> = match &o.env {
            Some(v) => v
                .iter()
                .map(|(k, v)| cstr(format!("{k}={v}").as_bytes()))
                .collect::<Result<_>>()?,
            None => std::env::vars_os()
                .filter_map(|(k, v)| {
                    let mut b = k.as_bytes().to_vec();
                    b.push(b'=');
                    b.extend_from_slice(v.as_bytes());
                    CString::new(b).ok()
                })
                .collect(),
        };
        let cwd = o.cwd.as_deref().map(|c| cstr(c.as_bytes())).transpose()?;
        let argv: Vec<*const libc::c_char> = args
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = env
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let fds = [o.stdin, o.stdout, o.stderr];
        let (mut go, mut err) = ([0i32; 2], [0i32; 2]);
        unsafe {
            if libc::pipe2(go.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                return Err(Error::Io(io::Error::last_os_error()));
            }
            if libc::pipe2(err.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                let e = io::Error::last_os_error();
                libc::close(go[0]);
                libc::close(go[1]);
                return Err(Error::Io(e));
            }
        }
        let cwd_p = cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { launch_child(go[0], err[1], fds, cwd_p, cpath.as_ptr(), &argv, &envp) }
        }
        unsafe {
            libc::close(go[0]);
            libc::close(err[1]);
        }
        let close = |fd: i32| unsafe {
            libc::close(fd);
        };
        if pid < 0 {
            let e = io::Error::last_os_error();
            close(go[1]);
            close(err[0]);
            return Err(Error::Io(e));
        }
        let pid = pid as Pid;
        if let Err(e) = pt(libc::PTRACE_SEIZE, pid, 0, OPTS) {
            close(go[1]);
            close(err[0]);
            kill_reap(pid);
            return Err(perr(e));
        }
        let one = 1u8;
        let wrote = unsafe { libc::write(go[1], (&one as *const u8).cast(), 1) };
        close(go[1]);
        let r = match wrote {
            1 => wait_exec(pid),
            _ => Err(Error::Io(io::Error::last_os_error())),
        };
        let mut code = [0u8; 4];
        let n = unsafe { libc::read(err[0], code.as_mut_ptr().cast(), 4) };
        close(err[0]);
        match r {
            Ok(true) => {}
            Ok(false) => {
                // Exited (and reaped) before exec: the child reported why.
                let e = match n {
                    4 => io::Error::from_raw_os_error(i32::from_ne_bytes(code)),
                    _ => io::Error::other("the child exited before exec"),
                };
                return Err(Error::Io(io::Error::new(
                    e.kind(),
                    format!("cannot run {}: {e}", path.display()),
                )));
            }
            Err(e) => {
                kill_reap(pid);
                return Err(e);
            }
        }
        let mut th = BTreeMap::new();
        th.insert(
            pid,
            T {
                stopped: true,
                ..T::default()
            },
        );
        Ok(Os {
            pid,
            th,
            dr: ([0; 4], 0),
            gadget: None,
            cursor: 0,
            backlog: Vec::new(),
            notes: Vec::new(),
        })
    }

    /// Kills the (launched) process and reaps it.
    pub fn kill(&mut self) {
        kill_reap(self.pid);
        self.th.clear();
    }

    /// Name, kernel state letter, user and system CPU milliseconds of a thread.
    pub fn thread_info(&self, tid: Tid) -> (String, String, u64, u64) {
        let dir = format!("/proc/{}/task/{tid}", self.pid);
        let name = std::fs::read_to_string(format!("{dir}/comm"))
            .map(|s| s.trim_end_matches('\n').to_string())
            .unwrap_or_default();
        let stat = std::fs::read_to_string(format!("{dir}/stat")).unwrap_or_default();
        // Fields after the `(comm)`: state is the first, utime / stime the 12th / 13th.
        let rest: Vec<&str> = stat
            .rfind(')')
            .map(|i| stat[i + 1..].split_whitespace().collect())
            .unwrap_or_default();
        let tick = match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
            t if t > 0 => t as u64,
            _ => 100,
        };
        let ms = |i: usize| {
            rest.get(i)
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(0, |t| t.saturating_mul(1000) / tick)
        };
        let state = rest.first().map(|s| s.to_string()).unwrap_or_default();
        (name, state, ms(11), ms(12))
    }

    /// Address of the dynamic loader's r_brk (called on every dlopen/dlclose), from the
    /// main executable's DT_DEBUG. None for static or 32-bit executables.
    pub fn loader_hook(&self, mem: &dyn Process) -> Option<Addr> {
        let auxv = std::fs::read(format!("/proc/{}/auxv", self.pid)).ok()?;
        let (mut phdr, mut phnum) = (0u64, 0u64);
        for c in auxv.chunks_exact(16) {
            let v = u64::from_le_bytes(c[8..].try_into().ok()?);
            match u64::from_le_bytes(c[..8].try_into().ok()?) {
                3 => phdr = v,  // AT_PHDR
                5 => phnum = v, // AT_PHNUM
                _ => {}
            }
        }
        if phdr == 0 || mem.pointer_size() != 8 {
            return None;
        }
        let (mut bias, mut dynamic) = (0u64, None);
        for i in 0..phnum.min(64) {
            let mut h = [0u8; 56];
            mem.read_exact(phdr + i * 56, &mut h).ok()?;
            let vaddr = u64::from_le_bytes(h[16..24].try_into().ok()?);
            match u32::from_le_bytes(h[..4].try_into().ok()?) {
                6 => bias = phdr.wrapping_sub(vaddr), // PT_PHDR
                2 => dynamic = Some(vaddr),           // PT_DYNAMIC
                _ => {}
            }
        }
        let dynamic = bias.wrapping_add(dynamic?);
        for i in 0..1024 {
            let tag = mem.read_ptr(dynamic + i * 16).ok()?;
            if tag == 0 {
                break;
            }
            if tag == 21 {
                // DT_DEBUG -> struct r_debug { int r_version; link_map *r_map; ElfW(Addr) r_brk; }
                let r_debug = mem.read_ptr(dynamic + i * 16 + 8).ok()?;
                let brk = mem.read_ptr(r_debug.checked_add(16)?).ok()?;
                return (r_debug != 0 && brk != 0).then_some(brk);
            }
        }
        None
    }

    pub fn is_stopped(&self, tid: Tid) -> bool {
        self.th.get(&tid).is_some_and(|t| t.stopped)
    }

    /// Running user code (not stopped, not on its way out).
    pub fn is_running(&self, tid: Tid) -> bool {
        self.th
            .get(&tid)
            .is_some_and(|t| !t.stopped && !t.exiting && !t.vforking)
    }

    /// AT_ENTRY of the current image (after an exec the loader hook is found from there).
    pub fn exec_entry(&self) -> Option<Addr> {
        let auxv = std::fs::read(format!("/proc/{}/auxv", self.pid)).ok()?;
        auxv.chunks_exact(16).find_map(|c| {
            let (k, v) = c.split_at(8);
            (k == 9u64.to_le_bytes()).then(|| u64::from_le_bytes(v.try_into().unwrap())) // AT_ENTRY
        })
    }

    /// Restarts a thread after a stop nobody asked for, the way it was running before.
    fn restart(&mut self, tid: Tid) -> Result<()> {
        let Some(t) = self.th.get_mut(&tid) else {
            return Ok(());
        };
        let req = match (t.exiting, t.step, t.group) {
            (true, ..) => libc::PTRACE_CONT,
            (_, true, _) => libc::PTRACE_SINGLESTEP,
            (_, _, true) => libc::PTRACE_LISTEN,
            _ => libc::PTRACE_CONT,
        };
        t.stopped = false;
        t.group = false;
        match pt(req, tid, 0, 0) {
            Err(e) if !is_esrch(&e) => Err(perr(e)),
            _ => Ok(()),
        }
    }

    fn siginfo(&self, tid: Tid) -> Result<libc::siginfo_t> {
        let mut si: libc::siginfo_t = unsafe { zeroed() };
        pt(
            libc::PTRACE_GETSIGINFO,
            tid,
            0,
            &mut si as *mut libc::siginfo_t as usize,
        )
        .map_err(perr)?;
        Ok(si)
    }

    /// Turns a wait status into an event. `halting`: the stop answers our PTRACE_INTERRUPT,
    /// so the thread stays stopped. Returns None for stops handled here.
    fn decode(&mut self, tid: Tid, st: i32, halting: bool) -> Result<Option<Raw>> {
        if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
            self.th.remove(&tid);
            if tid == self.pid {
                let code = libc::WIFEXITED(st).then(|| libc::WEXITSTATUS(st));
                return Ok(Some(Raw::ProcessExited { code }));
            }
            return Ok(Some(Raw::ThreadExited));
        }
        if !libc::WIFSTOPPED(st) {
            return Ok(None);
        }
        let Some(t) = self.th.get_mut(&tid) else {
            return Ok(None);
        };
        let (sig, ev) = (libc::WSTOPSIG(st), st >> 16);
        t.stopped = true;
        t.sig = 0;
        t.pass = false;
        match ev {
            libc::PTRACE_EVENT_CLONE | libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK => {
                let mut new: libc::c_ulong = 0;
                pt(
                    libc::PTRACE_GETEVENTMSG,
                    tid,
                    0,
                    &mut new as *mut libc::c_ulong as usize,
                )
                .map_err(perr)?;
                let new = new as Tid;
                let thread = ev == libc::PTRACE_EVENT_CLONE
                    && std::path::Path::new(&format!("/proc/{}/task/{new}", self.pid)).exists();
                if thread {
                    self.th.entry(new).or_insert(T {
                        fresh: true,
                        ..T::default()
                    });
                    return Ok(Some(Raw::ThreadCreated(new)));
                }
                // A new process. kcmp says whether it shares our memory; without kcmp, only a
                // plain fork is assumed not to.
                let r = unsafe {
                    libc::syscall(libc::SYS_kcmp, tid, new, 1 /* KCMP_VM */, 0, 0)
                };
                let shared = match r {
                    0 => true,
                    1..=3 => false,
                    _ => ev != libc::PTRACE_EVENT_FORK,
                };
                // The parent of any CLONE_VFORK, shared memory or not, waits (unstoppable)
                // until the child execs or exits: halting must not wait for it.
                if ev == libc::PTRACE_EVENT_VFORK {
                    t.vforking = true;
                }
                if shared {
                    self.th.insert(
                        new,
                        T {
                            fresh: true,
                            guest: true,
                            ..T::default()
                        },
                    );
                    return Ok(Some(Raw::GuestCreated(new)));
                }
                // Wait for its first stop so it can be cleaned up and detached.
                Ok(match self.wait_stop(new) {
                    Ok(st) if libc::WIFSTOPPED(st) => Some(Raw::Forked(new)),
                    _ => None, // already gone (or never stops: left alone)
                })
            }
            libc::PTRACE_EVENT_EXEC if t.guest => {
                // A guest got its own image: nothing of ours left in it.
                let _ = pt(libc::PTRACE_DETACH, tid, 0, 0);
                self.th.remove(&tid);
                Ok(Some(Raw::ThreadExited))
            }
            libc::PTRACE_EVENT_EXEC => {
                // Every other thread is gone; the execing one now has the leader's tid.
                let pid = self.pid;
                for (&k, _) in self.th.iter().filter(|(k, _)| **k != pid) {
                    let _ = wait(k, libc::WNOHANG); // reap if already reportable
                }
                self.th.retain(|&k, t| k == pid || t.guest);
                self.th.insert(
                    pid,
                    T {
                        stopped: true,
                        ..T::default()
                    },
                );
                self.gadget = None;
                self.dr = ([0; 4], 0);
                Ok(Some(Raw::Exec))
            }
            libc::PTRACE_EVENT_VFORK_DONE => {
                t.vforking = false;
                if !halting {
                    self.restart(tid)?;
                }
                Ok(None)
            }
            libc::PTRACE_EVENT_EXIT => {
                t.exiting = true;
                if !halting {
                    self.restart(tid)?;
                }
                // A leader's real exit is only reported once the whole group is gone.
                Ok((tid == self.pid).then_some(Raw::ThreadExited))
            }
            libc::PTRACE_EVENT_STOP => {
                // Our interrupt, a new thread's first stop, or a group stop.
                let fresh = std::mem::take(&mut t.fresh);
                t.interrupted = halting;
                t.group = matches!(
                    sig,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                );
                if fresh && !t.guest {
                    let (a, d) = self.dr;
                    self.write_dr(tid, a, d)?;
                }
                if !halting {
                    self.restart(tid)?;
                }
                Ok(None)
            }
            _ => {
                t.sig = sig;
                if sig == libc::SIGTRAP {
                    let code = self.siginfo(tid)?.si_code;
                    // > 0: raised by the CPU (int3 = SI_KERNEL, debug exceptions = TRAP_*),
                    // not by kill/tgkill.
                    if code > 0 {
                        return Ok(Some(Raw::Trap {
                            code: sig as u32,
                            int3: code == libc::SI_KERNEL || code == 1,
                        }));
                    }
                }
                if let Some(t) = self.th.get_mut(&tid) {
                    t.pass = true;
                }
                let addr = match sig {
                    // Only a fault the kernel raised (si_code > 0) has a fault address; for
                    // kill/tgkill/sigqueue the field holds the sender's pid/uid or user data.
                    libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE => {
                        let si = self.siginfo(tid)?;
                        (si.si_code > 0).then(|| unsafe { si.si_addr() } as Addr)
                    }
                    _ => None,
                };
                Ok(Some(Raw::Signal {
                    code: sig as u32,
                    addr,
                    first_chance: true,
                }))
            }
        }
    }

    /// Like `wait(tid, WNOHANG)`, but also finds a stop whose status someone else's waitpid
    /// took: the host waiting on its child (`waitpid(pid)`, e.g. `Child::try_wait`) is handed
    /// the main thread's ptrace stops, since the tracer and the parent are one process. Such a
    /// thread sits in a ptrace stop (PTRACE_GETSIGINFO only works then) with nothing to wait
    /// for; its status is rebuilt from the siginfo.
    fn wait_or_stolen(&mut self, tid: Tid) -> io::Result<Option<i32>> {
        if let Some(st) = wait(tid, libc::WNOHANG)? {
            return Ok(Some(st));
        }
        let Ok(si) = self.siginfo(tid) else {
            return Ok(None);
        };
        // It is stopped; a status reported meanwhile is pending now.
        if let Some(st) = wait(tid, libc::WNOHANG)? {
            return Ok(Some(st));
        }
        let st = status_of(&si);
        self.notes.push(format!(
            "recovered a stop of {tid} taken by another waitpid: {st:#x}"
        ));
        Ok(Some(st))
    }

    /// Recoveries since the last call.
    pub fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    /// Last resort: every thread we believe running that actually sits in a ptrace stop
    /// whose status is gone (see `wait_or_stolen`) gets its stop handled now.
    pub fn watchdog(&mut self) -> Result<Vec<(Tid, Raw)>> {
        let tids: Vec<Tid> = self
            .th
            .iter()
            .filter(|(_, t)| !t.stopped && !t.exiting && !t.vforking)
            .map(|(&k, _)| k)
            .collect();
        let mut out = Vec::new();
        for tid in tids {
            // Cheap for running threads: GETSIGINFO fails at once.
            if self.siginfo(tid).is_err() {
                continue;
            }
            if let Ok(Some(st)) = self.wait_or_stolen(tid)
                && let Some(raw) = self.decode(tid, st, false)?
            {
                out.push((tid, raw));
            }
        }
        Ok(out)
    }

    /// Waits up to `HALT_WAIT` for the next stop of `tid` (stolen ones included).
    fn wait_stop(&mut self, tid: Tid) -> Result<i32> {
        let deadline = std::time::Instant::now() + HALT_WAIT;
        let mut spins = 0u32;
        loop {
            let r = if spins < 100 {
                wait(tid, libc::WNOHANG)
            } else {
                self.wait_or_stolen(tid)
            };
            match r {
                Ok(Some(st)) => return Ok(st),
                Ok(None) if std::time::Instant::now() > deadline => {
                    return Err(Error::Other(format!("thread {tid} does not stop")));
                }
                Ok(None) => {
                    spins += 1;
                    if spins < 2000 {
                        std::thread::yield_now();
                    } else {
                        std::thread::sleep(std::time::Duration::from_micros(50));
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ECHILD) => return Err(Error::ProcessGone),
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }

    pub fn poll(&mut self) -> Result<Option<(Tid, Raw)>> {
        if !self.backlog.is_empty() {
            return Ok(Some(self.backlog.remove(0)));
        }
        let c = self.cursor;
        let tids: Vec<Tid> = self
            .th
            .range(c + 1..)
            .chain(self.th.range(..=c))
            .map(|(&k, _)| k)
            .collect();
        for tid in tids {
            let st = match wait(tid, libc::WNOHANG) {
                Ok(Some(st)) => st,
                Ok(None) => continue,
                Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                    self.th.remove(&tid);
                    if tid == self.pid {
                        return Ok(Some((tid, Raw::ProcessExited { code: None })));
                    }
                    continue;
                }
                Err(e) => return Err(Error::Io(e)),
            };
            if let Some(raw) = self.decode(tid, st, false)? {
                self.cursor = tid;
                return Ok(Some((tid, raw)));
            }
        }
        Ok(None)
    }

    /// Stops every thread. Events that arrive instead of the requested stop are returned.
    /// On failure the events collected so far go to the backlog (`take_backlog`, `poll`):
    /// an int3 hit among them still needs its rewind, a forked child its release.
    pub fn halt_all(&mut self) -> Result<Vec<(Tid, Raw)>> {
        let mut out = Vec::new();
        match self.halt_into(&mut out) {
            Ok(()) => Ok(out),
            Err(e) => {
                self.backlog.extend(out);
                Err(e)
            }
        }
    }

    /// Events a failed `halt_all` collected, oldest first.
    pub fn take_backlog(&mut self) -> Vec<(Tid, Raw)> {
        std::mem::take(&mut self.backlog)
    }

    fn halt_into(&mut self, out: &mut Vec<(Tid, Raw)>) -> Result<()> {
        loop {
            let running: Vec<Tid> = self
                .th
                .iter()
                .filter(|(_, t)| !t.stopped && !t.exiting && !t.vforking)
                .map(|(&k, _)| k)
                .collect();
            if running.is_empty() {
                return self.take_queued_traps(out);
            }
            for &t in &running {
                let _ = pt(libc::PTRACE_INTERRUPT, t, 0, 0);
            }
            // Bounded: a thread that cannot stop (uninterruptible sleep) must not hang every
            // debugger call. The others are still collected (their stops are pending by then),
            // so none is left in an unseen stop, e.g. after an int3 at A+1.
            let deadline = std::time::Instant::now() + HALT_WAIT;
            let mut spins = 0;
            let mut stuck = None;
            for t in running {
                while self
                    .th
                    .get(&t)
                    .is_some_and(|x| !x.stopped && !x.exiting && !x.vforking)
                {
                    // After a while, look for a stop someone else's waitpid took.
                    let r = match spins < 200 {
                        true => wait(t, libc::WNOHANG),
                        false => self.wait_or_stolen(t),
                    };
                    match r {
                        Ok(Some(st)) => {
                            if let Some(raw) = self.decode(t, st, true)? {
                                out.push((t, raw));
                            }
                        }
                        Ok(None) if std::time::Instant::now() > deadline => {
                            stuck.get_or_insert(t);
                            break;
                        }
                        Ok(None) if spins < 2000 => {
                            spins += 1;
                            std::thread::yield_now();
                        }
                        Ok(None) => std::thread::sleep(std::time::Duration::from_micros(50)),
                        Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                            self.th.remove(&t);
                            if t == self.pid {
                                out.push((t, Raw::ProcessExited { code: None }));
                            }
                        }
                        Err(e) => return Err(Error::Io(e)),
                    }
                }
            }
            if let Some(t) = stuck {
                // The threads that did stop may hold a queued int3 trap too.
                let _ = self.take_queued_traps(out);
                return Err(Error::Other(format!("thread {t} does not stop")));
            }
        }
    }

    /// The kernel reports our interrupt before a signal already queued, so a thread that
    /// executed an int3 can sit in the interrupt stop at A+1 with its SIGTRAP pending
    /// (detaching would then kill the target with it). Let each such thread take the
    /// signal now (it stops again right away) so the engine sees the trap and rewinds.
    fn take_queued_traps(&mut self, out: &mut Vec<(Tid, Raw)>) -> Result<()> {
        let tids: Vec<Tid> = self
            .th
            .iter()
            .filter(|(_, t)| t.stopped && t.interrupted && !t.exiting && !t.group)
            .map(|(&k, _)| k)
            .collect();
        for tid in tids {
            if let Some(t) = self.th.get_mut(&tid) {
                t.interrupted = false;
            }
            if !trap_pending(self.pid, tid) || pt(libc::PTRACE_CONT, tid, 0, 0).is_err() {
                continue;
            }
            if let Some(t) = self.th.get_mut(&tid) {
                t.stopped = false;
            }
            let deadline = std::time::Instant::now() + HALT_WAIT;
            let mut spins = 0u32;
            while self.th.get(&tid).is_some_and(|t| !t.stopped && !t.exiting) {
                spins += 1;
                let r = match spins < 200 {
                    true => wait(tid, libc::WNOHANG),
                    false => self.wait_or_stolen(tid),
                };
                match r {
                    Ok(Some(st)) => {
                        if let Some(raw) = self.decode(tid, st, true)? {
                            out.push((tid, raw));
                        }
                    }
                    Ok(None) if std::time::Instant::now() > deadline => {
                        return Err(Error::Other(format!("thread {tid} does not stop")));
                    }
                    Ok(None) => std::thread::yield_now(),
                    Err(_) => {
                        self.th.remove(&tid);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn resume(&mut self, mode: &dyn Fn(Tid) -> Mode) -> Result<()> {
        for (&tid, t) in self.th.iter_mut() {
            if !t.stopped {
                continue;
            }
            let m = mode(tid);
            if m == Mode::Stay && !t.exiting {
                continue;
            }
            let sig = if t.pass { t.sig } else { 0 };
            // Job control wins: a group-stopped thread stays stopped (a step it was asked for
            // happens when SIGCONT wakes it, see `restart`).
            let req = match m {
                _ if t.exiting => libc::PTRACE_CONT,
                _ if t.group => libc::PTRACE_LISTEN,
                Mode::Step => libc::PTRACE_SINGLESTEP,
                _ => libc::PTRACE_CONT,
            };
            match pt(req, tid, 0, sig as usize) {
                Err(e) if !is_esrch(&e) => return Err(perr(e)),
                _ => {}
            }
            t.step = m == Mode::Step && !t.exiting;
            (t.stopped, t.fresh, t.group, t.sig, t.pass) = (false, false, false, 0, false);
            t.interrupted = false;
        }
        Ok(())
    }

    pub fn set_pass(&mut self, tid: Tid, pass: bool) {
        if let Some(t) = self.th.get_mut(&tid) {
            t.pass = pass && t.sig != 0;
        }
    }

    fn regs(&self, tid: Tid) -> Result<libc::user_regs_struct> {
        let mut r: libc::user_regs_struct = unsafe { zeroed() };
        pt(
            libc::PTRACE_GETREGS,
            tid,
            0,
            &mut r as *mut libc::user_regs_struct as usize,
        )
        .map_err(perr)?;
        Ok(r)
    }

    fn set_regs(&self, tid: Tid, r: &libc::user_regs_struct) -> Result<()> {
        pt(
            libc::PTRACE_SETREGS,
            tid,
            0,
            r as *const libc::user_regs_struct as usize,
        )
        .map_err(perr)
        .map(|_| ())
    }

    fn fpregs(&self, tid: Tid) -> Result<libc::user_fpregs_struct> {
        let mut f: libc::user_fpregs_struct = unsafe { zeroed() };
        pt(
            libc::PTRACE_GETFPREGS,
            tid,
            0,
            &mut f as *mut libc::user_fpregs_struct as usize,
        )
        .map_err(perr)?;
        Ok(f)
    }

    fn peek_dr(&self, tid: Tid, i: usize) -> Result<u64> {
        pt(libc::PTRACE_PEEKUSER, tid, DR_OFF + i * 8, 0)
            .map(|v| v as u64)
            .map_err(perr)
    }

    fn poke_dr(&self, tid: Tid, i: usize, v: u64) -> io::Result<()> {
        pt(libc::PTRACE_POKEUSER, tid, DR_OFF + i * 8, v as usize).map(|_| ())
    }

    pub fn pc_sp(&self, tid: Tid) -> Result<(Addr, u64)> {
        let r = self.regs(tid)?;
        Ok((r.rip, r.rsp))
    }

    pub fn set_pc(&mut self, tid: Tid, pc: Addr) -> Result<()> {
        let mut r = self.regs(tid)?;
        r.rip = pc;
        self.set_regs(tid, &r)
    }

    pub fn context(&self, tid: Tid) -> Result<Context> {
        let r = self.regs(tid)?;
        let f = self.fpregs(tid)?;
        let mut dr = [0u64; 8];
        for i in [0, 1, 2, 3, 6, 7] {
            dr[i] = self.peek_dr(tid, i)?;
        }
        let st_b = words_to_bytes(&f.st_space);
        let xmm_b = words_to_bytes(&f.xmm_space);
        let mut fpu = Fpu {
            fcw: f.cwd,
            fsw: f.swd,
            ftw: f.ftw,
            fop: f.fop,
            fip: f.rip,
            fdp: f.rdp,
            mxcsr: f.mxcsr,
            ..Fpu::default()
        };
        for i in 0..8 {
            fpu.st[i].copy_from_slice(&st_b[i * 16..i * 16 + 10]);
        }
        for i in 0..16 {
            fpu.xmm[i].copy_from_slice(&xmm_b[i * 16..i * 16 + 16]);
        }
        Ok(Context {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rbp: r.rbp,
            rsp: r.rsp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.eflags,
            cs: r.cs as u16,
            ds: r.ds as u16,
            es: r.es as u16,
            fs: r.fs as u16,
            gs: r.gs as u16,
            ss: r.ss as u16,
            fs_base: r.fs_base,
            gs_base: r.gs_base,
            dr,
            fpu,
        })
    }

    /// `context` plus the YMM upper halves (PTRACE_GETREGSET NT_X86_XSTATE) when the CPU
    /// and kernel have AVX.
    pub fn context_full(&self, tid: Tid) -> Result<Context> {
        let mut c = self.context(tid)?;
        if let Some((buf, off)) = self.xstate(tid) {
            c.fpu.has_ymm = true;
            // Component in its init state (XSTATE_BV bit 2 clear): all zero.
            if xstate_bv(&buf) & 4 != 0 {
                for (i, y) in c.fpu.ymm_hi.iter_mut().enumerate() {
                    y.copy_from_slice(&buf[off + 16 * i..off + 16 * i + 16]);
                }
            }
        }
        Ok(c)
    }

    /// The thread's XSAVE image and the offset of its YMM_Hi128 component, if it has AVX.
    fn xstate(&self, tid: Tid) -> Option<(Vec<u8>, usize)> {
        const NT_X86_XSTATE: usize = 0x202;
        // CPUID.(EAX=0DH, ECX=2): size and (standard format) offset of YMM_Hi128.
        #[allow(unused_unsafe)]
        let r = unsafe { std::arch::x86_64::__cpuid_count(0xd, 2) };
        let off = r.ebx as usize;
        if r.eax != 256 || off < 576 {
            return None;
        }
        let mut buf = vec![0u8; 16384];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        pt(
            libc::PTRACE_GETREGSET,
            tid,
            NT_X86_XSTATE,
            &mut iov as *mut libc::iovec as usize,
        )
        .ok()?;
        buf.truncate(iov.iov_len);
        // ptrace puts XCR0 in xstate_fx_sw[0] (offset 464): it must include AVX.
        let xfeatures = u64::from_le_bytes(buf.get(464..472)?.try_into().ok()?);
        (xfeatures & 4 != 0 && buf.len() >= off + 256).then_some((buf, off))
    }

    fn set_ymm(&self, tid: Tid, ymm: &[[u8; 16]; 16]) -> Result<()> {
        const NT_X86_XSTATE: usize = 0x202;
        let Some((mut buf, off)) = self.xstate(tid) else {
            return Err(Error::Unsupported("YMM registers (no AVX state)"));
        };
        let live = xstate_bv(&buf) & 4 != 0;
        let cur: Vec<u8> = match live {
            true => buf[off..off + 256].to_vec(),
            false => vec![0; 256],
        };
        let new = ymm.concat();
        if cur == new {
            return Ok(());
        }
        buf[off..off + 256].copy_from_slice(&new);
        let bv = xstate_bv(&buf) | 4;
        buf[512..520].copy_from_slice(&bv.to_le_bytes());
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        pt(
            libc::PTRACE_SETREGSET,
            tid,
            NT_X86_XSTATE,
            &mut iov as *mut libc::iovec as usize,
        )
        .map_err(perr)
        .map(|_| ())
    }

    pub fn set_context(&mut self, tid: Tid, c: &Context) -> Result<()> {
        let mut r = self.regs(tid)?;
        if c.rip != r.rip {
            // Don't let a pending syscall restart move the new rip back by 2.
            r.orig_rax = u64::MAX;
        }
        (r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp) =
            (c.rax, c.rbx, c.rcx, c.rdx, c.rsi, c.rdi, c.rbp, c.rsp);
        (r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15) =
            (c.r8, c.r9, c.r10, c.r11, c.r12, c.r13, c.r14, c.r15);
        (r.rip, r.eflags, r.fs_base, r.gs_base) = (c.rip, c.rflags, c.fs_base, c.gs_base);
        (r.cs, r.ds, r.es, r.fs, r.gs, r.ss) = (
            c.cs as u64,
            c.ds as u64,
            c.es as u64,
            c.fs as u64,
            c.gs as u64,
            c.ss as u64,
        );
        self.set_regs(tid, &r)?;
        let mut f = self.fpregs(tid)?;
        let p = &c.fpu;
        (f.cwd, f.swd, f.ftw, f.fop, f.rip, f.rdp, f.mxcsr) =
            (p.fcw, p.fsw, p.ftw, p.fop, p.fip, p.fdp, p.mxcsr);
        let mut st_b = words_to_bytes(&f.st_space);
        for i in 0..8 {
            st_b[i * 16..i * 16 + 10].copy_from_slice(&p.st[i]);
        }
        bytes_to_words(&st_b, &mut f.st_space);
        bytes_to_words(&p.xmm.concat(), &mut f.xmm_space);
        pt(
            libc::PTRACE_SETFPREGS,
            tid,
            0,
            &f as *const libc::user_fpregs_struct as usize,
        )
        .map_err(perr)?;
        // After SETFPREGS: the XSAVE image read back carries the new legacy area.
        if p.has_ymm {
            self.set_ymm(tid, &p.ymm_hi)?;
        }
        Ok(())
    }

    /// DR6 (low 4 bits: which slots fired), cleared afterwards.
    pub fn take_dr6(&mut self, tid: Tid) -> Result<u64> {
        let v = self.peek_dr(tid, 6)?;
        if v & 0xf != 0 {
            self.poke_dr(tid, 6, 0).map_err(perr)?;
        }
        Ok(v)
    }

    fn write_dr(&self, tid: Tid, addrs: [u64; 4], dr7: u64) -> Result<()> {
        let r = (|| {
            // Disable first: the kernel validates each address against the current DR7.
            self.poke_dr(tid, 7, 0)?;
            for (i, &a) in addrs.iter().enumerate() {
                if dr7 & (3 << (2 * i)) != 0 {
                    self.poke_dr(tid, i, a)?;
                }
            }
            if dr7 != 0 {
                self.poke_dr(tid, 7, dr7)?;
            }
            Ok(())
        })();
        match r {
            Err(e) if !is_esrch(&e) => Err(perr(e)),
            _ => Ok(()),
        }
    }

    /// Debug registers of one stopped thread, or (None) of every thread including future ones.
    pub fn set_dr(&mut self, tid: Option<Tid>, addrs: [u64; 4], dr7: u64) -> Result<()> {
        let targets: Vec<Tid> = match tid {
            Some(t) => vec![t],
            None => {
                self.dr = (addrs, dr7);
                self.th
                    .iter()
                    .filter(|(_, t)| t.stopped)
                    .map(|(&k, _)| k)
                    .collect()
            }
        };
        for t in targets {
            self.write_dr(t, addrs, dr7)?;
        }
        Ok(())
    }

    /// Detaches every task of the process, from /proc as well as our list (whatever our
    /// bookkeeping missed): a task still traced when the tracer thread exits would be
    /// released with its stop's signal (SIGTRAP: killed).
    pub fn detach(&mut self) -> Result<()> {
        let mut done = std::collections::BTreeSet::new();
        // A thread still traced while we go may clone; its child is traced by us too, so
        // list again until a pass finds nobody new.
        for _ in 0..16 {
            let mut tids: Vec<Tid> = self.th.keys().copied().collect();
            if let Ok(rd) = std::fs::read_dir(format!("/proc/{}/task", self.pid)) {
                tids.extend(
                    rd.flatten()
                        .filter_map(|e| e.file_name().to_str()?.parse::<Tid>().ok()),
                );
            }
            tids.retain(|t| !done.contains(t));
            tids.sort_unstable();
            tids.dedup();
            if tids.is_empty() {
                break;
            }
            for tid in tids {
                done.insert(tid);
                self.detach_one(tid);
            }
        }
        self.th.clear();
        Ok(())
    }

    fn detach_one(&mut self, tid: Tid) {
        let sig = self
            .th
            .get(&tid)
            .filter(|t| t.stopped && t.pass)
            .map_or(0, |t| t.sig);
        if pt(libc::PTRACE_DETACH, tid, 0, sig as usize).is_ok() {
            return;
        }
        // A vfork parent stops only when its child lets go, which may take any time. The
        // kernel untraces it cleanly when the tracer thread exits, which follows the detach.
        if self.th.get(&tid).is_some_and(|t| t.vforking) {
            return;
        }
        // Not in a ptrace stop: running, ours or not (ESRCH either way). If it is traced by
        // us, stop it, then detach.
        if pt(libc::PTRACE_INTERRUPT, tid, 0, 0).is_err() {
            return;
        }
        let pass = match self.wait_stop(tid) {
            Ok(st) if libc::WIFSTOPPED(st) && st >> 16 == 0 => {
                // A real signal arrived instead of our stop: deliver it, unless it is a trap.
                let s = libc::WSTOPSIG(st);
                if s == libc::SIGTRAP { 0 } else { s }
            }
            Ok(st) if libc::WIFSTOPPED(st) => 0,
            _ => return,
        };
        let _ = pt(libc::PTRACE_DETACH, tid, 0, pass as usize);
    }

    /// Runs syscall `nr` in a stopped thread (the main one if possible) by pointing it at a
    /// `syscall` instruction and single-stepping. The process must be halted.
    fn syscall(&mut self, mem: &dyn Process, nr: i64, args: [u64; 6]) -> Result<u64> {
        if mem.pointer_size() != 8 {
            return Err(Error::Unsupported("remote syscalls in 32-bit processes"));
        }
        let usable = |t: &T| t.stopped && !t.exiting;
        let tid = match self.th.get(&self.pid).is_some_and(usable) {
            true => self.pid,
            false => {
                *self
                    .th
                    .iter()
                    .filter(|(_, t)| usable(t))
                    .min_by_key(|(_, t)| t.guest)
                    .ok_or(Error::ProcessGone)?
                    .0
            }
        };
        self.syscall_on(tid, mem, nr, args)
    }

    /// Runs syscall `nr` in the stopped (traced) task `tid`.
    fn syscall_on(&mut self, tid: Tid, mem: &dyn Process, nr: i64, args: [u64; 6]) -> Result<u64> {
        let gadget = self.gadget(mem)?;
        let saved = self.regs(tid)?;
        // A thread stopped inside an interrupted syscall would have the kernel restart it on
        // the way out; our injected syscall consumes that, so redo the restart by hand.
        let mut restore = saved;
        if (saved.orig_rax as i64) >= 0 {
            match -(saved.rax as i64) {
                512..=514 => (restore.rax, restore.rip) = (saved.orig_rax, saved.rip - 2),
                516 => {
                    (restore.rax, restore.rip) = (libc::SYS_restart_syscall as u64, saved.rip - 2)
                }
                _ => {}
            }
        }
        restore.orig_rax = u64::MAX;
        let mut r = saved;
        (r.rip, r.rax, r.orig_rax) = (gadget, nr as u64, u64::MAX);
        (r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9) =
            (args[0], args[1], args[2], args[3], args[4], args[5]);
        self.set_regs(tid, &r)?;
        let (sig, pass) = self.th.get(&tid).map_or((0, false), |t| (t.sig, t.pass));
        let mut keep = (sig, pass);
        let res = loop {
            if let Err(e) = pt(libc::PTRACE_SINGLESTEP, tid, 0, 0) {
                break Err(perr(e));
            }
            // Never a blocking wait: a stop taken by another waitpid would hang us forever.
            let st = match self.wait_stop(tid) {
                Ok(st) => st,
                Err(e) => break Err(e),
            };
            if !libc::WIFSTOPPED(st) {
                self.th.remove(&tid);
                break Err(Error::ProcessGone);
            }
            if st >> 16 != 0 {
                continue; // an event stop (e.g. exit): step on
            }
            if st >> 16 == 0 && libc::WSTOPSIG(st) != libc::SIGTRAP {
                // shortcut: keeps only the last signal that arrives during the few-µs syscall.
                keep = (libc::WSTOPSIG(st), true);
            }
            match self.regs(tid) {
                Ok(now) if now.rip != gadget => break Ok(now.rax),
                Ok(_) => {}
                Err(e) => break Err(e),
            }
        };
        match self.th.get_mut(&tid) {
            Some(t) => {
                (t.sig, t.pass) = keep;
                self.set_regs(tid, &restore)?;
            }
            // A forked child we are about to detach.
            None if res.is_ok() => self.set_regs(tid, &restore)?,
            None => {}
        }
        let ret = res? as i64;
        if (-4095..0).contains(&ret) {
            return Err(Error::Io(io::Error::from_raw_os_error(-ret as i32)));
        }
        Ok(ret as u64)
    }

    /// Any `0f 05` pair in executable memory, the vDSO first.
    fn gadget(&mut self, mem: &dyn Process) -> Result<Addr> {
        let mut b = [0u8; 2];
        if let Some(a) = self.gadget
            && mem.read_exact(a, &mut b).is_ok()
            && b == [0x0f, 0x05]
        {
            return Ok(a);
        }
        let mut regions: Vec<_> = mem
            .regions()?
            .into_iter()
            .filter(|r| r.prot.r && r.prot.x)
            .collect();
        regions.sort_by_key(|r| r.path.as_deref() != Some("[vdso]"));
        let mut buf = Vec::new();
        for r in regions {
            // shortcut: only the first 4 MiB of each region; real code has a syscall early.
            buf.resize(r.size.min(4 << 20) as usize, 0);
            let Ok(n) = mem.read(r.start, &mut buf) else {
                continue;
            };
            if let Some(i) = buf[..n].windows(2).position(|w| w == [0x0f, 0x05]) {
                self.gadget = Some(r.start + i as u64);
                return Ok(r.start + i as u64);
            }
        }
        Err(Error::Other(
            "no syscall instruction found in target".into(),
        ))
    }

    pub fn alloc(
        &mut self,
        mem: &dyn Process,
        size: u64,
        prot: Prot,
        near: Option<Addr>,
    ) -> Result<Addr> {
        let size = size
            .checked_add(PAGE - 1)
            .ok_or(Error::Other("size too large".into()))?
            & !(PAGE - 1);
        if size == 0 {
            return Err(Error::Other("alloc size is 0".into()));
        }
        let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        let p = prot_bits(prot);
        let Some(near) = near else {
            return self.syscall(mem, libc::SYS_mmap, [0, size, p, flags, u64::MAX, 0]);
        };
        let mut used: Vec<(u64, u64)> = mem
            .regions()?
            .iter()
            .map(|r| (r.start, r.start + r.size))
            .collect();
        let fixed = flags | libc::MAP_FIXED_NOREPLACE as u64;
        for hint in near_candidates(&mut used, near, size).into_iter().take(16) {
            match self.syscall(mem, libc::SYS_mmap, [hint, size, p, fixed, u64::MAX, 0]) {
                Ok(a) if a == hint => return Ok(a),
                // Kernels before 4.17 treat MAP_FIXED_NOREPLACE as a plain hint.
                Ok(a) => {
                    self.syscall(mem, libc::SYS_munmap, [a, size, 0, 0, 0, 0])?;
                }
                Err(Error::Io(e))
                    if matches!(e.raw_os_error(), Some(libc::EEXIST | libc::ENOMEM)) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Error::Other(format!(
            "no free memory within 2 GiB of {near:#x}"
        )))
    }

    /// mprotect for page watches; the process must be halted.
    pub fn mprotect(&mut self, mem: &dyn Process, start: Addr, len: u64, prot: Prot) -> Result<()> {
        self.syscall(
            mem,
            libc::SYS_mprotect,
            [start, len, prot_bits(prot), 0, 0, 0],
        )
        .map(|_| ())
    }

    /// mprotect inside a stopped, traced forked child.
    pub fn mprotect_child(
        &mut self,
        child: Pid,
        mem: &dyn Process,
        start: Addr,
        len: u64,
        prot: Prot,
    ) -> Result<()> {
        let args = [start, len, prot_bits(prot), 0, 0, 0];
        self.syscall_on(child, mem, libc::SYS_mprotect, args)
            .map(|_| ())
    }

    /// Writes into a stopped, traced forked child (we may, as its tracer).
    pub fn write_child(&self, child: Pid, addr: Addr, data: &[u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{child}/mem"))?
            .write_all_at(data, addr)?;
        Ok(())
    }

    pub fn detach_child(&self, child: Pid) -> Result<()> {
        let _ = self.poke_dr(child, 7, 0);
        pt(libc::PTRACE_DETACH, child, 0, 0)
            .map_err(perr)
            .map(|_| ())
    }

    pub fn free(&mut self, mem: &dyn Process, addr: Addr, size: u64) -> Result<()> {
        self.syscall(mem, libc::SYS_munmap, [addr, size, 0, 0, 0, 0])
            .map(|_| ())
    }

    pub fn protect(
        &mut self,
        mem: &dyn Process,
        addr: Addr,
        size: u64,
        prot: Prot,
    ) -> Result<Prot> {
        let old = mem
            .regions()?
            .into_iter()
            .find(|r| r.start <= addr && addr < r.start + r.size)
            .ok_or(Error::NoAccess { addr })?
            .prot;
        let start = addr & !(PAGE - 1);
        let len = (addr + size).next_multiple_of(PAGE) - start;
        self.syscall(
            mem,
            libc::SYS_mprotect,
            [start, len, prot_bits(prot), 0, 0, 0],
        )?;
        Ok(old)
    }
}

/// `program` itself when it holds a `/`, else the first executable match in `PATH`.
fn find_program(program: &str) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let runnable = |p: &std::path::Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    let not_found = || {
        Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("program not found or not executable: {program}"),
        ))
    };
    if program.is_empty() {
        return Err(not_found());
    }
    if program.contains('/') {
        let p = std::path::PathBuf::from(program);
        return if runnable(&p) { Ok(p) } else { Err(not_found()) };
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    std::env::split_paths(&path)
        .map(|d| d.join(program))
        .find(|p| runnable(p))
        .ok_or_else(not_found)
}

/// The forked child of `Os::launch`: only async-signal-safe calls (the parent may have had
/// other threads holding locks). Waits for the go byte, then execs; on failure writes errno
/// to `err` and exits 127.
unsafe fn launch_child(
    go: i32,
    err: i32,
    fds: [Option<i32>; 3],
    cwd: *const libc::c_char,
    path: *const libc::c_char,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
) -> ! {
    unsafe {
        let fail = || -> ! {
            let e = *libc::__errno_location();
            let b = e.to_ne_bytes();
            libc::write(err, b.as_ptr().cast(), 4);
            libc::_exit(127)
        };
        for (i, fd) in fds.iter().enumerate() {
            let Some(fd) = *fd else { continue };
            let to = i as i32;
            let r = match fd == to {
                // dup2 onto itself keeps FD_CLOEXEC: clear it instead.
                true => libc::fcntl(fd, libc::F_SETFD, 0),
                false => libc::dup2(fd, to),
            };
            if r < 0 {
                fail();
            }
        }
        // The host's signal mask and ignored signals (Rust ignores SIGPIPE) are inherited
        // through exec; give the program the defaults.
        let mut set: libc::sigset_t = zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        if !cwd.is_null() && libc::chdir(cwd) != 0 {
            fail();
        }
        let mut b = 0u8;
        loop {
            let r = libc::read(go, (&mut b as *mut u8).cast(), 1);
            if r == 1 {
                break;
            }
            if r < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::_exit(127); // the parent gave up
        }
        libc::execve(path, argv.as_ptr(), envp.as_ptr());
        fail()
    }
}

/// Waits (bounded) for the seized child's exec stop: Ok(true) at the exec stop, Ok(false)
/// when it exited first (reaped). Other stops before the exec are passed on.
fn wait_exec(pid: Pid) -> Result<bool> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match wait(pid, libc::WNOHANG) {
            Ok(Some(st)) if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) => return Ok(false),
            Ok(Some(st)) if libc::WIFSTOPPED(st) && st >> 16 == libc::PTRACE_EVENT_EXEC => {
                return Ok(true);
            }
            Ok(Some(st)) if libc::WIFSTOPPED(st) => {
                // A signal (delivered as usual) or an event stop (e.g. its exit).
                let sig = if st >> 16 == 0 { libc::WSTOPSIG(st) } else { 0 };
                let _ = pt(libc::PTRACE_CONT, pid, 0, sig as usize);
            }
            Ok(_) if std::time::Instant::now() > deadline => {
                return Err(Error::Other("the launched program did not start".into()));
            }
            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

/// SIGKILLs a child of ours (traced or not) and reaps it, bounded.
fn kill_reap(pid: Pid) {
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let deadline = std::time::Instant::now() + HALT_WAIT;
    while std::time::Instant::now() < deadline {
        match wait(pid, libc::WNOHANG) {
            Ok(Some(st)) if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) => return,
            Ok(Some(_)) => {
                let _ = pt(libc::PTRACE_CONT, pid, 0, 0);
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
            Err(_) => return, // not ours to wait for (or already reaped)
        }
    }
}

fn prot_bits(p: Prot) -> u64 {
    let mut b = 0;
    if p.r {
        b |= libc::PROT_READ;
    }
    if p.w {
        b |= libc::PROT_WRITE;
    }
    if p.x {
        b |= libc::PROT_EXEC;
    }
    b as u64
}

/// Page-aligned addresses in the gaps between `used` ranges where `size` bytes fit within
/// ±2 GiB of `near`, closest first.
fn near_candidates(used: &mut [(u64, u64)], near: u64, size: u64) -> Vec<u64> {
    // Slightly under 2 GiB so a rel32 from anywhere in the block back to `near` still reaches.
    const RANGE: u64 = 0x7fff_0000;
    // vm.mmap_min_addr default .. end of 4-level-paging user space.
    const LOW: u64 = 0x10000;
    const HIGH: u64 = 0x7fff_ffff_f000;
    let lo = near.saturating_sub(RANGE).max(LOW);
    let hi = near.saturating_add(RANGE).min(HIGH);
    used.sort_unstable();
    let mut out = Vec::new();
    let mut prev = 0;
    for &(s, e) in used.iter().chain([(HIGH, HIGH)].iter()) {
        let gs = prev.max(lo).next_multiple_of(PAGE);
        let ge = s.min(hi);
        if ge >= gs.saturating_add(size) {
            let last = (ge - size) & !(PAGE - 1);
            let c = (near & !(PAGE - 1)).clamp(gs, last);
            out.push((c.abs_diff(near), c));
        }
        prev = prev.max(e);
    }
    out.sort_unstable();
    out.into_iter().map(|(_, c)| c).collect()
}

#[cfg(test)]
mod tests {
    use super::near_candidates;

    #[test]
    fn near_gaps() {
        let mut used = [(0x1000_2000, 0x1000_3000), (0x1000_0000, 0x1000_1000)];
        let c = near_candidates(&mut used, 0x1000_0800, 0x1000);
        assert_eq!(c[0], 0x1000_1000);
        assert!(
            c.iter()
                .all(|&a| a.abs_diff(0x1000_0800) < 0x8000_0000 && a % 0x1000 == 0)
        );
        assert!(near_candidates(&mut used, 0x1000_0800, 1 << 40).is_empty());
    }
}
