//! Linux backend: every thread is PTRACE_SEIZEd (new threads via PTRACE_O_TRACECLONE) and
//! polled with waitpid(tid, WNOHANG | __WALL). waitpid(-1) is never used, so other children
//! of the host process are left alone. All calls happen on the debugger thread.
use std::collections::BTreeMap;
use std::io;
use std::mem::{offset_of, zeroed};

use hh_core::{Addr, Error, Pid, Process, Prot, Result};

use crate::engine::{Mode, Raw};
use crate::{Context, Fpu, SignalAction, Tid};

const OPTS: usize = (libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC) as usize;
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
}

pub(crate) struct Os {
    pid: Pid,
    th: BTreeMap<Tid, T>,
    /// Debug registers every thread should have.
    dr: ([u64; 4], u64),
    gadget: Option<Addr>,
    /// Round-robin start for poll, so a busy thread cannot starve the others.
    cursor: Tid,
}

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

fn words_to_bytes(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn bytes_to_words(b: &[u8], w: &mut [u32]) {
    for (d, c) in w.iter_mut().zip(b.chunks_exact(4)) {
        *d = u32::from_le_bytes(c.try_into().unwrap());
    }
}

impl Os {
    pub fn default_policy() -> Vec<(u32, SignalAction)> {
        [
            libc::SIGSEGV,
            libc::SIGILL,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGTRAP,
        ]
        .map(|s| (s as u32, SignalAction::Break))
        .into()
    }

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
        let raws = os.halt_all()?;
        Ok((os, raws))
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

    /// Restarts a thread after a stop nobody asked for, the way it was running before.
    fn restart(&mut self, tid: Tid) -> Result<()> {
        let Some(t) = self.th.get_mut(&tid) else {
            return Ok(());
        };
        let req = match (t.step, t.group) {
            (true, _) => libc::PTRACE_SINGLESTEP,
            (_, true) => libc::PTRACE_LISTEN,
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
            libc::PTRACE_EVENT_CLONE => {
                let mut new: libc::c_ulong = 0;
                pt(
                    libc::PTRACE_GETEVENTMSG,
                    tid,
                    0,
                    &mut new as *mut libc::c_ulong as usize,
                )
                .map_err(perr)?;
                self.th.entry(new as Tid).or_insert(T {
                    fresh: true,
                    ..T::default()
                });
                Ok(Some(Raw::ThreadCreated(new as Tid)))
            }
            libc::PTRACE_EVENT_EXEC => {
                // Every other thread is gone; the execing one now has the leader's tid.
                let pid = self.pid;
                self.th.retain(|&k, _| k == pid);
                Ok(Some(Raw::Exec))
            }
            libc::PTRACE_EVENT_STOP => {
                // Our interrupt, a new thread's first stop, or a group stop.
                let fresh = std::mem::take(&mut t.fresh);
                t.group = matches!(
                    sig,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                );
                if fresh {
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
                    libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE => {
                        Some(unsafe { self.siginfo(tid)?.si_addr() } as Addr)
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

    pub fn poll(&mut self) -> Result<Option<(Tid, Raw)>> {
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
    pub fn halt_all(&mut self) -> Result<Vec<(Tid, Raw)>> {
        let mut out = Vec::new();
        loop {
            let running: Vec<Tid> = self
                .th
                .iter()
                .filter(|(_, t)| !t.stopped)
                .map(|(&k, _)| k)
                .collect();
            if running.is_empty() {
                return Ok(out);
            }
            for &t in &running {
                let _ = pt(libc::PTRACE_INTERRUPT, t, 0, 0);
            }
            for t in running {
                while self.th.get(&t).is_some_and(|x| !x.stopped) {
                    match wait(t, 0) {
                        Ok(Some(st)) => {
                            if let Some(raw) = self.decode(t, st, true)? {
                                out.push((t, raw));
                            }
                        }
                        Ok(None) => {}
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
        }
    }

    pub fn resume(&mut self, mode: &dyn Fn(Tid) -> Mode) -> Result<()> {
        for (&tid, t) in self.th.iter_mut() {
            if !t.stopped {
                continue;
            }
            let m = mode(tid);
            if m == Mode::Stay {
                continue;
            }
            let sig = if t.pass { t.sig } else { 0 };
            let req = match m {
                Mode::Step => libc::PTRACE_SINGLESTEP,
                _ if t.group => libc::PTRACE_LISTEN,
                _ => libc::PTRACE_CONT,
            };
            match pt(req, tid, 0, sig as usize) {
                Err(e) if !is_esrch(&e) => return Err(perr(e)),
                _ => {}
            }
            *t = T {
                step: m == Mode::Step,
                ..T::default()
            };
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
        .map_err(perr)
        .map(|_| ())
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

    pub fn detach(&mut self) -> Result<()> {
        for (&tid, t) in &self.th {
            if t.stopped {
                let sig = if t.pass { t.sig } else { 0 };
                let _ = pt(libc::PTRACE_DETACH, tid, 0, sig as usize);
            }
        }
        self.th.clear();
        Ok(())
    }

    /// Runs syscall `nr` in a stopped thread (the main one if possible) by pointing it at a
    /// `syscall` instruction and single-stepping. The process must be halted.
    fn syscall(&mut self, mem: &dyn Process, nr: i64, args: [u64; 6]) -> Result<u64> {
        if mem.pointer_size() != 8 {
            return Err(Error::Unsupported("remote syscalls in 32-bit processes"));
        }
        let tid = match self.is_stopped(self.pid) {
            true => self.pid,
            false => {
                *self
                    .th
                    .iter()
                    .find(|(_, t)| t.stopped)
                    .ok_or(Error::ProcessGone)?
                    .0
            }
        };
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
            let st = match wait(tid, 0) {
                Ok(Some(st)) => st,
                Ok(None) => continue,
                Err(e) => break Err(Error::Io(e)),
            };
            if !libc::WIFSTOPPED(st) {
                self.th.remove(&tid);
                break Err(Error::ProcessGone);
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
        if let Some(t) = self.th.get_mut(&tid) {
            (t.sig, t.pass) = keep;
            self.set_regs(tid, &restore)?;
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
