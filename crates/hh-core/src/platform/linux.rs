//! Linux backend: /proc for enumeration and maps, process_vm_readv/writev for memory
//! (with /proc/pid/mem as fallback, which can also write read-only pages), and ptrace
//! remote-syscall injection for mmap/munmap/mprotect inside the target.
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::near_candidates;
use crate::{
    Addr, Error, Memory, Module, Pid, Process, ProcessInfo, Prot, Region, RegionKind, Result,
};

const PAGE: u64 = 4096;

pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    let mut out = Vec::new();
    for e in fs::read_dir("/proc")?.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<Pid>().ok()) else {
            continue;
        };
        // A process may exit between read_dir and here; just skip it.
        let Ok(name) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        out.push(ProcessInfo {
            pid,
            name: name.trim_end().to_owned(),
            exe,
        });
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

/// State letter from a `stat` file.
fn stat_state(path: &str) -> Option<char> {
    let stat = fs::read_to_string(path).ok()?;
    // comm may contain spaces and parens; the state follows the last ')'.
    stat[stat.rfind(')')? + 1..].trim_start().chars().next()
}

/// Threads that have not exited, with their state letter; the main thread first.
fn live_tasks(pid: Pid) -> Vec<(i32, char)> {
    let Ok(dir) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    let mut v: Vec<(i32, char)> = dir
        .flatten()
        .filter_map(|e| {
            let tid: i32 = e.file_name().to_str()?.parse().ok()?;
            let s = stat_state(&format!("/proc/{pid}/task/{tid}/stat"))?;
            (!matches!(s, 'Z' | 'X')).then_some((tid, s))
        })
        .collect();
    v.sort_by_key(|&(tid, _)| (tid != pid as i32, tid));
    v
}

/// `/proc/<pid>`, or a live thread's directory once the main thread has exited
/// (`pthread_exit` in main): the leader's maps, mem and exe then read as empty.
fn proc_dir(pid: Pid) -> String {
    let base = format!("/proc/{pid}");
    if stat_state(&format!("{base}/stat")) != Some('Z') {
        return base;
    }
    match live_tasks(pid).first() {
        Some((tid, _)) => format!("{base}/task/{tid}"),
        None => base,
    }
}

pub fn open(pid: Pid) -> Result<Arc<dyn Process>> {
    let dir = proc_dir(pid);
    // Opening mem needs the same ptrace access as everything else, so it doubles as the
    // permission check. The fd keeps the address space, even if this thread exits later.
    let mem = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("{dir}/mem"))
        .map_err(|e| os_err(e, pid))?;
    // ELF class byte: 1 = 32-bit, 2 = 64-bit.
    let mut ident = [0u8; 5];
    let ptr_size =
        match File::open(format!("{dir}/exe")).and_then(|f| f.read_exact_at(&mut ident, 0)) {
            Ok(()) if ident[..4] == *b"\x7fELF" && ident[4] == 1 => 4,
            _ => 8,
        };
    Ok(Arc::new(LinuxProcess {
        pid,
        mem,
        ptr_size,
        ptrace: Mutex::new(None),
    }))
}

struct LinuxProcess {
    pid: Pid,
    mem: File,
    ptr_size: usize,
    /// Serializes ptrace sessions; caches the address of a `syscall` instruction.
    ptrace: Mutex<Option<Addr>>,
}

fn os_err(e: io::Error, pid: Pid) -> Error {
    match e.raw_os_error() {
        Some(libc::ESRCH | libc::ENOENT) => Error::ProcessGone,
        Some(libc::EPERM | libc::EACCES) => Error::Permission(format!(
            "cannot access process {pid} ({e}). With kernel.yama.ptrace_scope=1 only child \
             processes can be traced; set it to 0 (`sysctl kernel.yama.ptrace_scope=0`), or give \
             HeapHook CAP_SYS_PTRACE (`setcap cap_sys_ptrace=eip <binary>`) or run it as root"
        )),
        _ => Error::Io(e),
    }
}

impl LinuxProcess {
    fn mem_err(&self, e: io::Error, addr: Addr) -> Error {
        match e.raw_os_error() {
            Some(libc::EFAULT | libc::EIO | libc::ENOMEM | libc::EINVAL) => {
                self.gone_or(Error::NoAccess { addr })
            }
            _ => os_err(e, self.pid),
        }
    }

    fn gone_or(&self, e: Error) -> Error {
        if self.is_alive() {
            e
        } else {
            Error::ProcessGone
        }
    }

    fn state(&self) -> Option<char> {
        stat_state(&format!("/proc/{}/stat", self.pid))
    }

    fn signal(&self, sig: i32) -> Result<()> {
        if unsafe { libc::kill(self.pid as i32, sig) } != 0 {
            return Err(os_err(io::Error::last_os_error(), self.pid));
        }
        Ok(())
    }
}

impl Memory for LinuxProcess {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut _,
            iov_len: buf.len(),
        };
        // One iovec: the kernel returns the contiguous prefix it could copy.
        let n = unsafe { libc::process_vm_readv(self.pid as i32, &local, 1, &remote, 1, 0) };
        if n > 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        // ESRCH also when only the main thread has exited; /proc/pid/mem still works then.
        if e.raw_os_error() == Some(libc::ESRCH) && !self.is_alive() {
            return Err(Error::ProcessGone);
        }
        // /proc/pid/mem reads with FOLL_FORCE, so it also gets pages that are mapped without
        // PROT_READ, and works where process_vm_readv is unavailable.
        match self.mem.read_at(buf, addr) {
            Ok(0) => Err(self.gone_or(Error::NoAccess { addr })),
            Ok(n) => Ok(n),
            Err(e) => Err(self.mem_err(e, addr)),
        }
    }

    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let local = libc::iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut _,
            iov_len: data.len(),
        };
        let n = unsafe { libc::process_vm_writev(self.pid as i32, &local, 1, &remote, 1, 0) };
        let mut done = n.max(0) as usize;
        // The rest goes through /proc/pid/mem, which writes read-only pages (code) via COW.
        while done < data.len() {
            let at = addr
                .checked_add(done as u64)
                .ok_or(Error::NoAccess { addr: u64::MAX })?;
            match self.mem.write_at(&data[done..], at) {
                Ok(0) => return Err(self.gone_or(Error::NoAccess { addr: at })),
                Ok(n) => done += n,
                Err(e) => return Err(self.mem_err(e, at)),
            }
        }
        Ok(())
    }

    fn pointer_size(&self) -> usize {
        self.ptr_size
    }
}

impl Process for LinuxProcess {
    fn pid(&self) -> Pid {
        self.pid
    }

    fn is_alive(&self) -> bool {
        match self.state() {
            None | Some('X') => false,
            // A zombie main thread with other threads still running is a live process.
            Some('Z') => !live_tasks(self.pid).is_empty(),
            _ => true,
        }
    }

    fn regions(&self) -> Result<Vec<Region>> {
        let maps = fs::read_to_string(format!("{}/maps", proc_dir(self.pid)))
            .map_err(|e| os_err(e, self.pid))?;
        Ok(parse_maps(&maps))
    }

    fn modules(&self) -> Result<Vec<Module>> {
        let mut out: Vec<Module> = Vec::new();
        for r in self
            .regions()?
            .into_iter()
            .filter(|r| r.kind == RegionKind::Image)
        {
            let path = r.path.unwrap_or_default();
            let end = r.start + r.size;
            match out.iter_mut().find(|m| m.path == path) {
                Some(m) => {
                    let m_end = (m.base + m.size).max(end);
                    m.base = m.base.min(r.start);
                    m.size = m_end - m.base;
                }
                None => out.push(Module {
                    name: path.rsplit('/').next().unwrap_or(&path).to_owned(),
                    path,
                    base: r.start,
                    size: r.size,
                }),
            }
        }
        out.sort_by_key(|m| m.base);
        Ok(out)
    }

    fn threads(&self) -> Result<Vec<u32>> {
        let dir =
            fs::read_dir(format!("/proc/{}/task", self.pid)).map_err(|e| os_err(e, self.pid))?;
        let mut tids: Vec<u32> = dir
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .collect();
        tids.sort_unstable();
        Ok(tids)
    }

    fn suspend(&self) -> Result<()> {
        self.signal(libc::SIGSTOP)?;
        // SIGSTOP is asynchronous; wait until the kernel reports the stop.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let tasks = live_tasks(self.pid);
            if tasks.is_empty() {
                return Err(Error::ProcessGone);
            }
            if tasks.iter().all(|t| matches!(t.1, 'T' | 't')) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(Error::Other("process did not stop".into()));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn resume(&self) -> Result<()> {
        self.signal(libc::SIGCONT)
    }

    fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> Result<Addr> {
        let size = size
            .checked_add(PAGE - 1)
            .ok_or(Error::Other("size too large".into()))?
            & !(PAGE - 1);
        if size == 0 {
            return Err(Error::Other("alloc size is 0".into()));
        }
        let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        let Some(near) = near else {
            return self.syscall(
                libc::SYS_mmap,
                [0, size, prot_bits(prot), flags, u64::MAX, 0],
            );
        };
        let mut used: Vec<(u64, u64)> = self
            .regions()?
            .iter()
            .map(|r| (r.start, r.start + r.size))
            .collect();
        // 0x10000 is the default vm.mmap_min_addr; the top is the end of 4-level-paging user space.
        for hint in near_candidates(&mut used, near, size, PAGE, 0x10000, 0x7fff_ffff_f000)
            .into_iter()
            .take(16)
        {
            let flags = flags | libc::MAP_FIXED_NOREPLACE as u64;
            match self.syscall(
                libc::SYS_mmap,
                [hint, size, prot_bits(prot), flags, u64::MAX, 0],
            ) {
                Ok(a) if a == hint => return Ok(a),
                // Kernels before 4.17 treat MAP_FIXED_NOREPLACE as a plain hint.
                Ok(a) => self
                    .syscall(libc::SYS_munmap, [a, size, 0, 0, 0, 0])
                    .map(|_| ())?,
                // Raced with another mapping, or a stack guard gap: try the next gap.
                Err(Error::Io(e))
                    if matches!(e.raw_os_error(), Some(libc::EEXIST | libc::ENOMEM)) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Error::Other(format!(
            "no free memory within 2 GiB of {near:#x}"
        )))
    }

    fn free(&self, addr: Addr, size: u64) -> Result<()> {
        self.syscall(libc::SYS_munmap, [addr, size, 0, 0, 0, 0])
            .map(|_| ())
    }

    fn protect(&self, addr: Addr, size: u64, prot: Prot) -> Result<Prot> {
        let old = self
            .regions()?
            .into_iter()
            .find(|r| r.start <= addr && addr < r.start + r.size)
            .ok_or(Error::NoAccess { addr })?
            .prot;
        let start = addr & !(PAGE - 1);
        let len = addr
            .checked_add(size)
            .and_then(|end| end.checked_next_multiple_of(PAGE))
            .ok_or_else(|| {
                Error::Other(format!("protect range {addr:#x} + {size:#x} overflows"))
            })?
            - start;
        self.syscall(libc::SYS_mprotect, [start, len, prot_bits(prot), 0, 0, 0])?;
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

fn parse_maps(maps: &str) -> Vec<Region> {
    struct Line<'a> {
        start: u64,
        end: u64,
        perms: &'a str,
        inode: &'a str,
        path: &'a str,
    }
    let lines: Vec<Line> = maps
        .lines()
        .filter_map(|line| {
            // "start-end perms offset dev inode   path"; path may contain spaces.
            let mut rest = line;
            let mut f = [""; 5];
            for slot in &mut f {
                rest = rest.trim_start();
                let end = rest.find(' ').unwrap_or(rest.len());
                *slot = &rest[..end];
                rest = &rest[end..];
            }
            let (s, e) = f[0].split_once('-')?;
            Some(Line {
                start: u64::from_str_radix(s, 16).ok()?,
                end: u64::from_str_radix(e, 16).ok()?,
                perms: f[1],
                inode: f[4],
                path: rest.trim_start(),
            })
        })
        .collect();
    // A file with an executable mapping is a loaded image (exe or shared object); its data
    // and read-only segments belong to it too. Other file mappings are plain mmaps.
    let images: HashSet<&str> = lines
        .iter()
        .filter(|l| l.inode != "0" && l.perms.contains('x'))
        .map(|l| l.path)
        .collect();
    lines
        .iter()
        .map(|l| {
            let bytes = l.perms.as_bytes();
            let kind = if l.inode == "0" {
                RegionKind::Private
            } else if images.contains(l.path) {
                RegionKind::Image
            } else {
                RegionKind::Mapped
            };
            Region {
                start: l.start,
                size: l.end - l.start,
                prot: Prot {
                    r: bytes.first() == Some(&b'r'),
                    w: bytes.get(1) == Some(&b'w'),
                    x: bytes.get(2) == Some(&b'x'),
                },
                kind,
                shared: bytes.get(3) == Some(&b's'),
                cow: false,
                path: (!l.path.is_empty()).then(|| l.path.to_owned()),
            }
        })
        .collect()
}

#[cfg(target_arch = "x86_64")]
mod inject {
    use super::*;

    /// A ptrace-seized thread. Dropping it puts the saved registers back and detaches,
    /// re-delivering a signal that arrived while we held it.
    struct Tracee {
        tid: i32,
        restore: Option<libc::user_regs_struct>,
        sig: i32,
    }

    impl Drop for Tracee {
        fn drop(&mut self) {
            unsafe {
                if let Some(r) = &self.restore {
                    libc::ptrace(
                        libc::PTRACE_SETREGS,
                        self.tid,
                        0usize,
                        r as *const libc::user_regs_struct,
                    );
                }
                libc::ptrace(libc::PTRACE_DETACH, self.tid, 0usize, self.sig as usize);
            }
        }
    }

    impl Tracee {
        fn req(&self, req: libc::c_uint, data: usize) -> io::Result<()> {
            if unsafe { libc::ptrace(req, self.tid, 0usize, data) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Waits until `until` for the next stop: Ok(None) on timeout, Err(ProcessGone) if the
        /// thread died instead.
        fn wait(&mut self, until: Instant) -> Result<Option<i32>> {
            let mut st = 0;
            let mut nap = Duration::from_micros(20);
            loop {
                match unsafe { libc::waitpid(self.tid, &mut st, libc::__WALL | libc::WNOHANG) } {
                    0 if Instant::now() >= until => return Ok(None),
                    0 => {
                        std::thread::sleep(nap);
                        nap = (nap * 2).min(Duration::from_millis(1));
                    }
                    -1 => {
                        let e = io::Error::last_os_error();
                        if e.kind() != io::ErrorKind::Interrupted {
                            return Err(Error::Io(e));
                        }
                    }
                    _ => break,
                }
            }
            if !libc::WIFSTOPPED(st) {
                self.restore = None;
                return Err(Error::ProcessGone);
            }
            let sig = libc::WSTOPSIG(st);
            // Signal-delivery-stop (not a ptrace event or syscall stop): hold the signal back
            // and deliver it on detach.
            // shortcut: keeps only the last such signal; good enough for a stop of a few µs.
            if st >> 16 == 0 && sig != libc::SIGTRAP && sig != (libc::SIGTRAP | 0x80) {
                self.sig = sig;
            }
            Ok(Some(sig))
        }

        fn regs(&self) -> io::Result<libc::user_regs_struct> {
            let mut r = unsafe { std::mem::zeroed::<libc::user_regs_struct>() };
            if unsafe {
                libc::ptrace(
                    libc::PTRACE_GETREGS,
                    self.tid,
                    0usize,
                    &mut r as *mut libc::user_regs_struct,
                )
            } == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(r)
        }

        fn set_regs(&self, r: &libc::user_regs_struct) -> io::Result<()> {
            self.req(libc::PTRACE_SETREGS, r as *const _ as usize)
        }
    }

    impl LinuxProcess {
        /// Runs syscall `nr` with `args` in one of the target's threads and returns its result.
        /// A negative errno from the target becomes `Error::Io`. Never blocks for more than a
        /// few seconds: a thread that will not stop is left running, untraced, with an error.
        pub(super) fn syscall(&self, nr: i64, args: [u64; 6]) -> Result<u64> {
            if self.ptr_size != 8 {
                return Err(Error::Unsupported("remote syscalls in 32-bit processes"));
            }
            let cache = &mut *self.ptrace.lock().unwrap_or_else(|e| e.into_inner());
            let gadget = self.syscall_gadget(cache)?;
            let pid = self.pid;
            // The main thread unless it has exited or sleeps uninterruptibly.
            let tasks = live_tasks(pid);
            let tid = tasks
                .iter()
                .find(|t| t.1 != 'D')
                .or(tasks.first())
                .ok_or(Error::ProcessGone)?
                .0;
            // The session runs on its own short-lived thread: when a tracer thread exits the
            // kernel detaches its tracees and drops pending ptrace traps, which is the only way
            // to let go of a thread that never reached a ptrace-stop.
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name("hh-core ptrace".into())
                .spawn(move || {
                    let r = remote_syscall(pid, tid, gadget, nr, args, &tx);
                    let _ = tx.send(r);
                })?;
            rx.recv_timeout(STOP_WAIT + SYSCALL_WAIT + Duration::from_secs(1))
                .unwrap_or_else(|_| Err(timed_out(pid, tid, "the remote syscall")))
        }
    }

    const STOP_WAIT: Duration = Duration::from_secs(2);
    const SYSCALL_WAIT: Duration = Duration::from_secs(5);

    fn timed_out(pid: Pid, tid: i32, what: &str) -> Error {
        Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "thread {tid} of process {pid} did not finish {what} in time (uninterruptible \
                 sleep?); it was left running and untraced"
            ),
        ))
    }

    /// One ptrace session on `tid`; runs on a dedicated thread (see `syscall`). An early
    /// error is also sent through `early` when the session keeps cleaning up afterwards.
    fn remote_syscall(
        pid: Pid,
        tid: i32,
        gadget: Addr,
        nr: i64,
        args: [u64; 6],
        early: &std::sync::mpsc::Sender<Result<u64>>,
    ) -> Result<u64> {
        let perr = |e: io::Error| os_err(e, pid);
        if unsafe {
            libc::ptrace(
                libc::PTRACE_SEIZE,
                tid,
                0usize,
                libc::PTRACE_O_TRACESYSGOOD as usize,
            )
        } == -1
        {
            return Err(perr(io::Error::last_os_error()));
        }
        let mut t = Tracee {
            tid,
            restore: None,
            sig: 0,
        };
        t.req(libc::PTRACE_INTERRUPT, 0).map_err(perr)?;
        if t.wait(Instant::now() + STOP_WAIT)?.is_none() {
            return Err(timed_out(pid, tid, "stopping for ptrace"));
        }

        let saved = t.regs().map_err(perr)?;
        // If we interrupted a blocking syscall, the kernel would restart it on the way out
        // of this stop, but our injected syscall takes that path instead. Do the restart
        // by hand: point back at the `syscall` instruction with the original number.
        let mut restore = saved;
        if (saved.orig_rax as i64) >= 0 {
            let back = saved.rip.wrapping_sub(2);
            match -(saved.rax as i64) {
                512..=514 => (restore.rax, restore.rip) = (saved.orig_rax, back),
                516 => (restore.rax, restore.rip) = (libc::SYS_restart_syscall as u64, back),
                _ => {}
            }
        }
        restore.orig_rax = u64::MAX;
        t.restore = Some(restore);

        let mut r = saved;
        (r.rip, r.rax, r.orig_rax) = (gadget, nr as u64, u64::MAX);
        (r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9) =
            (args[0], args[1], args[2], args[3], args[4], args[5]);
        t.set_regs(&r).map_err(perr)?;

        // Run to syscall entry, then to syscall exit; other stops (signals, group stop,
        // the INTERRUPT trap) are stepped over.
        let until = Instant::now() + SYSCALL_WAIT;
        for _ in 0..2 {
            loop {
                t.req(libc::PTRACE_SYSCALL, 0).map_err(perr)?;
                match t.wait(until)? {
                    Some(s) if s == libc::SIGTRAP | 0x80 => break,
                    Some(_) => {}
                    None => {
                        // The thread runs our registers: the caller gets its error now, and
                        // this thread waits for any stop to put the real ones back (Drop).
                        // If none comes, exiting detaches it anyway, with our registers.
                        let e = timed_out(pid, tid, "the remote syscall");
                        let _ = early.send(Err(timed_out(pid, tid, "the remote syscall")));
                        let _ = t.req(libc::PTRACE_INTERRUPT, 0);
                        let _ = t.wait(Instant::now() + Duration::from_secs(60));
                        return Err(e);
                    }
                }
            }
        }
        let ret = t.regs().map_err(perr)?.rax as i64;
        drop(t);
        if (-4095..0).contains(&ret) {
            return Err(Error::Io(io::Error::from_raw_os_error(-ret as i32)));
        }
        Ok(ret as u64)
    }

    impl LinuxProcess {
        /// Any `0f 05` byte pair in executable memory works: we stop right after it runs.
        fn syscall_gadget(&self, cache: &mut Option<Addr>) -> Result<Addr> {
            let mut b = [0u8; 2];
            if let Some(a) = *cache
                && self.read_exact(a, &mut b).is_ok()
                && b == [0x0f, 0x05]
            {
                return Ok(a);
            }
            let mut regions: Vec<Region> = self
                .regions()?
                .into_iter()
                .filter(|r| r.prot.r && r.prot.x)
                .collect();
            // The vDSO is tiny and always mapped.
            regions.sort_by_key(|r| r.path.as_deref() != Some("[vdso]"));
            let mut buf = Vec::new();
            for r in regions {
                // shortcut: only looks at the first 4 MiB of each region; real code has a syscall early.
                buf.resize(r.size.min(4 << 20) as usize, 0);
                let Ok(n) = self.read(r.start, &mut buf) else {
                    continue;
                };
                if let Some(i) = buf[..n].windows(2).position(|w| w == [0x0f, 0x05]) {
                    *cache = Some(r.start + i as u64);
                    return Ok(r.start + i as u64);
                }
            }
            Err(Error::Other(
                "no syscall instruction found in target".into(),
            ))
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl LinuxProcess {
    fn syscall(&self, _nr: i64, _args: [u64; 6]) -> Result<u64> {
        Err(Error::Unsupported(
            "remote syscalls on this CPU architecture",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_parsing() {
        let maps = "\
55d0c0a00000-55d0c0a01000 r--p 00000000 08:01 1234       /usr/bin/my prog
55d0c0a01000-55d0c0a02000 r-xp 00001000 08:01 1234       /usr/bin/my prog
55d0c0a02000-55d0c0a03000 rw-p 00000000 00:00 0          [heap]
7f0000000000-7f0000001000 r--s 00000000 08:01 99         /tmp/data.bin
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0
";
        let r = parse_maps(maps);
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].path.as_deref(), Some("/usr/bin/my prog"));
        assert_eq!(
            (r[0].kind, r[1].kind),
            (RegionKind::Image, RegionKind::Image)
        );
        assert_eq!(
            r[1].prot,
            Prot {
                r: true,
                w: false,
                x: true
            }
        );
        assert_eq!(
            (r[2].kind, r[2].path.as_deref()),
            (RegionKind::Private, Some("[heap]"))
        );
        assert_eq!(r[3].kind, RegionKind::Mapped);
        assert!(r[3].shared && !r[2].shared);
        assert_eq!((r[4].path.as_deref(), r[4].size), (None, 0x21000));
    }
}
