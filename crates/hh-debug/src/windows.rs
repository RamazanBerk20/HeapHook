//! Windows backend: Win32 debug API (DebugActiveProcess / WaitForDebugEvent /
//! ContinueDebugEvent, Get/SetThreadContext). While a debug event is outstanding the whole
//! process is frozen, which is our "halted" state; DebugBreakProcess produces one on demand.
//! Threads the engine wants held while others run are SuspendThread'ed.
//!
//! WOW64 (32-bit) targets: registers go through Wow64Get/SetThreadContext (the 32-bit view,
//! zero-extended into `Context`, r8..r15 zero) and their traps arrive as STATUS_WX86_*.
//! Page watches use VirtualProtectEx through hh-core and EXCEPTION_ACCESS_VIOLATION.
//! Nothing in this file can run in this repository's CI (Linux only).
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::io;
use std::mem::zeroed;

use hh_core::{Addr, Error, Module, Pid, Process, Prot, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, NTSTATUS, STATUS_WX86_BREAKPOINT,
    STATUS_WX86_SINGLE_STEP,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64,
    CONTEXT_FLOATING_POINT_AMD64, CONTEXT_INTEGER_AMD64, CONTEXT_SEGMENTS_AMD64,
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT,
    DebugActiveProcess, DebugActiveProcessStop, DebugBreakProcess, DebugSetProcessKillOnExit,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, GetThreadContext,
    LOAD_DLL_DEBUG_EVENT, M128A, ReadProcessMemory, SetThreadContext, UNLOAD_DLL_DEBUG_EVENT,
    WOW64_CONTEXT, WOW64_CONTEXT_CONTROL, WOW64_CONTEXT_DEBUG_REGISTERS,
    WOW64_CONTEXT_EXTENDED_REGISTERS, WOW64_CONTEXT_INTEGER, WOW64_CONTEXT_SEGMENTS,
    WaitForDebugEvent, Wow64GetThreadContext, Wow64SetThreadContext,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    IsWow64Process, OpenThread, ResumeThread, SuspendThread, THREAD_QUERY_LIMITED_INFORMATION,
};

use crate::engine::{Mode, Raw};
use crate::{Context, Fpu, SignalAction, Tid};
use SignalAction::{Break, Pass};

/// Exception codes and the default action of a new session (first chance; a second-chance
/// exception always breaks).
pub(crate) const SIGNALS: &[(u32, &str, SignalAction)] = &[
    (0xC000_0005, "EXCEPTION_ACCESS_VIOLATION", Pass),
    (0x8000_0003, "EXCEPTION_BREAKPOINT", Break),
    (0x4000_001F, "STATUS_WX86_BREAKPOINT", Break),
    (0x8000_0004, "EXCEPTION_SINGLE_STEP", Pass),
    (0x8000_0001, "EXCEPTION_GUARD_PAGE", Pass),
    (0x8000_0002, "EXCEPTION_DATATYPE_MISALIGNMENT", Pass),
    (0xC000_001D, "EXCEPTION_ILLEGAL_INSTRUCTION", Pass),
    (0xC000_0096, "EXCEPTION_PRIV_INSTRUCTION", Pass),
    (0xC000_0094, "EXCEPTION_INT_DIVIDE_BY_ZERO", Pass),
    (0xC000_0095, "EXCEPTION_INT_OVERFLOW", Pass),
    (0xC000_008E, "EXCEPTION_FLT_DIVIDE_BY_ZERO", Pass),
    (0xC000_0090, "EXCEPTION_FLT_INVALID_OPERATION", Pass),
    (0xC000_00FD, "EXCEPTION_STACK_OVERFLOW", Pass),
    (0xC000_0006, "EXCEPTION_IN_PAGE_ERROR", Pass),
    (0x4001_0005, "DBG_CONTROL_C", Pass),
    (0x406D_1388, "MS_VC_EXCEPTION (thread name)", Pass),
    (0xE06D_7363, "C++ exception", Pass),
];

/// GetThreadContext needs a 16-byte aligned CONTEXT; windows-sys does not align it.
#[repr(C, align(16))]
struct Ctx(CONTEXT);

const TRAP_FLAG: u32 = 0x100;

fn last_err() -> Error {
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(5) => Error::Permission(format!(
            "{e}: debugging this process needs the same or higher privileges (run HeapHook \
             as administrator for elevated or service processes)"
        )),
        _ => Error::Io(e),
    }
}

fn get_ctx(h: HANDLE, flags: u32) -> Result<Box<Ctx>> {
    let mut c = Box::new(Ctx(unsafe { zeroed() }));
    c.0.ContextFlags = flags;
    if unsafe { GetThreadContext(h, &mut c.0) } == 0 {
        return Err(last_err());
    }
    Ok(c)
}

fn set_ctx(h: HANDLE, c: &Ctx, flags: u32) -> Result<()> {
    let mut c = Box::new(Ctx(c.0));
    c.0.ContextFlags = flags;
    if unsafe { SetThreadContext(h, &c.0) } == 0 {
        return Err(last_err());
    }
    Ok(())
}

fn get32(h: HANDLE, flags: u32) -> Result<Box<WOW64_CONTEXT>> {
    let mut c = Box::new(WOW64_CONTEXT {
        ContextFlags: flags,
        ..WOW64_CONTEXT::default()
    });
    if unsafe { Wow64GetThreadContext(h, &mut *c) } == 0 {
        return Err(last_err());
    }
    Ok(c)
}

fn set32(h: HANDLE, c: &WOW64_CONTEXT, flags: u32) -> Result<()> {
    let c = Box::new(WOW64_CONTEXT {
        ContextFlags: flags,
        ..*c
    });
    if unsafe { Wow64SetThreadContext(h, &*c) } == 0 {
        return Err(last_err());
    }
    Ok(())
}

const W32_ALL: u32 = WOW64_CONTEXT_CONTROL
    | WOW64_CONTEXT_INTEGER
    | WOW64_CONTEXT_SEGMENTS
    | WOW64_CONTEXT_DEBUG_REGISTERS
    | WOW64_CONTEXT_EXTENDED_REGISTERS;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// FPU/SSE state from an FXSAVE image (WOW64 `ExtendedRegisters`, XMM0..7 only).
fn fpu_from_fxsave(b: &[u8; 512]) -> Fpu {
    let mut f = Fpu {
        fcw: le16(b, 0),
        fsw: le16(b, 2),
        ftw: b[4] as u16,
        fop: le16(b, 6),
        fip: le32(b, 8) as u64 | (le16(b, 12) as u64) << 32,
        fdp: le32(b, 16) as u64 | (le16(b, 20) as u64) << 32,
        mxcsr: le32(b, 24),
        ..Fpu::default()
    };
    for i in 0..8 {
        f.st[i].copy_from_slice(&b[32 + 16 * i..42 + 16 * i]);
        f.xmm[i].copy_from_slice(&b[160 + 16 * i..176 + 16 * i]);
    }
    f
}

fn fpu_to_fxsave(f: &Fpu, b: &mut [u8; 512]) {
    b[0..2].copy_from_slice(&f.fcw.to_le_bytes());
    b[2..4].copy_from_slice(&f.fsw.to_le_bytes());
    b[4] = f.ftw as u8;
    b[6..8].copy_from_slice(&f.fop.to_le_bytes());
    b[8..12].copy_from_slice(&(f.fip as u32).to_le_bytes());
    b[12..14].copy_from_slice(&((f.fip >> 32) as u16).to_le_bytes());
    b[16..20].copy_from_slice(&(f.fdp as u32).to_le_bytes());
    b[20..22].copy_from_slice(&((f.fdp >> 32) as u16).to_le_bytes());
    b[24..28].copy_from_slice(&f.mxcsr.to_le_bytes());
    for i in 0..8 {
        b[32 + 16 * i..42 + 16 * i].copy_from_slice(&f.st[i]);
        b[160 + 16 * i..176 + 16 * i].copy_from_slice(&f.xmm[i]);
    }
}

/// The thread's 64-bit TEB address (NtQueryInformationThread / ThreadBasicInformation), 0
/// when it cannot be read.
fn teb(tid: Tid) -> u64 {
    type Query = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        let Some(f) = GetProcAddress(ntdll, c"NtQueryInformationThread".as_ptr().cast()) else {
            return 0;
        };
        let f: Query = std::mem::transmute(f);
        let h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid);
        if h.is_null() {
            return 0;
        }
        // THREAD_BASIC_INFORMATION: ExitStatus, TebBaseAddress, ClientId, ... (48 bytes).
        let mut tbi = [0u64; 6];
        let st = f(h, 0, tbi.as_mut_ptr().cast(), 48, std::ptr::null_mut());
        CloseHandle(h);
        if st >= 0 { tbi[1] } else { 0 }
    }
}

fn m128(m: &M128A) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&m.Low.to_le_bytes());
    b[8..].copy_from_slice(&m.High.to_le_bytes());
    b
}

fn to_m128(b: &[u8; 16]) -> M128A {
    M128A {
        Low: u64::from_le_bytes(b[..8].try_into().unwrap()),
        High: i64::from_le_bytes(b[8..].try_into().unwrap()),
    }
}

fn close(h: HANDLE) {
    if !h.is_null() {
        unsafe { CloseHandle(h) };
    }
}

struct T {
    h: HANDLE,
    /// SuspendThread'ed by us (engine mode Stay).
    suspended: bool,
    /// 64-bit TEB.
    teb: u64,
}

enum Ev {
    Raw(Raw),
    /// The break-in breakpoint of DebugActiveProcess / DebugBreakProcess.
    BreakIn,
    Skip,
}

pub(crate) struct Os {
    pid: Pid,
    hproc: HANDLE,
    th: BTreeMap<Tid, T>,
    /// The outstanding debug event (process frozen) and how it will be continued.
    ev: Option<(Tid, NTSTATUS)>,
    dr: ([u64; 4], u64),
    /// ntdll!DbgBreakPoint (same address in every process of this bitness).
    brk: u64,
    /// Break-ins requested whose breakpoint has not arrived yet.
    pending_breaks: u32,
    /// A 32-bit process under WOW64.
    wow64: bool,
}

impl Os {
    pub const PAGE_FAULT: u32 = EXCEPTION_ACCESS_VIOLATION as u32;
    // shortcut: page watches use PAGE_NOACCESS / read-only + access violations like Linux,
    // not PAGE_GUARD; untested on Windows at runtime.
    pub const PAGE_WATCH: bool = true;

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn tids(&self) -> Vec<Tid> {
        self.th.keys().copied().collect()
    }

    /// Attaches and returns frozen at the attach breakpoint.
    pub fn attach(pid: Pid, _mem: &dyn Process) -> Result<(Os, Vec<(Tid, Raw)>)> {
        if unsafe { DebugActiveProcess(pid) } == 0 {
            return Err(last_err());
        }
        // Detaching or our own exit must not kill the target.
        unsafe { DebugSetProcessKillOnExit(0) };
        let brk = unsafe {
            let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
            GetProcAddress(ntdll, c"DbgBreakPoint".as_ptr().cast())
        }
        .map_or(0, |f| f as usize as u64);
        let mut os = Os {
            pid,
            hproc: std::ptr::null_mut(),
            th: BTreeMap::new(),
            ev: None,
            dr: ([0; 4], 0),
            brk,
            pending_breaks: 1,
            wow64: false,
        };
        // The system reports the existing process, threads and DLLs, then the break-in.
        loop {
            let Some(de) = os.wait(10_000) else {
                unsafe { DebugActiveProcessStop(pid) };
                return Err(Error::Other(
                    "timed out waiting for the attach breakpoint".into(),
                ));
            };
            match os.translate(&de) {
                Ev::BreakIn => break,
                Ev::Raw(Raw::ProcessExited { .. }) => {
                    os.continue_ev();
                    unsafe { DebugActiveProcessStop(pid) };
                    return Err(Error::ProcessGone);
                }
                _ => os.continue_ev(),
            }
        }
        Ok((os, Vec::new()))
    }

    pub fn loader_hook(&self, _mem: &dyn Process) -> Option<Addr> {
        None // LOAD_DLL_DEBUG_EVENT does the job.
    }

    fn wait(&mut self, ms: u32) -> Option<DEBUG_EVENT> {
        let mut de: DEBUG_EVENT = unsafe { zeroed() };
        if unsafe { WaitForDebugEvent(&mut de, ms) } == 0 {
            return None;
        }
        self.ev = Some((de.dwThreadId, DBG_CONTINUE));
        Some(de)
    }

    fn continue_ev(&mut self) {
        if let Some((tid, st)) = self.ev.take() {
            unsafe { ContinueDebugEvent(self.pid, tid, st) };
        }
    }

    fn add_thread(&mut self, tid: Tid, h: HANDLE) {
        self.th.insert(
            tid,
            T {
                h,
                suspended: false,
                teb: teb(tid),
            },
        );
        let (a, d) = self.dr;
        if d != 0 {
            let _ = write_dr(h, self.wow64, a, d);
        }
    }

    fn read(&self, addr: Addr, buf: &mut [u8]) -> bool {
        let mut n = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.hproc,
                addr as usize as *const c_void,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut n,
            )
        };
        ok != 0 && n == buf.len()
    }

    fn module(&self, file: HANDLE, base: Addr) -> Module {
        let mut buf = [0u16; 1024];
        let n = match file.is_null() {
            true => 0,
            false => unsafe {
                GetFinalPathNameByHandleW(file, buf.as_mut_ptr(), buf.len() as u32, 0) as usize
            },
        };
        let path = match n {
            1..1024 => String::from_utf16_lossy(&buf[..n])
                .trim_start_matches(r"\\?\")
                .to_owned(),
            _ => String::new(),
        };
        // SizeOfImage from the PE optional header.
        let mut b4 = [0u8; 4];
        let size = (|| {
            self.read(base + 0x3c, &mut b4).then_some(())?;
            let pe = u32::from_le_bytes(b4) as u64;
            self.read(base + pe + 0x50, &mut b4).then_some(())?;
            Some(u32::from_le_bytes(b4) as u64)
        })()
        .unwrap_or(0);
        Module {
            name: path.rsplit('\\').next().unwrap_or_default().to_owned(),
            path,
            base,
            size,
        }
    }

    fn translate(&mut self, de: &DEBUG_EVENT) -> Ev {
        let tid = de.dwThreadId;
        unsafe {
            match de.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let i = de.u.CreateProcessInfo;
                    close(i.hFile);
                    self.hproc = i.hProcess;
                    let mut w = 0;
                    self.wow64 = IsWow64Process(i.hProcess, &mut w) != 0 && w != 0;
                    self.add_thread(tid, i.hThread);
                    Ev::Skip
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    self.add_thread(tid, de.u.CreateThread.hThread);
                    Ev::Raw(Raw::ThreadCreated(tid))
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    self.th.remove(&tid);
                    Ev::Raw(Raw::ThreadExited)
                }
                EXIT_PROCESS_DEBUG_EVENT => Ev::Raw(Raw::ProcessExited {
                    code: Some(de.u.ExitProcess.dwExitCode as i32),
                }),
                LOAD_DLL_DEBUG_EVENT => {
                    let i = de.u.LoadDll;
                    let m = self.module(i.hFile, i.lpBaseOfDll as Addr);
                    close(i.hFile);
                    Ev::Raw(Raw::ModuleLoaded(m))
                }
                UNLOAD_DLL_DEBUG_EVENT => {
                    Ev::Raw(Raw::ModuleUnloaded(de.u.UnloadDll.lpBaseOfDll as Addr))
                }
                EXCEPTION_DEBUG_EVENT => {
                    let x = de.u.Exception;
                    let rec = x.ExceptionRecord;
                    let code = rec.ExceptionCode;
                    let at = rec.ExceptionAddress as Addr;
                    if code == EXCEPTION_BREAKPOINT
                        && self.pending_breaks > 0
                        && self.brk != 0
                        && at == self.brk
                    {
                        self.pending_breaks -= 1;
                        return Ev::BreakIn;
                    }
                    if matches!(
                        code,
                        EXCEPTION_BREAKPOINT
                            | EXCEPTION_SINGLE_STEP
                            | STATUS_WX86_BREAKPOINT
                            | STATUS_WX86_SINGLE_STEP
                    ) {
                        return Ev::Raw(Raw::Trap {
                            code: code as u32,
                            int3: code == EXCEPTION_BREAKPOINT || code == STATUS_WX86_BREAKPOINT,
                        });
                    }
                    if let Some(e) = &mut self.ev {
                        e.1 = DBG_EXCEPTION_NOT_HANDLED;
                    }
                    let addr = match code == EXCEPTION_ACCESS_VIOLATION && rec.NumberParameters >= 2
                    {
                        true => rec.ExceptionInformation[1] as Addr,
                        false => at,
                    };
                    Ev::Raw(Raw::Signal {
                        code: code as u32,
                        addr: Some(addr),
                        first_chance: x.dwFirstChance != 0,
                    })
                }
                _ => Ev::Skip,
            }
        }
    }

    pub fn is_stopped(&self, tid: Tid) -> bool {
        self.th
            .get(&tid)
            .is_some_and(|t| self.ev.is_some() || t.suspended)
    }

    pub fn is_running(&self, tid: Tid) -> bool {
        self.th.contains_key(&tid) && !self.is_stopped(tid)
    }

    pub fn exec_entry(&self) -> Option<Addr> {
        None
    }

    /// Protection change for page watches (hh-core's VirtualProtectEx works while attached).
    pub fn mprotect(&mut self, mem: &dyn Process, start: Addr, len: u64, prot: Prot) -> Result<()> {
        mem.protect(start, len, prot).map(|_| ())
    }

    // Forks do not exist here; the engine never calls these.
    pub fn write_child(&self, _: Pid, _: Addr, _: &[u8]) -> Result<()> {
        Err(Error::Unsupported("fork"))
    }
    pub fn mprotect_child(
        &mut self,
        _: Pid,
        _: &dyn Process,
        _: Addr,
        _: u64,
        _: Prot,
    ) -> Result<()> {
        Err(Error::Unsupported("fork"))
    }
    pub fn detach_child(&self, _: Pid) -> Result<()> {
        Err(Error::Unsupported("fork"))
    }

    fn clear_tf(&self, h: HANDLE) -> Result<()> {
        if self.wow64 {
            let mut c = get32(h, WOW64_CONTEXT_CONTROL)?;
            c.EFlags &= !TRAP_FLAG;
            return set32(h, &c, WOW64_CONTEXT_CONTROL);
        }
        let mut c = get_ctx(h, CONTEXT_CONTROL_AMD64)?;
        c.0.EFlags &= !TRAP_FLAG;
        set_ctx(h, &c, CONTEXT_CONTROL_AMD64)
    }

    fn set_tf(&self, h: HANDLE) -> Result<()> {
        if self.wow64 {
            let mut c = get32(h, WOW64_CONTEXT_CONTROL)?;
            c.EFlags |= TRAP_FLAG;
            return set32(h, &c, WOW64_CONTEXT_CONTROL);
        }
        let mut c = get_ctx(h, CONTEXT_CONTROL_AMD64)?;
        c.0.EFlags |= TRAP_FLAG;
        set_ctx(h, &c, CONTEXT_CONTROL_AMD64)
    }

    pub fn poll(&mut self) -> Result<Option<(Tid, Raw)>> {
        if self.ev.is_some() {
            return Ok(None);
        }
        loop {
            let Some(de) = self.wait(0) else {
                return Ok(None);
            };
            match self.translate(&de) {
                Ev::Raw(r) => return Ok(Some((de.dwThreadId, r))),
                // A break-in whose halt was satisfied by another event, or noise.
                _ => self.continue_ev(),
            }
        }
    }

    /// Freezes the process. Notifications seen on the way are returned; an exception that
    /// arrives before our break-in becomes the outstanding event and is returned too.
    pub fn halt_all(&mut self) -> Result<Vec<(Tid, Raw)>> {
        let mut out = Vec::new();
        if self.ev.is_some() {
            return Ok(out);
        }
        if unsafe { DebugBreakProcess(self.hproc) } == 0 {
            return Err(last_err());
        }
        self.pending_breaks += 1;
        loop {
            let de = self
                .wait(5000)
                .ok_or_else(|| Error::Other("process did not stop".into()))?;
            let tid = de.dwThreadId;
            match self.translate(&de) {
                Ev::BreakIn => return Ok(out),
                Ev::Skip => self.continue_ev(),
                Ev::Raw(
                    r @ (Raw::ThreadCreated(_)
                    | Raw::ThreadExited
                    | Raw::ModuleLoaded(_)
                    | Raw::ModuleUnloaded(_)),
                ) => {
                    out.push((tid, r));
                    self.continue_ev();
                }
                Ev::Raw(r) => {
                    out.push((tid, r));
                    return Ok(out);
                }
            }
        }
    }

    pub fn resume(&mut self, mode: &dyn Fn(Tid) -> Mode) -> Result<()> {
        let frozen = self.ev.is_some();
        let mut step = Vec::new();
        for (&tid, t) in self.th.iter_mut() {
            if !frozen && !t.suspended {
                continue; // running, not ours to touch
            }
            match mode(tid) {
                Mode::Stay => {
                    if !t.suspended && unsafe { SuspendThread(t.h) } != u32::MAX {
                        t.suspended = true;
                    }
                }
                m => {
                    if t.suspended && unsafe { ResumeThread(t.h) } != u32::MAX {
                        t.suspended = false;
                    }
                    if m == Mode::Step {
                        step.push(t.h);
                    }
                }
            }
        }
        for h in step {
            self.set_tf(h)?;
        }
        self.continue_ev();
        Ok(())
    }

    pub fn set_pass(&mut self, tid: Tid, pass: bool) {
        if let Some((t, st)) = &mut self.ev
            && *t == tid
        {
            *st = if pass {
                DBG_EXCEPTION_NOT_HANDLED
            } else {
                DBG_CONTINUE
            };
        }
    }

    fn h(&self, tid: Tid) -> Result<HANDLE> {
        self.th
            .get(&tid)
            .map(|t| t.h)
            .ok_or_else(|| Error::Other(format!("no thread {tid}")))
    }

    pub fn pc_sp(&self, tid: Tid) -> Result<(Addr, u64)> {
        if self.wow64 {
            let c = get32(self.h(tid)?, WOW64_CONTEXT_CONTROL)?;
            return Ok((c.Eip as u64, c.Esp as u64));
        }
        let c = get_ctx(self.h(tid)?, CONTEXT_CONTROL_AMD64)?;
        Ok((c.0.Rip, c.0.Rsp))
    }

    pub fn set_pc(&mut self, tid: Tid, pc: Addr) -> Result<()> {
        let h = self.h(tid)?;
        if self.wow64 {
            let mut c = get32(h, WOW64_CONTEXT_CONTROL)?;
            c.Eip = pc as u32;
            return set32(h, &c, WOW64_CONTEXT_CONTROL);
        }
        let mut c = get_ctx(h, CONTEXT_CONTROL_AMD64)?;
        c.0.Rip = pc;
        set_ctx(h, &c, CONTEXT_CONTROL_AMD64)
    }

    fn context32(&self, tid: Tid) -> Result<Context> {
        let x = get32(self.h(tid)?, W32_ALL)?;
        let teb = self.th.get(&tid).map_or(0, |t| t.teb);
        Ok(Context {
            rax: x.Eax as u64,
            rbx: x.Ebx as u64,
            rcx: x.Ecx as u64,
            rdx: x.Edx as u64,
            rsi: x.Esi as u64,
            rdi: x.Edi as u64,
            rbp: x.Ebp as u64,
            rsp: x.Esp as u64,
            rip: x.Eip as u64,
            rflags: x.EFlags as u64,
            cs: x.SegCs as u16,
            ds: x.SegDs as u16,
            es: x.SegEs as u16,
            fs: x.SegFs as u16,
            gs: x.SegGs as u16,
            ss: x.SegSs as u16,
            // shortcut: the 32-bit TEB sits 0x2000 after the 64-bit one (Windows 10/11 layout).
            fs_base: if teb != 0 { teb + 0x2000 } else { 0 },
            gs_base: teb,
            dr: [x.Dr0, x.Dr1, x.Dr2, x.Dr3, 0, 0, x.Dr6, x.Dr7].map(u64::from),
            fpu: fpu_from_fxsave(&x.ExtendedRegisters),
            ..Context::default()
        })
    }

    fn set_context32(&mut self, tid: Tid, c: &Context) -> Result<()> {
        let h = self.h(tid)?;
        let mut x = get32(h, W32_ALL)?;
        (x.Eax, x.Ebx, x.Ecx, x.Edx) = (c.rax as u32, c.rbx as u32, c.rcx as u32, c.rdx as u32);
        (x.Esi, x.Edi, x.Ebp, x.Esp) = (c.rsi as u32, c.rdi as u32, c.rbp as u32, c.rsp as u32);
        (x.Eip, x.EFlags) = (c.rip as u32, c.rflags as u32);
        (x.SegCs, x.SegDs, x.SegEs, x.SegFs, x.SegGs, x.SegSs) = (
            c.cs as u32,
            c.ds as u32,
            c.es as u32,
            c.fs as u32,
            c.gs as u32,
            c.ss as u32,
        );
        fpu_to_fxsave(&c.fpu, &mut x.ExtendedRegisters);
        set32(
            h,
            &x,
            WOW64_CONTEXT_CONTROL
                | WOW64_CONTEXT_INTEGER
                | WOW64_CONTEXT_SEGMENTS
                | WOW64_CONTEXT_EXTENDED_REGISTERS,
        )
    }

    pub fn context(&self, tid: Tid) -> Result<Context> {
        if self.wow64 {
            return self.context32(tid);
        }
        let c = get_ctx(self.h(tid)?, CONTEXT_ALL_AMD64)?;
        let x = &c.0;
        let f = unsafe { x.Anonymous.FltSave };
        let mut fpu = Fpu {
            fcw: f.ControlWord,
            fsw: f.StatusWord,
            ftw: f.TagWord as u16,
            fop: f.ErrorOpcode,
            fip: f.ErrorOffset as u64 | (f.ErrorSelector as u64) << 32 | (f.Reserved2 as u64) << 48,
            fdp: f.DataOffset as u64 | (f.DataSelector as u64) << 32 | (f.Reserved3 as u64) << 48,
            mxcsr: x.MxCsr,
            ..Fpu::default()
        };
        for (d, s) in fpu.st.iter_mut().zip(&f.FloatRegisters) {
            d.copy_from_slice(&m128(s)[..10]);
        }
        for (d, s) in fpu.xmm.iter_mut().zip(&f.XmmRegisters) {
            *d = m128(s);
        }
        Ok(Context {
            rax: x.Rax,
            rbx: x.Rbx,
            rcx: x.Rcx,
            rdx: x.Rdx,
            rsi: x.Rsi,
            rdi: x.Rdi,
            rbp: x.Rbp,
            rsp: x.Rsp,
            r8: x.R8,
            r9: x.R9,
            r10: x.R10,
            r11: x.R11,
            r12: x.R12,
            r13: x.R13,
            r14: x.R14,
            r15: x.R15,
            rip: x.Rip,
            rflags: x.EFlags as u64,
            cs: x.SegCs,
            ds: x.SegDs,
            es: x.SegEs,
            fs: x.SegFs,
            gs: x.SegGs,
            ss: x.SegSs,
            fs_base: 0,
            gs_base: self.th.get(&tid).map_or(0, |t| t.teb),
            dr: [x.Dr0, x.Dr1, x.Dr2, x.Dr3, 0, 0, x.Dr6, x.Dr7],
            fpu,
        })
    }

    pub fn set_context(&mut self, tid: Tid, c: &Context) -> Result<()> {
        if self.wow64 {
            return self.set_context32(tid, c);
        }
        let h = self.h(tid)?;
        let mut w = get_ctx(h, CONTEXT_ALL_AMD64)?;
        let x = &mut w.0;
        (x.Rax, x.Rbx, x.Rcx, x.Rdx, x.Rsi, x.Rdi, x.Rbp, x.Rsp) =
            (c.rax, c.rbx, c.rcx, c.rdx, c.rsi, c.rdi, c.rbp, c.rsp);
        (x.R8, x.R9, x.R10, x.R11, x.R12, x.R13, x.R14, x.R15) =
            (c.r8, c.r9, c.r10, c.r11, c.r12, c.r13, c.r14, c.r15);
        (x.Rip, x.EFlags) = (c.rip, c.rflags as u32);
        (x.SegCs, x.SegDs, x.SegEs, x.SegFs, x.SegGs, x.SegSs) =
            (c.cs, c.ds, c.es, c.fs, c.gs, c.ss);
        x.MxCsr = c.fpu.mxcsr;
        let f = unsafe { &mut x.Anonymous.FltSave };
        let p = &c.fpu;
        (f.ControlWord, f.StatusWord, f.TagWord, f.ErrorOpcode) =
            (p.fcw, p.fsw, p.ftw as u8, p.fop);
        (f.ErrorOffset, f.ErrorSelector, f.Reserved2) =
            (p.fip as u32, (p.fip >> 32) as u16, (p.fip >> 48) as u16);
        (f.DataOffset, f.DataSelector, f.Reserved3) =
            (p.fdp as u32, (p.fdp >> 32) as u16, (p.fdp >> 48) as u16);
        f.MxCsr = p.mxcsr;
        for (d, s) in f.FloatRegisters.iter_mut().zip(&p.st) {
            let mut b = m128(d);
            b[..10].copy_from_slice(s);
            *d = to_m128(&b);
        }
        for (d, s) in f.XmmRegisters.iter_mut().zip(&p.xmm) {
            *d = to_m128(s);
        }
        set_ctx(
            h,
            &w,
            CONTEXT_CONTROL_AMD64
                | CONTEXT_INTEGER_AMD64
                | CONTEXT_SEGMENTS_AMD64
                | CONTEXT_FLOATING_POINT_AMD64,
        )
    }

    pub fn take_dr6(&mut self, tid: Tid) -> Result<u64> {
        let h = self.h(tid)?;
        if self.wow64 {
            let mut c = get32(h, WOW64_CONTEXT_DEBUG_REGISTERS)?;
            let v = c.Dr6 as u64;
            if v & 0xf != 0 {
                c.Dr6 = 0;
                set32(h, &c, WOW64_CONTEXT_DEBUG_REGISTERS)?;
            }
            return Ok(v);
        }
        let mut c = get_ctx(h, CONTEXT_DEBUG_REGISTERS_AMD64)?;
        let v = c.0.Dr6;
        if v & 0xf != 0 {
            c.0.Dr6 = 0;
            set_ctx(h, &c, CONTEXT_DEBUG_REGISTERS_AMD64)?;
        }
        Ok(v)
    }

    pub fn set_dr(&mut self, tid: Option<Tid>, addrs: [u64; 4], dr7: u64) -> Result<()> {
        let targets: Vec<HANDLE> = match tid {
            Some(t) => vec![self.h(t)?],
            None => {
                self.dr = (addrs, dr7);
                self.th.values().map(|t| t.h).collect()
            }
        };
        for h in targets {
            write_dr(h, self.wow64, addrs, dr7)?;
        }
        Ok(())
    }

    /// Nothing to recover on Windows: debug events cannot be taken by another waiter.
    pub fn watchdog(&mut self) -> Result<Vec<(Tid, Raw)>> {
        Ok(Vec::new())
    }

    pub fn take_notes(&mut self) -> Vec<String> {
        Vec::new()
    }

    pub fn detach(&mut self) -> Result<()> {
        if self.ev.is_none() {
            let _ = self.halt_all(); // best effort: detaching matters more
        }
        for t in self.th.values_mut() {
            if t.suspended {
                unsafe { ResumeThread(t.h) };
                t.suspended = false;
            }
        }
        // A thread left with the trap flag would die of an unhandled single-step
        // exception once nobody is attached.
        let hs: Vec<HANDLE> = self.th.values().map(|t| t.h).collect();
        for h in hs {
            let _ = self.clear_tf(h);
        }
        // A break-in still in flight would hit DbgBreakPoint with no debugger attached and
        // kill the target, so drain it first.
        while self.pending_breaks > 0 {
            self.continue_ev();
            let Some(de) = self.wait(2000) else { break };
            let tid = de.dwThreadId;
            match self.translate(&de) {
                Ev::Raw(Raw::ProcessExited { .. }) => break,
                Ev::Raw(Raw::Trap { int3: true, .. }) => {
                    // An int3 of ours hit before we restored the byte: back up onto it.
                    let at = unsafe { de.u.Exception.ExceptionRecord.ExceptionAddress } as Addr;
                    let mut b = [0u8];
                    if self.read(at, &mut b) && b[0] != 0xcc {
                        let _ = self.set_pc(tid, at);
                    }
                }
                _ => {}
            }
        }
        // Step / breakpoint exceptions already raised but not yet reported: swallow them
        // (other exceptions keep their not-handled status and reach the program).
        for _ in 0..100 {
            self.continue_ev();
            let Some(de) = self.wait(50) else { break };
            let tid = de.dwThreadId;
            match self.translate(&de) {
                Ev::Raw(Raw::ProcessExited { .. }) => break,
                Ev::Raw(Raw::Trap { int3, .. }) => {
                    let at = unsafe { de.u.Exception.ExceptionRecord.ExceptionAddress } as Addr;
                    let mut b = [0u8];
                    if int3 && self.read(at, &mut b) && b[0] != 0xcc {
                        let _ = self.set_pc(tid, at);
                    }
                    if let Some(h) = self.th.get(&tid).map(|t| t.h) {
                        let _ = self.clear_tf(h);
                    }
                    if let Some(e) = &mut self.ev {
                        e.1 = DBG_CONTINUE;
                    }
                }
                _ => {}
            }
        }
        self.continue_ev();
        // shortcut: thread/process handles from the debug events are left to process exit.
        if unsafe { DebugActiveProcessStop(self.pid) } == 0 {
            return Err(last_err());
        }
        self.th.clear();
        Ok(())
    }
}

fn write_dr(h: HANDLE, wow64: bool, addrs: [u64; 4], dr7: u64) -> Result<()> {
    if wow64 {
        let mut c = get32(h, WOW64_CONTEXT_DEBUG_REGISTERS)?;
        let a = addrs.map(|a| a as u32);
        (c.Dr0, c.Dr1, c.Dr2, c.Dr3, c.Dr7) = (a[0], a[1], a[2], a[3], dr7 as u32);
        return set32(h, &c, WOW64_CONTEXT_DEBUG_REGISTERS);
    }
    let mut c = get_ctx(h, CONTEXT_DEBUG_REGISTERS_AMD64)?;
    (c.0.Dr0, c.0.Dr1, c.0.Dr2, c.0.Dr3, c.0.Dr7) = (addrs[0], addrs[1], addrs[2], addrs[3], dr7);
    set_ctx(h, &c, CONTEXT_DEBUG_REGISTERS_AMD64)
}
