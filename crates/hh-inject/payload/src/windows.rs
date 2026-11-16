//! Windows hooks: entry-point detours. `hh_speedhack_hook` (called by the host through a
//! remote thread after `LoadLibraryW`) overwrites the first 5 bytes of each timing export in
//! kernel32 / kernelbase / ntdll / winmm with `jmp rel32` to a relay (`jmp [rip+0]; dq hook`)
//! allocated within ±2 GiB. The 5 bytes are replaced with one aligned 8-byte store when they
//! sit in one qword (functions are 16-byte aligned, so nearly always), so a thread entering
//! the function sees either the old or the new code.
//!
//! The hooks never call the originals: every clock is driven by `NtQueryPerformanceCounter`
//! and starts from the original function's value at hook time, sleeps use
//! `NtDelayExecution`. Not caught: `rdtsc`, `KUSER_SHARED_DATA` reads, direct syscalls,
//! `NtQuerySystemTime` / waits with timeouts (`WaitForSingleObject`, ...), and winmm if it is
//! loaded after hooking.
use std::ffi::CStr;
use std::ptr::null_mut;
use std::sync::atomic::Ordering::{Acquire, Relaxed, Release, SeqCst};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize};

use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
    VirtualAlloc, VirtualProtect, VirtualQuery,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::core::PCWSTR;
use windows_sys::w;

use crate::{Clock, HH_SPEEDHACK, InFlight, MAGIC};

type NtQueryPerformanceCounter = unsafe extern "system" fn(*mut i64, *mut i64) -> i32;
type NtDelayExecution = unsafe extern "system" fn(u8, *const i64) -> i32;
type U64Fn = unsafe extern "system" fn() -> u64;
type U32Fn = unsafe extern "system" fn() -> u32;
type QpcFn = unsafe extern "system" fn(*mut i64) -> i32;
type FileTimeFn = unsafe extern "system" fn(*mut u64);

static NT_QPC: AtomicUsize = AtomicUsize::new(0);
static NT_DELAY: AtomicUsize = AtomicUsize::new(0);
static FREQ: AtomicI64 = AtomicI64::new(10_000_000);

// All in QPC ticks.
static QPC: Clock = Clock::new(true);
static TICK: Clock = Clock::new(true);
static TGT: Clock = Clock::new(true);
static FT: Clock = Clock::new(false);
static FTP: Clock = Clock::new(false);

const STATUS_USER_APC: i32 = 0xC0;
const STATUS_ALERTED: i32 = 0x101;
const WAIT_IO_COMPLETION: u32 = 0xC0;
/// Longest real nap inside a scaled sleep, in ms.
const SLICE_MS: i64 = 50;

fn real() -> i64 {
    let mut c = 0i64;
    let f = NT_QPC.load(Relaxed);
    if f != 0 {
        unsafe { std::mem::transmute::<usize, NtQueryPerformanceCounter>(f)(&mut c, null_mut()) };
    }
    c
}

fn freq() -> i128 {
    FREQ.load(Relaxed).max(1) as i128
}

fn to_units(ticks: i64, per_sec: i64) -> i64 {
    (ticks as i128 * per_sec as i128 / freq()) as i64
}

/// Ticks for `v` units, rounded up so converting back gives at least `v`.
fn from_units(v: i64, per_sec: i64) -> i64 {
    ((v as i128 * freq() + per_sec as i128 - 1) / per_sec as i128) as i64
}

unsafe extern "system" fn h_qpc(out: *mut i64) -> i32 {
    let _g = InFlight::enter();
    if out.is_null() {
        return 0;
    }
    unsafe { *out = QPC.get(real).0 };
    1
}

unsafe extern "system" fn h_tick64() -> u64 {
    let _g = InFlight::enter();
    to_units(TICK.get(real).0, 1000) as u64
}

unsafe extern "system" fn h_tick() -> u32 {
    let _g = InFlight::enter();
    to_units(TICK.get(real).0, 1000) as u32
}

unsafe extern "system" fn h_time_get_time() -> u32 {
    let _g = InFlight::enter();
    to_units(TGT.get(real).0, 1000) as u32
}

unsafe extern "system" fn h_filetime(out: *mut u64) {
    let _g = InFlight::enter();
    if !out.is_null() {
        unsafe { out.write_unaligned(to_units(FT.get(real).0, 10_000_000) as u64) };
    }
}

unsafe extern "system" fn h_filetime_precise(out: *mut u64) {
    let _g = InFlight::enter();
    if !out.is_null() {
        unsafe { out.write_unaligned(to_units(FTP.get(real).0, 10_000_000) as u64) };
    }
}

unsafe extern "system" fn h_sleep(ms: u32) {
    unsafe { h_sleep_ex(ms, 0) };
}

unsafe extern "system" fn h_sleep_ex(ms: u32, alertable: i32) -> u32 {
    let _g = InFlight::enter();
    // `interval` in 100 ns units, negative = relative. Returns false when an APC / alert
    // ended the wait early.
    let delay = |interval: i64| {
        let f = NT_DELAY.load(Relaxed);
        if f == 0 {
            return true;
        }
        let st = unsafe {
            std::mem::transmute::<usize, NtDelayExecution>(f)((alertable != 0) as u8, &interval)
        };
        st != STATUS_USER_APC && st != STATUS_ALERTED
    };
    let done = if ms == 0 || ms == u32::MAX {
        // Yield / infinite: nothing to scale.
        delay(if ms == 0 { 0 } else { i64::MIN })
    } else {
        let deadline = QPC.get(real).0.saturating_add(from_units(ms as i64, 1000));
        let slice = (freq() as i64 * SLICE_MS / 1000).max(1);
        QPC.sleep_until(real, deadline, slice, |ticks| {
            delay(-to_units(ticks, 10_000_000).max(1))
        })
        .is_none()
    };
    if done { 0 } else { WAIT_IO_COMPLETION }
}

// ---- patching -------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Qpc,
    Tick64,
    Tick32,
    TimeGetTime,
    FileTime,
    FileTimePrecise,
    Sleep,
    SleepEx,
}

impl Kind {
    fn hook(self) -> usize {
        match self {
            Kind::Qpc => h_qpc as *const () as usize,
            Kind::Tick64 => h_tick64 as *const () as usize,
            Kind::Tick32 => h_tick as *const () as usize,
            Kind::TimeGetTime => h_time_get_time as *const () as usize,
            Kind::FileTime => h_filetime as *const () as usize,
            Kind::FileTimePrecise => h_filetime_precise as *const () as usize,
            Kind::Sleep => h_sleep as *const () as usize,
            Kind::SleepEx => h_sleep_ex as *const () as usize,
        }
    }

    /// Starts this hook's clock at the original function's current value (once).
    unsafe fn init_clock(self, orig: usize) {
        static READY: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];
        let (i, clock) = match self {
            Kind::Qpc => (0, &QPC),
            Kind::Tick64 | Kind::Tick32 => (1, &TICK),
            Kind::TimeGetTime => (2, &TGT),
            Kind::FileTime => (3, &FT),
            Kind::FileTimePrecise => (4, &FTP),
            Kind::Sleep | Kind::SleepEx => return,
        };
        if READY[i].swap(1, Relaxed) != 0 {
            return;
        }
        unsafe {
            let virt = match self {
                Kind::Qpc => {
                    let mut c = 0;
                    std::mem::transmute::<usize, QpcFn>(orig)(&mut c);
                    c
                }
                Kind::Tick32 => {
                    // GetTickCount shares the 64-bit clock; base it on GetTickCount64.
                    let k = GetModuleHandleW(w!("kernel32.dll"));
                    match GetProcAddress(k, c"GetTickCount64".as_ptr().cast()) {
                        Some(f) => from_units(std::mem::transmute::<_, U64Fn>(f)() as i64, 1000),
                        None => from_units(std::mem::transmute::<usize, U32Fn>(orig)() as i64, 1000),
                    }
                }
                Kind::Tick64 => from_units(std::mem::transmute::<usize, U64Fn>(orig)() as i64, 1000),
                Kind::TimeGetTime => {
                    from_units(std::mem::transmute::<usize, U32Fn>(orig)() as i64, 1000)
                }
                _ => {
                    let mut ft = 0u64;
                    std::mem::transmute::<usize, FileTimeFn>(orig)(&mut ft);
                    from_units(ft as i64, 10_000_000)
                }
            };
            clock.init(real(), virt);
        }
    }
}

const TARGETS: &[(&CStr, Kind)] = &[
    (c"QueryPerformanceCounter", Kind::Qpc),
    (c"RtlQueryPerformanceCounter", Kind::Qpc),
    (c"GetTickCount64", Kind::Tick64),
    (c"GetTickCount", Kind::Tick32),
    (c"timeGetTime", Kind::TimeGetTime),
    (c"GetSystemTimeAsFileTime", Kind::FileTime),
    (c"GetSystemTimePreciseAsFileTime", Kind::FileTimePrecise),
    (c"Sleep", Kind::Sleep),
    (c"SleepEx", Kind::SleepEx),
];

fn modules() -> [PCWSTR; 5] {
    [
        w!("kernel32.dll"),
        w!("kernelbase.dll"),
        w!("ntdll.dll"),
        w!("winmm.dll"),
        w!("winmmbase.dll"),
    ]
}

/// (patched address, its original first 8 bytes).
const MAX_PATCHES: usize = 64;
static PATCHES: [[AtomicU64; 2]; MAX_PATCHES] =
    [const { [AtomicU64::new(0), AtomicU64::new(0)] }; MAX_PATCHES];
static PATCH_N: AtomicUsize = AtomicUsize::new(0);
/// Relay pages: (base, bytes used).
static RELAYS: [[AtomicUsize; 2]; 16] = [const { [AtomicUsize::new(0), AtomicUsize::new(0)] }; 16];
static INSTALLING: AtomicU32 = AtomicU32::new(0);

const PAGE: usize = 4096;
const REACH: usize = 0x7000_0000;

fn alloc_near(target: usize) -> Option<usize> {
    const GRAN: usize = 0x10000;
    let mut a = target.saturating_sub(REACH).max(GRAN);
    let end = target.saturating_add(REACH);
    while a < end {
        let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { VirtualQuery(a as *const _, &mut m, size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 {
            return None;
        }
        let region_end = m.BaseAddress as usize + m.RegionSize;
        if m.State == MEM_FREE {
            let at = a.max(m.BaseAddress as usize).next_multiple_of(GRAN);
            if at + PAGE <= region_end && at.abs_diff(target) < REACH {
                let p = unsafe {
                    VirtualAlloc(at as *const _, PAGE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
                };
                if !p.is_null() {
                    return Some(p as usize);
                }
            }
        }
        a = region_end.max(a + GRAN);
    }
    None
}

/// A 16-byte `jmp [rip+0]; dq hook` within rel32 reach of `target`.
fn relay(target: usize, hook: usize) -> Option<usize> {
    let mut code = [0u8; 16];
    code[..6].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
    code[6..14].copy_from_slice(&hook.to_le_bytes());
    let place = |at: usize| unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), at as *mut u8, 16);
        at
    };
    for r in &RELAYS {
        let (base, used) = (r[0].load(Relaxed), r[1].load(Relaxed));
        if base != 0 && base.abs_diff(target) < REACH && used + 16 <= PAGE {
            r[1].store(used + 16, Relaxed);
            return Some(place(base + used));
        }
    }
    let slot = RELAYS.iter().find(|r| r[0].load(Relaxed) == 0)?;
    let base = alloc_near(target)?;
    slot[0].store(base, Relaxed);
    slot[1].store(16, Relaxed);
    Some(place(base))
}

/// Replaces the first 5 bytes at `at`; returns the previous first 8 bytes.
unsafe fn write5(at: usize, bytes: [u8; 5]) -> Option<u64> {
    let mut old = 0u32;
    unsafe {
        if VirtualProtect(at as *const _, 16, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return None;
        }
        let prev = (at as *const u64).read_unaligned();
        let q = at & !7;
        let off = at - q;
        if off <= 3 {
            // One aligned qword holds all 5 bytes: swap them in with a single store.
            let cell = AtomicU64::from_ptr(q as *mut u64);
            let mut b = cell.load(SeqCst).to_le_bytes();
            b[off..off + 5].copy_from_slice(&bytes);
            cell.store(u64::from_le_bytes(b), SeqCst);
        } else {
            // shortcut: not atomic for oddly aligned entries; a thread entering right now could
            // see a torn jump. Upgrade by suspending the other threads if this ever shows up.
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), at as *mut u8, 5);
        }
        VirtualProtect(at as *const _, 16, old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), at as *const _, 16);
        Some(prev)
    }
}

unsafe fn patch(target: usize, kind: Kind) {
    let n = PATCH_N.load(Relaxed);
    if n == MAX_PATCHES
        || PATCHES[..n].iter().any(|p| p[0].load(Relaxed) == target as u64)
    {
        return;
    }
    unsafe { kind.init_clock(target) };
    let Some(r) = relay(target, kind.hook()) else {
        return;
    };
    let rel = r as i64 - (target as i64 + 5);
    let Ok(rel) = i32::try_from(rel) else {
        return;
    };
    let mut jmp = [0xe9, 0, 0, 0, 0];
    jmp[1..].copy_from_slice(&rel.to_le_bytes());
    if let Some(prev) = unsafe { write5(target, jmp) } {
        PATCHES[n][0].store(target as u64, Relaxed);
        PATCHES[n][1].store(prev, Relaxed);
        PATCH_N.store(n + 1, Relaxed);
    }
}

/// Detours every timing export found. Returns the number of patched entry points.
#[unsafe(no_mangle)]
pub extern "C" fn hh_speedhack_hook() -> i32 {
    init();
    if INSTALLING.swap(1, Acquire) != 0 {
        return -1;
    }
    for m in modules() {
        let h = unsafe { GetModuleHandleW(m) };
        if h.is_null() {
            continue;
        }
        for &(name, kind) in TARGETS {
            // Forwarded exports resolve to the final function; `patch` skips duplicates.
            if let Some(f) = unsafe { GetProcAddress(h, name.as_ptr().cast()) } {
                unsafe { patch(f as usize, kind) };
            }
        }
    }
    let n = PATCH_N.load(Relaxed);
    HH_SPEEDHACK.hooks.store(n as u32, Relaxed);
    INSTALLING.store(0, Release);
    n as i32
}

/// Restores every patched entry point. Returns how many threads are still inside a hook;
/// unload only once that reaches 0. The relay pages stay allocated.
#[unsafe(no_mangle)]
pub extern "C" fn hh_speedhack_unhook() -> i64 {
    if INSTALLING.swap(1, Acquire) != 0 {
        return -1;
    }
    for p in PATCHES[..PATCH_N.load(Relaxed)].iter().rev() {
        let (at, orig) = (p[0].load(Relaxed) as usize, p[1].load(Relaxed).to_le_bytes());
        let mut b = [0u8; 5];
        b.copy_from_slice(&orig[..5]);
        unsafe { write5(at, b) };
    }
    PATCH_N.store(0, Relaxed);
    HH_SPEEDHACK.hooks.store(0, Relaxed);
    INSTALLING.store(0, Release);
    HH_SPEEDHACK.inflight.load(Acquire)
}

extern "C" fn init() {
    unsafe {
        let nt = GetModuleHandleW(w!("ntdll.dll"));
        if let Some(f) = GetProcAddress(nt, c"NtQueryPerformanceCounter".as_ptr().cast()) {
            let mut c = 0i64;
            let mut fq = 0i64;
            std::mem::transmute::<_, NtQueryPerformanceCounter>(f)(&mut c, &mut fq);
            if fq > 0 {
                FREQ.store(fq, Relaxed);
            }
            NT_QPC.store(f as usize, Relaxed);
        }
        if let Some(f) = GetProcAddress(nt, c"NtDelayExecution".as_ptr().cast()) {
            NT_DELAY.store(f as usize, Relaxed);
        }
    }
    HH_SPEEDHACK.magic.store(MAGIC, Release);
}

/// Runs at DLL load, like a C++ static initializer (the CRT walks `.CRT$XCU`).
#[used]
#[unsafe(link_section = ".CRT$XCU")]
static INIT: extern "C" fn() = init;
