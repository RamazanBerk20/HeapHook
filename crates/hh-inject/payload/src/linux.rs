//! Linux hooks. Two ways in:
//! - `LD_PRELOAD`: the exported functions below interpose libc's by symbol name.
//! - Runtime injection: `hh_speedhack_hook` (called by the host after `dlopen`) rewrites the
//!   GOT slots (`JUMP_SLOT` / `GLOB_DAT` relocations) naming these functions in every module
//!   loaded at that moment. Slots are pointer-sized aligned stores, so this is safe while
//!   other threads run. It misses modules loaded later, pointers fetched earlier with
//!   `dlsym`, libc-internal calls, static binaries, raw syscalls / vDSO calls and `rdtsc`.
//!
//! Real time comes straight from the vDSO (or the raw syscall), real sleeps and waits are raw
//! syscalls, so a hook never re-enters another hook.
// Casts between libc time types are kept for portability to targets where they differ.
#![allow(clippy::unnecessary_cast)]
use std::ffi::CStr;
use std::ptr::null_mut;
use std::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use std::sync::atomic::{AtomicU32, AtomicUsize};

use libc::{c_int, c_long, c_uint, c_void, clockid_t, time_t, timespec, timeval};

use crate::{Clock, HH_SPEEDHACK, InFlight, MAGIC};

const NS: i64 = 1_000_000_000;
/// Longest real nap inside a scaled sleep, so speed changes reach sleeping threads.
const SLICE: i64 = 50_000_000;

/// Clock ids 0..12; CPU-time clocks (2, 3) and the unused id 10 run at real speed.
static CLOCKS: [Clock; 12] = [
    Clock::new(false), // REALTIME
    Clock::new(true),  // MONOTONIC
    Clock::new(false),
    Clock::new(false),
    Clock::new(true),  // MONOTONIC_RAW
    Clock::new(false), // REALTIME_COARSE
    Clock::new(true),  // MONOTONIC_COARSE
    Clock::new(true),  // BOOTTIME
    Clock::new(false), // REALTIME_ALARM
    Clock::new(true),  // BOOTTIME_ALARM
    Clock::new(false),
    Clock::new(false), // TAI
];

fn scaled(id: clockid_t) -> Option<&'static Clock> {
    match id {
        0 | 1 | 4..=9 | 11 => CLOCKS.get(id as usize),
        _ => None,
    }
}

static VDSO_CLOCK_GETTIME: AtomicUsize = AtomicUsize::new(0);
type ClockGettime = unsafe extern "C" fn(clockid_t, *mut timespec) -> c_int;

fn real(id: clockid_t) -> i64 {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let f = VDSO_CLOCK_GETTIME.load(Relaxed);
    unsafe {
        if f == 0 || std::mem::transmute::<usize, ClockGettime>(f)(id, &mut ts) != 0 {
            libc::syscall(libc::SYS_clock_gettime, id, &mut ts);
        }
    }
    ts.tv_sec as i64 * NS + ts.tv_nsec as i64
}

fn ts(ns: i64) -> timespec {
    timespec {
        tv_sec: ns.div_euclid(NS) as time_t,
        tv_nsec: ns.rem_euclid(NS) as c_long,
    }
}

fn ns(t: &timespec) -> Option<i64> {
    (t.tv_sec >= 0 && (0..NS).contains(&(t.tv_nsec as i64)))
        .then(|| (t.tv_sec as i64).saturating_mul(NS).saturating_add(t.tv_nsec as i64))
}

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_errno(e: c_int) {
    unsafe { *libc::__errno_location() = e }
}

fn speed() -> f64 {
    CLOCKS[1].get(|| real(1)).1
}

/// Sleeps `dur` virtual ns on `id` (or until the virtual time `dur` if `abs`). Returns the
/// virtual ns left when a signal interrupted it.
fn virtual_sleep(id: clockid_t, c: &Clock, dur: i64, abs: bool) -> Option<i64> {
    let deadline = if abs {
        dur
    } else {
        c.get(|| real(id)).0.saturating_add(dur)
    };
    c.sleep_until(|| real(id), deadline, SLICE, |real_ns| {
        let t = ts(real_ns);
        unsafe {
            libc::syscall(
                libc::SYS_clock_nanosleep,
                libc::CLOCK_MONOTONIC,
                0,
                &t,
                null_mut::<timespec>(),
            ) == 0
                || errno() != libc::EINTR
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(id: clockid_t, tp: *mut timespec) -> c_int {
    let _g = InFlight::enter();
    match scaled(id) {
        Some(c) if !tp.is_null() => {
            unsafe { *tp = ts(c.get(|| real(id)).0) };
            0
        }
        _ => unsafe { libc::syscall(libc::SYS_clock_gettime, id, tp) as c_int },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettimeofday(tv: *mut timeval, tz: *mut c_void) -> c_int {
    let _g = InFlight::enter();
    let v = CLOCKS[0].get(|| real(0)).0;
    unsafe {
        if !tv.is_null() {
            *tv = timeval {
                tv_sec: v.div_euclid(NS) as time_t,
                tv_usec: (v.rem_euclid(NS) / 1000) as libc::suseconds_t,
            };
        }
        if !tz.is_null() {
            // struct timezone is obsolete; Linux reports zeros nowadays.
            *(tz as *mut [c_int; 2]) = [0, 0];
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(t: *mut time_t) -> time_t {
    let _g = InFlight::enter();
    let s = CLOCKS[0].get(|| real(0)).0.div_euclid(NS) as time_t;
    if !t.is_null() {
        unsafe { *t = s };
    }
    s
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_nanosleep(
    id: clockid_t,
    flags: c_int,
    req: *const timespec,
    rem: *mut timespec,
) -> c_int {
    let _g = InFlight::enter();
    let abs = flags & libc::TIMER_ABSTIME != 0;
    let (Some(c), Some(dur)) = (scaled(id), unsafe { req.as_ref() }.and_then(ns)) else {
        let r = unsafe { libc::syscall(libc::SYS_clock_nanosleep, id, flags, req, rem) };
        return if r == 0 { 0 } else { errno() };
    };
    match virtual_sleep(id, c, dur, abs) {
        None => 0,
        Some(left) => {
            if !abs && !rem.is_null() {
                unsafe { *rem = ts(left) };
            }
            libc::EINTR
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    let _g = InFlight::enter();
    let Some(dur) = unsafe { req.as_ref() }.and_then(ns) else {
        set_errno(if req.is_null() { libc::EFAULT } else { libc::EINVAL });
        return -1;
    };
    match virtual_sleep(1, &CLOCKS[1], dur, false) {
        None => 0,
        Some(left) => {
            if !rem.is_null() {
                unsafe { *rem = ts(left) };
            }
            set_errno(libc::EINTR);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn usleep(us: libc::useconds_t) -> c_int {
    let _g = InFlight::enter();
    match virtual_sleep(1, &CLOCKS[1], us as i64 * 1000, false) {
        None => 0,
        Some(_) => {
            set_errno(libc::EINTR);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sleep(s: c_uint) -> c_uint {
    let _g = InFlight::enter();
    match virtual_sleep(1, &CLOCKS[1], s as i64 * NS, false) {
        None => 0,
        // Like glibc: whole seconds left, rounded.
        Some(left) => ((left + NS / 2) / NS) as c_uint,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn poll(fds: *mut libc::pollfd, n: libc::nfds_t, timeout: c_int) -> c_int {
    let _g = InFlight::enter();
    let timeout = scale_ms(timeout);
    unsafe { libc::syscall(libc::SYS_poll, fds, n, timeout) as c_int }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_wait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    max: c_int,
    timeout: c_int,
) -> c_int {
    let _g = InFlight::enter();
    let timeout = scale_ms(timeout);
    unsafe { libc::syscall(libc::SYS_epoll_wait, epfd, events, max, timeout) as c_int }
}

/// A positive millisecond timeout in real time (rounded up so it never becomes 0 = poll).
fn scale_ms(ms: c_int) -> c_int {
    if ms <= 0 {
        return ms;
    }
    (ms as f64 / speed()).ceil().clamp(1.0, c_int::MAX as f64) as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    n: c_int,
    r: *mut libc::fd_set,
    w: *mut libc::fd_set,
    e: *mut libc::fd_set,
    tv: *mut timeval,
) -> c_int {
    let _g = InFlight::enter();
    let Some(t) = (unsafe { tv.as_mut() }) else {
        return unsafe { libc::syscall(libc::SYS_select, n, r, w, e, tv) as c_int };
    };
    let s = speed();
    let virt = t.tv_sec as i64 * 1_000_000 + t.tv_usec as i64;
    let real = (virt as f64 / s).ceil() as i64;
    let mut rt = timeval {
        tv_sec: (real / 1_000_000) as time_t,
        tv_usec: (real % 1_000_000) as libc::suseconds_t,
    };
    if virt <= 0 {
        rt = *t;
    }
    let ret = unsafe { libc::syscall(libc::SYS_select, n, r, w, e, &mut rt) as c_int };
    if virt > 0 {
        // Linux reports the time left; hand it back in virtual time.
        let left = ((rt.tv_sec as i64 * 1_000_000 + rt.tv_usec as i64) as f64 * s) as i64;
        let left = left.min(virt);
        *t = timeval {
            tv_sec: (left / 1_000_000) as time_t,
            tv_usec: (left % 1_000_000) as libc::suseconds_t,
        };
    }
    ret
}

// ---- runtime hooking: GOT slots -------------------------------------------------------

fn hooks() -> [(&'static CStr, usize); 11] {
    [
        (c"clock_gettime", clock_gettime as *const () as usize),
        (c"gettimeofday", gettimeofday as *const () as usize),
        (c"time", time as *const () as usize),
        (c"clock_nanosleep", clock_nanosleep as *const () as usize),
        (c"nanosleep", nanosleep as *const () as usize),
        (c"usleep", usleep as *const () as usize),
        (c"sleep", sleep as *const () as usize),
        (c"poll", poll as *const () as usize),
        (c"epoll_wait", epoll_wait as *const () as usize),
        (c"select", select as *const () as usize),
        // `__clock_gettime` is what some older binaries import.
        (c"__clock_gettime", clock_gettime as *const () as usize),
    ]
}

/// Patched slots: (slot address | 1 if it sits in RELRO, original value).
const MAX_SLOTS: usize = 1024;
static SAVED: [[AtomicUsize; 2]; MAX_SLOTS] = [const { [AtomicUsize::new(0), AtomicUsize::new(0)] }; MAX_SLOTS];
static SAVED_N: AtomicUsize = AtomicUsize::new(0);
/// Serializes hook/unhook calls (the host issues them one at a time anyway).
static INSTALLING: AtomicU32 = AtomicU32::new(0);

fn page() -> usize {
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        n if n > 0 => n as usize,
        _ => 4096,
    }
}

/// Writes `val` into the pointer slot `slot`; RELRO slots are made writable for the store.
unsafe fn store_slot(slot: usize, val: usize, relro: bool) -> bool {
    let pg = slot & !(page() - 1);
    unsafe {
        if relro
            && libc::mprotect(
                pg as *mut c_void,
                page(),
                libc::PROT_READ | libc::PROT_WRITE,
            ) != 0
        {
            return false;
        }
        AtomicUsize::from_ptr(slot as *mut usize).store(val, Release);
        if relro {
            libc::mprotect(pg as *mut c_void, page(), libc::PROT_READ);
        }
    }
    true
}

#[repr(C)]
struct Dyn {
    tag: i64,
    val: u64,
}

#[repr(C)]
struct Rela {
    offset: u64,
    info: u64,
    addend: i64,
}

const DT_PLTRELSZ: i64 = 2;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_JMPREL: i64 = 23;
const R_X86_64_GLOB_DAT: u64 = 6;
const R_X86_64_JUMP_SLOT: u64 = 7;

unsafe extern "C" fn patch_module(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    _data: *mut c_void,
) -> c_int {
    let info = unsafe { &*info };
    let base = info.dlpi_addr as usize;
    let phdrs = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
    let own = std::ptr::addr_of!(HH_SPEEDHACK) as usize;
    if phdrs.iter().any(|p| {
        p.p_type == libc::PT_LOAD
            && (base + p.p_vaddr as usize..base + (p.p_vaddr + p.p_memsz) as usize).contains(&own)
    }) {
        return 0; // never hook ourselves
    }
    // The range ld.so made read-only after relocation (both ends rounded down to pages).
    let relro = phdrs
        .iter()
        .find(|p| p.p_type == libc::PT_GNU_RELRO)
        .map(|p| {
            let (s, e) = (base + p.p_vaddr as usize, base + (p.p_vaddr + p.p_memsz) as usize);
            (s & !(page() - 1))..(e & !(page() - 1))
        })
        .unwrap_or(0..0);
    let Some(dynamic) = phdrs.iter().find(|p| p.p_type == libc::PT_DYNAMIC) else {
        return 0;
    };
    // glibc relocates these pointers in place; the vDSO's are still offsets.
    let fix = |p: u64| {
        if (p as usize) < base {
            p as usize + base
        } else {
            p as usize
        }
    };
    let (mut symtab, mut strtab) = (0, 0);
    let mut tables = [(0usize, 0usize); 2];
    let mut d = (base + dynamic.p_vaddr as usize) as *const Dyn;
    unsafe {
        while (*d).tag != 0 {
            let v = (*d).val;
            match (*d).tag {
                DT_SYMTAB => symtab = fix(v),
                DT_STRTAB => strtab = fix(v),
                DT_RELA => tables[0].0 = fix(v),
                DT_RELASZ => tables[0].1 = v as usize,
                DT_JMPREL => tables[1].0 = fix(v),
                DT_PLTRELSZ => tables[1].1 = v as usize,
                _ => {}
            }
            d = d.add(1);
        }
    }
    if symtab == 0 || strtab == 0 {
        return 0;
    }
    let hooks = hooks();
    for (rel, size) in tables {
        if rel == 0 {
            continue;
        }
        let rels =
            unsafe { std::slice::from_raw_parts(rel as *const Rela, size / size_of::<Rela>()) };
        for r in rels {
            let (ty, sym) = (r.info & 0xffff_ffff, (r.info >> 32) as usize);
            if (ty != R_X86_64_JUMP_SLOT && ty != R_X86_64_GLOB_DAT) || sym == 0 {
                continue;
            }
            let s = unsafe { &*(symtab as *const libc::Elf64_Sym).add(sym) };
            let name = unsafe { CStr::from_ptr((strtab + s.st_name as usize) as *const _) };
            let Some(&(_, hook)) = hooks.iter().find(|(n, _)| *n == name) else {
                continue;
            };
            let slot = base + r.offset as usize;
            let cur = unsafe { AtomicUsize::from_ptr(slot as *mut usize).load(Acquire) };
            let n = SAVED_N.load(Relaxed);
            if cur == hook || n == MAX_SLOTS {
                continue;
            }
            let in_relro = relro.contains(&slot);
            SAVED[n][0].store(slot | in_relro as usize, Relaxed);
            SAVED[n][1].store(cur, Relaxed);
            if unsafe { store_slot(slot, hook, in_relro) } {
                SAVED_N.store(n + 1, Relaxed);
            }
        }
    }
    0
}

/// Points every GOT slot naming a hooked function at the hook. Returns the number of
/// slots hooked so far. Called by the host (remote call) after injecting the library.
#[unsafe(no_mangle)]
pub extern "C" fn hh_speedhack_hook() -> c_int {
    init();
    if INSTALLING.swap(1, Acquire) != 0 {
        return -1;
    }
    unsafe { libc::dl_iterate_phdr(Some(patch_module), null_mut()) };
    let n = SAVED_N.load(Relaxed);
    HH_SPEEDHACK.hooks.store(n as u32, Relaxed);
    INSTALLING.store(0, Release);
    n as c_int
}

/// Puts back every slot this library patched (unless someone re-patched it since).
/// Returns how many threads are still inside a hook; unload only once that reaches 0.
#[unsafe(no_mangle)]
pub extern "C" fn hh_speedhack_unhook() -> i64 {
    if INSTALLING.swap(1, Acquire) != 0 {
        return -1;
    }
    let hooks = hooks();
    for e in SAVED[..SAVED_N.load(Relaxed)].iter().rev() {
        let (tagged, orig) = (e[0].load(Relaxed), e[1].load(Relaxed));
        let slot = tagged & !1;
        let cur = unsafe { AtomicUsize::from_ptr(slot as *mut usize).load(Acquire) };
        if hooks.iter().any(|&(_, h)| h == cur) {
            unsafe { store_slot(slot, orig, tagged & 1 != 0) };
        }
    }
    SAVED_N.store(0, Relaxed);
    HH_SPEEDHACK.hooks.store(0, Relaxed);
    INSTALLING.store(0, Release);
    HH_SPEEDHACK.inflight.load(Acquire)
}

// ---- initializer ----------------------------------------------------------------------

/// Address of an exported vDSO function, found through the vDSO's section headers.
fn vdso_symbol(name: &CStr) -> usize {
    unsafe {
        let base = libc::getauxval(libc::AT_SYSINFO_EHDR) as usize;
        if base == 0 {
            return 0;
        }
        let eh = &*(base as *const libc::Elf64_Ehdr);
        let phdrs = std::slice::from_raw_parts(
            (base + eh.e_phoff as usize) as *const libc::Elf64_Phdr,
            eh.e_phnum as usize,
        );
        let Some(load) = phdrs.iter().find(|p| p.p_type == libc::PT_LOAD) else {
            return 0;
        };
        let bias = base.wrapping_sub(load.p_vaddr as usize);
        let shdrs = std::slice::from_raw_parts(
            (base + eh.e_shoff as usize) as *const libc::Elf64_Shdr,
            eh.e_shnum as usize,
        );
        for sh in shdrs.iter().filter(|s| s.sh_type == 11 /* SHT_DYNSYM */) {
            let Some(strs) = shdrs.get(sh.sh_link as usize) else {
                continue;
            };
            let syms = std::slice::from_raw_parts(
                (base + sh.sh_offset as usize) as *const libc::Elf64_Sym,
                sh.sh_size as usize / size_of::<libc::Elf64_Sym>(),
            );
            for s in syms {
                let n = CStr::from_ptr((base + strs.sh_offset as usize + s.st_name as usize) as *const _);
                if s.st_shndx != 0 && n == name {
                    return bias.wrapping_add(s.st_value as usize);
                }
            }
        }
        0
    }
}

extern "C" fn init() {
    if VDSO_CLOCK_GETTIME.load(Relaxed) == 0 {
        VDSO_CLOCK_GETTIME.store(vdso_symbol(c"__vdso_clock_gettime"), Relaxed);
    }
    HH_SPEEDHACK.magic.store(MAGIC, Release);
}

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: extern "C" fn() = init;
