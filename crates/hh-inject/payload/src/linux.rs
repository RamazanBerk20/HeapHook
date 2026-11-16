//! Linux hooks: loaded through `LD_PRELOAD`, the exported functions below interpose libc's
//! by symbol name.
//!
//! Real time comes straight from the vDSO (or the raw syscall), real sleeps and waits are raw
//! syscalls, so a hook never re-enters another hook.
// Casts between libc time types are kept for portability to targets where they differ.
#![allow(clippy::unnecessary_cast)]
#[cfg(not(target_arch = "x86_64"))]
compile_error!("the speedhack payload supports x86-64 only (the vDSO lookup reads Elf64 structures)");
use std::ffi::CStr;
use std::ptr::null_mut;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::{Relaxed, Release};

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
    (ts.tv_sec as i64).saturating_mul(NS).saturating_add(ts.tv_nsec as i64)
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
    match virtual_sleep(1, &CLOCKS[1], (us as i64).saturating_mul(1000), false) {
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
    match virtual_sleep(1, &CLOCKS[1], (s as i64).saturating_mul(NS), false) {
        None => 0,
        // Like glibc: whole seconds left, rounded.
        Some(left) => (left.saturating_add(NS / 2) / NS) as c_uint,
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

/// A timeval in µs, saturating (a timeout of years must not overflow).
fn usecs(t: &timeval) -> i64 {
    (t.tv_sec as i64).saturating_mul(1_000_000).saturating_add(t.tv_usec as i64)
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
    let virt = usecs(t);
    // Float-to-int casts saturate, so a huge timeout stays huge instead of overflowing.
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
        let left = (usecs(&rt) as f64 * s) as i64;
        let left = left.min(virt);
        *t = timeval {
            tv_sec: (left / 1_000_000) as time_t,
            tv_usec: (left % 1_000_000) as libc::suseconds_t,
        };
    }
    ret
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_conversions_saturate() {
        let huge = timeval { tv_sec: time_t::MAX, tv_usec: 999_999 };
        assert_eq!(usecs(&huge), i64::MAX);
        assert_eq!(usecs(&timeval { tv_sec: 2, tv_usec: 5 }), 2_000_005);
        let t = timespec { tv_sec: time_t::MAX, tv_nsec: 0 };
        assert_eq!(ns(&t), Some(i64::MAX));
    }
}
