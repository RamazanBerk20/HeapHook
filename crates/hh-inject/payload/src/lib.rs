//! HeapHook speedhack payload: a library loaded into the target that scales the target's
//! view of time. The supported route is Linux `LD_PRELOAD` at launch (`hh_inject::launch`);
//! the runtime-hook entry points in `linux.rs` / `windows.rs` are not used by the host.
//! The host finds the exported [`HH_SPEEDHACK`] control block in the target and
//! writes `speed` then bumps `generation`; every hooked clock notices the new generation on
//! its next call and rebases (virtual = base_virt + (real - base_real) * speed), so time stays
//! continuous across changes. Each clock rebases lazily, so the real time between the host's
//! write and a clock's next read still counts at the old speed.
//! Before the first change every clock is the identity (virtual == real).
//!
//! Hooks never allocate, lock, touch TLS or call a hooked function (real time comes from
//! the vDSO or a raw syscall), so they are async-signal-safe, thread-safe and safe to run
//! before the initializer (they fall back to raw syscalls until it has found the vDSO).
//! A rebase is a try-lock: a thread (or signal handler) that loses keeps the old record.
//!
//! fork: the child gets a copy of the current state (same speed) and its own control block;
//! in the rare case it forks while another thread is mid-rebase, the child's clock keeps its
//! speed forever. exec: `LD_PRELOAD` is inherited, so exec'd children (e.g. a launcher
//! script's game binary) load the payload too, starting at speed 1.0 with their own block.
//!
//! Not affected (see `linux.rs`): code that reads time without going through the dynamic
//! symbols above, i.e. raw `syscall` instructions, direct calls into the vDSO (e.g. Go
//! binaries), static binaries, `rdtsc`, libc-internal calls (`timespec_get`, `clock`,
//! `pthread_cond_timedwait`, `sem_timedwait`, `ppoll`, `pselect`, `epoll_pwait`, futex
//! timeouts), and setuid programs (the loader ignores `LD_PRELOAD` there). Sleeps here are
//! not pthread cancellation points.
//!
//! Layout of [`Control`] is shared with `hh-inject` (`src/lib.rs`, `OFF_*`); keep them in sync.
use std::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, fence};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// "HHSH": set by the library initializer, so the host can tell the payload is live.
pub const MAGIC: u32 = 0x4853_4848;

#[repr(C)]
pub struct Control {
    /// [`MAGIC`] once the initializer ran.
    pub magic: AtomicU32,
    /// Layout version (1).
    pub version: AtomicU32,
    /// Bumped by the host after every write of `speed`.
    pub generation: AtomicU32,
    /// Number of hooks currently installed.
    pub hooks: AtomicU32,
    /// Requested speed as f64 bits.
    pub speed: AtomicU64,
    /// Threads currently executing inside a hook (the host waits for 0 before unloading).
    pub inflight: AtomicI64,
}

#[unsafe(no_mangle)]
pub static HH_SPEEDHACK: Control = Control {
    magic: AtomicU32::new(0),
    version: AtomicU32::new(1),
    generation: AtomicU32::new(0),
    hooks: AtomicU32::new(0),
    speed: AtomicU64::new(0x3ff0_0000_0000_0000), // 1.0
    inflight: AtomicI64::new(0),
};

/// Counts a thread as inside a hook for as long as it lives.
pub(crate) struct InFlight;

impl InFlight {
    pub(crate) fn enter() -> Self {
        HH_SPEEDHACK.inflight.fetch_add(1, Relaxed);
        InFlight
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        HH_SPEEDHACK.inflight.fetch_sub(1, Release);
    }
}

const RING: u64 = 8;

/// One scaled clock. Readers never wait: the record in use is published through `seq` and
/// lives in a small ring, so a rebase never overwrites a record a reader may be copying.
pub(crate) struct Clock {
    /// Index of the current record (it is `recs[seq % RING]`).
    seq: AtomicU64,
    /// (base_real, base_virt, speed bits).
    recs: [[AtomicU64; 3]; RING as usize],
    /// Rebase try-lock; a thread that loses just keeps using the old record.
    busy: AtomicU32,
    /// Generation of the control block this clock has applied.
    generation: AtomicU32,
    /// Highest value handed out, for clocks that must never go backwards.
    last: AtomicI64,
    monotonic: bool,
}

#[derive(Clone, Copy)]
struct Rec {
    real: i64,
    virt: i64,
    speed: f64,
}

impl Rec {
    fn at(&self, real: i64) -> i64 {
        self.virt
            .wrapping_add((real.wrapping_sub(self.real) as f64 * self.speed) as i64)
    }
}

impl Clock {
    pub(crate) const fn new(monotonic: bool) -> Self {
        Clock {
            seq: AtomicU64::new(0),
            recs: [const {
                [
                    AtomicU64::new(0),
                    AtomicU64::new(0),
                    AtomicU64::new(0x3ff0_0000_0000_0000),
                ]
            }; RING as usize],
            busy: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            last: AtomicI64::new(i64::MIN),
            monotonic,
        }
    }

    /// Sets the first record (before any reader exists): virtual `virt` at real `real`.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn init(&self, real: i64, virt: i64) {
        let r = &self.recs[0];
        r[0].store(real as u64, Relaxed);
        r[1].store(virt as u64, Relaxed);
        self.seq.store(0, Release);
    }

    fn load(&self) -> Rec {
        loop {
            let i = self.seq.load(Acquire);
            let r = &self.recs[(i % RING) as usize];
            let rec = Rec {
                real: r[0].load(Relaxed) as i64,
                virt: r[1].load(Relaxed) as i64,
                speed: f64::from_bits(r[2].load(Relaxed)),
            };
            fence(Acquire);
            // The writer only reuses this slot RING-1 rebases later.
            if self.seq.load(Relaxed).wrapping_sub(i) < RING - 1 {
                return rec;
            }
        }
    }

    fn rebase_if_needed(&self, now: &impl Fn() -> i64) {
        let g = HH_SPEEDHACK.generation.load(Acquire);
        if g == self.generation.load(Relaxed)
            || self
                .busy
                .compare_exchange(0, 1, Acquire, Relaxed)
                .is_err()
        {
            return;
        }
        if g != self.generation.load(Relaxed) {
            let speed = f64::from_bits(HH_SPEEDHACK.speed.load(Acquire));
            if speed.is_finite() && speed > 0.0 {
                let real = now();
                let mut virt = self.load().at(real);
                if self.monotonic {
                    virt = virt.max(self.last.load(Relaxed));
                }
                let i = self.seq.load(Relaxed).wrapping_add(1);
                // Seqlock writer side: a reader that sees any of the stores below must also
                // see the previous `seq` store, so its validity check in `load` holds.
                fence(Release);
                let r = &self.recs[(i % RING) as usize];
                r[0].store(real as u64, Relaxed);
                r[1].store(virt as u64, Relaxed);
                r[2].store(speed.to_bits(), Relaxed);
                self.seq.store(i, Release);
            }
            self.generation.store(g, Relaxed);
        }
        self.busy.store(0, Release);
    }

    /// Current virtual time and speed; `now` reads the real clock in the same unit.
    pub(crate) fn get(&self, now: impl Fn() -> i64) -> (i64, f64) {
        self.rebase_if_needed(&now);
        let rec = self.load();
        let mut v = rec.at(now());
        if self.monotonic {
            // A thread that lost the rebase race may have handed out a slightly later value.
            v = v.max(self.last.fetch_max(v, Relaxed));
        }
        (v, rec.speed)
    }

    /// Sleeps until this clock reaches virtual `deadline`, in real naps of at most `slice`
    /// (so speed changes apply to long sleeps). `nap(real)` returns false when interrupted;
    /// then the virtual time still left is returned.
    pub(crate) fn sleep_until(
        &self,
        now: impl Fn() -> i64,
        deadline: i64,
        slice: i64,
        mut nap: impl FnMut(i64) -> bool,
    ) -> Option<i64> {
        loop {
            let (v, speed) = self.get(&now);
            let left = deadline.saturating_sub(v);
            if left <= 0 {
                return None;
            }
            let real = ((left as f64 / speed).ceil() as i64).clamp(1, slice);
            if !nap(real) {
                return Some(deadline.saturating_sub(self.get(&now).0).max(0));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn rebase_is_continuous_and_monotonic() {
        let real = Cell::new(1_000i64);
        let c = Clock::new(true);
        let now = || real.get();
        assert_eq!(c.get(now).0, 1_000); // identity until the first change
        HH_SPEEDHACK.speed.store(2.0f64.to_bits(), Relaxed);
        HH_SPEEDHACK.generation.fetch_add(1, Release);
        real.set(2_000);
        assert_eq!(c.get(now), (2_000, 2.0));
        real.set(3_000);
        assert_eq!(c.get(now).0, 4_000);
        HH_SPEEDHACK.speed.store(0.5f64.to_bits(), Relaxed);
        HH_SPEEDHACK.generation.fetch_add(1, Release);
        real.set(3_000);
        assert_eq!(c.get(now).0, 4_000);
        real.set(5_000);
        assert_eq!(c.get(now).0, 5_000);
        // Real clock stepping back: the monotonic clock holds still instead.
        real.set(4_000);
        assert_eq!(c.get(now).0, 5_000);
        // A bad speed is ignored.
        HH_SPEEDHACK.speed.store(f64::NAN.to_bits(), Relaxed);
        HH_SPEEDHACK.generation.fetch_add(1, Release);
        real.set(6_000);
        assert_eq!(c.get(now), (5_500, 0.5));
        let mut naps = 0;
        let left = c.sleep_until(now, 5_600, 50, |r| {
            naps += 1;
            real.set(real.get() + r);
            true
        });
        assert_eq!((left, naps), (None, 4)); // 200 real at 0.5x, in 50-unit slices
        HH_SPEEDHACK.speed.store(1.0f64.to_bits(), Relaxed);
        HH_SPEEDHACK.generation.fetch_add(1, Release);
    }
}
