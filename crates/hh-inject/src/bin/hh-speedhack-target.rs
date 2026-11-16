//! Test target for the speedhack (Linux). Prints `ready`, then answers stdin commands, one
//! line each:
//! - `clocks` -> `<CLOCK_MONOTONIC ns> <CLOCK_REALTIME ns> <gettimeofday us>`
//! - `nanosleep <ms>` / `usleep <ms>` -> monotonic ns the sleep appeared to take
//! - `stats` -> `<calls> <backwards>` of the second thread, which keeps calling all three
//!   clocks and counts monotonic readings that went backwards
//! - `quit` -> exits 0
#[cfg(target_os = "linux")]
fn main() {
    use std::io::BufRead;
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    fn clock(id: libc::clockid_t) -> i64 {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(id, &mut t) };
        t.tv_sec * 1_000_000_000 + t.tv_nsec
    }
    fn tod() -> i64 {
        let mut t = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        unsafe { libc::gettimeofday(&mut t, std::ptr::null_mut()) };
        t.tv_sec * 1_000_000 + t.tv_usec
    }
    let mono = || clock(libc::CLOCK_MONOTONIC);

    static CALLS: AtomicU64 = AtomicU64::new(0);
    static BACKWARDS: AtomicU64 = AtomicU64::new(0);
    std::thread::spawn(move || {
        let mut last = i64::MIN;
        loop {
            let m = mono();
            std::hint::black_box((clock(libc::CLOCK_REALTIME), tod()));
            if m < last {
                BACKWARDS.fetch_add(1, Relaxed);
            }
            last = m;
            CALLS.fetch_add(1, Relaxed);
        }
    });

    println!("ready");
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let mut w = line.split_whitespace();
        let ms: i64 = w.clone().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        match w.next() {
            Some("clocks") => println!("{} {} {}", mono(), clock(libc::CLOCK_REALTIME), tod()),
            Some("nanosleep") => {
                let t = libc::timespec {
                    tv_sec: ms / 1000,
                    tv_nsec: ms % 1000 * 1_000_000,
                };
                let t0 = mono();
                unsafe { libc::nanosleep(&t, std::ptr::null_mut()) };
                println!("{}", mono() - t0);
            }
            Some("usleep") => {
                let t0 = mono();
                unsafe { libc::usleep(ms as libc::useconds_t * 1000) };
                println!("{}", mono() - t0);
            }
            Some("stats") => println!("{} {}", CALLS.load(Relaxed), BACKWARDS.load(Relaxed)),
            Some("quit") => return,
            _ => println!("error"),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hh-speedhack-target only runs on Linux");
    std::process::exit(2);
}
