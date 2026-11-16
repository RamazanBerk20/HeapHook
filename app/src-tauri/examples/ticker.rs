//! A target for driving the real UI by hand (`cargo build -p heaphook --example ticker`):
//! values that change by themselves, so it works when launched by "Create process" (whose
//! stdin is not a terminal you hold).
//!
//! - `health` (i32) = 100, only changes when you write it; `ticks` (i32) +1 every 500 ms,
//!   written by `tick()` (a target for "find what writes"); `speed` (f32) = 1.5,
//!   `gold` (f64) = 250.75, `name` = "TickerHero" (UTF-8), `name16` (UTF-16LE),
//!   `magic` = AOB 11 22 33 44 55 66 77 88; `level` (i32) = 7 behind a static pointer chain
//!   `[[CHAIN]+0x10]+0x8`; `zeros`: 4M i32 (16 MiB) of 0 for scans with millions of results.
//! - Prints one JSON line with the addresses and writes it to the file given as the first
//!   argument, if any.
use std::hint::black_box;
use std::ptr::{read_volatile as rd, write_volatile as wr};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::Duration;

#[repr(C)]
struct Values {
    health: i32,
    ticks: i32,
    speed: f32,
    gold: f64,
    name: [u8; 16],
    name16: [u16; 16],
    magic: [u8; 8],
}

static CHAIN: AtomicPtr<usize> = AtomicPtr::new(std::ptr::null_mut());

#[inline(never)]
fn tick(v: *mut Values) {
    // SAFETY: `v` is the leaked Values below.
    unsafe { wr(&mut (*v).ticks, rd(&(*v).ticks) + 1) }
}

fn main() {
    let mut name16 = [0u16; 16];
    for (d, c) in name16.iter_mut().zip("TickerHero16".encode_utf16()) {
        *d = c;
    }
    let mut name = [0u8; 16];
    name[..10].copy_from_slice(b"TickerHero");
    let v: *mut Values = Box::leak(Box::new(Values {
        health: 100,
        ticks: 0,
        speed: 1.5,
        gold: 250.75,
        name,
        name16,
        magic: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    }));
    let level: &'static mut i32 = Box::leak(Box::new(7));
    let hop2: &'static mut [usize; 4] = Box::leak(Box::new([0; 4]));
    hop2[1] = level as *mut i32 as usize; // +0x8
    let hop1: &'static mut [usize; 4] = Box::leak(Box::new([0; 4]));
    hop1[2] = hop2.as_ptr() as usize; // +0x10
    CHAIN.store(hop1.as_mut_ptr(), Ordering::SeqCst);
    let zeros: &'static mut [i32] = Box::leak(vec![0i32; 4 << 20].into_boxed_slice());
    // Touch every page so the zeros are real, readable memory.
    for i in (0..zeros.len()).step_by(1024) {
        // SAFETY: in bounds.
        unsafe { wr(zeros.as_mut_ptr().add(i), 0) };
    }

    // SAFETY: plain field addresses of the leaked Values.
    let a = |p: *const u8| format!("{:#x}", p as usize);
    let line = unsafe {
        format!(
            r#"{{"pid":{},"health":"{}","ticks":"{}","speed":"{}","gold":"{}","name":"{}","name16":"{}","magic":"{}","chain":"{}","level":"{}","zeros":"{}","tick":"{}"}}"#,
            std::process::id(),
            a(&raw const (*v).health as _),
            a(&raw const (*v).ticks as _),
            a(&raw const (*v).speed as _),
            a(&raw const (*v).gold as _),
            a(&raw const (*v).name as _),
            a(&raw const (*v).name16 as _),
            a(&raw const (*v).magic as _),
            a(CHAIN.as_ptr() as _),
            a(level as *const i32 as _),
            a(zeros.as_ptr() as _),
            a(tick as *const u8),
        )
    };
    println!("{line}");
    if let Some(path) = std::env::args().nth(1) {
        let _ = std::fs::write(path, &line);
    }
    let _idle = std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_secs(1));
    });
    let started = std::time::Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        tick(black_box(v));
        // Exit after an hour so a forgotten target does not linger forever.
        if started.elapsed() > Duration::from_secs(3600) {
            break;
        }
    }
}
