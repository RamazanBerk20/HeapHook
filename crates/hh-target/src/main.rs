//! hh-target: a process with known values for HeapHook tests to scan, read and write.
//!
//! Protocol (line based, stdin/stdout):
//! - On start it prints ONE line of JSON with the addresses (hex strings) of its values:
//!   `{"pid":N,"i32":"0x..","i64":"0x..","f32":"0x..","f64":"0x..","str":"0x..","str16":"0x..",
//!     "aob":"0x..","chain":"0x..","chain_offsets":["0x10","0x18","0x8"],"chain_value":"0x.."}`
//!   `chain` is the address of the base pointer; the value lives at `[[[chain]+o1]+o2]+o3`
//!   (Cheat Engine notation). The base pointer lives in a static of the executable (so it is
//!   reachable as "hh-target"+offset); the three hops point into separate heap allocations.
//!   Offsets are byte offsets and assume the target's pointer width (8 on 64-bit, 4 on 32-bit).
//! - Initial values: i32 = 123456, i64 = 1234567890123, f32 = 3.5, f64 = 2.25,
//!   str = "HeapHook test string" (UTF-8, NUL padded), str16 = "HeapHook UTF-16 string" (UTF-16LE),
//!   aob = DE AD BE EF 13 37 C0 DE, chain value (i32) = 4242.
//! - Then it reads commands, one per line, and answers each with one JSON line of the current
//!   numeric values: `{"i32":..,"i64":..,"f32":..,"f64":..,"chain_value":..}`.
//!   `get`  – just report;  `inc` – add 1 to every numeric value, then report;  `quit` – exit.
//!   EOF on stdin also exits. Unknown commands get `{"error":"unknown command"}`.
//! - It also starts one idle extra thread, so the process has two threads.
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::ptr::{addr_of_mut, read_volatile as rd, write_volatile as wr};

#[repr(C)]
struct Values {
    i32_: i32,
    i64_: i64,
    f32_: f32,
    f64_: f64,
    text: [u8; 32],
    text16: [u16; 32],
    aob: [u8; 8],
}

/// The chain base pointer, in the executable's static storage.
static CHAIN: AtomicPtr<usize> = AtomicPtr::new(std::ptr::null_mut());

const W: usize = size_of::<usize>();
// Pointer slots used at each hop: offsets are index * pointer width.
const HOP1: usize = 2;
const HOP2: usize = 3;
const HOP3: usize = 1;

fn leak<T>(v: T) -> *mut T {
    Box::into_raw(Box::new(v))
}

fn main() {
    let mut text = [0u8; 32];
    let s = "HeapHook test string";
    text[..s.len()].copy_from_slice(s.as_bytes());
    let mut text16 = [0u16; 32];
    for (d, c) in text16
        .iter_mut()
        .zip("HeapHook UTF-16 string".encode_utf16())
    {
        *d = c;
    }

    // value lives at l3 + HOP3*W; l3 is stored at l2[HOP2], l2 at l1[HOP1], l1 at v.chain.
    let l3 = leak([0usize; 4]);
    let value = unsafe { l3.cast::<u8>().add(HOP3 * W).cast::<i32>() };
    unsafe { wr(value, 4242) };
    let l2 = leak([0usize; 4]);
    unsafe { (*l2)[HOP2] = l3 as usize };
    let l1 = leak([0usize; 4]);
    unsafe { (*l1)[HOP1] = l2 as usize };

    let v = leak(Values {
        i32_: 123456,
        i64_: 1234567890123,
        f32_: 3.5,
        f64_: 2.25,
        text,
        text16,
        aob: [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE],
    });
    CHAIN.store(l1.cast(), Ordering::Relaxed);

    std::thread::spawn(|| {
        loop {
            std::thread::park();
        }
    });

    let mut out = std::io::stdout().lock();
    unsafe {
        writeln!(
            out,
            r#"{{"pid":{},"i32":"{:#x}","i64":"{:#x}","f32":"{:#x}","f64":"{:#x}","str":"{:#x}","str16":"{:#x}","aob":"{:#x}","chain":"{:#x}","chain_offsets":["{:#x}","{:#x}","{:#x}"],"chain_value":"{:#x}"}}"#,
            std::process::id(),
            addr_of_mut!((*v).i32_) as usize,
            addr_of_mut!((*v).i64_) as usize,
            addr_of_mut!((*v).f32_) as usize,
            addr_of_mut!((*v).f64_) as usize,
            addr_of_mut!((*v).text) as usize,
            addr_of_mut!((*v).text16) as usize,
            addr_of_mut!((*v).aob) as usize,
            CHAIN.as_ptr() as usize,
            HOP1 * W,
            HOP2 * W,
            HOP3 * W,
            value as usize,
        )
        .unwrap();
    }
    out.flush().unwrap();

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        // Volatile access: another process changes these behind the compiler's back.
        unsafe {
            match line.trim() {
                "quit" => break,
                "get" => {}
                "inc" => {
                    wr(
                        addr_of_mut!((*v).i32_),
                        rd(addr_of_mut!((*v).i32_)).wrapping_add(1),
                    );
                    wr(
                        addr_of_mut!((*v).i64_),
                        rd(addr_of_mut!((*v).i64_)).wrapping_add(1),
                    );
                    wr(addr_of_mut!((*v).f32_), rd(addr_of_mut!((*v).f32_)) + 1.0);
                    wr(addr_of_mut!((*v).f64_), rd(addr_of_mut!((*v).f64_)) + 1.0);
                    wr(value, rd(value).wrapping_add(1));
                }
                _ => {
                    writeln!(out, r#"{{"error":"unknown command"}}"#).unwrap();
                    out.flush().unwrap();
                    continue;
                }
            }
            writeln!(
                out,
                r#"{{"i32":{},"i64":{},"f32":{:?},"f64":{:?},"chain_value":{}}}"#,
                rd(addr_of_mut!((*v).i32_)),
                rd(addr_of_mut!((*v).i64_)),
                rd(addr_of_mut!((*v).f32_)),
                rd(addr_of_mut!((*v).f64_)),
                rd(value),
            )
            .unwrap();
        }
        out.flush().unwrap();
    }
}
