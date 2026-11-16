//! hh-debug-target: test target for hh-debug's integration tests.
//!
//! On start it prints one JSON line with hex addresses:
//! `{"pid":N,"store":"0x..","load":"0x..","outer":"0x..","value":"0x..","value2":"0x.."}`
//! - `store(p, v)`: `mov [rdi], rsi` (48 89 37, the first 3 bytes) then `ret`.
//! - `load(p)`: `mov rax, [rdi]` (48 8b 07) then `ret`.
//! - `outer(p, v)`: `nop; call store; nop; ret` (offsets 0, 1, 6, 7).
//!
//! `value` starts at 100 and `value2` at 200. Commands, one per line, each answered with
//! `ok <value> <value2>`:
//! `store` (value += 1 via store), `store2` (value2 += 1 via store), `load` (reads value
//! via load), `outer` (value += 1 via outer), `spawn` (a new thread does value2 += 1 via
//! store; joined), `dlopen <lib>` (Linux), `quit`. EOF also exits.
use std::io::{BufRead, Write};

#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    ".globl hh_store",
    "hh_store:",
    "mov qword ptr [rdi], rsi",
    "ret",
    ".globl hh_load",
    "hh_load:",
    "mov rax, qword ptr [rdi]",
    "ret",
    ".globl hh_outer",
    "hh_outer:",
    "nop",
    "call hh_store",
    "nop",
    "ret",
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn hh_store(p: *mut u64, v: u64);
    fn hh_load(p: *const u64) -> u64;
    fn hh_outer(p: *mut u64, v: u64);
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn dlopen(name: *const std::ffi::c_char, flags: i32) -> *mut std::ffi::c_void;
}

#[cfg(target_arch = "x86_64")]
fn main() {
    let value: &'static mut u64 = Box::leak(Box::new(100));
    let value2: &'static mut u64 = Box::leak(Box::new(200));
    let (v, v2) = (value as *mut u64 as usize, value2 as *mut u64 as usize);
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        r#"{{"pid":{},"store":"{:#x}","load":"{:#x}","outer":"{:#x}","value":"{v:#x}","value2":"{v2:#x}"}}"#,
        std::process::id(),
        hh_store as *const () as usize,
        hh_load as *const () as usize,
        hh_outer as *const () as usize,
    )
    .unwrap();
    out.flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let (p, p2) = (v as *mut u64, v2 as *mut u64);
        unsafe {
            match line.trim() {
                "quit" => break,
                "store" => hh_store(p, hh_load(p) + 1),
                "store2" => hh_store(p2, hh_load(p2) + 1),
                "load" => {
                    hh_load(p);
                }
                "outer" => hh_outer(p, hh_load(p) + 1),
                "spawn" => std::thread::spawn(move || {
                    let p2 = v2 as *mut u64;
                    hh_store(p2, hh_load(p2) + 1)
                })
                .join()
                .unwrap(),
                #[cfg(target_os = "linux")]
                l if l.starts_with("dlopen ") => {
                    let name = std::ffi::CString::new(&l[7..]).unwrap();
                    dlopen(name.as_ptr(), 2); // RTLD_NOW
                }
                _ => {
                    writeln!(out, "error").unwrap();
                    out.flush().unwrap();
                    continue;
                }
            }
            writeln!(out, "ok {} {}", hh_load(p), hh_load(p2)).unwrap();
        }
        out.flush().unwrap();
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("hh-debug-target only supports x86_64");
}
