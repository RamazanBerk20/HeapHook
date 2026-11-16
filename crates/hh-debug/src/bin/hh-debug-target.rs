//! hh-debug-target: test target for hh-debug's integration tests.
//!
//! On start it prints one JSON line with hex addresses:
//! `{"pid":N,"store":"0x..","load":"0x..","outer":"0x..","value":"0x..","value2":"0x..",...}`
//! - `store(p, v)`: `mov [rdi], rsi` (48 89 37, the first 3 bytes) then `ret`.
//! - `load(p)`: `mov rax, [rdi]` (48 8b 07) then `ret`.
//! - `outer(p, v)`: `nop; call store; nop; ret` (offsets 0, 1, 6, 7).
//! - `hot(p)`: `lock inc qword [rdi]; ret` (the hot loop of `hot`).
//! - `rec(n)`: `test rdi,rdi; jz +; dec rdi; call rec; nop; ret` (offsets 0, 3, 5, 8, 13, 14).
//! - `rep(dst, n)`: `mov rcx, rsi; mov al, 0x41; rep stosb; ret` (offsets 0, 3, 5, 7).
//! - `call(f)`: `call rdi; ret` (offsets 0, 2).
//! - `trip()`: `movabs rax, imm; ret`; entered at +1 it executes ud2 (SIGILL).
//! - `buf`: a page-aligned 3-page buffer (zeroed); `execve`: libc's execve.
//!
//! `value` starts at 100 and `value2` at 200. Commands, one per line, each answered with
//! `ok <value> <value2>` unless noted:
//! `store` (value += 1 via store), `store2` (value2 += 1 via store), `load` (reads value
//! via load), `outer` (value += 1 via outer), `spawn` (a new thread does value2 += 1 via
//! store; joined), `dlopen <lib>` (Linux), `quit`. EOF also exits.
//! Linux only:
//! `hot <threads> <iters>` (each thread calls hot(&counter) iters times; `hot <counter>`),
//! `rec <n>`, `rep <n>` (`rep <bytes set>`), `callsleep <ms>` (call(sleep), `ok`),
//! `bufw <off>` / `bufr <off>` (store / load at buf+off),
//! `fork` (child does store then _exit(42); `fork <status>`, negative = killed by signal),
//! `spawntrue` (posix_spawn /bin/true; `spawn <status>`), `exec` (re-executes itself, which
//! prints a new info line), `exitmain` (`ok`, then the main thread exits and a second thread
//! keeps serving), `raise <sig>` (`sig <SIGUSR1 count> <SIGUSR2 count>`), `sigs` (same).
//! Stress (Linux): `bg <hot> <writers> <churn> <sleep_us>` starts background threads until
//! `bgstop` (`ok`): `hot` threads call hot(&counter) in a loop, `writers` threads store to
//! buf+8, `churn` threads keep creating short-lived threads that call hot(&counter);
//! `sleep_us` pauses between iterations. `mainhot <iters> <sleep_us>` calls hot(&counter)
//! on the main thread (`hot <counter>`). `prog` answers `prog <counter> <writes> <churned>`.
//! `fakesegv <addr>` (`ok` if it survives): sends itself a SIGSEGV with si_code SI_QUEUE
//! and si_addr = addr.
//! `bgtrip` (`ok`): a background thread calls trip() and hot(&counter) until `bgstop`.
//! `vforkbg <ms>` (`ok`): a new thread does clone(CLONE_VFORK) without CLONE_VM; the child
//! sleeps `ms` and exits, the thread waits for it. `vforks` answers `vforks <done>`.
//! `dlopen <path>` keeps the handle; `dlclose` closes the last one (`ok`); `libcall <n>`
//! calls `hh_lib_add(n)` of the last library (`lib <result>`).
//! `mapfile <path>` maps the file again read-only and keeps it (`mapped <address>`).
//! `named <name>` (`ok`): a thread with that name waits until `bgstop`.
//! `deep` (value += 1 via `f1 -> f2 -> f3`, all with frame pointers; `f1` calls at +4 and
//! `f2` at +4, both return to +9; `f3` stores at +4).
//! `ymm` answers `ymm <ymm0 as 32 hex bytes> <mxcsr hex>` (needs AVX).
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
    ".globl hh_hot",
    "hh_hot:",
    "lock inc qword ptr [rdi]",
    "ret",
    ".globl hh_rec",
    "hh_rec:",
    "test rdi, rdi",
    "jz 2f",
    "dec rdi",
    "call hh_rec",
    "nop",
    "2:",
    "ret",
    ".globl hh_rep",
    "hh_rep:",
    "mov rcx, rsi",
    "mov al, 0x41",
    "rep stosb",
    "ret",
    ".globl hh_call",
    "hh_call:",
    "call rdi",
    "ret",
    // Resumed one byte in (mid-instruction), the rest of the immediate decodes as ud2.
    ".globl hh_trip",
    "hh_trip:",
    "movabs rax, 0x0b0f0b0f00000000",
    "ret",
    ".globl hh_f1",
    "hh_f1:",
    "push rbp",
    "mov rbp, rsp",
    "call hh_f2",
    "pop rbp",
    "ret",
    ".globl hh_f2",
    "hh_f2:",
    "push rbp",
    "mov rbp, rsp",
    "call hh_f3",
    "pop rbp",
    "ret",
    ".globl hh_f3",
    "hh_f3:",
    "push rbp",
    "mov rbp, rsp",
    "mov qword ptr [rdi], rsi",
    "pop rbp",
    "ret",
    ".globl hh_getfp",
    "hh_getfp:",
    "vmovdqu ymmword ptr [rdi], ymm0",
    "stmxcsr dword ptr [rdi + 32]",
    "vzeroupper",
    "ret",
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn hh_store(p: *mut u64, v: u64);
    fn hh_load(p: *const u64) -> u64;
    fn hh_outer(p: *mut u64, v: u64);
    fn hh_hot(p: *mut u64);
    fn hh_rec(n: u64);
    fn hh_rep(dst: *mut u8, n: u64);
    fn hh_call(f: extern "C" fn());
    fn hh_trip();
    fn hh_f1(p: *mut u64, v: u64);
    fn hh_f3(p: *mut u64, v: u64);
    fn hh_getfp(out: *mut u8);
}

#[cfg(target_os = "linux")]
mod lx {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub static USR1: AtomicU64 = AtomicU64::new(0);
    pub static USR2: AtomicU64 = AtomicU64::new(0);
    pub static SLEEP_MS: AtomicU64 = AtomicU64::new(0);
    pub static WRITES: AtomicU64 = AtomicU64::new(0);
    pub static CHURNED: AtomicU64 = AtomicU64::new(0);
    pub static VFORKS: AtomicU64 = AtomicU64::new(0);
    pub static BG_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    pub static BG: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>> =
        std::sync::Mutex::new(Vec::new());
    pub static LIB: std::sync::Mutex<usize> = std::sync::Mutex::new(0);

    pub fn nap(us: u64) {
        if us > 0 {
            std::thread::sleep(std::time::Duration::from_micros(us));
        }
    }

    extern "C" fn on_sig(s: libc::c_int) {
        let c = if s == libc::SIGUSR1 { &USR1 } else { &USR2 };
        c.fetch_add(1, Ordering::SeqCst);
    }

    pub fn install() {
        unsafe {
            libc::signal(libc::SIGUSR1, on_sig as *const () as libc::sighandler_t);
            libc::signal(libc::SIGUSR2, on_sig as *const () as libc::sighandler_t);
        }
    }

    pub extern "C" fn sleeper() {
        std::thread::sleep(std::time::Duration::from_millis(
            SLEEP_MS.load(Ordering::SeqCst),
        ));
    }

    pub fn sigs() -> String {
        format!(
            "sig {} {}",
            USR1.load(Ordering::SeqCst),
            USR2.load(Ordering::SeqCst)
        )
    }

    /// Exit status as a number, negative for "killed by signal".
    pub fn status(st: libc::c_int) -> i32 {
        if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else {
            -libc::WTERMSIG(st)
        }
    }
}

#[derive(Clone, Copy)]
struct State {
    v: usize,
    v2: usize,
    buf: usize,
    counter: usize,
}

#[cfg(target_arch = "x86_64")]
fn main() {
    #[cfg(target_os = "linux")]
    lx::install();
    let value: &'static mut u64 = Box::leak(Box::new(100));
    let value2: &'static mut u64 = Box::leak(Box::new(200));
    let buf = Box::leak(vec![0u8; 4 * 4096].into_boxed_slice());
    let buf = (buf.as_mut_ptr() as usize).next_multiple_of(4096);
    let counter: &'static mut u64 = Box::leak(Box::new(0));
    let st = State {
        v: value as *mut u64 as usize,
        v2: value2 as *mut u64 as usize,
        buf,
        counter: counter as *mut u64 as usize,
    };
    #[cfg(target_os = "linux")]
    let execve = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"execve".as_ptr()) as usize };
    #[cfg(not(target_os = "linux"))]
    let execve = 0usize;
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        r#"{{"pid":{},"store":"{:#x}","load":"{:#x}","outer":"{:#x}","hot":"{:#x}","rec":"{:#x}","rep":"{:#x}","call":"{:#x}","trip":"{:#x}","value":"{:#x}","value2":"{:#x}","buf":"{:#x}","counter":"{:#x}","execve":"{execve:#x}","f1":"{:#x}","f3":"{:#x}","getfp":"{:#x}"}}"#,
        std::process::id(),
        hh_store as *const () as usize,
        hh_load as *const () as usize,
        hh_outer as *const () as usize,
        hh_hot as *const () as usize,
        hh_rec as *const () as usize,
        hh_rep as *const () as usize,
        hh_call as *const () as usize,
        hh_trip as *const () as usize,
        st.v,
        st.v2,
        st.buf,
        st.counter,
        hh_f1 as *const () as usize,
        hh_f3 as *const () as usize,
        hh_getfp as *const () as usize,
    )
    .unwrap();
    out.flush().unwrap();
    drop(out);
    serve(st);
}

/// The command loop; `exitmain` hands it to a second thread.
#[cfg(target_arch = "x86_64")]
fn serve(st: State) {
    let mut line = String::new();
    loop {
        line.clear();
        if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let reply = command(&st, line.trim());
        let Some(reply) = reply else { break };
        let mut out = std::io::stdout().lock();
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
    std::process::exit(0);
}

#[cfg(target_arch = "x86_64")]
fn command(st: &State, line: &str) -> Option<String> {
    let (p, p2) = (st.v as *mut u64, st.v2 as *mut u64);
    let ok = || unsafe { format!("ok {} {}", hh_load(p), hh_load(p2)) };
    let mut words = line.split_whitespace();
    let cmd = words.next().unwrap_or("");
    #[cfg_attr(not(target_os = "linux"), allow(unused))]
    let mut num = || -> u64 { words.next().and_then(|w| w.parse().ok()).unwrap_or(0) };
    unsafe {
        match cmd {
            "quit" => return None,
            "store" => hh_store(p, hh_load(p) + 1),
            "store2" => hh_store(p2, hh_load(p2) + 1),
            "load" => {
                hh_load(p);
            }
            "outer" => hh_outer(p, hh_load(p) + 1),
            "spawn" => {
                let v2 = st.v2;
                std::thread::spawn(move || {
                    let p2 = v2 as *mut u64;
                    hh_store(p2, hh_load(p2) + 1)
                })
                .join()
                .unwrap()
            }
            #[cfg(target_os = "linux")]
            "dlopen" => {
                let name = std::ffi::CString::new(line[7..].trim()).unwrap();
                let h = libc::dlopen(name.as_ptr(), libc::RTLD_NOW);
                if !h.is_null() {
                    *lx::LIB.lock().unwrap() = h as usize;
                }
            }
            "deep" => hh_f1(p, hh_load(p) + 1),
            #[cfg(target_os = "linux")]
            _ => return Some(linux_command(st, cmd, line, &mut num)),
            #[cfg(not(target_os = "linux"))]
            _ => return Some("error".into()),
        }
    }
    Some(ok())
}

#[cfg(target_os = "linux")]
fn linux_command(st: &State, cmd: &str, line: &str, num: &mut dyn FnMut() -> u64) -> String {
    use std::sync::atomic::Ordering;
    let p = st.v as *mut u64;
    unsafe {
        match cmd {
            "hot" => {
                let (threads, iters) = (num(), num());
                let c = st.counter;
                let hs: Vec<_> = (0..threads)
                    .map(|_| {
                        std::thread::spawn(move || {
                            for _ in 0..iters {
                                hh_hot(c as *mut u64);
                            }
                        })
                    })
                    .collect();
                for h in hs {
                    h.join().unwrap();
                }
                format!("hot {}", hh_load(c as *const u64))
            }
            "rec" => {
                hh_rec(num());
                "ok".into()
            }
            "rep" => {
                let n = num().min(4096);
                let mut v = vec![0u8; 4096];
                hh_rep(v.as_mut_ptr(), n);
                format!("rep {}", v.iter().filter(|&&b| b == 0x41).count())
            }
            "callsleep" => {
                lx::SLEEP_MS.store(num(), Ordering::SeqCst);
                hh_call(lx::sleeper);
                "ok".into()
            }
            "bufw" => {
                let a = (st.buf + num() as usize) as *mut u64;
                hh_store(a, hh_load(a) + 1);
                format!("buf {}", hh_load(a))
            }
            "bufr" => format!("buf {}", hh_load((st.buf + num() as usize) as *const u64)),
            "fork" => match libc::fork() {
                0 => {
                    hh_store(p, 5);
                    libc::_exit(42);
                }
                -1 => "fork failed".into(),
                child => {
                    let mut s = 0;
                    libc::waitpid(child, &mut s, 0);
                    format!("fork {}", lx::status(s))
                }
            },
            "spawntrue" => {
                let mut pid = 0;
                let path = c"/bin/true";
                let argv = [path.as_ptr() as *mut libc::c_char, std::ptr::null_mut()];
                let envp = [std::ptr::null_mut()];
                let r = libc::posix_spawn(
                    &mut pid,
                    path.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                );
                if r != 0 {
                    return format!("spawn failed {r}");
                }
                let mut s = 0;
                libc::waitpid(pid, &mut s, 0);
                format!("spawn {}", lx::status(s))
            }
            "exec" => {
                let exe =
                    std::ffi::CString::new(std::env::current_exe().unwrap().to_str().unwrap())
                        .unwrap();
                let argv = [exe.as_ptr(), std::ptr::null()];
                libc::execv(exe.as_ptr(), argv.as_ptr());
                "exec failed".into()
            }
            "exitmain" => {
                let st2 = *st;
                let mut out = std::io::stdout().lock();
                writeln!(out, "ok").unwrap();
                out.flush().unwrap();
                drop(out);
                std::thread::spawn(move || serve(st2));
                libc::syscall(libc::SYS_exit, 0);
                unreachable!()
            }
            "raise" => {
                libc::raise(num() as i32);
                lx::sigs()
            }
            "sigs" => lx::sigs(),
            "bg" => {
                let (hot, writers, churn, us) = (num(), num(), num(), num());
                let (c, w) = (st.counter, st.buf + 8);
                lx::BG_STOP.store(false, Ordering::SeqCst);
                let run = || !lx::BG_STOP.load(Ordering::SeqCst);
                let mut g = lx::BG.lock().unwrap();
                for _ in 0..hot {
                    g.push(std::thread::spawn(move || {
                        while run() {
                            hh_hot(c as *mut u64);
                            lx::nap(us);
                        }
                    }));
                }
                for _ in 0..writers {
                    g.push(std::thread::spawn(move || {
                        while run() {
                            hh_store(w as *mut u64, hh_load(w as *const u64) + 1);
                            lx::WRITES.fetch_add(1, Ordering::SeqCst);
                            lx::nap(us);
                        }
                    }));
                }
                for _ in 0..churn {
                    g.push(std::thread::spawn(move || {
                        while run() {
                            std::thread::spawn(move || {
                                for _ in 0..3 {
                                    hh_hot(c as *mut u64);
                                }
                            })
                            .join()
                            .unwrap();
                            lx::CHURNED.fetch_add(1, Ordering::SeqCst);
                            lx::nap(us);
                        }
                    }));
                }
                "ok".into()
            }
            "bgstop" => {
                lx::BG_STOP.store(true, Ordering::SeqCst);
                for h in lx::BG.lock().unwrap().drain(..) {
                    h.join().unwrap();
                }
                "ok".into()
            }
            "mainhot" => {
                let (iters, us) = (num(), num());
                for _ in 0..iters {
                    hh_hot(st.counter as *mut u64);
                    lx::nap(us);
                }
                format!("hot {}", hh_load(st.counter as *const u64))
            }
            "bgtrip" => {
                let c = st.counter;
                lx::BG_STOP.store(false, Ordering::SeqCst);
                lx::BG.lock().unwrap().push(std::thread::spawn(move || {
                    while !lx::BG_STOP.load(Ordering::SeqCst) {
                        hh_trip();
                        hh_hot(c as *mut u64);
                    }
                }));
                "ok".into()
            }
            "vforkbg" => {
                // clone(CLONE_VFORK) without CLONE_VM: a copied child, but the parent thread
                // waits (unstoppable) until the child exits.
                let us = (num() * 1000).min(u32::MAX as u64) as u32;
                std::thread::spawn(move || {
                    let r = libc::syscall(
                        libc::SYS_clone,
                        libc::CLONE_VFORK | libc::SIGCHLD,
                        0,
                        0,
                        0,
                        0,
                    );
                    if r == 0 {
                        libc::usleep(us);
                        libc::_exit(0);
                    }
                    if r > 0 {
                        let mut s = 0;
                        libc::waitpid(r as i32, &mut s, 0);
                    }
                    lx::VFORKS.fetch_add(1, Ordering::SeqCst);
                });
                "ok".into()
            }
            "fakesegv" => {
                // A user-sent SIGSEGV (si_code SI_QUEUE) whose si_addr field holds `addr`.
                let mut si: libc::siginfo_t = std::mem::zeroed();
                si.si_signo = libc::SIGSEGV;
                si.si_code = -1; // SI_QUEUE
                (&mut si as *mut libc::siginfo_t as *mut u8)
                    .add(16)
                    .cast::<u64>()
                    .write_unaligned(num());
                libc::syscall(
                    libc::SYS_rt_tgsigqueueinfo,
                    libc::getpid(),
                    libc::gettid(),
                    libc::SIGSEGV,
                    &si,
                );
                "ok".into()
            }
            "vforks" => format!("vforks {}", lx::VFORKS.load(Ordering::SeqCst)),
            "mapfile" => {
                // Maps a file again, read-only, and keeps it (what crash reporters do).
                let Ok(f) = std::fs::File::open(line[8..].trim()) else { return "error".into() };
                let len = f.metadata().map_or(0, |m| m.len()) as usize;
                let m = libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE, std::os::fd::AsRawFd::as_raw_fd(&f), 0);
                if m == libc::MAP_FAILED { "error".into() } else { format!("mapped {m:p}") }
            }
            "dlclose" => {
                let h = std::mem::take(&mut *lx::LIB.lock().unwrap());
                if h != 0 {
                    libc::dlclose(h as *mut libc::c_void);
                }
                "ok".into()
            }
            "libcall" => {
                let h = *lx::LIB.lock().unwrap();
                let f = libc::dlsym(h as *mut libc::c_void, c"hh_lib_add".as_ptr());
                if h == 0 || f.is_null() {
                    return "nolib".into();
                }
                let f: extern "C" fn(u64) -> u64 = std::mem::transmute(f);
                format!("lib {}", f(num()))
            }
            "named" => {
                let name = line.split_whitespace().nth(1).unwrap_or("named").to_string();
                let started = std::sync::Arc::new(std::sync::Barrier::new(2));
                let s2 = started.clone();
                lx::BG_STOP.store(false, Ordering::SeqCst);
                let h = std::thread::Builder::new()
                    .name(name)
                    .spawn(move || {
                        s2.wait();
                        while !lx::BG_STOP.load(Ordering::SeqCst) {
                            lx::nap(2000);
                        }
                    })
                    .unwrap();
                started.wait();
                lx::BG.lock().unwrap().push(h);
                "ok".into()
            }
            "ymm" => {
                let mut out = [0u8; 36];
                hh_getfp(out.as_mut_ptr());
                let hex: String = out[..32].iter().map(|b| format!("{b:02x}")).collect();
                let mx = u32::from_le_bytes(out[32..36].try_into().unwrap());
                format!("ymm {hex} {mx:x}")
            }
            "prog" => format!(
                "prog {} {} {}",
                hh_load(st.counter as *const u64),
                lx::WRITES.load(Ordering::SeqCst),
                lx::CHURNED.load(Ordering::SeqCst)
            ),
            _ => "error".into(),
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("hh-debug-target only supports x86_64");
}
