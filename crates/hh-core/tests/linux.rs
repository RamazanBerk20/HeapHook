//! Live tests against hh-target spawned as a child (ptrace_scope=1 only allows children).
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;

use hh_core::{Error, Prot, RegionKind};
use serde_json::Value;

/// Builds hh-target once per test binary and returns its path.
fn target_exe() -> &'static PathBuf {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        // This test binary lives in <target>/<profile>/deps/; build hh-target to match.
        let dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let mut args = vec!["build", "-q", "-p", "hh-target"];
        if dir.ends_with("release") {
            args.push("--release");
        }
        let ok = Command::new(env!("CARGO"))
            .args(&args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("run cargo")
            .success();
        assert!(ok, "cargo build -p hh-target failed");
        dir.join("hh-target")
    })
}

struct Target {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    info: Value,
}

impl Target {
    fn spawn() -> Self {
        let mut child = Command::new(target_exe())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let info = serde_json::from_str(&line).unwrap();
        Target {
            child,
            stdin,
            stdout,
            info,
        }
    }
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn addr(&self, key: &str) -> u64 {
        u64::from_str_radix(
            self.info[key].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap()
    }
    fn cmd(&mut self, c: &str) -> Value {
        writeln!(self.stdin, "{c}").unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn state(pid: u32) -> char {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    s[s.rfind(')').unwrap() + 2..].chars().next().unwrap()
}

#[test]
fn list_and_open() {
    let t = Target::spawn();
    let procs = hh_core::list_processes().unwrap();
    let me = procs
        .iter()
        .find(|p| p.pid == t.pid())
        .expect("target listed");
    assert_eq!(me.name, "hh-target");
    assert_eq!(PathBuf::from(me.exe.as_ref().unwrap()), *target_exe());

    let p = hh_core::open(t.pid()).unwrap();
    assert_eq!(p.pid(), t.pid());
    assert!(p.is_alive());
    assert_eq!(p.pointer_size(), 8);
    assert_eq!(p.threads().unwrap().len(), 2);
    assert!(p.threads().unwrap().contains(&t.pid()));
}

#[test]
fn regions_and_modules() {
    let t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    let regions = p.regions().unwrap();
    let heap = regions
        .iter()
        .find(|r| r.start <= t.addr("i32") && t.addr("i32") < r.start + r.size)
        .unwrap();
    assert_eq!(
        heap.prot,
        Prot {
            r: true,
            w: true,
            x: false
        }
    );
    assert_eq!(heap.kind, RegionKind::Private);

    let mods = p.modules().unwrap();
    let exe = mods
        .iter()
        .find(|m| m.name == "hh-target")
        .expect("exe module");
    assert!(mods.iter().any(|m| m.name.starts_with("libc.so")));
    // Every region of the exe is inside the module range and tagged Image.
    for r in regions
        .iter()
        .filter(|r| r.path.as_deref() == Some(exe.path.as_str()))
    {
        assert_eq!(r.kind, RegionKind::Image);
        assert!(r.start >= exe.base && r.start + r.size <= exe.base + exe.size);
    }
    assert!(regions.iter().any(|r| r.path.as_deref() == Some("[stack]")));
}

#[test]
fn read_values() {
    let t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    let mut b4 = [0u8; 4];
    let mut b8 = [0u8; 8];
    p.read_exact(t.addr("i32"), &mut b4).unwrap();
    assert_eq!(i32::from_le_bytes(b4), 123456);
    p.read_exact(t.addr("i64"), &mut b8).unwrap();
    assert_eq!(i64::from_le_bytes(b8), 1234567890123);
    p.read_exact(t.addr("f32"), &mut b4).unwrap();
    assert_eq!(f32::from_le_bytes(b4), 3.5);
    p.read_exact(t.addr("f64"), &mut b8).unwrap();
    assert_eq!(f64::from_le_bytes(b8), 2.25);
    let mut s = [0u8; 20];
    p.read_exact(t.addr("str"), &mut s).unwrap();
    assert_eq!(&s, b"HeapHook test string");
    let mut s16 = [0u8; 44];
    p.read_exact(t.addr("str16"), &mut s16).unwrap();
    let u: Vec<u16> = s16
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(String::from_utf16(&u).unwrap(), "HeapHook UTF-16 string");
    p.read_exact(t.addr("aob"), &mut b8).unwrap();
    assert_eq!(b8, [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE]);

    // Pointer chain [[[chain]+o1]+o2]+o3.
    let mut a = p.read_ptr(t.addr("chain")).unwrap();
    let offs: Vec<u64> = t.info["chain_offsets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| u64::from_str_radix(o.as_str().unwrap().trim_start_matches("0x"), 16).unwrap())
        .collect();
    a = p.read_ptr(a + offs[0]).unwrap();
    a = p.read_ptr(a + offs[1]).unwrap();
    assert_eq!(a + offs[2], t.addr("chain_value"));
    p.read_exact(a + offs[2], &mut b4).unwrap();
    assert_eq!(i32::from_le_bytes(b4), 4242);

    // Short read at the end of a region returns the readable prefix; unmapped address errs.
    let stack = p
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| r.path.as_deref() == Some("[stack]"))
        .unwrap();
    let mut big = vec![0u8; 0x2000];
    assert_eq!(
        p.read(stack.start + stack.size - 0x100, &mut big).unwrap(),
        0x100
    );
    assert!(matches!(
        p.read(8, &mut big),
        Err(Error::NoAccess { addr: 8 })
    ));
}

#[test]
fn write_values() {
    let mut t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    p.write(t.addr("i32"), &(-7i32).to_le_bytes()).unwrap();
    p.write(t.addr("f64"), &10.5f64.to_le_bytes()).unwrap();
    p.write(t.addr("chain_value"), &99i32.to_le_bytes())
        .unwrap();
    let v = t.cmd("inc");
    assert_eq!(v["i32"], -6);
    assert_eq!(v["f64"], 11.5);
    assert_eq!(v["chain_value"], 100);
    assert_eq!(v["i64"], 1234567890124i64);

    // Writing a read-only page (the exe's ELF header; e_ident padding is unused at runtime).
    let exe = p
        .modules()
        .unwrap()
        .into_iter()
        .find(|m| m.name == "hh-target")
        .unwrap();
    let r = p
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| r.start == exe.base)
        .unwrap();
    assert!(!r.prot.w);
    let mut b = [0u8; 4];
    p.write(exe.base + 10, &[1, 2, 3, 4]).unwrap();
    p.read_exact(exe.base + 10, &mut b).unwrap();
    assert_eq!(b, [1, 2, 3, 4]);
    p.write(exe.base + 10, &[0; 4]).unwrap();
    assert!(p.write(8, &[0]).is_err());
}

#[test]
fn suspend_resume() {
    let mut t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    p.suspend().unwrap();
    assert_eq!(state(t.pid()), 'T');
    writeln!(t.stdin, "inc").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut b4 = [0u8; 4];
    p.read_exact(t.addr("i32"), &mut b4).unwrap();
    assert_eq!(
        i32::from_le_bytes(b4),
        123456,
        "stopped target must not run"
    );
    p.resume().unwrap();
    let mut line = String::new();
    t.stdout.read_line(&mut line).unwrap();
    assert!(line.contains(r#""i32":123457"#), "{line}");
}

#[test]
fn alloc_protect_free() {
    let mut t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    let exe = p
        .modules()
        .unwrap()
        .into_iter()
        .find(|m| m.name == "hh-target")
        .unwrap();
    let rw = Prot {
        r: true,
        w: true,
        x: false,
    };

    let a = p.alloc(100, rw, Some(exe.base)).unwrap();
    assert!(
        a.abs_diff(exe.base) < 1 << 31,
        "{a:#x} not near {:#x}",
        exe.base
    );
    assert_eq!(a % 4096, 0);
    let r = p
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| r.start <= a && a < r.start + r.size)
        .unwrap();
    assert_eq!(r.prot, rw);
    p.write(a, b"hello").unwrap();
    let mut b = [0u8; 5];
    p.read_exact(a, &mut b).unwrap();
    assert_eq!(&b, b"hello");

    // The target was blocked in read(stdin) while we injected; it must still work.
    assert_eq!(t.cmd("get")["i32"], 123456);

    let rx = Prot {
        r: true,
        w: false,
        x: true,
    };
    assert_eq!(p.protect(a, 4096, rx).unwrap(), rw);
    let r = p
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| r.start <= a && a < r.start + r.size)
        .unwrap();
    assert_eq!(r.prot, rx);
    p.write(a, b"bye").unwrap(); // read-only page: goes through /proc/pid/mem

    p.free(a, 4096).unwrap();
    assert!(p.read(a, &mut b).is_err());

    let far = p.alloc(1 << 20, rw, None).unwrap();
    p.write(far + (1 << 20) - 1, &[7]).unwrap();
    p.free(far, 1 << 20).unwrap();
    assert_eq!(t.cmd("inc")["i32"], 123457);
}

#[test]
fn alloc_while_suspended_keeps_it_stopped() {
    let mut t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    p.suspend().unwrap();
    let a = p
        .alloc(
            4096,
            Prot {
                r: true,
                w: true,
                x: false,
            },
            None,
        )
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(state(t.pid()), 'T');
    p.free(a, 4096).unwrap();
    p.resume().unwrap();
    assert_eq!(t.cmd("get")["i32"], 123456);
}

#[test]
fn errors() {
    assert!(matches!(
        hh_core::open(0x7fff_fff0),
        Err(Error::ProcessGone)
    ));
    // pid 1 is not our child: ptrace_scope / missing CAP_SYS_PTRACE.
    if is_root() {
        return;
    }
    assert!(matches!(hh_core::open(1), Err(Error::Permission(_))));

    let mut t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    writeln!(t.stdin, "quit").unwrap();
    t.child.wait().unwrap();
    assert!(!p.is_alive());
    let mut b = [0u8; 4];
    assert!(matches!(
        p.read(t.addr("i32"), &mut b),
        Err(Error::ProcessGone)
    ));
    assert!(matches!(
        p.write(t.addr("i32"), &b),
        Err(Error::ProcessGone)
    ));
}

// ---- odd targets: this test binary re-run with HH_CORE_TEST_CHILD set ----------------------

/// Runs before `main` (on the main thread) when this binary is started as a test target:
/// - `main-exit`: a worker thread answers stdin lines, then the main thread calls pthread_exit.
/// - `vfork`: the main thread sits in vfork (uninterruptible sleep) for 4 s, then answers stdin.
extern "C" fn test_child() {
    use std::io::{BufRead, Write};
    let Ok(mode) = std::env::var("HH_CORE_TEST_CHILD") else {
        return;
    };
    let serve = || {
        for l in std::io::stdin().lock().lines() {
            let Ok(l) = l else { break };
            println!("ok {l}");
        }
        unsafe { libc::_exit(0) }
    };
    match mode.as_str() {
        "main-exit" => {
            std::thread::spawn(move || {
                println!("ready");
                serve()
            });
            // The raw exit syscall ends only this thread, like pthread_exit without its
            // forced unwind (which must not cross this extern "C" frame).
            unsafe { libc::syscall(libc::SYS_exit, 0) };
            unreachable!()
        }
        "vfork" => {
            println!("ready");
            let _ = std::io::stdout().flush();
            #[allow(deprecated)]
            if unsafe { libc::vfork() } == 0 {
                unsafe {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                    libc::sleep(4);
                    libc::_exit(0);
                }
            }
            println!("resumed");
            serve()
        }
        _ => unsafe { libc::_exit(2) },
    }
}

#[used]
#[unsafe(link_section = ".init_array")]
static TEST_CHILD: extern "C" fn() = test_child;

fn spawn_odd(mode: &str) -> Target {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env("HH_CORE_TEST_CHILD", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    Target {
        child,
        stdin,
        stdout,
        info: Value::Null,
    }
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t = std::time::Instant::now();
    while !f() {
        assert!(t.elapsed().as_secs() < 5, "timed out waiting for {what}");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn tracer_pid(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:").map(|v| v.trim().to_owned()))
        .unwrap()
}

const RW: Prot = Prot {
    r: true,
    w: true,
    x: false,
};

#[test]
fn remote_syscall_after_main_thread_exit() {
    let mut t = spawn_odd("main-exit");
    wait_for("the main thread to exit", || state(t.pid()) == 'Z');
    let p = hh_core::open(t.pid()).unwrap();
    assert!(p.is_alive());
    assert_eq!(p.pointer_size(), 8);
    assert!(!p.regions().unwrap().is_empty());
    let a = p.alloc(4096, RW, None).unwrap();
    p.write(a, b"hello").unwrap();
    let mut b = [0u8; 5];
    p.read_exact(a, &mut b).unwrap();
    assert_eq!(&b, b"hello");
    p.free(a, 4096).unwrap();
    // The worker thread survived the injection.
    writeln!(t.stdin, "ping").unwrap();
    let mut line = String::new();
    t.stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ok ping");
}

#[test]
fn remote_syscall_times_out_and_leaves_target_running() {
    let mut t = spawn_odd("vfork");
    wait_for("vfork sleep", || state(t.pid()) == 'D');
    let p = hh_core::open(t.pid()).unwrap();
    let start = std::time::Instant::now();
    let e = p.alloc(4096, RW, None).unwrap_err();
    assert!(start.elapsed().as_secs() < 4, "{:?}", start.elapsed());
    assert!(e.to_string().contains("untraced"), "{e}");
    wait_for("detach", || tracer_pid(t.pid()) == "0");
    // Once vfork returns the target runs on: no leftover ptrace stop.
    let mut line = String::new();
    t.stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "resumed");
    writeln!(t.stdin, "ping").unwrap();
    line.clear();
    t.stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ok ping");
    assert_eq!(tracer_pid(t.pid()), "0");
    let a = p.alloc(4096, RW, None).unwrap();
    p.free(a, 4096).unwrap();
}

#[test]
fn protect_overflow_is_an_error() {
    let t = Target::spawn();
    let p = hh_core::open(t.pid()).unwrap();
    assert!(p.protect(t.addr("i32"), u64::MAX, RW).is_err());
    assert!(p.write(u64::MAX - 1, &[0; 4]).is_err());
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(2) == Some("0"))
}
