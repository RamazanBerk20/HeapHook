//! Live tests of the 1.0 feature set: launching under the debugger, debug-event breaks,
//! pending breakpoints, filters, tracepoints, trace options, coverage, stepping options,
//! thread info and register writes. Every scenario ends by checking the target was left
//! alive, untraced, unpatched and making progress.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use hh_debug::*;

const T: Duration = Duration::from_secs(10);
const TARGET: &str = env!("CARGO_BIN_EXE_hh-debug-target");

struct Target {
    child: Option<Child>,
    pid: u32,
    stdin: Option<Box<dyn Write + Send>>,
    lines: Receiver<String>,
    info: serde_json::Value,
    /// Child ends of the pipes of a launch, closed once it started.
    child_fds: Vec<OwnedFd>,
}

fn reader(r: impl Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for l in BufReader::new(r).lines() {
            let Ok(l) = l else { break };
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    rx
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

impl Target {
    fn spawn() -> Self {
        let mut child = Command::new(TARGET)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = reader(child.stdout.take().unwrap());
        let mut t = Target {
            pid: child.id(),
            child: Some(child),
            stdin: Some(Box::new(stdin)),
            lines,
            info: serde_json::Value::Null,
            child_fds: Vec::new(),
        };
        t.read_info();
        t
    }

    /// Launches `opts` (stdin / stdout wired to us) under a new debugger.
    fn launch(mut opts: LaunchOptions) -> (Self, Result<Debugger, hh_core::Error>) {
        use std::os::fd::AsRawFd;
        let (in_r, in_w) = pipe();
        let (out_r, out_w) = pipe();
        opts.stdin = Some(in_r.as_raw_fd());
        opts.stdout = Some(out_w.as_raw_fd());
        let d = Debugger::launch(&opts);
        let mut t = Target {
            child: None,
            pid: d.as_ref().map_or(0, |d| d.pid()),
            stdin: Some(Box::new(std::fs::File::from(in_w))),
            lines: reader(std::fs::File::from(out_r)),
            info: serde_json::Value::Null,
            child_fds: vec![in_r, out_w],
        };
        t.child_fds.clear(); // the child has its copies
        (t, d)
    }

    fn read_info(&mut self) {
        let first = self.recv();
        self.info = serde_json::from_str(&first).unwrap();
    }
    fn addr(&self, key: &str) -> u64 {
        u64::from_str_radix(
            self.info[key].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap()
    }
    fn send(&mut self, c: &str) {
        let w = self.stdin.as_mut().unwrap();
        writeln!(w, "{c}").unwrap();
        w.flush().unwrap();
    }
    fn recv(&mut self) -> String {
        self.lines.recv_timeout(T).expect("target answer")
    }
    fn cmd(&mut self, c: &str) -> String {
        self.send(c);
        self.recv()
    }
    fn quiet(&self, ms: u64) -> bool {
        self.lines
            .recv_timeout(Duration::from_millis(ms))
            .is_err()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(c) = &mut self.child {
            let _ = c.kill();
            let _ = c.wait();
        } else if self.pid != 0 {
            unsafe {
                libc::kill(self.pid as i32, libc::SIGKILL);
                let mut st = 0;
                libc::waitpid(self.pid as i32, &mut st, 0);
            }
        }
    }
}

fn next(d: &Debugger) -> Event {
    d.next_event(T).unwrap_or_else(|| fail(d, "no event"))
}

fn wait_break(d: &Debugger) -> (Tid, BreakReason, Context) {
    loop {
        match next(d) {
            Event::Break {
                tid,
                reason,
                context,
            } => return (tid, reason, *context),
            Event::ProcessExited { .. } => fail(d, "target exited"),
            _ => {}
        }
    }
}

/// The `Stopped` event of a debug-event break and its `Break`.
fn wait_stopped(d: &Debugger) -> (Trigger, Tid, Context) {
    let why = loop {
        match next(d) {
            Event::Stopped { why, .. } => break why,
            Event::Break { reason, .. } => fail(d, &format!("break {reason:?} before Stopped")),
            _ => {}
        }
    };
    let (tid, reason, ctx) = wait_break(d);
    assert_eq!(reason, BreakReason::Pause);
    (why, tid, ctx)
}

fn wait_for(d: &Debugger, f: impl Fn(&Event) -> bool) -> Event {
    loop {
        let e = next(d);
        if let Event::Break { reason, .. } = &e
            && !f(&e)
        {
            fail(d, &format!("unexpected break {reason:?}"));
        }
        if f(&e) {
            return e;
        }
    }
}

fn fail(d: &Debugger, msg: &str) -> ! {
    let h = d.history().unwrap_or_default();
    panic!("{msg}\n--- engine history ---\n{}", h.join("\n"));
}

fn status_field(pid: u32, tid: u32, key: &str) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status")).ok()?;
    s.lines()
        .find(|l| l.starts_with(key))
        .map(|l| l[key.len()..].trim().to_string())
}

fn tasks(pid: u32) -> Vec<u32> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|r| {
            r.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn raw_byte(pid: u32, a: u64) -> u8 {
    let mut b = [0u8];
    hh_core::open(pid).unwrap().read(a, &mut b).unwrap();
    b[0]
}

fn hits(d: &Debugger, id: BpId) -> u64 {
    info(d, id).hits
}

fn info(d: &Debugger, id: BpId) -> BreakpointInfo {
    d.breakpoints()
        .unwrap()
        .into_iter()
        .find(|i| i.id == id)
        .unwrap()
}

/// No task sits in a tracing stop (unchanged for 300 ms) while the engine says Running.
fn assert_no_stuck(d: &Debugger, pid: u32) {
    let stopped = || {
        tasks(pid)
            .into_iter()
            .filter(|&t| {
                status_field(pid, t, "State:").is_some_and(|s| s.starts_with("t"))
            })
            .collect::<Vec<_>>()
    };
    for _ in 0..15 {
        if stopped().is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let st = d.state().unwrap();
    if !matches!(st, State::Broken { .. } | State::Suspended) {
        fail(d, &format!("tasks {:?} stuck in tracing stop while {st:?}", stopped()));
    }
}

/// After detach / drop: alive, untraced, no task stopped, the given bytes restored, the
/// pages of `buf` writable, and the command loop still answers.
fn assert_released(t: &mut Target, bytes: &[(u64, u8)]) {
    let pid = t.pid;
    for tid in tasks(pid) {
        if let Some(tp) = status_field(pid, tid, "TracerPid:") {
            assert_eq!(tp, "0", "task {tid} still traced");
        }
        if let Some(s) = status_field(pid, tid, "State:") {
            assert!(!s.starts_with(['t', 'T']), "task {tid} stopped: {s}");
        }
    }
    if let Some(c) = &mut t.child {
        assert!(c.try_wait().unwrap().is_none(), "target died");
    }
    for &(a, b) in bytes {
        assert_eq!(raw_byte(pid, a), b, "byte at {a:#x}");
    }
    let buf = t.addr("buf");
    let r = hh_core::open(pid)
        .unwrap()
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| buf >= r.start && buf < r.start + r.size)
        .unwrap();
    assert!(r.prot.r && r.prot.w, "buf protection {:?}", r.prot);
    assert_eq!(t.cmd("sigs"), "sig 0 0", "still serving");
}

fn at_entry(pid: u32) -> u64 {
    let auxv = std::fs::read(format!("/proc/{pid}/auxv")).unwrap();
    auxv.chunks_exact(16)
        .find(|c| u64::from_le_bytes(c[..8].try_into().unwrap()) == 9)
        .map(|c| u64::from_le_bytes(c[8..].try_into().unwrap()))
        .unwrap()
}

fn masked_byte(d: &Debugger, a: u64) -> u8 {
    let mut b = [0u8];
    d.process().read(a, &mut b).unwrap();
    b[0]
}

/// A small shared object (`hh_lib_add(x) = x + 1`), built once with rustc.
fn test_lib() -> PathBuf {
    static LIB: OnceLock<PathBuf> = OnceLock::new();
    LIB.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("hh-debug-lib");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("hhtest.rs");
        std::fs::write(
            &src,
            "#[no_mangle]\npub extern \"C\" fn hh_lib_add(x: u64) -> u64 { x.wrapping_add(1) }\n",
        )
        .unwrap();
        let out = dir.join(format!("libhhtest-{}.so", std::process::id()));
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        let st = Command::new(rustc)
            .args(["--crate-type", "cdylib", "--edition", "2021", "-C", "opt-level=1"])
            .args(["-C", "panic=abort", "-o"])
            .arg(&out)
            .arg(&src)
            .status()
            .unwrap();
        assert!(st.success(), "building the test library");
        // A stable name for patterns and symbol lookups.
        let link = dir.join(format!("{}/libhhtest.so", std::process::id()));
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&link);
        std::fs::copy(&out, &link).unwrap();
        let _ = std::fs::remove_file(&out);
        link
    })
    .clone()
}

fn launch_opts(stop: LaunchStop) -> LaunchOptions {
    LaunchOptions {
        program: TARGET.into(),
        stop,
        ..LaunchOptions::default()
    }
}

// ---- item 1: launch, debug-event breaks --------------------------------------------------

#[test]
fn launch_breaks_at_entry_then_detaches() {
    let (mut t, d) = Target::launch(launch_opts(LaunchStop::Entry));
    let d = d.unwrap();
    let pid = t.pid;
    let (why, tid, ctx) = wait_stopped(&d);
    assert!(matches!(why, Trigger::Entry), "{why:?}");
    assert_eq!(tid, pid);
    let entry = at_entry(pid);
    assert_eq!(ctx.rip, entry);
    assert!(t.quiet(200), "no program code ran yet");
    // A breakpoint by symbol, set before the program's code runs.
    let id = d
        .add_pending_breakpoint(
            "hh_store",
            Breakpoint::execute(0),
            Hooks::default(),
            BpOptions::default(),
            BpExtra::default(),
        )
        .unwrap();
    let i = info(&d, id);
    assert!(i.resolved && i.enabled, "{i:?}");
    let entry_byte = masked_byte(&d, entry);
    d.cont(false).unwrap();
    t.read_info();
    let store = t.addr("store");
    assert_eq!(info(&d, id).bp.address, store);
    t.send("store");
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Breakpoint(id), store));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");
    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &[(store, 0x48), (entry, entry_byte)]);
    assert_eq!(t.cmd("store"), "ok 102 200");
}

/// Decision: dropping the debugger of a launched process that never continued releases it
/// (it runs from where it stopped, untraced, our int3s removed).
#[test]
fn launch_first_instruction_then_drop_releases() {
    let (mut t, d) = Target::launch(launch_opts(LaunchStop::FirstInstruction));
    let d = d.unwrap();
    let pid = t.pid;
    let (why, tid, ctx) = wait_stopped(&d);
    assert!(matches!(why, Trigger::Start), "{why:?}");
    assert_eq!(tid, pid);
    let regions = d.process().regions().unwrap();
    let r = regions
        .iter()
        .find(|r| ctx.rip >= r.start && ctx.rip < r.start + r.size)
        .unwrap();
    assert!(
        r.path.as_deref().is_some_and(|p| p.contains("ld-linux")),
        "first instruction in the loader: {r:?}"
    );
    let entry = at_entry(pid);
    let entry_byte = masked_byte(&d, entry);
    assert_eq!(raw_byte(pid, entry), 0xcc, "entry hook armed");
    drop(d);
    t.read_info();
    assert_released(&mut t, &[(entry, entry_byte)]);
    assert_eq!(t.cmd("store"), "ok 101 200");
}

/// Zombie children of ours that never exec'd (still named after the debugger thread).
fn failed_launch_zombies() -> usize {
    let me = std::process::id().to_string();
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| std::fs::read_to_string(e.path().join("stat")).ok())
        .filter(|s| {
            let Some(i) = s.rfind(')') else { return false };
            let f: Vec<&str> = s[i + 2..].split_whitespace().collect();
            f.first() == Some(&"Z") && f.get(1) == Some(&me.as_str()) && s.contains("(hh-debug)")
        })
        .count()
}

#[test]
fn launch_errors_are_clean() {
    let (_t, d) = Target::launch(LaunchOptions {
        program: "/nonexistent/hh-no-such-program".into(),
        ..LaunchOptions::default()
    });
    assert!(d.is_err());
    let (_t, d) = Target::launch(LaunchOptions {
        program: "hh-no-such-program-in-path".into(),
        ..LaunchOptions::default()
    });
    assert!(d.is_err());
    // Exists and is executable, but exec fails (no shebang, not ELF): fails in the child.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let bad = dir.join(format!("hh-not-a-program-{}", std::process::id()));
    std::fs::write(&bad, b"\x01\x02 not a program").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (_t, d) = Target::launch(LaunchOptions {
        program: bad.to_str().unwrap().into(),
        ..LaunchOptions::default()
    });
    let e = d.err().expect("exec must fail").to_string();
    assert!(e.contains("cannot run"), "{e}");
    let _ = std::fs::remove_file(&bad);
    // A working directory that does not exist: chdir fails in the child.
    let (_t, d) = Target::launch(LaunchOptions {
        program: TARGET.into(),
        cwd: Some("/nonexistent/hh-dir".into()),
        ..LaunchOptions::default()
    });
    assert!(d.is_err());
    assert_eq!(failed_launch_zombies(), 0);
}

/// A launcher that execs the real program keeps its pending breakpoints.
#[test]
fn launcher_exec_keeps_pending_breakpoints() {
    let (mut t, d) = Target::launch(LaunchOptions {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), format!("exec '{TARGET}'")],
        stop: LaunchStop::FirstInstruction,
        ..LaunchOptions::default()
    });
    let d = d.unwrap();
    wait_stopped(&d);
    let id = d
        .add_pending_breakpoint(
            "hh_store",
            Breakpoint::execute(0),
            Hooks::default(),
            BpOptions::default(),
            BpExtra::default(),
        )
        .unwrap();
    assert!(!info(&d, id).resolved, "no hh_store in the shell");
    d.cont(false).unwrap();
    wait_for(&d, |e| matches!(e, Event::Exec));
    wait_for(
        &d,
        |e| matches!(e, Event::BreakpointResolved { bp, .. } if *bp == id),
    );
    t.read_info();
    let store = t.addr("store");
    t.send("store");
    let (tid, r, c) = wait_break(&d);
    assert_eq!((tid, r, c.rip), (t.pid, BreakReason::Breakpoint(id), store));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");
    d.detach().unwrap();
    assert_released(&mut t, &[(store, 0x48)]);
}

#[test]
fn break_on_thread_events() {
    let mut t = Target::spawn();
    let pid = t.pid;
    let d = Debugger::attach(pid).unwrap();
    d.set_break_on(BreakOn {
        thread_created: true,
        thread_exited: true,
        ..BreakOn::default()
    })
    .unwrap();
    t.send("spawn");
    let (why, tid, _) = wait_stopped(&d);
    let Trigger::ThreadCreated { tid: new } = why else {
        fail(&d, &format!("{why:?}"))
    };
    assert_eq!(tid, new);
    assert_ne!(new, pid);
    assert!(d.context(new).is_ok());
    assert!(d.threads().unwrap().iter().any(|x| x.tid == new));
    d.cont(false).unwrap();
    let (why, tid, _) = wait_stopped(&d);
    assert!(
        matches!(why, Trigger::ThreadExited { tid } if tid == new),
        "{why:?}"
    );
    assert_eq!(tid, pid, "reported on a live thread");
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 100 201");
    // Notify only: events, no breaks.
    d.set_break_on(BreakOn::default()).unwrap();
    assert_eq!(t.cmd("spawn"), "ok 100 202");
    wait_for(&d, |e| matches!(e, Event::ThreadExited { .. }));
    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &[]);
}

#[test]
fn module_breaks_and_pending_breakpoint_in_a_library() {
    let lib = test_lib();
    let mut t = Target::spawn();
    let pid = t.pid;
    let d = Debugger::attach(pid).unwrap();
    d.set_break_on(BreakOn {
        module_loaded: vec!["LIBHHTEST*".into()],
        module_unloaded: vec!["libhhtest.so".into()],
        ..BreakOn::default()
    })
    .unwrap();
    let id = d
        .add_pending_breakpoint(
            "libhhtest.hh_lib_add",
            Breakpoint::execute(0),
            Hooks::default(),
            BpOptions::default(),
            BpExtra::default(),
        )
        .unwrap();
    assert!(!info(&d, id).resolved);
    let mut last = 0;
    for round in 0..2 {
        t.send(&format!("dlopen {}", lib.display()));
        let (why, _, _) = wait_stopped(&d);
        let Trigger::ModuleLoaded(m) = why else {
            fail(&d, &format!("{why:?}"))
        };
        assert_eq!(m.name, "libhhtest.so");
        let i = info(&d, id);
        assert!(i.resolved && i.enabled, "round {round}: {i:?}");
        assert!(i.bp.address >= m.base && i.bp.address < m.base + m.size);
        assert_eq!(raw_byte(pid, i.bp.address), 0xcc);
        d.cont(false).unwrap();
        assert_eq!(t.recv(), "ok 100 200");
        t.send("libcall 41");
        let (_, r, c) = wait_break(&d);
        assert_eq!((r, c.rip), (BreakReason::Breakpoint(id), i.bp.address));
        d.cont(false).unwrap();
        assert_eq!(t.recv(), "lib 42");
        last = i.bp.address;
        if round == 1 {
            break;
        }
        t.send("dlclose");
        let (why, _, _) = wait_stopped(&d);
        assert!(
            matches!(&why, Trigger::ModuleUnloaded(m) if m.name == "libhhtest.so"),
            "{why:?}"
        );
        let i = info(&d, id);
        assert!(!i.resolved && !i.enabled, "{i:?}");
        d.cont(false).unwrap();
        assert_eq!(t.recv(), "ok");
        // The int3 went with the mapping; nothing of ours is remembered there.
        let mapped = d
            .process()
            .regions()
            .unwrap()
            .iter()
            .any(|r| last >= r.start && last < r.start + r.size);
        if mapped {
            assert_ne!(raw_byte(pid, last), 0xcc);
        }
    }
    let orig = masked_byte(&d, last);
    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &[(last, orig)]);
    assert_eq!(t.cmd("libcall 1"), "lib 2");
}

// ---- item 4: breakpoint filters, tracepoints, value conditions ----------------------------

#[test]
fn thread_filter_tracepoints_and_value_conditions() {
    let mut t = Target::spawn();
    let pid = t.pid;
    let d = Debugger::attach(pid).unwrap();
    let (store, value, buf) = (t.addr("store"), t.addr("value"), t.addr("buf"));

    // Only the main thread breaks; the spawned one runs past silently.
    let only_main = BpExtra {
        thread: Some(pid),
        ..BpExtra::default()
    };
    let id = d
        .add_breakpoint_ext(
            Breakpoint::execute(store),
            Hooks::default(),
            BpOptions::default(),
            only_main,
        )
        .unwrap();
    assert_eq!(t.cmd("spawn"), "ok 100 201");
    assert_eq!(hits(&d, id), 0);
    t.send("store");
    let (tid, r, _) = wait_break(&d);
    assert_eq!((tid, r), (pid, BreakReason::Breakpoint(id)));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 201");
    d.remove_breakpoint(id).unwrap();

    // Tracepoint: logs instead of breaking.
    let hooks = Hooks {
        message: Some(Arc::new(|c: &Context, _: Option<&DataHit>| {
            format!("store {}", c.rsi)
        })),
        ..Hooks::default()
    };
    let tp = d
        .add_breakpoint_ext(
            Breakpoint::execute(store),
            hooks,
            BpOptions::default(),
            BpExtra {
                log_only: true,
                ..BpExtra::default()
            },
        )
        .unwrap();
    assert_eq!(t.cmd("store"), "ok 102 201");
    wait_for(
        &d,
        |e| matches!(e, Event::Log { bp, text, .. } if *bp == tp && text == "store 102"),
    );
    d.remove_breakpoint(tp).unwrap();

    // Debug-register write watch that breaks only when the new value is 104.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let hooks = Hooks {
        value_condition: Some(Arc::new(move |_: &Context, h: &DataHit| {
            s2.lock().unwrap().push((h.old, h.new));
            h.new == Some(104)
        })),
        ..Hooks::default()
    };
    let w = d
        .add_breakpoint(
            Breakpoint {
                action: Action::Break,
                ..Breakpoint::watch(value, 8, BpKind::Write)
            },
            hooks,
        )
        .unwrap();
    assert_eq!(t.cmd("store"), "ok 103 201");
    t.send("store");
    let (_, r, _) = wait_break(&d);
    assert_eq!(r, BreakReason::Breakpoint(w));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 104 201");
    assert_eq!(hits(&d, w), 1);
    assert_eq!(
        *seen.lock().unwrap(),
        [(Some(102), Some(103)), (Some(103), Some(104))]
    );
    d.remove_breakpoint(w).unwrap();

    // Page watch as a tracepoint: the exact old / new value.
    let hooks = Hooks {
        message: Some(Arc::new(|_: &Context, h: Option<&DataHit>| {
            let h = h.unwrap();
            format!("{:?}->{:?}", h.old, h.new)
        })),
        ..Hooks::default()
    };
    let pw = d
        .add_breakpoint_ext(
            Breakpoint {
                address: buf,
                kind: BpKind::Write,
                size: 8,
                method: BpMethod::Page,
                action: Action::Break,
            },
            hooks,
            BpOptions::default(),
            BpExtra {
                log_only: true,
                ..BpExtra::default()
            },
        )
        .unwrap();
    assert_eq!(t.cmd("bufw 0"), "buf 1");
    wait_for(
        &d,
        |e| matches!(e, Event::Log { bp, text, .. } if *bp == pw && text == "Some(0)->Some(1)"),
    );
    d.remove_breakpoint(pw).unwrap();

    // "Access from outside module X".
    let a = d
        .add_breakpoint_ext(
            Breakpoint::watch(value, 8, BpKind::Access),
            Hooks::default(),
            BpOptions::default(),
            BpExtra {
                outside_module: Some("hh-debug-target".into()),
                ..BpExtra::default()
            },
        )
        .unwrap();
    assert_eq!(t.cmd("store"), "ok 105 201");
    assert_eq!(hits(&d, a), 0, "every access is from the target itself");
    d.set_extra(
        a,
        BpExtra {
            outside_module: Some("libc.so.6".into()),
            ..BpExtra::default()
        },
    )
    .unwrap();
    assert_eq!(t.cmd("store"), "ok 106 201");
    assert!(hits(&d, a) >= 2);
    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &[(store, 0x48)]);
}

// ---- item 2: trace options, capture, save / load, coverage --------------------------------

fn trace_bp(at: u64, steps: u32, opts: TraceOptions) -> (Breakpoint, BpExtra) {
    (
        Breakpoint {
            action: Action::Trace {
                steps,
                step_over_calls: false,
            },
            ..Breakpoint::execute(at)
        },
        BpExtra {
            trace: opts,
            ..BpExtra::default()
        },
    )
}

fn add_trace(d: &Debugger, at: u64, steps: u32, opts: TraceOptions) -> BpId {
    let (bp, extra) = trace_bp(at, steps, opts);
    d.add_breakpoint_ext(bp, Hooks::default(), BpOptions::default(), extra)
        .unwrap()
}

fn trace_done(d: &Debugger, id: BpId) -> Vec<u64> {
    wait_for(d, |e| matches!(e, Event::TraceDone { bp, .. } if *bp == id));
    d.trace(id).unwrap().iter().map(|c| c.rip).collect()
}

#[test]
fn trace_options() {
    let mut t = Target::spawn();
    let pid = t.pid;
    let d = Debugger::attach(pid).unwrap();
    let (call, outer, store, value) = (
        t.addr("call"),
        t.addr("outer"),
        t.addr("store"),
        t.addr("value"),
    );
    let libc = d
        .process()
        .modules()
        .unwrap()
        .into_iter()
        .find(|m| m.name.starts_with("libc.so"))
        .unwrap();

    // Skip libc, end when hh_call returns.
    let opts = TraceOptions {
        skip_modules: vec!["libc.so*".into()],
        until_return: true,
        ..TraceOptions::default()
    };
    let id = add_trace(&d, call, 50_000, opts);
    assert_eq!(t.cmd("callsleep 1"), "ok");
    let rips = trace_done(&d, id);
    assert!(rips.len() > 3 && rips.len() < 50_000, "{}", rips.len());
    assert_eq!(rips[0], call);
    assert_eq!(rips[rips.len() - 2], call + 2, "the ret of hh_call");
    assert!(
        rips.iter()
            .all(|&r| r < libc.base || r >= libc.base + libc.size),
        "no step inside libc"
    );
    d.remove_breakpoint(id).unwrap();

    // Stay inside hh_call.
    let opts = TraceOptions {
        stay_in: Some((call, call + 3)),
        until_return: true,
        ..TraceOptions::default()
    };
    let id = add_trace(&d, call, 1000, opts);
    assert_eq!(t.cmd("callsleep 1"), "ok");
    let rips = trace_done(&d, id);
    assert_eq!(rips[..2], [call, call + 2]);
    assert!(rips.len() <= 3, "{rips:x?}");
    d.remove_breakpoint(id).unwrap();

    // Memory capture: what `mov [rdi], rsi` in store wrote.
    let opts = TraceOptions {
        capture_memory: true,
        ..TraceOptions::default()
    };
    let id = add_trace(&d, outer, 5, opts);
    assert_eq!(t.cmd("outer"), "ok 101 200");
    trace_done(&d, id);
    let steps = d.trace_steps(id).unwrap();
    let s = steps.iter().find(|s| s.context.rip == store).unwrap();
    let a = s.accesses.iter().find(|a| a.write).unwrap();
    assert_eq!((a.addr, a.size), (value, 8));
    assert_eq!(a.before, 100u64.to_le_bytes());
    assert_eq!(a.after.as_deref(), Some(&101u64.to_le_bytes()[..]));
    // The call pushed its return address.
    let c = steps.iter().find(|s| s.context.rip == outer + 1).unwrap();
    assert!(c.accesses.iter().any(|a| a.write && a.size == 8));

    // Save / load round trip, and bad files.
    let mut file = Vec::new();
    write_trace(&mut file, &steps).unwrap();
    assert_eq!(read_trace(&mut &file[..]).unwrap(), steps);
    let bad = String::from_utf8(file.clone())
        .unwrap()
        .replace("\"version\":1", "\"version\":2");
    assert!(read_trace(&mut bad.as_bytes()).is_err());
    let mut big = steps[..1].to_vec();
    big[0].accesses = vec![TraceAccess::default(); 65];
    let mut f2 = Vec::new();
    write_trace(&mut f2, &big).unwrap();
    assert!(read_trace(&mut &f2[..]).is_err());
    assert!(read_trace(&mut &b"{\"format\":\"x\""[..]).is_err());
    d.remove_breakpoint(id).unwrap();

    // Time limit: a 300 ms sleep traced instruction by instruction stops after ~20 ms of
    // tracing (checked per instruction, so after the blocking syscall).
    let opts = TraceOptions {
        max_ms: 20,
        ..TraceOptions::default()
    };
    let id = add_trace(&d, call, 1_000_000, opts);
    assert_eq!(t.cmd("callsleep 300"), "ok");
    let rips = trace_done(&d, id);
    assert!(rips.len() < 1_000_000);
    d.remove_breakpoint(id).unwrap();

    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &[(call, 0xff), (outer, 0x90)]);
}

#[test]
fn coverage_code_filter() {
    let mut t = Target::spawn();
    let pid = t.pid;
    let d = Debugger::attach(pid).unwrap();
    let names = ["store", "load", "outer", "hot", "rec", "rep", "f1"];
    let entries: Vec<u64> = names.iter().map(|n| t.addr(n)).collect();
    let orig: Vec<(u64, u8)> = entries.iter().map(|&a| (a, raw_byte(pid, a))).collect();
    let mut with_data = entries.clone();
    with_data.push(t.addr("value"));
    assert_eq!(d.coverage_start(with_data).unwrap(), entries.len());
    assert!(entries.iter().all(|&a| raw_byte(pid, a) == 0xcc));
    assert_eq!(t.cmd("store"), "ok 101 200");
    let a = d.coverage_stop().unwrap();
    assert!(entries.iter().all(|&a| raw_byte(pid, a) != 0xcc));
    assert_eq!(d.coverage_start(entries.clone()).unwrap(), entries.len());
    assert_eq!(t.cmd("load"), "ok 101 200");
    assert_eq!(d.coverage_hits().unwrap(), [t.addr("load")]);
    let b = d.coverage_stop().unwrap();
    let only_a: Vec<u64> = a.iter().copied().filter(|x| !b.contains(x)).collect();
    assert_eq!(only_a, [t.addr("store")]);
    assert_eq!(b, [t.addr("load")]);
    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &orig);
}

// ---- item 3: stepping options ------------------------------------------------------------

#[test]
fn stepping_options() {
    let mut t = Target::spawn();
    let pid = t.pid;
    let d = Debugger::attach(pid).unwrap();
    let (outer, store, call, hot) = (
        t.addr("outer"),
        t.addr("store"),
        t.addr("call"),
        t.addr("hot"),
    );

    // Step over a call without stopping at the breakpoint inside it.
    let bo = d
        .add_breakpoint(Breakpoint::execute(outer), Hooks::default())
        .unwrap();
    let bs = d
        .add_breakpoint(Breakpoint::execute(store), Hooks::default())
        .unwrap();
    t.send("outer");
    let (tid, _, _) = wait_break(&d);
    d.step_into(tid).unwrap();
    assert_eq!(wait_break(&d).2.rip, outer + 1);
    let skip = StepOptions {
        skip_breakpoints: true,
        ..StepOptions::default()
    };
    d.step_with(tid, StepKind::Over, skip).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Step, outer + 6));
    assert_eq!(hits(&d, bs), 0);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");
    d.remove_breakpoint(bs).unwrap();

    // Set the instruction pointer past the call: nothing is stored.
    t.send("outer");
    let (tid, _, _) = wait_break(&d);
    assert!(d.set_ip(tid, t.addr("value")).is_err(), "not executable");
    d.set_ip(tid, outer + 6).unwrap();
    assert_eq!(d.context(tid).unwrap().rip, outer + 6);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");
    d.remove_breakpoint(bo).unwrap();

    // Step into a call into a module stepped over.
    let bc = d
        .add_breakpoint(Breakpoint::execute(call), Hooks::default())
        .unwrap();
    t.send("callsleep 1");
    let (tid, _, _) = wait_break(&d);
    let over = StepOptions {
        over_modules: vec!["hh-debug-*".into()],
        ..StepOptions::default()
    };
    d.step_with(tid, StepKind::Into, over).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Step, call + 2));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok");
    d.remove_breakpoint(bc).unwrap();

    // Run until the 5th execution of hot.
    d.pause().unwrap();
    wait_break(&d);
    assert!(d.run_to_count(hot, 0, None).is_err());
    d.run_to_count(hot, 5, None).unwrap();
    t.send("mainhot 10 0");
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Step, hot));
    assert_eq!(d.process().read_ptr(t.addr("counter")).unwrap(), 4);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "hot 10");

    // Execute till return of frame 1 (f2) from inside f3.
    let (f1, f3) = (t.addr("f1"), t.addr("f3"));
    let b3 = d
        .add_breakpoint(Breakpoint::execute(f3 + 4), Hooks::default())
        .unwrap();
    t.send("deep");
    let (tid, _, c3) = wait_break(&d);
    let frames = d.backtrace(tid, 8).unwrap();
    assert!(frames.len() >= 3 && frames[2] == f1 + 9, "{frames:x?}");
    assert!(d.run_until_return(tid, 99).is_err());
    let rbp_f2 = d.process().read_ptr(c3.rbp).unwrap();
    d.run_until_return(tid, 1).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip, c.rsp), (BreakReason::Step, f1 + 9, rbp_f2 + 16));
    assert_eq!(d.process().read_ptr(t.addr("value")).unwrap(), 102);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 102 200");
    d.remove_breakpoint(b3).unwrap();

    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &[(outer, 0x90), (store, 0x48), (hot, 0xf0), (f3 + 4, 0x48)]);
}

// ---- item 5: thread list and registers -----------------------------------------------------

#[test]
fn thread_info_and_register_writes() {
    let mut t = Target::spawn();
    let pid = t.pid;
    let d = Debugger::attach(pid).unwrap();
    assert_eq!(t.cmd("named hhworker"), "ok");
    let th = d.threads().unwrap();
    let w = th
        .iter()
        .find(|x| x.name == "hhworker")
        .unwrap_or_else(|| panic!("{th:?}"));
    assert!(!w.state.is_empty());
    let main = th.iter().find(|x| x.tid == pid).unwrap();
    assert_eq!(main.name, "hh-debug-target");
    assert_eq!(t.cmd("bgstop"), "ok");

    let getfp = t.addr("getfp");
    let id = d
        .add_breakpoint(Breakpoint::execute(getfp), Hooks::default())
        .unwrap();
    t.send("ymm");
    let (tid, _, _) = wait_break(&d);
    let mut c = d.context(tid).unwrap();
    c.fpu.mxcsr = 0x7f80; // round toward zero
    c.fpu.fcw = 0x027f;
    c.fpu.st[7] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x40];
    c.fpu.xmm[0] = std::array::from_fn(|i| i as u8);
    let avx = c.fpu.has_ymm;
    if avx {
        c.fpu.ymm_hi[0] = std::array::from_fn(|i| 0xa0 + i as u8);
    }
    d.set_context(tid, c.clone()).unwrap();
    let back = d.context(tid).unwrap();
    assert_eq!(
        (back.fpu.mxcsr, back.fpu.fcw, back.fpu.st[7], back.fpu.xmm[0]),
        (0x7f80, 0x027f, c.fpu.st[7], c.fpu.xmm[0])
    );
    assert_eq!(back.fpu.ymm_hi[0], c.fpu.ymm_hi[0]);
    d.cont(false).unwrap();
    let line = t.recv();
    if avx {
        let want: String = c.fpu.xmm[0]
            .iter()
            .chain(&c.fpu.ymm_hi[0])
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(line, format!("ymm {want} 7f80"));
    } else {
        eprintln!("no AVX: YMM write not checked ({line})");
    }
    d.remove_breakpoint(id).unwrap();
    assert_no_stuck(&d, pid);
    d.detach().unwrap();
    assert_released(&mut t, &[(getfp, 0xc5)]);
}
