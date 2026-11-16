//! Live tests against hh-debug-target spawned as a child (ptrace_scope=1 only allows children).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use hh_core::Prot;
use hh_debug::*;

const T: Duration = Duration::from_secs(10);

struct Target {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    info: serde_json::Value,
}

impl Target {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hh-debug-target"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        // A reader thread, so a stopped target makes a test fail instead of hang.
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for l in stdout.lines() {
                let Ok(l) = l else { break };
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let first = lines.recv_timeout(T).unwrap();
        let info = serde_json::from_str(&first).unwrap();
        Target {
            child,
            stdin,
            lines,
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
    fn send(&mut self, c: &str) {
        writeln!(self.stdin, "{c}").unwrap();
        self.stdin.flush().unwrap();
    }
    fn recv(&mut self) -> String {
        self.lines.recv_timeout(T).expect("target answer")
    }
    fn cmd(&mut self, c: &str) -> String {
        self.send(c);
        self.recv()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_break(d: &Debugger) -> (Tid, BreakReason, Context) {
    loop {
        match d.next_event(T).expect("break event") {
            Event::Break {
                tid,
                reason,
                context,
            } => return (tid, reason, *context),
            Event::ProcessExited { .. } => panic!("target exited"),
            _ => {}
        }
    }
}

fn wait_for(d: &Debugger, f: impl Fn(&Event) -> bool) -> Event {
    loop {
        let e = d.next_event(T).expect("event");
        if f(&e) {
            return e;
        }
    }
}

fn tracer_pid(pid: u32) -> u32 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let l = s.lines().find(|l| l.starts_with("TracerPid:")).unwrap();
    l[10..].trim().parse().unwrap()
}

fn read_u64(d: &Debugger, a: u64) -> u64 {
    d.process().read_ptr(a).unwrap()
}

#[test]
fn attach_detach_leaves_target_running() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    assert_ne!(tracer_pid(t.pid()), 0);
    assert_eq!(d.state().unwrap(), State::Running);
    assert!(d.threads().unwrap().iter().any(|th| th.tid == t.pid()));
    assert_eq!(t.cmd("store"), "ok 101 200");
    d.detach().unwrap();
    assert_eq!(tracer_pid(t.pid()), 0);
    assert_eq!(t.cmd("store"), "ok 102 200");
    // Dropping instead of detaching also detaches.
    let d = Debugger::attach(t.pid()).unwrap();
    d.add_breakpoint(Breakpoint::execute(t.addr("store")), Hooks::default())
        .unwrap();
    drop(d);
    assert_eq!(tracer_pid(t.pid()), 0);
    assert_eq!(t.cmd("store"), "ok 103 200");
}

#[test]
fn software_breakpoint() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let store = t.addr("store");
    let raw = hh_core::open(t.pid()).unwrap();
    let id = d
        .add_breakpoint(Breakpoint::execute(store), Hooks::default())
        .unwrap();
    let mut b = [0u8; 3];
    raw.read(store, &mut b).unwrap();
    assert_eq!(b[0], 0xcc);
    // The session's process hides the int3.
    d.process().read(store, &mut b).unwrap();
    assert_eq!(b, [0x48, 0x89, 0x37]);
    for i in 1..=2u64 {
        t.send("store");
        let (tid, reason, ctx) = wait_break(&d);
        assert_eq!(reason, BreakReason::Breakpoint(id));
        assert_eq!(tid, t.pid());
        assert_eq!(ctx.rip, store);
        assert_eq!(ctx.rdi, t.addr("value"));
        assert_eq!(ctx.rsi, 100 + i);
        assert_eq!(d.state().unwrap(), State::Broken { tid });
        d.cont(false).unwrap();
        assert_eq!(t.recv(), format!("ok {} 200", 100 + i));
    }
    assert_eq!(d.breakpoints().unwrap()[0].hits, 2);
    d.remove_breakpoint(id).unwrap();
    assert_eq!(t.cmd("store"), "ok 103 200");
    raw.read(store, &mut b).unwrap();
    assert_eq!(b, [0x48, 0x89, 0x37]);
    assert!(d.events().iter().all(|e| !matches!(e, Event::Break { .. })));
}

#[test]
fn conditional_breakpoint() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let hooks = Hooks {
        condition: Some(Arc::new(|c: &Context| c.rsi == 103)),
        ..Hooks::default()
    };
    let id = d
        .add_breakpoint(Breakpoint::execute(t.addr("store")), hooks)
        .unwrap();
    assert_eq!(t.cmd("store"), "ok 101 200");
    assert_eq!(t.cmd("store"), "ok 102 200");
    t.send("store");
    let (_, reason, ctx) = wait_break(&d);
    assert_eq!((reason, ctx.rsi), (BreakReason::Breakpoint(id), 103));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 103 200");
    assert_eq!(d.breakpoints().unwrap()[0].hits, 1);
}

#[test]
fn hardware_breakpoint() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let outer = t.addr("outer");
    let bp = Breakpoint {
        method: BpMethod::Hardware,
        ..Breakpoint::execute(outer)
    };
    let id = d.add_breakpoint(bp, Hooks::default()).unwrap();
    let mut b = [0u8];
    hh_core::open(t.pid()).unwrap().read(outer, &mut b).unwrap();
    assert_eq!(b[0], 0x90, "no int3 for a hardware breakpoint");
    for i in 1..=2u64 {
        t.send("outer");
        let (_, reason, ctx) = wait_break(&d);
        assert_eq!(reason, BreakReason::Breakpoint(id));
        assert_eq!(ctx.rip, outer);
        assert_eq!(ctx.dr[0], outer);
        assert_eq!(ctx.dr[7] & 3, 1);
        d.cont(false).unwrap();
        assert_eq!(t.recv(), format!("ok {} 200", 100 + i));
    }
    let info = &d.breakpoints().unwrap()[0];
    assert_eq!((info.slot, info.hits), (Some(0), 2));
    d.remove_breakpoint(id).unwrap();
    assert_eq!(t.cmd("outer"), "ok 103 200");
    // Slots are limited and validated.
    for i in 0..4 {
        d.add_breakpoint(
            Breakpoint::watch(t.addr("value"), 8, BpKind::Write),
            Hooks::default(),
        )
        .unwrap_or_else(|e| panic!("slot {i}: {e}"));
    }
    assert!(
        d.add_breakpoint(
            Breakpoint::watch(t.addr("value2"), 8, BpKind::Write),
            Hooks::default()
        )
        .is_err()
    );
    assert!(
        d.add_breakpoint(
            Breakpoint::watch(t.addr("value") + 1, 4, BpKind::Write),
            Hooks::default()
        )
        .is_err()
    );
}

#[test]
fn find_what_writes() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let (value, store) = (t.addr("value"), t.addr("store"));
    let id = d
        .add_breakpoint(Breakpoint::watch(value, 8, BpKind::Write), Hooks::default())
        .unwrap();
    for _ in 0..3 {
        t.cmd("store");
    }
    assert_eq!(t.cmd("outer"), "ok 104 200");
    t.cmd("load");
    t.cmd("store2");
    let recs = d.records(id).unwrap();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    // The trap reports the instruction after the write; the writer ends at `ip`.
    assert_eq!(r.ip, store + 3);
    assert_eq!(r.count, 4);
    assert_eq!(r.code_at + r.code.len() as u64, r.ip);
    assert!(r.code.ends_with(&[0x48, 0x89, 0x37]));
    assert_eq!(r.context.rdi, value);
    assert!(d.events().iter().all(|e| !matches!(e, Event::Break { .. })));
    d.clear_records(id).unwrap();
    assert!(d.records(id).unwrap().is_empty());
}

#[test]
fn find_what_accesses() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let id = d
        .add_breakpoint(
            Breakpoint::watch(t.addr("value"), 8, BpKind::Access),
            Hooks::default(),
        )
        .unwrap();
    t.cmd("load");
    // `store` reads (load) then writes (store); the answer line reads again.
    assert_eq!(t.cmd("store"), "ok 101 200");
    let recs = d.records(id).unwrap();
    let ips: Vec<(u64, u64)> = recs.iter().map(|r| (r.ip, r.count)).collect();
    let (load, store) = (t.addr("load"), t.addr("store"));
    assert!(ips.contains(&(store + 3, 1)), "{ips:x?}");
    assert!(
        ips.iter().any(|&(ip, n)| ip == load + 3 && n >= 3),
        "{ips:x?}"
    );
}

#[test]
fn find_what_addresses_an_instruction_accesses() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let store = t.addr("store");
    let bp = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(store)
    };
    let hooks = Hooks {
        address_of: Some(Arc::new(|c: &Context| Some(c.rdi))),
        ..Hooks::default()
    };
    let id = d.add_breakpoint(bp, hooks).unwrap();
    assert_eq!(t.cmd("store"), "ok 101 200");
    assert_eq!(t.cmd("store"), "ok 102 200");
    assert_eq!(t.cmd("store2"), "ok 102 201");
    let got: Vec<(u64, Option<u64>, u64)> = d
        .records(id)
        .unwrap()
        .iter()
        .map(|r| (r.ip, r.address, r.count))
        .collect();
    let mut want = vec![
        (store, Some(t.addr("value")), 2),
        (store, Some(t.addr("value2")), 1),
    ];
    want.sort();
    assert_eq!(got, want);
    assert_eq!(d.records(id).unwrap()[0].code[..3], [0x48, 0x89, 0x37]);
}

#[test]
fn registers_and_stepping() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let (outer, store) = (t.addr("outer"), t.addr("store"));
    d.add_breakpoint(Breakpoint::execute(outer), Hooks::default())
        .unwrap();
    t.send("outer");
    let (tid, _, at) = wait_break(&d);
    assert_eq!((at.rip, at.rsi), (outer, 101));
    assert!(d.backtrace(tid, 4).unwrap()[0] == outer);
    assert_eq!(d.read_stack(tid, 2).unwrap().len(), 2);

    d.step_into(tid).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Step, outer + 1));
    d.step_into(tid).unwrap();
    let (_, _, c) = wait_break(&d);
    assert_eq!((c.rip, c.rsp), (store, at.rsp - 8));
    d.step_out(tid).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip, c.rsp), (BreakReason::Step, outer + 6, at.rsp));
    assert_eq!(read_u64(&d, t.addr("value")), 101);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");

    // Register writes: the stored value comes from rsi.
    t.send("outer");
    let (tid, _, _) = wait_break(&d);
    let mut c = d.context(tid).unwrap();
    c.rsi = 999;
    c.fpu.xmm[5] = [7; 16];
    d.set_context(tid, c.clone()).unwrap();
    let back = d.context(tid).unwrap();
    assert_eq!((back.rsi, back.fpu.xmm[5]), (999, [7; 16]));
    assert_eq!(back.rip, c.rip);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 999 200");
}

#[test]
fn step_over_and_run_to() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let outer = t.addr("outer");
    d.add_breakpoint(Breakpoint::execute(outer), Hooks::default())
        .unwrap();
    t.send("outer");
    let (tid, _, _) = wait_break(&d);
    d.step_into(tid).unwrap();
    assert_eq!(wait_break(&d).2.rip, outer + 1);
    d.step_over(tid).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Step, outer + 6));
    assert_eq!(read_u64(&d, t.addr("value")), 101);
    d.step_over(tid).unwrap();
    assert_eq!(wait_break(&d).2.rip, outer + 7);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");

    t.send("outer");
    wait_break(&d);
    d.run_to(outer + 6).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Step, outer + 6));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 102 200");
}

#[test]
fn break_and_trace() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let (outer, store) = (t.addr("outer"), t.addr("store"));
    let trace = |steps, over| Breakpoint {
        action: Action::Trace {
            steps,
            step_over_calls: over,
        },
        ..Breakpoint::execute(outer)
    };
    let rips = |id| -> Vec<u64> { d.trace(id).unwrap().iter().map(|c| c.rip).collect() };

    let id = d.add_breakpoint(trace(5, false), Hooks::default()).unwrap();
    assert_eq!(t.cmd("outer"), "ok 101 200");
    wait_for(
        &d,
        |e| matches!(e, Event::TraceDone { bp, steps: 5 } if *bp == id),
    );
    assert_eq!(rips(id), [outer, outer + 1, store, store + 3, outer + 6]);
    d.remove_breakpoint(id).unwrap();

    let id = d.add_breakpoint(trace(4, true), Hooks::default()).unwrap();
    assert_eq!(t.cmd("outer"), "ok 102 200");
    wait_for(
        &d,
        |e| matches!(e, Event::TraceDone { bp, .. } if *bp == id),
    );
    assert_eq!(rips(id), [outer, outer + 1, outer + 6, outer + 7]);
    d.remove_breakpoint(id).unwrap();

    let hooks = Hooks {
        stop_when: Some(Arc::new(move |c: &Context| c.rip == store + 3)),
        ..Hooks::default()
    };
    let id = d.add_breakpoint(trace(100, false), hooks).unwrap();
    t.send("outer");
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::TraceStop(id), store + 3));
    assert_eq!(rips(id).len(), 4);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 103 200");
}

#[test]
fn new_threads_are_tracked() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let (value2, store) = (t.addr("value2"), t.addr("store"));
    let w = d
        .add_breakpoint(
            Breakpoint::watch(value2, 8, BpKind::Write),
            Hooks::default(),
        )
        .unwrap();
    assert_eq!(t.cmd("spawn"), "ok 100 201");
    let Event::ThreadCreated { tid } = wait_for(&d, |e| matches!(e, Event::ThreadCreated { .. }))
    else {
        unreachable!()
    };
    wait_for(
        &d,
        |e| matches!(e, Event::ThreadExited { tid: x } if *x == tid),
    );
    let recs = d.records(w).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!((recs[0].ip, recs[0].count), (store + 3, 1));

    // A software breakpoint stops the new thread, and only the break is reported for it.
    let b = d
        .add_breakpoint(Breakpoint::execute(store), Hooks::default())
        .unwrap();
    t.send("spawn");
    let (tid, r, _) = wait_break(&d);
    assert_ne!(tid, t.pid());
    assert_eq!(r, BreakReason::Breakpoint(b));
    assert!(d.threads().unwrap().iter().any(|th| th.tid == tid));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 100 202");
}

#[test]
fn process_wrapper_while_attached() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let p = d.process();
    let rw = Prot {
        r: true,
        w: true,
        x: false,
    };
    // The plain backend's own ptrace seize cannot work while we are the tracer.
    assert!(
        hh_core::open(t.pid())
            .unwrap()
            .alloc(0x1000, rw, None)
            .is_err()
    );

    let a = p.alloc(0x1000, rw, None).unwrap();
    p.write(a, b"hello").unwrap();
    let mut b = [0u8; 5];
    p.read(a, &mut b).unwrap();
    assert_eq!(&b, b"hello");
    let ro = Prot {
        r: true,
        ..Prot::default()
    };
    assert_eq!(p.protect(a, 0x1000, ro).unwrap(), rw);
    let r = p
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| r.start == a)
        .unwrap();
    assert_eq!(r.prot, ro);
    let store = t.addr("store");
    let n = p.alloc(0x1000, rw, Some(store)).unwrap();
    assert!(n.abs_diff(store) < 0x8000_0000);
    p.free(a, 0x1000).unwrap();
    p.free(n, 0x1000).unwrap();
    // The main thread was interrupted inside read(); it must still work.
    assert_eq!(t.cmd("store"), "ok 101 200");

    // Also while broken, and the break survives.
    d.add_breakpoint(Breakpoint::execute(store), Hooks::default())
        .unwrap();
    t.send("store");
    let (tid, _, _) = wait_break(&d);
    let a = p.alloc(0x1000, rw, None).unwrap();
    assert_eq!(d.state().unwrap(), State::Broken { tid });
    p.free(a, 0x1000).unwrap();
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 102 200");

    // Writes over a breakpoint keep it armed.
    let mut orig = [0u8; 1];
    p.read(store, &mut orig).unwrap();
    p.write(store, &orig).unwrap();
    t.send("store");
    wait_break(&d);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 103 200");
    drop(d);
    // After detach the wrapper falls back to the plain backend.
    let a = p.alloc(0x1000, rw, None).unwrap();
    p.free(a, 0x1000).unwrap();
}

#[test]
fn pause_suspend_and_threads() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let pid = t.pid();
    assert!(d.context(pid).is_err(), "running thread has no context");
    d.pause().unwrap();
    let (tid, r, c) = wait_break(&d);
    assert_eq!((tid, r), (pid, BreakReason::Pause));
    assert_eq!(d.context(pid).unwrap(), c);
    d.cont(false).unwrap();

    let p = d.process();
    p.suspend().unwrap();
    assert_eq!(d.state().unwrap(), State::Suspended);
    t.send("store");
    assert!(t.lines.recv_timeout(Duration::from_millis(300)).is_err());
    assert!(d.context(pid).is_ok());
    p.resume().unwrap();
    assert_eq!(t.recv(), "ok 101 200");

    d.suspend_thread(pid).unwrap();
    assert!(d.threads().unwrap()[0].suspended);
    t.send("store");
    assert!(t.lines.recv_timeout(Duration::from_millis(300)).is_err());
    d.resume_thread(pid).unwrap();
    assert_eq!(t.recv(), "ok 102 200");
}

#[test]
fn module_load_event() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    assert_eq!(t.cmd("dlopen libm.so.6"), "ok 100 200");
    let Event::ModuleLoaded(m) = wait_for(&d, |e| matches!(e, Event::ModuleLoaded(_))) else {
        unreachable!()
    };
    assert!(m.name.starts_with("libm"), "{m:?}");
}

#[test]
fn process_exit_ends_session() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    t.send("quit");
    wait_for(&d, |e| matches!(e, Event::ProcessExited { code: Some(0) }));
    assert_eq!(d.state().unwrap(), State::Exited);
    assert!(d.pause().is_err());
}

/// Item 1(a): while one thread steps over a software breakpoint (original byte back in
/// place) the other threads must not run past it unseen.
#[test]
fn software_breakpoint_hot_loop_from_many_threads() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let bp = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(t.addr("hot"))
    };
    let id = d.add_breakpoint(bp, Hooks::default()).unwrap();
    let (threads, iters) = (4u64, 5000u64);
    t.send(&format!("hot {threads} {iters}"));
    assert_eq!(
        t.lines
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| fail(&d, "hot loop did not finish")),
        format!("hot {}", threads * iters)
    );
    let info = &d.breakpoints().unwrap()[0];
    assert_eq!(info.hits, threads * iters, "missed hits");
    let n: u64 = d.records(id).unwrap().iter().map(|r| r.count).sum();
    assert_eq!(n, threads * iters);
    d.detach().unwrap();
    let mut b = [0u8];
    hh_core::open(t.pid())
        .unwrap()
        .read(t.addr("hot"), &mut b)
        .unwrap();
    assert_eq!(b[0], 0xf0, "no stray int3");
}

fn raw_byte(pid: u32, a: u64) -> u8 {
    let mut b = [0u8];
    hh_core::open(pid).unwrap().read(a, &mut b).unwrap();
    b[0]
}

fn proc_state(pid: u32) -> char {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    s[s.rfind(')').unwrap() + 2..].chars().next().unwrap()
}

fn wait_until(f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("condition not reached");
}

impl Target {
    fn recv_long(&mut self) -> String {
        match self.lines.recv_timeout(Duration::from_secs(60)) {
            Ok(l) => l,
            Err(e) => {
                std::thread::sleep(Duration::from_millis(200));
                panic!("target answer: {e:?}; target {:?}", self.child.try_wait());
            }
        }
    }
}

/// Item 1(b): a forked child inherits neither int3 bytes nor page protections.
#[test]
fn fork_child_runs_without_our_patches() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let store = t.addr("store");
    let bp = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(store)
    };
    let id = d.add_breakpoint(bp, Hooks::default()).unwrap();
    let w = d
        .add_watch_range(
            t.addr("value"),
            8,
            BpKind::Write,
            Action::Record,
            Hooks::default(),
            BpOptions::default(),
        )
        .unwrap();
    for _ in 0..2 {
        assert_eq!(t.cmd("fork"), "fork 42");
        wait_for(&d, |e| matches!(e, Event::Forked { .. }));
    }
    // The child's store is neither a hit nor a crash.
    assert_eq!(d.breakpoints().unwrap()[0].hits, 0);
    assert_eq!(t.cmd("store"), "ok 101 200");
    let infos = d.breakpoints().unwrap();
    assert_eq!(infos.iter().find(|i| i.id == id).unwrap().hits, 1);
    assert_eq!(infos.iter().find(|i| i.id == w).unwrap().hits, 1);
}

/// Item 1(b): a vfork child (posix_spawn) shares our memory, so it is stepped over our
/// breakpoints until it execs.
#[test]
fn vfork_child_steps_over_breakpoints() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let execve = t.addr("execve");
    let bp = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(execve)
    };
    d.add_breakpoint(bp, Hooks::default()).unwrap();
    for _ in 0..3 {
        assert_eq!(t.cmd("spawntrue"), "spawn 0");
    }
    // Guests are not our threads and their hits do not count.
    assert_eq!(d.breakpoints().unwrap()[0].hits, 0);
    assert_eq!(d.threads().unwrap().len(), 1);
    assert_eq!(raw_byte(t.pid(), execve), 0xcc);
    d.detach().unwrap();
    assert_ne!(raw_byte(t.pid(), execve), 0xcc);
    assert_eq!(t.cmd("spawntrue"), "spawn 0");
}

/// Item 1(c): after execve every breakpoint is disabled and nothing is written into the new
/// image; the loader hook comes back.
#[test]
fn exec_disables_breakpoints() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let old = t.addr("store");
    let sw = d
        .add_breakpoint(Breakpoint::execute(old), Hooks::default())
        .unwrap();
    d.add_breakpoint(
        Breakpoint::watch(t.addr("value"), 8, BpKind::Write),
        Hooks::default(),
    )
    .unwrap();
    t.send("store");
    wait_break(&d);
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");
    t.send("exec");
    t.info = serde_json::from_str(&t.recv()).unwrap();
    wait_for(&d, |e| matches!(e, Event::Exec));
    let infos = d.breakpoints().unwrap();
    assert!(
        infos.iter().all(|i| !i.enabled && i.slot.is_none()),
        "{infos:?}"
    );
    assert_eq!(infos.iter().find(|i| i.id == sw).unwrap().hits, 1);
    let store = t.addr("store");
    assert_ne!(raw_byte(t.pid(), store), 0xcc);
    assert_eq!(t.cmd("store"), "ok 101 200");
    let id = d
        .add_breakpoint(Breakpoint::execute(store), Hooks::default())
        .unwrap();
    t.send("store");
    let (tid, r, _) = wait_break(&d);
    assert_eq!((tid, r), (t.pid(), BreakReason::Breakpoint(id)));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 102 200");
    assert_eq!(t.cmd("dlopen libm.so.6"), "ok 102 200");
    wait_for(
        &d,
        |e| matches!(e, Event::ModuleLoaded(m) if m.name.starts_with("libm")),
    );
}

/// Item 1(d): the main thread exits while another keeps the process alive.
#[test]
fn main_thread_exit() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let d = Debugger::attach(pid).unwrap();
    assert_eq!(t.cmd("exitmain"), "ok");
    wait_for(
        &d,
        |e| matches!(e, Event::ThreadExited { tid } if *tid == pid),
    );
    assert!(d.threads().unwrap().iter().all(|th| th.tid != pid));
    let id = d
        .add_breakpoint(Breakpoint::execute(t.addr("store")), Hooks::default())
        .unwrap();
    t.send("store");
    let (tid, r, _) = wait_break(&d);
    assert_ne!(tid, pid);
    assert_eq!(r, BreakReason::Breakpoint(id));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");
    d.pause().unwrap();
    assert_ne!(wait_break(&d).0, pid);
    d.cont(false).unwrap();
    let p = d.process();
    let a = p
        .alloc(
            0x1000,
            Prot {
                r: true,
                w: true,
                x: false,
            },
            None,
        )
        .unwrap();
    p.free(a, 0x1000).unwrap();
    t.send("quit");
    wait_for(&d, |e| matches!(e, Event::ProcessExited { code: Some(0) }));
}

#[test]
fn main_thread_exit_then_detach() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    d.add_breakpoint(Breakpoint::execute(t.addr("store")), Hooks::default())
        .unwrap();
    assert_eq!(t.cmd("exitmain"), "ok");
    wait_for(&d, |e| matches!(e, Event::ThreadExited { .. }));
    d.detach().unwrap();
    assert_eq!(t.cmd("store"), "ok 101 200");
}

/// Item 1(e): dropping the debugger in awkward states leaves the target running, untraced
/// and unpatched.
#[test]
fn drop_while_broken_or_stepping() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let store = t.addr("store");
    // Broken at a breakpoint.
    let d = Debugger::attach(pid).unwrap();
    d.add_breakpoint(Breakpoint::execute(store), Hooks::default())
        .unwrap();
    t.send("store");
    wait_break(&d);
    drop(d);
    assert_eq!(t.recv(), "ok 101 200");
    assert_eq!((tracer_pid(pid), raw_byte(pid, store)), (0, 0x48));
    // During a step over a long call (temporary breakpoint armed, thread running).
    let call = t.addr("call");
    let d = Debugger::attach(pid).unwrap();
    d.add_breakpoint(Breakpoint::execute(call), Hooks::default())
        .unwrap();
    t.send("callsleep 300");
    let (tid, _, _) = wait_break(&d);
    d.step_over(tid).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    drop(d);
    assert_eq!(t.recv(), "ok");
    assert_eq!(tracer_pid(pid), 0);
    assert_eq!((raw_byte(pid, call), raw_byte(pid, call + 2)), (0xff, 0xc3));
    // In the middle of a hot multi-threaded breakpoint loop.
    let d = Debugger::attach(pid).unwrap();
    let bp = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(t.addr("hot"))
    };
    d.add_breakpoint(bp, Hooks::default()).unwrap();
    t.send("hot 4 200000");
    std::thread::sleep(Duration::from_millis(150));
    assert!(d.breakpoints().unwrap()[0].hits > 0);
    drop(d);
    assert_eq!(t.recv_long(), "hot 800000");
    assert_eq!((tracer_pid(pid), raw_byte(pid, t.addr("hot"))), (0, 0xf0));
}

#[test]
fn drop_with_pending_signal_and_page_watch() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let d = Debugger::attach(pid).unwrap();
    d.set_signal_action(10, SignalAction::Break).unwrap();
    d.add_watch_range(
        t.addr("buf"),
        64,
        BpKind::Access,
        Action::Record,
        Hooks::default(),
        BpOptions::default(),
    )
    .unwrap();
    t.send("raise 10");
    let (_, r, _) = wait_break(&d);
    assert!(matches!(r, BreakReason::Signal { code: 10, .. }));
    drop(d);
    // The signal the break was about is delivered, the page is usable again.
    assert_eq!(t.recv(), "sig 1 0");
    assert_eq!(t.cmd("bufw 8"), "buf 1");
    assert_eq!(tracer_pid(pid), 0);
}

/// Item 1(f): job-control stops survive attach, breaks and detach.
#[test]
fn job_control_stop() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let d = Debugger::attach(pid).unwrap();
    let id = d
        .add_breakpoint(Breakpoint::execute(t.addr("store")), Hooks::default())
        .unwrap();
    unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
    wait_until(|| matches!(proc_state(pid), 't' | 'T'));
    std::thread::sleep(Duration::from_millis(50));
    t.send("store");
    assert!(t.lines.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(d.state().unwrap(), State::Running);
    // A pause and continue keep it stopped.
    d.pause().unwrap();
    wait_break(&d);
    d.cont(false).unwrap();
    assert!(t.lines.recv_timeout(Duration::from_millis(300)).is_err());
    unsafe { libc::kill(pid as i32, libc::SIGCONT) };
    let (_, r, _) = wait_break(&d);
    assert_eq!(r, BreakReason::Breakpoint(id));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");
    // Detached while stopped: stays stopped, SIGCONT resumes it.
    unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
    wait_until(|| matches!(proc_state(pid), 't' | 'T'));
    std::thread::sleep(Duration::from_millis(50));
    d.detach().unwrap();
    assert_eq!(tracer_pid(pid), 0);
    t.send("store");
    assert!(t.lines.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(proc_state(pid), 'T');
    unsafe { libc::kill(pid as i32, libc::SIGCONT) };
    assert_eq!(t.recv(), "ok 102 200");
}

/// Item 1(g): pass / ignore / break per signal, defaults and reset.
#[test]
fn signal_policy() {
    let table = signal_table();
    let def = |c| table.iter().find(|s| s.code == c).unwrap().default;
    assert_eq!(def(11), SignalAction::Break);
    assert_eq!(def(10), SignalAction::Pass);
    assert_eq!(table.iter().find(|s| s.code == 10).unwrap().name, "SIGUSR1");

    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    assert_eq!(d.signal_action(10).unwrap(), SignalAction::Pass);
    assert_eq!(t.cmd("raise 10"), "sig 1 0");
    assert!(matches!(
        wait_for(&d, |e| matches!(e, Event::Signal { .. })),
        Event::Signal {
            code: 10,
            passed: true,
            ..
        }
    ));
    d.set_signal_action(10, SignalAction::Ignore).unwrap();
    assert_eq!(t.cmd("raise 10"), "sig 1 0");
    assert!(matches!(
        wait_for(&d, |e| matches!(e, Event::Signal { .. })),
        Event::Signal { passed: false, .. }
    ));
    d.set_signal_action(10, SignalAction::Break).unwrap();
    d.set_signal_action(12, SignalAction::Break).unwrap();
    t.send("raise 10");
    assert!(matches!(
        wait_break(&d).1,
        BreakReason::Signal { code: 10, .. }
    ));
    d.cont(true).unwrap();
    assert_eq!(t.recv(), "sig 2 0");
    t.send("raise 12");
    assert!(matches!(
        wait_break(&d).1,
        BreakReason::Signal { code: 12, .. }
    ));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "sig 2 0");
    let all = d.signal_actions().unwrap();
    assert!(all.contains(&(10, SignalAction::Break)) && all.contains(&(11, SignalAction::Break)));
    d.reset_signal_action(10).unwrap();
    assert_eq!(d.signal_action(10).unwrap(), SignalAction::Pass);
    assert_eq!(d.signal_action(12).unwrap(), SignalAction::Break);
    d.set_signal_action(11, SignalAction::Pass).unwrap();
    d.reset_signal_actions().unwrap();
    assert_eq!(d.signal_action(12).unwrap(), SignalAction::Pass);
    assert_eq!(d.signal_action(11).unwrap(), SignalAction::Break);
    assert_eq!(t.cmd("raise 12"), "sig 2 1");
}

/// Item 2: enable/disable in place, hooks and options replaced in place.
#[test]
fn enable_disable_and_options_in_place() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let store = t.addr("store");
    let rec = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(store)
    };
    let id = d.add_breakpoint(rec, Hooks::default()).unwrap();
    let hw = d
        .add_breakpoint(
            Breakpoint::watch(t.addr("value"), 8, BpKind::Write),
            Hooks::default(),
        )
        .unwrap();
    t.cmd("store");
    d.set_enabled(id, false).unwrap();
    d.set_enabled(hw, false).unwrap();
    assert_eq!(raw_byte(t.pid(), store), 0x48);
    t.cmd("store");
    let info = d.breakpoints().unwrap();
    assert!(
        info.iter()
            .all(|i| !i.enabled && i.hits == 1 && i.slot.is_none())
    );
    assert_eq!(d.records(id).unwrap().len(), 1);
    // All four slots can be taken while it is disabled; enabling then fails cleanly.
    let others: Vec<BpId> = (0..4)
        .map(|_| {
            d.add_breakpoint(
                Breakpoint::watch(t.addr("value2"), 8, BpKind::Write),
                Hooks::default(),
            )
            .unwrap()
        })
        .collect();
    assert!(d.set_enabled(hw, false).is_ok());
    assert!(d.set_enabled(hw, true).is_err());
    d.remove_breakpoint(others[0]).unwrap();
    d.set_enabled(hw, true).unwrap();
    d.set_enabled(id, true).unwrap();
    t.cmd("store");
    let info = d.breakpoints().unwrap();
    assert_eq!(info.iter().find(|i| i.id == id).unwrap().hits, 2);
    assert_eq!(info.iter().find(|i| i.id == hw).unwrap().hits, 2);

    // Condition replaced in place keeps the count.
    d.set_condition(id, Some(Arc::new(|c: &Context| c.rsi == 999)))
        .unwrap();
    t.cmd("store");
    assert_eq!(d.breakpoints().unwrap()[0].hits, 2);
    d.set_hooks(id, Hooks::default()).unwrap();
    t.cmd("store");
    assert_eq!(d.breakpoints().unwrap()[0].hits, 3);

    // Break after 2 skipped hits, once.
    let b = d
        .add_breakpoint_with(
            Breakpoint::execute(t.addr("outer")),
            Hooks::default(),
            BpOptions {
                skip_hits: 2,
                one_shot: true,
                ..BpOptions::default()
            },
        )
        .unwrap();
    assert_eq!(t.cmd("outer"), "ok 106 200");
    assert_eq!(t.cmd("outer"), "ok 107 200");
    t.send("outer");
    assert_eq!(wait_break(&d).1, BreakReason::Breakpoint(b));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 108 200");
    assert_eq!(t.cmd("outer"), "ok 109 200");
    let i = d
        .breakpoints()
        .unwrap()
        .into_iter()
        .find(|i| i.id == b)
        .unwrap();
    assert_eq!((i.hits, i.enabled), (3, false));

    // Recorder auto-stop after 2 more hits (`outer` hit it too).
    let hits = |d: &Debugger| {
        d.breakpoints()
            .unwrap()
            .into_iter()
            .find(|i| i.id == id)
            .unwrap()
    };
    let before = hits(&d).hits;
    d.set_options(
        id,
        BpOptions {
            max_hits: Some(before + 2),
            ..BpOptions::default()
        },
    )
    .unwrap();
    for _ in 0..4 {
        t.cmd("store");
    }
    wait_for(
        &d,
        |e| matches!(e, Event::BreakpointDisabled { bp } if *bp == id),
    );
    let i = hits(&d);
    assert_eq!((i.hits, i.enabled), (before + 2, false));
}

/// Item 3: page-protection watches over a range larger than a debug register.
#[test]
fn page_watch_range() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let (buf, store, load) = (t.addr("buf"), t.addr("store"), t.addr("load"));
    // 6000 bytes from buf+1000: spans two pages.
    let w = d
        .add_watch_range(
            buf + 1000,
            6000,
            BpKind::Write,
            Action::Record,
            Hooks::default(),
            BpOptions::default(),
        )
        .unwrap();
    assert_eq!(t.cmd("bufw 1000"), "buf 1");
    assert_eq!(t.cmd("bufw 6992"), "buf 1");
    assert_eq!(t.cmd("bufw 6992"), "buf 2");
    // Same pages but outside the range, and reads: not reported.
    assert_eq!(t.cmd("bufw 0"), "buf 1");
    assert_eq!(t.cmd("bufw 7000"), "buf 1");
    assert_eq!(t.cmd("bufr 2000"), "buf 0");
    let mut recs = d.records(w).unwrap();
    recs.sort_by_key(|r| r.address);
    let got: Vec<_> = recs
        .iter()
        .map(|r| (r.address, r.count, r.insn, r.ip))
        .collect();
    assert_eq!(
        got,
        [
            (Some(buf + 1000), 1, Some(store), store + 3),
            (Some(buf + 6992), 2, Some(store), store + 3)
        ]
    );
    assert_eq!(d.breakpoints().unwrap()[0].len, 6000);
    // Access watch with break: stops after the read with the reader known.
    let a = d
        .add_watch_range(
            buf + 2 * 4096 + 16,
            32,
            BpKind::Access,
            Action::Break,
            Hooks::default(),
            BpOptions::default(),
        )
        .unwrap();
    t.send("bufr 8208");
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip), (BreakReason::Breakpoint(a), load + 3));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "buf 0");
    // Removing restores the protections.
    d.remove_breakpoint(w).unwrap();
    d.remove_breakpoint(a).unwrap();
    let prot = |a: u64| {
        d.process()
            .regions()
            .unwrap()
            .into_iter()
            .find(|r| a >= r.start && a < r.start + r.size)
            .unwrap()
            .prot
    };
    assert!(prot(buf).w && prot(buf + 8192).r);
    assert_eq!(t.cmd("bufw 1000"), "buf 2");
}

/// Item 4: step over a whole `rep` instruction and over recursive calls; step out of a
/// recursion level; run to an address for one thread only.
#[test]
fn stepping_rep_recursion_and_run_to_thread() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let (rep, rec) = (t.addr("rep"), t.addr("rec"));
    let b = d
        .add_breakpoint(Breakpoint::execute(rep + 5), Hooks::default())
        .unwrap();
    t.send("rep 100");
    let (tid, _, c) = wait_break(&d);
    assert_eq!((c.rip, c.rcx), (rep + 5, 100));
    d.step_over(tid).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip, c.rcx), (BreakReason::Step, rep + 7, 0));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "rep 100");
    d.remove_breakpoint(b).unwrap();

    // `call rec` in rec(2) (rdi == 1 after the dec); the deeper call hits the same address.
    let hooks = Hooks {
        condition: Some(Arc::new(|c: &Context| c.rdi == 1)),
        ..Hooks::default()
    };
    let b = d
        .add_breakpoint(Breakpoint::execute(rec + 8), hooks)
        .unwrap();
    t.send("rec 3");
    let (tid, _, at) = wait_break(&d);
    d.step_over(tid).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip, c.rsp), (BreakReason::Step, rec + 13, at.rsp));
    // Step out of this level returns into the caller's level, right after its call.
    d.step_out(tid).unwrap();
    let (_, r, c) = wait_break(&d);
    assert_eq!((r, c.rip, c.rsp), (BreakReason::Step, rec + 13, at.rsp + 8));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok");
    d.remove_breakpoint(b).unwrap();

    // run_to_thread: another thread reaching the address first does not stop.
    let hot = t.addr("hot");
    let b = d
        .add_breakpoint(Breakpoint::execute(hot), Hooks::default())
        .unwrap();
    t.send("hot 3 3000");
    // The first worker may break before the others exist: keep going until one does.
    let other = loop {
        let (first, _, _) = wait_break(&d);
        let other = d
            .threads()
            .unwrap()
            .into_iter()
            .map(|th| th.tid)
            .find(|&x| x != first && x != t.pid());
        match other {
            Some(o) => break o,
            None => d.cont(false).unwrap(),
        }
    };
    d.remove_breakpoint(b).unwrap();
    d.run_to_thread(other, hot).unwrap();
    let (tid, r, c) = wait_break(&d);
    assert_eq!((tid, r, c.rip), (other, BreakReason::Step, hot));
    d.cont(false).unwrap();
    assert_eq!(t.recv_long(), "hot 9000");
    assert_eq!(raw_byte(t.pid(), hot), 0xf0);
}

/// Item 5 + 6: validated, annotated backtrace; records name the accessing instruction.
#[test]
fn backtrace_symbols_and_record_insn() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let (store, outer) = (t.addr("store"), t.addr("outer"));
    d.add_breakpoint(Breakpoint::execute(store), Hooks::default())
        .unwrap();
    t.send("outer");
    let (tid, _, _) = wait_break(&d);
    let f = d.backtrace_frames(tid, 16).unwrap();
    assert_eq!(f[0].addr, store);
    assert!(
        f[0].symbol.as_deref().unwrap_or("").contains("hh_store"),
        "{f:?}"
    );
    assert!(
        f[0].module
            .as_deref()
            .unwrap_or("")
            .starts_with("hh-debug-target")
    );
    let p = d.process();
    let regions = p.regions().unwrap();
    for fr in &f[1..] {
        assert!(
            regions
                .iter()
                .any(|r| r.prot.x && fr.addr >= r.start && fr.addr < r.start + r.size)
        );
    }
    // With rbp pointing at a hand-made frame [next=0, ret=outer+6] the walk finds outer.
    let mut c = d.context(tid).unwrap();
    let frame = c.rsp - 64;
    p.write(frame, &0u64.to_le_bytes()).unwrap();
    p.write(frame + 8, &(outer + 6).to_le_bytes()).unwrap();
    let saved = c.rbp;
    c.rbp = frame;
    d.set_context(tid, c.clone()).unwrap();
    assert_eq!(d.backtrace(tid, 8).unwrap(), [store, outer + 6]);
    // Garbage return address: the walk stops.
    p.write(frame + 8, &(outer + 3).to_le_bytes()).unwrap();
    assert_eq!(d.backtrace(tid, 8).unwrap(), [store]);
    c.rbp = saved;
    d.set_context(tid, c).unwrap();
    d.remove_breakpoint(1).unwrap();
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 101 200");

    let w = d
        .add_breakpoint(
            Breakpoint::watch(t.addr("value"), 8, BpKind::Write),
            Hooks::default(),
        )
        .unwrap();
    t.cmd("store");
    let r = &d.records(w).unwrap()[0];
    assert_eq!((r.ip, r.insn), (store + 3, Some(store)));
}

/// Audit 1: removing / disabling a software breakpoint on a hot instruction while other
/// threads keep hitting it must not leave any of them at A+1.
#[test]
fn remove_hot_breakpoint_while_running() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let hot = t.addr("hot");
    let rec = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(hot)
    };
    t.send("hot 4 100000");
    let mut id = d.add_breakpoint(rec.clone(), Hooks::default()).unwrap();
    for i in 0..30 {
        std::thread::sleep(Duration::from_millis(5));
        if i % 2 == 0 {
            d.remove_breakpoint(id).unwrap();
            id = d.add_breakpoint(rec.clone(), Hooks::default()).unwrap();
        } else {
            d.set_enabled(id, false).unwrap();
            d.set_enabled(id, true).unwrap();
        }
    }
    d.remove_breakpoint(id).unwrap();
    assert_eq!(t.recv_long(), "hot 400000");
    assert!(
        d.events()
            .iter()
            .all(|e| !matches!(e, Event::Break { .. } | Event::ProcessExited { .. }))
    );
}

/// Audit 3: a write through the wrapper that covers an armed int3 from before (a hook
/// over the breakpointed instruction) drops that breakpoint instead of re-planting 0xCC.
#[test]
fn write_over_breakpoint_drops_it() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let outer = t.addr("outer");
    let id = d
        .add_breakpoint(Breakpoint::execute(outer + 1), Hooks::default())
        .unwrap();
    let p = d.process();
    let mut code = [0u8; 8];
    p.read(outer, &mut code).unwrap();
    assert_eq!(raw_byte(t.pid(), outer + 1), 0xcc);
    p.write(outer, &code).unwrap();
    assert_eq!(raw_byte(t.pid(), outer + 1), 0xe8);
    wait_for(
        &d,
        |e| matches!(e, Event::BreakpointDisabled { bp } if *bp == id),
    );
    assert!(!d.breakpoints().unwrap()[0].enabled);
    assert_eq!(t.cmd("outer"), "ok 101 200");
    // Re-enabling arms it again at the new bytes.
    d.set_enabled(id, true).unwrap();
    t.send("outer");
    assert_eq!(wait_break(&d).1, BreakReason::Breakpoint(id));
    d.cont(false).unwrap();
    assert_eq!(t.recv(), "ok 102 200");
}

/// Audit 8: distinct records are capped, the overflow counted.
#[test]
fn records_are_capped() {
    let mut t = Target::spawn();
    let d = Debugger::attach(t.pid()).unwrap();
    let n = std::sync::atomic::AtomicU64::new(0);
    let n = Arc::new(n);
    let hooks = Hooks {
        address_of: Some(Arc::new(move |_: &Context| {
            Some(n.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        })),
        ..Hooks::default()
    };
    let bp = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(t.addr("hot"))
    };
    let id = d.add_breakpoint(bp, hooks).unwrap();
    let total = MAX_RECORDS as u64 + 100;
    t.send(&format!("hot 1 {total}"));
    assert_eq!(t.recv_long(), format!("hot {total}"));
    let info = &d.breakpoints().unwrap()[0];
    assert_eq!((info.hits, info.records_dropped), (total, 100));
    assert_eq!(d.records(id).unwrap().len(), MAX_RECORDS);
}

// ---- stress: invariants that must hold after any combination of breakpoints ------------
//
// Iterations per scenario come from HH_STRESS (default 4); run with HH_STRESS=200 for the
// long version. A failure prints the engine's recent event history.

fn stress_iters() -> usize {
    std::env::var("HH_STRESS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4)
}

fn fail(d: &Debugger, msg: &str) -> ! {
    let h = d.history().unwrap_or_default();
    panic!("{msg}\n--- engine history ---\n{}", h.join("\n"));
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

/// (state, context switches) of a task.
fn task_sample(pid: u32, tid: u32) -> Option<(char, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat")).ok()?;
    let st = stat[stat.rfind(')')? + 2..].chars().next()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status")).ok()?;
    let sw: u64 = status
        .lines()
        .filter(|l| l.contains("ctxt_switches:"))
        .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        .sum();
    Some((st, sw))
}

fn task_tracer(pid: u32, tid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status")).ok()?;
    s.lines()
        .find(|l| l.starts_with("TracerPid:"))
        .and_then(|l| l[10..].trim().parse().ok())
}

/// Recoveries the engine's watchdog made (from the history summary line).
fn recoveries(d: &Debugger) -> u64 {
    let h = d.history().unwrap_or_default();
    h.first()
        .and_then(|l| l.split("recoveries=").nth(1))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// No task sits in a tracing stop (unchanged, for 300 ms) while the engine says Running.
fn assert_no_stuck(d: &Debugger, pid: u32, what: &str) {
    let first: Vec<(u32, (char, u64))> = tasks(pid)
        .into_iter()
        .filter_map(|t| Some((t, task_sample(pid, t)?)))
        .collect();
    let mut stuck: Vec<u32> = first
        .iter()
        .filter(|(_, s)| s.0 == 't')
        .map(|x| x.0)
        .collect();
    for _ in 0..15 {
        if stuck.is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
        stuck.retain(|&t| {
            let f = first.iter().find(|x| x.0 == t).unwrap().1;
            task_sample(pid, t).is_some_and(|s| s.0 == 't' && s.1 == f.1)
        });
    }
    if stuck.is_empty() {
        return;
    }
    let st = d.state().unwrap();
    if !matches!(st, State::Broken { .. } | State::Suspended) {
        fail(
            d,
            &format!("{what}: tasks {stuck:?} stuck in tracing stop while {st:?}"),
        );
    }
}

/// Stops the process with `pause`, checks every task is stopped, continues.
fn pause_cont(d: &Debugger, pid: u32, what: &str) {
    if let Err(e) = d.pause() {
        fail(d, &format!("{what}: pause: {e}"));
    }
    if !matches!(d.state().unwrap(), State::Broken { .. }) {
        fail(d, &format!("{what}: not broken after pause"));
    }
    for t in tasks(pid) {
        if let Some((s, _)) = task_sample(pid, t)
            && !matches!(s, 't' | 'Z' | 'X')
        {
            // A thread past its exit event may still be on its way out.
            std::thread::sleep(Duration::from_millis(20));
            if task_sample(pid, t).is_some_and(|x| !matches!(x.0, 't' | 'Z' | 'X')) {
                fail(d, &format!("{what}: task {t} in state {s} while broken"));
            }
        }
    }
    if let Err(e) = d.cont(false) {
        fail(d, &format!("{what}: cont: {e}"));
    }
}

fn prog(t: &mut Target) -> Vec<u64> {
    let l = t.recv_after("prog");
    l.split_whitespace()
        .skip(1)
        .map(|w| w.parse().unwrap())
        .collect()
}

impl Target {
    /// Sends `c`, skipping answers of earlier commands, until a line starting like `c`.
    fn recv_after(&mut self, c: &str) -> String {
        self.send(c);
        loop {
            let l = self.recv();
            if l.starts_with(c) {
                return l;
            }
        }
    }
}

/// After detach: alive, untraced, no int3 left, pages writable again, still progressing.
fn assert_detached(t: &mut Target, int3s: &[(u64, u8)], what: &str) {
    let pid = t.pid();
    for tid in tasks(pid) {
        // A churn thread may be gone by now.
        if let Some(tp) = task_tracer(pid, tid) {
            assert_eq!(tp, 0, "{what}: task {tid} still traced");
        }
        if let Some((s, _)) = task_sample(pid, tid) {
            assert!(!matches!(s, 't' | 'T'), "{what}: task {tid} stopped ({s})");
        }
    }
    assert!(t.child.try_wait().unwrap().is_none(), "{what}: target died");
    for &(a, b) in int3s {
        assert_eq!(raw_byte(pid, a), b, "{what}: byte at {a:#x}");
    }
    let buf = t.addr("buf");
    let r = hh_core::open(pid)
        .unwrap()
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| buf >= r.start && buf < r.start + r.size)
        .unwrap();
    assert!(r.prot.r && r.prot.w, "{what}: buf protection {:?}", r.prot);
    let a = prog(t);
    std::thread::sleep(Duration::from_millis(30));
    let b = prog(t);
    assert!(
        b[0] > a[0] && b[1] > a[1],
        "{what}: no progress {a:?} -> {b:?}"
    );
}

/// Continues every breakpoint break from its own thread (like the app's Lua driver);
/// returns the events it saw.
struct Continuer {
    stop: Arc<std::sync::atomic::AtomicBool>,
    h: std::thread::JoinHandle<(Vec<Event>, Vec<String>)>,
}

impl Continuer {
    fn start(d: Arc<Debugger>) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s = stop.clone();
        let h = std::thread::spawn(move || {
            let (mut evs, mut errs) = (Vec::new(), Vec::new());
            while !s.load(std::sync::atomic::Ordering::SeqCst) {
                let Some(e) = d.next_event(Duration::from_millis(5)) else {
                    continue;
                };
                if let Event::Break {
                    reason: BreakReason::Breakpoint(_),
                    ..
                } = &e
                    && let Err(err) = d.cont(false)
                {
                    errs.push(err.to_string());
                }
                evs.push(e);
            }
            (evs, errs)
        });
        Continuer { stop, h }
    }

    /// Stops it; a break it did not get to is continued here.
    fn finish(self, d: &Debugger) -> Vec<Event> {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let (mut evs, errs) = self.h.join().unwrap();
        evs.extend(d.events());
        if !errs.is_empty() {
            fail(d, &format!("cont from the continuer failed: {errs:?}"));
        }
        if let State::Broken { .. } = d.state().unwrap() {
            d.cont(false).unwrap();
        }
        evs
    }
}

fn no_signal_breaks(d: &Debugger, evs: &[Event], what: &str) {
    for e in evs {
        if let Event::Break {
            reason: r @ BreakReason::Signal { .. },
            tid,
            ..
        } = e
        {
            fail(d, &format!("{what}: spurious {r:?} on {tid}"));
        }
        if let Event::ProcessExited { .. } = e {
            fail(d, &format!("{what}: target exited"));
        }
    }
}

fn hits(d: &Debugger, id: BpId) -> u64 {
    d.breakpoints()
        .unwrap()
        .into_iter()
        .find(|i| i.id == id)
        .map_or(0, |i| i.hits)
}

/// A software and a hardware execute breakpoint on one address: each counts every
/// execution once and each execution gives one break, continued from another thread.
#[test]
fn stress_same_address_sw_hw_breaks() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let hot = t.addr("hot");
    assert_eq!(t.cmd("bg 3 1 1 200"), "ok");
    let d = Arc::new(Debugger::attach(pid).unwrap());
    let hw = Breakpoint {
        method: BpMethod::Hardware,
        ..Breakpoint::execute(hot)
    };
    for i in 0..stress_iters() {
        let what = format!("iteration {i}");
        d.pause().unwrap();
        // Either order of creation.
        let (a, b) = match i % 2 {
            0 => (Breakpoint::execute(hot), hw.clone()),
            _ => (hw.clone(), Breakpoint::execute(hot)),
        };
        let a = d.add_breakpoint(a, Hooks::default()).unwrap();
        let b = d.add_breakpoint(b, Hooks::default()).unwrap();
        d.cont(false).unwrap();
        let c = Continuer::start(d.clone());
        std::thread::sleep(Duration::from_millis(40));
        let mut evs = c.finish(&d);
        d.pause().unwrap();
        evs.extend(d.events());
        let breaks = evs
            .iter()
            .filter(|e| {
                matches!(e, Event::Break { reason: BreakReason::Breakpoint(x), .. }
                    if *x == a || *x == b)
            })
            .count() as u64;
        let (ha, hb) = (hits(&d, a), hits(&d, b));
        if ha != hb || ha != breaks || ha == 0 {
            fail(&d, &format!("{what}: hits {ha} / {hb}, breaks {breaks}"));
        }
        no_signal_breaks(&d, &evs, &what);
        d.remove_breakpoint(a).unwrap();
        d.remove_breakpoint(b).unwrap();
        d.cont(false).unwrap();
        assert_no_stuck(&d, pid, &what);
    }
    pause_cont(&d, pid, "end");
    assert_eq!(recoveries(&d), 0, "{:#?}", d.history().unwrap());
    Arc::try_unwrap(d).ok().unwrap().detach().unwrap();
    assert_detached(&mut t, &[(hot, 0xf0)], "end");
}

/// Page watches with a small hit limit, re-armed again and again while threads keep
/// writing to the page: no fault may surface as the program's own.
#[test]
fn stress_page_watch_hit_limit_rearmed() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let buf = t.addr("buf");
    assert_eq!(t.cmd("bg 2 3 1 0"), "ok");
    let d = Debugger::attach(pid).unwrap();
    let mut evs = Vec::new();
    for i in 0..stress_iters() * 3 {
        let what = format!("iteration {i}");
        let opts = BpOptions {
            max_hits: Some(1 + i as u64 % 4),
            ..BpOptions::default()
        };
        let w = d
            .add_watch_range(
                buf,
                64,
                BpKind::Write,
                Action::Record,
                Hooks::default(),
                opts,
            )
            .unwrap();
        loop {
            match d.next_event(T) {
                Some(Event::BreakpointDisabled { bp }) if bp == w => break,
                Some(e) => evs.push(e),
                None => fail(&d, &format!("{what}: watch never reached its limit")),
            }
        }
        let h = hits(&d, w);
        if h != 1 + i as u64 % 4 {
            fail(&d, &format!("{what}: {h} hits"));
        }
        if i % 2 == 0 {
            d.remove_breakpoint(w).unwrap();
        }
        evs.extend(d.events());
        no_signal_breaks(&d, &evs, &what);
        if let State::Broken { .. } = d.state().unwrap() {
            fail(&d, &format!("{what}: left broken"));
        }
    }
    assert_no_stuck(&d, pid, "end");
    pause_cont(&d, pid, "end");
    assert_eq!(recoveries(&d), 0, "{:#?}", d.history().unwrap());
    d.detach().unwrap();
    assert_detached(&mut t, &[], "end");
}

/// run_to_thread while breakpoints on the same code are hot, including a run-to onto the
/// address of a software + hardware breakpoint pair.
#[test]
fn stress_run_to_thread_while_hot() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let hot = t.addr("hot");
    assert_eq!(t.cmd("bg 3 1 1 100"), "ok");
    let d = Debugger::attach(pid).unwrap();
    let rec = Breakpoint {
        action: Action::Record,
        ..Breakpoint::execute(hot)
    };
    let hw = Breakpoint {
        method: BpMethod::Hardware,
        ..rec.clone()
    };
    // Added while paused, so both see the same executions.
    d.pause().unwrap();
    let r1 = d.add_breakpoint(rec, Hooks::default()).unwrap();
    let r2 = d.add_breakpoint(hw, Hooks::default()).unwrap();
    d.cont(false).unwrap();
    d.events();
    for i in 0..stress_iters() * 2 {
        let what = format!("iteration {i}");
        // Learn a thread that runs `hot` from a one-shot break on it.
        let once = d
            .add_breakpoint_with(
                Breakpoint {
                    method: BpMethod::Hardware,
                    ..Breakpoint::execute(hot + 4)
                },
                Hooks::default(),
                BpOptions {
                    one_shot: true,
                    ..BpOptions::default()
                },
            )
            .unwrap();
        let (tid, r) = loop {
            match d.next_event(T) {
                Some(Event::Break { tid, reason, .. }) => break (tid, reason),
                Some(_) => {}
                None => fail(&d, &format!("{what}: no break on the one-shot")),
            }
        };
        if r != BreakReason::Breakpoint(once) {
            fail(&d, &format!("{what}: {r:?}"));
        }
        d.remove_breakpoint(once).unwrap();
        let to = if i % 2 == 0 { hot } else { hot + 4 };
        if d.run_to_thread(tid, to).is_err() {
            // The thread (a churn one) exited meanwhile.
            d.cont(false).unwrap();
            continue;
        }
        let deadline = std::time::Instant::now() + T;
        loop {
            if std::time::Instant::now() > deadline {
                fail(&d, &format!("{what}: no stop"));
            }
            let e = d
                .next_event(T)
                .unwrap_or_else(|| fail(&d, &format!("{what}: no stop")));
            match e {
                Event::Break {
                    tid: x,
                    reason,
                    context,
                } => {
                    if x != tid || reason != BreakReason::Step || context.rip != to {
                        fail(&d, &format!("{what}: {x} {reason:?} {:#x}", context.rip));
                    }
                    break;
                }
                Event::ThreadExited { tid: x } if x == tid => {
                    // A churn thread that left before reaching it: nothing to stop at.
                    d.pause().unwrap();
                    wait_break(&d);
                    break;
                }
                Event::ProcessExited { .. } => fail(&d, "exited"),
                _ => {}
            }
        }
        if hits(&d, r1) != hits(&d, r2) {
            fail(
                &d,
                &format!("{what}: hits {} / {}", hits(&d, r1), hits(&d, r2)),
            );
        }
        d.cont(false).unwrap();
        assert_no_stuck(&d, pid, &what);
    }
    pause_cont(&d, pid, "end");
    assert_eq!(recoveries(&d), 0, "{:#?}", d.history().unwrap());
    d.detach().unwrap();
    assert_detached(&mut t, &[(hot, 0xf0)], "end");
}

/// Attach, arm everything, detach (or drop) in every state, again and again.
#[test]
fn stress_attach_detach_under_load() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let (hot, store, buf) = (t.addr("hot"), t.addr("store"), t.addr("buf"));
    assert_eq!(t.cmd("bg 3 2 1 100"), "ok");
    for i in 0..stress_iters() * 2 {
        let what = format!("iteration {i}");
        let d = Arc::new(Debugger::attach(pid).unwrap());
        d.add_breakpoint(Breakpoint::execute(hot), Hooks::default())
            .unwrap();
        d.add_breakpoint(
            Breakpoint {
                method: BpMethod::Hardware,
                ..Breakpoint::execute(hot)
            },
            Hooks::default(),
        )
        .unwrap();
        d.add_breakpoint(
            Breakpoint {
                action: Action::Record,
                ..Breakpoint::execute(store)
            },
            Hooks::default(),
        )
        .unwrap();
        d.add_watch_range(
            buf,
            64,
            BpKind::Write,
            Action::Record,
            Hooks::default(),
            BpOptions {
                max_hits: Some(1 + i as u64 % 5),
                ..BpOptions::default()
            },
        )
        .unwrap();
        let c = Continuer::start(d.clone());
        std::thread::sleep(Duration::from_millis(10 + (i as u64 % 4) * 10));
        let evs = match i % 3 {
            // Detach while it runs (the continuer still going).
            0 => {
                c.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                let (evs, _) = c.h.join().unwrap();
                evs
            }
            // Detach while broken.
            1 => {
                let evs = c.finish(&d);
                d.pause().unwrap();
                evs
            }
            _ => c.finish(&d),
        };
        no_signal_breaks(&d, &evs, &what);
        assert_eq!(recoveries(&d), 0, "{what}: {:#?}", d.history().unwrap());
        let d = Arc::try_unwrap(d).ok().unwrap();
        if i % 2 == 0 {
            d.detach().unwrap();
        } else {
            drop(d);
        }
        assert_detached(&mut t, &[(hot, 0xf0), (store, 0x48)], &what);
    }
}

/// The host waiting on its child (`waitpid(pid, WNOHANG)`, as `Child::try_wait` does) takes
/// the main thread's ptrace stops away from the debugger. The reported stall: the main
/// thread left in a tracing stop while the engine believes it runs. The engine must notice
/// and recover, and detach must not kill the target.
#[test]
fn stress_stolen_main_thread_stops() {
    let mut t = Target::spawn();
    let pid = t.pid();
    let (hot, buf) = (t.addr("hot"), t.addr("buf"));
    assert_eq!(t.cmd("bg 1 1 0 300"), "ok");
    let d = Arc::new(Debugger::attach(pid).unwrap());
    d.add_breakpoint(Breakpoint::execute(hot), Hooks::default())
        .unwrap();
    d.add_breakpoint(
        Breakpoint {
            method: BpMethod::Hardware,
            ..Breakpoint::execute(hot)
        },
        Hooks::default(),
    )
    .unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s = stop.clone();
    let thief = std::thread::spawn(move || {
        let mut stolen = 0u32;
        while !s.load(std::sync::atomic::Ordering::SeqCst) {
            let mut st = 0;
            let r = unsafe { libc::waitpid(pid as i32, &mut st, libc::WNOHANG) };
            if r > 0 && libc::WIFSTOPPED(st) {
                stolen += 1;
            }
            // Far more often than the app's once a second, so the race is hit every run.
            std::thread::sleep(Duration::from_micros(500));
        }
        stolen
    });
    let c = Continuer::start(d.clone());
    let n = 100 * stress_iters() as u64;
    for i in 0..stress_iters() {
        let w = d
            .add_watch_range(
                buf,
                64,
                BpKind::Write,
                Action::Record,
                Hooks::default(),
                BpOptions {
                    max_hits: Some(3),
                    ..BpOptions::default()
                },
            )
            .unwrap();
        t.send(&format!("mainhot {} 0", n / stress_iters() as u64));
        let l = t
            .lines
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| fail(&d, &format!("iteration {i}: main thread stalled")));
        assert!(l.starts_with("hot "), "{l}");
        let _ = d.remove_breakpoint(w);
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let stolen = thief.join().unwrap();
    let evs = c.finish(&d);
    no_signal_breaks(&d, &evs, "end");
    assert_no_stuck(&d, pid, "end");
    pause_cont(&d, pid, "end");
    eprintln!("stolen stops: {stolen}, recoveries: {}", recoveries(&d));
    assert!(
        recoveries(&d) >= stolen as u64,
        "{:#?}",
        d.history().unwrap()
    );
    Arc::try_unwrap(d).ok().unwrap().detach().unwrap();
    assert_detached(&mut t, &[(hot, 0xf0)], "end");
}
