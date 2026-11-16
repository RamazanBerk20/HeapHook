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
