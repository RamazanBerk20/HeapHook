//! The command layer against a live hh-target child (ptrace_scope=1 only allows children).
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use heaphook::commands::{App, parse_addr};
use heaphook::debug::BpReq;
use heaphook::ptr::{PtrRescanReq, PtrScanReq};
use hh_scan::Fmt;
use serde_json::{Value, json};

const T: Duration = Duration::from_secs(10);

/// Builds `bin` of `package` once per test binary and returns its path.
fn exe(package: &'static str, bin: &'static str) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<Vec<&'static str>>> = OnceLock::new();
    let mut built = BUILT.get_or_init(Default::default).lock().unwrap();
    if !built.contains(&bin) {
        let ok = Command::new(env!("CARGO"))
            .args(["build", "-q", "-p", package, "--bin", bin])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("run cargo")
            .success();
        assert!(ok, "cargo build -p {package} failed");
        built.push(bin);
    }
    // This test binary lives in <target>/<profile>/deps/.
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join(bin)
}

struct Target {
    child: Child,
    stdin: ChildStdin,
    /// Lines from a reader thread, so a stopped target fails a test instead of hanging it.
    lines: Receiver<String>,
    info: Value,
}

impl Target {
    fn spawn() -> Self {
        Self::spawn_exe(exe("hh-target", "hh-target"))
    }
    fn spawn_exe(path: PathBuf) -> Self {
        let mut child = Command::new(path).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for l in stdout.lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let first = lines.recv_timeout(T).expect("target start line");
        Target { child, stdin, lines, info: serde_json::from_str(&first).unwrap() }
    }
    fn addr(&self, key: &str) -> String {
        self.info[key].as_str().unwrap().to_string()
    }
    fn send(&mut self, c: &str) {
        writeln!(self.stdin, "{c}").unwrap();
        self.stdin.flush().unwrap();
    }
    fn line(&mut self) -> String {
        self.lines.recv_timeout(T).expect("target answer")
    }
    fn cmd(&mut self, c: &str) -> Value {
        self.send(c);
        serde_json::from_str(&self.line()).unwrap()
    }
}

/// Polls `f` until it returns `Some`, failing after 10 s.
fn wait<V>(what: &str, mut f: impl FnMut() -> Option<V>) -> V {
    let t0 = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(t0.elapsed() < T, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn tracer_pid(pid: u32) -> u32 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines().find_map(|l| l.strip_prefix("TracerPid:")).unwrap().trim().parse().unwrap()
}

fn hex(a: u64) -> String {
    format!("{a:#x}")
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn de<T: serde::de::DeserializeOwned>(v: Value) -> T {
    serde_json::from_value(v).unwrap()
}

#[test]
fn commands_against_live_target() {
    let mut t = Target::spawn();
    let app = App::default();
    let pid = t.child.id();
    assert_eq!(app.regions().unwrap_err(), "no process opened");

    let info = app.open_process(pid).unwrap();
    assert_eq!((info.pid, info.name.as_str(), info.is_64bit), (pid, "hh-target", true));
    assert!(app.list_processes().unwrap().iter().any(|p| p.pid == pid));
    let regions = serde_json::to_value(app.regions().unwrap()).unwrap();
    assert!(regions[0]["start"].as_str().unwrap().starts_with("0x") && regions[0]["size"].is_u64());

    // First scan for the exact i32, inc, next scan "increased": the known address survives.
    let i32_addr = t.addr("i32");
    let first = app
        .scan_first(&de(json!({"vtype": "4bytes", "scan_type": "exact", "value": "123456", "not": false,
            "opts": {"start": "0x0", "stop": "0x7fffffffffff", "writable": "yes", "executable": "any",
                     "copy_on_write": "any", "alignment": 4, "hex": false, "case_sensitive": false,
                     "utf16": false, "rounding": "rounded", "percent": false, "pause_while_scanning": false}})))
        .unwrap();
    assert!(first.count >= 1, "first scan found nothing");
    let p = app.scan_progress().unwrap();
    assert!(!p.running && p.total > 0 && p.done == p.total, "{p:?}");
    assert_eq!(t.cmd("inc")["i32"], 123457);
    let next = app.scan_next(&de(json!({"scan_type": "increased", "value": "", "value2": null, "not": false}))).unwrap();
    assert!(next.count >= 1 && next.count <= first.count);
    let rows = app.scan_results(0, 10_000, None).unwrap();
    let row = rows.iter().find(|r| r.addr == parse_addr(&i32_addr).unwrap()).expect("i32 survived next scan");
    assert_eq!((row.value.as_deref(), row.previous.as_str(), row.first.as_str()), (Some("123457"), "123457", "123456"));
    app.scan_undo().unwrap();
    assert_eq!(app.scan_results(0, 10_000, None).unwrap().len() as u64, first.count);

    // Write (with a 0x prefix, as the UI sends hex-displayed entries) and confirm via hh-target.
    app.write_value(&i32_addr, de(json!("4bytes")), "0x3E8", &Fmt::default(), None).unwrap();
    assert_eq!(t.cmd("get")["i32"], 1000);
    let vals = app
        .read_values(de(json!([{"addr": i32_addr, "vtype": "4bytes", "len": 0, "signed": true},
                                {"addr": t.addr("str"), "vtype": "string", "len": 8},
                                {"addr": t.addr("str16"), "vtype": "string", "len": 8, "utf16": true},
                                {"addr": "0x10", "vtype": "4bytes"}])))
        .unwrap();
    assert_eq!(vals, [Some("1000".into()), Some("HeapHook".into()), Some("HeapHook".into()), None]);

    // Freeze survives inc.
    app.set_frozen(&de::<Vec<_>>(json!([{"addr": i32_addr, "vtype": "4bytes", "value": "777", "mode": "exact"}]))).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    t.cmd("inc");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(t.cmd("get")["i32"], 777);
    app.set_frozen(&[]).unwrap();

    // Raw memory.
    assert_eq!(app.read_memory(&t.addr("aob"), 8).unwrap(), "deadbeef1337c0de");
    assert_eq!(app.read_memory("0x10", 3).unwrap(), "??????");
    app.write_bytes(&t.addr("aob"), "11 22").unwrap();
    assert_eq!(app.read_memory(&t.addr("aob"), 4).unwrap(), "1122beef");

    // Pointer chain and module-relative expressions.
    let offs: Vec<String> = t.info["chain_offsets"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().into()).collect();
    let expr = format!("[[[{}]+{}]+{}]+{}", t.addr("chain"), offs[0], offs[1], offs[2]);
    assert_eq!(parse_addr(&app.resolve_address(&expr).unwrap()), parse_addr(&t.addr("chain_value")));
    let module = app.modules().unwrap().into_iter().find(|m| m.name == "hh-target").expect("hh-target module");
    let base = parse_addr(&module.base).unwrap();
    assert_eq!(parse_addr(&app.resolve_address("\"hh-target\"+10").unwrap()).unwrap(), base + 0x10);

    // Disassemble at the module's executable region.
    let code = app
        .regions()
        .unwrap()
        .into_iter()
        .find(|r| r.prot.x && r.path.as_deref().is_some_and(|p| p.ends_with("hh-target")))
        .expect("executable region of hh-target");
    let lines = app.disassemble(&code.start, 20).unwrap();
    assert_eq!(lines.len(), 20);
    assert_eq!(lines[0].addr, code.start);
    assert!(lines.iter().all(|l| l.bytes != "??" && !l.text.is_empty()), "{lines:?}");
    assert_eq!(app.assemble(&code.start, "nop\nret").unwrap(), "90c3");

    // Auto Assembler: alloc + write + registersymbol, then disable.
    let script = "[ENABLE]\nalloc(hhmem,$100)\nregistersymbol(hhmem)\nhhmem:\n  db 11 22 33 44\n  mov eax,1\n  ret\n\n[DISABLE]\nunregistersymbol(hhmem)\ndealloc(hhmem)\n";
    assert!(app.aa_check(script).unwrap().is_none());
    let bad = app.aa_check("[ENABLE]\nfoo bar\n[DISABLE]\n").unwrap().expect("syntax error");
    assert_eq!(bad.line, 2);
    let st = app.aa_execute(script, true, None).unwrap();
    let mem = app.resolve_address("hhmem").unwrap();
    assert_eq!(app.read_memory(&mem, 4).unwrap(), "11223344");
    assert_eq!(app.disassemble(&app.resolve_address("hhmem+4").unwrap(), 2).unwrap()[0].text, "mov eax,1");
    // The state crosses IPC as JSON and comes back for disable.
    let st: hh_asm::AaState = de(serde_json::to_value(&st).unwrap());
    app.aa_execute(script, false, Some(&st)).unwrap();
    assert!(app.resolve_address("hhmem").is_err(), "symbol still registered after disable");
    assert_eq!(app.read_memory(&mem, 4).unwrap(), "????????", "alloc not freed");

    // Switching process resets everything.
    let mut t2 = Target::spawn();
    app.open_process(t2.child.id()).unwrap();
    assert!(app.scan_results(0, 10, None).unwrap().is_empty());
    t2.cmd("get");
}

#[test]
fn scan_progress_and_cancel_from_another_thread() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let a2 = app.clone();
    // "unknown" over everything, byte-aligned: long enough to observe and cancel.
    let h = std::thread::spawn(move || {
        a2.scan_first(&de(json!({"vtype": "byte", "scan_type": "unknown", "opts": {"alignment": 1}})))
    });
    let mut saw_running = false;
    for _ in 0..200 {
        let p = app.scan_progress().unwrap();
        if p.running {
            saw_running = true;
            app.scan_cancel().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let r = h.join().unwrap();
    if saw_running {
        assert_eq!(r.unwrap_err(), "scan cancelled");
    } else {
        eprintln!("scan finished before it could be observed: {r:?}");
    }
    assert!(!app.scan_progress().unwrap().running);
}

#[test]
fn permission_error_text_is_unchanged() {
    // pid 1 is not our child: hh-core's Permission error must reach the UI as-is.
    let e = App::default().open_process(1).unwrap_err();
    assert!(e.starts_with("permission denied") || e.contains("ermission"), "{e}");
}

fn bp(v: Value) -> BpReq {
    de(v)
}

fn scan_exact_i32(app: &App, value: &str) -> u64 {
    app.scan_first(&de(json!({"vtype": "4bytes", "scan_type": "exact", "value": value, "not": false,
        "opts": {"start": "0x0", "stop": "0x7fffffffffff", "writable": "yes", "executable": "any",
                 "copy_on_write": "any", "alignment": 4}})))
        .unwrap()
        .count
}

#[test]
fn find_what_writes_while_scans_and_freeze_keep_working() {
    let mut t = Target::spawn();
    let app = App::default();
    let pid = t.child.id();
    app.open_process(pid).unwrap();
    let i32_addr = t.addr("i32");
    let st = app.debug_attach().unwrap();
    assert_eq!((st.attached, st.state), (true, "running"));
    assert_ne!(tracer_pid(pid), 0);

    // Find out what writes to the i32: inc writes it once.
    let id = app.debug_add_breakpoint(&bp(json!({"addr": i32_addr, "kind": "write", "size": 4, "action": "record"}))).unwrap();
    assert_eq!(t.cmd("inc")["i32"], 123457);
    let recs = wait("a write record", || Some(app.debug_records(id).unwrap()).filter(|r| !r.is_empty()));
    let r = &recs[0];
    assert_eq!(r.count, 1);
    // The trap ip is the next instruction; the record shows the one that wrote, ending at ip.
    let (at, ip) = (parse_addr(&r.addr).unwrap(), parse_addr(&r.ip).unwrap());
    assert_eq!(at + r.bytes.split(' ').count() as u64, ip, "{r:?}");
    let dst = r.text.split(',').next().unwrap();
    assert!(dst.contains('[') && (r.text.starts_with("mov") || r.text.starts_with("add") || r.text.starts_with("inc")), "not a write: {r:?}");
    assert_eq!(app.debug_breakpoints().unwrap()[0].hits, 1);
    assert_eq!(r.context["rip"], r.ip);

    // Everything else keeps working through the debugger: scan, next scan, write, freeze.
    let n = scan_exact_i32(&app, "123457");
    assert!(n >= 1);
    assert!(app.scan_results(0, 10_000, None).unwrap().iter().any(|x| x.addr == parse_addr(&i32_addr).unwrap()));
    app.write_value(&i32_addr, de(json!("4bytes")), "500", &Fmt::default(), None).unwrap();
    assert_eq!(t.cmd("get")["i32"], 500);
    app.set_frozen(&de::<Vec<_>>(json!([{"addr": i32_addr, "vtype": "4bytes", "value": "777", "mode": "exact"}]))).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    t.cmd("inc");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(t.cmd("get")["i32"], 777);
    app.set_frozen(&[]).unwrap();
    assert!(app.debug_records(id).unwrap()[0].count >= 2, "frozen writes and inc are recorded too");
    assert_ne!(tracer_pid(pid), 0, "still attached");

    // UTF-16 strings are written and frozen as UTF-16.
    let s16 = t.addr("str16");
    let utf16 = Fmt { utf16: true, ..Fmt::default() };
    app.write_value(&s16, de(json!("string")), "Hook", &utf16, None).unwrap();
    let read = |app: &App| app.read_values(de(json!([{"addr": s16, "vtype": "string", "len": 8, "utf16": true}]))).unwrap();
    assert_eq!(read(&app), [Some("HookHook".into())]);
    app.set_frozen(&de::<Vec<_>>(json!([{"addr": s16, "vtype": "string", "value": "Heap", "mode": "exact", "utf16": true, "len": 4}]))).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(read(&app), [Some("HeapHook".into())]);
    app.set_frozen(&[]).unwrap();

    // Detach: the tracer goes away and memory access switches back.
    app.debug_detach().unwrap();
    assert_eq!(tracer_pid(pid), 0);
    assert_eq!(app.debug_status().unwrap().state, "detached");
    assert!(app.debug_records(id).is_err());
    assert_eq!(t.cmd("inc")["i32"], 778);
    assert!(scan_exact_i32(&app, "778") >= 1);
    app.write_value(&i32_addr, de(json!("4bytes")), "5", &Fmt::default(), None).unwrap();
    assert_eq!(t.cmd("get")["i32"], 5);
}

#[test]
fn pointer_scan_finds_static_chain_rescans_and_exports() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    // Scanning while the debugger is attached goes through it.
    app.debug_attach().unwrap();
    let target = t.addr("chain_value");
    let offs: Vec<String> = t.info["chain_offsets"].as_array().unwrap().iter().map(|o| format!("{:X}", parse_addr(o.as_str().unwrap()).unwrap())).collect();
    let req: PtrScanReq = de(json!({"target": target, "opts": {"max_level": 3, "max_offset": 0x100, "static_only": true, "thread_stacks": false}}));
    let info = app.ptr_scan(&req).unwrap();
    assert!(info.count >= 1 && info.max_level == 3, "{info:?}");
    let p = app.ptr_progress().unwrap();
    assert!(!p.running && p.phase.is_empty());
    let find = |app: &App, count: u64| {
        let rows = app.ptr_results(0, count as usize, de(json!("4bytes")), &Fmt::default()).unwrap();
        rows.iter().position(|r| r.base.starts_with("\"hh-target\"+") && r.offsets == offs).map(|i| (i, rows[i].clone()))
    };
    let (_, row) = find(&app, info.count).expect("\"hh-target\"+off chain");
    assert_eq!(row.address.as_deref(), Some(target.as_str()));
    assert_eq!(row.value.as_deref(), Some("4242"));

    // Rescan after the value changed: same address, value filter.
    assert_eq!(t.cmd("inc")["chain_value"], 4243);
    let re: PtrRescanReq = de(json!({"target": target, "value": "4243", "vtype": "4bytes"}));
    let info2 = app.ptr_rescan(&re).unwrap();
    assert!(info2.count >= 1 && info2.count <= info.count);
    let (_, row) = find(&app, info2.count).expect("chain survives the rescan");
    assert_eq!(row.value.as_deref(), Some("4243"));
    // Column sorts: by the first offset descending, then hh-ptr's base order.
    let n = app.ptr_sort("offset", 0, true, de(json!("4bytes")), &Fmt::default()).unwrap().count;
    let rows = app.ptr_results(0, n as usize, de(json!("4bytes")), &Fmt::default()).unwrap();
    let first = |r: &heaphook::ptr::PtrRow| r.offsets.first().map(|o| i64::from_str_radix(o, 16).unwrap_or(0));
    assert!(rows.windows(2).all(|w| first(&w[0]) >= first(&w[1])));
    assert!(app.ptr_sort("value", 0, false, de(json!("4bytes")), &Fmt::default()).is_ok());
    assert_eq!(app.ptr_sort("base", 0, false, de(json!("4bytes")), &Fmt::default()).unwrap().count, n);
    let (i, _) = find(&app, n).expect("chain after sorting");
    // A value filter that matches nothing empties the set.
    let none: PtrRescanReq = de(json!({"value": "99999", "vtype": "4bytes"}));
    let tmp = tempfile::tempdir().unwrap();
    let saved = tmp.path().join("t.hhptr");
    app.ptr_save_results(saved.to_str().unwrap()).unwrap();
    assert_eq!(app.ptr_rescan(&none).unwrap().count, 0);
    assert_eq!(app.ptr_open_results(saved.to_str().unwrap()).unwrap().count, info2.count);

    // Export as a table entry; the UI resolves it as [[[addr]+o1]+o2]+o3.
    let e = app.ptr_entry(i as u64, "4bytes", "health").unwrap();
    assert_eq!((e["vtype"].as_str(), e["description"].as_str()), (Some("4bytes"), Some("health")));
    let expr = e["offsets"].as_array().unwrap().iter().fold(e["addr"].as_str().unwrap().to_string(), |x, o| format!("[{x}]+{}", o.as_str().unwrap()));
    assert_eq!(parse_addr(&app.resolve_address(&expr).unwrap()).unwrap(), parse_addr(&target).unwrap());
    let vals = app.read_values(de(json!([{"addr": app.resolve_address(&expr).unwrap(), "vtype": "4bytes"}]))).unwrap();
    assert_eq!(vals, [Some("4243".into())]);

    // Pointer map save works too.
    let map = tmp.path().join("t.hhpmap");
    app.ptr_save_map(map.to_str().unwrap()).unwrap();
    assert!(std::fs::metadata(&map).unwrap().len() > 16);
    app.debug_detach().unwrap();
}

#[test]
fn breakpoints_stepping_registers_trace() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    let pid = t.child.id();
    app.open_process(pid).unwrap();
    app.debug_attach().unwrap();
    let (store, load, outer, value) = (t.addr("store"), t.addr("load"), t.addr("outer"), t.addr("value"));
    let store_a = parse_addr(&store).unwrap();
    let broken = |app: &App| wait("a break", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken"));

    // Software breakpoint on store(p, v): `mov [rdi], rsi; ret`.
    let id = app.debug_add_breakpoint(&bp(json!({"addr": store}))).unwrap();
    t.send("store");
    let st = broken(&app);
    let tid = st.tid.unwrap();
    assert_eq!((st.rip.as_deref(), st.reason.as_deref()), (Some(store.as_str()), Some(format!("breakpoint {id}").as_str())));
    assert!(app.debug_threads().unwrap().iter().any(|th| th.tid == tid));
    let ctx = app.debug_context(tid).unwrap();
    assert_eq!(ctx["rip"], store);
    assert_eq!(ctx["rdi"], value);
    assert_eq!(ctx["fpu"]["st"].as_array().unwrap().len(), 8);
    // The return address is on top of the stack.
    let stack = app.debug_stack(tid, 4).unwrap();
    assert_eq!(stack[0].addr, ctx["rsp"]);
    assert_ne!(parse_addr(&stack[0].value).unwrap(), 0);
    // Edit a register and a flag, then step into: the store writes the edited value.
    app.debug_set_register(tid, "rsi", "0x1234").unwrap();
    let fl = parse_addr(app.debug_context(tid).unwrap()["rflags"].as_str().unwrap()).unwrap();
    app.debug_set_register(tid, "rflags", &hex(fl ^ 0x80)).unwrap();
    assert_eq!(parse_addr(app.debug_context(tid).unwrap()["rflags"].as_str().unwrap()).unwrap() & 0x80, (fl ^ 0x80) & 0x80);
    app.debug_set_register(tid, "rflags", &hex(fl)).unwrap();
    assert!(app.debug_set_register(tid, "xyz", "0x1").is_err());
    app.debug_step(tid, "into").unwrap();
    let st = wait("the step", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken" && s.rip.as_deref() == Some(hex(store_a + 3).as_str())));
    assert_eq!(st.reason.as_deref(), Some("step"));
    assert_eq!(app.read_values(de(json!([{"addr": value, "vtype": "8bytes"}]))).unwrap(), [Some("4660".into())]);
    // Step out of store lands back in the caller.
    app.debug_step(tid, "out").unwrap();
    let st = wait("step out", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken" && s.reason.as_deref() == Some("step")));
    let rip = parse_addr(st.rip.as_deref().unwrap()).unwrap();
    assert!(rip < store_a || rip > store_a + 4, "still in store: {rip:#x}");
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 4660 200");
    let b = &app.debug_breakpoints().unwrap()[0];
    assert_eq!((b.hits, b.kind, b.method, b.action, b.enabled), (1, "execute", "software", "break", true));
    // Disabled breakpoints stay listed and do not stop the target.
    app.debug_set_enabled(id, false).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 4661 200");
    app.debug_set_enabled(id, true).unwrap();
    t.send("store");
    assert_eq!(broken(&app).rip.as_deref(), Some(store.as_str()));
    app.debug_remove_breakpoint(id).unwrap();
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 4662 200");
    assert!(app.debug_breakpoints().unwrap().is_empty());

    // Run to cursor: break at outer, run to the nop after its call.
    let outer_a = parse_addr(&outer).unwrap();
    let id = app.debug_add_breakpoint(&bp(json!({"addr": outer, "method": "hardware"}))).unwrap();
    t.send("outer");
    assert_eq!(broken(&app).rip.as_deref(), Some(outer.as_str()));
    app.debug_remove_breakpoint(id).unwrap();
    app.debug_run_to(&hex(outer_a + 6), None).unwrap();
    wait("run to", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken" && s.rip.as_deref() == Some(hex(outer_a + 6).as_str())));
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 4663 200");

    // Pause and continue.
    app.debug_pause().unwrap();
    assert_eq!(broken(&app).reason.as_deref(), Some("paused"));
    app.debug_continue(false).unwrap();

    // What addresses does `mov rax, [rdi]` in load access?
    let id = app.debug_add_breakpoint(&bp(json!({"addr": load, "action": "record", "ea": true}))).unwrap();
    assert_eq!(t.cmd_line("load"), "ok 4663 200");
    let recs = wait("an access record", || Some(app.debug_records(id).unwrap()).filter(|r| !r.is_empty()));
    assert_eq!((recs[0].address.as_deref(), recs[0].addr.as_str(), recs[0].text.as_str()), (Some(value.as_str()), load.as_str(), "mov rax,[rdi]"));
    app.debug_remove_breakpoint(id).unwrap();
    // Not a memory instruction: refused.
    assert!(app.debug_add_breakpoint(&bp(json!({"addr": outer, "action": "record", "ea": true}))).is_err());

    // Break and trace from outer: nop, call store, mov [rdi],rsi, ret, nop...
    let id = app.debug_add_breakpoint(&bp(json!({"addr": outer, "action": "trace", "steps": 5}))).unwrap();
    assert_eq!(t.cmd_line("outer"), "ok 4664 200");
    let tr = wait("a trace", || Some(app.debug_trace(id).unwrap()).filter(|r| r.len() >= 5));
    assert_eq!(tr[0].addr, outer);
    assert!(tr[1].text.starts_with("call"), "{:?}", tr.iter().map(|x| &x.text).collect::<Vec<_>>());
    assert_eq!(tr[2].addr, store);
    app.debug_remove_breakpoint(id).unwrap();

    // Replace with NOPs, then restore.
    let orig = app.nop_instruction(&store).unwrap();
    assert_eq!(orig, "488937");
    assert_eq!(t.cmd_line("store"), "ok 4664 200");
    app.write_bytes(&store, &orig).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 4665 200");

    app.debug_detach().unwrap();
    assert_eq!(tracer_pid(pid), 0);
    assert_eq!(t.cmd_line("store"), "ok 4666 200");
}

impl Target {
    fn cmd_line(&mut self, c: &str) -> String {
        self.send(c);
        self.line()
    }
}

#[test]
fn breakpoint_needs_attached_debugger() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let e = app.debug_add_breakpoint(&bp(json!({"addr": "0x1000"}))).unwrap_err();
    assert_eq!(e, "the debugger is not attached");
    assert!(app.ptr_results(0, 10, de(json!("4bytes")), &Fmt::default()).is_err());
}

// ---------------------------------------------------------------- Lua and the live table

use heaphook::table::{Dropdown, DropdownItem, Entry, Hotkey, Table};

fn log_text(app: &App) -> String {
    app.lua_poll(0).unwrap().log.iter().map(|l| format!("{}: {}", l.kind, l.text)).collect::<Vec<_>>().join("\n")
}

fn i32_entry(id: i64, t: &Target) -> Entry {
    Entry { id, description: "hp".into(), addr: t.addr("i32"), ..Entry::default() }
}

fn put(app: &App, entries: Vec<Entry>) {
    let base = app.table_get().unwrap().version;
    app.table_put(Table { entries, ..Table::default() }, base).unwrap();
}

fn entry(app: &App, id: i64) -> Entry {
    fn find(l: &[Entry], id: i64) -> Option<Entry> {
        l.iter().find_map(|e| if e.id == id { Some(e.clone()) } else { find(&e.children, id) })
    }
    find(&app.table_get().unwrap().table.entries, id).expect("entry")
}

#[test]
fn lua_console_reads_writes_and_prints() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let a = t.addr("i32");
    app.lua_exec(&format!("local a = {a}\nprint('i32 =', readInteger(a))\nwriteInteger(a, 777)\nreturn readInteger(a) + 1")).unwrap();
    let log = log_text(&app);
    assert!(log.contains("out: i32 = 123456"), "{log}");
    assert!(log.contains("result: 778"), "{log}");
    assert_eq!(t.cmd("get")["i32"], 777);
    // Errors carry the position and a traceback.
    let err = app.lua_exec("local function f() error('boom') end\nf()").unwrap_err();
    assert!(err.contains("console:1: boom") && err.contains("traceback"), "{err}");
    assert!(log_text(&app).contains("err: console:1: boom"));
    // Polling from a cursor returns only newer lines.
    let next = app.lua_poll(0).unwrap().next;
    app.lua_exec("print('later')").unwrap();
    let p = app.lua_poll(next).unwrap();
    assert_eq!(p.log.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), ["print('later')", "later"]);
}

#[test]
fn aa_entry_with_lua_block_enables_and_disables() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let a = parse_addr(&t.addr("i32")).unwrap();
    let block = |v: u32, what: &str| {
        format!("{{$lua}}\nif syntaxcheck then return nil end\nprint('{what} ' .. memrec.Description)\nreturn string.format('%X:\\ndd %X', {a:#x}, {v})\n{{$asm}}\n")
    };
    let script = format!("[ENABLE]\n{}[DISABLE]\n{}", block(4321, "enable"), block(123456, "disable"));
    assert!(app.aa_check(&script).unwrap().is_none(), "{:?}", app.aa_check(&script));
    let bad = "[ENABLE]\n{$lua}\nerror('lua says no')\n{$asm}\n[DISABLE]\n";
    // The live check never runs Lua (it would run untrusted code on every keystroke).
    assert!(app.aa_check(bad).unwrap().is_none(), "aa_check ran the {{$lua}} block");
    put(&app, vec![Entry { id: 1, description: "lua patch".into(), script: Some(script), ..Entry::default() }]);

    app.table_set_active(&[1], true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 4321);
    assert!(entry(&app, 1).frozen);
    app.table_set_active(&[1], false).unwrap();
    assert_eq!(t.cmd("get")["i32"], 123456);
    assert!(!entry(&app, 1).frozen);
    let log = log_text(&app);
    assert!(log.contains("out: enable lua patch") && log.contains("out: disable lua patch"), "{log}");
}

#[test]
fn lua_flips_active_table_reflects_and_freezer_enforces() {
    let mut t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let group = Entry {
        id: 2,
        description: "group".into(),
        options: vec!["moActivateChildrenAsWell".into(), "moDeactivateChildrenAsWell".into()],
        children: vec![Entry { id: 3, description: "i64".into(), addr: t.addr("i64"), vtype: hh_scan::VType::Bytes8, ..Entry::default() }],
        ..Entry::default()
    };
    put(&app, vec![i32_entry(1, &t), group]);
    let v0 = app.table_get().unwrap().version;

    app.lua_exec("local r = getAddressList().getMemoryRecordByDescription('hp')\nr.Active = true\nassert(r.Active)").unwrap();
    assert!(entry(&app, 1).frozen, "{}", log_text(&app));
    assert!(app.lua_poll(0).unwrap().table_version > v0, "the UI sees a new version");
    assert_eq!(t.cmd("inc")["i32"], 123457);
    wait("freezer restores i32", || (t.cmd("get")["i32"] == 123456).then_some(()));

    // A group activated from Lua takes its children along (driver applies the options).
    let i64_before = t.cmd("get")["i64"].clone();
    app.lua_exec("getAddressList().getMemoryRecordByID(2).Active = true").unwrap();
    wait("child activated", || entry(&app, 3).frozen.then_some(()));
    t.cmd("inc");
    wait("freezer restores i64", || (t.cmd("get")["i64"] == i64_before).then_some(()));

    app.lua_exec("getAddressList().getMemoryRecordByDescription('hp').Active = false\ngetAddressList().getMemoryRecordByID(2).Active = false").unwrap();
    wait("child deactivated", || (!entry(&app, 3).frozen).then_some(()));
    assert!(!entry(&app, 1).frozen);
    std::thread::sleep(Duration::from_millis(300));
    let v = t.cmd("inc");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(t.cmd("get")["i32"], v["i32"], "no longer frozen");
}

#[test]
fn runaway_script_is_interrupted() {
    let app = App::default();
    let mut s = app.settings_get().unwrap();
    s.lua_budget_ms = 0;
    app.settings_set(s.clone()).unwrap();
    let a2 = app.clone();
    let h = std::thread::spawn(move || a2.lua_exec("while true do end"));
    wait("script busy", || app.lua_poll(0).unwrap().busy.then_some(()));
    app.lua_interrupt().unwrap();
    let r = h.join().unwrap();
    assert!(r.unwrap_err().contains("interrupted"));
    app.lua_exec("x = 1").unwrap();
    // The budget setting reaches the engine too.
    s.lua_budget_ms = 200;
    app.settings_set(s).unwrap();
    let t0 = Instant::now();
    assert!(app.lua_exec("while true do end").unwrap_err().contains("budget"));
    assert!(t0.elapsed() < Duration::from_secs(5));
}

#[test]
fn hotkey_actions_at_the_command_layer() {
    let mut t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let hk = |action: &str, keys: Vec<u32>, value: Option<&str>| Hotkey { action: action.into(), keys, value: value.map(Into::into), description: None, id: None };
    let mut e = i32_entry(1, &t);
    e.hotkeys = vec![
        hk("Toggle Activation", vec![17, 112], None),
        hk("Set Value", vec![17, 113], Some("500")),
        hk("Increase Value", vec![17, 114], Some("10")),
        hk("Decrease Value", vec![17, 115], Some("3")),
    ];
    put(&app, vec![e]);
    assert!(app.lua_poll(0).unwrap().hotkeys.contains(&vec![17, 112]));

    app.table_hotkey(1, 0).unwrap();
    assert!(entry(&app, 1).frozen);
    app.table_hotkey(1, 1).unwrap();
    assert_eq!(t.cmd("get")["i32"], 500);
    t.cmd("inc");
    wait("frozen to the new value", || (t.cmd("get")["i32"] == 500).then_some(()));
    // Key order does not matter; a repeat within the dedupe window fires nothing.
    assert_eq!(app.hotkey_press(&[112, 17]).unwrap(), 1);
    assert!(!entry(&app, 1).frozen);
    assert_eq!(app.hotkey_press(&[17, 112]).unwrap(), 0);
    app.table_hotkey(1, 2).unwrap();
    assert_eq!(t.cmd("get")["i32"], 510);
    assert_eq!(app.hotkey_press(&[17, 115]).unwrap(), 1);
    assert_eq!(t.cmd("get")["i32"], 507);
    assert_eq!(app.hotkey_press(&[18, 65]).unwrap(), 0, "unbound combo");

    // createHotkey from Lua goes through the same press path.
    app.lua_exec(&format!("hk = createHotkey(function() writeInteger({}, 42) end, VK_CONTROL, VK_F9)", t.addr("i32"))).unwrap();
    assert!(app.lua_poll(0).unwrap().hotkeys.contains(&vec![17, 120]));
    assert_eq!(app.hotkey_press(&[17, 120]).unwrap(), 1);
    assert_eq!(t.cmd("get")["i32"], 42);
    app.lua_exec("hk.destroy()").unwrap();
    assert!(!app.lua_poll(0).unwrap().hotkeys.contains(&vec![17, 120]));
}

#[test]
fn ct_round_trip_of_the_live_table() {
    let app = App::default();
    let item = |v: &str, t: &str| DropdownItem { value: v.into(), text: t.into() };
    let value = Entry {
        id: 2,
        description: "Difficulty".into(),
        addr: "game.exe+200".into(),
        vtype: hh_scan::VType::Byte,
        dropdown: Some(Dropdown { options: vec![item("0", "Easy"), item("1", "Hard")], read_only: true, description_only: false, display_value_as_item: true }),
        hotkeys: vec![
            Hotkey { action: "Set Value".into(), keys: vec![17, 112], value: Some("1".into()), description: Some("hard".into()), id: None },
            Hotkey { action: "Toggle Activation".into(), keys: vec![18, 65], value: None, description: None, id: None },
        ],
        ..Entry::default()
    };
    let script = Entry { id: 3, description: "script".into(), script: Some("[ENABLE]\n{$lua}\nprint(1 < 2)\n{$asm}\n[DISABLE]\n".into()), ..Entry::default() };
    let group = Entry {
        id: 1,
        description: "Group & co".into(),
        options: vec!["moHideChildren".into(), "moActivateChildrenAsWell".into()],
        children: vec![value, script],
        ..Entry::default()
    };
    let t = Table {
        entries: vec![group],
        lua_script: "print('table <script>')\n".into(),
        comments: "made by a test".into(),
        codes: vec![heaphook::table::CodeEntry { description: "mov".into(), address: "game.exe+10".into(), bytes: "89 43 58".into(), ..Default::default() }],
        ct_extra: vec![],
        structures: hh_tools::structure::from_json(r#"[{"name":"player","elements":[{"offset":0,"vtype":"pointer","description":"inv","child":"inv"},{"offset":16,"vtype":"4bytes","signed":true},{"offset":24,"vtype":"string","size":12,"utf16":true}]},{"name":"inv","elements":[{"offset":8,"vtype":"float","description":"weight"}]}]"#).unwrap(),
        ..Table::default()
    };
    app.table_put(t.clone(), 0).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    for name in ["t.CT", "t.json"] {
        let p = dir.join(name);
        app.table_export(p.to_str().unwrap()).unwrap();
        let back = app.table_open(p.to_str().unwrap(), false).unwrap();
        assert_eq!(back.table, t, "{name}");
    }
    let ct = std::fs::read_to_string(dir.join("t.CT")).unwrap();
    assert!(ct.contains("<LuaScript>print('table &lt;script&gt;')") && ct.contains("moHideChildren=\"1\""), "{ct}");
}

// ---------------------------------------------------------------- analysis tools (hh-tools)

/// The element of structure `name` at `offset`.
fn elem_at(app: &App, name: &str, offset: u64) -> usize {
    let st = app.struct_get().unwrap().into_iter().find(|s| s.name == name).expect("structure");
    st.elements.iter().position(|e| e.offset == offset).unwrap_or_else(|| panic!("no element at {offset:#x} in {:?}", st.elements))
}

#[test]
fn structure_dissect_follows_the_chain_and_exports_an_entry() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let chain = t.addr("chain");
    let offs: Vec<u64> = t.info["chain_offsets"].as_array().unwrap().iter().map(|o| parse_addr(o.as_str().unwrap()).unwrap()).collect();
    let root = app.struct_guess("root", &chain, 8).unwrap();
    assert_eq!(serde_json::to_value(root.elements[0].vtype).unwrap(), "pointer");
    // Expand [chain] -> l1, l1+o1 -> l2, l2+o2 -> l3; children are auto-guessed.
    let mut cur = heaphook::tools::EvalReq { name: "root".into(), addr: chain.clone() };
    let mut field = (0usize, parse_addr(&chain).unwrap());
    for &o in &offs[..2] {
        let next = app.struct_expand(&cur.name, field.0, &hex(field.1), 0x20).unwrap();
        let base = parse_addr(&next.addr).unwrap();
        field = (elem_at(&app, &next.name, o), base + o);
        cur = next;
    }
    let last = app.struct_expand(&cur.name, field.0, &hex(field.1), 0x20).unwrap();
    assert_eq!(app.resolve_address(&format!("[[[{chain}]+{:x}]+{:x}]", offs[0], offs[1])).unwrap(), last.addr);
    let vals = app.struct_eval(std::slice::from_ref(&last)).unwrap().pop().unwrap().unwrap();
    let f = vals.iter().find(|f| f.offset == offs[2]).expect("field at the last offset");
    assert_eq!(f.value.as_deref(), Some("4242"));
    // Export the field with its pointer path; the entry resolves to the value.
    let idx = elem_at(&app, &last.name, offs[2]);
    let es = app.struct_entries(&last.name, &chain, &[0, offs[0], offs[1]], Some(vec![idx])).unwrap();
    assert_eq!(es.len(), 1);
    let a = app.resolve_address(&heaphook::cheat::expr_of(&es[0])).unwrap();
    assert_eq!(a, t.addr("chain_value"));
    assert_eq!(t.cmd("inc")["chain_value"], 4243);
    assert_eq!(app.read_values(de(json!([{"addr": a, "vtype": "4bytes"}]))).unwrap(), [Some("4243".into())]);
    // Saved with the table: JSON and .CT keep the definitions.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let before = app.struct_get().unwrap();
    for name in ["s.json", "s.CT"] {
        let p = dir.join(name);
        app.table_export(p.to_str().unwrap()).unwrap();
        assert_eq!(app.table_open(p.to_str().unwrap(), false).unwrap().table.structures, before, "{name}");
    }
}

#[test]
fn dissect_code_functions_strings_xrefs() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let sum = app.dissect_run(&["hh-target".into()], &Default::default()).unwrap();
    assert!(sum.functions > 10 && sum.strings > 0 && sum.instructions > 1000, "{sum:?}");
    let f = app.dissect_list("functions", "", 0, 10).unwrap();
    assert_eq!(f.total, sum.functions);
    let s = app.dissect_list("strings", "unknown command", 0, 10).unwrap();
    assert!(s.total >= 1, "no referenced 'unknown command' string");
    let saddr = s.rows[0]["addr"].as_str().unwrap().to_string();
    let x = app.dissect_xrefs(&saddr, 1, 0, 10).unwrap();
    assert!(x.total >= 1 && x.rows[0].func.is_some(), "{:?}", x.rows);
    // The most-called function: its callers are listed as call references.
    let called = app.dissect_list("called", "", 0, 1).unwrap();
    let faddr = called.rows[0]["addr"].as_str().unwrap().to_string();
    let callers = called.rows[0]["callers"].as_u64().unwrap();
    let x = app.dissect_xrefs(&faddr, 1, 0, 1000).unwrap();
    assert!(x.rows.iter().filter(|r| serde_json::to_value(r.kind).unwrap() == "call").count() as u64 >= callers.min(1), "{:?}", x.rows);
    // The disassembler annotates call targets.
    let line = &app.disassemble(&faddr, 1).unwrap()[0];
    assert!(line.xrefs.as_ref().is_some_and(|c| c.calls >= 1), "{line:?}");
}

#[test]
fn memory_tools_save_load_snapshot_pointers() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let i32a = t.addr("i32");
    let range: Vec<hh_tools::memory::Range> = de(json!([{"start": i32a, "size": 64}]));
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("t.hhmem");
    let sum = app.mem_save(&range, file.to_str().unwrap()).unwrap();
    assert_eq!(sum.bytes, 64);
    app.write_value(&i32a, de(json!("4bytes")), "999", &Fmt::default(), None).unwrap();
    assert_eq!(t.cmd("get")["i32"], 999);
    let r = app.mem_load(file.to_str().unwrap(), None).unwrap();
    assert!(r.failed.is_empty());
    assert_eq!(t.cmd("get")["i32"], 123456);

    // Snapshot, inc, diff: the i32 changed.
    let snap = app.snapshot_take(&range, "before inc").unwrap();
    assert_eq!(snap.bytes, 64);
    t.cmd("inc");
    let d = app.snapshot_diff(snap.id, 100).unwrap();
    let a = parse_addr(&i32a).unwrap();
    assert!(d.iter().any(|x| x.addr <= a && a < x.addr + x.len), "{d:?}");
    assert_eq!(app.snapshot_list().unwrap().len(), 1);

    // Fill and copy.
    app.mem_fill(&t.addr("aob"), 4, "AB").unwrap();
    assert_eq!(app.read_memory(&t.addr("aob"), 8).unwrap(), "abababab1337c0de");
    app.mem_copy(&hex(a), &t.addr("aob"), 4).unwrap();
    assert_eq!(app.read_memory(&t.addr("aob"), 4).unwrap(), app.read_memory(&i32a, 4).unwrap());

    // What points to the chain's last hop.
    let l3 = app.resolve_address(&format!("[[[{}]+10]+18]", t.addr("chain"))).unwrap();
    let hits = app.find_pointers(&de(json!({"target": l3, "max_offset": 0}))).unwrap();
    assert!(!hits.is_empty() && hits.iter().all(|h| h.value == parse_addr(&l3).unwrap()));

    // Regions with tags, module header.
    let regs = app.regions_info().unwrap();
    assert!(regs.iter().any(|r| r.module.as_deref() == Some("hh-target")));
    let h = app.module_header("hh-target").unwrap();
    assert_eq!(h.format, "elf");
    assert!(!h.sections.is_empty());
    assert!(app.tools_progress().unwrap().job.is_empty());
}

#[test]
fn signatures_code_list_conditional_and_hardware_breakpoints() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let (store, load) = (t.addr("store"), t.addr("load"));
    // AOB signature: unique and found again by scanning.
    let sig = app.aob_signature(&store).unwrap();
    assert!(sig.sig.unique, "{:?}", sig.sig);
    assert_eq!(sig.found, std::slice::from_ref(&store));
    assert!(sig.sig.pattern.starts_with("48 89 37"), "{}", sig.sig.pattern);
    let script = app.aa_template(&store, "aob").unwrap();
    assert!(script.to_lowercase().contains("aobscanmodule"), "{script}");

    // Code list: add, NOP (verified), restore.
    assert_eq!(app.code_add(&store, "store").unwrap(), 0);
    app.code_nop(0).unwrap();
    let row = serde_json::to_value(&app.code_list().unwrap()[0]).unwrap();
    assert_eq!((row["state"].as_str(), row["bytes"].as_str()), (Some("nopped"), Some("48 89 37")));
    assert_eq!(t.cmd_line("store"), "ok 100 200");
    app.code_restore(0, false).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 101 200");
    app.code_remove(0).unwrap();

    // Conditional breakpoint: store(p, v) is called with v = value + 1; break only at 103.
    app.debug_attach().unwrap();
    let broken = |app: &App| wait("a break", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken"));
    assert!(app.debug_add_breakpoint(&bp(json!({"addr": store, "condition": "rsi == "}))).is_err());
    let id = app.debug_add_breakpoint(&bp(json!({"addr": store, "condition": "rsi == 103 && rdi != 0"}))).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 102 200");
    t.send("store");
    let st = broken(&app);
    assert_eq!(st.rip.as_deref(), Some(store.as_str()));
    assert_eq!(app.debug_context(st.tid.unwrap()).unwrap()["rsi"], "0x67");
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 103 200");
    // Changing the condition re-arms it.
    app.debug_set_condition(id, "rsi == 0").unwrap();
    assert_eq!(t.cmd_line("store"), "ok 104 200");
    assert_eq!(app.debug_breakpoints().unwrap()[0].condition.as_deref(), Some("rsi == 0"));
    app.debug_remove_breakpoint(id).unwrap();

    // Hardware execute breakpoint (debug register).
    let id = app.debug_add_breakpoint(&bp(json!({"addr": load, "method": "hardware"}))).unwrap();
    t.send("load");
    assert_eq!(broken(&app).rip.as_deref(), Some(load.as_str()));
    let b = app.debug_breakpoints().unwrap().into_iter().find(|b| b.id == id).unwrap();
    assert_eq!((b.method, b.kind, b.hits), ("hardware", "execute", 1));
    assert!(b.slot.is_some());
    app.debug_remove_breakpoint(id).unwrap();
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 104 200");
    app.close_process().unwrap();
    assert_eq!(tracer_pid(t.child.id()), 0);
    assert_eq!(app.regions().unwrap_err(), "no process opened");
}

#[test]
fn table_undo_redo_and_deleting_an_active_script() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let a = parse_addr(&t.addr("i32")).unwrap();
    put(&app, vec![i32_entry(1, &t)]);
    put(&app, vec![i32_entry(1, &t), i32_entry(2, &t)]);
    assert_eq!(app.table_history(false).unwrap().table.entries.len(), 1);
    assert_eq!(app.table_history(false).unwrap().table.entries.len(), 0);
    assert!(app.table_history(false).is_err());
    assert_eq!(app.table_history(true).unwrap().table.entries.len(), 1);
    assert_eq!(app.table_history(true).unwrap().table.entries.len(), 2);
    assert!(app.table_history(true).is_err());

    // Deleting an active script entry runs its [DISABLE] section first.
    let script = format!("[ENABLE]\n{a:X}:\ndd #4321\n[DISABLE]\n{a:X}:\ndd #123456\n");
    put(&app, vec![i32_entry(1, &t), Entry { id: 3, description: "patch".into(), script: Some(script), ..Entry::default() }]);
    app.table_set_active(&[3], true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 4321);
    put(&app, vec![i32_entry(1, &t)]);
    assert_eq!(t.cmd("get")["i32"], 123456);
    // Undo brings the entry back, inactive; undoing again past its activation is harmless.
    let st = app.table_history(false).unwrap();
    assert!(st.table.entries.iter().any(|e| e.id == 3 && !e.frozen));
    app.table_set_active(&[3], true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 4321);
    // Redo removes it again: disabled first.
    app.table_history(true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 123456);
}

#[test]
fn create_process_with_speedhack() {
    let app = App::default();
    let ok = Command::new(env!("CARGO"))
        .args(["build", "-q", "--release", "--manifest-path"])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/hh-inject/payload/Cargo.toml"))
        .status()
        .unwrap()
        .success();
    assert!(ok, "building the speedhack payload failed");
    let info = app.process_create(&de(json!({"program": "sleep", "args": "30", "speedhack": true}))).unwrap();
    assert_eq!(info.name, "sleep");
    let st = app.speed_set(2.5).unwrap();
    assert_eq!(st.speed, 2.5);
    assert_eq!(app.speed_get().unwrap().unwrap().speed, 2.5);
    // Lua's speedhack_setSpeed drives the same control block.
    app.lua_exec("print(speedhack_setSpeed(0.5))").unwrap();
    assert!(log_text(&app).contains("out: true"), "{}", log_text(&app));
    assert_eq!(app.speed_get().unwrap().unwrap().speed, 0.5);
    app.close_process().unwrap();
    let _ = Command::new("kill").arg(info.pid.to_string()).status();
    // Without the speedhack there is no control block.
    let info = app.process_create(&de(json!({"program": "sleep", "args": "30"}))).unwrap();
    assert!(app.speed_get().unwrap().is_none());
    assert!(app.speed_set(2.0).is_err());
    let _ = Command::new("kill").arg(info.pid.to_string()).status();
    app.close_process().unwrap();
}

// ---------- found by driving the real UI through the dev bridge ----------

#[test]
fn unknown_symbol_keeps_the_assembler_error_text() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let e = app.resolve_address("nosuchsymbol+5").unwrap_err();
    assert!(!e.contains("Some("), "debug formatting leaked into the error: {e}");
    assert!(app.resolve_address("hh-target+10").is_ok());
}

#[test]
fn lua_poll_reports_the_process_and_its_exit() {
    let mut t = Target::spawn();
    let app = App::default();
    assert!(app.lua_poll(0).unwrap().process.is_none());
    let pid = t.child.id();
    app.open_process(pid).unwrap();
    let p = serde_json::to_value(app.lua_poll(0).unwrap()).unwrap();
    assert_eq!(p["process"], json!({"pid": pid, "name": "hh-target", "is_64bit": true, "alive": true, "paused": false}));
    t.send("quit");
    t.child.wait().unwrap();
    wait("exit seen", || (!app.lua_poll(0).unwrap().process.unwrap().alive).then_some(()));
    app.close_process().unwrap();
    assert!(app.lua_poll(0).unwrap().process.is_none());
}

#[test]
fn failed_speedhack_launch_leaves_nothing_open() {
    // A static-pie binary never loads the preloaded library (and exits at once).
    let app = App::default();
    let e = app.process_create(&de(json!({"program": "/usr/bin/sln", "speedhack": true}))).unwrap_err();
    assert!(!e.is_empty());
    assert_eq!(app.regions().unwrap_err(), "no process opened", "after: {e}");
}

// ---------- release audit ----------

/// An AA script whose `{$lua}` block writes `v` to `addr` (proof the block ran).
fn lua_writes(addr: &str, v: u32) -> String {
    format!("[ENABLE]\n{{$lua}}\nwriteInteger({addr}, {v})\nreturn nil\n{{$asm}}\n[DISABLE]\n")
}

#[test]
fn aa_check_never_runs_lua() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    assert!(app.aa_check(&lua_writes(&t.addr("i32"), 777)).unwrap().is_none());
    assert_eq!(t.cmd("get")["i32"], 123456, "the syntax check executed the {{$lua}} block");
}

#[test]
fn loaded_table_lua_needs_consent() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("t.json");
    let table = Table { entries: vec![Entry { id: 1, description: "lua".into(), script: Some(lua_writes(&t.addr("i32"), 777)), ..Entry::default() }], ..Table::default() };
    heaphook::table::save(&p, &table).unwrap();
    app.table_open(p.to_str().unwrap(), false).unwrap();
    let e = app.table_set_active(&[1], true).unwrap_err();
    assert!(e.starts_with(heaphook::cheat::NEEDS_CONSENT), "{e}");
    assert_eq!(t.cmd("get")["i32"], 123456);
    // Settings "never" refuses without asking.
    let mut st = app.settings_get().unwrap();
    st.table_script = "never".into();
    app.settings_set(st.clone()).unwrap();
    assert!(app.table_set_active(&[1], true).unwrap_err().contains("never"));
    st.table_script = "ask".into();
    app.settings_set(st).unwrap();
    app.table_trust(false).unwrap();
    assert!(app.table_set_active(&[1], true).unwrap_err().contains("chose not to"));
    assert_eq!(t.cmd("get")["i32"], 123456);
    app.table_trust(true).unwrap();
    app.table_set_active(&[1], true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 777);
    // Opening a table again asks again.
    app.table_open(p.to_str().unwrap(), false).unwrap();
    assert!(app.table_set_active(&[1], true).unwrap_err().starts_with(heaphook::cheat::NEEDS_CONSENT));
}

#[test]
fn deep_or_huge_tables_are_refused_not_crashing() {
    let tmp = tempfile::tempdir().unwrap();
    let n = 10_000;
    let mut xml = String::from("<CheatTable><CheatEntries>");
    for i in 0..n {
        xml += &format!("<CheatEntry><ID>{i}</ID><Description>\"g\"</Description><GroupHeader>1</GroupHeader><CheatEntries>");
    }
    for _ in 0..n {
        xml += "</CheatEntries></CheatEntry>";
    }
    xml += "</CheatEntries></CheatTable>";
    let ct = tmp.path().join("deep.CT");
    std::fs::write(&ct, &xml).unwrap();
    let app = App::default();
    let e = app.table_open(ct.to_str().unwrap(), false).unwrap_err();
    assert!(e.contains("64 levels"), "{e}");
    // JSON as deep as serde allows, and a put just past the limit.
    let mut deep = Entry { id: 1, ..Entry::default() };
    for id in 2..=66 {
        deep = Entry { id, children: vec![deep], ..Entry::default() };
    }
    let base = app.table_get().unwrap().version;
    assert!(app.table_put(Table { entries: vec![deep.clone()], ..Table::default() }, base).unwrap_err().contains("64 levels"));
    let js = tmp.path().join("deep.json");
    heaphook::table::save(&js, &Table { entries: vec![deep], ..Table::default() }).unwrap();
    assert!(app.table_open(js.to_str().unwrap(), false).is_err());
    // Too big a file is refused before it is read.
    let big = tmp.path().join("big.json");
    std::fs::File::create(&big).unwrap().set_len(heaphook::table::MAX_FILE + 1).unwrap();
    assert!(app.table_open(big.to_str().unwrap(), false).unwrap_err().contains("too big"));
}

#[test]
fn opening_a_table_or_closing_disables_active_scripts() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let a = t.addr("i32");
    let ok = format!("[ENABLE]\n{a}:\ndd #999\n[DISABLE]\n{a}:\ndd #123456\n");
    // Its [DISABLE] writes to an unmapped address, so it cannot be disabled.
    let stuck = format!("[ENABLE]\n{a}:\ndd #999\n[DISABLE]\n10:\ndd 0\n");
    put(&app, vec![Entry { id: 1, description: "ok".into(), script: Some(ok), ..Entry::default() }]);
    app.table_set_active(&[1], true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 999);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("other.json");
    heaphook::table::save(&p, &Table::default()).unwrap();
    app.table_open(p.to_str().unwrap(), false).unwrap();
    assert_eq!(t.cmd("get")["i32"], 123456, "table_open left the script's patch in");

    put(&app, vec![Entry { id: 1, description: "stuck".into(), script: Some(stuck), ..Entry::default() }]);
    app.table_set_active(&[1], true).unwrap();
    let e = app.table_open(p.to_str().unwrap(), false).unwrap_err();
    assert!(e.contains("could not be disabled"), "{e}");
    assert!(entry(&app, 1).frozen, "refused open must keep the table");
    let st = app.table_open(p.to_str().unwrap(), true).unwrap();
    let g = &st.table.entries[0];
    assert_eq!((g.description.as_str(), g.children.len()), ("Still active from the previous table", 1));
    assert!(g.children[0].frozen && g.children[0].description == "stuck");

    // close_process undoes what it can.
    let mut cur = app.table_get().unwrap();
    cur.table.entries.push(Entry { id: 99, description: "ok".into(), script: Some(format!("[ENABLE]\n{a}:\ndd #5\n[DISABLE]\n{a}:\ndd #123456\n")), ..Entry::default() });
    app.table_put(cur.table, cur.version).unwrap();
    app.table_set_active(&[99], true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 5);
    app.close_process().unwrap();
    assert_eq!(t.cmd("get")["i32"], 123456, "close_process left the script's patch in");
    assert!(log_text(&app).contains("still patched"), "{}", log_text(&app));
}

// ---------------------------------------------------------------- debugger adoption (1.0)

fn bp_row(app: &App, id: u32) -> heaphook::debug::BpOut {
    app.debug_breakpoints().unwrap().into_iter().find(|b| b.id == id).expect("breakpoint listed")
}

#[test]
fn breakpoints_change_in_place_options_signals_backtrace() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    app.debug_attach().unwrap();
    let (store, load, outer) = (t.addr("store"), t.addr("load"), t.addr("outer"));
    let store_a = parse_addr(&store).unwrap();
    let broken = |app: &App| wait("a break", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken"));

    // Disable / enable / condition change in place: hits and records survive.
    let id = app.debug_add_breakpoint(&bp(json!({"addr": store, "action": "record"}))).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 101 200");
    assert_eq!(t.cmd_line("store"), "ok 102 200");
    assert_eq!(bp_row(&app, id).hits, 2);
    app.debug_set_enabled(id, false).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 103 200");
    let b = bp_row(&app, id);
    assert_eq!((b.enabled, b.hits, app.debug_records(id).unwrap()[0].count), (false, 2, 2));
    app.debug_set_enabled(id, true).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 104 200");
    assert_eq!(bp_row(&app, id).hits, 3, "hits kept across disable/enable");
    app.debug_set_condition(id, "rsi == 0").unwrap();
    assert_eq!(t.cmd_line("store"), "ok 105 200");
    assert_eq!((bp_row(&app, id).hits, bp_row(&app, id).condition.as_deref()), (3, Some("rsi == 0")));
    app.debug_set_condition(id, "").unwrap();
    assert_eq!(t.cmd_line("store"), "ok 106 200");
    assert_eq!(bp_row(&app, id).hits, 4, "condition cleared in place");
    // The record list names the executing instruction (HitRecord.insn), no backwards decoding.
    let r = &app.debug_records(id).unwrap()[0];
    assert_eq!((r.addr.as_str(), r.text.as_str()), (store.as_str(), "mov [rdi],rsi"));
    // Stop recording after N hits: the debugger disables it and says why.
    app.debug_set_options(id, de(json!({"max_hits": 5}))).unwrap();
    assert_eq!(t.cmd_line("store"), "ok 107 200");
    assert_eq!(t.cmd_line("store"), "ok 108 200");
    let b = wait("max hits disable", || Some(bp_row(&app, id)).filter(|b| b.note.is_some()));
    assert_eq!((b.enabled, b.hits, b.options.max_hits), (false, 5, Some(5)));
    assert!(b.note.as_deref().unwrap().contains("after 5 hits"), "{:?}", b.note);
    app.debug_remove_breakpoint(id).unwrap();

    // Break after N hits (`load` runs hh_load three times per command: load + the reply's two).
    let id = app.debug_add_breakpoint(&bp(json!({"addr": outer, "skip_hits": 2}))).unwrap();
    assert_eq!(t.cmd_line("outer"), "ok 109 200");
    assert_eq!(t.cmd_line("outer"), "ok 110 200");
    t.send("outer");
    assert_eq!(broken(&app).reason.as_deref(), Some(format!("breakpoint {id}").as_str()));
    assert_eq!(bp_row(&app, id).hits, 3);
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 111 200");
    app.debug_remove_breakpoint(id).unwrap();
    let _ = load;

    // One-shot: breaks once, then the debugger disables it (log notice).
    let id = app.debug_add_breakpoint(&bp(json!({"addr": outer, "one_shot": true}))).unwrap();
    t.send("outer");
    broken(&app);
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 112 200");
    assert_eq!(t.cmd_line("outer"), "ok 113 200");
    let b = wait("one-shot disable", || Some(bp_row(&app, id)).filter(|b| !b.enabled));
    assert!(b.note.as_deref().is_some_and(|n| n.contains("one-shot")), "{:?}", b.note);
    let log = app.debug_log(0).unwrap();
    assert!(log.lines.iter().any(|l| l.text.contains(&format!("breakpoint {id} disabled: one-shot"))), "{:?}", log.lines);
    assert!(app.debug_log(log.next).unwrap().lines.is_empty());
    app.debug_remove_breakpoint(id).unwrap();

    // Backtrace and run-to for one thread only.
    let id = app.debug_add_breakpoint(&bp(json!({"addr": store}))).unwrap();
    t.send("outer");
    let st = broken(&app);
    let tid = st.tid.unwrap();
    let frames = app.debug_backtrace(tid, 16).unwrap();
    assert_eq!(frames[0].addr, store);
    assert_eq!(frames[0].module.as_deref(), Some("hh-debug-target"), "{frames:?}");
    app.debug_remove_breakpoint(id).unwrap();
    app.debug_run_to(&hex(store_a + 3), Some(tid)).unwrap();
    let st = wait("run to (thread)", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken" && s.rip.as_deref() == Some(hex(store_a + 3).as_str())));
    assert_eq!((st.tid, st.reason.as_deref()), (Some(tid), Some("step")));
    app.debug_continue(false).unwrap();
    assert_eq!(t.line(), "ok 114 200");

    // Signals: the engine's table, an override from settings, and the reset to defaults.
    let sigs = app.debug_signals().unwrap();
    let usr1 = *sigs.iter().find(|s| s.1 == "SIGUSR1").expect("SIGUSR1 in the table");
    assert_eq!((usr1.0, usr1.2, usr1.3), (10, "pass", Some("pass")));
    let mut s = app.settings_get().unwrap();
    s.signals.insert("10".into(), "break".into());
    app.settings_set(s.clone()).unwrap();
    assert_eq!(app.debug_signals().unwrap().iter().find(|x| x.0 == 10).unwrap().3, Some("break"));
    t.send("raise 10");
    assert_eq!(broken(&app).reason.as_deref(), Some("signal 10"));
    app.debug_continue(true).unwrap();
    assert_eq!(t.line(), "sig 1 0");
    s.signals.clear();
    app.settings_set(s).unwrap();
    assert_eq!(app.debug_signals().unwrap().iter().find(|x| x.0 == 10).unwrap().3, Some("pass"), "reset to the default");
    assert_eq!(t.cmd_line("raise 10"), "sig 2 0");
    app.debug_detach().unwrap();
}

#[test]
fn page_watch_records_the_writer_and_refuses_stacks() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    app.debug_attach().unwrap();
    let (buf, store) = (parse_addr(&t.addr("buf")).unwrap(), t.addr("store"));
    let range = |a: u64, len: u64| de::<heaphook::debug::RangeReq>(json!({"addr": hex(a), "len": len, "kind": "write"}));
    let id = app.debug_watch_range(&range(buf + 0x100, 512)).unwrap();
    let b = bp_row(&app, id);
    assert_eq!((b.method, b.kind, b.len, b.action), ("page", "write", 512, "record"));
    assert_eq!(t.cmd_line("bufw 264"), "buf 1");
    // Outside the range (same page): not recorded.
    assert_eq!(t.cmd_line("bufw 8"), "buf 1");
    let recs = wait("a page-watch record", || Some(app.debug_records(id).unwrap()).filter(|r| !r.is_empty()));
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!((recs[0].addr.as_str(), recs[0].text.as_str(), recs[0].address.clone()), (store.as_str(), "mov [rdi],rsi", Some(hex(buf + 264))));
    app.debug_remove_breakpoint(id).unwrap();
    // Stack memory is refused: the [stack] mapping and the region of a thread's stack pointer.
    let stack = app.regions_info().unwrap().into_iter().find(|r| r.path.as_deref() == Some("[stack]")).expect("[stack] region");
    let e = app.debug_watch_range(&range(stack.start + stack.size - 0x100, 16)).unwrap_err();
    assert!(e.contains("stack"), "{e}");
    assert!(app.debug_watch_range(&range(buf, 0)).is_err());
    assert_eq!(t.cmd_line("bufw 264"), "buf 2");
}

#[test]
fn lua_breakpoint_function_reads_and_changes_registers() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let store = t.addr("store");
    // CE: the function returns 1 to continue; register globals are read and written back.
    app.lua_exec(&format!("debug_setBreakpoint({store}, function() seen = RSI; RSI = 500; return 1 end)")).unwrap();
    let b = app.debug_breakpoints().unwrap();
    assert_eq!((b.len(), b[0].owner, b[0].addr.as_str()), (1, "script", store.as_str()));
    assert_eq!(t.cmd_line("store"), "ok 500 200", "{}", log_text(&app));
    app.lua_exec("print('seen', seen, debug_isBroken())").unwrap();
    assert!(log_text(&app).contains("out: seen 101 false"), "{}", log_text(&app));
    // Not continued: the thread stays broken for the user, then continues from Lua.
    app.lua_exec(&format!("debug_setBreakpoint({store}, function() EAX = 1 end)")).unwrap();
    t.send("store");
    let st = wait("left broken", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken"));
    assert_eq!(st.rip.as_deref(), Some(store.as_str()));
    app.lua_exec("assert(debug_isBroken()); debug_continueFromBreakpoint(co_run)").unwrap();
    assert_eq!(t.line(), "ok 501 200");
    app.lua_exec(&format!("debug_removeBreakpoint({store})")).unwrap();
    assert!(app.debug_breakpoints().unwrap().is_empty());
    assert_eq!(t.cmd_line("store"), "ok 502 200");
}

/// The control with `class` (and caption, when given) in a form snapshot.
fn find_control(n: &[hh_lua::ControlNode], class: &str, caption: Option<&str>) -> Option<hh_lua::Control> {
    n.iter().find_map(|c| {
        let cap = c.control.props.get("Caption").and_then(|p| if let hh_lua::Prop::Str(s) = p { Some(s.as_str()) } else { None });
        if c.control.class == class && (caption.is_none() || cap == caption) {
            Some(c.control.clone())
        } else {
            find_control(&c.children, class, caption)
        }
    })
}

#[test]
fn lua_form_button_toggles_an_entry_through_ui_commands() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    put(&app, vec![i32_entry(1, &t)]);
    app.lua_exec(
        "f = createForm()\nf.Caption = 'Tools'\nb = createButton(f)\nb.Caption = 'Toggle'\nb.OnClick = function() local r = getAddressList().getMemoryRecordByID(1); r.Active = not r.Active end\ne = createEdit(f)\ne.OnChange = function(s) print('typed ' .. s.Text) end",
    )
    .unwrap();
    let p = app.ui_poll(0).unwrap();
    let roots = p.snapshot.expect("first poll is a snapshot").roots;
    let form = find_control(&roots, "TCEForm", Some("Tools")).expect("form");
    let button = find_control(&roots, "TButton", Some("Toggle")).expect("button");
    assert_eq!(button.parent, Some(form.id));
    assert!(button.events.contains("OnClick"));
    app.ui_event(button.id, "OnClick", vec![]).unwrap();
    assert!(entry(&app, 1).frozen, "{}", log_text(&app));
    app.ui_event(button.id, "OnClick", vec![]).unwrap();
    assert!(!entry(&app, 1).frozen);
    let edit = find_control(&roots, "TEdit", None).unwrap();
    app.ui_input(edit.id, "Text", hh_lua::Prop::Str("hello".into())).unwrap();
    assert!(log_text(&app).contains("out: typed hello"));
    // Script changes arrive incrementally; user input is not echoed back.
    let since = app.ui_poll(0).unwrap().next;
    app.lua_exec("b.Caption = 'Toggle hp'").unwrap();
    let p = app.ui_poll(since).unwrap();
    assert!(p.snapshot.is_none());
    let ch = serde_json::to_value(&p.changes).unwrap();
    assert_eq!(ch[0]["op"], "update");
    assert_eq!((ch[0]["id"].as_u64(), ch[0]["prop"].as_str(), ch[0]["value"].as_str()), (Some(button.id as u64), Some("Caption"), Some("Toggle hp")));
    assert_eq!(app.lua_poll(0).unwrap().ui_seq, p.next);
    // Closing (OnClose) hides by default; a table switch destroys the form.
    app.ui_event(form.id, "OnClose", vec![]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.json");
    app.table_export(path.to_str().unwrap()).unwrap();
    let since = app.ui_poll(0).unwrap().next;
    app.table_open(path.to_str().unwrap(), false).unwrap();
    let ch = serde_json::to_value(app.ui_poll(since).unwrap().changes).unwrap();
    assert!(ch.as_array().unwrap().iter().any(|c| c["op"] == "destroy" && c["id"] == form.id), "{ch}");
    assert!(app.ui_poll(0).unwrap().snapshot.unwrap().roots.is_empty());
}

#[test]
fn generated_trainer_runs_and_its_hotkey_toggles_an_entry() {
    let t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    put(&app, vec![i32_entry(1, &t)]);
    let req: heaphook::trainer::TrainerReq = de(json!({"title": "HP trainer", "about": "Ctrl F7 toggles", "beep": true, "show_keys": true,
        "entries": [{"id": 1, "label": "Freeze health", "keys": [17, 118]}]}));
    let script = app.trainer_script(&req).unwrap();
    assert!(script.starts_with(heaphook::trainer::BEGIN) && script.trim_end().ends_with(heaphook::trainer::END));
    let st = app.table_get().unwrap();
    app.table_put(Table { lua_script: script, ..st.table }, st.version).unwrap();
    app.table_run_script().unwrap();
    let roots = app.ui_poll(0).unwrap().snapshot.unwrap().roots;
    assert!(find_control(&roots, "TCEForm", Some("HP trainer")).is_some(), "{}", log_text(&app));
    let cb = find_control(&roots, "TCheckBox", None).expect("toggle");
    assert!(app.lua_poll(0).unwrap().hotkeys.contains(&vec![17, 118]));
    assert_eq!(app.hotkey_press(&[17, 118]).unwrap(), 1);
    assert!(entry(&app, 1).frozen, "{}", log_text(&app));
    // The check box follows (timer) and unchecking it deactivates the entry.
    wait("box checked", || {
        let r = app.ui_poll(0).unwrap().snapshot.unwrap().roots;
        (find_control(&r, "TCheckBox", None)?.props.get("Checked") == Some(&hh_lua::Prop::Bool(true))).then_some(())
    });
    app.ui_input(cb.id, "Checked", hh_lua::Prop::Bool(false)).unwrap();
    assert!(!entry(&app, 1).frozen, "{}", log_text(&app));
    // Running it again replaces the form instead of stacking a second one.
    app.table_run_script().unwrap();
    let roots = app.ui_poll(0).unwrap().snapshot.unwrap().roots;
    assert_eq!(roots.iter().filter(|r| r.control.class == "TCEForm").count(), 1);
    assert_eq!(app.lua_poll(0).unwrap().hotkeys.iter().filter(|k| **k == vec![17, 118]).count(), 1);
}

#[test]
fn group_activation_from_lua_runs_children_once_and_records_carry_fields() {
    let mut t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let child = Entry { id: 2, description: "kid".into(), script: Some("[ENABLE]\n{$lua}\nprint('kid on')\n{$asm}\n[DISABLE]\n{$lua}\nprint('kid off')\n{$asm}\n".into()), ..Entry::default() };
    let mut value = i32_entry(3, &t);
    value.dropdown = Some(Dropdown { options: vec![DropdownItem { value: "1".into(), text: "one".into() }], read_only: true, ..Dropdown::default() });
    value.hotkeys = vec![Hotkey { action: "Set Value".into(), keys: vec![17, 119], value: Some("77".into()), description: None, id: None }];
    let group = Entry {
        id: 1,
        description: "grp".into(),
        options: vec!["moActivateChildrenAsWell".into(), "moDeactivateChildrenAsWell".into()],
        children: vec![child, value],
        ..Entry::default()
    };
    put(&app, vec![group]);
    app.lua_exec("local g = getAddressList().getMemoryRecordByID(1)\nprint('hdr', g.IsGroupHeader, g.Type ~= 11, g.Options)\ng.Active = true").unwrap();
    let log = log_text(&app);
    assert_eq!(log.matches("out: kid on").count(), 1, "{log}");
    assert!(log.contains("out: hdr true true [moActivateChildrenAsWell,moDeactivateChildrenAsWell]"), "{log}");
    assert!(entry(&app, 2).frozen && entry(&app, 3).frozen);
    app.table_set_active(&[1], false).unwrap();
    assert_eq!(log_text(&app).matches("out: kid off").count(), 1);
    app.table_set_active(&[1], true).unwrap();
    assert_eq!(log_text(&app).matches("out: kid on").count(), 2, "{}", log_text(&app));
    // Dropdown and hotkeys reach Lua; a hotkey made in Lua fires through the app's path with
    // its OnHotkey callback.
    app.lua_exec(
        "local r = getAddressList().getMemoryRecordByID(3)\nprint('dd', r.DropDownList[0], r.DropDownReadOnly, r.HotkeyCount)\nlocal h = r.createHotkey({VK_CONTROL, VK_F10}, mrhSetValue, '1234')\nh.OnHotkey = function() print('hotkey cb') end",
    )
    .unwrap();
    assert!(log_text(&app).contains("out: dd 1:one true 1"), "{}", log_text(&app));
    let e = entry(&app, 3);
    assert_eq!((e.hotkeys.len(), e.hotkeys[1].action.as_str(), e.hotkeys[1].keys.clone()), (2, "Set Value", vec![17, 121]));
    assert!(app.lua_poll(0).unwrap().hotkeys.contains(&vec![17, 121]));
    assert_eq!(app.hotkey_press(&[17, 121]).unwrap(), 1);
    assert_eq!(t.cmd("get")["i32"], 1234);
    assert!(log_text(&app).contains("out: hotkey cb"));
}

#[test]
fn load_table_from_lua_clears_the_previous_tables_callbacks() {
    let t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    put(&app, vec![i32_entry(1, &t)]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("next.json");
    app.table_export(path.to_str().unwrap()).unwrap();
    app.lua_exec("getAddressList().getMemoryRecordByID(1).OnActivate = function() print('old callback') end\nhk = createHotkey(function() end, VK_CONTROL, VK_F11)\nf = createForm()").unwrap();
    assert!(app.lua_poll(0).unwrap().hotkeys.contains(&vec![17, 122]));
    app.lua_exec(&format!("loadTable({:?})\nsaveTable({:?})", path.to_str().unwrap(), dir.path().join("saved.CT").to_str().unwrap())).unwrap();
    assert!(dir.path().join("saved.CT").exists());
    app.table_set_active(&[1], true).unwrap();
    assert!(!log_text(&app).contains("out: old callback"), "{}", log_text(&app));
    assert!(!app.lua_poll(0).unwrap().hotkeys.contains(&vec![17, 122]));
    assert!(app.ui_poll(0).unwrap().snapshot.unwrap().roots.is_empty());
    // Merge appends with new ids and keeps the current entries.
    app.lua_exec(&format!("loadTable({:?}, true)", path.to_str().unwrap())).unwrap();
    let st = app.table_get().unwrap().table;
    assert_eq!(st.entries.iter().map(|e| e.id).collect::<Vec<_>>(), [1, 2]);
    assert!(entry(&app, 1).frozen && !entry(&app, 2).frozen);
}

#[test]
fn lua_host_extras_keys_selection_memscan_memory_limit_create_process() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    put(&app, vec![i32_entry(1, &t), i32_entry(2, &t)]);
    app.key_state(&[17, 65]).unwrap();
    app.lua_exec("print('keys', isKeyPressed(VK_CONTROL), isKeyPressed(VK_A), isKeyPressed(VK_B))").unwrap();
    app.table_select(vec![1]).unwrap();
    app.lua_exec("print('sel', getAddressList().SelCount, getAddressList().SelectedRecord.ID)").unwrap();
    app.lua_exec("local al = getAddressList(); al.SelectedRecords = { al.getMemoryRecordByID(2) }").unwrap();
    let sel = app.lua_poll(0).unwrap().selection;
    assert_eq!((sel.seq, sel.ids), (1, vec![2]));
    scan_exact_i32(&app, "123456");
    app.lua_exec("print('memscan', getCurrentMemscan() ~= nil)").unwrap();
    // Structures: the table's list is the one Lua sees.
    app.lua_exec("local s = createStructure('fromLua'); s.addToGlobalStructureList(); print('structs', getStructureCount())").unwrap();
    assert_eq!(app.struct_get().unwrap().iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["fromLua"]);
    let log = log_text(&app);
    for want in ["out: keys true true false", "out: sel 1 1", "out: memscan true", "out: structs 1"] {
        assert!(log.contains(want), "{want}\n{log}");
    }
    // The memory limit setting reaches the engine.
    let mut s = app.settings_get().unwrap();
    s.lua_memory_mb = 16;
    app.settings_set(s.clone()).unwrap();
    let e = app.lua_exec("local t = {} for i = 1, 1e7 do t[i] = string.rep('x', 64) .. i end").unwrap_err();
    assert!(e.contains("not enough memory"), "{e}");
    s.lua_memory_mb = 1024;
    app.settings_set(s).unwrap();
    app.lua_exec("local t = {} for i = 1, 2e5 do t[i] = string.rep('x', 64) .. i end").unwrap();
    // createProcess goes through the app's create-process path and opens the new process.
    app.lua_exec("pid = createProcess('/bin/sleep', '30')\nprint('pid', pid)").unwrap();
    let opened = app.lua_poll(0).unwrap().process.unwrap();
    assert!(log_text(&app).contains(&format!("out: pid {}", opened.info.pid)), "{}", log_text(&app));
    assert_ne!(opened.info.pid, t.child.id());
    app.close_process().unwrap();
    let _ = Command::new("kill").arg("-9").arg(opened.info.pid.to_string()).status();
}

#[test]
fn exec_and_fork_show_in_the_debugger_log_and_breakpoints() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    app.debug_attach().unwrap();
    let id = app.debug_add_breakpoint(&bp(json!({"addr": t.addr("store"), "action": "record"}))).unwrap();
    assert_eq!(t.cmd_line("fork"), "fork 42");
    wait("fork notice", || app.debug_log(0).unwrap().lines.iter().any(|l| l.text.contains("forked")).then_some(()));
    t.send("exec");
    let info: Value = serde_json::from_str(&t.line()).unwrap();
    assert!(info["store"].is_string());
    let b = wait("disabled by exec", || Some(bp_row(&app, id)).filter(|b| !b.enabled));
    assert!(b.note.as_deref().is_some_and(|n| n.contains("exec")), "{:?}", b.note);
    assert!(app.debug_log(0).unwrap().lines.iter().any(|l| l.text.contains("ran exec")));
    app.debug_detach().unwrap();
}

// ---------- 1.0 RC: saved scans, custom types, binary, pause, remote, labels, big tables ----------

fn first_scan(app: &App, v: Value) -> u64 {
    app.scan_first(&de(v)).unwrap().count
}

fn has_addr(app: &App, addr: &str) -> bool {
    let a = parse_addr(addr).unwrap();
    app.scan_results(0, 100_000, None).unwrap().iter().any(|r| r.addr == a)
}

#[test]
fn saved_scan_and_compare_to_saved() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    assert!(scan_exact_i32(&app, "123456") >= 1);
    app.scan_save("before").unwrap();
    assert!(app.scan_save("first").is_err(), "reserved name");
    t.cmd("inc");
    // Unchanged against the previous scan would drop i32; against the saved scan it increased.
    let n = app.scan_next(&de(json!({"scan_type": "increased", "not": false, "compare_to": "before"}))).unwrap().count;
    assert!(n >= 1 && has_addr(&app, &t.addr("i32")));
    let saved = app.scan_saved().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].name, "before");
    assert!(saved[0].kept >= 1);
    let a = parse_addr(&t.addr("i32")).unwrap();
    let row = app.scan_results(0, 1000, Some("before")).unwrap().into_iter().find(|r| r.addr == a).unwrap();
    assert_eq!((row.value.as_deref(), row.saved.clone()), (Some("123457"), Some(Some("123456".into()))));
    // "first" compares with the first scan.
    t.cmd("inc");
    let n = app.scan_next(&de(json!({"scan_type": "increased_by", "value": "2", "not": false, "compare_to": "first"}))).unwrap().count;
    assert!(n >= 1 && has_addr(&app, &t.addr("i32")));
    assert!(app.scan_next(&de(json!({"scan_type": "changed", "not": false, "compare_to": "nope"}))).is_err());
    app.scan_delete_saved("before").unwrap();
    assert!(app.scan_saved().unwrap().is_empty());
    assert!(app.scan_results(0, 10, Some("before")).is_err());
}

#[test]
fn big_endian_custom_type_scan_read_write_freeze_and_round_trip() {
    let mut t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let be4 = hh_scan::CustomType::preset("4 Byte Big Endian").unwrap();
    let ct = serde_json::to_value(be4).unwrap();
    // i32 = 123456 = bytes 40 E2 01 00 -> big endian 0x40E20100.
    let n = first_scan(&app, json!({"vtype": "4bytes", "scan_type": "exact", "value": "1088553216", "not": false,
        "opts": {"writable": "yes", "alignment": 4, "custom": ct}}));
    assert!(n >= 1 && has_addr(&app, &t.addr("i32")));
    let i32a = t.addr("i32");
    let read = |app: &App| app.read_values(de(json!([{"addr": i32a, "vtype": "4bytes", "custom": ct}]))).unwrap()[0].clone();
    assert_eq!(read(&app).as_deref(), Some("1088553216"));
    app.write_value(&i32a, de(json!("4bytes")), "16909060", &Fmt::default(), Some(&be4)).unwrap();
    assert_eq!(t.cmd("get")["i32"], 0x0403_0201);
    // A frozen custom entry holds its big-endian value.
    let e = Entry { id: 1, description: "be".into(), addr: i32a.clone(), custom: Some(be4), custom_name: Some("4 Byte Big Endian".into()), ..Entry::default() };
    put(&app, vec![e]);
    app.table_set_active(&[1], true).unwrap();
    assert!(entry(&app, 1).frozen, "{}", log_text(&app));
    app.write_value(&i32a, de(json!("4bytes")), "5", &Fmt::default(), None).unwrap();
    wait("freezer restores the custom value", || (t.cmd("get")["i32"] == 0x0403_0201).then_some(()));
    app.table_set_value(&[1], "1").unwrap();
    wait("freezes to the new value", || (t.cmd("get")["i32"] == 0x0100_0000).then_some(()));
    app.table_set_active(&[1], false).unwrap();
    // A non-preset custom type and an unknown CE custom type survive JSON and .CT.
    let fixed = hh_scan::CustomType { scale: 0.01, signed: true, ..hh_scan::CustomType::int(2, true) };
    let base = app.table_get().unwrap().version;
    let mut tb = app.table_get().unwrap().table;
    tb.entries.push(Entry { id: 2, description: "fixed".into(), addr: i32a.clone(), custom: Some(fixed), custom_name: Some("fixed".into()), ..Entry::default() });
    tb.custom_types.push(heaphook::table::NamedCustom { name: "fixed".into(), ct: fixed });
    app.table_put(tb, base).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for name in ["c.json", "c.CT"] {
        let p = dir.path().join(name);
        app.table_export(p.to_str().unwrap()).unwrap();
        let back = app.table_open(p.to_str().unwrap(), false).unwrap().table;
        assert_eq!((back.entries[0].custom, back.entries[0].custom_name.as_deref()), (Some(be4), Some("4 Byte Big Endian")), "{name}");
        assert_eq!((back.entries[1].custom, back.entries[1].custom_name.as_deref()), (Some(fixed), Some("fixed")), "{name}");
    }
    let ct_text = r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable CheatEngineTableVersion="45"><CheatEntries><CheatEntry><ID>7</ID><Description>"odd"</Description>
<VariableType>Custom</VariableType><CustomType>Mystery Type</CustomType><Address>1000</Address></CheatEntry></CheatEntries>
<CustomTypes><CustomType><Name>Mystery Type</Name><Script>alloc(x,4)</Script></CustomType></CustomTypes></CheatTable>"#;
    let p = dir.path().join("odd.CT");
    std::fs::write(&p, ct_text).unwrap();
    let back = app.table_open(p.to_str().unwrap(), false).unwrap().table;
    assert_eq!((back.entries[0].custom, back.entries[0].custom_name.as_deref()), (None, Some("Mystery Type")));
    assert!(app.table_set_value(&[7], "1").unwrap_err().contains("not supported"));
    let out = dir.path().join("odd2.CT");
    app.table_export(out.to_str().unwrap()).unwrap();
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("<VariableType>Custom</VariableType>") && text.contains("<CustomType>Mystery Type</CustomType>"), "{text}");
    // CE runs a table's <CustomTypes> scripts on load and HeapHook never shows them: not carried.
    assert!(!text.contains("<Script>"), "table-level <CustomTypes> carried a hidden script: {text}");
}

#[test]
fn binary_scan_with_a_bit_offset() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    // aob = DE AD BE EF ...: byte 0xAD = 1010_1101; bits 2..5 (from bit 2, 4 bits) = 1011 = 11.
    let n = first_scan(&app, json!({"vtype": "binary", "scan_type": "exact", "value": "11", "not": false,
        "opts": {"writable": "yes", "binary_decimal": true, "bit_len": 4, "bit_start": 2}}));
    assert!(n >= 1);
    let a = parse_addr(&t.addr("aob")).unwrap() + 1;
    let row = app.scan_results(0, 100_000, None).unwrap().into_iter().find(|r| r.addr == a).expect("0xAD matched");
    assert_eq!(row.bit, Some(2));
}

#[test]
fn pause_and_resume_a_running_scan() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let a2 = app.clone();
    let h = std::thread::spawn(move || {
        a2.scan_first(&de(json!({"vtype": "byte", "scan_type": "unknown", "opts": {"alignment": 1, "threads": 1, "priority": "idle", "writable": "any"}})))
    });
    let mut paused = false;
    for _ in 0..2000 {
        if app.scan_progress().unwrap().running {
            app.scan_pause(true).unwrap();
            paused = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if paused {
        std::thread::sleep(Duration::from_millis(100));
        let p1 = app.scan_progress().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let p2 = app.scan_progress().unwrap();
        assert!(p2.paused && p2.running && p1.done == p2.done, "{p1:?} {p2:?}");
        app.scan_pause(false).unwrap();
    } else {
        eprintln!("scan finished before it could be paused");
    }
    assert!(h.join().unwrap().unwrap().count > 0);
    let p = app.scan_progress().unwrap();
    assert!(!p.running && !p.paused && !p.spill_dir.is_empty());
}

#[test]
fn remote_session_end_to_end_and_connection_drop() {
    let mut t = Target::spawn();
    let token = "test-token-0123456789";
    let server = hh_net::Server::bind("127.0.0.1:0", hh_net::ServerConfig::new(token), std::sync::Arc::new(hh_net::LocalBackend)).unwrap().spawn().unwrap();
    let addr = server.addr().to_string();
    let app = App::default();
    app.start_driver();
    let cfg = tempfile::tempdir().unwrap();
    app.set_config_dir(cfg.path());
    assert!(app.remote_connect(&addr, "wrong-token-0123456789", false).is_err());
    app.remote_connect(&addr, token, true).unwrap();
    let file = cfg.path().join("remote.json");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    let saved = app.remote_saved().unwrap();
    assert!(saved.has_token && saved.addr == addr);
    // Reconnecting with an empty token uses the remembered one; not ticking "remember" drops it.
    app.remote_connect(&addr, "", false).unwrap();
    assert!(!app.remote_saved().unwrap().has_token);
    assert!(!std::fs::read_to_string(&file).unwrap().contains(token));

    let pid = t.child.id();
    assert!(app.remote_processes().unwrap().iter().any(|p| p.pid == pid));
    let info = app.remote_open(pid).unwrap();
    assert_eq!((info.name.as_str(), info.remote.as_deref()), ("hh-target", Some(addr.as_str())));
    assert!(scan_exact_i32(&app, "123456") >= 1 && has_addr(&app, &t.addr("i32")));
    app.write_value(&t.addr("i32"), de(json!("4bytes")), "777", &Fmt::default(), None).unwrap();
    assert_eq!(t.cmd("get")["i32"], 777);
    assert_eq!(app.read_memory(&t.addr("i32"), 4).unwrap(), "09030000");
    let offs: Vec<String> = t.info["chain_offsets"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string()).collect();
    let expr = offs.iter().fold(t.addr("chain"), |x, o| format!("[{x}]+{o}"));
    assert_eq!(parse_addr(&app.resolve_address(&expr).unwrap()).unwrap(), parse_addr(&t.addr("chain_value")).unwrap());
    let e = app.debug_attach().unwrap_err();
    assert!(e.contains("local processes only"), "{e}");
    assert!(app.module_header("hh-target").unwrap_err().contains("local processes only"));
    let p = serde_json::to_value(app.lua_poll(0).unwrap()).unwrap();
    assert_eq!((p["process"]["remote"].as_str(), p["process"]["alive"].as_bool()), (Some(addr.as_str()), Some(true)));

    assert!(app.remote_status().unwrap().unwrap().connected, "liveness by ping");
    drop(server);
    let lost = wait("lost connection seen", || app.lua_poll(0).unwrap().process.and_then(|p| p.lost));
    assert!(lost.contains("connection to server lost"), "{lost}");
    let e = app.read_memory(&t.addr("i32"), 4).unwrap_err();
    assert!(e.contains("connection to server lost"), "{e}");
    app.close_process().unwrap();
    assert!(app.lua_poll(0).unwrap().process.is_none());
    assert!(!app.remote_status().unwrap().unwrap().connected);
    app.remote_disconnect().unwrap();
    assert!(app.remote_status().unwrap().is_none());
    // The local target was never touched by the drop.
    assert_eq!(t.cmd("get")["i32"], 777);
}

#[test]
fn user_labels_resolve_and_survive_a_table_round_trip() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let i32a = parse_addr(&t.addr("i32")).unwrap();
    let base = app.table_get().unwrap().version;
    let sym = |n: &str, a: &str| heaphook::table::UserSymbol { name: n.into(), address: a.into() };
    let tb = Table {
        symbols: vec![sym("hpvar", &t.addr("i32")), sym("after_hp", "hpvar+4")],
        disasm_comments: vec![heaphook::table::DisasmComment { address: "hpvar".into(), comment: "player health".into() }],
        ..Table::default()
    };
    app.table_put(tb, base).unwrap();
    assert_eq!(parse_addr(&app.resolve_address("hpvar").unwrap()).unwrap(), i32a);
    assert_eq!(parse_addr(&app.resolve_address("[after_hp-4]").unwrap()).unwrap(), 123456);
    assert_eq!(app.resolve_many(&["after_hp".into(), "nosuchlabel".into()]).unwrap(), [Some(format!("{:#x}", i32a + 4)), None]);
    let dir = tempfile::tempdir().unwrap();
    for name in ["l.json", "l.CT"] {
        let p = dir.path().join(name);
        app.table_export(p.to_str().unwrap()).unwrap();
        app.table_put(Table::default(), app.table_get().unwrap().version).unwrap();
        assert!(app.resolve_address("hpvar").is_err(), "dropped with the table");
        let back = app.table_open(p.to_str().unwrap(), false).unwrap().table;
        assert_eq!(back.symbols.len(), 2, "{name}");
        assert_eq!(back.disasm_comments[0].comment, "player health", "{name}");
        assert_eq!(parse_addr(&app.resolve_address("after_hp").unwrap()).unwrap(), i32a + 4, "{name}");
    }
    // A reopened process gets the labels again.
    app.open_process(t.child.id()).unwrap();
    assert_eq!(parse_addr(&app.resolve_address("hpvar").unwrap()).unwrap(), i32a);
}

#[test]
fn table_with_50k_entries_loads_and_pages() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let i32a = parse_addr(&t.addr("i32")).unwrap();
    let entries: Vec<Entry> = (0..50_000)
        .map(|i| Entry { id: i + 1, description: format!("entry {i}"), addr: format!("{:#x}", i32a + (i as u64 % 64) * 4), ..Entry::default() })
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.json");
    std::fs::write(&p, serde_json::to_string(&Table { entries, ..Table::default() }).unwrap()).unwrap();
    let t0 = Instant::now();
    let st = app.table_open(p.to_str().unwrap(), false).unwrap();
    let open = t0.elapsed();
    assert_eq!(st.table.entries.len(), 50_000);
    let t0 = Instant::now();
    let got = app.table_get().unwrap();
    let get = t0.elapsed();
    let t0 = Instant::now();
    // The UI resolves and reads one visible page at a time.
    for page in 0..20 {
        let rows = &got.table.entries[page * 40..page * 40 + 40];
        let addrs = app.resolve_many(&rows.iter().map(|e| e.addr.clone()).collect::<Vec<_>>()).unwrap();
        let vals = app.read_values(de(json!(addrs.iter().map(|a| json!({"addr": a, "vtype": "4bytes"})).collect::<Vec<_>>()))).unwrap();
        assert!(vals.iter().all(Option::is_some));
    }
    let paging = t0.elapsed() / 20;
    eprintln!("50k table: open {open:?}, table_get {get:?}, one 40-row page (resolve + read) {paging:?}");
    assert!(open < Duration::from_secs(10) && paging < Duration::from_millis(500));
}

#[test]
fn created_and_debugged_process_is_never_reaped_from_under_the_debugger() {
    let ok = Command::new(env!("CARGO"))
        .args(["build", "-q", "-p", "heaphook", "--example", "ticker"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let ticker = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join("examples/ticker");
    let dir = tempfile::tempdir().unwrap();
    let info_file = dir.path().join("info.json");
    let app = App::default();
    app.start_driver();
    let info = app.process_create(&de(json!({"program": ticker.to_str().unwrap(), "args": info_file.to_str().unwrap()}))).unwrap();
    let tinfo: Value = wait("ticker info", || std::fs::read_to_string(&info_file).ok().and_then(|t| serde_json::from_str(&t).ok()));
    app.debug_attach().unwrap();
    let id = app.debug_add_breakpoint(&bp(json!({"addr": tinfo["tick"], "action": "record"}))).unwrap();
    // Reap as hard as the driver could: every call used to steal the tracee's stops.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(3) {
        app.reap_children();
        std::thread::sleep(Duration::from_millis(2));
    }
    let hits = bp_row(&app, id).hits;
    assert!(hits >= 3, "breakpoint hits {hits}");
    let hist = app.debug_history().unwrap().join("\n");
    assert!(!hist.contains("taken by another waitpid") && hist.contains("recoveries=0"), "{hist}");
    app.debug_detach().unwrap();
    let ticks = || app.read_values(de(json!([{"addr": tinfo["ticks"], "vtype": "4bytes"}]))).unwrap()[0].clone().unwrap().parse::<i64>().unwrap();
    let a = ticks();
    std::thread::sleep(Duration::from_millis(1200));
    assert!(ticks() > a, "the target runs after detach");
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", info.pid)).unwrap();
    assert!(!stat.contains(") Z") && !stat.contains(") t"), "{stat}");
    app.close_process().unwrap();
    let _ = Command::new("kill").arg(info.pid.to_string()).status();
    // Once exited and untraced, the child is reaped.
    wait("reaped", || {
        app.reap_children();
        std::fs::read_to_string(format!("/proc/{}/stat", info.pid)).is_err().then_some(())
    });
}

// ---------------------------------------------------------------- the consent gate (rc.1 audit)

/// An entry whose `{$lua}` appends `on` / `off` to `marker` when it enables / disables.
fn marker_script(marker: &std::path::Path) -> String {
    let m = format!("{:?}", marker.to_str().unwrap());
    format!(
        "[ENABLE]\n{{$lua}}\nlocal f = io.open({m}, 'a') f:write('on\\n') f:close()\nreturn ''\n{{$asm}}\n[DISABLE]\n{{$lua}}\nlocal f = io.open({m}, 'a') f:write('off\\n') f:close()\nreturn ''\n{{$asm}}\n"
    )
}

/// A writable 4-byte slot of either test target.
fn slot(t: &Target) -> String {
    t.info.get("i32").or_else(|| t.info.get("value")).and_then(Value::as_str).unwrap().to_string()
}

fn marks(marker: &std::path::Path) -> String {
    std::fs::read_to_string(marker).unwrap_or_default()
}

/// The hostile table of the audit: a `{$lua}` entry with a plain F1 hotkey, a group that
/// cascades into a second one, a table script and a value entry with a Ctrl hotkey.
fn hostile_table(marker: &std::path::Path, t: &Target) -> Table {
    let hk = |action: &str, keys: Vec<u32>| Hotkey { action: action.into(), keys, value: None, description: None, id: None };
    let lua = Entry { id: 1, description: "Infinite HP".into(), script: Some(marker_script(marker)), hotkeys: vec![hk("Toggle Activation", vec![112]), hk("Activate", vec![17, 113])], ..Entry::default() };
    let kid = Entry { id: 3, description: "kid".into(), script: Some(marker_script(marker)), ..Entry::default() };
    let group = Entry { id: 2, description: "grp".into(), options: vec!["moActivateChildrenAsWell".into()], children: vec![kid], ..Entry::default() };
    let mut value = Entry { id: 4, description: "hp".into(), addr: slot(t), ..Entry::default() };
    value.hotkeys = vec![hk("Toggle Activation", vec![17, 114])];
    let script = format!("local f = io.open({:?}, 'a') f:write('script\\n') f:close()", marker.to_str().unwrap());
    Table { entries: vec![lua, group, value], lua_script: script, ..Table::default() }
}

fn needs_consent(r: Result<impl std::fmt::Debug, String>) -> String {
    let e = r.expect_err("must be refused");
    assert!(e.contains(heaphook::cheat::NEEDS_CONSENT), "{e}");
    e
}

/// Every route by which a record of a loaded table can become active, or its script run,
/// while the user has not agreed: none runs Lua. Then, agreed, each one works.
#[test]
fn untrusted_table_lua_never_runs_on_any_route() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let file = dir.path().join("evil.json");
    let evil = hostile_table(&marker, &t);
    heaphook::table::save(&file, &evil).unwrap();
    let evil_path = file.to_str().unwrap().to_string();

    // Before the switch, under the user's own table: a timer, a form button, a record callback
    // and a Lua breakpoint that would all activate entry 1 of whatever table is loaded next.
    let store = t.addr("store");
    app.lua_exec(&format!(
        "tm = createTimer(nil) tm.Interval = 30 tm.OnTimer = function() local r = getAddressList().getMemoryRecordByID(1) if r then r.Active = true end end\n\
         fm = createForm() bt = createButton(fm) bt.OnClick = function() getAddressList().getMemoryRecordByID(1).Active = true end\n\
         debug_setBreakpoint({store}, function() local r = getAddressList().getMemoryRecordByID(1) if r then r.Active = true end return 1 end)"
    ))
    .unwrap();
    let old_button = find_control(&app.ui_poll(0).unwrap().snapshot.unwrap().roots, "TButton", None).unwrap();
    assert_eq!(app.debug_breakpoints().unwrap().len(), 1);

    let st = app.table_open(&evil_path, false).unwrap();
    assert_eq!(st.trust, heaphook::cheat::Trust::Ask);
    let off = || assert!(!entry(&app, 1).frozen && !entry(&app, 3).frozen, "{}", log_text(&app));
    let none = |route: &str| assert_eq!(marks(&marker), "", "Lua ran via {route}\n{}", log_text(&app));

    // 1. click
    needs_consent(app.table_set_active(&[1], true));
    none("table_set_active");
    // 2. the hotkey of the audit's reproduction (plain F1, Toggle) and an Activate hotkey
    needs_consent(app.hotkey_press(&[112]));
    needs_consent(app.table_hotkey(1, 1));
    none("hotkeys");
    // 3. a group whose option activates a {$lua} child, from the UI and from Lua
    needs_consent(app.table_set_active(&[2], true));
    app.lua_exec("getAddressList().getMemoryRecordByID(2).Active = true").unwrap();
    none("group cascade");
    // 4. the engine itself: memrec.Active, a record hotkey, a createHotkey function, a form
    app.lua_exec("getAddressList().getMemoryRecordByID(1).Active = true").unwrap();
    app.lua_exec("getAddressList().getMemoryRecordByID(1).Hotkey[0].doHotkey()").unwrap();
    app.lua_exec("h2 = createHotkey(function() getAddressList().getMemoryRecordByID(1).Active = true end, VK_CONTROL, VK_F8)").unwrap();
    assert_eq!(app.hotkey_press(&[17, 119]).unwrap(), 1);
    app.lua_exec("f2 = createForm() b2 = createButton(f2) b2.OnClick = function() getAddressList().getMemoryRecordByID(1).Active = true end").unwrap();
    let b2 = find_control(&app.ui_poll(0).unwrap().snapshot.unwrap().roots, "TButton", None).unwrap();
    app.ui_event(b2.id, "OnClick", vec![]).unwrap();
    none("the engine's own activation");
    off();
    assert!(log_text(&app).contains("needs your consent"), "the engine's refusal is reported: {}", log_text(&app));
    // 5. what the previous table's scripts left: timer, form, callbacks, breakpoint are gone
    std::thread::sleep(Duration::from_millis(200));
    assert!(app.ui_event(old_button.id, "OnClick", vec![]).is_err() || marks(&marker).is_empty());
    assert!(app.debug_breakpoints().unwrap().is_empty(), "the Lua breakpoint survived the switch");
    assert!(t.cmd_line("store").starts_with("ok"));
    none("leftovers of the previous table");
    // 6. a put carrying an active entry, and undo / redo restoring one
    let cur = app.table_get().unwrap();
    let mut tb = cur.table.clone();
    tb.entries[0].frozen = true;
    app.table_put(tb, cur.version).unwrap();
    off();
    let cur = app.table_get().unwrap();
    let mut tb = cur.table.clone();
    tb.entries[0].script = None;
    tb.entries[0].addr = slot(&t);
    app.table_put(tb, cur.version).unwrap();
    app.table_set_active(&[1], true).unwrap(); // a value entry now: no Lua, allowed
    app.table_history(false).unwrap(); // entry 1 is the {$lua} script again, still marked active
    assert!(entry(&app, 1).frozen && entry(&app, 1).script.is_some());
    // Switched off without running its [DISABLE] {$lua}: only what an enable recorded is undone.
    app.table_set_active(&[1], false).unwrap();
    assert!(!entry(&app, 1).frozen);
    app.table_history(true).unwrap();
    app.table_history(false).unwrap();
    none("put / undo / redo");
    // 7. the table script, the Auto Assembler window, a trainer the table brought along
    needs_consent(app.table_run_script());
    needs_consent(app.aa_execute(&marker_script(&marker), true, None));
    none("table script / aa_execute");
    // 8. not system-wide while untrusted; keys are not watched for it
    assert_eq!(app.global_combos(), vec![vec![17, 119]], "only the console's own createHotkey; none of the table's");
    assert!(app.lua_poll(0).unwrap().hotkeys.contains(&vec![112]), "in-app it is still bound (and refused when pressed)");
    app.key_state(&[65]).unwrap();
    app.lua_exec("assert(not isKeyPressed(VK_A))").unwrap();
    // 9. declining keeps all of it inert
    app.table_trust(false).unwrap();
    assert!(app.table_set_active(&[1], true).unwrap_err().contains("chose not to"));
    assert!(app.hotkey_press(&[112]).unwrap_err().contains("chose not to"));
    none("after declining");

    // Agreed: every route runs the entry's Lua.
    app.table_trust(true).unwrap();
    assert_eq!(app.table_get().unwrap().trust, heaphook::cheat::Trust::Agreed);
    let count = |s: &str| marks(&marker).lines().filter(|l| *l == s).count();
    app.table_set_active(&[1], true).unwrap();
    assert_eq!(count("on"), 1, "click");
    std::thread::sleep(Duration::from_millis(200));
    app.hotkey_press(&[112]).unwrap();
    assert_eq!(count("off"), 1, "hotkey");
    app.table_hotkey(1, 1).unwrap();
    assert_eq!(count("on"), 2, "Activate hotkey");
    app.lua_exec("getAddressList().getMemoryRecordByID(1).Active = false").unwrap();
    app.lua_exec("getAddressList().getMemoryRecordByID(1).Hotkey[0].doHotkey()").unwrap();
    assert_eq!((count("on"), count("off")), (3, 2), "memrec.Active and doHotkey");
    app.table_set_active(&[2], false).unwrap(); // Lua switched the header on earlier (its child stayed off)
    app.table_set_active(&[2], true).unwrap();
    assert!(entry(&app, 3).frozen, "group cascade");
    app.table_run_script().unwrap();
    assert_eq!(count("script"), 1);
    assert_eq!(app.global_combos(), vec![vec![17, 113], vec![17, 114], vec![17, 119]], "plain F1 never system-wide");
    app.key_state(&[65]).unwrap();
    app.lua_exec("assert(isKeyPressed(VK_A))").unwrap();

    // A table loaded by a trusted script is a new, untrusted table (trust is not inherited).
    app.lua_exec(&format!("loadTable({evil_path:?})")).unwrap();
    assert_eq!(app.table_get().unwrap().trust, heaphook::cheat::Trust::Ask);
    let before = marks(&marker);
    needs_consent(app.table_set_active(&[1], true));
    assert_eq!(marks(&marker), before);
    // Merged by a script: the new entries need consent, the table's own keep working.
    let own = dir.path().join("own.json");
    heaphook::table::save(&own, &Table { entries: vec![Entry { id: 1, description: "mine".into(), script: Some(marker_script(&marker)), ..Entry::default() }], ..Table::default() }).unwrap();
    app.table_open(own.to_str().unwrap(), false).unwrap();
    app.table_trust(true).unwrap();
    app.lua_exec(&format!("loadTable({evil_path:?}, true)")).unwrap();
    assert_eq!(app.table_get().unwrap().trust, heaphook::cheat::Trust::Ask);
    let before = marks(&marker).lines().count();
    app.table_set_active(&[1], true).unwrap();
    assert_eq!(marks(&marker).lines().count(), before + 1, "the current entry still runs");
    needs_consent(app.table_set_active(&[2], true));
    assert_eq!(marks(&marker).lines().count(), before + 1);

    // Lua that reaches a trusted table from another one asks for itself, on every route:
    // paste, a put carrying it, undo, the UI's merge, a dropped file, the Auto Assemble window.
    let mine = dir.path().join("mine.json");
    let my_script = format!("// mine\n{}", marker_script(&marker));
    heaphook::table::save(&mine, &Table { entries: vec![Entry { id: 1, description: "mine".into(), script: Some(my_script), ..Entry::default() }], ..Table::default() }).unwrap();
    app.table_open(mine.to_str().unwrap(), false).unwrap();
    app.table_trust(true).unwrap();
    let lines = || marks(&marker).lines().count();
    let n = lines();
    let entry_consent = |r: Result<(), String>| {
        let e = r.expect_err("must be refused");
        assert!(e.starts_with(heaphook::cheat::NEEDS_ENTRY_CONSENT), "{e}");
    };
    // 1. paste (from the untrusted table's file: what the UI's clipboard carries)
    let pasted = app.table_paste(vec![evil.entries[0].clone()], Some(1), None).unwrap();
    let pid_ = pasted.ids[0];
    assert_eq!(app.table_get().unwrap().untrusted, vec![pid_]);
    entry_consent(app.table_set_active(&[pid_], true));
    app.lua_exec(&format!("getAddressList().getMemoryRecordByID({pid_}).Active = true")).unwrap();
    entry_consent(app.hotkey_press(&[17, 113]).map(|_| ()));
    assert!(!app.global_combos().contains(&vec![17, 113]), "a pasted entry's hotkey is not system-wide before its consent");
    assert_eq!(lines(), n, "paste\n{}", log_text(&app));
    // ... while the table's own entry still runs.
    app.table_set_active(&[1], true).unwrap();
    app.table_set_active(&[1], false).unwrap();
    assert_eq!(lines(), n + 2);
    // 2. a put that brings the same script under a new id, 3. undo bringing a deleted one back
    let cur = app.table_get().unwrap();
    let mut tb = cur.table.clone();
    tb.entries.push(Entry { id: 99, description: "typed?".into(), script: evil.entries[0].script.clone(), ..Entry::default() });
    app.table_put(tb, cur.version).unwrap();
    entry_consent(app.table_set_active(&[99], true));
    let cur = app.table_get().unwrap();
    let mut tb = cur.table.clone();
    tb.entries.retain(|e| e.id != pid_);
    app.table_put(tb, cur.version).unwrap();
    app.table_history(false).unwrap();
    entry_consent(app.table_set_active(&[pid_], true));
    assert_eq!(lines(), n + 2, "put / undo");
    // 4. the UI's merge: its entries ask; the table script it brings asks for the table
    let st = app.table_merge(&evil_path).unwrap();
    assert_eq!(st.trust, heaphook::cheat::Trust::Ask);
    let merged = st.table.entries.iter().find(|e| e.description == "Infinite HP" && !st.untrusted.is_empty() && st.untrusted.contains(&e.id) && e.id != pid_).map(|e| e.id).unwrap();
    entry_consent(app.table_set_active(&[merged], true));
    app.table_set_active(&[1], true).unwrap();
    app.table_set_active(&[1], false).unwrap();
    assert_eq!(lines(), n + 4, "merge keeps the own entry running");
    // 5. a file dropped on the window: opened like any table
    let st = app.table_open_data("evil.json", &std::fs::read_to_string(&file).unwrap(), false).unwrap();
    assert_eq!(st.trust, heaphook::cheat::Trust::Ask);
    needs_consent(app.table_set_active(&[1], true));
    assert_eq!(lines(), n + 4, "drop");
    // 6. the Auto Assemble window: a script file asks, a typed one does not
    let aa = dir.path().join("evil.cea");
    std::fs::write(&aa, marker_script(&marker)).unwrap();
    let text = app.aa_load_file(aa.to_str().unwrap()).unwrap();
    needs_consent(app.aa_execute(&text, true, None));
    assert_eq!(lines(), n + 4, "aa window");
    app.aa_trust(&text).unwrap();
    let st = app.aa_execute(&text, true, None).unwrap();
    app.aa_execute(&text, false, Some(&st)).unwrap();
    assert_eq!(lines(), n + 6, "agreed aa script");
    let typed = format!("// typed here\n{}", marker_script(&marker));
    let st = app.aa_execute(&typed, true, None).unwrap();
    app.aa_execute(&typed, false, Some(&st)).unwrap();
    assert_eq!(lines(), n + 8, "typed aa script");
    // 7. consent for the entry: it runs, and its hotkey goes system-wide
    app.table_open(mine.to_str().unwrap(), false).unwrap();
    app.table_trust(true).unwrap();
    let pasted = app.table_paste(vec![evil.entries[0].clone()], None, None).unwrap();
    entry_consent(app.table_set_active(&pasted.ids, true));
    app.table_trust_entries(&pasted.ids).unwrap();
    assert!(app.table_get().unwrap().untrusted.is_empty());
    app.table_set_active(&pasted.ids, true).unwrap();
    assert_eq!(lines(), n + 9, "agreed entry");
    assert!(app.global_combos().contains(&vec![17, 113]));
}

/// Settings "never": nothing of a loaded table's Lua runs, consent cannot be given, and turning
/// it on withdraws consent already given.
#[test]
fn never_setting_holds_on_every_route() {
    let t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let file = dir.path().join("evil.json");
    heaphook::table::save(&file, &hostile_table(&marker, &t)).unwrap();
    let mut st = app.settings_get().unwrap();
    st.table_script = "never".into();
    app.settings_set(st.clone()).unwrap();
    app.table_open(file.to_str().unwrap(), false).unwrap();
    let never = |r: Result<(), String>| assert!(r.unwrap_err().contains("never"));
    never(app.table_set_active(&[1], true));
    never(app.hotkey_press(&[112]).map(|_| ()));
    never(app.table_run_script());
    assert!(app.table_trust(true).unwrap_err().contains("never"));
    app.lua_exec("getAddressList().getMemoryRecordByID(1).Active = true\ngetAddressList().getMemoryRecordByID(2).Active = true").unwrap();
    assert_eq!(marks(&marker), "", "{}", log_text(&app));
    // Agreed first, then "never": withdrawn.
    st.table_script = "ask".into();
    app.settings_set(st.clone()).unwrap();
    app.table_trust(true).unwrap();
    st.table_script = "never".into();
    app.settings_set(st).unwrap();
    never(app.table_set_active(&[1], true));
    assert_eq!(app.table_get().unwrap().trust, heaphook::cheat::Trust::Declined);
    assert!(app.global_combos().is_empty());
    assert_eq!(marks(&marker), "");

    // Lua from another table in the user's own table: no consent can be given for it.
    let st = app.settings_get().unwrap();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    app.settings_set(st.clone()).unwrap();
    let evil = hostile_table(&marker, &t);
    let pasted = app.table_paste(vec![evil.entries[0].clone()], None, None).unwrap();
    never(app.table_set_active(&pasted.ids, true));
    assert!(app.table_trust_entries(&pasted.ids).unwrap_err().contains("never"));
    let aa = dir.path().join("evil.cea");
    std::fs::write(&aa, marker_script(&marker)).unwrap();
    let text = app.aa_load_file(aa.to_str().unwrap()).unwrap();
    assert!(app.aa_execute(&text, true, None).unwrap_err().contains("never"));
    assert!(app.aa_trust(&text).unwrap_err().contains("never"));
    // Agreed first, then "never": the entry's consent is withdrawn too.
    let mut ask = st.clone();
    ask.table_script = "ask".into();
    app.settings_set(ask).unwrap();
    app.table_trust_entries(&pasted.ids).unwrap();
    app.settings_set(st).unwrap();
    never(app.table_set_active(&pasted.ids, true));
    assert_eq!(app.table_get().unwrap().untrusted, pasted.ids);
    assert_eq!(marks(&marker), "");
}

/// Settings "Allow Lua scripts to access files and run programs" off: hh-lua's own `io`/`os`
/// and HeapHook's file / program hosts are refused; on by default (Cheat Engine behaviour).
#[test]
fn lua_file_and_program_access_can_be_turned_off() {
    assert_eq!(App::default().app_info().unwrap()["lua_allow_os"], true);
    let cfg = tempfile::tempdir().unwrap();
    std::fs::write(cfg.path().join("settings.json"), r#"{"lua_allow_os": false}"#).unwrap();
    let app = App::default();
    app.set_config_dir(cfg.path());
    assert_eq!(app.app_info().unwrap()["lua_allow_os"], false);
    assert!(app.lua_exec("return io.open('/etc/hostname')").is_err());
    for call in ["loadTable('/nonexistent.json')", "saveTable('/tmp/never-written.json')", "createProcess('/bin/true')"] {
        let r = app.lua_exec(&format!("return {call}"));
        let all = format!("{r:?}\n{}", log_text(&app));
        assert!(all.contains("do not allow") || all.contains("is disabled"), "{call}: {all}");
    }
    assert!(!std::path::Path::new("/tmp/never-written.json").exists());
    assert!(app.ui_image("/usr/share/pixmaps/x.png").unwrap_err().contains("do not allow"));
}

// ---------------------------------------------------------------- 1.0 additions

/// Memory viewer search, block allocation, pausing the process, trace files, the table as
/// text and "unsaved changes".
#[test]
fn search_alloc_pause_trace_files_and_dirty() {
    let mut t = Target::spawn();
    let app = App::default();
    let pid = t.child.id();
    app.open_process(pid).unwrap();
    use heaphook::search::{DisasmSearchReq, SearchReq};
    let text: String = "HeapHook test string".bytes().map(|b| format!("{b:02x} ")).collect();
    let str_a = parse_addr(&t.addr("str")).unwrap();
    let find = |pattern: &str, start: u64, backward: bool| {
        app.mem_search(&SearchReq { start: hex(start), pattern: pattern.into(), backward, limit: Some(1000), ..SearchReq::default() }).unwrap()
    };
    assert!(find(&text, 0, false).contains(&hex(str_a)));
    assert_eq!(find(&text, str_a, false)[0], hex(str_a), "forward includes the start");
    assert_eq!(find(&text, str_a + 1, true)[0], hex(str_a), "backward: the nearest below");
    assert!(!find(&text, str_a, true).contains(&hex(str_a)), "backward excludes the start");
    assert!(find("48 65 61 70 ?? 6f 6f 6b", 0, false).contains(&hex(str_a)), "wildcards");
    assert!(app.mem_search(&SearchReq { start: "0".into(), pattern: "?? ??".into(), ..SearchReq::default() }).is_err());
    // Disassembly search over the target's own module.
    let m = app.modules().unwrap().into_iter().find(|m| m.name.starts_with("hh-target")).unwrap();
    let base = parse_addr(&m.base).unwrap();
    let rets = app.disasm_search(&DisasmSearchReq { start: m.base.clone(), end: hex(base + m.size.min(16 << 20)), text: "RET".into(), limit: Some(5) }).unwrap();
    assert_eq!(rets.len(), 5);
    assert!(rets.iter().all(|r| r.text.to_lowercase().contains("ret")));
    assert!(app.disasm_search(&DisasmSearchReq { start: "0".into(), end: hex(1 << 40), text: "ret".into(), limit: None }).is_err());

    // Allocate, use and free a block.
    let a = app.mem_alloc(0x1000, hh_core::Prot { r: true, w: true, x: false }).unwrap();
    app.write_bytes(&a, "deadbeef").unwrap();
    assert_eq!(app.read_memory(&a, 4).unwrap(), "deadbeef");
    app.mem_free(&a, 0x1000).unwrap();
    assert_eq!(app.read_memory(&a, 4).unwrap(), "????????");

    // Pause: every thread stops, the target answers nothing until resumed.
    let state = || std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap().split(") ").nth(1).unwrap().chars().next().unwrap();
    app.process_pause(true).unwrap();
    assert_eq!(state(), 'T');
    assert!(app.lua_poll(0).unwrap().process.unwrap().paused);
    t.send("get");
    assert!(t.lines.recv_timeout(Duration::from_millis(300)).is_err(), "a paused target must not answer");
    // Values can still be read and written while it is paused.
    app.write_value(&t.addr("i32"), de(json!("4bytes")), "31337", &Fmt::default(), None).unwrap();
    app.process_pause(false).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&t.line()).unwrap()["i32"], 31337);
    assert!(!app.lua_poll(0).unwrap().process.unwrap().paused);
    // Closing a paused process lets it run again.
    app.process_pause(true).unwrap();
    app.close_process().unwrap();
    assert_ne!(state(), 'T');

    // Trace files round trip; anything else is refused.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("t.hhtrace");
    let trace = json!({"version": 1, "addr": "0x1000", "rows": [{"addr": "0x1000", "text": "nop", "context": {"rax": "0x1"}}]});
    app.trace_save(p.to_str().unwrap(), &trace).unwrap();
    assert_eq!(app.trace_load(p.to_str().unwrap()).unwrap(), trace);
    std::fs::write(&p, "{\"rows\": []}").unwrap();
    assert!(app.trace_load(p.to_str().unwrap()).unwrap_err().contains("not a HeapHook trace"));

    // The table as text, and unsaved changes (activation does not count).
    app.open_process(pid).unwrap();
    assert!(!app.table_dirty().unwrap(), "an empty new table has nothing to save");
    let group = Entry { id: 2, description: "Player".into(), children: vec![i32_entry(1, &t)], ..Entry::default() };
    put(&app, vec![group]);
    assert!(app.table_dirty().unwrap());
    let tp = dir.path().join("t.json");
    app.table_export(tp.to_str().unwrap()).unwrap();
    assert!(!app.table_dirty().unwrap());
    app.table_set_active(&[1], true).unwrap();
    assert!(!app.table_dirty().unwrap(), "activation is not an unsaved change");
    let txt = dir.path().join("t.txt");
    app.table_export_text(txt.to_str().unwrap()).unwrap();
    let listing = std::fs::read_to_string(&txt).unwrap();
    assert!(listing.contains("Player\t\tgroup") && listing.contains(&format!("  hp\t{}\t4 bytes\t31337", t.addr("i32"))), "{listing}");
    app.table_open(tp.to_str().unwrap(), false).unwrap();
    assert!(!app.table_dirty().unwrap(), "just opened");
}

/// FPU / XMM registers can be edited; a trace stops where its stop condition holds.
#[test]
fn fpu_xmm_registers_and_trace_stop_condition() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    app.debug_attach().unwrap();
    let (store, outer) = (t.addr("store"), t.addr("outer"));
    let broken = |app: &App| wait("a break", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken"));
    let id = app.debug_add_breakpoint(&bp(json!({"addr": store}))).unwrap();
    t.send("store");
    let tid = broken(&app).tid.unwrap();
    app.debug_set_register(tid, "xmm3", "00112233445566778899aabbccddeeff").unwrap();
    app.debug_set_register(tid, "st0", "-2.5").unwrap();
    app.debug_set_register(tid, "MXCSR", "0x1fa0").unwrap();
    let c = app.debug_context(tid).unwrap();
    assert_eq!(c["fpu"]["xmm"][3], "00112233445566778899aabbccddeeff");
    assert_eq!(c["fpu"]["st"][0]["value"], "-2.5");
    assert!(app.debug_set_register(tid, "xmm3", "1234").is_err());
    assert!(app.debug_set_register(tid, "st0", "abc").is_err());
    assert!(app.debug_set_register(tid, "fcw", "0x10000").is_err());
    app.debug_remove_breakpoint(id).unwrap();
    app.debug_continue(false).unwrap();
    assert!(t.line().starts_with("ok"));
    // Trace from outer, stopping when it reaches store.
    let id = app.debug_add_breakpoint(&bp(json!({"addr": outer, "action": "trace", "steps": 50, "stop_when": format!("rip=={store}")}))).unwrap();
    assert_eq!(app.debug_breakpoints().unwrap()[0].stop_when.as_deref(), Some(format!("rip=={store}").as_str()));
    t.send("outer");
    let st = broken(&app);
    assert_eq!((st.rip.as_deref(), st.reason.as_deref()), (Some(store.as_str()), Some(format!("trace stop, breakpoint {id}").as_str())));
    assert!(app.debug_add_breakpoint(&bp(json!({"addr": outer, "action": "trace", "stop_when": "rax ==="}))).is_err());
    app.debug_remove_breakpoint(id).unwrap();
    app.debug_continue(false).unwrap();
    assert!(t.line().starts_with("ok"));
}

/// Form changes coalesce per property; `since` 0 always gets the whole tree.
#[test]
fn form_changes_coalesce_and_snapshot() {
    let app = App::default();
    app.lua_exec("f = createForm() l = createLabel(f)").unwrap();
    let first = app.ui_poll(0).unwrap();
    assert!(first.snapshot.is_some() && first.changes.is_empty());
    app.lua_exec("for i = 1, 5000 do l.Caption = 'n' .. i end").unwrap();
    let r = app.ui_poll(first.next).unwrap();
    assert!(r.snapshot.is_none());
    let caps: Vec<_> = r.changes.iter().filter(|c| serde_json::to_value(c).unwrap().to_string().contains("Caption")).collect();
    assert_eq!(caps.len(), 1, "5000 caption updates arrive as one");
    assert!(serde_json::to_value(caps[0]).unwrap().to_string().contains("n5000"));
    assert!(app.ui_poll(r.next + 100).unwrap().snapshot.is_some(), "a UI ahead of the backend (restarted) gets the tree");
}
