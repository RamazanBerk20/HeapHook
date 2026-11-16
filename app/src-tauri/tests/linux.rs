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
    assert!(app.aa_check(script, None, None).unwrap().is_none());
    let bad = app.aa_check("[ENABLE]\nfoo bar\n[DISABLE]\n", None, None).unwrap().expect("syntax error");
    assert_eq!(bad.line, 2);
    // A plain script runs without a session (no capabilities needed).
    let st = app.aa_execute(script, true, None, None).unwrap();
    let mem = app.resolve_address("hhmem").unwrap();
    assert_eq!(app.read_memory(&mem, 4).unwrap(), "11223344");
    assert_eq!(app.disassemble(&app.resolve_address("hhmem+4").unwrap(), 2).unwrap()[0].text, "mov eax,1");
    // The state crosses IPC as JSON and comes back for disable.
    let st: hh_asm::AaState = de(serde_json::to_value(&st).unwrap());
    app.aa_execute(script, false, Some(&st), None).unwrap();
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
    app.debug_step(tid, "into", false).unwrap();
    let st = wait("the step", || Some(app.debug_status().unwrap()).filter(|s| s.state == "broken" && s.rip.as_deref() == Some(hex(store_a + 3).as_str())));
    assert_eq!(st.reason.as_deref(), Some("step"));
    assert_eq!(app.read_values(de(json!([{"addr": value, "vtype": "8bytes"}]))).unwrap(), [Some("4660".into())]);
    // Step out of store lands back in the caller.
    app.debug_step(tid, "out", false).unwrap();
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
    app.debug_run_to(&hex(outer_a + 6), None, 1).unwrap();
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

/// Makes the table hold `entries`: ones it has keep their id (a put edits them), new ones are
/// created through `table_new` first (their ids must be the next the backend issues).
fn put(app: &App, entries: Vec<Entry>) {
    let mut have = Vec::new();
    preorder(&app.table_get().unwrap().table.entries, &mut have);
    for e in entries.iter().filter(|e| !have.contains(&e.id)) {
        let got = app.table_new(vec![e.clone()], None, None).unwrap().ids;
        assert_eq!(got, [e.id], "the test's new entry ids must be the next ones issued");
    }
    let st = app.table_get().unwrap();
    app.table_put(Table { entries, ..st.table }, st.version).unwrap();
}

fn preorder(l: &[Entry], out: &mut Vec<i64>) {
    for e in l {
        out.push(e.id);
        preorder(&e.children, out);
    }
}

/// Builds `t` in an empty table the way the UI does: the entries through `table_new` (the
/// backend issues ids 1.. in pre-order, which the test's ids must match), the rest by a put.
fn fill(app: &App, t: Table) {
    let mut want = Vec::new();
    preorder(&t.entries, &mut want);
    if !t.entries.is_empty() {
        app.table_new(t.entries.clone(), None, None).unwrap();
    }
    let st = app.table_get().unwrap();
    let mut got = Vec::new();
    preorder(&st.table.entries, &mut got);
    assert_eq!(got, want, "the test's entry ids must be 1.. in pre-order");
    app.table_put(Table { entries: st.table.entries, ..t }, st.version).unwrap();
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
    let s = app.aa_session().unwrap();
    assert!(app.aa_check(&script, Some(s), None).unwrap().is_none(), "{:?}", app.aa_check(&script, Some(s), None));
    let bad = "[ENABLE]\n{$lua}\nerror('lua says no')\n{$asm}\n[DISABLE]\n";
    // The live check never runs Lua (it would run untrusted code on every keystroke).
    assert!(app.aa_check(bad, Some(s), None).unwrap().is_none(), "aa_check ran the {{$lua}} block");
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
    fill(&app, t.clone());
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
    // Nothing is written before the plan's blocks are approved.
    let plan = app.mem_load_plan(file.to_str().unwrap(), None).unwrap();
    assert_eq!((plan.blocks.len(), plan.blocks[0].mapped, plan.blocks[0].writable), (1, true, true));
    let none = app.mem_load_approved(file.to_str().unwrap(), None, &[]).unwrap();
    assert_eq!(none.blocks, 0);
    assert_eq!(t.cmd("get")["i32"], 999);
    let r = app.mem_load_approved(file.to_str().unwrap(), None, &plan.blocks).unwrap();
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
    let s = app.aa_session().unwrap();
    assert!(app.aa_check(&lua_writes(&t.addr("i32"), 777), Some(s), None).unwrap().is_none());
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
    assert!(app.table_new(vec![deep.clone()], None, None).unwrap_err().contains("64 levels"));
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
    let ok = app.table_new(vec![Entry { description: "ok".into(), script: Some(format!("[ENABLE]\n{a}:\ndd #5\n[DISABLE]\n{a}:\ndd #123456\n")), ..Entry::default() }], None, None).unwrap().ids[0];
    app.table_set_active(&[ok], true).unwrap();
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
    app.debug_run_to(&hex(store_a + 3), Some(tid), 1).unwrap();
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
    // loadTable(f) replaces the table: Lua is reset, the rest of that script is refused.
    let e = app.lua_exec(&format!("loadTable({:?})\nsaveTable({:?})", path.to_str().unwrap(), dir.path().join("saved.CT").to_str().unwrap())).unwrap_err();
    assert!(e.contains("stopped"), "{e}");
    assert!(!dir.path().join("saved.CT").exists());
    assert!(log_text(&app).contains("Lua was reset"), "{}", log_text(&app));
    app.lua_exec(&format!("saveTable({:?})", dir.path().join("saved.CT").to_str().unwrap())).unwrap();
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
    app.table_new(vec![Entry { description: "fixed".into(), addr: i32a.clone(), custom: Some(fixed), custom_name: Some("fixed".into()), ..Entry::default() }], None, None).unwrap();
    let base = app.table_get().unwrap().version;
    let mut tb = app.table_get().unwrap().table;
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
    // A remote target's header comes from its memory, never from a same-named local file.
    let hdr = app.module_header("hh-target").unwrap();
    assert!(hdr.format == "elf" && hdr.source == "memory", "{hdr:?}");
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

/// A writable 4-byte slot of either test target.
fn slot(t: &Target) -> String {
    t.info.get("i32").or_else(|| t.info.get("value")).and_then(Value::as_str).unwrap().to_string()
}

fn marks(marker: &std::path::Path) -> String {
    std::fs::read_to_string(marker).unwrap_or_default()
}

fn needs_consent(r: Result<impl std::fmt::Debug, String>) -> String {
    let e = r.expect_err("must be refused");
    assert!(e.contains(heaphook::cheat::NEEDS_CONSENT), "{e}");
    e
}

// ---------- the consent matrix: entry routes x payloads x execution routes ----------
//
// Trust is decided by origin, never by content: an entry that arrived from outside gets no
// capabilities (no Lua, no file reads, no callbacks a trusted table registered) on any
// route until the user consents, and none at all under Settings "never".

/// How untrusted content arrives.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Route {
    OpenCt,
    OpenJson,
    MergeUi,
    Paste,
    Dropped,
    LoadTable,
    LoadTableMerge,
    UndoRedoRestore,
    PutFromUi,
    AaFileLf,
    AaFileCrlf,
    AaAssign,
    RemoteTemplate,
    // Inserted by a foreign route, then undo past the insert and redo it.
    PasteRedo,
    MergeRedo,
    LoadTableMergeRedo,
    AaAssignRedo,
    RemoteTemplateRedo,
}

impl Route {
    /// (the route that brings the entry, whether it is then undone past and redone).
    fn base(self) -> (Route, bool) {
        match self {
            Route::PasteRedo => (Route::Paste, true),
            Route::MergeRedo => (Route::MergeUi, true),
            Route::LoadTableMergeRedo => (Route::LoadTableMerge, true),
            Route::AaAssignRedo => (Route::AaAssign, true),
            Route::RemoteTemplateRedo => (Route::RemoteTemplate, true),
            r => (r, false),
        }
    }
}

const ROUTES: [Route; 18] = [
    Route::OpenCt,
    Route::OpenJson,
    Route::MergeUi,
    Route::Paste,
    Route::Dropped,
    Route::LoadTable,
    Route::LoadTableMerge,
    Route::UndoRedoRestore,
    Route::PutFromUi,
    Route::AaFileLf,
    Route::AaFileCrlf,
    Route::AaAssign,
    Route::RemoteTemplate,
    Route::PasteRedo,
    Route::MergeRedo,
    Route::LoadTableMergeRedo,
    Route::AaAssignRedo,
    Route::RemoteTemplateRedo,
];

/// What the content tries to do (each kind leaves its own trace when it runs).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Lua,
    LuaCall,
    File,
    Command,
    Prologue,
    Symbol,
    TableScript,
    Callback,
}

/// How the content is run.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Exec {
    Click,
    HotkeyPress,
    TableHotkey,
    Cascade,
    LuaActive,
    LuaAutoAssemble,
    Check,
    UndoRedo,
    TableScript,
    AaWindow,
}

const ENTRY_EXECS: [Exec; 8] = [Exec::Click, Exec::HotkeyPress, Exec::TableHotkey, Exec::Cascade, Exec::LuaActive, Exec::LuaAutoAssemble, Exec::Check, Exec::UndoRedo];

struct Payload {
    name: String,
    kind: Kind,
    /// The entry's (or the Auto Assemble window's) script.
    script: String,
    /// The table's Lua script (only `Kind::TableScript`).
    table_script: String,
}

/// Spellings of directive `name` hh-asm's parser takes for it: `{...}` and `/*...*/`
/// comments are stripped first, the text before `(` is trimmed, must be ASCII alphanumerics
/// and is compared lowercased (`aa.rs`: `strip_comments`, `directive`). Each is checked
/// against hh-asm itself before use (`spelling_is_directive`), so a spelling the parser
/// does not take fails the test instead of passing it vacuously.
fn spellings(name: &str) -> Vec<String> {
    let (a, b) = name.split_at(name.len() / 2);
    let alt: String = name.chars().enumerate().map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c }).collect();
    vec![
        name.into(),
        name.to_ascii_uppercase(),
        alt,
        format!("{a}{{}}{b}"),
        format!("{a}{{ x }}{b}"),
        format!("{a}/**/{b}"),
        format!("{a}/* x */{b}"),
        format!("  {name} "),
        format!("\t{}{{}}{b} ", a.to_ascii_uppercase()),
    ]
}

/// `{$lua}` opens a block when it is the whole trimmed line, any case (`extract_lua`).
fn lua_spellings() -> Vec<String> {
    vec!["{$lua}".into(), "{$LUA}".into(), "  {$Lua}  ".into(), "\t{$lUa}".into()]
}

fn spelling_is_directive(pid: u32, script: &str) {
    let p = hh_core::open(pid).unwrap();
    let e = hh_asm::aa_check(&*p, &hh_asm::SymbolTable::default(), script, &mut hh_asm::AaHooks::default()).expect("hh-asm accepted it without hooks");
    assert!(e.message.contains(hh_asm::NOT_AVAILABLE), "hh-asm does not take this as the directive: {script:?}: {e:?}");
}

fn payloads(pid: u32, marker: &std::path::Path, secret: &std::path::Path, slot: &str) -> Vec<Payload> {
    let m = format!("{:?}", marker.to_str().unwrap());
    let mark = |what: &str| format!("local f = io.open({m}, 'a') f:write('{what}\\n') f:close()");
    let at = slot.trim_start_matches("0x");
    let file = secret.display();
    let plain = "[ENABLE]\n[DISABLE]\n".to_string();
    let p = |name: String, kind, script: String| Payload { name, kind, script, table_script: String::new() };
    let mut out = Vec::new();
    for sp in lua_spellings() {
        out.push(p(format!("lua block {sp:?}"), Kind::Lua, format!("[ENABLE]\n{sp}\n{}\nreturn ''\n{{$asm}}\n[DISABLE]\n", mark("lua"))));
    }
    for sp in spellings("luacall") {
        out.push(p(format!("luacall {sp:?}"), Kind::LuaCall, format!("[ENABLE]\n{sp}({})\n[DISABLE]\n", mark("luacall"))));
    }
    for sp in spellings("loadbinary") {
        out.push(p(format!("loadbinary {sp:?}"), Kind::File, format!("[ENABLE]\n{sp}({at},{file})\n[DISABLE]\n")));
    }
    out.push(p("loadbinary via define".into(), Kind::File, format!("[ENABLE]\ndefine(lb,loadbinary)\nlb({at},{file})\n[DISABLE]\n")));
    for x in &out {
        spelling_is_directive(pid, &x.script);
    }
    out.push(p("custom command of a trusted table".into(), Kind::Command, "[ENABLE]\nMYCMD(attacker args)\n[DISABLE]\n".into()));
    out.push(p("prologue of a trusted table".into(), Kind::Prologue, plain.clone()));
    out.push(p("symbol lookup of a trusted table".into(), Kind::Symbol, "[ENABLE]\nalloc(hhm,8)\nhhm:\ndq magicsym\n[DISABLE]\ndealloc(hhm)\n".into()));
    out.push(Payload { name: "table Lua script".into(), kind: Kind::TableScript, script: plain.clone(), table_script: mark("script") });
    out.push(p("record callback of a trusted table".into(), Kind::Callback, plain));
    out
}

/// What the trusted side (the user's own console, standing in for a trusted table) has
/// registered when the payload arrives; each callback leaves a trace when it is called.
fn trusted_registrations(kind: Kind, marker: &std::path::Path, slot: &str, id: Option<i64>) -> String {
    let m = format!("{:?}", marker.to_str().unwrap());
    let mark = format!("local function mark(s) local f = io.open({m}, 'a') f:write(s .. '\\n') f:close() end\n");
    mark + &match kind {
        Kind::Command => "registerAutoAssemblerCommand('MYCMD', function(p) mark('cmd:' .. p) return '' end)".to_string(),
        Kind::Prologue => "registerAutoAssemblerPrologue(function(s) mark('prologue') end)".to_string(),
        Kind::Symbol => format!("registerSymbolLookupCallback(function(n) if n:lower() == 'magicsym' then mark('sym') return {slot} end end, slFailure)"),
        Kind::Callback => format!("getAddressList().getMemoryRecordByID({}).OnActivate = function() mark('onactivate') end", id.unwrap()),
        _ => String::new(),
    }
}

fn is_aa_window(r: Route) -> bool {
    matches!(r.base().0, Route::AaFileLf | Route::AaFileCrlf)
}

/// The routes whose data brings a table script along.
fn brings_table_script(r: Route) -> bool {
    matches!(r.base().0, Route::OpenCt | Route::OpenJson | Route::Dropped | Route::LoadTable | Route::MergeUi | Route::LoadTableMerge)
}

/// Routes that apply to a (route, payload) cell. Empty: the cell does not exist (listed in
/// the report of `consent_matrix`).
fn execs(r: Route, k: Kind) -> Vec<Exec> {
    match (is_aa_window(r), k) {
        (true, Kind::TableScript | Kind::Callback) => vec![],
        (true, _) => vec![Exec::AaWindow, Exec::Check],
        (false, Kind::TableScript) if brings_table_script(r) => vec![Exec::TableScript],
        (false, Kind::TableScript) => vec![],
        // A record callback is not part of the script: assembling or checking its text
        // involves no callback.
        (false, Kind::Callback) => ENTRY_EXECS.iter().copied().filter(|e| !matches!(e, Exec::LuaAutoAssemble | Exec::Check)).collect(),
        (false, _) => ENTRY_EXECS.to_vec(),
    }
}

/// A server that reports every module of a process under a hostile name.
struct HostileBackend;
struct Renamed(std::sync::Arc<dyn hh_core::Process>);
const HOSTILE_MODULE: &str = "a\"\n{$lua}\nos.exit(1)\n--";
impl hh_core::Memory for Renamed {
    fn read(&self, a: u64, b: &mut [u8]) -> hh_core::Result<usize> {
        self.0.read(a, b)
    }
    fn write(&self, a: u64, d: &[u8]) -> hh_core::Result<()> {
        self.0.write(a, d)
    }
    fn pointer_size(&self) -> usize {
        self.0.pointer_size()
    }
}
impl hh_core::Process for Renamed {
    fn pid(&self) -> u32 {
        self.0.pid()
    }
    fn is_alive(&self) -> bool {
        self.0.is_alive()
    }
    fn regions(&self) -> hh_core::Result<Vec<hh_core::Region>> {
        self.0.regions()
    }
    fn modules(&self) -> hh_core::Result<Vec<hh_core::Module>> {
        Ok(self.0.modules()?.into_iter().map(|m| hh_core::Module { name: HOSTILE_MODULE.into(), ..m }).collect())
    }
    fn threads(&self) -> hh_core::Result<Vec<u32>> {
        self.0.threads()
    }
    fn alloc(&self, s: u64, p: hh_core::Prot, n: Option<u64>) -> hh_core::Result<u64> {
        self.0.alloc(s, p, n)
    }
    fn free(&self, a: u64, s: u64) -> hh_core::Result<()> {
        self.0.free(a, s)
    }
    fn protect(&self, a: u64, s: u64, p: hh_core::Prot) -> hh_core::Result<hh_core::Prot> {
        self.0.protect(a, s, p)
    }
}
impl hh_net::Backend for HostileBackend {
    fn list_processes(&self) -> hh_core::Result<Vec<hh_core::ProcessInfo>> {
        hh_core::list_processes()
    }
    fn open(&self, pid: u32) -> hh_core::Result<std::sync::Arc<dyn hh_core::Process>> {
        Ok(std::sync::Arc::new(Renamed(hh_core::open(pid)?)))
    }
}

/// One (route, payload) cell set up in a fresh app.
struct Cell {
    app: App,
    route: Route,
    payload_name: String,
    kind: Kind,
    script: String,
    id: Option<i64>,
    group: Option<i64>,
    session: Option<u64>,
    marker: PathBuf,
    slot: String,
    base: String,
    log_at: u64,
}

const SECRET: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
const TOKEN: &str = "matrix-token-0123456789";

fn find_desc(app: &App, d: &str) -> i64 {
    fn go(l: &[Entry], d: &str) -> Option<i64> {
        l.iter().find_map(|e| if e.description == d { Some(e.id) } else { go(&e.children, d) })
    }
    go(&app.table_get().unwrap().table.entries, d).unwrap_or_else(|| panic!("no entry {d:?}"))
}

fn take_entry(l: &mut Vec<Entry>, id: i64) -> Option<Entry> {
    if let Some(i) = l.iter().position(|e| e.id == id) {
        return Some(l.remove(i));
    }
    l.iter_mut().find_map(|e| take_entry(&mut e.children, id))
}


impl Cell {
    #[allow(clippy::too_many_arguments)]
    fn new(route: Route, p: &Payload, never: bool, pid: u32, slot: &str, dir: &std::path::Path, server: &str, n: usize) -> Cell {
        let app = App::default();
        let (base_route, redo) = route.base();
        if base_route == Route::RemoteTemplate {
            app.remote_connect(server, TOKEN, false).unwrap();
            app.remote_open(pid).unwrap();
        } else {
            app.open_process(pid).unwrap();
        }
        let base = app.read_memory(slot, 4).unwrap();
        let cdir = dir.join(format!("cell{n}"));
        std::fs::create_dir_all(&cdir).unwrap();
        let marker = cdir.join("marker");
        if never {
            let mut st = app.settings_get().unwrap();
            st.table_script = "never".into();
            app.settings_set(st).unwrap();
        }
        // The data the route brings: a table with the payload entry (and its table script).
        let entry = Entry { id: 1, description: "payload".into(), script: Some(p.script.clone()), ..Entry::default() };
        let table = Table { entries: vec![entry.clone()], lua_script: p.table_script.clone(), ..Table::default() };
        let json = cdir.join("evil.json");
        heaphook::table::save(&json, &table).unwrap();
        let mut cell = Cell { app, route, payload_name: p.name.clone(), kind: p.kind, script: p.script.clone(), id: None, group: None, session: None, marker, slot: slot.into(), base, log_at: 0 };
        let app = &cell.app;
        let paste = || app.table_paste(vec![entry.clone()], None, None).unwrap().ids[0];
        match base_route {
            Route::OpenCt => {
                let ct = cdir.join("evil.CT");
                heaphook::table::save(&ct, &table).unwrap();
                app.table_open(ct.to_str().unwrap(), false).unwrap();
            }
            Route::OpenJson => {
                app.table_open(json.to_str().unwrap(), false).unwrap();
            }
            Route::Dropped => {
                app.table_open_data("evil.json", &std::fs::read_to_string(&json).unwrap(), false).unwrap();
            }
            Route::LoadTable => app.lua_exec(&format!("loadTable({:?})", json.to_str().unwrap())).unwrap(),
            Route::MergeUi => {
                app.table_merge(json.to_str().unwrap()).unwrap();
            }
            Route::LoadTableMerge => app.lua_exec(&format!("loadTable({:?}, true)", json.to_str().unwrap())).unwrap(),
            Route::Paste => {
                paste();
            }
            Route::UndoRedoRestore => {
                let id = paste();
                let cur = app.table_get().unwrap();
                let mut t = cur.table.clone();
                take_entry(&mut t.entries, id);
                app.table_put(t, cur.version).unwrap();
                app.table_history(false).unwrap();
            }
            Route::PutFromUi => {
                let id = paste();
                // The frontend edits it (text and description) and moves it: still untrusted.
                let cur = app.table_get().unwrap();
                let mut t = cur.table.clone();
                let mut e = take_entry(&mut t.entries, id).unwrap();
                e.script = Some(format!("// edited by the user\n{}", p.script));
                t.entries.insert(0, e);
                app.table_put(t, cur.version).unwrap();
                cell.script = format!("// edited by the user\n{}", p.script);
            }
            Route::AaFileLf | Route::AaFileCrlf | Route::AaAssign => {
                let f = cdir.join("evil.cea");
                let text = if base_route == Route::AaFileCrlf { p.script.replace('\n', "\r\n") } else { p.script.clone() };
                std::fs::write(&f, &text).unwrap();
                let s = app.aa_session().unwrap();
                let loaded = app.aa_load_file(f.to_str().unwrap(), s).unwrap();
                // The window's textarea normalizes line endings: the backend must not care.
                cell.script = loaded.replace("\r\n", "\n");
                cell.session = Some(s);
                if base_route == Route::AaAssign {
                    app.aa_assign(s, &cell.script, "payload", None, None).unwrap();
                }
            }
            Route::RemoteTemplate => {
                let r = app.table_add_template(&cell_store(), "code", "payload", None, None).unwrap();
                let tpl = entry_script(app, r.ids[0]);
                assert!(!tpl.contains(HOSTILE_MODULE) && !tpl.to_ascii_lowercase().contains("{$lua}"), "the template embedded the server's module name:\n{tpl}");
                assert_eq!(app.table_get().unwrap().untrusted, r.ids, "a remote template is untrusted");
                // Its text edited into the payload: editing does not make it trusted.
                let cur = app.table_get().unwrap();
                let mut t = cur.table.clone();
                t.entries.iter_mut().find(|e| e.id == r.ids[0]).unwrap().script = Some(p.script.clone());
                app.table_put(t, cur.version).unwrap();
            }
            _ => unreachable!(),
        }
        if redo {
            // Undo past the insert (the entry is gone), then redo it all: the entry comes back
            // with the id and origin it had.
            let mut n = 0;
            let has = |app: &App| { let mut ids = Vec::new(); preorder(&app.table_get().unwrap().table.entries, &mut ids); ids.iter().any(|&i| crate::entry(app, i).description == "payload") };
            while has(app) {
                app.table_history(false).unwrap();
                n += 1;
                assert!(n < 5, "the insert does not undo");
            }
            for _ in 0..n {
                app.table_history(true).unwrap();
            }
        }
        if !is_aa_window(route) {
            // Into a group that activates its children (the user's own, made through the
            // backend like the UI does), with two hotkeys: frontend edits, which keep the
            // entry's origin.
            let id = find_desc(app, "payload");
            let gid = app.table_new(vec![Entry { description: "grp".into(), options: vec!["moActivateChildrenAsWell".into(), "moDeactivateChildrenAsWell".into()], ..Entry::default() }], None, None).unwrap().ids[0];
            let cur = app.table_get().unwrap();
            let mut t = cur.table.clone();
            let mut e = take_entry(&mut t.entries, id).unwrap();
            let hk = |keys: Vec<u32>| Hotkey { action: "Activate".into(), keys, value: None, description: None, id: None };
            e.hotkeys = vec![hk(vec![17, 118]), hk(vec![17, 119])];
            t.entries.iter_mut().find(|g| g.id == gid).unwrap().children = vec![e];
            app.table_put(t, cur.version).unwrap();
            cell.id = Some(id);
            cell.group = Some(gid);
        }
        let reg = trusted_registrations(p.kind, &cell.marker, slot, cell.id);
        cell.app.lua_exec(&reg).unwrap();
        cell.log_at = cell.app.lua_poll(0).unwrap().next;
        cell
    }

    fn happened(&self) -> Option<String> {
        let m = marks(&self.marker);
        let v = self.app.read_memory(&self.slot, 4).unwrap();
        (!m.is_empty() || v != self.base).then(|| format!("marker {m:?}, slot {v} (was {})", self.base))
    }

    fn reset(&mut self) {
        if let (Some(g), Some(id)) = (self.group, self.id) {
            let _ = self.app.table_set_active(&[id, g], false);
        }
        let _ = std::fs::remove_file(&self.marker);
        let b = u32::from_str_radix(&self.base, 16).unwrap().swap_bytes();
        self.app.write_value(&self.slot, de(json!("4bytes")), &b.to_string(), &Fmt::default(), None).unwrap();
        self.log_at = self.app.lua_poll(0).unwrap().next;
    }

    fn new_log(&self) -> String {
        self.app.lua_poll(self.log_at).unwrap().log.iter().map(|l| format!("{}: {}", l.kind, l.text)).collect::<Vec<_>>().join("\n")
    }

    /// Runs `e`; Ok(what it said) or Err(its error).
    fn run(&self, e: Exec, second: bool) -> Result<String, String> {
        let app = &self.app;
        let (id, g) = (self.id.unwrap_or(0), self.group.unwrap_or(0));
        match e {
            Exec::Click => app.table_set_active(&[id], true).map(|_| String::new()),
            Exec::HotkeyPress => app.hotkey_press(if second { &[17, 119] } else { &[17, 118] }).map(|n| n.to_string()),
            Exec::TableHotkey => app.table_hotkey(id, 0).map(|_| String::new()),
            Exec::Cascade => app.table_set_active(&[g], true).map(|_| String::new()),
            Exec::LuaActive => app.lua_exec(&format!("getAddressList().getMemoryRecordByID({id}).Active = true")).map(|_| self.new_log()),
            Exec::LuaAutoAssemble => app
                .lua_exec(&format!("local ok, err = autoAssemble(getAddressList().getMemoryRecordByID({id}).Script) if not ok then print(err) end"))
                .map(|_| self.new_log()),
            Exec::Check => match app.aa_check(&self.script, self.session, self.id).unwrap() {
                None => Ok(String::new()),
                Some(e) => Err(e.message),
            },
            Exec::UndoRedo => {
                let cur = app.table_get().unwrap();
                let mut t = cur.table.clone();
                take_entry(&mut t.entries, g).unwrap();
                app.table_put(t, cur.version).unwrap();
                app.table_history(false).unwrap();
                app.table_history(true).unwrap();
                app.table_history(false).unwrap();
                app.table_set_active(&[id], true).map(|_| String::new())
            }
            Exec::TableScript => app.table_run_script().map(|_| String::new()),
            Exec::AaWindow => {
                let st = app.aa_execute(&self.script, true, None, self.session)?;
                app.aa_execute(&self.script, false, Some(&st), self.session).map(|_| String::new())
            }
        }
    }

    fn grant(&self) -> Result<(), String> {
        let app = &self.app;
        match self.route.base().0 {
            Route::AaFileLf | Route::AaFileCrlf => app.aa_trust(self.session.unwrap()),
            Route::OpenCt | Route::OpenJson | Route::Dropped | Route::LoadTable => app.table_trust(true),
            _ if self.kind == Kind::TableScript => app.table_trust(true),
            _ => app.table_trust_entries(&[self.id.unwrap()]),
        }
    }

    fn what(&self, e: Exec) -> String {
        format!("{:?} x {} x {e:?}", self.route, self.payload_name)
    }
}

thread_local! {
    static STORE: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}
fn cell_store() -> String {
    STORE.with(|s| s.borrow().clone())
}

fn entry_script(app: &App, id: i64) -> String {
    entry(app, id).script.unwrap_or_default()
}

/// Whether `r` (the outcome of a refused cell) tells the user consent is needed (`never`:
/// that Settings refuse it).
fn reports_refusal(e: Exec, r: &Result<String, String>, never: bool) -> bool {
    let consent = |t: &str| if never { t.contains("never") || t.contains("needs your consent") } else { t.contains(heaphook::cheat::NEEDS_CONSENT) || t.contains("needs your consent") };
    match (e, r) {
        (Exec::LuaActive | Exec::LuaAutoAssemble, Ok(log)) => log.contains("needs your consent"),
        (Exec::Check, Err(m)) => m.contains(hh_asm::NOT_AVAILABLE) || m.contains("needs your consent"),
        (_, Err(m)) => consent(m),
        _ => false,
    }
}

/// Runs every cell of the matrix under Settings "ask" (refused, then consented and working)
/// or "never" (refused, and consent refused too). Returns (cells run, cells that do not
/// exist).
fn run_matrix(never: bool) -> (usize, Vec<String>) {
    let t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let pid = t.child.id();
    STORE.with(|s| *s.borrow_mut() = t.addr("store"));
    let slot = slot(&t);
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.bin");
    std::fs::write(&secret, SECRET).unwrap();
    let server = hh_net::Server::bind("127.0.0.1:0", hh_net::ServerConfig::new(TOKEN), std::sync::Arc::new(HostileBackend)).unwrap().spawn().unwrap();
    let addr = server.addr().to_string();
    let payloads = payloads(pid, &dir.path().join("unused"), &secret, &slot);
    let (mut cells, mut missing, mut n) = (0, Vec::new(), 0);
    for route in ROUTES {
        for p in &payloads {
            let ex = execs(route, p.kind);
            if ex.is_empty() {
                missing.push(format!("{route:?} x {}", p.name));
                continue;
            }
            n += 1;
            // The payload's trace goes to this cell's own marker.
            let cdir = dir.path().join(format!("cell{n}"));
            std::fs::create_dir_all(&cdir).unwrap();
            let p2 = Payload {
                name: p.name.clone(),
                kind: p.kind,
                script: p.script.replace(dir.path().join("unused").to_str().unwrap(), cdir.join("marker").to_str().unwrap()),
                table_script: p.table_script.replace(dir.path().join("unused").to_str().unwrap(), cdir.join("marker").to_str().unwrap()),
            };
            let mut c = Cell::new(route, &p2, never, pid, &slot, dir.path(), &addr, n);
            for &e in &ex {
                c.reset();
                let r = c.run(e, false);
                if let Some(h) = c.happened() {
                    panic!("{}: ran without consent: {h}\n{r:?}\n{}", c.what(e), c.new_log());
                }
                assert!(reports_refusal(e, &r, never), "{}: refused without saying why: {r:?}\n{}", c.what(e), c.new_log());
                cells += 1;
            }
            c.reset();
            if never {
                let g = c.grant().expect_err("consent under never");
                assert!(g.contains("never"), "{}: {g}", c.what(ex[0]));
                for &e in &ex {
                    let r = c.run(e, true);
                    assert!(c.happened().is_none(), "{}: ran after a refused grant: {r:?}", c.what(e));
                    assert!(reports_refusal(e, &r, true), "{}: {r:?}", c.what(e));
                    c.reset();
                }
                continue;
            }
            c.grant().unwrap_or_else(|g| panic!("{:?} x {}: grant: {g}", route, p.name));
            for &e in &ex {
                c.reset();
                let r = c.run(e, true);
                match e {
                    Exec::Check => assert!(r.is_ok(), "{}: consented check: {r:?}", c.what(e)),
                    _ => {
                        assert!(r.is_ok() && !reports_refusal(e, &r, false), "{}: consented but refused: {r:?}\n{}", c.what(e), c.new_log());
                        assert!(c.happened().is_some(), "{}: consented but nothing ran: {r:?}\n{}", c.what(e), c.new_log());
                    }
                }
            }
            c.reset();
        }
    }
    drop(server);
    (cells, missing)
}

/// The matrix under Settings "ask": every cell refuses and asks; consented, every cell runs.
#[test]
fn consent_matrix() {
    let (cells, missing) = run_matrix(false);
    eprintln!("consent matrix: {cells} refused cells (then consented); cells that do not exist: {missing:?}");
    assert!(cells > 1000, "{cells}");
}

/// The matrix under Settings "never": every cell stays refused and consent cannot be given.
#[test]
fn consent_matrix_never() {
    let (cells, _) = run_matrix(true);
    eprintln!("consent matrix under never: {cells} cells");
    assert!(cells > 1000, "{cells}");
}

/// "Never" (and a withdrawn yes) stops what the table's Lua already started: a timer that
/// runs every 20 ms is gone by the next driver tick.
#[test]
fn never_and_withdrawn_consent_stop_running_lua() {
    for how in ["never", "decline"] {
        let t = Target::spawn();
        let app = App::default();
        app.start_driver();
        app.open_process(t.child.id()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker");
        let m = format!("{:?}", marker.to_str().unwrap());
        let script = format!(
            "tm = createTimer(nil) tm.Interval = 20 tm.OnTimer = function() local f = io.open({m}, 'a') f:write('t\\n') f:close() end\n\
             createHotkey(function() local f = io.open({m}, 'a') f:write('hk\\n') f:close() end, VK_CONTROL, VK_F9)"
        );
        let file = dir.path().join("timer.json");
        heaphook::table::save(&file, &Table { lua_script: script, ..Table::default() }).unwrap();
        app.table_open(file.to_str().unwrap(), false).unwrap();
        app.table_trust(true).unwrap();
        app.table_run_script().unwrap();
        wait("timer runs", || (marks(&marker).lines().count() >= 2).then_some(()));
        if how == "never" {
            let mut st = app.settings_get().unwrap();
            st.table_script = "never".into();
            app.settings_set(st).unwrap();
        } else {
            app.table_trust(false).unwrap();
        }
        let n = marks(&marker).lines().count();
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(marks(&marker).lines().count(), n, "{how}: the timer kept running");
        assert_eq!(app.hotkey_press(&[17, 120]).unwrap(), 0, "{how}: the createHotkey hotkey survived");
        assert!(!marks(&marker).contains("hk"));
    }
}

/// A table's entry hotkeys go system-wide only with the entry's consent, and keys are
/// watched for a table only once it is trusted.
#[test]
fn global_hotkeys_follow_consent() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let hk = |keys: Vec<u32>| Hotkey { action: "Toggle Activation".into(), keys, value: None, description: None, id: None };
    let e = Entry { id: 1, description: "hp".into(), addr: t.addr("i32"), hotkeys: vec![hk(vec![17, 113]), hk(vec![112])], ..Entry::default() };
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("t.json");
    heaphook::table::save(&file, &Table { entries: vec![e.clone()], ..Table::default() }).unwrap();
    app.table_open(file.to_str().unwrap(), false).unwrap();
    assert!(app.global_combos().is_empty());
    app.key_state(&[65]).unwrap();
    app.lua_exec("assert(not isKeyPressed(VK_A))").unwrap();
    app.table_trust(true).unwrap();
    assert_eq!(app.global_combos(), vec![vec![17, 113]], "plain F1 is never system-wide");
    let pasted = app.table_paste(vec![Entry { hotkeys: vec![hk(vec![17, 114])], ..e }], None, None).unwrap();
    assert!(!app.global_combos().contains(&vec![17, 114]));
    app.table_trust_entries(&pasted.ids).unwrap();
    assert!(app.global_combos().contains(&vec![17, 114]));
    app.key_state(&[65]).unwrap();
    app.lua_exec("assert(isKeyPressed(VK_A))").unwrap();
}

/// Opening a table drops what the previous table's Lua left (timer, form, breakpoint).
#[test]
fn opening_a_table_drops_the_previous_tables_lua() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let m = format!("{:?}", marker.to_str().unwrap());
    let store = t.addr("store");
    app.lua_exec(&format!(
        "tm = createTimer(nil) tm.Interval = 30 tm.OnTimer = function() local f = io.open({m}, 'a') f:write('t\\n') f:close() end\n\
         fm = createForm() bt = createButton(fm) bt.OnClick = function() local f = io.open({m}, 'a') f:write('b\\n') f:close() end\n\
         debug_setBreakpoint({store}, function() local f = io.open({m}, 'a') f:write('bp\\n') f:close() return 1 end)"
    ))
    .unwrap();
    let old_button = find_control(&app.ui_poll(0).unwrap().snapshot.unwrap().roots, "TButton", None).unwrap();
    let file = dir.path().join("t.json");
    heaphook::table::save(&file, &Table::default()).unwrap();
    app.table_open(file.to_str().unwrap(), false).unwrap();
    let _ = std::fs::remove_file(&marker);
    std::thread::sleep(Duration::from_millis(200));
    assert!(app.ui_event(old_button.id, "OnClick", vec![]).is_err() || marks(&marker).is_empty());
    assert!(app.debug_breakpoints().unwrap().is_empty(), "the Lua breakpoint survived the switch");
    assert!(t.cmd_line("store").starts_with("ok"));
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
    let group = Entry { id: 1, description: "Player".into(), children: vec![i32_entry(2, &t)], ..Entry::default() };
    put(&app, vec![group]);
    assert!(app.table_dirty().unwrap());
    let tp = dir.path().join("t.json");
    app.table_export(tp.to_str().unwrap()).unwrap();
    assert!(!app.table_dirty().unwrap());
    app.table_set_active(&[2], true).unwrap();
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

// ------------------------------------------------- 1.0 RC: last wave's engine features

fn ticker() -> PathBuf {
    let ok = Command::new(env!("CARGO"))
        .args(["build", "-q", "-p", "heaphook", "--example", "ticker"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap()
        .success();
    assert!(ok);
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join("examples/ticker")
}

fn broken(app: &App) -> heaphook::debug::DebugStatus {
    wait("a break", || app.debug_status().ok().filter(|s| s.state == "broken"))
}

#[test]
fn launch_under_debugger_pending_breakpoint_tracepoint_and_reaping() {
    let dir = tempfile::tempdir().unwrap();
    let info_file = dir.path().join("info.json");
    let app = App::default();
    app.start_driver();
    let info = app.debug_launch(&de(json!({"program": ticker().to_str().unwrap(), "args": info_file.to_str().unwrap(), "stop": "first"}))).unwrap();
    // A failed assertion must not leave the program running.
    struct Kill(u32);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = Command::new("kill").args(["-9", &self.0.to_string()]).status();
        }
    }
    let _kill = Kill(info.pid);
    // Stopped before its first instruction: nothing of the program ran, libc is not loaded.
    let st = broken(&app);
    assert!(st.reason.as_deref().unwrap_or("").contains("before the first instruction"), "{st:?}");
    assert!(!info_file.exists());
    // Traced by the debugger thread of this process.
    let tracer = tracer_pid(info.pid);
    assert!(std::path::Path::new(&format!("/proc/self/task/{tracer}")).exists(), "tracer {tracer}");
    // A breakpoint set now, by expression, resolves once libc is loaded.
    let id = app.debug_add_breakpoint(&bp(json!({"pending": "clock_nanosleep"}))).unwrap();
    let row = bp_row(&app, id);
    assert!(row.pending.as_deref() == Some("clock_nanosleep") && !row.resolved, "{row:?}");
    app.debug_continue(false).unwrap();
    let st = broken(&app);
    assert_eq!(st.reason.as_deref(), Some(format!("breakpoint {id}").as_str()), "{st:?}");
    assert!(bp_row(&app, id).resolved);
    assert!(app.debug_log(0).unwrap().lines.iter().any(|l| l.text.contains(&format!("breakpoint {id} resolved"))));
    // The same place as a tracepoint: it logs instead of breaking.
    app.debug_remove_breakpoint(id).unwrap();
    let tp = app.debug_add_breakpoint(&bp(json!({"pending": "clock_nanosleep", "log": true, "message": "sleep clock={rdi}"}))).unwrap();
    app.debug_continue(false).unwrap();
    wait("a tracepoint line", || app.debug_log(0).unwrap().lines.iter().any(|l| l.text.contains(&format!("tracepoint {tp}")) && l.text.contains("sleep clock=0x")).then_some(()));
    assert_ne!(app.debug_status().unwrap().state, "broken");
    // Released, killed and reaped by the app (it has no `Child` for it).
    app.close_process().unwrap();
    assert_eq!(tracer_pid(info.pid), 0);
    let _ = Command::new("kill").arg(info.pid.to_string()).status();
    wait("reaped", || {
        app.reap_children();
        std::fs::read_to_string(format!("/proc/{}/stat", info.pid)).is_err().then_some(())
    });
}

#[test]
fn code_filter_finds_the_function_that_ran() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    assert!(app.code_filter_start().is_err(), "needs a dissection");
    app.dissect_run(&["hh-debug-target".into()], &Default::default()).unwrap();
    assert!(app.code_filter_start().is_err(), "needs the debugger");
    app.debug_attach().unwrap();
    let mut rec = |cmd: &str, ran: bool| {
        let s = app.code_filter_start().unwrap();
        assert!(s.recording && s.armed > 10, "{s:?}");
        t.send(cmd);
        assert!(t.line().starts_with("ok"));
        app.code_filter_stop(ran).unwrap()
    };
    rec("store", true);
    let s = rec("load", false);
    assert_eq!((s.ran_sets, s.not_ran_sets), (1, 1));
    let list = app.code_filter_list(0, 10_000).unwrap();
    let addrs: Vec<String> = list.rows.iter().map(|f| hex(f.addr)).collect();
    assert!(addrs.contains(&t.addr("store")), "store ran: {addrs:?}");
    assert!(!addrs.contains(&t.addr("load")), "load is in the did-not-run set");
    app.code_filter_reset().unwrap();
    assert_eq!(app.code_filter_state().unwrap().ran_sets, 0);
    app.debug_detach().unwrap();
}

/// `loadbinary` in a typed Auto Assemble script: reads the file as Settings allow, never a
/// device or a pipe; a loaded table's entry reads it only with the table's consent.
#[test]
fn loadbinary_follows_origin_and_file_access() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("four.bin");
    std::fs::write(&bin, [0x11u8, 0x22, 0x33, 0x44]).unwrap();
    let at = t.addr("i32").trim_start_matches("0x").to_string();
    let script = format!("[ENABLE]\nloadbinary({at},{})\n[DISABLE]\n", bin.display());
    let tbl = dir.path().join("t.json");
    let e = Entry { id: 1, description: "blob".into(), script: Some(script.clone()), ..Entry::default() };
    heaphook::table::save(&tbl, &Table { entries: vec![e], ..Table::default() }).unwrap();
    app.table_open(tbl.to_str().unwrap(), false).unwrap();
    // The loaded table's entry: refused until the table is trusted.
    needs_consent(app.table_set_active(&[1], true));
    // No session: nothing proves the text was typed.
    needs_consent(app.aa_execute(&script, true, None, None));
    assert_eq!(t.cmd("get")["i32"], 123456);
    app.table_trust(true).unwrap();
    app.table_set_active(&[1], true).unwrap();
    assert_eq!(t.cmd("get")["i32"], 0x44332211);
    app.table_set_active(&[1], false).unwrap();
    app.write_value(&t.addr("i32"), de(json!("4bytes")), "5", &Fmt::default(), None).unwrap();
    // Typed into the Auto Assemble window: it runs.
    let s = app.aa_session().unwrap();
    let st = app.aa_execute(&script, true, None, Some(s)).unwrap();
    assert_eq!(t.cmd("get")["i32"], 0x44332211);
    let _ = app.aa_execute(&script, false, Some(&st), Some(s));
    // Never a device or a pipe.
    let dev = format!("[ENABLE]\nloadbinary({at},/dev/zero)\n[DISABLE]\n");
    assert!(app.aa_execute(&dev, true, None, Some(s)).unwrap_err().contains("not a regular file"));
    // Settings without file access refuse it outright.
    let st = app.settings_get().unwrap();
    app.settings_set(heaphook::settings::Settings { lua_allow_os: false, ..st.clone() }).unwrap();
    assert!(app.aa_execute(&script, true, None, Some(s)).unwrap_err().contains("do not allow"));
    // "Never" withdraws the table's consent: its entry is refused again.
    app.settings_set(heaphook::settings::Settings { table_script: "never".into(), ..st }).unwrap();
    assert!(app.table_set_active(&[1], true).unwrap_err().contains("never"));
}

#[test]
fn region_filters_sort_remove_export_and_stats() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let i32a = t.addr("i32");
    let a = parse_addr(&i32a).unwrap();
    let scan = |opts: Value| first_scan(&app, json!({"vtype": "4bytes", "scan_type": "exact", "value": "123456", "not": false, "opts": opts}));
    // The values live on the heap: private memory, not in a module image.
    assert!(scan(json!({"writable": "any", "kinds": ["Private"]})) >= 1 && has_addr(&app, &i32a));
    scan(json!({"writable": "any", "kinds": ["Image"]}));
    assert!(!has_addr(&app, &i32a));
    scan(json!({"writable": "any", "modules": ["hh-target"]}));
    assert!(!has_addr(&app, &i32a));
    assert!(app.scan_first(&de(json!({"vtype": "4bytes", "scan_type": "exact", "value": "1", "not": false, "opts": {"modules": ["no-such-module"]}}))).is_err());
    assert_eq!(scan(json!({"writable": "any", "ranges": [{"start": i32a, "end": hex(a + 4)}]})), 1);
    assert_eq!(scan(json!({"writable": "any", "min_region_size": 1u64 << 40})), 0);
    // A wider scan to sort, remove, export.
    let n = first_scan(&app, json!({"vtype": "byte", "scan_type": "unknown", "not": false, "opts": {"writable": "yes", "alignment": 4, "ranges": [{"start": i32a, "end": hex(a + 0x40)}]}}));
    assert_eq!(n, 16);
    app.scan_sort(de(json!("value")), true).unwrap();
    let rows = app.scan_results(0, 100, None).unwrap();
    let v: Vec<i64> = rows.iter().map(|r| r.value.clone().unwrap().parse().unwrap()).collect();
    assert!(v.windows(2).all(|w| w[0] >= w[1]), "{v:?}");
    assert_eq!(app.scan_remove(std::slice::from_ref(&i32a)).unwrap(), 1);
    assert!(!has_addr(&app, &i32a));
    app.scan_undo().unwrap();
    assert!(has_addr(&app, &i32a));
    let text = app.scan_copy_addresses().unwrap();
    assert_eq!(text.lines().count(), 16);
    assert!(text.contains(&format!("{a:X}")));
    let f = tempfile::NamedTempFile::new().unwrap();
    assert_eq!(app.scan_export_addresses(f.path().to_str().unwrap()).unwrap(), 16);
    let stats = app.scan_stats().unwrap();
    assert_eq!(stats.iter().map(|s| s.count).sum::<u64>(), 16);
    // Pointer-value scan: the chain's base pointer points into the heap.
    let c = app.scan_pointer(&de(json!({"opts": {"writable": "any"}}))).unwrap().count;
    assert!(c >= 1 && has_addr(&app, &t.addr("chain")));
}

#[test]
fn custom_typed_hotkey_increase_and_freeze_in_converted_units() {
    let mut t = Target::spawn();
    let app = App::default();
    app.start_driver();
    app.open_process(t.child.id()).unwrap();
    let ct: hh_scan::CustomType = de(json!({"size": 4, "signed": true, "scale": 0.5, "offset": 0.0}));
    let hk = |action: &str, value: &str| Hotkey { action: action.into(), keys: vec![17, 112], value: Some(value.into()), description: None, id: None };
    let mut e = i32_entry(1, &t);
    e.custom = Some(ct);
    e.hotkeys = vec![hk("Increase Value", "1"), hk("Set Value", "100"), hk("Toggle Activation", "")];
    put(&app, vec![e]);
    // 123456 raw = 61728 converted; +1 converted = +2 raw.
    app.table_hotkey(1, 0).unwrap();
    assert_eq!(t.cmd("get")["i32"], 123458);
    app.table_hotkey(1, 1).unwrap();
    assert_eq!(t.cmd("get")["i32"], 200);
    // Frozen to its converted value (100 = raw 200).
    app.table_hotkey(1, 2).unwrap();
    t.cmd("inc");
    wait("frozen to 100 converted", || (t.cmd("get")["i32"] == 200).then_some(()));
    let lua = "local r = getAddressList().getMemoryRecordByID(1) r.Value = 7 print(r.Value)";
    app.lua_exec(lua).unwrap();
    assert!(log_text(&app).contains('7'));
    wait("frozen to 7 converted", || (t.cmd("get")["i32"] == 14).then_some(()));
}

#[test]
fn pointer_scan_pauses_and_resumes() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    assert!(app.ptr_pause(true).is_err(), "nothing runs");
    let a2 = app.clone();
    let target = t.addr("chain_value");
    let h = std::thread::spawn(move || {
        a2.ptr_scan(&de(json!({"target": target, "opts": {"max_level": 4, "max_offset": 0x400, "static_only": true, "threads": 1, "starts_with": [], "stop_at_static": true, "time_limit_secs": 60}})))
    });
    let mut paused = false;
    for _ in 0..5000 {
        if app.ptr_progress().unwrap().running && app.ptr_pause(true).is_ok() {
            paused = true;
            break;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    if paused {
        std::thread::sleep(Duration::from_millis(100));
        let p1 = app.ptr_progress().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let p2 = app.ptr_progress().unwrap();
        assert!(p2.paused && p2.running && p1.done == p2.done && p1.phase == p2.phase, "{p1:?} {p2:?}");
        app.ptr_pause(false).unwrap();
    } else {
        eprintln!("pointer scan finished before it could be paused");
    }
    let info = h.join().unwrap().unwrap();
    assert!(info.count >= 1 && info.compact, "{info:?}");
    assert!(!app.ptr_progress().unwrap().paused);
}

#[test]
fn memory_file_search_stats_change_map_and_structure_view() {
    let mut t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let i32a = t.addr("i32");
    let range: Vec<hh_tools::memory::Range> = de(json!([{"start": i32a, "size": 4096}]));
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("m.hhmem");
    app.mem_save(&range, file.to_str().unwrap()).unwrap();
    let hits = app.mem_file_search(&de(json!({"path": file.to_str().unwrap(), "pattern": "40 E2 01 00"}))).unwrap();
    assert!(hits.contains(&i32a), "{hits:?}");
    let hits = app.mem_file_search(&de(json!({"path": file.to_str().unwrap(), "vtype": "4bytes", "value": "123456"}))).unwrap();
    assert!(hits.contains(&i32a));
    assert!(app.mem_file_search(&de(json!({"path": "/dev/zero", "pattern": "00"}))).is_err());
    let st = app.region_stats().unwrap();
    assert!(st.regions > 0 && !st.by_prot.is_empty());
    let s1 = app.snapshot_take(&range, "a").unwrap();
    t.cmd("inc");
    let s2 = app.snapshot_take(&range, "b").unwrap();
    let m = app.snapshot_change_map(s1.id, s2.id, "", "", 16).unwrap();
    // The range may straddle a page boundary: every compared page holds a changed value.
    let (c, x) = (m.compared.iter().sum::<u32>(), m.changed.iter().sum::<u32>());
    assert!(c >= 1 && x >= 1 && x <= c, "{m:?}");
    // Structure view: changed fields between views, lock, write, C export, field entry.
    let el = |o: u64, t: &str| json!({"offset": o, "description": format!("f{o}"), "vtype": t});
    let st: Vec<hh_tools::structure::Structure> = de(json!([{"name": "V", "elements": [el(0, "4bytes"), el(8, "8bytes")]}]));
    app.struct_set(st).unwrap();
    let req: Vec<heaphook::tools::EvalReq> = de(json!([{"name": "V", "addr": i32a}]));
    let v = app.struct_view(&req).unwrap().remove(0).unwrap();
    assert!(v.changed.is_empty() && !v.locked);
    t.cmd("inc");
    let v = app.struct_view(&req).unwrap().remove(0).unwrap();
    assert!(v.changed.contains(&0), "{v:?}");
    app.struct_lock("V", &i32a, true).unwrap();
    app.struct_write("V", &i32a, 0, "77").unwrap();
    let v = app.struct_view(&req).unwrap().remove(0).unwrap();
    assert!(v.locked && v.changed.contains(&0) && v.fields[0].value.as_deref() != Some("77"), "{v:?}");
    app.struct_lock("V", &i32a, false).unwrap();
    assert_eq!(t.cmd("get")["i32"], 77);
    assert!(app.struct_code(&[], "c").unwrap().contains("struct V"));
    let e = app.struct_field_entry("V", &i32a, &[1]).unwrap();
    assert_eq!(e.vtype, de::<hh_scan::VType>(json!("8bytes")));
    // Bad definitions are refused.
    assert!(app.struct_set(de(json!([{"name": "B", "elements": [{"offset": 0, "description": "x", "vtype": "float", "bit_len": 3}]}]))).is_err());
}

// ---------- origin through undo / redo, and a state-machine fuzz of the trust model ----------

fn live_ids(app: &App) -> Vec<i64> {
    let mut v = Vec::new();
    preorder(&app.table_get().unwrap().table.entries, &mut v);
    v
}

/// The fourth audit's bypass: an inserted entry undone and redone must come back with the
/// origin it had (it came back as the user's own). Consent given to that id may stay; ids are
/// never reused; a put can neither bring in an id the backend did not issue nor change an
/// existing id's origin.
#[test]
fn undo_redo_never_forgets_origin() {
    use hh_lua::Caps;
    let app = App::default();
    let e = |d: &str| Entry { description: d.into(), script: Some("[ENABLE]\n{$lua}\nreturn ''\n{$asm}\n[DISABLE]\n".into()), ..Entry::default() };
    let a = app.table_paste(vec![e("a")], None, None).unwrap().ids[0];
    assert_eq!(app.table_caps(a), Caps::None);
    app.table_history(false).unwrap();
    app.table_history(true).unwrap();
    assert_eq!(app.table_caps(a), Caps::None, "undo + redo laundered the pasted entry");
    assert!(app.table_get().unwrap().untrusted.contains(&a));
    // Granted, undone past the insert, redone: the grant stays with that id.
    app.table_trust_entries(&[a]).unwrap();
    app.table_history(false).unwrap();
    app.table_history(true).unwrap();
    assert_eq!(app.table_caps(a), Caps::Full);
    // A second one, never granted: undone and redone, it stays untrusted.
    let b = app.table_paste(vec![e("b")], None, None).unwrap().ids[0];
    app.table_history(false).unwrap();
    app.table_history(true).unwrap();
    assert_eq!(app.table_caps(b), Caps::None);
    // Undone, then something new: a new id, never the old one.
    app.table_history(false).unwrap();
    let c = app.table_new(vec![e("c")], None, None).unwrap().ids[0];
    assert!(c > b, "id {b} reused as {c}");
    assert_eq!(app.table_caps(c), Caps::Full);
    // A put cannot change an origin (move, rename, retype) nor bring in an unissued id.
    let cur = app.table_get().unwrap();
    let mut t = cur.table.clone();
    t.entries.retain(|x| x.id != c);
    let mut moved = cur.table.entries.iter().find(|x| x.id == c).unwrap().clone();
    moved.description = "now under a".into();
    t.entries.iter_mut().find(|x| x.id == a).unwrap().children.push(moved);
    app.table_put(t, cur.version).unwrap();
    assert_eq!(app.table_caps(c), Caps::Full);
    let cur = app.table_get().unwrap();
    let mut t = cur.table.clone();
    t.entries.push(Entry { id: 9999, ..e("typed?") });
    assert!(app.table_put(t, cur.version).unwrap_err().contains("not issued"));
    // The old id of b is in no table any more; putting it back cannot make it the user's.
    let cur = app.table_get().unwrap();
    let mut t = cur.table.clone();
    t.entries.push(Entry { id: b, ..e("b again") });
    app.table_put(t, cur.version).unwrap();
    assert_eq!(app.table_caps(b), Caps::None);
}

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum FuzzOp {
    Open,
    OpenData,
    LuaLoadTable,
    ForceOpen,
    Paste,
    Merge,
    MergeWithScript,
    LuaMerge,
    AaAssign,
    TypedAssign,
    Template,
    New,
    LuaCreate,
    LuaSetDelete,
    PutEdits,
    Delete,
    StructEdit,
    Undo,
    Redo,
    GrantEntries,
    GrantTable,
    Revoke,
    NeverOn,
    NeverOff,
    SwitchProcess,
    RunScript,
    Callback,
    Execute,
    Console,
    TableLuaCreate,
    TableLuaModify,
}
const FUZZ_OPS: [FuzzOp; 31] = [
    FuzzOp::Open,
    FuzzOp::OpenData,
    FuzzOp::LuaLoadTable,
    FuzzOp::ForceOpen,
    FuzzOp::Paste,
    FuzzOp::Merge,
    FuzzOp::MergeWithScript,
    FuzzOp::LuaMerge,
    FuzzOp::AaAssign,
    FuzzOp::TypedAssign,
    FuzzOp::Template,
    FuzzOp::New,
    FuzzOp::LuaCreate,
    FuzzOp::LuaSetDelete,
    FuzzOp::PutEdits,
    FuzzOp::Delete,
    FuzzOp::StructEdit,
    FuzzOp::Undo,
    FuzzOp::Redo,
    FuzzOp::GrantEntries,
    FuzzOp::GrantTable,
    FuzzOp::Revoke,
    FuzzOp::NeverOn,
    FuzzOp::NeverOff,
    FuzzOp::SwitchProcess,
    FuzzOp::RunScript,
    FuzzOp::Callback,
    FuzzOp::Execute,
    FuzzOp::Console,
    FuzzOp::TableLuaCreate,
    FuzzOp::TableLuaModify,
];

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind2 {
    Own,
    Table,
    Foreign,
}

/// What the trust model says, kept independently of the backend.
#[derive(Default)]
struct Model {
    kind: std::collections::HashMap<i64, Kind2>,
    agreed: std::collections::HashSet<i64>,
    table_agreed: bool,
    never: bool,
    max_id: i64,
    /// A table script ran with consent that is still in force (its globals may exist).
    script_live: bool,
    remote: bool,
    /// No table was opened (nor a script merged in): the session's own table, all the user's.
    opened: bool,
    /// The record the table script (put in by `TableLuaModify`) scripts when it runs.
    script_target: Option<i64>,
}

impl Model {
    fn allowed(&self, id: i64) -> bool {
        match self.kind.get(&id) {
            Some(Kind2::Own) => true,
            Some(Kind2::Table) => self.table_agreed && !self.never,
            Some(Kind2::Foreign) => self.agreed.contains(&id) && !self.never,
            None => false,
        }
    }
    fn opened(&mut self, ids: Vec<i64>) {
        self.opened = true;
        self.script_target = None;
        self.kind.clear();
        self.agreed.clear();
        self.table_agreed = false;
        self.script_live = false;
        self.max_id = 0;
        for id in ids {
            self.kind.insert(id, Kind2::Table);
            self.max_id = self.max_id.max(id);
        }
    }
    /// The table script ran (as the table): it needed consent unless the table is the
    /// session's own; an own record it scripted is the table's from now on.
    fn script_ran(&mut self, app: &App) -> Result<(), String> {
        if !self.opened {
            return Ok(());
        }
        if !(self.table_agreed && !self.never) {
            return Err("the table script ran without consent".into());
        }
        self.script_live = true;
        if let Some(id) = self.script_target
            && self.kind.get(&id) == Some(&Kind2::Own)
            && live_ids(app).contains(&id)
        {
            self.kind.insert(id, Kind2::Table);
        }
        Ok(())
    }

    /// Consent for the table withdrawn (the app resets Lua when it was in force).
    fn table_withdrawn(&mut self) {
        if self.table_agreed {
            self.script_live = false;
        }
        self.table_agreed = false;
    }
}

/// The shared world of the fuzz runs: one target, one (hostile) remote server.
struct FuzzEnv {
    pid: u32,
    store: String,
    server: String,
    dir: tempfile::TempDir,
}

/// Each entry's `{$lua}` writes its own id (`memrec.ID`) to the marker when it runs.
fn fuzz_script(marker: &std::path::Path) -> String {
    format!("[ENABLE]\n{{$lua}}\nlocal f = io.open({:?}, 'a') f:write(memrec.ID .. '\\n') f:close()\nreturn ''\n{{$asm}}\n[DISABLE]\n", marker.to_str().unwrap())
}

/// A table script that leaves a global behind: `tostring` writing `T` to the marker.
fn fuzz_table_script(marker: &std::path::Path) -> String {
    format!("local t, o = tostring, io.open\ntostring = function(...) local f = o({:?}, 'a') f:write('T\\n') f:close() return t(...) end", marker.to_str().unwrap())
}

fn fuzz_entries(r: &mut Rng, tag: &str, marker: &std::path::Path) -> Vec<Entry> {
    let hk = |keys: Vec<u32>| Hotkey { action: "Activate".into(), keys, value: None, description: None, id: None };
    (0..1 + r.below(3))
        .map(|i| {
            let kids = if r.below(3) == 0 { vec![Entry { description: format!("{tag}{i}k"), script: Some(fuzz_script(marker)), ..Entry::default() }] } else { vec![] };
            Entry { description: format!("{tag}{i}"), script: Some(fuzz_script(marker)), hotkeys: vec![hk(vec![17, 118])], children: kids, ..Entry::default() }
        })
        .collect()
}

fn set_never(app: &App, on: bool) {
    let mut st = app.settings_get().unwrap();
    st.table_script = if on { "never" } else { "ask" }.into();
    app.settings_set(st).unwrap();
}

fn take_marks(marker: &std::path::Path) -> Vec<String> {
    let m = marks(marker);
    let _ = std::fs::remove_file(marker);
    m.lines().map(str::to_string).collect()
}

/// Runs `ops` (each with its own random word); Err((step, why)) at the first broken invariant.
fn fuzz_run(env: &FuzzEnv, ops: &[(FuzzOp, u64)]) -> Result<(), (usize, String)> {
    let app = App::default();
    app.open_process(env.pid).unwrap();
    let dir = tempfile::tempdir_in(env.dir.path()).unwrap();
    let marker = dir.path().join("marker");
    let mut m = Model::default();
    let (mut ran, mut ran_t) = (0usize, 0usize);
    for (step, &(op, word)) in ops.iter().enumerate() {
        let mut r = Rng(word | 1);
        let before = live_ids(&app);
        let file = |r: &mut Rng, name: &str, script: bool| {
            let p = dir.path().join(format!("{name}{step}.json"));
            let lua_script = if script { fuzz_table_script(&marker) } else { String::new() };
            heaphook::table::save(&p, &Table { entries: fuzz_entries(r, name, &marker), lua_script, ..Table::default() }).unwrap();
            p
        };
        // The kind the ids this op mints get (None: it mints none).
        let mut mint: Option<Kind2> = None;
        match op {
            FuzzOp::Open | FuzzOp::OpenData | FuzzOp::LuaLoadTable => {
                let with_script = r.below(2) == 0;
                let p = file(&mut r, "open", with_script);
                match op {
                    FuzzOp::Open => drop(app.table_open(p.to_str().unwrap(), false)),
                    FuzzOp::OpenData => drop(app.table_open_data("x.json", &std::fs::read_to_string(&p).unwrap(), false)),
                    _ => drop(app.lua_exec(&format!("loadTable({:?})", p.to_str().unwrap()))),
                }
                m.opened(live_ids(&app));
                continue;
            }
            FuzzOp::ForceOpen => {
                // An own script whose [DISABLE] fails stays active: a forced open carries it.
                let stuck = Entry { description: "stuck".into(), script: Some("[ENABLE]\n[DISABLE]\nassert(0,00)\n".into()), ..Entry::default() };
                let id = app.table_new(vec![stuck], None, None).unwrap().ids[0];
                app.table_set_active(&[id], true).unwrap();
                let p = file(&mut r, "force", false);
                app.table_open(p.to_str().unwrap(), true).unwrap();
                m.opened(live_ids(&app));
                let st = app.table_get().unwrap();
                if let Some(g) = st.table.entries.iter().find(|e| e.description == "Still active from the previous table") {
                    m.kind.insert(g.id, Kind2::Own);
                    for c in &g.children {
                        m.kind.insert(c.id, Kind2::Own);
                    }
                }
                let _ = app.lua_exec("getAddressList().disableAllWithoutExecute()");
                continue;
            }
            FuzzOp::Paste => {
                let after = (!before.is_empty() && r.below(2) == 0).then(|| before[r.below(before.len())]);
                let _ = app.table_paste(fuzz_entries(&mut r, "paste", &marker), after, None);
                mint = Some(Kind2::Foreign);
            }
            FuzzOp::Merge | FuzzOp::MergeWithScript | FuzzOp::LuaMerge => {
                let script = matches!(op, FuzzOp::MergeWithScript);
                let adopts = script && app.table_get().unwrap().table.lua_script.trim().is_empty();
                let p = file(&mut r, "merge", script);
                let ok = if matches!(op, FuzzOp::LuaMerge) { app.lua_exec(&format!("loadTable({:?}, true)", p.to_str().unwrap())).is_ok() } else { app.table_merge(p.to_str().unwrap()).is_ok() };
                if ok && adopts {
                    // The table asks again; its entries that could run keep running.
                    if m.table_agreed && !m.never {
                        for (id, k) in m.kind.iter_mut() {
                            if *k == Kind2::Table {
                                *k = Kind2::Foreign;
                                m.agreed.insert(*id);
                            }
                        }
                    }
                    m.table_agreed = false;
                    m.opened = true;
                }
                mint = Some(Kind2::Foreign);
            }
            FuzzOp::AaAssign => {
                let f = dir.path().join(format!("s{step}.cea"));
                std::fs::write(&f, fuzz_script(&marker)).unwrap();
                let s = app.aa_session().unwrap();
                app.aa_load_file(f.to_str().unwrap(), s).unwrap();
                let agree = r.below(2) == 0 && app.aa_trust(s).is_ok();
                let before_ids = live_ids(&app);
                let _ = app.aa_assign(s, &fuzz_script(&marker), "assigned", None, None);
                for id in live_ids(&app).into_iter().filter(|i| !before_ids.contains(i)) {
                    if agree {
                        m.agreed.insert(id);
                    }
                }
                mint = Some(Kind2::Foreign);
            }
            FuzzOp::TypedAssign => {
                let s = app.aa_session().unwrap();
                let _ = app.aa_assign(s, &fuzz_script(&marker), "typed", None, None);
                mint = Some(Kind2::Own);
            }
            FuzzOp::Template => {
                let _ = app.table_add_template(&env.store, "code", "tpl", None, None);
                mint = Some(if m.remote { Kind2::Foreign } else { Kind2::Own });
            }
            FuzzOp::New => {
                let _ = app.table_new(fuzz_entries(&mut r, "new", &marker), None, None);
                mint = Some(Kind2::Own);
            }
            FuzzOp::LuaCreate => {
                let _ = app.lua_exec("getAddressList().createMemoryRecord().Description = 'lua'");
                mint = Some(Kind2::Own);
            }
            FuzzOp::LuaSetDelete => {
                if !before.is_empty() {
                    let id = before[r.below(before.len())];
                    let what = if r.below(2) == 0 { "Description = 'renamed by lua'" } else { "destroy()" };
                    let _ = app.lua_exec(&format!("local r = getAddressList().getMemoryRecordByID({id}) if r then r.{what} end"));
                }
            }
            FuzzOp::PutEdits | FuzzOp::Delete => {
                let cur = app.table_get().unwrap();
                let mut t = cur.table.clone();
                let ids = live_ids(&app);
                for _ in 0..1 + r.below(3) {
                    if ids.is_empty() {
                        break;
                    }
                    let id = ids[r.below(ids.len())];
                    match if matches!(op, FuzzOp::Delete) { 0 } else { r.below(4) } {
                        0 => {
                            take_entry(&mut t.entries, id);
                        }
                        1 => {
                            if let Some(mut e) = take_entry(&mut t.entries, id) {
                                e.description = format!("edited {}", r.next() % 100);
                                e.script = Some(format!("// edited\n{}", e.script.unwrap_or_default()));
                                t.entries.insert(r.below(t.entries.len() + 1), e);
                            }
                        }
                        _ => {
                            let to = ids[r.below(ids.len())];
                            if let Some(e) = take_entry(&mut t.entries, id) {
                                fn find(l: &mut [Entry], id: i64) -> Option<&mut Entry> {
                                    for x in l {
                                        if x.id == id {
                                            return Some(x);
                                        }
                                        if let Some(y) = find(&mut x.children, id) {
                                            return Some(y);
                                        }
                                    }
                                    None
                                }
                                match find(&mut t.entries, to) {
                                    Some(p) => p.children.push(e),
                                    None => t.entries.push(e),
                                }
                            }
                        }
                    }
                }
                let _ = app.table_put(t, cur.version);
            }
            FuzzOp::StructEdit => {
                let s = hh_tools::structure::from_json(&format!(r#"[{{"name":"s{}","elements":[{{"offset":0,"vtype":"4bytes"}}]}}]"#, r.below(5))).unwrap();
                let _ = app.struct_set(s);
            }
            FuzzOp::Undo => {
                let _ = app.table_history(false);
            }
            FuzzOp::Redo => {
                let _ = app.table_history(true);
            }
            FuzzOp::GrantEntries => {
                let st = app.table_get().unwrap();
                if !st.untrusted.is_empty() {
                    let pick = st.untrusted[r.below(st.untrusted.len())];
                    if app.table_trust_entries(&[pick]).is_ok() {
                        fn sub(l: &[Entry], id: i64, out: &mut Vec<i64>, inside: bool) {
                            for e in l {
                                let now = inside || e.id == id;
                                if now {
                                    out.push(e.id);
                                }
                                sub(&e.children, id, out, now);
                            }
                        }
                        let mut v = Vec::new();
                        sub(&st.table.entries, pick, &mut v, false);
                        for id in v.into_iter().filter(|i| m.kind.get(i) == Some(&Kind2::Foreign)) {
                            m.agreed.insert(id);
                        }
                    } else if !m.never {
                        return Err((step, "a grant was refused without never".into()));
                    }
                }
            }
            FuzzOp::GrantTable => {
                if app.table_trust(true).is_ok() {
                    m.table_agreed = true;
                } else if !m.never {
                    return Err((step, "the table grant was refused without never".into()));
                }
            }
            FuzzOp::Revoke => {
                app.table_trust(false).unwrap();
                m.table_withdrawn();
            }
            FuzzOp::NeverOn => {
                set_never(&app, true);
                m.never = true;
                m.table_withdrawn();
                m.agreed.clear();
            }
            FuzzOp::NeverOff => {
                set_never(&app, false);
                m.never = false;
            }
            FuzzOp::SwitchProcess => {
                // A process change keeps the table, its consent and its Lua.
                if r.below(2) == 0 {
                    app.remote_connect(&env.server, TOKEN, false).unwrap();
                    app.remote_open(env.pid).unwrap();
                    m.remote = true;
                } else {
                    app.open_process(env.pid).unwrap();
                    m.remote = false;
                }
            }
            FuzzOp::RunScript => {
                let has = !app.table_get().unwrap().table.lua_script.trim().is_empty();
                if app.table_run_script().is_ok() && has {
                    m.script_ran(&app).map_err(|e| (step, e))?;
                }
                mint = Some(if m.opened { Kind2::Table } else { Kind2::Own });
            }
            FuzzOp::Callback => {
                if !before.is_empty() {
                    let id = before[r.below(before.len())];
                    // The user's own console code sets a callback on some entry: it runs only
                    // for an entry with capabilities.
                    let _ = app.lua_exec(&format!(
                        "local r = getAddressList().getMemoryRecordByID({id}) if r then r.OnActivate = function() local f = io.open({:?}, 'a') f:write('cb{id}\\n') f:close() end end",
                        marker.to_str().unwrap()
                    ));
                }
            }
            FuzzOp::Execute => {
                if !before.is_empty() {
                    let id = before[r.below(before.len())];
                    let _ = take_marks(&marker);
                    let _ = match r.below(4) {
                        0 => app.table_set_active(&[id], true),
                        1 => app.table_hotkey(id, 0),
                        2 => app.hotkey_press(&[17, 118]).map(|_| ()),
                        _ => app.lua_exec(&format!("local r = getAddressList().getMemoryRecordByID({id}) if r then r.Active = true end")),
                    };
                    for line in take_marks(&marker) {
                        ran += 1;
                        let ran = line.trim_start_matches("cb").parse::<i64>().unwrap_or(-1);
                        if line == "T" {
                            if !m.script_live {
                                return Err((step, "the table script's global ran without consent in force".into()));
                            }
                        } else if !m.allowed(ran) {
                            return Err((step, format!("entry {ran} ran ({line}) while the model does not allow it ({:?}, never {})", m.kind.get(&ran), m.never)));
                        }
                    }
                    let _ = app.lua_exec("getAddressList().disableAllWithoutExecute()");
                }
            }
            FuzzOp::TableLuaCreate | FuzzOp::TableLuaModify => {
                // The table's own script (edited in, then run as the table): what it creates is
                // the table's, and an own record it scripts becomes the table's.
                let target = (!before.is_empty()).then(|| before[r.below(before.len())]);
                let code = match (op, target) {
                    (FuzzOp::TableLuaModify, Some(id)) => format!(
                        "local r = getAddressList().getMemoryRecordByID({id}) if r then r.Script = {:?} end",
                        fuzz_script(&marker)
                    ),
                    _ => format!("local m = getAddressList().createMemoryRecord() m.Type = vtAutoAssembler m.Script = {:?}", fuzz_script(&marker)),
                };
                let cur = app.table_get().unwrap();
                if app.table_put(Table { lua_script: code, ..cur.table }, cur.version).is_ok() {
                    m.script_target = if op == FuzzOp::TableLuaModify { target } else { None };
                    if app.table_run_script().is_ok() {
                        m.script_ran(&app).map_err(|e| (step, e))?;
                    }
                }
                mint = Some(if m.opened { Kind2::Table } else { Kind2::Own });
            }
            FuzzOp::Console => {
                let _ = take_marks(&marker);
                let _ = app.lua_exec("return tostring(1)");
                if take_marks(&marker).iter().any(|l| l == "T") {
                    ran_t += 1;
                    if !m.script_live {
                        return Err((step, "a withdrawn table script's tostring ran".into()));
                    }
                }
            }
        }
        // Ids: only inserting ops mint, always past every id issued before.
        let fresh: Vec<i64> = live_ids(&app).into_iter().filter(|i| !m.kind.contains_key(i)).collect();
        for id in fresh {
            let Some(k) = mint else { return Err((step, format!("{op:?} brought in id {id} nobody issued"))) };
            if id <= m.max_id {
                return Err((step, format!("{op:?} reused id {id} (max issued {})", m.max_id)));
            }
            m.kind.insert(id, k);
        }
        m.max_id = m.max_id.max(m.kind.keys().copied().max().unwrap_or(0));
        // The invariant, for every live entry.
        for id in live_ids(&app) {
            let full = app.table_caps(id) == hh_lua::Caps::Full;
            if full && !m.allowed(id) {
                return Err((step, format!("after {op:?}: id {id} ({:?}) has capabilities the model does not grant (never {})", m.kind.get(&id), m.never)));
            }
            if m.never && full && m.kind.get(&id) != Some(&Kind2::Own) {
                return Err((step, format!("after {op:?}: id {id} is Full under never")));
            }
            if !full && m.allowed(id) {
                return Err((step, format!("after {op:?}: id {id} ({:?}) lost capabilities the model grants", m.kind.get(&id))));
            }
        }
    }
    if std::env::var("HH_FUZZ_STATS").is_ok() {
        let ids = live_ids(&app);
        let full = ids.iter().filter(|&&i| app.table_caps(i) == hh_lua::Caps::Full).count();
        eprintln!("end: {} live entries, {full} with capabilities, {} ids issued, never {}; {ran} entry runs and {ran_t} table-global runs seen", ids.len(), m.kind.len(), m.never);
    }
    Ok(())
}

/// Seeded random sequences over every operation that touches entries, consent or Lua; after
/// every step each live entry's capabilities match an independent model, and at intervals
/// entries and the console actually run: a marker appears only when the model allows it. On
/// failure: the seed and a greedily shortened sequence.
#[test]
fn trust_model_fuzz() {
    let t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let server = hh_net::Server::bind("127.0.0.1:0", hh_net::ServerConfig::new(TOKEN), std::sync::Arc::new(HostileBackend)).unwrap().spawn().unwrap();
    let env = FuzzEnv { pid: t.child.id(), store: t.addr("store"), server: server.addr().to_string(), dir: tempfile::tempdir().unwrap() };
    let seeds: Vec<u64> = match std::env::var("HH_FUZZ_SEED") {
        Ok(s) => vec![s.parse().unwrap()],
        Err(_) => vec![0x9e37_79b9, 1, 42, 0xdead_beef, 7_777_777],
    };
    let steps: usize = std::env::var("HH_FUZZ_STEPS").ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
    // Running things and granting consent come up more often than the rest.
    let mut pool: Vec<FuzzOp> = FUZZ_OPS.to_vec();
    for (op, extra) in [(FuzzOp::Execute, 5), (FuzzOp::Console, 2), (FuzzOp::GrantTable, 2), (FuzzOp::GrantEntries, 3), (FuzzOp::RunScript, 2), (FuzzOp::NeverOff, 1)] {
        pool.extend(std::iter::repeat_n(op, extra));
    }
    let mut total = 0;
    for seed in seeds {
        let mut r = Rng(seed | 1);
        let ops: Vec<(FuzzOp, u64)> = (0..steps).map(|_| (pool[r.below(pool.len())], r.next())).collect();
        if let Err((at, why)) = fuzz_run(&env, &ops) {
            let mut short: Vec<(FuzzOp, u64)> = ops[..=at].to_vec();
            let mut i = short.len();
            while i > 0 {
                i -= 1;
                let mut t = short.clone();
                t.remove(i);
                if fuzz_run(&env, &t).is_err() {
                    short = t;
                }
            }
            let last = fuzz_run(&env, &short).unwrap_err();
            panic!("seed {seed}: step {at}: {why}\nshortened to {} steps: {:?}\nfails with: {}", short.len(), short, last.1);
        }
        total += ops.len();
    }
    drop(server);
    eprintln!("trust model fuzz: {total} steps");
}

// ---------- withdrawing consent leaves nothing of the table's Lua (a new interpreter) ----------

/// What a once-trusted table script leaves behind to run later; each leaves its own trace.
fn poison_payloads() -> Vec<(&'static str, &'static str)> {
    vec![
        ("replaced tostring", "local t = tostring tostring = function(...) mark('tostring') return t(...) end"),
        ("string metatable __index", "getmetatable('').__index = function(s, k) mark('strmeta') return string[k] end"),
        ("debugger_onBreakpoint", "function debugger_onBreakpoint() mark('onbp') return 1 end"),
        ("onOpenProcess", "function onOpenProcess() mark('onopen') end"),
        ("package.loaded poisoning", "package.loaded.string = setmetatable({}, { __index = function(_, k) mark('pkg') return string[k] end })"),
        ("parked thread", "createThread(function() while true do mark('thread') sleep(20) end end)"),
        ("_G traps", "setmetatable(_G, { __index = function(_, k) mark('index') end, __newindex = function(t, k, v) mark('newindex') rawset(t, k, v) end })"),
        ("replaced print", "print = function(...) mark('print') end"),
        ("replaced pcall", "pcall = function(...) mark('pcall') return true end"),
    ]
}

#[test]
fn withdrawn_table_lua_leaves_nothing_running() {
    let mut t = Target::spawn_exe(exe("hh-debug", "hh-debug-target"));
    let pid = t.child.id();
    let store = t.addr("store");
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.json");
    heaphook::table::save(&empty, &Table::default()).unwrap();
    let mut cells = 0;
    for how in ["decline", "never", "open another table"] {
        for (name, payload) in poison_payloads() {
            let app = App::default();
            app.start_driver();
            app.open_process(pid).unwrap();
            let marker = dir.path().join(format!("m-{cells}"));
            let m = format!("{:?}", marker.to_str().unwrap());
            let script = format!(
                "local io_open = io.open\nlocal function mark(w) local f = io_open({m}, 'a') f:write(w .. '\\n') f:close() end\n\
                 tm = createTimer(nil) tm.Interval = 20 tm.OnTimer = function() mark('timer') end\n\
                 fm = createForm() bt = createButton(fm) bt.OnClick = function() mark('form') end\n\
                 createHotkey(function() mark('hotkey') end, VK_CONTROL, VK_F9)\n{payload}\n"
            );
            let file = dir.path().join(format!("t-{cells}.json"));
            heaphook::table::save(&file, &Table { lua_script: script, ..Table::default() }).unwrap();
            app.table_open(file.to_str().unwrap(), false).unwrap();
            app.table_trust(true).unwrap();
            app.table_run_script().unwrap();
            wait("the table's timer runs", || marks(&marker).contains("timer").then_some(()));
            let button = find_control(&app.ui_poll(0).unwrap().snapshot.unwrap().roots, "TButton", None).unwrap();
            match how {
                "decline" => app.table_trust(false).unwrap(),
                "never" => set_never(&app, true),
                _ => {
                    app.table_open(empty.to_str().unwrap(), false).unwrap();
                }
            }
            assert!(log_text(&app).contains("Lua was reset"), "{how}: no reset notice");
            std::thread::sleep(Duration::from_millis(60)); // a timer tick in flight lands first
            let _ = std::fs::remove_file(&marker);
            let what = format!("{how} x {name}");
            // console eval (traps, replaced functions, package.loaded)
            app.lua_exec("x = 1 local _ = y return require('string').format('%d', 1 + 1), tostring(3), ('a'):upper()").unwrap();
            app.lua_exec("print('hi') pcall(print, 'x')").unwrap();
            // openProcess
            app.lua_exec(&format!("openProcess({pid})")).unwrap();
            // timer / thread ticks
            std::thread::sleep(Duration::from_millis(150));
            // form event, hotkey press
            let _ = app.ui_event(button.id, "OnClick", vec![]);
            assert!(app.ui_poll(0).unwrap().snapshot.unwrap().roots.is_empty(), "{what}: the form survived");
            assert_eq!(app.hotkey_press(&[17, 120]).unwrap(), 0, "{what}: the hotkey survived");
            // breakpoint hit: the user's own breakpoint; no Lua function may see it
            app.debug_attach().unwrap();
            app.debug_add_breakpoint(&bp(json!({"addr": store}))).unwrap();
            t.send("store");
            wait("broken at store", || (app.debug_status().unwrap().state == "broken").then_some(()));
            app.debug_continue(false).unwrap();
            assert!(t.line().starts_with("ok"));
            app.debug_detach().unwrap();
            assert_eq!(marks(&marker), "", "{what}: the withdrawn table's Lua ran\n{}", log_text(&app));
            cells += 1;
        }
    }
    eprintln!("withdrawal matrix: {cells} cells x 6 routes");
}

/// Trusted Lua copying an untrusted entry's script into another record: that record turns
/// untrusted (it asks like a pasted entry) instead of running the text with full capabilities.
#[test]
fn script_copied_from_an_untrusted_entry_stays_untrusted() {
    let t = Target::spawn();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let script = format!("[ENABLE]\n{{$lua}}\nlocal f = io.open({:?}, 'a') f:write('ran\\n') f:close()\nreturn ''\n{{$asm}}\n[DISABLE]\n", marker.to_str().unwrap());
    let u = app.table_paste(vec![Entry { description: "u".into(), script: Some(script), ..Entry::default() }], None, None).unwrap().ids[0];
    app.lua_exec(&format!(
        "local u = getAddressList().getMemoryRecordByID({u})\nm = getAddressList().createMemoryRecord()\nm.Type = vtAutoAssembler\nm.Script = '// copy\\n' .. u.Script\nm.Active = true\nmid = m.ID"
    ))
    .unwrap();
    assert_eq!(marks(&marker), "", "{}", log_text(&app));
    let st = app.table_get().unwrap();
    assert_eq!(st.untrusted.len(), 2, "the copy is untrusted too: {:?}", st.untrusted);
    let copy = *st.untrusted.iter().find(|&&i| i != u).unwrap();
    assert!(app.table_set_active(&[copy], true).unwrap_err().starts_with(heaphook::cheat::NEEDS_ENTRY_CONSENT));
    assert_eq!(marks(&marker), "");
    app.table_trust_entries(&[copy]).unwrap();
    app.table_set_active(&[copy], true).unwrap();
    assert_eq!(marks(&marker), "ran\n");
}

/// Ids in memory are always positive, unique and at most u32: a file's valid ones are kept
/// (its Lua may name them), the rest renumbered after them.
#[test]
fn loaded_ids_are_renumbered_when_invalid() {
    let app = App::default();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ids.json");
    let e = |id: i64| Entry { id, description: format!("e{id}"), addr: "0x10".into(), ..Entry::default() };
    let t = Table { entries: vec![e(7), e(-3), e(0), e(7), Entry { children: vec![e(1 << 40)], ..e(9) }], ..Table::default() };
    std::fs::write(&p, serde_json::to_string(&t).unwrap()).unwrap();
    let st = app.table_open(p.to_str().unwrap(), false).unwrap();
    let ids = live_ids(&app);
    let mut uniq = ids.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), ids.len(), "{ids:?}");
    assert!(ids.iter().all(|&i| i > 0 && i <= u32::MAX as i64), "{ids:?}");
    assert_eq!((st.table.entries[0].id, st.table.entries[4].id), (7, 9), "valid ids are kept");
    // New ones come after all of them.
    let n = app.table_new(vec![e(0)], None, None).unwrap().ids[0];
    assert!(n > *ids.iter().max().unwrap());
}

/// Records a table's Lua creates or scripts belong to that table: while it is trusted they
/// work; once its consent is withdrawn (or Settings say never, or another table is opened)
/// none of them runs on any route, and their hotkeys are not system-wide.
#[test]
fn records_a_table_made_lose_their_abilities_with_its_consent() {
    let t = Target::spawn();
    let dir = tempfile::tempdir().unwrap();
    for how in ["decline", "never", "open another table"] {
        let app = App::default();
        app.open_process(t.child.id()).unwrap();
        let marker = dir.path().join(format!("m-{}", how.len()));
        let script = format!("[ENABLE]\n{{$lua}}\nlocal f = io.open({:?}, 'a') f:write('ran\\n') f:close()\nreturn ''\n{{$asm}}\n[DISABLE]\n", marker.to_str().unwrap());
        let file = dir.path().join("made.json");
        let lua = format!(
            "made = getAddressList().createMemoryRecord() made.Description = 'made' made.Type = vtAutoAssembler made.Script = {script:?}\n\
             made.createHotkey({{VK_CONTROL, VK_F8}}, mrhToggleActivation)\n\
             local own = getAddressList().getMemoryRecordByDescription('mine') own.Script = {script:?}"
        );
        heaphook::table::save(&file, &Table { lua_script: lua, ..Table::default() }).unwrap();
        app.table_open(file.to_str().unwrap(), false).unwrap();
        // The user's own record (made in the console), later scripted by the table.
        app.lua_exec("local m = getAddressList().createMemoryRecord() m.Description = 'mine' m.Type = vtAutoAssembler m.Script = '[ENABLE]\\n[DISABLE]\\n'").unwrap();
        let mine = find_desc(&app, "mine");
        assert_eq!(app.table_caps(mine), hh_lua::Caps::Full, "the console's record is the user's");
        app.table_trust(true).unwrap();
        app.table_run_script().unwrap();
        let made = find_desc(&app, "made");
        // Trusted: it works.
        app.table_set_active(&[made], true).unwrap();
        app.table_set_active(&[made], false).unwrap();
        assert_eq!(marks(&marker), "ran\n");
        assert!(app.global_combos().contains(&vec![17, 119]));
        let _ = std::fs::remove_file(&marker);
        match how {
            "decline" => app.table_trust(false).unwrap(),
            "never" => set_never(&app, true),
            _ => {
                let empty = dir.path().join("empty.json");
                heaphook::table::save(&empty, &Table::default()).unwrap();
                app.table_open(empty.to_str().unwrap(), false).unwrap();
                assert!(live_ids(&app).is_empty(), "the old table's records went with it");
                continue;
            }
        }
        for id in [made, mine] {
            assert_eq!(app.table_caps(id), hh_lua::Caps::None, "{how}: record {id}");
            let gid = app.table_new(vec![Entry { description: "g".into(), options: vec!["moActivateChildrenAsWell".into()], ..Entry::default() }], None, None).unwrap().ids[0];
            let cur = app.table_get().unwrap();
            let mut tb = cur.table.clone();
            let e = take_entry(&mut tb.entries, id).unwrap();
            tb.entries.iter_mut().find(|g| g.id == gid).unwrap().children.push(e);
            app.table_put(tb, cur.version).unwrap();
            assert!(app.table_set_active(&[id], true).is_err(), "{how}: click");
            assert!(app.table_set_active(&[gid], true).is_err(), "{how}: cascade");
            let _ = app.table_set_active(&[gid], false);
            app.lua_exec(&format!("getAddressList().getMemoryRecordByID({id}).Active = true")).unwrap();
        }
        assert!(app.table_hotkey(made, 0).is_err(), "{how}: table hotkey");
        assert!(app.hotkey_press(&[17, 119]).is_err(), "{how}: hotkey press");
        assert!(!app.global_combos().contains(&vec![17, 119]), "{how}: still system-wide");
        assert_eq!(marks(&marker), "", "{how}: a record the table made ran\n{}", log_text(&app));
    }
}

/// A trusted table's finalizers: it cannot install any (`setmetatable` refuses `__gc`, adding
/// `__gc` later does not register one, host userdata metatables are locked), whether the
/// object would sit in a global, an upvalue of a registered callback or a lookup callback; and
/// on every way consent ends nothing of it runs (no marker, no new entry).
#[test]
fn a_tables_finalizers_never_run() {
    let dir = tempfile::tempdir().unwrap();
    for how in ["decline", "never", "open another table"] {
        let app = App::default();
        let marker = dir.path().join(format!("gc-{}", how.len()));
        let m = format!("{:?}", marker.to_str().unwrap());
        let script = format!(
            "local o = io.open\nlocal function fin() local f = o({m}, 'a') f:write('gc\\n') f:close() getAddressList().createMemoryRecord().Description = 'from gc' end\n\
             tried = 0\n\
             local function try(f) local ok = pcall(f) if not ok then tried = tried + 1 end end\n\
             try(function() held = setmetatable({{}}, {{ __gc = fin }}) end)\n\
             local up\n\
             try(function() up = setmetatable({{}}, {{ __gc = fin }}) end)\n\
             tm = createTimer(nil) tm.OnTimer = function() return up end\n\
             try(function() local x = setmetatable({{}}, {{ __gc = fin }}) registerSymbolLookupCallback(function() return x end, slFailure) end)\n\
             try(function() local ok, t = autoAssemble('[ENABLE]\\n[DISABLE]\\n') getmetatable(t.__state).__gc = fin end)\n\
             local mt = {{}} keep = setmetatable({{}}, mt) mt.__gc = fin\n"
        );
        let file = dir.path().join("gc.json");
        heaphook::table::save(&file, &Table { lua_script: script, ..Table::default() }).unwrap();
        app.table_open(file.to_str().unwrap(), false).unwrap();
        app.table_trust(true).unwrap();
        app.table_run_script().unwrap();
        assert_eq!(app.lua_exec("assert(tried == 4, tried)").map(|_| ()), Ok(()), "{}", log_text(&app));
        let before = live_ids(&app).len();
        match how {
            "decline" => app.table_trust(false).unwrap(),
            "never" => set_never(&app, true),
            _ => {
                let empty = dir.path().join("e.json");
                heaphook::table::save(&empty, &Table::default()).unwrap();
                app.table_open(empty.to_str().unwrap(), false).unwrap();
            }
        }
        app.lua_exec("collectgarbage() collectgarbage()").unwrap();
        assert_eq!(marks(&marker), "", "{how}: a finalizer ran");
        assert_eq!(live_ids(&app).len(), if how == "open another table" { 0 } else { before }, "{how}: a finalizer made an entry");
    }
}

/// A consent answer names the table (or file) it was asked about: once another one is open,
/// it is refused and grants nothing.
#[test]
fn stale_consent_answers_are_refused() {
    let app = App::default();
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.json");
    let b = dir.path().join("b.json");
    let e = Entry { id: 1, description: "x".into(), script: Some("[ENABLE]\n[DISABLE]\n".into()), ..Entry::default() };
    heaphook::table::save(&a, &Table { entries: vec![e.clone()], lua_script: "x = 1".into(), ..Table::default() }).unwrap();
    heaphook::table::save(&b, &Table { entries: vec![e.clone()], lua_script: "y = 1".into(), ..Table::default() }).unwrap();
    let asked = app.table_open(a.to_str().unwrap(), false).unwrap().generation;
    app.table_open(b.to_str().unwrap(), false).unwrap();
    assert!(app.table_trust_at(true, asked).unwrap_err().contains("changed"));
    assert_eq!(app.table_get().unwrap().trust, heaphook::cheat::Trust::Ask);
    assert!(app.table_run_script_at(asked).unwrap_err().contains("changed"));
    let p = app.table_paste(vec![e.clone()], None, None).unwrap().ids[0];
    assert!(app.table_trust_entries_at(&[p], asked).unwrap_err().contains("changed"));
    let now = app.table_get().unwrap().generation;
    assert!(app.table_trust_entries_at(&[p, 9999], now).unwrap_err().contains("no entry"));
    assert!(app.table_get().unwrap().untrusted.contains(&p));
    app.table_trust_entries_at(&[p], now).unwrap();
    app.table_trust_at(true, now).unwrap();
    // An Auto Assemble session: consent for one load is not consent for the next.
    let f1 = dir.path().join("1.cea");
    std::fs::write(&f1, "[ENABLE]\n[DISABLE]\n").unwrap();
    let s = app.aa_session().unwrap();
    let first = app.aa_load(f1.to_str().unwrap(), s).unwrap().load;
    app.aa_load(f1.to_str().unwrap(), s).unwrap();
    assert!(app.aa_trust_at(s, first).unwrap_err().contains("changed"));
}
