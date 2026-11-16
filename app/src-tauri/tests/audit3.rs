//! Third release audit: saved dissections must never place int3 bytes off instruction
//! boundaries, pointer files are bounded, pointer sort answers cancel, launches stay owned
//! by the debugger. Live tests against children (ptrace_scope=1 only allows children).
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use heaphook::commands::{App, parse_addr};
use hh_scan::{Fmt, VType};
use serde_json::{Value, json};

const T: Duration = Duration::from_secs(10);

// ---- helpers (copied from tests/linux.rs) ----------------------------------------------------

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
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join(bin)
}

struct Target {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    info: Value,
}

impl Target {
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
    fn debug_target() -> Self {
        Self::spawn_exe(exe("hh-debug", "hh-debug-target"))
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
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tracer_pid(pid: u32) -> u32 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines().find_map(|l| l.strip_prefix("TracerPid:")).unwrap().trim().parse().unwrap()
}

fn hex(a: u64) -> String {
    format!("{a:#x}")
}

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

// ---- local helpers ---------------------------------------------------------------------------

/// The byte in the target's memory as it is (our int3s included).
fn raw_byte(pid: u32, a: u64) -> u8 {
    let mut b = [0u8];
    let p = hh_core::open(pid).unwrap();
    hh_core::Memory::read(&*p, a, &mut b).unwrap();
    b[0]
}

/// The `ticker` example, which runs without a terminal on stdin (copied from tests/linux.rs).
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

/// Rewrites the JSON metadata of a saved `.hhdis` file.
fn edit_dissection(src: &Path, dst: &Path, f: impl FnOnce(&mut Value)) {
    let b = std::fs::read(src).unwrap();
    let mlen = u64::from_le_bytes(b[16..24].try_into().unwrap()) as usize;
    let mut meta: Value = serde_json::from_slice(&b[24..24 + mlen]).unwrap();
    f(&mut meta);
    let m = serde_json::to_vec(&meta).unwrap();
    let mut out = b[..16].to_vec();
    out.extend_from_slice(&(m.len() as u64).to_le_bytes());
    out.extend_from_slice(&m);
    out.extend_from_slice(&b[24 + mlen..]);
    std::fs::write(dst, out).unwrap();
}

fn sparse(path: &Path, head: &[u8], len: u64) {
    std::fs::write(path, head).unwrap();
    std::fs::OpenOptions::new().write(true).open(path).unwrap().set_len(len).unwrap();
}

// ---- D1: saved dissections and the code filter -----------------------------------------------

#[test]
fn stale_dissection_is_rebased_and_bogus_ones_arm_nothing() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let saved = dir.path().join("run1.hhdis");
    let saved = saved.to_str().unwrap();
    let app = App::default();

    // Run 1: dissect and save.
    {
        let t1 = Target::debug_target();
        app.open_process(t1.child.id()).unwrap();
        let sum = app.dissect_run(&["hh-debug-target".into()], &Default::default()).unwrap();
        assert!(sum.validated && sum.functions > 10, "{sum:?}");
        app.dissect_save(saved).unwrap();
        app.close_process().unwrap();
    }

    // Run 2: the same program, another address layout.
    let mut t = Target::debug_target();
    let pid = t.child.id();
    app.open_process(pid).unwrap();
    let sum = app.dissect_load(saved).unwrap();
    assert!(sum.validated, "{sum:?}");
    app.debug_attach().unwrap();
    let s = app.code_filter_start().unwrap();
    assert!(s.recording && s.armed > 10, "{s:?}");
    t.send("store");
    assert!(t.line().starts_with("ok"));
    app.code_filter_stop(true).unwrap();
    let ran: Vec<String> = app.code_filter_list(0, 10_000).unwrap().rows.iter().map(|f| hex(f.addr)).collect();
    assert!(ran.contains(&t.addr("store")), "store of this run ran: {ran:?}");
    app.code_filter_reset().unwrap();

    let store = parse_addr(&t.addr("store")).unwrap();
    let load = parse_addr(&t.addr("load")).unwrap();
    let watched = [store, store + 1, load, load + 1, load + 2];
    let before: Vec<u8> = watched.iter().map(|&a| raw_byte(pid, a)).collect();

    // Every function a few bytes off, identity intact (a hostile file): only addresses that
    // still are instruction starts get an int3 (after a one-byte `push` many are), never one
    // inside an instruction, and the target keeps computing correctly.
    for by in [1u64, 2] {
        let shifted = dir.path().join("shifted.hhdis");
        edit_dissection(Path::new(saved), &shifted, |m| {
            for f in m["functions"].as_array_mut().unwrap() {
                let a = parse_addr(f["addr"].as_str().unwrap()).unwrap();
                f["addr"] = json!(hex(a + by));
            }
        });
        app.dissect_load(shifted.to_str().unwrap()).unwrap();
        if let Ok(s) = app.code_filter_start() {
            assert!(s.rejected > 0, "{s:?}");
            // `store` is `mov [rdi], rsi` (3 bytes), `load` `mov rax, [rdi]` (3 bytes).
            for a in [store + 1, store + 2, load + 1, load + 2] {
                assert_ne!(raw_byte(pid, a), 0xcc, "int3 inside an instruction at {a:#x}");
            }
            t.send("store");
            assert_eq!(t.line(), format!("ok {} 200", 101 + by));
            app.code_filter_stop(true).unwrap();
        } else {
            t.send("store");
            assert_eq!(t.line(), format!("ok {} 200", 101 + by));
        }
        app.code_filter_reset().unwrap();
    }

    // Another build at that path (fingerprint differs): its addresses are dropped.
    let other = dir.path().join("other.hhdis");
    edit_dissection(Path::new(saved), &other, |m| {
        let fp = m["module_info"][0]["fingerprint"].as_u64().unwrap();
        m["module_info"][0]["fingerprint"] = json!(fp ^ 1);
    });
    app.dissect_load(other.to_str().unwrap()).unwrap();
    assert!(app.code_filter_start().is_err());

    // A file from before module identities: browsable, never used to set breakpoints.
    let old = dir.path().join("old.hhdis");
    edit_dissection(Path::new(saved), &old, |m| {
        m.as_object_mut().unwrap().remove("module_info");
    });
    let sum = app.dissect_load(old.to_str().unwrap()).unwrap();
    assert!(!sum.validated);
    let e = app.code_filter_start().unwrap_err();
    assert!(e.contains("cannot use this dissection"), "{e}");

    app.debug_detach().unwrap();
    assert_eq!(tracer_pid(pid), 0);
    let after: Vec<u8> = watched.iter().map(|&a| raw_byte(pid, a)).collect();
    assert_eq!(before, after, "bytes changed");
    assert!(after.iter().all(|&b| b != 0xcc));
    t.send("store");
    assert!(t.line().starts_with("ok"), "target still serves");
}

// ---- F1 / F3: pointer files ------------------------------------------------------------------

#[test]
fn pointer_files_are_bounded() {
    let t = Target::debug_target();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let header = br#"{"pointer_size":8,"regions":[],"modules":[]}"#;
    let map_head = |count: u64| {
        let mut v = b"HHPMAP01".to_vec();
        v.extend_from_slice(&(header.len() as u32).to_le_bytes());
        v.extend_from_slice(header);
        v.extend_from_slice(&count.to_le_bytes());
        v
    };
    let scan = |map: &Path| {
        app.ptr_scan(&serde_json::from_value(json!({"target": "0x1000", "map_path": map.to_str().unwrap()})).unwrap()).unwrap_err()
    };
    // A sparse 64 GiB map whose header matches its length: refused by size.
    let big = dir.path().join("big.pmap");
    let count = 4u64 << 30;
    sparse(&big, &map_head(count), 20 + header.len() as u64 + count * 16);
    let e = scan(&big);
    assert!(e.contains("too big"), "{e}");
    // Within the app's file limit but over hh-ptr's pointer cap: refused before reserving.
    let count = (1u64 << 28) + 1;
    sparse(&big, &map_head(count), 20 + header.len() as u64 + count * 16);
    let e = scan(&big);
    assert!(e.contains("limit"), "{e}");
    // The comparison maps go through the same check.
    let e = app
        .ptr_scan(&serde_json::from_value(json!({"target": "0x1000", "compare": [{"path": big.to_str().unwrap(), "target": "0x10"}]})).unwrap())
        .unwrap_err();
    assert!(e.contains("limit"), "{e}");
    assert!(!app.ptr_progress().unwrap().running);
    // A result file far beyond any real one.
    let res = dir.path().join("big.ptr");
    sparse(&res, b"HHPTRS02", 65 << 30);
    let e = app.ptr_open_results(res.to_str().unwrap()).unwrap_err();
    assert!(e.contains("too big"), "{e}");
    // A huge header length inside a small enough file.
    let mut head = b"HHPTRS02".to_vec();
    head.extend_from_slice(&u32::MAX.to_le_bytes());
    sparse(&res, &head, (u32::MAX as u64) + 64);
    assert!(app.ptr_open_results(res.to_str().unwrap()).is_err());
}

// ---- F5: pointer sort answers cancel ---------------------------------------------------------

/// A v2 pointer result file of `n` one-level paths in reverse order (format in hh-ptr).
fn result_file(path: &Path, n: u64) {
    fn var(b: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            b.push(v as u8 | 0x80);
            v >>= 7;
        }
        b.push(v as u8);
    }
    let h = serde_json::to_vec(&json!({"pointer_size": 8, "max_level": 2, "target": 4096, "bases": ["a.exe"]})).unwrap();
    let mut b = b"HHPTRS02".to_vec();
    b.extend_from_slice(&(h.len() as u32).to_le_bytes());
    b.extend_from_slice(&h);
    let start = b.len();
    let mut index = Vec::new();
    for i in 0..n {
        if i % 4096 == 0 {
            index.push((b.len() - start) as u64);
        }
        var(&mut b, 1);
        var(&mut b, (n - i) << 1); // zigzag, positive
        b.push(1);
        var(&mut b, (i % 64) << 1);
    }
    let index_off = (b.len() - start) as u64;
    for o in index {
        b.extend_from_slice(&o.to_le_bytes());
    }
    b.extend_from_slice(&n.to_le_bytes());
    b.extend_from_slice(&index_off.to_le_bytes());
    std::fs::write(path, b).unwrap();
}

#[test]
fn pointer_sort_answers_cancel() {
    let t = Target::debug_target();
    let app = App::default();
    app.open_process(t.child.id()).unwrap();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("many.ptr");
    result_file(&f, 3_000_000);
    assert_eq!(app.ptr_open_results(f.to_str().unwrap()).unwrap().count, 3_000_000);
    let a2 = app.clone();
    let h = std::thread::spawn(move || a2.ptr_sort("base", 0, false, VType::Bytes4, &Fmt::default()));
    wait("the sort phase", || {
        let p = app.ptr_progress().unwrap();
        (p.phase == "sort" || h.is_finished()).then_some(())
    });
    app.ptr_cancel().unwrap();
    // 3 M paths take seconds to sort in a debug build: the cancel lands mid-sort.
    let e = h.join().unwrap().unwrap_err();
    assert!(e.contains("cancel"), "{e}");
    let p = app.ptr_progress().unwrap();
    assert!(!p.running && p.phase.is_empty(), "{p:?}");
    // The results are still there and the next operation may start.
    assert_eq!(app.ptr_results(0, 1, VType::Bytes4, &Fmt::default()).unwrap().len(), 1);
}

// ---- D4 / D5: launched children stay owned by the debugger -----------------------------------

#[test]
fn launch_is_not_raced_by_child_reaping() {
    let app = App::default();
    // Reaping hammered from another thread while the launch installs the debugger.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (a2, s2) = (app.clone(), stop.clone());
    let reaper = std::thread::spawn(move || {
        while !s2.load(std::sync::atomic::Ordering::Relaxed) {
            a2.reap_children();
        }
    });
    // A launch that fails leaves nothing behind.
    assert!(app.debug_launch(&serde_json::from_value(json!({"program": "/nonexistent/heaphook-x"})).unwrap()).is_err());
    let program = ticker();
    let info = app.debug_launch(&serde_json::from_value(json!({"program": program.to_str().unwrap(), "stop": "run"})).unwrap()).unwrap();
    struct Kill(u32);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = Command::new("kill").args(["-9", &self.0.to_string()]).status();
        }
    }
    let _k = Kill(info.pid);
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    reaper.join().unwrap();
    // Still traced by us and responsive to the debugger (no stolen stop, not a zombie).
    assert_ne!(tracer_pid(info.pid), 0);
    app.debug_pause().unwrap();
    wait("a break", || app.debug_status().ok().filter(|s| s.state == "broken"));
    app.debug_continue(false).unwrap();
    app.close_process().unwrap();
    assert_eq!(tracer_pid(info.pid), 0);
    let _ = Command::new("kill").arg(info.pid.to_string()).status();
    wait("reaped", || {
        app.reap_children();
        std::fs::read_to_string(format!("/proc/{}/stat", info.pid)).is_err().then_some(())
    });
}
