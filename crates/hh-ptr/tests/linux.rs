//! Pointer scan against the real hh-target, spawned as a child (ptrace_scope=1).
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};

use hh_ptr::{
    CollectOptions, PointerMap, PointerPath, Progress, RescanOptions, ScanOptions, Source,
    thread_stacks,
};
use serde_json::Value;

fn target_exe() -> PathBuf {
    // This test binary lives in <target>/<profile>/deps/; build hh-target to match.
    let dir = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
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
}

struct Target {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
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

#[test]
fn rediscovers_hh_target_chain() {
    let mut t = Target::spawn();
    let p = hh_core::open(t.child.id()).unwrap();
    let (chain, value) = (t.addr("chain"), t.addr("chain_value"));
    let offs: Vec<i64> = t.info["chain_offsets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| i64::from_str_radix(o.as_str().unwrap().trim_start_matches("0x"), 16).unwrap())
        .collect();

    let map = PointerMap::collect(&*p, &CollectOptions::default(), &Progress::new()).unwrap();
    assert_eq!(map.read_ptr(chain), Some(p.read_ptr(chain).unwrap()));
    let o = ScanOptions {
        max_level: 4,
        max_offset: 0x100,
        stack_max: 0x10000,
        ..Default::default()
    };
    let tmp =
        |n: &str| std::env::temp_dir().join(format!("hh-ptr-live-{}-{n}", std::process::id()));
    let r = map
        .scan(value, &o, &[], &tmp("scan"), &Progress::new())
        .unwrap();
    let paths = r.read(0, r.len() as usize).unwrap();
    eprintln!("{} paths to the hh-target chain value", paths.len());
    let rows = r.results(0, 1000, Some(&*p)).unwrap();
    assert!(
        rows.iter().all(|row| row.address == Some(value)),
        "every path resolves"
    );

    // The planted chain must come back, ending with its offsets. When its base pointer is
    // in the exe's static data the whole path is module-relative; while hh-target keeps it
    // on the heap, the base is the main thread's stack (a local holds it).
    let exe = map.modules.iter().find(|m| m.name == "hh-target").unwrap();
    if (exe.base..exe.base + exe.size).contains(&chain) {
        let want = PointerPath {
            module: Some("hh-target".into()),
            base_offset: (chain - exe.base) as i64,
            offsets: offs.clone(),
        };
        assert!(paths.contains(&want), "missing {want}");
    } else {
        let hit = paths
            .iter()
            .find(|p| {
                p.offsets.ends_with(&offs)
                    && p.module
                        .as_deref()
                        .is_some_and(|m| m == "hh-target" || m == "THREADSTACK0")
            })
            .expect("chain rediscovered");
        eprintln!("chain base is on the heap; found {hit}");
    }

    // The target keeps running; rescan the live process for the incremented value.
    assert_eq!(t.cmd("inc")["chain_value"], 4243);
    let ro = RescanOptions {
        target: Some(value),
        value: Some(4243i32.to_le_bytes().to_vec()),
        ends_with: offs.clone(),
        ..Default::default()
    };
    let r2 = r
        .rescan(Source::Process(&*p), &ro, &tmp("rescan"), &Progress::new())
        .unwrap();
    assert!(!r2.is_empty());
    for path in r2.read(0, 100).unwrap() {
        assert_eq!(hh_ptr::resolve(&*p, &path).unwrap(), value);
    }
    std::fs::remove_file(tmp("scan")).ok();
    std::fs::remove_file(tmp("rescan")).ok();
}

#[test]
fn paused_and_resumed_scan_of_hh_target() {
    let t = Target::spawn();
    let p = hh_core::open(t.child.id()).unwrap();
    let (chain, value) = (t.addr("chain"), t.addr("chain_value"));

    // hh-target has an idle second thread, parked in a futex wait: its stack is found
    // from /proc/<pid>/task/<tid>/syscall (we are its parent, so ptrace access is allowed).
    let stacks = thread_stacks(&*p, true).unwrap();
    assert_eq!(thread_stacks(&*p, false).unwrap().len(), 1, "only [stack] is tagged");
    assert!(stacks.len() >= 2, "{stacks:x?}");
    let map = PointerMap::collect_ex(&*p, &CollectOptions::default(), true, &Progress::new()).unwrap();
    assert_eq!(map.stack_ranges(), stacks);

    let o = ScanOptions { max_level: 4, max_offset: 0x100, stack_max: 0x10000, ..Default::default() };
    let out = std::env::temp_dir().join(format!("hh-ptr-live-{}-paused", std::process::id()));
    let prog = Progress::new();
    prog.pause();
    let r = std::thread::scope(|s| {
        let h = s.spawn(|| map.scan(value, &o, &[], &out, &prog));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!h.is_finished() && prog.snapshot().paused && prog.snapshot().found == 0);
        prog.resume();
        h.join().unwrap().unwrap()
    });
    assert!(r.is_compact() && !r.is_empty());
    let rows = r.results_ex(0, 1000, Some(&*p), true).unwrap();
    assert!(rows.iter().all(|row| row.address == Some(value)), "every path resolves");
    let exe = map.modules.iter().find(|m| m.name == "hh-target").unwrap();
    if (exe.base..exe.base + exe.size).contains(&chain) {
        let paths = r.read(0, r.len() as usize).unwrap();
        assert!(paths.iter().any(|p| p.module.as_deref() == Some("hh-target") && p.base_offset == (chain - exe.base) as i64));
    }
    std::fs::remove_file(out).ok();
}
