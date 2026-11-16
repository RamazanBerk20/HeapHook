//! Region-restricted scans against the real hh-target, spawned as a child (ptrace_scope=1).
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use hh_core::RegionKind;
use hh_scan::*;
use serde_json::Value;

fn target_exe() -> PathBuf {
    // This test binary lives in <target>/<profile>/deps/; build hh-target to match.
    let dir = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
    let mut args = vec!["build", "-q", "-p", "hh-target"];
    if dir.ends_with("release") {
        args.push("--release");
    }
    let ok = Command::new(env!("CARGO")).args(&args).current_dir(env!("CARGO_MANIFEST_DIR")).status().expect("run cargo").success();
    assert!(ok, "cargo build -p hh-target failed");
    dir.join("hh-target")
}

struct Target(Child, Value);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn() -> Target {
    let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    Target(child, serde_json::from_str(&line).unwrap())
}

fn addr(t: &Target, key: &str) -> u64 {
    u64::from_str_radix(t.1[key].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn module_restricted_scans_of_hh_target() {
    let t = spawn();
    let p = hh_core::open(t.0.id()).unwrap();
    let exe = p.modules().unwrap().into_iter().find(|m| m.name == "hh-target").expect("exe module");
    let in_exe = |a: u64| (exe.base..exe.base + exe.size).contains(&a);
    let s = Scanner::new(p.clone());
    let rows = |s: &Scanner| s.results(0, 100_000).unwrap().into_iter().map(|r| r.addr).collect::<Vec<_>>();

    // The values live on the heap: found among private memory, not inside the exe.
    let i32_at = addr(&t, "i32");
    let exact = |o: ScanOptions| FirstScan { vtype: VType::Bytes4, scan_type: ScanType::Exact, value: Some("123456".into()), value2: None, not: false, opts: o };
    s.first_scan(&exact(ScanOptions { kinds: vec![RegionKind::Private], ..ScanOptions::default() })).unwrap();
    assert!(rows(&s).contains(&i32_at));
    s.first_scan(&exact(ScanOptions { modules: vec!["hh-target".into()], ..ScanOptions::default() })).unwrap();
    assert!(rows(&s).iter().all(|&a| in_exe(a)) && !rows(&s).contains(&i32_at));
    s.first_scan(&exact(ScanOptions { exclude_modules: vec!["hh-target".into()], ..ScanOptions::default() })).unwrap();
    assert!(rows(&s).contains(&i32_at) && !rows(&s).iter().any(|&a| in_exe(a)));

    // Pointers stored inside the exe (GOT, statics), and the chain's static base pointer.
    let n = s.pointer_scan(&PointerScan { opts: ScanOptions { modules: vec!["hh-target".into()], ..ScanOptions::default() }, ..PointerScan::default() }).unwrap();
    assert!(n.count > 0 && rows(&s).iter().all(|&a| in_exe(a)));
    let chain = addr(&t, "chain");
    let l1 = p.read_ptr(chain).unwrap();
    let to_l1 = PointerScan { ranges: vec![AddrRange { start: l1, end: l1 + 1 }], ..PointerScan::default() };
    s.pointer_scan(&to_l1).unwrap();
    assert!(rows(&s).contains(&chain), "the chain base points at its first hop");
    if in_exe(chain) {
        s.pointer_scan(&PointerScan { opts: ScanOptions { modules: vec!["hh-target".into()], ..ScanOptions::default() }, ..to_l1 }).unwrap();
        assert_eq!(rows(&s), [chain]);
    } else {
        eprintln!("chain base {chain:#x} is in .bss outside the exe's file mappings");
    }
}
