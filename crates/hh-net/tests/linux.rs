//! End to end: the real hh_core backend served over loopback, hh-target as a child process
//! (ptrace_scope=1 only allows children), and hh-scan running through `RemoteProcess`.
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, OnceLock};

use hh_core::{Error, Prot};
use hh_net::{LocalBackend, Server, ServerConfig, connect};
use hh_scan::{FirstScan, NextScan, ScanOptions, ScanType, Scanner, VType};
use serde_json::Value;

/// Builds hh-target once per test binary and returns its path.
fn target_exe() -> &'static PathBuf {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let ok = Command::new(env!("CARGO"))
            .args(["build", "-q", "-p", "hh-target"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("run cargo")
            .success();
        assert!(ok, "cargo build -p hh-target failed");
        // This test binary lives in <target>/<profile>/deps/.
        let dir = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
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
        let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let info = serde_json::from_str(&line).unwrap();
        Target { child, stdin, stdout, info }
    }
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn addr(&self, key: &str) -> u64 {
        u64::from_str_radix(self.info[key].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
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
fn remote_target_end_to_end() {
    let mut t = Target::spawn();
    let server = Server::bind("127.0.0.1:0", ServerConfig::new("tok"), Arc::new(LocalBackend)).unwrap().spawn().unwrap();
    let host = connect(server.addr(), "tok").unwrap();

    let procs = host.list_processes().unwrap();
    let me = procs.iter().find(|p| p.pid == t.pid()).expect("target listed");
    assert_eq!(me.name, "hh-target");
    assert_eq!(PathBuf::from(me.exe.as_ref().unwrap()), *target_exe());

    let p = host.open(t.pid()).unwrap();
    assert_eq!((p.pid(), p.pointer_size()), (t.pid(), 8));
    assert!(p.is_alive());
    assert_eq!(p.threads().unwrap().len(), 2);

    // Known values.
    let mut b4 = [0u8; 4];
    let mut b8 = [0u8; 8];
    p.read_exact(t.addr("i32"), &mut b4).unwrap();
    assert_eq!(i32::from_le_bytes(b4), 123456);
    p.read_exact(t.addr("f64"), &mut b8).unwrap();
    assert_eq!(f64::from_le_bytes(b8), 2.25);
    let mut s = [0u8; 20];
    p.read_exact(t.addr("str"), &mut s).unwrap();
    assert_eq!(&s, b"HeapHook test string");
    p.read_exact(t.addr("aob"), &mut b8).unwrap();
    assert_eq!(b8, [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE]);
    assert!(matches!(p.read(8, &mut b8), Err(Error::NoAccess { addr: 8 })));

    // Write, confirmed by the target itself.
    p.write(t.addr("i32"), &(-7i32).to_le_bytes()).unwrap();
    assert_eq!(t.cmd("get")["i32"], -7);
    p.write(t.addr("i32"), &123456i32.to_le_bytes()).unwrap();

    // Regions and modules.
    let regions = p.regions().unwrap();
    assert!(regions.iter().any(|r| r.start <= t.addr("i32") && t.addr("i32") < r.start + r.size && r.prot.w));
    assert!(regions.iter().any(|r| r.path.as_deref() == Some("[stack]")));
    let mods = p.modules().unwrap();
    let exe = mods.iter().find(|m| m.name == "hh-target").expect("exe module");

    // Alloc / protect / free.
    let rw = Prot { r: true, w: true, x: false };
    let a = p.alloc(100, rw, Some(exe.base)).unwrap();
    assert!(a.abs_diff(exe.base) < 1 << 31);
    p.write(a, b"hello").unwrap();
    let mut b5 = [0u8; 5];
    p.read_exact(a, &mut b5).unwrap();
    assert_eq!(&b5, b"hello");
    assert_eq!(p.protect(a, 4096, Prot { r: true, w: false, x: true }).unwrap(), rw);
    p.free(a, 4096).unwrap();
    assert!(p.read(a, &mut b5).is_err());
    assert_eq!(t.cmd("get")["i32"], 123456);

    // Suspend / resume.
    p.suspend().unwrap();
    assert_eq!(state(t.pid()), 'T');
    writeln!(t.stdin, "inc").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    p.read_exact(t.addr("i32"), &mut b4).unwrap();
    assert_eq!(i32::from_le_bytes(b4), 123456, "stopped target must not run");
    p.resume().unwrap();
    let mut line = String::new();
    t.stdout.read_line(&mut line).unwrap();
    assert!(line.contains(r#""i32":123457"#), "{line}");

    // hh-scan through the remote process: first scan, change, next scan.
    let scanner = Scanner::new(p.clone());
    let first = FirstScan { vtype: VType::Bytes4, scan_type: ScanType::Exact, value: Some("123457".into()), value2: None, not: false, opts: ScanOptions::default() };
    let n1 = scanner.first_scan(&first).unwrap().count;
    assert!(n1 >= 1);
    assert_eq!(t.cmd("inc")["i32"], 123458);
    let next = NextScan { scan_type: ScanType::Exact, value: Some("123458".into()), value2: None, not: false, percent: None };
    let n2 = scanner.next_scan(&next).unwrap().count;
    assert!(n2 >= 1 && n2 <= n1, "{n1} -> {n2}");
    let rows = scanner.results(0, 1000).unwrap();
    assert!(rows.iter().any(|r| r.addr == t.addr("i32") && r.value.as_deref() == Some("123458")), "{rows:?}");

    // The target exits: the remote process reports it.
    writeln!(t.stdin, "quit").unwrap();
    t.child.wait().unwrap();
    assert!(!p.is_alive());
    assert!(matches!(p.read(t.addr("i32"), &mut b4), Err(Error::ProcessGone)));
}
