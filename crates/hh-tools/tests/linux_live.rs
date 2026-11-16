//! Live test against hh-target spawned as a child (ptrace_scope=1 only allows children).
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;

use hh_tools::Progress;
use hh_tools::structure::{ElemType, evaluate, expand_pointer, guess_structure};
use serde_json::Value;

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
        let exe = std::env::current_exe().unwrap();
        exe.parent().unwrap().parent().unwrap().join("hh-target")
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
    fn hex(v: &Value) -> u64 {
        u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }
    fn addr(&self, key: &str) -> u64 {
        Self::hex(&self.info[key])
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
fn live_hh_target() {
    let mut t = Target::spawn();
    let p = hh_core::open(t.child.id()).unwrap();
    let p = p.as_ref();
    let exe = p.modules().unwrap().into_iter().find(|m| m.name == "hh-target").expect("exe module");

    // Dissect the executable.
    let prog = Progress::new();
    let d = hh_tools::dissect::dissect(p, std::slice::from_ref(&exe), &Default::default(), &prog).unwrap();
    let s = d.summary();
    assert!(s.functions > 200 && s.instructions > 10_000, "{s:?}");
    assert!(!d.strings(Some("HeapHook"), 0, 10).is_empty(), "no HeapHook string among {:?}", d.strings(None, 0, 20));
    let main_ref = d.referenced_functions(0, 50).into_iter().find(|f| f.internal).unwrap();
    assert!(d.xref_count(main_ref.addr, main_ref.addr + 1, &[]) >= main_ref.callers as usize);
    // Save and load the dissection.
    let dir = tempfile::tempdir().unwrap();
    let dfile = dir.path().join("target.hhdis");
    d.save(&dfile, &Progress::new()).unwrap();
    let back = hh_tools::dissect::Dissection::load(&dfile, &Progress::new()).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.summary(), s);
    // Remote mode: headers from memory only.
    let hm = hh_tools::headers::summary_with(p, &exe, false).unwrap();
    assert_eq!((hm.format.as_str(), hm.source.as_str()), ("elf", "memory"));

    let h = hh_tools::headers::summary(p, &exe).unwrap();
    assert_eq!((h.format.as_str(), h.source.as_str()), ("elf", "file"));
    assert!(h.entry >= exe.base && h.entry < exe.base + exe.size);
    assert!(h.sections.iter().any(|s| s.name == ".text" && s.prot.x));
    assert!(h.imports.unwrap() > 0);

    // Unique AOB for a called function's first instruction.
    let sig = hh_tools::signature::make_signature(p, main_ref.addr, &Default::default()).unwrap();
    assert!(sig.unique, "{sig:?}");
    assert_eq!(hh_tools::signature::verify_signature(p, "hh-target", &sig.pattern, 2).unwrap(), [main_ref.addr]);

    // Structure at the static chain base; follow the chain by expanding pointer fields.
    let offsets: Vec<u64> = t.info["chain_offsets"].as_array().unwrap().iter().map(Target::hex).collect();
    let mut structs = vec![guess_structure(p, "root", t.addr("chain"), 8).unwrap()];
    let (mut name, mut base) = ("root".to_string(), t.addr("chain"));
    let mut off = 0;
    for next in offsets.iter().copied() {
        let f = evaluate(p, &structs, &name, base).unwrap();
        let pf = f.iter().find(|f| f.offset == off).unwrap();
        assert_eq!(pf.vtype, ElemType::Pointer, "{f:?}");
        (name, base) = expand_pointer(p, &mut structs, &name, pf.index, pf.addr, 32).unwrap();
        off = next;
    }
    let f = evaluate(p, &structs, &name, base).unwrap();
    assert_eq!(base + off, t.addr("chain_value"));
    assert_eq!(f.iter().find(|f| f.offset == off).unwrap().value.as_deref(), Some("4242"));

    // Save the region holding i32, change the value, load the file back.
    let a = t.addr("i32");
    let r = p.regions().unwrap().into_iter().find(|r| r.start <= a && a < r.start + r.size).unwrap();
    let file = dir.path().join("heap.hhmem");
    let range = hh_tools::memory::Range { start: r.start, size: r.size };
    let saved = hh_tools::memory::save_memory(p, &[range], &file, &Progress::new()).unwrap();
    assert_eq!(saved.bytes, r.size);
    p.write(a, &999i32.to_le_bytes()).unwrap();
    // Check through memory: a command would let the target allocate, and restoring a whole
    // heap region over newer allocator state is not safe.
    let mut v = [0u8; 4];
    p.read_exact(a, &mut v).unwrap();
    assert_eq!(i32::from_le_bytes(v), 999);
    // Plan first: the region is mapped and writable, nothing written yet.
    let plan = hh_tools::memory::plan_load(p, &file, None).unwrap();
    assert_eq!(plan.bytes, r.size);
    assert!(plan.blocks.iter().all(|b| b.mapped && b.writable), "{plan:?}");
    p.read_exact(a, &mut v).unwrap();
    assert_eq!(i32::from_le_bytes(v), 999);
    let back = hh_tools::memory::load_memory_approved(p, &file, None, &plan.blocks).unwrap();
    assert!(back.failed.is_empty());
    assert_eq!(back.bytes, r.size);
    assert_eq!(t.cmd("get")["i32"], 123456);

    // Find what points at the chain's first heap object: the static base.
    let l1 = p.read_ptr(t.addr("chain")).unwrap();
    let q = hh_tools::memory::PointerQuery { target: l1, static_only: true, ..Default::default() };
    let hits = hh_tools::memory::find_pointers(p, &q, &Progress::new()).unwrap();
    assert!(hits.iter().any(|h| h.addr == t.addr("chain") && h.module.as_deref().is_some_and(|m| m.starts_with("hh-target+"))));

    let regs = hh_tools::memory::regions(p).unwrap();
    assert!(regs.iter().any(|r| r.tag == hh_tools::memory::RegionTag::Stack));
}

/// Real-code throughput: dissects this test binary and libc in its own process.
#[test]
#[ignore]
fn bench_dissect_real_modules() {
    let p = hh_core::open(std::process::id()).unwrap();
    let mods: Vec<_> = p
        .modules()
        .unwrap()
        .into_iter()
        .filter(|m| m.name.starts_with("libc.so") || m.path == std::env::current_exe().unwrap().to_string_lossy())
        .collect();
    let t = std::time::Instant::now();
    let d = hh_tools::dissect::dissect(p.as_ref(), &mods, &Default::default(), &Progress::new()).unwrap();
    let secs = t.elapsed().as_secs_f64();
    let s = d.summary();
    let mib = s.code_bytes as f64 / (1 << 20) as f64;
    println!(
        "dissect {:?}: {mib:.1} MiB code in {secs:.2}s = {:.0} MiB/s ({} functions, {} refs, {} strings)",
        s.modules,
        mib / secs,
        s.functions,
        s.refs,
        s.strings
    );
}
