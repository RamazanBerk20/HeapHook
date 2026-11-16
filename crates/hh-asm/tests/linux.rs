//! Live tests against hh-target spawned as a child (ptrace_scope=1 only allows children).
#![cfg(target_os = "linux")]
use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use hh_asm::*;
use hh_core::{Module, Process, RegionKind};

fn target_exe() -> &'static PathBuf {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        // This test binary lives in <target>/<profile>/deps/; build hh-target to match.
        let dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
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
    })
}

struct Target(Child);

impl Target {
    fn spawn() -> Self {
        let mut child = Command::new(target_exe())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // The first line means it is up and initialised.
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        Target(child)
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn module<'m>(mods: &'m [Module], prefix: &str) -> &'m Module {
    mods.iter()
        .find(|m| m.name.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix} in {mods:?}"))
}

#[test]
fn live_symbols_disassembly_and_script() {
    let t = Target::spawn();
    let p = hh_core::open(t.0.id()).unwrap();
    let p: &dyn Process = &*p;
    let mods = p.modules().unwrap();
    let exe = module(&mods, "hh-target");
    let libc = module(&mods, "libc.so");
    let syms = SymbolTable::default();
    let r = |e: &str| resolve_address(p, &syms, e).unwrap_or_else(|x| panic!("{e}: {x}"));

    // 1. Dashed module name, unquoted.
    assert_eq!(r("hh-target+10"), exe.base + 0x10);
    assert_eq!(r("hh-target+100-8"), exe.base + 0xF8);

    // 2. libc export by plain and qualified name; memory fallback agrees with the file.
    let malloc = r("malloc");
    assert!(malloc >= libc.base && malloc < libc.base + libc.size);
    assert_eq!(r(&format!("{}.malloc", libc.name)), malloc);
    assert_eq!(r("libc.malloc+10"), malloc + 0x10, "module stem works too");
    let fake = Module {
        path: "/nonexistent/for/hh-asm/test".into(),
        ..libc.clone()
    };
    let from_mem = module_symbols(p, &fake);
    assert!(
        from_mem
            .iter()
            .any(|s| s.name == "malloc" && s.addr == malloc),
        "memory fallback: {} symbols",
        from_mem.len()
    );
    let l = disassemble(p, &syms, malloc, 8).unwrap();
    assert!(l.iter().all(|x| x.text != "??"), "{l:?}");
    assert_eq!(
        symbol_at(p, &syms, malloc).unwrap(),
        format!("{}.malloc", libc.name)
    );

    // 2b. Rust symbols are shown demangled; both forms read back.
    let rust = module_symbols(p, exe)
        .into_iter()
        .find(|s| s.name.starts_with("_RNvNtCs") && s.name.contains("lang_start_internal"))
        .expect("a mangled Rust symbol in hh-target");
    let shown = symbol_at(p, &syms, rust.addr).unwrap();
    assert!(
        !shown.contains("_RNv") && shown.contains("std::rt::lang_start_internal"),
        "{shown}"
    );
    assert_eq!(r(&shown), rust.addr, "{shown}");
    assert_eq!(r(&format!("{shown}+4")), rust.addr + 4, "{shown}");
    assert_eq!(r(&format!("{}.{}", exe.name, rust.name)), rust.addr);

    // 3. Some call/jmp in the executable is annotated with a libc symbol.
    let code: Vec<_> = p
        .regions()
        .unwrap()
        .into_iter()
        .filter(|g| g.kind == RegionKind::Image && g.prot.x && g.path.as_deref() == Some(&exe.path))
        .collect();
    let (mut n, mut hits) = (0usize, Vec::new());
    let t0 = std::time::Instant::now();
    for g in &code {
        for line in disassemble(p, &syms, g.start, g.size as usize / 3).unwrap() {
            n += 1;
            if line.addr < g.start + g.size && line.comment.contains(&format!("{}.", libc.name)) {
                hits.push(format!("{} ; {}", line.text, line.comment));
            }
        }
    }
    println!(
        "live: {n} instructions in {:.3}s, {} libc-annotated, e.g. {:?}",
        t0.elapsed().as_secs_f64(),
        hits.len(),
        hits.first()
    );
    assert!(!hits.is_empty(), "no libc symbol in any call/jmp comment");

    // 4. Auto Assembler: alloc near the module, write, register, disable restores.
    let mut syms = SymbolTable::default();
    let mut orig = [0u8; 8];
    p.read_exact(exe.base + 8, &mut orig).unwrap();
    let script = "[ENABLE]\nalloc(newmem,$1000,hh-target)\nlabel(val)\nregistersymbol(val)\nnewmem:\n  mov eax,[val]\n  call malloc\n  jmp hh-target+10\nval:\n  dd 12345678\nhh-target+8:\n  db 90 90 90 90\n[DISABLE]\nhh-target+8:\n  readmem(val,0)\nunregistersymbol(val)\ndealloc(newmem)\n";
    let script = script.replace(
        "  readmem(val,0)\n",
        &format!("  db {}\n", hexs(&orig[..4])),
    );
    assert_eq!(aa_check(p, &syms, &script, &mut AaHooks::default()), None);
    let st = aa_execute(p, &mut syms, &script, true, None, &mut AaHooks::default()).unwrap();
    let newmem = st.allocs[0].addr;
    assert!(
        newmem.abs_diff(exe.base) < 0x8000_0000,
        "alloc near the module"
    );
    let mut b = [0u8; 4];
    p.read_exact(exe.base + 8, &mut b).unwrap();
    assert_eq!(b, [0x90; 4]);
    let val = syms.get("val").unwrap();
    p.read_exact(val, &mut b).unwrap();
    assert_eq!(u32::from_le_bytes(b), 0x12345678);
    let l = disassemble(p, &syms, newmem, 3).unwrap();
    // libc is usually beyond rel32 range: the call goes through an inline pointer.
    assert!(
        l[1].comment.ends_with(&format!("{}.malloc", libc.name)),
        "{l:?}"
    );
    aa_execute(
        p,
        &mut syms,
        &script,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    let mut now = [0u8; 8];
    p.read_exact(exe.base + 8, &mut now).unwrap();
    assert_eq!(now, orig);
    assert_eq!(syms.get("val"), None);
    assert!(p.read_exact(newmem, &mut b).is_err(), "allocation freed");
}

fn hexs(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
