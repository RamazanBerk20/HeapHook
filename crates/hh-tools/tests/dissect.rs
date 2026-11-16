mod common;
use common::*;
use hh_core::RegionKind;
use hh_tools::Progress;
use hh_tools::dissect::*;

fn u16b(p: &FakeProc, a: u64, v: u16) {
    p.put(a, &v.to_le_bytes());
}
fn u32b(p: &FakeProc, a: u64, v: u32) {
    p.put(a, &v.to_le_bytes());
}

/// A PE-like module "test.dll" at 0x400000: headers, .text with four functions and a cave,
/// .rdata with strings and a call slot.
fn module() -> (FakeProc, Vec<u64>, Vec<u64>) {
    let mut p = FakeProc::new();
    p.add(0x400000, vec![0; 0x1000], R, RegionKind::Image, Some("/x/test.dll"));
    p.add(0x401000, vec![0xC3; 0x1000], RX, RegionKind::Image, Some("/x/test.dll"));
    p.add(0x402000, vec![0; 0x1000], R, RegionKind::Image, Some("/x/test.dll"));
    p.module("test.dll", 0x400000, 0x3000);
    // PE headers.
    p.put(0x400000, b"MZ");
    u32b(&p, 0x40003C, 0x80);
    p.put(0x400080, b"PE\0\0");
    u16b(&p, 0x400084, 0x8664);
    u16b(&p, 0x400086, 2);
    u16b(&p, 0x400094, 0xF0);
    u16b(&p, 0x400096, 0x2022);
    u16b(&p, 0x400098, 0x20b);
    u32b(&p, 0x4000A8, 0x1000);
    p.put_u64(0x4000B0, 0x400000);
    u32b(&p, 0x400104, 16);
    u32b(&p, 0x400108, 0x2300);
    u32b(&p, 0x40010C, 0x28);
    u32b(&p, 0x400110, 0x2400);
    u32b(&p, 0x400114, 0x28);
    p.put(0x400188, b".text\0\0\0");
    u32b(&p, 0x400190, 0x1000);
    u32b(&p, 0x400194, 0x1000);
    u32b(&p, 0x4001AC, 0x6000_0020);
    p.put(0x4001B0, b".rdata\0\0");
    u32b(&p, 0x4001B8, 0x1000);
    u32b(&p, 0x4001BC, 0x2000);
    u32b(&p, 0x4001D4, 0x4000_0040);
    u32b(&p, 0x402314, 3);
    u32b(&p, 0x402400, 0x2500);
    u32b(&p, 0x40240C, 0x2600);
    p.put_u64(0x402500, 0x2700);
    p.put_u64(0x402508, 0x2710);
    // Data.
    p.put(0x402000, b"Hello dissect\0");
    let w: Vec<u8> = "Wide str\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    p.put(0x402020, &w);
    p.put_u64(0x402100, 0x401300);
    u32b(&p, 0x402200, 5);
    // Code.
    let main = asm_seq(
        &p,
        0x401000,
        &["call 401100", "call 401100", "call 401200", "lea rcx,[402000]", "call qword ptr [402100]", "ret"],
    );
    let f1 = asm_seq(&p, 0x401100, &["lea rdx,[402020]", "call 401200", "ret"]);
    asm_seq(&p, 0x401200, &["mov eax,dword ptr [402200]", "ret"]);
    asm_seq(&p, 0x401300, &["ret"]);
    p.put(0x401400, &[0xCC; 64]);
    (p, main, f1)
}

#[test]
fn dissect_synthetic_module() {
    let (p, main, f1) = module();
    let mods = p.modules.clone();
    let prog = Progress::new();
    let d = dissect(&p, &mods, &DissectOptions::default(), &prog).unwrap();
    let s = d.summary();
    assert_eq!(s.code_bytes, 0x1000);
    assert_eq!(prog.snapshot().done, 0x1000);
    let f: Vec<_> = d.functions(0, 100).iter().map(|f| (f.addr, f.callers, f.internal)).collect();
    assert_eq!(f, [(0x401000, 0, true), (0x401100, 2, true), (0x401200, 2, true), (0x401300, 1, true)]);
    let rf = d.referenced_functions(0, 10);
    assert_eq!(rf.len(), 3);
    assert_eq!(rf[2].addr, 0x401300);
    assert_eq!(d.functions(1, 1)[0].addr, 0x401100);
    assert_eq!(d.function_at(0x401105).unwrap().addr, 0x401100);

    let x = d.xrefs_to(0x401200, 0x401201, &[RefKind::Call], 0, 10);
    assert_eq!(x.iter().map(|x| x.from).collect::<Vec<_>>(), [main[2], f1[1]]);
    assert_eq!(d.xref_count(0x401100, 0x401101, &[]), 2);
    // Data references: the call slot and the dword global, by range.
    let slot = d.xrefs_to(0x402100, 0x402101, &[RefKind::Data], 0, 10);
    assert_eq!(slot.iter().map(|x| x.from).collect::<Vec<_>>(), [main[4]]);
    assert_eq!(d.xrefs_to(0x402000, 0x403000, &[RefKind::Data], 0, 10).len(), 4);
    assert_eq!(d.xrefs_to(0x402000, 0x403000, &[RefKind::Data], 1, 2).len(), 2);

    let st = d.strings(None, 0, 10);
    let got: Vec<_> = st.iter().map(|s| (s.addr, s.text.as_str(), s.utf16, s.refs)).collect();
    assert_eq!(got, [(0x402000, "Hello dissect", false, 1), (0x402020, "Wide str", true, 1)]);
    assert_eq!(d.strings(Some("WIDE"), 0, 10).len(), 1);
    assert_eq!(d.xrefs_to(st[1].addr, st[1].addr + 1, &[], 0, 10)[0].from, f1[0]);

    let caves = d.caves(0, 10);
    assert_eq!(caves.len(), 1);
    assert_eq!((caves[0].addr, caves[0].len, caves[0].byte), (0x401400, 64, 0xCC));
    let c = find_code_caves(&p, 0x400000, 0x403000, 32, &Progress::new()).unwrap();
    assert_eq!(c, caves);
    assert!(find_code_caves(&p, 5, 5, 32, &Progress::new()).is_err());

    let json = serde_json::to_value(x[0]).unwrap();
    assert_eq!(json["kind"], "call");
    assert_eq!(json["to"], "0x401200");

    let c = Progress::new();
    c.cancel();
    assert!(dissect(&p, &mods, &DissectOptions::default(), &c).is_err());
    // Linear only still finds the direct calls.
    let lin = dissect(&p, &mods, &DissectOptions { recursive: false, ..Default::default() }, &Progress::new()).unwrap();
    assert_eq!(lin.summary().functions, 4);
}

#[test]
fn pe_header_summary() {
    let (p, _, _) = module();
    let h = hh_tools::headers::summary(&p, &p.modules[0]).unwrap();
    assert_eq!((h.format.as_str(), h.machine.as_str(), h.kind.as_str()), ("pe", "x86_64", "dll"));
    assert!(h.is_64);
    assert_eq!((h.entry, h.image_base), (0x401000, 0x400000));
    assert_eq!((h.imports, h.import_libs, h.exports), (Some(2), Some(1), Some(3)));
    assert_eq!(h.sections.len(), 2);
    assert_eq!((h.sections[0].name.as_str(), h.sections[0].addr, h.sections[0].prot.x), (".text", 0x401000, true));
    assert!(!h.sections[1].prot.x);
    // Garbage instead of a header is an error, not a panic.
    p.put(0x400000, b"XX");
    assert!(hh_tools::headers::summary(&p, &p.modules[0]).is_err());
    p.put(0x400000, b"MZ");
    u32b(&p, 0x40003C, 0xFFFF_FFF0);
    assert!(hh_tools::headers::summary(&p, &p.modules[0]).is_err());
}

#[test]
fn signature_unique() {
    use hh_tools::signature::*;
    let (p, main, _) = module();
    let s = make_signature(&p, main[1], &SigOptions::default()).unwrap();
    assert!(s.unique, "{s:?}");
    assert!(s.pattern.starts_with("E8 ?? ?? ?? ?? E8 ?? ?? ?? ??"), "{}", s.pattern);
    assert_eq!(s.module_offset, main[1] - 0x400000);
    assert_eq!(verify_signature(&p, "test.dll", &s.pattern, 5).unwrap(), [main[1]]);
    // The lea's RIP-relative displacement is wildcarded.
    let s = make_signature(&p, main[3], &SigOptions::default()).unwrap();
    assert!(s.pattern.starts_with("48 8D 0D ?? ?? ?? ??"), "{}", s.pattern);
    assert!(make_signature(&p, 0x900000, &SigOptions::default()).is_err());
    // Not unique within the length limit: repeated filler.
    let s = make_signature(&p, 0x401800, &SigOptions { max_len: 8 }).unwrap();
    assert!(!s.unique);
}

#[test]
#[ignore]
fn bench_dissect() {
    use hh_core::Memory;
    // A realistic instruction mix: repeat a decoded stream of common instructions.
    let lines = [
        "push rbx", "mov rax,qword ptr [rbx+rcx*8+100]", "lea rcx,[402000]", "call 401100",
        "mov dword ptr [rsp+20],eax", "test eax,eax", "je 401000", "add rsp,28", "movss xmm0,dword ptr [402200]",
        "cmp qword ptr [rax+18],0", "jne 401000", "call qword ptr [402100]", "pop rbx", "ret",
    ];
    let mut q = FakeProc::new();
    const SIZE: usize = 32 << 20;
    q.add(0x400000, vec![0; 0x1000], R, RegionKind::Image, None);
    q.add(0x401000, vec![0; SIZE], RX, RegionKind::Image, None);
    q.add(0x401000 + SIZE as u64, vec![0; 0x1000], R, RegionKind::Image, None);
    q.module("big.dll", 0x400000, SIZE as u64 + 0x2000);
    let addrs = asm_seq(&q, 0x401000, &lines);
    let len = (addrs[addrs.len() - 1] - 0x401000 + 1) as usize;
    let mut unit = vec![0u8; len];
    q.read(0x401000, &mut unit).unwrap();
    let code: Vec<u8> = unit.iter().copied().cycle().take(SIZE).collect();
    q.put(0x401000, &code);
    let t = std::time::Instant::now();
    let d = dissect(&q, &q.modules.clone(), &DissectOptions::default(), &Progress::new()).unwrap();
    let secs = t.elapsed().as_secs_f64();
    let s = d.summary();
    println!(
        "dissect: {} MiB in {secs:.2}s = {:.0} MiB/s ({} instructions, {} refs, {} functions)",
        SIZE >> 20,
        (SIZE >> 20) as f64 / secs,
        s.instructions,
        s.refs,
        s.functions
    );
}
