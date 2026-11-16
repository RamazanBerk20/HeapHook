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

// ---------------------------------------------------------------- 1.0: save/load, merge, filter

#[test]
fn constant_slots_resolve_indirect_calls() {
    let (mut p, _, _) = module();
    // A writable data page inside the module: its slots are not constant.
    p.add(0x403000, vec![0; 0x1000], RW, RegionKind::Image, Some("/x/test.dll"));
    p.modules[0].size = 0x4000;
    asm_seq(&p, 0x401500, &["jmp qword ptr [402108]"]);
    p.put_u64(0x402108, 0x401600);
    p.put_u64(0x402110, 0x401650);
    p.put_u64(0x403000, 0x401680);
    let site = asm_seq(&p, 0x401700, &["call 401500", "mov rax,qword ptr [402110]", "call rax", "mov rbx,qword ptr [403000]", "call rbx", "ret"]);
    let d = dissect(&p, &p.modules.clone(), &DissectOptions::default(), &Progress::new()).unwrap();
    let callers = |a: u64| d.xrefs_to(a, a + 1, &[RefKind::Call], 0, 10).iter().map(|x| x.from).collect::<Vec<_>>();
    // Through the thunk: the caller of the thunk also calls its target.
    assert_eq!(callers(0x401500), [site[0]]);
    assert_eq!(callers(0x401600), [site[0]]);
    // mov reg,[constant slot]; call reg.
    assert_eq!(callers(0x401650), [site[2]]);
    // A writable slot may change: not resolved.
    assert!(callers(0x401680).is_empty());
}

fn second_module(p: &mut FakeProc) -> Vec<u64> {
    p.add(0x700000, vec![0xC3; 0x1000], RX, RegionKind::Image, Some("/x/two.dll"));
    p.module("two.dll", 0x700000, 0x1000);
    let a = asm_seq(p, 0x700000, &["call 401300", "call 700100", "ret"]);
    asm_seq(p, 0x700100, &["ret"]);
    a
}

#[test]
fn add_module_matches_dissecting_both() {
    let (mut p, _, _) = module();
    second_module(&mut p);
    let opts = DissectOptions::default();
    let mut d = dissect(&p, &p.modules[..1], &opts, &Progress::new()).unwrap();
    let s = d.add_modules(&p, &p.modules.clone(), &opts, &Progress::new()).unwrap();
    assert_eq!(s.modules, ["test.dll", "two.dll"]);
    let both = dissect(&p, &p.modules.clone(), &opts, &Progress::new()).unwrap();
    assert_eq!(s, both.summary());
    assert_eq!(d.functions(0, 100), both.functions(0, 100));
    assert_eq!(d.referenced_functions(0, 100), both.referenced_functions(0, 100));
    assert_eq!(d.xrefs_to(0, u64::MAX, &[], 0, 1000), both.xrefs_to(0, u64::MAX, &[], 0, 1000));
    assert_eq!(d.function_at(0x401300).unwrap().callers, 2);
    // Adding known modules again changes nothing.
    let again = d.add_modules(&p, &p.modules.clone(), &opts, &Progress::new()).unwrap();
    assert_eq!(again, s);
}

#[test]
fn code_filter_from_recorded_sets() {
    let (p, main, f1) = module();
    let d = dissect(&p, &p.modules.clone(), &DissectOptions::default(), &Progress::new()).unwrap();
    let ran = [vec![main[1], f1[1] + 1], vec![f1[0], 0x401201]];
    let addrs = |v: Vec<Function>| v.iter().map(|f| f.addr).collect::<Vec<_>>();
    assert_eq!(addrs(d.code_filter(&ran, &[])), [0x401100]);
    assert_eq!(addrs(d.code_filter(&ran[..1], &[])), [0x401000, 0x401100]);
    assert_eq!(addrs(d.code_filter(&ran[..1], &[vec![main[0]]])), [0x401100]);
    assert!(d.code_filter(&ran, &[vec![f1[0]]]).is_empty());
    assert!(d.code_filter(&[], &[]).is_empty());
    // Addresses outside every function are ignored.
    assert!(d.code_filter(&[vec![0x900000]], &[]).is_empty());
}

#[test]
fn dissection_file_round_trip() {
    let (p, _, _) = module();
    let d = dissect(&p, &p.modules.clone(), &DissectOptions::default(), &Progress::new()).unwrap();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("d.hhdis");
    d.save(&f, &Progress::new()).unwrap();
    let mut back = Dissection::load(&f, &Progress::new()).unwrap();
    // Loaded addresses are of some earlier run until matched against the live process.
    assert!(!back.is_validated() && !back.summary().validated);
    assert!(back.validate(&p).unwrap().unchanged());
    assert_eq!(back, d);
    assert_eq!(back.strings(None, 0, 10), d.strings(None, 0, 10));
    let c = Progress::new();
    c.cancel();
    assert!(Dissection::load(&f, &c).is_err());
}

/// An `.hhdis` file from parts.
fn craft(version: u32, meta: &str, count: Option<u64>, refs: &[(u64, u64, u8)]) -> Vec<u8> {
    let mut v = b"HHDISS\0\0".to_vec();
    v.extend_from_slice(&version.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(meta.len() as u64).to_le_bytes());
    v.extend_from_slice(meta.as_bytes());
    v.extend_from_slice(&count.unwrap_or(refs.len() as u64).to_le_bytes());
    for (t, f, k) in refs {
        v.extend_from_slice(&t.to_le_bytes());
        v.extend_from_slice(&f.to_le_bytes());
        v.push(*k);
    }
    v
}

#[test]
fn hostile_dissection_files_fail_cleanly() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("bad.hhdis");
    let meta = r#"{"modules":["m"],"code_bytes":1,"instructions":1,"functions":[{"addr":"0x10","callers":1,"internal":true,"name":null}],"strings":[],"caves":[]}"#;
    let load = |bytes: &[u8]| {
        std::fs::write(&f, bytes).unwrap();
        Dissection::load(&f, &Progress::new())
    };
    let ok = load(&craft(1, meta, None, &[(0x10, 0x20, 0)])).unwrap();
    assert_eq!(ok.functions(0, 10)[0].addr, 0x10);
    assert_eq!(ok.referenced_functions(0, 10).len(), 1);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("magic", b"HHMEM\x01\0\0garbage garbage garbage".to_vec()),
        ("version", craft(2, meta, None, &[])),
        ("meta json", craft(1, "{", None, &[])),
        ("meta shape", craft(1, r#"{"modules":1}"#, None, &[])),
        ("count over file", craft(1, meta, Some(u64::MAX / 17), &[])),
        ("count over cap", craft(1, meta, Some(1 << 40), &[])),
        ("count short", craft(1, meta, Some(2), &[(1, 2, 0)])),
        ("kind", craft(1, meta, None, &[(1, 2, 9)])),
        ("order", craft(1, meta, None, &[(5, 2, 0), (1, 2, 0)])),
        ("duplicate", craft(1, meta, None, &[(5, 2, 0), (5, 2, 0)])),
        (
            "functions order",
            craft(1, &meta.replace(r#"[{"addr":"0x10""#, r#"[{"addr":"0x20","callers":0,"internal":true,"name":null},{"addr":"0x10""#), None, &[]),
        ),
    ];
    for (what, bytes) in cases {
        assert!(load(&bytes).is_err(), "{what} was accepted");
    }
    // A meta length beyond the file is refused before allocating it.
    let mut v = craft(1, meta, None, &[]);
    v[16..24].copy_from_slice(&(1u64 << 40).to_le_bytes());
    assert!(load(&v).is_err());
}

/// `p` loaded `by` bytes higher (same bytes; the PE header's ImageBase is not rewritten
/// here, which the fingerprint ignores anyway).
fn shifted(p: &FakeProc, by: u64) -> FakeProc {
    let mut q = FakeProc::new();
    for (r, d) in p.regions.read().unwrap().iter() {
        q.add(r.start + by, d.clone(), r.prot, r.kind, r.path.as_deref());
    }
    for m in &p.modules {
        q.modules.push(hh_core::Module { base: m.base + by, ..m.clone() });
    }
    q
}

#[test]
fn loaded_dissection_is_rebased_or_dropped() {
    let (p, main, _) = module();
    let d = dissect(&p, &p.modules.clone(), &DissectOptions::default(), &Progress::new()).unwrap();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("d.hhdis");
    d.save(&f, &Progress::new()).unwrap();
    let internal = |d: &Dissection| d.functions(0, 100).iter().filter(|f| f.internal).map(|f| f.addr).collect::<Vec<_>>();
    let before = internal(&d);

    // The next run loaded it elsewhere: every address moves with it.
    let by = 0x10_0000;
    let q = shifted(&p, by);
    let mut back = Dissection::load(&f, &Progress::new()).unwrap();
    let v = back.validate(&q).unwrap();
    assert_eq!((v.rebased.as_slice(), v.dropped.len()), (&["test.dll".to_string()][..], 0));
    assert!(back.is_validated());
    assert_eq!(internal(&back), before.iter().map(|a| a + by).collect::<Vec<_>>());
    assert_eq!(back.module_idents()[0].base, 0x400000 + by);
    let x = back.xrefs_to(0x401200 + by, 0x401201 + by, &[RefKind::Call], 0, 10);
    assert_eq!(x[0].from, main[2] + by);
    assert_eq!(back.summary().code_bytes, 0x1000);
    assert_eq!(back.code_filter(&[vec![main[1] + by]], &[]).len(), 1);
    // Validating again against the same layout changes nothing.
    assert!(back.validate(&q).unwrap().unchanged());

    // A different build at the same path (header differs): nothing of it is kept.
    let r = shifted(&p, 0);
    r.put(0x400088, &[0x55; 4]); // PE TimeDateStamp
    let mut back = Dissection::load(&f, &Progress::new()).unwrap();
    let v = back.validate(&r).unwrap();
    assert_eq!(v.dropped, ["test.dll"]);
    assert!(internal(&back).is_empty() && back.summary().code_bytes == 0);
    assert!(back.xrefs_to(0, u64::MAX, &[], 0, 10).is_empty());

    // Not loaded at all.
    let mut empty = FakeProc::new();
    empty.add(0x10000, vec![0; 0x1000], RW, RegionKind::Private, None);
    let mut back = Dissection::load(&f, &Progress::new()).unwrap();
    assert_eq!(back.validate(&empty).unwrap().dropped, ["test.dll"]);
    assert!(internal(&back).is_empty());
}

#[test]
fn hostile_or_old_dissection_files_arm_nothing_outside_their_modules() {
    let (p, _, _) = module();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("h.hhdis");
    // Old format (no module identities): loads, cannot be validated.
    let old = r#"{"modules":["test.dll"],"code_bytes":1,"instructions":1,"functions":[{"addr":"0x401000","callers":1,"internal":true,"name":null}],"strings":[],"caves":[]}"#;
    std::fs::write(&f, craft(1, old, None, &[])).unwrap();
    let mut d = Dissection::load(&f, &Progress::new()).unwrap();
    assert!(d.validate(&p).is_err());
    assert!(!d.is_validated());
    // Identity matches, but it claims code outside the module: that part is dropped.
    let fp = module_fingerprint(&p, &p.modules[0], &hh_core::Process::regions(&p).unwrap()).unwrap();
    let meta = format!(
        r#"{{"modules":["test.dll"],"code_bytes":2,"instructions":1,"functions":[{{"addr":"0x401001","callers":1,"internal":true,"name":null}},{{"addr":"0x900000","callers":1,"internal":true,"name":null}}],"strings":[],"caves":[{{"addr":"0x900010","len":40,"byte":204}}],"code":[[4198400,4202496],[9437184,9441280]],"module_info":[{{"name":"test.dll","path":"{}","base":"0x400000","size":12288,"fingerprint":{fp}}}]}}"#,
        p.modules[0].path
    );
    std::fs::write(&f, craft(1, &meta, None, &[(0x401001, 0x900000, 0), (0x900000, 0x401000, 0)])).unwrap();
    let mut d = Dissection::load(&f, &Progress::new()).unwrap();
    assert!(d.validate(&p).unwrap().dropped.is_empty());
    let fs: Vec<u64> = d.functions(0, 10).iter().map(|f| f.addr).collect();
    assert_eq!(fs, [0x401001]);
    assert!(d.caves(0, 10).is_empty());
    assert_eq!(d.summary().code_bytes, 0x1000);
    // Only the reference made from inside the module is kept.
    assert_eq!(d.xrefs_to(0, u64::MAX, &[], 0, 10).len(), 1);
}

#[test]
fn tiny_metadata_elements_cannot_expand_memory() {
    // ~8.4 M empty module names: 25 MB of JSON, ~200 MiB once decoded. Refused once the
    // decoded elements pass the cap.
    let n = (MAX_META_DECODED / 24) as usize + 1;
    let mut meta = String::with_capacity(n * 3 + 128);
    meta.push_str(r#"{"modules":["#);
    for i in 0..n {
        meta.push_str(if i == 0 { "\"\"" } else { ",\"\"" });
    }
    meta.push_str(r#"],"code_bytes":0,"instructions":0,"functions":[],"strings":[],"caves":[]}"#);
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("big.hhdis");
    std::fs::write(&f, craft(1, &meta, None, &[])).unwrap();
    drop(meta);
    let e = Dissection::load(&f, &Progress::new()).unwrap_err();
    assert!(e.to_string().contains("too large"), "{e}");
}
