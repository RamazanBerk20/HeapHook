mod common;
use common::*;
use hh_core::{Memory, RegionKind};
use hh_tools::Progress;
use hh_tools::memory::*;

fn proc_() -> FakeProc {
    let mut p = FakeProc::new();
    p.add(0x10000, (0..0x2000u32).map(|i| i as u8).collect(), RW, RegionKind::Private, Some("[heap]"));
    p.add(0x13000, vec![0x11; 0x1000], RW, RegionKind::Private, None);
    p
}

fn bytes(p: &FakeProc, a: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    p.read_exact(a, &mut b).unwrap();
    b
}

#[test]
fn region_view() {
    let mut p = proc_();
    p.add(0x400000, vec![0; 0x1000], RX, RegionKind::Image, Some("/x/a.so"));
    p.add(0x7ff000, vec![0; 0x1000], RW, RegionKind::Private, Some("[stack]"));
    p.add(0x800000, vec![0; 0x1000], R, RegionKind::Private, Some("[vdso]"));
    p.add(0x900000, vec![0; 0x1000], R, RegionKind::Mapped, Some("/tmp/data.bin"));
    p.module("a.so", 0x400000, 0x1000);
    let r = regions(&p).unwrap();
    let tags: Vec<_> = r.iter().map(|r| r.tag).collect();
    assert_eq!(
        tags,
        [RegionTag::Heap, RegionTag::Private, RegionTag::Image, RegionTag::Stack, RegionTag::Special, RegionTag::Mapped]
    );
    assert_eq!(r[2].module.as_deref(), Some("a.so"));
    assert_eq!(r[2].prot_text, "r-xp");
    assert_eq!(serde_json::to_value(&r[0]).unwrap()["start"], "0x10000");
}

#[test]
fn save_load_roundtrip() {
    let p = proc_();
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("m.hhmem");
    let prog = Progress::new();
    // The range spans an unmapped gap: two blocks.
    let s = save_memory(&p, &[Range { start: 0x10000, size: 0x4000 }], &f, &prog).unwrap();
    assert_eq!((s.blocks, s.bytes), (2, 0x3000));
    assert_eq!(prog.snapshot().done, 0x4000);
    let orig = bytes(&p, 0x10000, 0x2000);
    p.put(0x10010, &[0xAA; 32]);
    p.put(0x13000, &[0xBB; 8]);
    let r = load_memory(&p, &f, None).unwrap();
    assert_eq!((r.blocks, r.bytes, r.failed.len()), (2, 0x3000, 0));
    assert_eq!(bytes(&p, 0x10000, 0x2000), orig);
    assert_eq!(bytes(&p, 0x13000, 8), [0x11; 8]);

    // Relocated load.
    save_memory(&p, &[Range { start: 0x10000, size: 0x100 }], &f, &Progress::new()).unwrap();
    load_memory(&p, &f, Some(0x10800)).unwrap();
    assert_eq!(bytes(&p, 0x10800, 0x100), bytes(&p, 0x10000, 0x100));
    let r = load_memory(&p, &f, Some(0x50000)).unwrap();
    assert_eq!(r.failed, [0x50000]);

    // Snapshot file round trip and bad files.
    let snap = snapshot(&p, &readable_ranges(&p, true).unwrap(), &Progress::new()).unwrap();
    save_snapshot(&snap, &f).unwrap();
    assert_eq!(load_snapshot(&f).unwrap(), snap);
    let mut raw = std::fs::read(&f).unwrap();
    raw.truncate(raw.len() - 10);
    std::fs::write(&f, &raw).unwrap();
    assert!(load_snapshot(&f).is_err());
    std::fs::write(&f, b"garbage garbage garbage").unwrap();
    assert!(load_snapshot(&f).is_err());
    let c = Progress::new();
    c.cancel();
    assert!(save_memory(&p, &[Range { start: 0x10000, size: 0x100 }], &f, &c).is_err());
}

#[test]
fn fill_copy() {
    let p = proc_();
    fill(&p, 0x10001, 10, &[1, 2, 3]).unwrap();
    assert_eq!(bytes(&p, 0x10000, 12), [0, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 11]);
    assert!(fill(&p, 0x10000, 4, &[]).is_err());
    assert!(fill(&p, 0x11000, 0x2000, &[0]).is_err());

    let seq: Vec<u8> = (0..16).collect();
    p.put(0x10100, &seq);
    copy(&p, 0x10100, 0x10104, 16).unwrap();
    assert_eq!(bytes(&p, 0x10104, 16), seq);
    p.put(0x10200, &seq);
    copy(&p, 0x10204, 0x10200, 12).unwrap();
    assert_eq!(bytes(&p, 0x10200, 12), &seq[4..]);
    assert!(copy(&p, 0x20000, 0x10000, 4).is_err());
}

#[test]
fn snapshot_diffs() {
    let p = proc_();
    let ranges = readable_ranges(&p, false).unwrap();
    let a = snapshot(&p, &ranges, &Progress::new()).unwrap();
    p.put(0x10010, &[0xF0, 0xF1]);
    p.put(0x13100, &[0x99]);
    let b = snapshot(&p, &ranges, &Progress::new()).unwrap();
    let d = diff_snapshots(&a, &b, 100);
    assert_eq!(d.len(), 2);
    assert_eq!((d[0].addr, d[0].len, d[0].old.clone(), d[0].new.clone()), (0x10010, 2, vec![0x10, 0x11], vec![0xF0, 0xF1]));
    assert_eq!((d[1].addr, d[1].new.clone()), (0x13100, vec![0x99]));
    assert_eq!(diff_snapshots(&a, &b, 1).len(), 1);
    assert_eq!(diff_live(&p, &a, 100, &Progress::new()).unwrap(), d);
    // A region that went away is reported as unreadable.
    p.regions.write().unwrap().retain(|r| r.0.start != 0x13000);
    let d = diff_live(&p, &a, 100, &Progress::new()).unwrap();
    assert_eq!(d.len(), 2);
    assert_eq!((d[1].addr, d[1].len, d[1].new.len()), (0x13000, 0x1000, 0));
    assert_eq!(serde_json::to_value(&d[0]).unwrap()["new"], "F0 F1");
}

#[test]
fn pointers_to() {
    let mut p = proc_();
    p.add(0x400000, vec![0; 0x1000], RW, RegionKind::Image, Some("/x/a.so"));
    p.module("a.so", 0x400000, 0x1000);
    p.put(0x10100, &[0; 32]);
    p.put_u64(0x400010, 0x10050);
    p.put_u64(0x10100, 0x10040);
    p.put_u64(0x10109, 0x10050); // unaligned: not a pointer slot
    let q = PointerQuery { target: 0x10050, max_offset: 0x20, ..Default::default() };
    let h = find_pointers(&p, &q, &Progress::new()).unwrap();
    let got: Vec<_> = h.iter().map(|h| (h.addr, h.offset, h.module.clone())).collect();
    assert_eq!(got, [(0x10100, 0x10, None), (0x400010, 0, Some("a.so+10".into()))]);
    let q = PointerQuery { static_only: true, ..q };
    assert_eq!(find_pointers(&p, &q, &Progress::new()).unwrap().len(), 1);
    let q = PointerQuery { max_offset: 0, ..q };
    assert_eq!(find_pointers(&p, &q, &Progress::new()).unwrap()[0].addr, 0x400010);
}

// ---------------------------------------------------------------- hostile input (release audit)

#[test]
fn pointer_search_stops_at_max_results() {
    let mut p = FakeProc::new();
    // 64k slots all pointing at the target.
    p.add(0x100000, 0x200000u64.to_le_bytes().repeat(0x10000), RW, RegionKind::Private, None);
    p.add(0x900000, 0x200000u64.to_le_bytes().repeat(0x10000), RW, RegionKind::Private, None);
    let q = PointerQuery { target: 0x200000, max_results: 3, ..Default::default() };
    let h = find_pointers(&p, &q, &Progress::new()).unwrap();
    assert_eq!(h.iter().map(|h| h.addr).collect::<Vec<_>>(), [0x100000, 0x100008, 0x100010]);
}

#[test]
fn wrapping_ranges_are_rejected() {
    let p = proc_();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("wrap.hhmem");
    let snap = snapshot(&p, &[Range { start: 0x10000, size: 0x20 }], &Progress::new()).unwrap();
    save_snapshot(&snap, &f).unwrap();
    let mut raw = std::fs::read(&f).unwrap();
    raw[16..24].copy_from_slice(&(u64::MAX - 4).to_le_bytes());
    std::fs::write(&f, &raw).unwrap();
    assert!(load_snapshot(&f).is_err());
    assert!(fill(&p, u64::MAX - 4, 0x10, &[0]).is_err());
    assert!(copy(&p, 0x10000, u64::MAX - 4, 0x10).is_err());
}

#[test]
fn pe_import_walk_is_bounded() {
    // 4096 descriptors, each pointing at the same 64k-slot thunk array.
    let mut img = vec![0u8; 0x20000 + 0x10000 * 8 + 8];
    img[..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    img[0x40..0x44].copy_from_slice(b"PE\0\0");
    img[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    img[0x46] = 1; // one (empty) section header
    img[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
    let opt = 0x58;
    img[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    img[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    img[opt + 120..opt + 124].copy_from_slice(&0x1000u32.to_le_bytes());
    for i in 0..4096 {
        let d = 0x1000 + i * 20;
        img[d..d + 4].copy_from_slice(&0x20000u32.to_le_bytes());
    }
    for j in 0..0x10000 {
        img[0x20000 + j * 8] = 1;
    }
    let mut p = FakeProc::new();
    p.add(0x400000, img, RX, RegionKind::Image, None);
    p.module("imp.dll", 0x400000, 0xA0008);
    let t = std::time::Instant::now();
    let e = hh_tools::headers::summary(&p, &p.modules[0]).unwrap_err().to_string();
    assert!(e.contains("import slots"), "{e}");
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
}

#[cfg(unix)]
#[test]
fn elf_headers_never_open_a_fifo() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let fifo = dir.path().join("lib.so");
    if !std::process::Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success()) {
        return;
    }
    let mut elf = vec![0u8; 0x1000];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    let mut p = FakeProc::new();
    p.add(0x500000, elf, RX, RegionKind::Image, None);
    p.modules.push(hh_core::Module { name: "lib.so".into(), path: fifo.to_str().unwrap().into(), base: 0x500000, size: 0x1000 });
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = hh_tools::headers::summary(&p, &p.modules[0]).map(|h| h.source);
        let _ = tx.send(r);
    });
    let r = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("headers view hung on a FIFO");
    assert!(r.is_err() || r.unwrap() == "memory");
}

// ---------------------------------------------------------------- 1.0: load plan, search, stats

#[test]
fn load_plan_then_approved_blocks_only() {
    let mut p = proc_();
    p.add(0x20000, vec![0x22; 0x1000], R, RegionKind::Private, None);
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("plan.hhmem");
    let snap = Snapshot {
        blocks: vec![
            Block { addr: 0x13000, data: vec![0xAA; 0x10] },
            Block { addr: 0x10000, data: vec![0xBB; 0x20] },
            Block { addr: 0x20000, data: vec![0xCC; 0x10] },
            Block { addr: 0x30000, data: vec![0xDD; 0x10] },
            Block { addr: 0x10FF0, data: vec![0xEE; 0x20] },
        ],
    };
    save_snapshot(&snap, &f).unwrap();
    let before = bytes(&p, 0x10000, 0x20);
    let plan = plan_load(&p, &f, None).unwrap();
    // Sorted by address; nothing written yet.
    let got: Vec<_> = plan.blocks.iter().map(|b| (b.index, b.addr, b.len, b.mapped, b.writable)).collect();
    assert_eq!(
        got,
        [
            (0, 0x10000, 0x20, true, true),
            (1, 0x10FF0, 0x20, true, true),
            (2, 0x13000, 0x10, true, true),
            (3, 0x20000, 0x10, true, false),
            (4, 0x30000, 0x10, false, false),
        ]
    );
    assert_eq!((plan.bytes, plan.unmapped, plan.read_only), (0x70, 1, 1));
    assert_eq!(bytes(&p, 0x10000, 0x20), before);
    assert_eq!(serde_json::to_value(plan.blocks[0]).unwrap()["addr"], "0x10000");

    // Only block 2 approved.
    let r = load_memory_approved(&p, &f, None, &plan.blocks[2..3]).unwrap();
    assert_eq!((r.blocks, r.bytes, r.failed.len()), (1, 0x10, 0));
    assert_eq!(bytes(&p, 0x13000, 0x10), [0xAA; 0x10]);
    assert_eq!(bytes(&p, 0x10000, 0x20), before);
    // An unmapped block fails, reported like load_memory does.
    let r = load_memory_approved(&p, &f, None, &plan.blocks[4..]).unwrap();
    assert_eq!(r.failed, [0x30000]);
    // Relocated plans move every block by the same distance.
    let moved = plan_load(&p, &f, Some(0x10100)).unwrap();
    assert_eq!(moved.blocks[2].addr, 0x13100);
    // A plan for another file (or a changed file) is refused without writing anything.
    let mut stale = plan.blocks[0];
    stale.len = 0x21;
    assert!(load_memory_approved(&p, &f, None, &[plan.blocks[1], stale]).is_err());
    assert_eq!(bytes(&p, 0x10FF0, 0x10), bytes(&proc_(), 0x10FF0, 0x10));
    let mut out_of_range = plan.blocks[0];
    out_of_range.index = 99;
    assert!(load_memory_approved(&p, &f, None, &[out_of_range]).is_err());
    // load_memory still writes everything.
    let r = load_memory(&p, &f, None).unwrap();
    assert_eq!(r.failed, [0x30000]);
}

#[test]
fn hostile_memory_files_fail_cleanly() {
    let p = proc_();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("bad.hhmem");
    let head = |count: u32| {
        let mut v = b"HHMEM\x01\0\0".to_vec();
        v.extend_from_slice(&count.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v
    };
    // Billions of declared blocks in a tiny file: refused before allocating an index.
    std::fs::write(&f, head(u32::MAX)).unwrap();
    assert!(plan_load(&p, &f, None).is_err());
    assert!(search_file(&f, &[Some(1)], 10, &Progress::new()).is_err());
    // A block longer than the file.
    let mut v = head(1);
    v.extend_from_slice(&0x10000u64.to_le_bytes());
    v.extend_from_slice(&(1u64 << 40).to_le_bytes());
    std::fs::write(&f, &v).unwrap();
    assert!(plan_load(&p, &f, None).is_err());
    assert!(load_memory_approved(&p, &f, None, &[]).is_err());
    // Wrapping block.
    let mut v = head(1);
    v.extend_from_slice(&(u64::MAX - 1).to_le_bytes());
    v.extend_from_slice(&4u64.to_le_bytes());
    v.extend_from_slice(&[0; 4]);
    std::fs::write(&f, &v).unwrap();
    assert!(plan_load(&p, &f, None).is_err());
    std::fs::write(&f, b"HHMEM").unwrap();
    assert!(plan_load(&p, &f, None).is_err());
    std::fs::write(&f, b"").unwrap();
    assert!(search_file(&f, &[Some(1)], 10, &Progress::new()).is_err());
}

#[test]
fn search_saved_snapshot_files() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let f = dir.path().join("s.hhmem");
    // The second block is larger than one read piece (16 MiB) with a hit across the border.
    let mut big = vec![0u8; (16 << 20) + 64];
    let border = (16 << 20) - 2;
    big[border..border + 4].copy_from_slice(&1234i32.to_le_bytes());
    let mut small = vec![0u8; 64];
    small[8..12].copy_from_slice(&1234i32.to_le_bytes());
    small[60..64].copy_from_slice(&1234i32.to_le_bytes());
    let snap = Snapshot { blocks: vec![Block { addr: 0x1000, data: small }, Block { addr: 0x4000_0000, data: big }] };
    save_snapshot(&snap, &f).unwrap();
    drop(snap);
    let prog = Progress::new();
    let fmt = hh_scan::Fmt::default();
    let hits = search_file_value(&f, hh_scan::VType::Bytes4, "1234", &fmt, 100, &prog).unwrap();
    assert_eq!(hits, [0x1008, 0x103C, 0x4000_0000 + border as u64]);
    assert_eq!(prog.snapshot().done, 64 + (16 << 20) + 64);
    assert_eq!(search_file_value(&f, hh_scan::VType::Bytes4, "1234", &fmt, 2, &Progress::new()).unwrap(), [0x1008, 0x103C]);
    // Wildcards: D2 ?? 00 00.
    let hits = search_file(&f, &[Some(0xD2), None, Some(0), Some(0)], 100, &Progress::new()).unwrap();
    assert_eq!(hits.len(), 3);
    assert!(search_file(&f, &[], 1, &Progress::new()).is_err());
    assert!(search_file(&f, &vec![None; MAX_PATTERN + 1], 1, &Progress::new()).is_err());
    let c = Progress::new();
    c.cancel();
    assert!(search_file(&f, &[Some(1)], 1, &c).is_err());
}

#[test]
fn region_statistics() {
    let mut p = proc_();
    p.add(0x400000, vec![0; 0x2000], RX, RegionKind::Image, Some("/x/a.so"));
    p.add(0x7ff000, vec![0; 0x1000], RW, RegionKind::Private, Some("[stack]"));
    p.module("a.so", 0x400000, 0x2000);
    let s = region_stats(&regions(&p).unwrap());
    assert_eq!((s.regions, s.bytes), (4, 0x6000));
    let rows = |v: &[StatRow]| v.iter().map(|r| (r.key.clone(), r.regions, r.bytes)).collect::<Vec<_>>();
    assert_eq!(rows(&s.by_prot), [("rw-p".into(), 3, 0x4000), ("r-xp".into(), 1, 0x2000)]);
    assert_eq!(rows(&s.by_tag), [("heap".into(), 1, 0x2000), ("image".into(), 1, 0x2000), ("private".into(), 1, 0x1000), ("stack".into(), 1, 0x1000)]);
    assert_eq!(rows(&s.by_kind)[0], ("Private".into(), 3, 0x4000));
    assert_eq!(rows(&s.by_module), [("a.so".into(), 1, 0x2000)]);
}

#[test]
fn page_change_map() {
    let p = proc_();
    let ranges = readable_ranges(&p, false).unwrap();
    let a = snapshot(&p, &ranges, &Progress::new()).unwrap();
    p.put(0x10010, &[0xF0]);
    p.put(0x10FFF, &[0xF0, 0xF1]); // straddles two pages
    p.put(0x13100, &[0x99]);
    let b = snapshot(&p, &ranges, &Progress::new()).unwrap();
    // One page per cell.
    let m = change_map(&a, &b, 0x10000, 0x14000, 4).unwrap();
    assert_eq!(m.cell_size, 0x1000);
    assert_eq!(m.compared, [1, 1, 0, 1]);
    assert_eq!(m.changed, [1, 1, 0, 1]);
    // Two cells: pages are summed per cell.
    let m = change_map(&a, &b, 0x10000, 0x14000, 2).unwrap();
    assert_eq!((m.cell_size, m.compared.clone(), m.changed.clone()), (0x2000, vec![2, 1], vec![2, 1]));
    // The resolution is capped.
    let m = change_map(&a, &b, 0, u64::MAX, usize::MAX).unwrap();
    assert_eq!(m.changed.len(), MAX_MAP_CELLS);
    assert_eq!(m.changed.iter().sum::<u32>(), 3);
    assert!(change_map(&a, &b, 5, 5, 4).is_err());
}

/// A module whose memory holds a minimal ELF but whose path names a different local file
/// (as with a remote target): local mode parses the local file, remote mode only memory.
#[cfg(unix)]
#[test]
fn remote_targets_never_read_local_module_files() {
    let mut elf = vec![0u8; 0x1000];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[16] = 3; // ET_DYN
    elf[18] = 62;
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    let mut p = FakeProc::new();
    p.add(0x500000, elf, RX, RegionKind::Image, None);
    let local = std::env::current_exe().unwrap();
    p.modules.push(hh_core::Module { name: "m".into(), path: local.to_str().unwrap().into(), base: 0x500000, size: 0x1000 });
    let m = &p.modules[0];
    assert_eq!(hh_tools::headers::summary(&p, m).unwrap().source, "file");
    let h = hh_tools::headers::summary_with(&p, m, false).unwrap();
    assert_eq!((h.source.as_str(), h.sections.len()), ("memory", 1));
    let opts = hh_tools::dissect::DissectOptions { local_files: false, ..Default::default() };
    let d = hh_tools::dissect::dissect(&p, &p.modules, &opts, &Progress::new()).unwrap();
    assert!(d.functions(0, 100).iter().all(|f| f.name.is_none()));
}
