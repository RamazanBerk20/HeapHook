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
