use std::sync::{Mutex, RwLock};

use hh_asm::*;
use hh_core::{Addr, Error, Memory, Module, Process, Prot, Region, RegionKind, Result};

/// Sparse multi-region fake process with modules and alloc/free.
struct TestProc {
    regions: RwLock<Vec<(Addr, Vec<u8>)>>,
    mods: Vec<Module>,
    ptr: usize,
    next: Mutex<u64>,
    pid: u32,
    /// (prot, near) of every alloc.
    alloc_log: Mutex<Vec<(Prot, Option<Addr>)>>,
}

impl TestProc {
    fn new(ptr: usize) -> Self {
        Self {
            regions: RwLock::new(Vec::new()),
            mods: Vec::new(),
            ptr,
            next: Mutex::new(0),
            pid: 1,
            alloc_log: Mutex::new(Vec::new()),
        }
    }
    fn map(&self, start: Addr, data: Vec<u8>) {
        self.regions.write().unwrap().push((start, data));
    }
    fn module(mut self, name: &str, base: Addr, data: Vec<u8>) -> Self {
        self.mods.push(Module {
            name: name.into(),
            path: format!("/x/{name}"),
            base,
            size: data.len() as u64,
        });
        self.map(base, data);
        self
    }
    fn snapshot(&self) -> Vec<(Addr, Vec<u8>)> {
        let mut v = self.regions.read().unwrap().clone();
        v.sort_by_key(|r| r.0);
        v
    }
}

impl Memory for TestProc {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        for (s, d) in self.regions.read().unwrap().iter() {
            if addr >= *s && addr < s + d.len() as u64 {
                let o = (addr - s) as usize;
                let n = buf.len().min(d.len() - o);
                buf[..n].copy_from_slice(&d[o..o + n]);
                return Ok(n);
            }
        }
        Err(Error::NoAccess { addr })
    }
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        for (s, d) in self.regions.write().unwrap().iter_mut() {
            if addr >= *s && addr + data.len() as u64 <= *s + d.len() as u64 {
                let o = (addr - *s) as usize;
                d[o..o + data.len()].copy_from_slice(data);
                return Ok(());
            }
        }
        Err(Error::NoAccess { addr })
    }
    fn pointer_size(&self) -> usize {
        self.ptr
    }
}

impl Process for TestProc {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(self
            .snapshot()
            .into_iter()
            .map(|(start, d)| Region {
                start,
                size: d.len() as u64,
                prot: Prot {
                    r: true,
                    w: true,
                    x: true,
                },
                kind: RegionKind::Private,
                shared: false,
                cow: false,
                path: None,
            })
            .collect())
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.mods.clone())
    }
    fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> Result<Addr> {
        self.alloc_log.lock().unwrap().push((prot, near));
        let mut n = self.next.lock().unwrap();
        let base = near.map_or(0x5000_0000, |a| (a & !0xFFFF) + 0x10_0000);
        let a = base + *n;
        *n += size.next_multiple_of(0x1000);
        self.map(a, vec![0; size as usize]);
        Ok(a)
    }
    fn free(&self, addr: Addr, _size: u64) -> Result<()> {
        let mut r = self.regions.write().unwrap();
        let i = r
            .iter()
            .position(|x| x.0 == addr)
            .ok_or(Error::NoAccess { addr })?;
        r.remove(i);
        Ok(())
    }
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

const GAME64: Addr = 0x1_4000_0000;

/// game.exe with a "health decrement" routine at +1000 and a pointer chain at +3000.
fn game64() -> TestProc {
    let mut img = vec![0xCCu8; 0x4000];
    let code = hex("48 89 5C 24 08 \
         29 81 E0 00 00 00 \
         8B 81 E0 00 00 00 \
         8B 05 09 20 00 00 \
         C3");
    img[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    // +3000: pointer -> 0x2000_0000 ; +3010: "Hello" ; +3020: 0x2A
    img[0x3000..0x3008].copy_from_slice(&0x2000_0000u64.to_le_bytes());
    img[0x3010..0x3016].copy_from_slice(b"Hello\0");
    img[0x3020..0x3024].copy_from_slice(&0x2Au32.to_le_bytes());
    let p = TestProc::new(8).module("game.exe", GAME64, img);
    let mut heap = vec![0u8; 0x100];
    heap[8..16].copy_from_slice(&0x2000_0080u64.to_le_bytes());
    heap[0x88..0x90].copy_from_slice(&0x1234u64.to_le_bytes());
    p.map(0x2000_0000, heap);
    p
}

fn no_syms(_: &str) -> Option<u64> {
    None
}

// ---------------------------------------------------------------- disassembler

#[test]
fn disassemble_64() {
    let p = game64();
    let syms = SymbolTable::default();
    let l = disassemble(&p, &syms, GAME64 + 0x1000, 5).unwrap();
    let texts: Vec<&str> = l.iter().map(|x| x.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "mov [rsp+8],rbx",
            "sub [rcx+E0],eax",
            "mov eax,[rcx+E0]",
            "mov eax,[140003020]",
            "ret"
        ]
    );
    assert_eq!(l[1].addr, GAME64 + 0x1005);
    assert_eq!(l[1].bytes, hex("29 81 E0 00 00 00"));
    assert_eq!(l[3].comment, "[game.exe+3020]=0000002A");
    // Unreadable memory.
    let bad = disassemble(&p, &syms, 0x10, 2).unwrap();
    assert_eq!(bad[0].text, "??");
    assert_eq!(bad[1].addr, 0x11);
}

#[test]
fn disassemble_comments_and_32bit() {
    let p = TestProc::new(4).module("game.exe", 0x40_0000, vec![0; 0x2000]);
    // call game.exe+1000 ; mov eax,[game.exe+1800] (string) ; invalid byte
    p.write(0x40_0000, &hex("E8 FB 0F 00 00 A1 00 18 40 00 0F 0B"))
        .unwrap();
    p.write(0x40_1800, b"Score").unwrap();
    let mut syms = SymbolTable::default();
    syms.register("myfunc", 0x40_1000);
    let l = disassemble(&p, &syms, 0x40_0000, 3).unwrap();
    assert_eq!(l[0].text, "call 401000");
    assert_eq!(l[0].comment, "myfunc");
    assert_eq!(l[1].text, "mov eax,[401800]");
    assert_eq!(l[1].comment, "[game.exe+1800]='Score'");
    assert_eq!(l[2].text, "ud2");
}

#[test]
fn previous_instruction_scrolls_back() {
    let p = game64();
    let starts = [0x1000u64, 0x1005, 0x100B, 0x1011, 0x1017];
    for w in starts.windows(2) {
        assert_eq!(
            previous_instruction(&p, GAME64 + w[1]).unwrap(),
            GAME64 + w[0]
        );
    }
}

// ---------------------------------------------------------------- assembler

/// (text, ip, expected bytes or "" for round-trip only)
const TABLE64: &[(&str, u64, &str)] = &[
    ("mov [rax+10],ecx", 0x1000, "89 48 10"),
    ("mov rax,[rbx+rcx*8+100]", 0x1000, "48 8B 84 CB 00 01 00 00"),
    (
        "mov rax,qword ptr [rbx+rcx*8+100]",
        0x1000,
        "48 8B 84 CB 00 01 00 00",
    ),
    ("add eax,1", 0x1000, "83 C0 01"),
    ("add rax,FFFFFFFFFFFFFFFF", 0x1000, "48 83 C0 FF"),
    ("add rax,-1", 0x1000, "48 83 C0 FF"),
    ("and eax,FFFFFFF0", 0x1000, "83 E0 F0"),
    ("mov eax,#100", 0x1000, "B8 64 00 00 00"),
    ("mov eax,0x10", 0x1000, "B8 10 00 00 00"),
    ("ret", 0x1000, "C3"),
    ("retn", 0x1000, "C3"),
    ("ret 8", 0x1000, "C2 08 00"),
    ("push rbp", 0x1000, "55"),
    ("pop r15", 0x1000, "41 5F"),
    ("mov dword ptr [rax],1", 0x1000, "C7 00 01 00 00 00"),
    ("mov [rax],1", 0x1000, "C7 00 01 00 00 00"),
    ("mov byte ptr [rax],1", 0x1000, "C6 00 01"),
    ("mov word ptr [rax],1", 0x1000, "66 C7 00 01 00"),
    ("mov qword ptr [rax],1", 0x1000, "48 C7 00 01 00 00 00"),
    ("movss xmm0,[rax+4]", 0x1000, "F3 0F 10 40 04"),
    ("movss [rax+4],xmm15", 0x1000, "F3 44 0F 11 78 04"),
    ("movsd xmm1,qword ptr [rsp+8]", 0x1000, "F2 0F 10 4C 24 08"),
    ("cvttss2si eax,xmm0", 0x1000, "F3 0F 2C C0"),
    ("jmp 1010", 0x1000, "EB 0E"),
    ("jmp 2000", 0x1000, "E9 FB 0F 00 00"),
    ("jne 1000", 0x1000, "75 FE"),
    ("jnz 1000", 0x1000, "75 FE"),
    ("je 900", 0x1000, "0F 84 FA F8 FF FF"),
    ("call 2000", 0x1000, "E8 FB 0F 00 00"),
    ("lea rcx,[rip+10]", 0x1000, "48 8D 0D 10 00 00 00"),
    ("mov eax,[1100]", 0x1000, "8B 05 FA 00 00 00"),
    ("mov rax,gs:[60]", 0x1000, "65 48 8B 04 25 60 00 00 00"),
    ("lock cmpxchg [rcx],edx", 0x1000, "F0 0F B1 11"),
    ("rep movsb", 0x1000, "F3 A4"),
    ("rep stosq", 0x1000, "F3 48 AB"),
    ("lodsb", 0x1000, "AC"),
    ("fld dword ptr [rax]", 0x1000, "D9 00"),
    ("fstp st(1)", 0x1000, "DD D9"),
    ("fadd st(0),st(2)", 0x1000, "D8 C2"),
    ("vaddps ymm0,ymm1,ymm2", 0x1000, "C5 F4 58 C2"),
    ("vmovups xmm0,[rax]", 0x1000, "C5 F8 10 00"),
    ("shl eax,1", 0x1000, "D1 E0"),
    ("shr rcx,4", 0x1000, "48 C1 E9 04"),
    ("imul eax,ecx,10", 0x1000, "6B C1 10"),
    ("test al,al", 0x1000, "84 C0"),
    ("setne al", 0x1000, "0F 95 C0"),
    ("setnz al", 0x1000, "0F 95 C0"),
    ("cmovz eax,ecx", 0x1000, "0F 44 C1"),
    ("mov r8d,[r9+r10*4-8]", 0x1000, "47 8B 44 91 F8"),
    ("movzx eax,byte ptr [rcx]", 0x1000, "0F B6 01"),
    (
        "mov rax,123456789ABC",
        0x1000,
        "48 B8 BC 9A 78 56 34 12 00 00",
    ),
    ("mov rax,-2", 0x1000, "48 C7 C0 FE FF FF FF"),
    ("push 12345678", 0x1000, "68 78 56 34 12"),
    ("push 10", 0x1000, "6A 10"),
    ("int3", 0x1000, "CC"),
    ("xchg rax,rcx", 0x1000, "48 87 C8"),
    ("xchg rcx,rax", 0x1000, "48 91"),
    ("pushfq", 0x1000, "9C"),
    ("jmp qword ptr [rax]", 0x1000, "FF 20"),
    ("jmp [rax]", 0x1000, "FF 20"),
    ("call rax", 0x1000, "FF D0"),
    ("call qword ptr [rip+100]", 0x1000, "FF 15 00 01 00 00"),
    ("inc dword ptr [rbx+rsi]", 0x1000, "FF 04 33"),
    ("dec [rbx]", 0x1000, "FF 0B"),
    ("cmp byte ptr [rcx+5],0", 0x1000, "80 79 05 00"),
    ("sub [rcx+000000E0],eax", 0x1000, "29 81 E0 00 00 00"),
    ("  MOV   EAX , [ RCX + E0 ]  ", 0x1000, "8B 81 E0 00 00 00"),
    ("mov eax,[rsp]", 0x1000, "8B 04 24"),
    ("mov eax,[rbp]", 0x1000, "8B 45 00"),
    ("mov eax,[r13]", 0x1000, "41 8B 45 00"),
    ("mov eax,[ecx]", 0x1000, "67 8B 01"),
    ("mov ax,word ptr [rcx]", 0x1000, "66 8B 01"),
    ("mov ah,bl", 0x1000, "88 DC"),
    ("mov cr0,rax", 0x1000, ""),
    ("cpuid", 0x1000, "0F A2"),
    ("syscall", 0x1000, "0F 05"),
    ("nop", 0x1000, "90"),
    ("nop dword ptr [rax]", 0x1000, "0F 1F 00"),
    ("pxor xmm0,xmm0", 0x1000, "66 0F EF C0"),
    ("cvtsi2ss xmm0,eax", 0x1000, "F3 0F 2A C0"),
    ("mulss xmm0,[rip+20]", 0x1000, "F3 0F 59 05 20 00 00 00"),
    ("enter 10,0", 0x1000, "C8 10 00 00"),
    ("bt eax,3", 0x1000, "0F BA E0 03"),
    ("xor eax,eax", 0x1000, "31 C0"),
];

const TABLE32: &[(&str, u64, &str)] = &[
    ("mov eax,[12345678]", 0x40_0000, "A1 78 56 34 12"),
    ("push ebp", 0x40_0000, "55"),
    ("mov ebp,esp", 0x40_0000, "89 E5"),
    ("mov [esi+04],eax", 0x40_0000, "89 46 04"),
    ("call 401000", 0x40_0000, "E8 FB 0F 00 00"),
    ("jmp 400010", 0x40_0000, "EB 0E"),
    ("fld dword ptr [403000]", 0x40_0000, "D9 05 00 30 40 00"),
    ("mov eax,fs:[30]", 0x40_0000, "64 A1 30 00 00 00"),
    ("inc eax", 0x40_0000, "40"),
    ("pushad", 0x40_0000, "60"),
    (
        "mov dword ptr [ebx+ecx*4+10],FFFFFFFF",
        0x40_0000,
        "C7 44 8B 10 FF FF FF FF",
    ),
    ("movss xmm0,[eax]", 0x40_0000, "F3 0F 10 00"),
    ("ret 4", 0x40_0000, "C2 04 00"),
    ("rep movsd", 0x40_0000, "F3 A5"),
];

fn check_table(table: &[(&str, u64, &str)], ptr: usize) {
    let bits = if ptr == 4 { 32 } else { 64 };
    for &(text, ip, want) in table {
        let got = assemble_line(text, ip, bits, &no_syms).unwrap_or_else(|e| panic!("{text}: {e}"));
        if !want.is_empty() {
            assert_eq!(got, hex(want), "{text}");
        }
        // Round trip: disassemble, reassemble, same bytes.
        let p = TestProc::new(ptr);
        p.map(ip, got.clone());
        let line = &disassemble(&p, &SymbolTable::default(), ip, 1).unwrap()[0];
        assert_eq!(line.bytes, got, "{text} -> {}", line.text);
        let again = assemble_line(&line.text, ip, bits, &no_syms)
            .unwrap_or_else(|e| panic!("{text} -> {}: {e}", line.text));
        assert_eq!(again, got, "{text} -> {}", line.text);
    }
}

#[test]
fn assembler_table_64() {
    check_table(TABLE64, 8);
}

#[test]
fn assembler_table_32() {
    check_table(TABLE32, 4);
}

#[test]
fn assembler_roundtrip_decoded_stream() {
    // Every instruction iced decodes from a mixed byte stream must reassemble identically.
    let code = hex(
        "55 48 89 E5 48 83 EC 20 48 8B 05 10 00 00 00 F3 0F 11 45 FC 0F B7 C8 66 0F 6E C1 \
         C5 FA 58 C1 48 63 D0 4C 8D 04 92 41 FF D0 E8 00 00 00 00 0F 1F 44 00 00 \
         F2 0F 5E C1 0F 28 D0 48 C1 F8 3F 48 F7 D8 41 0F 94 C1 D9 EE DE C9 C9 C3",
    );
    let p = TestProc::new(8);
    p.map(0x7FF6_0000_1000, code.clone());
    let lines = disassemble(&p, &SymbolTable::default(), 0x7FF6_0000_1000, 64).unwrap();
    let mut total = 0;
    for l in lines.iter().take_while(|l| l.text != "??") {
        let again = assemble_line(&l.text, l.addr, 64, &no_syms)
            .unwrap_or_else(|e| panic!("{}: {e}", l.text));
        if again != l.bytes {
            // Equivalent shorter encodings (e.g. a redundant disp8 of 0) are fine.
            let q = TestProc::new(8);
            q.map(l.addr, again.clone());
            assert_eq!(
                disassemble(&q, &SymbolTable::default(), l.addr, 1).unwrap()[0].text,
                l.text
            );
        }
        total += l.bytes.len();
    }
    assert_eq!(total, code.len());
}

#[test]
fn assembler_data_and_helpers() {
    let a = |t: &str| assemble_line(t, 0x1000, 64, &no_syms).unwrap();
    assert_eq!(a("db 90 90 'AB'"), hex("90 90 41 42"));
    assert_eq!(a("db 90,91,\"x\""), hex("90 91 78"));
    assert_eq!(a("dw 1234 'A'"), hex("34 12 41 00"));
    assert_eq!(a("dd (float)1"), hex("00 00 80 3F"));
    assert_eq!(a("dd (float)100.5, 2"), hex("00 00 C9 42 02 00 00 00"));
    assert_eq!(a("dq (double)1"), hex("00 00 00 00 00 00 F0 3F"));
    assert_eq!(a("dd (int)-1"), hex("FF FF FF FF"));
    assert_eq!(a("dq 1122334455667788"), hex("88 77 66 55 44 33 22 11"));
    assert_eq!(a("nop 3"), hex("90 90 90"));
    assert_eq!(a("nop A"), vec![0x90; 10]);
    assert_eq!(a("jmp short 1010"), hex("EB 0E"));
    assert!(assemble_line("jmp short 2000", 0x1000, 64, &no_syms).is_err());
    // 64-bit jump beyond rel32 falls back to jmp [rip] + qword.
    assert_eq!(
        a("jmp 7FFF00001234"),
        hex("FF 25 00 00 00 00 34 12 00 00 FF 7F 00 00")
    );
    // Symbols and labels via the lookup.
    let look = |n: &str| (n.eq_ignore_ascii_case("target")).then_some(0x1100u64);
    assert_eq!(
        assemble_line("jmp target", 0x1000, 64, &look).unwrap(),
        hex("E9 FB 00 00 00")
    );
    assert_eq!(
        assemble_line("mov eax,[target+10]", 0x1000, 64, &look).unwrap(),
        hex("8B 05 0A 01 00 00")
    );
    // Errors, not panics.
    for bad in [
        "",
        "foo eax",
        "mov eax",
        "mov eax,ebx,ecx",
        "mov [rax",
        "mov eax,[rax*3]",
        "mov eax,unknownsym",
        "db 'x",
        "mov al,1234",
        "add eax,[rax+rbx+rcx]",
        "mov eax,cs:",
        "jmp",
        "dd 'abc'",
        "nop 99999999",
    ] {
        assert!(
            assemble_line(bad, 0x1000, 64, &no_syms).is_err(),
            "{bad:?} should fail"
        );
    }
}

#[test]
fn assemble_with_process_symbols() {
    let p = game64();
    let mut syms = SymbolTable::default();
    syms.register("hook", GAME64 + 0x2000);
    let b = assemble(&p, &syms, GAME64 + 0x1000, "jmp game.exe+1010\ncall hook").unwrap();
    assert_eq!(b, hex("EB 0E E8 F9 0F 00 00"));
}

// ---------------------------------------------------------------- expressions

#[test]
fn resolve_expressions() {
    let p = game64();
    let mut syms = SymbolTable::default();
    syms.register("Player", 0x2000_0000);
    let r = |e: &str| resolve_address(&p, &syms, e);
    assert_eq!(r("game.exe+1A2B").unwrap(), GAME64 + 0x1A2B);
    assert_eq!(r("\"game.exe\"+10").unwrap(), GAME64 + 0x10);
    assert_eq!(r("GAME.EXE").unwrap(), GAME64);
    assert_eq!(r("player+#16").unwrap(), 0x2000_0010);
    assert_eq!(r("[game.exe+3000]").unwrap(), 0x2000_0000);
    assert_eq!(r("[[game.exe+3000]+8]+8").unwrap(), 0x2000_0088);
    assert_eq!(r("[[[game.exe+3000]+8]+8]").unwrap(), 0x1234);
    assert_eq!(r("(10+6)*2").unwrap(), 0x2C);
    assert_eq!(r("100/2-#10").unwrap(), 0x76);
    assert_eq!(r("-1").unwrap(), u64::MAX);
    assert_eq!(r("0x10").unwrap(), 0x10);
    assert_eq!(r("$10").unwrap(), 0x10);
    assert_eq!(r("#10").unwrap(), 10);
    assert_eq!(r(" 7FF6ABCD ").unwrap(), 0x7FF6_ABCD);
    for bad in [
        "",
        "nosuch.dll+10",
        "[10",
        "1+",
        "(1",
        "[0]",
        "1/0",
        "a b",
        "game.exe+'x",
    ] {
        assert!(r(bad).is_err(), "{bad:?} should fail");
    }
    assert_eq!(syms.unregister("PLAYER"), Some(0x2000_0000));
    assert!(resolve_address(&p, &syms, "player").is_err());
}

// ---------------------------------------------------------------- auto assembler

const HEALTH_SCRIPT: &str = r#"
{ Game   : game.exe
  Author : test }
[ENABLE]
aobscanmodule(health,game.exe,29 81 E0 00 00 00 8B) // should be unique
alloc(newmem,$1000,health)
label(code)
label(return)
label(godmode)
registersymbol(health,godmode)

newmem:
  cmp byte ptr [godmode],1
  jne short @f
  xor eax,eax        /* no damage */
@@:
code:
  sub [rcx+000000E0],eax
  jmp return
godmode:
  db 01

health:
  jmp newmem
  nop
return:

[DISABLE]
health:
  db 29 81 E0 00 00 00

unregistersymbol(health)
unregistersymbol(godmode)
dealloc(newmem)
"#;

#[test]
fn aa_health_script_enable_disable() {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    assert_eq!(
        aa_check(&p, &syms, HEALTH_SCRIPT, &mut AaHooks::default()),
        None
    );
    assert_eq!(p.snapshot(), before, "check must not write");

    let st = aa_execute(
        &p,
        &mut syms,
        HEALTH_SCRIPT,
        true,
        None,
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(st.allocs.len(), 1);
    let newmem = st.allocs[0].addr;
    let hook = GAME64 + 0x1005;
    assert_eq!(syms.get("health"), Some(hook));
    let godmode = syms.get("godmode").unwrap();
    // jmp newmem ; nop
    let l = disassemble(&p, &syms, hook, 2).unwrap();
    assert_eq!(l[0].text, format!("jmp {newmem:X}"));
    assert_eq!(l[1].text, "nop");
    // Injected code, with a short jne over the xor and a RIP-relative flag.
    let l = disassemble(&p, &syms, newmem, 5).unwrap();
    let t: Vec<&str> = l.iter().map(|x| x.text.as_str()).collect();
    assert_eq!(t[0], format!("cmp byte ptr [{godmode:X}],1"));
    assert_eq!(l[1].bytes, hex("75 02"));
    assert_eq!(t[2], "xor eax,eax");
    assert_eq!(t[3], "sub [rcx+E0],eax");
    assert_eq!(t[4], format!("jmp {:X}", hook + 6));
    let mut flag = [0u8];
    p.read(godmode, &mut flag).unwrap();
    assert_eq!(flag[0], 1);
    // State is serializable for the IPC round trip.
    let st2: AaState = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
    assert_eq!(st2, st);

    aa_execute(
        &p,
        &mut syms,
        HEALTH_SCRIPT,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(
        p.snapshot(),
        before,
        "memory restored byte for byte, alloc freed"
    );
    assert_eq!(syms.get("health"), None);
    assert_eq!(syms.get("godmode"), None);
}

fn template_roundtrip(kind: Template) {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let script = injection_template(&p, GAME64 + 0x1005, kind).unwrap();
    assert_eq!(
        aa_check(&p, &syms, &script, &mut AaHooks::default()),
        None,
        "{script}"
    );
    let st = aa_execute(&p, &mut syms, &script, true, None, &mut AaHooks::default())
        .unwrap_or_else(|e| panic!("{e}\n{script}"));
    assert_ne!(p.snapshot(), before);
    let newmem = st.allocs[0].addr;
    // Hook jumps to newmem; the moved instruction runs there and jumps back.
    let l = disassemble(&p, &syms, GAME64 + 0x1005, 2).unwrap();
    assert_eq!(l[0].text, format!("jmp {newmem:X}"));
    assert_eq!(l[1].text, "nop");
    let moved = disassemble(&p, &syms, newmem, 2).unwrap();
    assert_eq!(moved[0].bytes, hex("29 81 E0 00 00 00"));
    assert_eq!(moved[1].text, format!("jmp {:X}", GAME64 + 0x100B));
    aa_execute(
        &p,
        &mut syms,
        &script,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(p.snapshot(), before, "{kind:?}");
}

#[test]
fn aa_code_injection_template() {
    template_roundtrip(Template::CodeInjection);
}

#[test]
fn aa_aob_injection_template() {
    let p = game64();
    let s = injection_template(&p, GAME64 + 0x1005, Template::AobInjection).unwrap();
    assert!(
        s.contains("aobscanmodule(INJECT,game.exe,29 81 E0 00 00 00"),
        "{s}"
    );
    template_roundtrip(Template::AobInjection);
}

#[test]
fn aa_full_injection_template() {
    template_roundtrip(Template::FullInjection);
}

#[test]
fn aa_rip_relative_instruction_is_moved_correctly() {
    // Inject over "mov eax,[game.exe+3020]" (RIP-relative): the moved copy must still read
    // game.exe+3020 from the new location.
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let script = injection_template(&p, GAME64 + 0x1011, Template::CodeInjection).unwrap();
    let st = aa_execute(&p, &mut syms, &script, true, None, &mut AaHooks::default()).unwrap();
    let l = disassemble(&p, &syms, st.allocs[0].addr, 1).unwrap();
    assert_eq!(l[0].text, format!("mov eax,[{:X}]", GAME64 + 0x3020));
    aa_execute(
        &p,
        &mut syms,
        &script,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(p.snapshot(), before);
}

const SCRIPT32: &str = r#"
define(hit,game.exe+10)
define(origbytes,89 46 04 8B C3)
[ENABLE]
assert(hit,origbytes)
alloc(cave,400)
label(back)
label(scale)
label(loop)
label(table)
registersymbol(scale)

cave:
  push ecx
  mov ecx,3
loop:
  dec ecx
  jnz loop
  pop ecx
  fild dword ptr [esi+04]
  fmul dword ptr [scale]
  fistp dword ptr [esi+04]
  mov [esi+04],eax
  mov eax,ebx
  jmp back
scale:
  dd (float)2.5
table:
  dd cave back 0

hit:
  jmp cave
back:

[DISABLE]
hit:
  db origbytes
dealloc(cave)
unregistersymbol(scale)
"#;

#[test]
fn aa_32bit_script() {
    let mut img = vec![0u8; 0x1000];
    img[0x10..0x15].copy_from_slice(&hex("89 46 04 8B C3"));
    let p = TestProc::new(4).module("game.exe", 0x40_0000, img);
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let st = aa_execute(&p, &mut syms, SCRIPT32, true, None, &mut AaHooks::default()).unwrap();
    let cave = st.allocs[0].addr;
    assert_eq!(
        st.originals.iter().find(|o| o.0 == 0x40_0010).unwrap().1,
        hex("89 46 04 8B C3")
    );
    let l = disassemble(&p, &syms, 0x40_0010, 1).unwrap();
    assert_eq!(l[0].text, format!("jmp {cave:X}"));
    let scale = syms.get("scale").unwrap();
    let mut f = [0u8; 16];
    p.read(scale, &mut f).unwrap();
    assert_eq!(f32::from_le_bytes(f[..4].try_into().unwrap()), 2.5);
    assert_eq!(u32::from_le_bytes(f[4..8].try_into().unwrap()) as u64, cave);
    assert_eq!(u32::from_le_bytes(f[8..12].try_into().unwrap()), 0x40_0015);
    let code = disassemble(&p, &syms, cave, 4).unwrap();
    assert_eq!(code[2].text, "dec ecx");
    assert_eq!(code[3].bytes, hex("75 FD"));
    aa_execute(
        &p,
        &mut syms,
        SCRIPT32,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(p.snapshot(), before);
    assert_eq!(syms.get("scale"), None);

    // assert() fails on different bytes, with the right line, and nothing is left behind.
    p.write(0x40_0010, &[0x90]).unwrap();
    let before = p.snapshot();
    let e = aa_check(&p, &syms, SCRIPT32, &mut AaHooks::default()).unwrap();
    assert_eq!(e.line, 5);
    assert!(e.message.contains("assert"), "{}", e.message);
    assert!(aa_execute(&p, &mut syms, SCRIPT32, true, None, &mut AaHooks::default()).is_err());
    assert_eq!(p.snapshot(), before);
}

#[test]
fn aa_check_reports_line_numbers() {
    let p = game64();
    let syms = SymbolTable::default();
    let h = &mut AaHooks::default();
    let cases = [
        (
            "[ENABLE]\nalloc(x,10)\nx:\n  mov eax,ebx\n  bogus eax\n[DISABLE]\n",
            5,
            "unknown instruction",
        ),
        (
            "[ENABLE]\nalloc(x,10)\nlabel(l)\nx:\n  jmp l\n[DISABLE]\n",
            5,
            "never defined",
        ),
        ("[ENABLE]\n  nop\n[DISABLE]\n", 2, "without an address"),
        (
            "[ENABLE]\naobscan(a,DE AD BE EF 11 22)\n[DISABLE]\n",
            2,
            "not found",
        ),
        ("[ENABLE]\n{$lua}\nreturn 1\n{$asm}\n[DISABLE]\n", 2, "Lua"),
        ("[ENABLE]\nalloc(x)\n[DISABLE]\n", 2, "expected 2"),
        (
            "[ENABLE]\n[DISABLE]\ngame.exe+1000:\n  db zz\n",
            4,
            "unknown symbol",
        ),
        ("[ENABLE]\n{$try}\n[DISABLE]\n", 2, "unsupported"),
    ];
    for (s, line, msg) in cases {
        let e = aa_check(&p, &syms, s, h).unwrap_or_else(|| panic!("no error for {s:?}"));
        assert_eq!(e.line, line, "{s:?}: {}", e.message);
        assert!(e.message.contains(msg), "{s:?}: {}", e.message);
    }
    assert_eq!(aa_check(&p, &syms, "[ENABLE]\n[DISABLE]\n", h), None);
}

#[test]
fn aa_without_disable_section_restores_originals() {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let script = "alloc(mem,100)\nregistersymbol(mem)\ngame.exe+1005:\n  nop 6\nmem:\n  readmem(game.exe+1005,6)\n  reassemble(game.exe+1011)\n";
    let st = aa_execute(&p, &mut syms, script, true, None, &mut AaHooks::default()).unwrap();
    let mem = syms.get("mem").unwrap();
    let mut b = [0u8; 12];
    p.read(mem, &mut b).unwrap();
    assert_eq!(&b[..6], &hex("29 81 E0 00 00 00")[..]);
    // reassembled RIP-relative load still targets game.exe+3020
    let l = disassemble(&p, &syms, mem + 6, 1).unwrap();
    assert_eq!(l[0].text, format!("mov eax,[{:X}]", GAME64 + 0x3020));
    aa_execute(
        &p,
        &mut syms,
        script,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(p.snapshot(), before);
    assert_eq!(syms.get("mem"), None);
}

#[test]
fn aa_hooks_and_globalalloc() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let mut hooks = AaHooks {
        lua: Some(Box::new(|src: String| {
            assert!(src.contains("return"));
            Ok("label(fromlua)\n".into())
        })),
        create_thread: Some(Box::new(|a| {
            assert_ne!(a, 0);
            Ok(())
        })),
        ..Default::default()
    };
    let script = "[ENABLE]\n{$lua}\nreturn 'x'\n{$asm}\nglobalalloc(shared,100)\nshared:\nfromlua:\n  ret\ncreatethread(fromlua)\n[DISABLE]\n";
    let st = aa_execute(&p, &mut syms, script, true, None, &mut hooks).unwrap();
    let g = syms.get("shared").unwrap();
    assert!(st.allocs.is_empty(), "globalalloc is never freed");
    // A second enable reuses the existing global allocation.
    aa_execute(&p, &mut syms, script, true, None, &mut hooks).unwrap();
    assert_eq!(syms.get("shared"), Some(g));
    // createthread without a hook is an error.
    let e = aa_execute(
        &p,
        &mut syms,
        script,
        true,
        None,
        &mut AaHooks {
            lua: hooks.lua.take(),
            ..Default::default()
        },
    );
    assert!(e.unwrap_err().to_string().contains("createthread"));
}

#[test]
fn aa_failed_write_rolls_back() {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    // Second write targets unmapped memory: the first must be undone and the alloc freed.
    let script =
        "[ENABLE]\nalloc(m,10)\nm:\n  ret\ngame.exe+1000:\n  nop 2\n1000:\n  nop\n[DISABLE]\n";
    assert!(aa_execute(&p, &mut syms, script, true, None, &mut AaHooks::default()).is_err());
    assert_eq!(p.snapshot(), before);
}

#[test]
fn aobscan_wildcards() {
    let p = game64();
    let hits = aob_scan(&p, 0, u64::MAX, "29 81 ?? 00 00 00 8B", 10).unwrap();
    assert_eq!(hits, vec![GAME64 + 0x1005]);
    let hits = aob_scan(&p, 0, u64::MAX, "2981*000000 8?", 10).unwrap();
    assert_eq!(hits, vec![GAME64 + 0x1005]);
    assert!(aob_scan(&p, 0, u64::MAX, "2G", 10).is_err());
}

#[test]
fn nop_helper() {
    let p = game64();
    let before = p.snapshot();
    let patch = nop_instruction(&p, GAME64 + 0x1005).unwrap();
    assert_eq!(patch.original, hex("29 81 E0 00 00 00"));
    let mut b = [0u8; 7];
    p.read(GAME64 + 0x1005, &mut b).unwrap();
    assert_eq!(b, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x8B]);
    restore_patch(&p, &patch).unwrap();
    assert_eq!(p.snapshot(), before);
    assert!(nop_instruction(&p, 0x10).is_err());
}

#[test]
fn works_with_hh_core_mock() {
    let p = hh_core::MockProcess::new(0x1000, vec![0; 0x100]);
    let syms = SymbolTable::default();
    let b = assemble(&p, &syms, 0x1000, "mov rax,[rip+10]").unwrap();
    p.write(0x1000, &b).unwrap();
    assert_eq!(
        disassemble(&p, &syms, 0x1000, 1).unwrap()[0].text,
        "mov rax,[1017]"
    );
    let st = aa_execute(
        &p,
        &mut syms.clone(),
        "[ENABLE]\n1010:\ndb 90\n[DISABLE]\n1010:\ndb 00\n",
        true,
        None,
        &mut AaHooks::default(),
    );
    assert!(st.is_ok());
}

/// Decodes pseudo-random bytes, reassembles every instruction from its disassembly text and
/// checks the result disassembles to the same text. Exercises the whole iced opcode table.
fn fuzz_roundtrip(ptr: usize, min_ok: f64) {
    let bits = if ptr == 4 { 32 } else { 64 };
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let bytes: Vec<u8> = (0..60_000)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        })
        .collect();
    let base = 0x1000_0000;
    let p = TestProc::new(ptr);
    p.map(base, bytes.clone());
    let syms = SymbolTable::default();
    let lines = disassemble(&p, &syms, base, 25_000).unwrap();
    let (mut ok, mut total) = (0, 0);
    for l in lines
        .iter()
        .filter(|l| !l.text.starts_with("db ") && l.text != "??" && !l.text.contains('{'))
    {
        total += 1;
        let Ok(b) = assemble_line(&l.text, l.addr, bits, &no_syms) else {
            continue;
        };
        let q = TestProc::new(ptr);
        q.map(l.addr, b.clone());
        let back = &disassemble(&q, &syms, l.addr, 1).unwrap()[0];
        if back.text == l.text && back.bytes.len() == b.len() {
            ok += 1;
        }
    }
    let rate = ok as f64 / total as f64;
    assert!(
        total > 10_000 && rate >= min_ok,
        "{bits}-bit round trip {ok}/{total}"
    );
}

#[test]
fn fuzz_roundtrip_64() {
    fuzz_roundtrip(8, 0.995);
}

#[test]
fn fuzz_roundtrip_32() {
    // Misses are mostly `jmp/call far seg:offset` and 16-bit address/operand prefixes.
    fuzz_roundtrip(4, 0.985);
}

#[test]
fn garbage_input_never_panics() {
    let p = game64();
    let syms = SymbolTable::default();
    let chars: Vec<char> = "[]+-*,:;'\"()@#$ \nabcdefrxst0123456789{}/movjmpdbqwp"
        .chars()
        .collect();
    let mut seed = 7u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    for _ in 0..20_000 {
        let len = next() % 30;
        let s: String = (0..len).map(|_| chars[next() % chars.len()]).collect();
        let _ = assemble_line(&s, 0x1000, 64, &no_syms);
        let _ = assemble_line(&format!("mov {s}"), 0x1000, 32, &no_syms);
        let _ = resolve_address(&p, &syms, &s);
        let _ = aa_check(
            &p,
            &syms,
            &format!("[ENABLE]\nalloc(m,10)\nm:\n{s}\n[DISABLE]\n{s}"),
            &mut AaHooks::default(),
        );
    }
}

// ---------------------------------------------------------------- names with '-' / '+'

fn dashed() -> TestProc {
    let mut img = vec![0u8; 0x4000];
    img[0x3000..0x3008].copy_from_slice(&0x2000_0000u64.to_le_bytes());
    img[0x3020..0x3024].copy_from_slice(&0x2Au32.to_le_bytes());
    let p = TestProc::new(8)
        .module("hh-target", 0x5555_0000_0000, img)
        .module("libstdc++.so.6", 0x7F00_0000_0000, vec![0; 0x1000])
        .module("ld-linux-x86-64.so.2", 0x7F10_0000_0000, vec![0; 0x1000])
        .module("My Game.exe", 0x40_0000, vec![0; 0x1000]);
    p.map(0x2000_0000, vec![0; 0x100]);
    p
}

#[test]
fn names_with_dashes_resolve_unquoted() {
    let p = dashed();
    let mut syms = SymbolTable::default();
    syms.register("base", 0x1000);
    syms.register("my-sym", 0x2000);
    let r = |e: &str| resolve_address(&p, &syms, e).unwrap_or_else(|e2| panic!("{e}: {e2}"));
    let t = 0x5555_0000_0000u64;
    assert_eq!(r("hh-target+10"), t + 0x10);
    assert_eq!(r("HH-Target+10"), t + 0x10);
    assert_eq!(r("\"hh-target\"+10"), t + 0x10);
    assert_eq!(r("hh-target-10"), t - 0x10);
    assert_eq!(r("hh-target+100-8"), t + 0xF8);
    assert_eq!(r("[hh-target+3000]+8"), 0x2000_0008);
    assert_eq!(r("libstdc++.so.6+10"), 0x7F00_0000_0010);
    assert_eq!(r("libstdc++.so.6"), 0x7F00_0000_0000);
    assert_eq!(r("ld-linux-x86-64.so.2+8"), 0x7F10_0000_0008);
    assert_eq!(r("base-10"), 0xFF0);
    assert_eq!(r("base - 10"), 0xFF0);
    assert_eq!(r("my-sym+4"), 0x2004);
    assert_eq!(r("my-sym-base"), 0x1000);
    assert_eq!(r("\"My Game.exe\"+4"), 0x40_0004);
    assert!(resolve_address(&p, &syms, "hh-nothing+10").is_err());

    // Assembler operands and branch targets.
    let b = assemble(
        &p,
        &syms,
        t + 0x1000,
        "mov eax,[hh-target+3020]\njmp hh-target+1010",
    )
    .unwrap();
    assert_eq!(b, hex("8B 05 1A 20 00 00 EB 08"));
    let b = assemble(&p, &syms, t + 0x1000, "mov eax,[\"hh-target\"+3020-0]").unwrap();
    assert_eq!(b, hex("8B 05 1A 20 00 00"));

    // Disassembler comments read back through resolve_address.
    p.write(t + 0x1000, &hex("8B 05 1A 20 00 00")).unwrap();
    p.write(0x40_0000, &hex("8B 05 00 00 00 00")).unwrap();
    for a in [t + 0x1000, 0x40_0000] {
        let l = &disassemble(&p, &syms, a, 1).unwrap()[0];
        let inner = &l.comment[1..l.comment.find(']').unwrap()];
        let want = if a == t + 0x1000 {
            t + 0x3020
        } else {
            0x40_0006
        };
        assert_eq!(r(inner), want, "{}", l.comment);
    }
    assert_eq!(module_symbols_names(&p, "hh-target"), Vec::<String>::new());
}

fn module_symbols_names(p: &TestProc, module: &str) -> Vec<String> {
    let m = p.mods.iter().find(|m| m.name == module).unwrap();
    module_symbols(p, m).into_iter().map(|s| s.name).collect()
}

#[test]
fn aa_script_with_dashed_module() {
    let p = dashed();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let script = "[ENABLE]\nalloc(mem,100,hh-target)\nlabel(back)\nregistersymbol(back)\nmem:\n  mov eax,[hh-target+3020]\n  jmp back\nhh-target+1000:\n  jmp mem\nback:\n[DISABLE]\nhh-target+1000:\n  db 00 00 00 00 00\ndealloc(mem)\nunregistersymbol(back)\n";
    let st = aa_execute(&p, &mut syms, script, true, None, &mut AaHooks::default()).unwrap();
    assert_eq!(syms.get("back"), Some(0x5555_0000_1005));
    let l = disassemble(&p, &syms, st.allocs[0].addr, 1).unwrap();
    assert_eq!(l[0].text, "mov eax,[555500003020]");
    aa_execute(
        &p,
        &mut syms,
        script,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(p.snapshot(), before);
}

// ---------------------------------------------------------------- PE / ELF symbols

fn put(b: &mut Vec<u8>, off: usize, v: u64, w: usize) {
    if b.len() < off + w {
        b.resize(off + w, 0);
    }
    b[off..off + w].copy_from_slice(&v.to_le_bytes()[..w]);
}

/// A minimal PE with one `.edata` section at RVA 0x1000 exporting `Sleep` (0x2100),
/// `GetTickCount` (0x2200) and a forwarder. `file`: file layout (raw data at 0x400) instead
/// of the mapped layout (raw == RVA), which also gets a code page at 0x2000.
fn build_pe(is64: bool, file: bool) -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[..2].copy_from_slice(b"MZ");
    put(&mut b, 0x3C, 0x40, 4);
    b[0x40..0x44].copy_from_slice(b"PE\0\0");
    put(&mut b, 0x46, 1, 2); // sections
    let optsz = if is64 { 240 } else { 224 };
    put(&mut b, 0x54, optsz, 2);
    let opt = 0x58;
    put(&mut b, opt, if is64 { 0x20b } else { 0x10b }, 2);
    let (nd, dirs) = if is64 { (108, 112) } else { (92, 96) };
    put(&mut b, opt + nd, 16, 4);
    put(&mut b, opt + dirs, 0x1000, 4);
    put(&mut b, opt + dirs + 4, 0x200, 4);
    let sec = opt + optsz as usize;
    b[sec..sec + 6].copy_from_slice(b".edata");
    put(&mut b, sec + 8, 0x1000, 4);
    put(&mut b, sec + 12, 0x1000, 4);
    put(&mut b, sec + 16, 0x1000, 4);
    let raw = if file { 0x400 } else { 0x1000 };
    put(&mut b, sec + 20, raw, 4);
    b.resize(raw as usize + 0x1000, 0);
    let at = |rva: usize| raw as usize + rva - 0x1000;
    // Export directory: 3 functions, 3 names (sorted), arrays at 0x1028/0x1040/0x1050.
    put(&mut b, at(0x1000 + 20), 3, 4);
    put(&mut b, at(0x1000 + 24), 3, 4);
    put(&mut b, at(0x1000 + 28), 0x1028, 4);
    put(&mut b, at(0x1000 + 32), 0x1040, 4);
    put(&mut b, at(0x1000 + 36), 0x1050, 4);
    for (i, f) in [0x2100u64, 0x2200, 0x1100].iter().enumerate() {
        put(&mut b, at(0x1028 + i * 4), *f, 4);
    }
    let names = ["Forwarded", "GetTickCount", "Sleep"];
    let ords = [2u64, 1, 0];
    let mut s = 0x1080;
    for (i, n) in names.iter().enumerate() {
        put(&mut b, at(0x1040 + i * 4), s as u64, 4);
        put(&mut b, at(0x1050 + i * 2), ords[i], 2);
        b[at(s)..at(s) + n.len()].copy_from_slice(n.as_bytes());
        s += n.len() + 1;
    }
    b[at(0x1100)..at(0x1100) + 12].copy_from_slice(b"NTDLL.RtlFoo");
    if !file {
        b.resize(0x3000, 0xCC);
    }
    b
}

/// A minimal ELF shared object (file layout == memory layout, loaded at vaddr 0) defining
/// `malloc` (0x1100, size 0x20) and `free` (0x1200), plus an undefined `puts` and a TLS
/// symbol that must be skipped. `gnu`: DT_GNU_HASH instead of DT_HASH. `sections`: emit
/// section headers (else only PT_DYNAMIC describes the symbols).
fn build_elf(is64: bool, gnu: bool, sections: bool) -> Vec<u8> {
    let w = if is64 { 8 } else { 4 };
    let (eh, ph, sh, se) = if is64 {
        (64, 56, 64, 24)
    } else {
        (52, 32, 40, 16)
    };
    let mut b = vec![0u8; 0x2000];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = if is64 { 2 } else { 1 };
    b[5] = 1;
    b[6] = 1;
    put(&mut b, 16, 3, 2);
    let (phoff, shoff) = (eh, 0x800);
    let o = |o32: usize, o64: usize| if is64 { o64 } else { o32 };
    put(&mut b, o(28, 32), phoff as u64, w);
    put(&mut b, o(32, 40), if sections { shoff } else { 0 }, w);
    put(&mut b, o(42, 54), ph as u64, 2);
    put(&mut b, o(44, 56), 2, 2);
    put(&mut b, o(46, 58), sh as u64, 2);
    put(&mut b, o(48, 60), if sections { 3 } else { 0 }, 2);
    let (dynsym, dynstr, hash, dynamic) = (0x400usize, 0x500usize, 0x600usize, 0x700usize);
    // Program headers: PT_LOAD everything, PT_DYNAMIC.
    let phdr = |b: &mut Vec<u8>, i: usize, typ: u64, off: u64, sz: u64| {
        let p = phoff + i * ph;
        put(b, p, typ, 4);
        if is64 {
            put(b, p + 8, off, 8);
            put(b, p + 16, off, 8);
            put(b, p + 32, sz, 8);
            put(b, p + 40, sz, 8);
        } else {
            put(b, p + 4, off, 4);
            put(b, p + 8, off, 4);
            put(b, p + 16, sz, 4);
            put(b, p + 20, sz, 4);
        }
    };
    phdr(&mut b, 0, 1, 0, 0x2000);
    phdr(&mut b, 1, 2, dynamic as u64, 0x60);
    // Strings and symbols: (name, value, size, info, shndx)
    let strs = b"\0malloc\0free\0puts\0tlsvar\0";
    b[dynstr..dynstr + strs.len()].copy_from_slice(strs);
    let syms: [(u64, u64, u64, u8, u64); 5] = [
        (0, 0, 0, 0, 0),
        (1, 0x1100, 0x20, 0x12, 5), // GLOBAL FUNC
        (8, 0x1200, 0x10, 0x12, 5), // GLOBAL FUNC
        (13, 0, 0, 0x12, 0),        // undefined
        (18, 0x10, 4, 0x16, 6),     // TLS
    ];
    for (i, (n, v, s, info, shndx)) in syms.iter().enumerate() {
        let e = dynsym + i * se;
        put(&mut b, e, *n, 4);
        if is64 {
            b[e + 4] = *info;
            put(&mut b, e + 6, *shndx, 2);
            put(&mut b, e + 8, *v, 8);
            put(&mut b, e + 16, *s, 8);
        } else {
            put(&mut b, e + 4, *v, 4);
            put(&mut b, e + 8, *s, 4);
            b[e + 12] = *info;
            put(&mut b, e + 14, *shndx, 2);
        }
    }
    let hash_tag = if gnu {
        // nbuckets 1, symoffset 1, bloom 1 word; bucket -> 1; chain ends at the last symbol.
        put(&mut b, hash, 1, 4);
        put(&mut b, hash + 4, 1, 4);
        put(&mut b, hash + 8, 1, 4);
        let buckets = hash + 16 + w;
        put(&mut b, buckets, 1, 4);
        for i in 0..4 {
            put(&mut b, buckets + 4 + i * 4, if i == 3 { 1 } else { 2 }, 4);
        }
        0x6fff_fef5
    } else {
        put(&mut b, hash, 1, 4);
        put(&mut b, hash + 4, 5, 4);
        4
    };
    for (i, (t, v)) in [
        (hash_tag, hash as u64),
        (6, dynsym as u64),
        (5, dynstr as u64),
        (10, strs.len() as u64),
        (0, 0),
    ]
    .iter()
    .enumerate()
    {
        put(&mut b, dynamic + i * 2 * w, *t, w);
        put(&mut b, dynamic + i * 2 * w + w, *v, w);
    }
    if sections {
        // null, .dynsym (link 2), .dynstr
        for (i, (typ, off, size, link)) in [
            (0u64, 0u64, 0u64, 0u64),
            (11, dynsym as u64, 5 * se as u64, 2),
            (3, dynstr as u64, strs.len() as u64, 0),
        ]
        .iter()
        .enumerate()
        {
            let s = shoff as usize + i * sh;
            put(&mut b, s + 4, *typ, 4);
            if is64 {
                put(&mut b, s + 24, *off, 8);
                put(&mut b, s + 32, *size, 8);
                put(&mut b, s + 40, *link, 4);
            } else {
                put(&mut b, s + 16, *off, 4);
                put(&mut b, s + 20, *size, 4);
                put(&mut b, s + 24, *link, 4);
            }
        }
    }
    b
}

fn names(v: &[Symbol]) -> Vec<(String, Addr)> {
    let mut v: Vec<_> = v.iter().map(|s| (s.name.clone(), s.addr)).collect();
    v.sort();
    v
}

#[test]
fn pe_exports_from_file_and_memory() {
    for is64 in [true, false] {
        let base = if is64 { 0x7FF8_0000_0000 } else { 0x7700_0000 };
        let want = vec![
            ("GetTickCount".to_string(), base + 0x2200),
            ("Sleep".to_string(), base + 0x2100),
        ];
        assert_eq!(
            names(&parse_symbols(&build_pe(is64, true), base).unwrap()),
            want
        );
        // Memory fallback: the module path does not exist.
        let p = TestProc::new(if is64 { 8 } else { 4 }).module(
            "kernel32.dll",
            base,
            build_pe(is64, false),
        );
        assert_eq!(names(&module_symbols(&p, &p.mods[0])), want);
        let syms = SymbolTable::default();
        let r = |e: &str| resolve_address(&p, &syms, e).unwrap_or_else(|x| panic!("{e}: {x}"));
        assert_eq!(r("kernel32.Sleep"), base + 0x2100);
        assert_eq!(r("KERNEL32.DLL.sleep+4"), base + 0x2104);
        assert_eq!(r("GetTickCount"), base + 0x2200);
        assert!(resolve_address(&p, &syms, "kernel32.Forwarded").is_err());
    }
}

#[test]
fn disassembler_names_call_targets() {
    let base = 0x7FF9_0000_0000u64;
    let p = TestProc::new(8).module("kernel32.dll", base, build_pe(true, false));
    // +2000: call Sleep ; call [rip+slot] ; jmp [rip+slot]   slot at +2080 holds GetTickCount
    p.write(
        base + 0x2000,
        &hex("E8 FB 00 00 00 FF 15 75 00 00 00 FF 25 6F 00 00 00"),
    )
    .unwrap();
    p.write(base + 0x2080, &(base + 0x2200).to_le_bytes())
        .unwrap();
    let syms = SymbolTable::default();
    let l = disassemble(&p, &syms, base + 0x2000, 3).unwrap();
    assert_eq!(l[0].comment, "kernel32.dll.Sleep");
    assert_eq!(
        l[1].comment,
        "[kernel32.dll+2080]->kernel32.dll.GetTickCount"
    );
    assert_eq!(
        l[2].comment,
        "[kernel32.dll+2080]->kernel32.dll.GetTickCount"
    );
    assert_eq!(
        symbol_at(&p, &syms, base + 0x2104).as_deref(),
        Some("kernel32.dll+2104")
    );
    // Every annotation reads back.
    assert_eq!(
        resolve_address(&p, &syms, "kernel32.dll.GetTickCount").unwrap(),
        base + 0x2200
    );
}

#[test]
fn elf_symbols_sections_dynamic_and_memory() {
    let mut n = 0u64;
    for is64 in [true, false] {
        for gnu in [false, true] {
            for sections in [true, false] {
                n += 1;
                let base = 0x6000_0000_0000 + n * 0x100_0000;
                let img = build_elf(is64, gnu, sections);
                let want = vec![
                    ("free".to_string(), base + 0x1200),
                    ("malloc".to_string(), base + 0x1100),
                ];
                let ctx = format!("is64={is64} gnu={gnu} sections={sections}");
                assert_eq!(names(&parse_symbols(&img, base).unwrap()), want, "{ctx}");
                // From memory, with the dynamic pointers relocated by the loader for 64-bit.
                let mut mem = img.clone();
                if is64 {
                    for i in 0..5 {
                        let e = 0x700 + i * 16;
                        let tag = u64::from_le_bytes(mem[e..e + 8].try_into().unwrap());
                        if matches!(tag, 4 | 5 | 6 | 0x6fff_fef5) {
                            let v = u64::from_le_bytes(mem[e + 8..e + 16].try_into().unwrap());
                            mem[e + 8..e + 16].copy_from_slice(&(v + base).to_le_bytes());
                        }
                    }
                }
                let p = TestProc::new(8).module(&format!("libfake{n}.so.1"), base, mem);
                assert_eq!(names(&module_symbols(&p, &p.mods[0])), want, "{ctx}");
                let syms = SymbolTable::default();
                let name = format!("libfake{n}.so.1.malloc+4");
                assert_eq!(resolve_address(&p, &syms, &name).unwrap(), base + 0x1104);
                assert_eq!(
                    symbol_at(&p, &syms, base + 0x1110).as_deref(),
                    Some(format!("libfake{n}.so.1.malloc+10").as_str())
                );
                // Past the symbol's size: plain module offset.
                assert_eq!(
                    symbol_at(&p, &syms, base + 0x1120).as_deref(),
                    Some(format!("libfake{n}.so.1+1120").as_str())
                );
            }
        }
    }
}

#[test]
fn symbols_prefer_the_file_on_disk() {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("hh_asm_libdisk.so");
    std::fs::write(&path, build_elf(true, false, true)).unwrap();
    let base = 0x6100_0000_0000;
    let mut p = TestProc::new(8);
    p.mods.push(Module {
        name: "libdisk.so".into(),
        path: path.to_string_lossy().into(),
        base,
        size: 0x2000,
    });
    p.map(base, vec![0; 0x2000]); // memory has no headers at all
    assert_eq!(
        resolve_address(&p, &SymbolTable::default(), "malloc").unwrap(),
        base + 0x1100
    );
}

#[cfg(target_os = "linux")]
#[test]
fn parses_own_executable() {
    let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let syms = parse_symbols(&exe, 0x10_0000).unwrap();
    assert!(
        syms.iter().any(|s| s.name == "main"),
        "{} symbols",
        syms.len()
    );
}

#[test]
fn corrupt_images_never_panic() {
    let mut seed = 99u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let images = [
        build_pe(true, true),
        build_pe(false, true),
        build_pe(true, false),
        build_elf(true, true, true),
        build_elf(false, false, true),
        build_elf(true, false, false),
    ];
    let mut k = 0u64;
    for img in &images {
        // Every truncation.
        for len in (0..img.len()).step_by(7) {
            let _ = parse_symbols(&img[..len], 0x1000);
        }
        // Random corruption, through both the file parser and the memory fallback.
        for _ in 0..300 {
            let mut b = img.clone();
            for _ in 0..1 + next() % 8 {
                let i = next() % b.len();
                b[i] = match next() % 3 {
                    0 => 0xFF,
                    1 => 0,
                    _ => next() as u8,
                };
            }
            let _ = parse_symbols(&b, 0x1000);
            k += 1;
            let p = TestProc::new(8).module("corrupt.so", 0x3000_0000_0000 + k * 0x10_0000, b);
            let _ = module_symbols(&p, &p.mods[0]);
            let _ = resolve_address(&p, &SymbolTable::default(), "corrupt.so.malloc");
        }
    }
    assert!(parse_symbols(b"", 0).is_err());
    assert!(parse_symbols(b"\x7fELF", 0).is_err());
    assert!(parse_symbols(b"MZ", 0).is_err());
}

// ---------------------------------------------------------------- instruction analysis

fn regs(v: &[(&str, u64)]) -> Registers {
    v.iter().map(|(k, x)| (k.to_string(), *x)).collect()
}

#[test]
fn analysis_flow_kinds_and_targets() {
    let p = TestProc::new(8);
    let code = hex("E8 0B 00 00 00 75 05 EB 03 FF D0 C3 FF 24 25 00 00 00 20 FF 20 CD 80 90 0F 05");
    p.map(0x1000, code);
    let mut stack = vec![0u8; 0x100];
    stack[0x10..0x18].copy_from_slice(&0x4242u64.to_le_bytes());
    stack[0x20..0x28].copy_from_slice(&0x7777u64.to_le_bytes());
    p.map(0x2000_0000, stack);
    let r = regs(&[("rax", 0x2000_0020), ("rsp", 0x2000_0010)]);
    let a = |addr| analyze_instruction(&p, addr, Some(&r)).unwrap();
    let call = a(0x1000);
    assert_eq!(
        (call.kind, call.target, call.next()),
        (FlowKind::Call, Some(0x1010), 0x1005)
    );
    assert_eq!(
        (a(0x1005).kind, a(0x1005).target),
        (FlowKind::CondJump, Some(0x100C))
    );
    assert_eq!(
        (a(0x1007).kind, a(0x1007).target),
        (FlowKind::Jump, Some(0x100C))
    );
    assert_eq!(
        (a(0x1009).kind, a(0x1009).target),
        (FlowKind::Call, Some(0x2000_0020))
    );
    assert_eq!(
        (a(0x100B).kind, a(0x100B).target),
        (FlowKind::Ret, Some(0x4242))
    );
    // jmp [20000000] reads the pointer; jmp [rax] too.
    assert_eq!(
        (a(0x100C).kind, a(0x100C).target),
        (FlowKind::Jump, Some(0))
    );
    assert_eq!(
        (a(0x1013).kind, a(0x1013).target),
        (FlowKind::Jump, Some(0x7777))
    );
    assert_eq!(a(0x1015).kind, FlowKind::Interrupt);
    assert_eq!(a(0x1017).kind, FlowKind::Normal);
    assert_eq!(a(0x1018).kind, FlowKind::Interrupt);
    // Without registers indirect targets are unknown.
    assert_eq!(analyze_instruction(&p, 0x1009, None).unwrap().target, None);
    assert!(analyze_instruction(&p, 0x10, None).is_err());
}

#[test]
fn analysis_memory_accesses() {
    let p = TestProc::new(8);
    // mov [rax+rcx*4+8],edx ; add [rbx],al ; push rax ; movsb ; lea rax,[rbx] ; mov eax,fs:[30] ; mov eax,[rip+10]
    p.map(
        0x1000,
        hex("89 54 88 08 00 03 50 A4 48 8D 03 64 8B 04 25 30 00 00 00 8B 05 10 00 00 00"),
    );
    let r = regs(&[
        ("rax", 0x100),
        ("rcx", 2),
        ("rbx", 0x500),
        ("rsp", 0x8000),
        ("rsi", 0x10),
        ("rdi", 0x20),
        ("fs_base", 0x7000),
    ]);
    let m = |a| memory_accesses(&p, a, &r).unwrap();
    assert_eq!(
        m(0x1000),
        vec![MemAccess {
            addr: 0x110,
            size: 4,
            read: false,
            write: true
        }]
    );
    assert_eq!(
        m(0x1004),
        vec![MemAccess {
            addr: 0x500,
            size: 1,
            read: true,
            write: true
        }]
    );
    assert_eq!(
        m(0x1006),
        vec![MemAccess {
            addr: 0x7FF8,
            size: 8,
            read: false,
            write: true
        }]
    );
    let movsb = m(0x1007);
    assert!(movsb.contains(&MemAccess {
        addr: 0x10,
        size: 1,
        read: true,
        write: false
    }));
    assert!(movsb.contains(&MemAccess {
        addr: 0x20,
        size: 1,
        read: false,
        write: true
    }));
    assert_eq!(m(0x1008), vec![]);
    assert_eq!(
        m(0x100B),
        vec![MemAccess {
            addr: 0x7030,
            size: 4,
            read: true,
            write: false
        }]
    );
    assert_eq!(
        m(0x1013),
        vec![MemAccess {
            addr: 0x1029,
            size: 4,
            read: true,
            write: false
        }]
    );
    // 32-bit sub-registers come from the full ones; a missing register drops the access.
    assert_eq!(
        memory_accesses(&p, 0x1000, &regs(&[("rax", 0x100)])).unwrap(),
        vec![]
    );
    let p32 = TestProc::new(4);
    p32.map(0x1000, hex("89 54 88 08"));
    let r32 = regs(&[("eax", 0x100), ("ecx", 2)]);
    assert_eq!(memory_accesses(&p32, 0x1000, &r32).unwrap()[0].addr, 0x110);
}

#[test]
fn analysis_instruction_before_trap() {
    let p = game64();
    // Data breakpoint fired after "sub [rcx+E0],eax" (game.exe+1005, 6 bytes).
    let i = instruction_before(&p, GAME64 + 0x100B).unwrap();
    assert_eq!(
        (i.addr, i.text.as_str()),
        (GAME64 + 0x1005, "sub [rcx+E0],eax")
    );
    // Ambiguous tail: "B8 89 08 00 00" decodes as mov eax,889 from -5 but the data access
    // "mov [rax],ecx" (89 08) also ends there; the memory access wins.
    let q = TestProc::new(8);
    q.map(0x1000, hex("90 90 90 90 B8 89 08 00 00 C3"));
    let i = instruction_before(&q, 0x1007).unwrap();
    assert_eq!(i.text, "mov [rax],ecx");
    assert!(instruction_before(&q, 0x0).is_err());
}

// ---------------------------------------------------------------- auto assembler additions

#[test]
fn aa_struct_and_label_offsets() {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let script = "[ENABLE]\nstruct player\n  hp: dd ?\n  pos: resd 3\n  name:\n    db 'abcd',0\n  flags: dw ?\nends\nalloc(m,100)\nlabel(exit)\nregistersymbol(m)\nm:\n  mov eax,[rbx+pos]\n  mov [rbx+player.flags],ax\nexit:\n  ret\n  ret\nexit+1:\n  int3\n[DISABLE]\ndealloc(*)\nunregistersymbol(m)\n";
    assert_eq!(aa_check(&p, &syms, script, &mut AaHooks::default()), None);
    let st = aa_execute(&p, &mut syms, script, true, None, &mut AaHooks::default()).unwrap();
    let m = syms.get("m").unwrap();
    let l = disassemble(&p, &syms, m, 4).unwrap();
    let t: Vec<&str> = l.iter().map(|x| x.text.as_str()).collect();
    assert_eq!(t, ["mov eax,[rbx+4]", "mov [rbx+15],ax", "ret", "int3"]);
    aa_execute(
        &p,
        &mut syms,
        script,
        false,
        Some(&st),
        &mut AaHooks::default(),
    )
    .unwrap();
    assert_eq!(p.snapshot(), before, "dealloc(*) freed everything");
}

#[test]
fn aa_new_errors() {
    let p = game64();
    let syms = SymbolTable::default();
    let h = &mut AaHooks::default();
    let cases = [
        (
            // CE's default declares `foo:` implicitly; {$strict} makes it an error.
            "[ENABLE]\n{$strict}\nalloc(x,10)\nx:\nfoo:\n  nop\n[DISABLE]\n",
            5,
            "not declared",
        ),
        ("[ENABLE]\nkalloc(x,10)\n[DISABLE]\n", 2, "kernel mode"),
        (
            "[ENABLE]\nsharedallocate(x,10)\n[DISABLE]\n",
            2,
            "sharedallocate",
        ),
        (
            "[ENABLE]\nstruct s\n  a: dd ?\n[DISABLE]\n",
            2,
            "without ends",
        ),
        (
            "[ENABLE]\naobscanmodule(a,game.exe,DE AD BE EF 11 22)\n[DISABLE]\n",
            2,
            "not found in module game.exe",
        ),
        (
            "[ENABLE]\naobscanregion(a,game.exe,game.exe+10,29 81)\n[DISABLE]\n",
            2,
            "not found in",
        ),
        ("[ENABLE]\nnope+2:\n  nop\n[DISABLE]\n", 2, "unknown symbol"),
    ];
    for (s, line, msg) in cases {
        let e = aa_check(&p, &syms, s, h).unwrap_or_else(|| panic!("no error for {s:?}"));
        assert_eq!(e.line, line, "{s:?}: {}", e.message);
        assert!(e.message.contains(msg), "{s:?}: {}", e.message);
    }
}

#[test]
fn aa_try_except_shared_and_hook_rollback() {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let mut hooks = AaHooks {
        try_except: Some(Box::new(move |(t, e)| {
            s2.lock().unwrap().push((t, e));
            Ok(())
        })),
        shared_alloc: Some(Box::new(|(name, size)| {
            assert_eq!((name.as_str(), size), ("shared", 100));
            Ok(0x2000_0040)
        })),
        ..Default::default()
    };
    let script = "[ENABLE]\nalloc(m,100)\nsharedallocate(shared,100)\nm:\n{$try}\n  mov eax,[rax]\n  jmp @f\n{$except}\n  xor eax,eax\n@@:\n  ret\n[DISABLE]\ndealloc(m)\n";
    assert_eq!(aa_check(&p, &syms, script, &mut hooks), None);
    assert!(seen.lock().unwrap().is_empty(), "check calls no hooks");
    let st = aa_execute(&p, &mut syms, script, true, None, &mut hooks).unwrap();
    let m = st.allocs[0].addr;
    assert_eq!(*seen.lock().unwrap(), vec![(m, m + 4)]);
    assert_eq!(syms.get("shared"), Some(0x2000_0040));
    aa_execute(&p, &mut syms, script, false, Some(&st), &mut hooks).unwrap();

    // A failing post-write hook undoes the whole enable.
    let snap = p.snapshot();
    let script = "[ENABLE]\nalloc(m,100)\nregistersymbol(m)\nm:\n  ret\ngame.exe+1005:\n  nop 6\ncreatethread(m)\n[DISABLE]\n";
    let mut hooks = AaHooks {
        create_thread: Some(Box::new(|_| Err(Error::Other("no threads today".into())))),
        ..Default::default()
    };
    let e = aa_execute(&p, &mut syms, script, true, None, &mut hooks).unwrap_err();
    assert!(e.to_string().contains("no threads today"), "{e}");
    assert_eq!(p.snapshot(), snap);
    assert_eq!(syms.get("m"), None);
    let _ = before;
}

// ---------------------------------------------------------------- assembler syntax additions

#[test]
fn assembler_avx512_far_movabs_16bit() {
    let a64 =
        |t: &str| assemble_line(t, 0x1000, 64, &no_syms).unwrap_or_else(|e| panic!("{t}: {e}"));
    let a32 =
        |t: &str| assemble_line(t, 0x40_0000, 32, &no_syms).unwrap_or_else(|e| panic!("{t}: {e}"));
    assert_eq!(
        a64("vaddps zmm0{k1}{z},zmm1,zmm2"),
        hex("62 F1 74 C9 58 C2")
    );
    assert_eq!(
        a64("vaddps zmm0,zmm1,[rax]{1to16}"),
        hex("62 F1 74 58 58 00")
    );
    assert_eq!(
        a64("vaddps zmm0{rne-sae},zmm1,zmm2"),
        hex("62 F1 74 18 58 C2")
    );
    assert_eq!(
        a64("vaddps zmm0,zmm1,zmm2,{rz-sae}"),
        hex("62 F1 74 78 58 C2")
    );
    assert_eq!(
        a64("vpgatherdd zmm0{k1},[rax+zmm1*4]"),
        hex("62 F2 7D 49 90 04 88")
    );
    assert_eq!(
        a64("movabs rax,1122334455667788"),
        hex("48 B8 88 77 66 55 44 33 22 11")
    );
    assert_eq!(
        a64("movabs rax,[1122334455667788]"),
        hex("48 A1 88 77 66 55 44 33 22 11")
    );
    assert_eq!(
        a64("mov [1122334455667788],al"),
        hex("A2 88 77 66 55 44 33 22 11")
    );
    assert_eq!(a32("jmp 0010:00401000"), hex("EA 00 10 40 00 10 00"));
    assert_eq!(a32("jmp far 401000,10"), hex("EA 00 10 40 00 10 00"));
    assert_eq!(a32("call 0010:00401000"), hex("9A 00 10 40 00 10 00"));
    assert_eq!(a32("jmp far fword ptr [403000]"), hex("FF 2D 00 30 40 00"));
    assert_eq!(a32("mov eax,[bx+si]"), hex("67 8B 00"));
    assert_eq!(a32("mov eax,[si+bx]"), hex("67 8B 00"));
    assert_eq!(a32("mov eax,[bp+di+10]"), hex("67 8B 43 10"));
    for bad in [
        "vaddps zmm0{k9},zmm1,zmm2",
        "vaddps zmm0{k1,zmm1,zmm2",
        "vaddps xmm0{z},xmm1,xmm2,{bogus}",
        "addps xmm0{k1},xmm1",
        "jmp 0010:00401000",
        "mov eax,[bx+si+rax]",
    ] {
        assert!(assemble_line(bad, 0x1000, 64, &no_syms).is_err(), "{bad}");
    }
    assert!(assemble_line("jmp 10000:0", 0x1000, 32, &no_syms).is_err());
}

/// Random EVEX instructions must reassemble to the same text.
#[test]
fn evex_roundtrip() {
    use iced_x86::{Decoder, EncodingKind};
    for (bits, ptr) in [(64u32, 8usize), (32, 4)] {
        let mut seed = 0x1234_5678u64;
        let (mut ok, mut total) = (0, 0);
        for _ in 0..200_000 {
            let mut b = [0x62u8; 13];
            for x in &mut b[1..] {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *x = (seed >> 33) as u8;
            }
            let ins = Decoder::with_ip(bits, &b, 0x1000_0000, 0).decode();
            if ins.is_invalid() || ins.encoding() != EncodingKind::EVEX {
                continue;
            }
            total += 1;
            let p = TestProc::new(ptr);
            p.map(0x1000_0000, b[..ins.len()].to_vec());
            let l = &disassemble(&p, &SymbolTable::default(), 0x1000_0000, 1).unwrap()[0];
            if let Ok(again) = assemble_line(&l.text, l.addr, bits, &no_syms) {
                let q = TestProc::new(ptr);
                q.map(l.addr, again.clone());
                let back = &disassemble(&q, &SymbolTable::default(), l.addr, 1).unwrap()[0];
                ok += usize::from(back.text == l.text && back.bytes.len() == again.len());
            }
        }
        assert!(
            total > 50 && ok as f64 / total as f64 >= 0.99,
            "{bits}-bit EVEX {ok}/{total}"
        );
    }
}

// ---------------------------------------------------------------- bulk disassembly

#[test]
fn bulk_disassembly_matches_single_steps() {
    // Random code crossing 64 KiB block boundaries and ending at a region edge.
    let mut seed = 5u64;
    let bytes: Vec<u8> = (0..0x2_1003)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        })
        .collect();
    let p = TestProc::new(8);
    p.map(0x1000_0000, bytes);
    let syms = SymbolTable::default();
    let bulk = disassemble(&p, &syms, 0x1000_0000, 70_000).unwrap();
    let mut a = 0x1000_0000;
    for (i, l) in bulk.iter().enumerate() {
        if i % 97 == 0 || l.addr > 0x1002_0FF0 {
            assert_eq!(&disassemble(&p, &syms, a, 1).unwrap()[0], l, "at {a:X}");
        }
        assert_eq!(l.addr, a);
        a += l.bytes.len().max(1) as u64;
    }
    assert_eq!(bulk.last().unwrap().text, "??");
}

#[test]
#[ignore = "benchmark: cargo test -p hh-asm --release -- --ignored --nocapture"]
fn bench_disassembly() {
    let mut seed = 11u64;
    let bytes: Vec<u8> = (0..0x40_0000)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        })
        .collect();
    let p = game64();
    p.map(0x3000_0000, bytes);
    let syms = SymbolTable::default();
    let n = 200_000;
    let t = std::time::Instant::now();
    let l = disassemble(&p, &syms, 0x3000_0000, n).unwrap();
    let dt = t.elapsed().as_secs_f64();
    assert_eq!(l.len(), n);
    println!(
        "disassembly: {n} instructions in {dt:.3}s = {:.0} instructions/s",
        n as f64 / dt
    );
}

#[test]
fn aa_lua_block_reaches_hook_verbatim() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let lua = "local t = {1, 2} -- a table\nlocal q = 7 // 2 /* not a comment in Lua */\nreturn 'label(x)'\n";
    let got = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
    let g = got.clone();
    let mut hooks = AaHooks {
        lua: Some(Box::new(move |src: String| {
            g.lock().unwrap().push(src);
            Ok("alloc(x,10)\n".into())
        })),
        ..Default::default()
    };
    // The block sits after a { comment } and before code, so line numbers must survive.
    let script =
        format!("[ENABLE]\n{{ header }}\n{{$lua}}\n{lua}{{$asm}}\nx:\n  bogus\n[DISABLE]\n");
    let e = aa_check(&p, &syms, &script, &mut hooks).unwrap();
    assert_eq!(e.line, 9, "{}", e.message);
    assert_eq!(got.lock().unwrap()[0], lua);
    let ok = script.replace("  bogus", "  ret");
    let st = aa_execute(&p, &mut syms, &ok, true, None, &mut hooks).unwrap();
    assert_eq!(got.lock().unwrap().last().unwrap(), lua);
    assert_eq!(st.allocs.len(), 1);
    aa_execute(&p, &mut syms, &ok, false, Some(&st), &mut hooks).unwrap();
}

// ---------------------------------------------------------------- hostile input (release audit)

fn check_msg(p: &TestProc, script: &str, hooks: &mut AaHooks) -> String {
    aa_check(p, &SymbolTable::default(), script, hooks)
        .map(|e| e.message)
        .unwrap_or_default()
}

#[test]
fn deep_expressions_error_instead_of_overflowing_the_stack() {
    let p = game64();
    let syms = SymbolTable::default();
    let deep = format!("dd {}1{}", "(".repeat(10_000), ")".repeat(10_000));
    assert!(assemble_line(&deep, 0x1000, 64, &no_syms).is_err());
    let unary = format!("{}1", "-".repeat(100_000));
    assert!(resolve_address(&p, &syms, &unary).is_err());
    let ptrs = format!("{}1000{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(resolve_address(&p, &syms, &ptrs).is_err());
    // Reasonable nesting still works.
    let ok = format!("{}1{}", "(".repeat(200), ")".repeat(200));
    assert_eq!(resolve_address(&p, &syms, &ok).unwrap(), 1);
    assert_eq!(resolve_address(&p, &syms, "--1").unwrap(), 1);
}

#[test]
fn chained_defines_are_capped_and_fast() {
    let p = game64();
    let mut s = String::from("define(a0,x)\n");
    for i in 1..40 {
        s += &format!("define(a{i},a{} a{})\n", i - 1, i - 1);
    }
    s += "[ENABLE]\n[DISABLE]\n";
    let t = std::time::Instant::now();
    let m = check_msg(&p, &s, &mut AaHooks::default());
    assert!(m.contains("expands to more than"), "{m}");
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
    // A long line with many replacements stays linear.
    let line = "v ".repeat(200_000);
    let s = format!("define(v,1)\n[ENABLE]\nalloc(m,10)\nm:\ndb {line}\n[DISABLE]\n");
    let t = std::time::Instant::now();
    assert_eq!(check_msg(&p, &s, &mut AaHooks::default()), "");
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
    // Whole-word replacement only.
    let s = "define(a,90)\n[ENABLE]\nalloc(m,10)\nm:\ndb a\nlabel(aa)\naa:\n[DISABLE]\n";
    assert_eq!(check_msg(&p, s, &mut AaHooks::default()), "");
}

#[test]
fn lua_blocks_cannot_expand_forever() {
    let p = game64();
    let mut hooks = AaHooks {
        lua: Some(Box::new(|_| Ok("{$lua:0}\n{$lua:0}\n".into()))),
        ..Default::default()
    };
    let m = check_msg(
        &p,
        "[ENABLE]\n{$lua}\nreturn ''\n{$asm}\n[DISABLE]\n",
        &mut hooks,
    );
    assert!(m.contains("{$lua} blocks"), "{m}");
}

#[test]
fn includes_are_capped() {
    let p = game64();
    let mut hooks = AaHooks {
        include: Some(Box::new(|_| {
            Ok("include(x)\ninclude(x)\ninclude(x)\n".into())
        })),
        ..Default::default()
    };
    let m = check_msg(&p, "[ENABLE]\ninclude(x)\n[DISABLE]\n", &mut hooks);
    assert!(m.contains("include"), "{m}");
}

#[test]
fn aobscan_skips_ahead_caps_and_cancels() {
    let p = TestProc::new(8);
    p.map(0x1000_0000, vec![0u8; 16 << 20]);
    let pat = format!("{}01", "?? ".repeat(1000));
    let t = std::time::Instant::now();
    assert!(aob_scan(&p, 0, u64::MAX, &pat, 1).unwrap().is_empty());
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
    p.map(0x2000_0000, hex("90 90 01 02 90 01 02 03"));
    assert_eq!(
        aob_scan(&p, 0, u64::MAX, "01 02 ?? 01", 10).unwrap(),
        vec![0x2000_0002]
    );
    assert_eq!(
        aob_scan(&p, 0, u64::MAX, "?? 02", 10).unwrap(),
        vec![0x2000_0002, 0x2000_0005]
    );
    assert!(aob_scan(&p, 0, u64::MAX, &"?? ".repeat(1025), 1).is_err());
    let stop = std::sync::atomic::AtomicBool::new(true);
    assert!(aob_scan_cancellable(&p, 0, u64::MAX, "01 02", 1, &stop).is_err());
}

#[test]
fn struct_offset_overflow_is_an_error() {
    let p = game64();
    let s = "[ENABLE]\nstruct s\na: resq FFFFFFFFFFFFFFFF\nb: resb 1\nc: resb 1\nends\n[DISABLE]\n";
    let m = check_msg(&p, s, &mut AaHooks::default());
    assert!(m.contains("larger than"), "{m}");
}

#[test]
fn readmem_and_assembled_size_are_capped() {
    let p = game64();
    p.map(0x3000_0000, vec![0x11u8; 2 << 20]);
    // One read larger than the old silent 1 MiB truncation is copied whole.
    let s = "[ENABLE]\nalloc(m,3000000)\nm:\nreadmem(30000000,2000000)\nlabel(e)\ne:\nregistersymbol(e)\n[DISABLE]\n";
    let mut syms = SymbolTable::default();
    let st = aa_execute(&p, &mut syms, s, true, None, &mut AaHooks::default()).unwrap();
    assert_eq!(st.registered[0].1 - st.allocs[0].addr, 2_000_000);
    let reads = "readmem(30000000,1000000)\n".repeat(17);
    let s = format!("[ENABLE]\nalloc(m,10)\nm:\n{reads}[DISABLE]\n");
    let m = check_msg(&p, &s, &mut AaHooks::default());
    assert!(m.contains("readmem"), "{m}");
    let nops = "nop FFFF\n".repeat(1100);
    let s = format!("[ENABLE]\nalloc(m,10)\nm:\n{nops}[DISABLE]\n");
    let m = check_msg(&p, &s, &mut AaHooks::default());
    assert!(m.contains("assembles to more than"), "{m}");
}

/// ELF64 with `n_dup` copies of one `.symtab` header over `n` symbols named from `strtab`.
fn elf_with_symtab(strtab: &[u8], name_off: u64, n: usize, n_dup: usize) -> Vec<u8> {
    let mut b = build_elf(true, false, true);
    let str_at = b.len();
    b.extend_from_slice(strtab);
    let sym_at = b.len();
    for _ in 0..n {
        let e = b.len();
        b.resize(e + 24, 0);
        put(&mut b, e, name_off, 4);
        b[e + 4] = 0x12;
        put(&mut b, e + 6, 5, 2);
        put(&mut b, e + 8, 0x1100, 8);
        put(&mut b, e + 16, 0, 8);
    }
    let sh_at = b.len();
    let sec = |b: &mut Vec<u8>, typ: u64, off: usize, size: usize, link: u64| {
        let s = b.len();
        put(b, s + 4, typ, 4);
        put(b, s + 24, off as u64, 8);
        put(b, s + 32, size as u64, 8);
        put(b, s + 40, link, 4);
        put(b, s + 56, 0, 8);
    };
    sec(&mut b, 0, 0, 0, 0);
    sec(&mut b, 3, str_at, strtab.len(), 0);
    for _ in 0..n_dup {
        sec(&mut b, 2, sym_at, n * 24, 1);
    }
    put(&mut b, 40, sh_at as u64, 8);
    put(&mut b, 60, 2 + n_dup as u64, 2);
    b
}

#[test]
fn hostile_elf_symbol_tables_are_bounded() {
    // 5000 headers naming one table: parsed once.
    let img = elf_with_symtab(b"\0f\0", 1, 1000, 5000);
    let t = std::time::Instant::now();
    let syms = parse_symbols(&img, 0).unwrap();
    assert_eq!(syms.len(), 1000);
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
    // Names without a terminator within the cap are skipped, not copied per symbol.
    let img = elf_with_symtab(&vec![b'A'; 1 << 20], 0, 1000, 5000);
    let syms = parse_symbols(&img, 0).unwrap_or_default();
    assert!(syms.iter().all(|s| s.name.len() <= 4096));
    assert!(syms.len() < 10, "{}", syms.len());
}

#[test]
fn hostile_elf_program_headers_do_not_overflow() {
    // PT_LOAD at a file offset near u64::MAX: the stripped-file fallback maps through it.
    let mut b = build_elf(true, false, false);
    put(&mut b, 64 + 8, u64::MAX - 0x10, 8);
    let _ = parse_symbols(&b, 0x1000);
    // Load address above the module base: the bias wraps, dynamic pointers must not underflow.
    let mut b = build_elf(true, false, false);
    put(&mut b, 64 + 16, 0xFFFF_0000_0000_0000, 8);
    let base = 0x3000_0000_0000;
    let dynamic = 0x700;
    for i in 1..4 {
        let v = u64::from_le_bytes(
            b[dynamic + i * 16 + 8..dynamic + i * 16 + 16]
                .try_into()
                .unwrap(),
        );
        put(&mut b, dynamic + i * 16 + 8, base + v, 8);
    }
    let p = TestProc::new(8).module("wrap.so", base, b);
    let _ = module_symbols(&p, &p.mods[0]);
}

#[test]
fn hostile_pe_export_counts_are_bounded() {
    let mut b = build_pe(true, true);
    // 0xFFFFFFFF names: the loop is bounded by what the name array read returned.
    put(&mut b, 0x400 + 24, 0xFFFF_FFFF, 4);
    let _ = parse_symbols(&b, 0);
    // e_lfanew near u32::MAX.
    let mut b = build_pe(true, true);
    put(&mut b, 0x3C, 0xFFFF_FFF0, 4);
    assert!(parse_symbols(&b, 0).is_err());
}

#[cfg(unix)]
#[test]
fn module_files_must_be_regular() {
    let dir = std::env::temp_dir().join(format!("hh-asm-fifo-{}", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    let ok = std::process::Command::new("mkfifo")
        .arg(&dir)
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        // Opening a FIFO without O_NONBLOCK would block forever (no writer).
        assert!(module_file_reader(dir.to_str().unwrap()).is_err());
        let p = TestProc::new(8).module("fifo.so", 0x7000_0000, build_elf(true, false, false));
        let mut m = p.mods[0].clone();
        m.path = dir.to_str().unwrap().into();
        assert!(!module_symbols(&p, &m).is_empty());
        let _ = std::fs::remove_file(&dir);
    }
    assert!(module_file_reader("/").is_err());
    let exe = std::env::current_exe().unwrap();
    let rd = module_file_reader(exe.to_str().unwrap()).unwrap();
    assert_eq!(rd(0, 4).unwrap(), b"\x7fELF");
}

#[test]
fn garbage_scripts_never_panic_or_hang() {
    let p = game64();
    let syms = SymbolTable::default();
    let frags = [
        "define(a,a a)",
        "define(b,(((",
        "readmem(game.exe,FFFFFFFFFFFFFFFF)",
        "readmem(FFFFFFFFFFFFFFFF,10)",
        "struct s",
        "x: resq FFFFFFFFFFFFFFFF",
        "ends",
        "aobscan(q,?? ?? 01)",
        "aobscanregion(q,FFFFFFFFFFFFFFF0,FFFFFFFFFFFFFFFF,01)",
        "alloc(m,FFFFFFFFFFFFFFFF)",
        "m:",
        "FFFFFFFFFFFFFFFF:",
        "nop FFFF",
        "db a b a b",
        "dd [[[[game.exe]]]]",
        "fullaccess(FFFFFFFFFFFFFFFF,FFFFFFFFFFFFFFFF)",
        "assert(FFFFFFFFFFFFFFFF,01)",
        "{$try}",
        "{$except}",
        "@@:",
        "jmp @f",
        "reassemble(FFFFFFFFFFFFFFFF)",
    ];
    let mut seed = 11u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let t = std::time::Instant::now();
    for _ in 0..2_000 {
        let n = 1 + next() % 12;
        let body: Vec<&str> = (0..n).map(|_| frags[next() % frags.len()]).collect();
        let s = format!("[ENABLE]\n{}\n[DISABLE]\n", body.join("\n"));
        let _ = aa_check(&p, &syms, &s, &mut AaHooks::default());
    }
    assert!(t.elapsed().as_secs() < 60, "{:?}", t.elapsed());
}

// ---------------------------------------------------------------- 1.0 feature gaps

type Log = std::sync::Arc<Mutex<Vec<String>>>;

fn logger() -> (Log, Log) {
    let l = Log::default();
    (l.clone(), l)
}

/// A CE-style script using the new directives, enabled then disabled.
const NEW_DIRECTIVES: &str = r#"
define(target,game.exe+1005)
define(tmp,1)
undefine(tmp)
define(fill,CC)
[ENABLE]
{$ifdef tmp}
this line is skipped
{$endif}
{$ifndef CPU64}
garbage
{$else}
{$ifdef HEAPHOOK}
alloc(newmem,$1000,target)
{$else}
garbage too
{$endif}
{$endif}
assert(target,29 81 ?? 00 00 00)
aobscanmodule(aobhit,$process,"29 81 E0 ?? 00 00")
allocnx(data,100)
fullaccess(game.exe+3000,10,1000)
label(code,return,flt)
registersymbol(aobhit,flt,cmdval)
luacall(print('hi'))
newmem:
code:
  sub [rcx+E0],eax
  jmp return
  align 10 fill
flt:
  dd (float)1.5
implicit:
  db #PATCHME#
{$ifdef already}
seenalready:
  db 77
registersymbol(seenalready)
{$endif}
data:
  dd 1234
mycmd(7)
org data+8
  dd 5678
loadbinary(data+10,file.bin)
target:
  jmp newmem
  nop
return:

[DISABLE]
target:
  db 29 81 E0 00 00 00
unregistersymbol(aobhit,flt,cmdval,seenalready)
dealloc(newmem)
dealloc(data)
"#;

fn new_directive_hooks(log: &Log) -> AaHooks {
    let (l1, l2, l3, l4, l5) = (log.clone(), log.clone(), log.clone(), log.clone(), log.clone());
    AaHooks {
        lua: Some(Box::new(|_| panic!("luacall must use lua_call"))),
        lua_call: Some(Box::new(move |code| {
            l1.lock().unwrap().push(format!("luacall {code}"));
            Ok(())
        })),
        read_file: Some(Box::new(move |f| {
            l2.lock().unwrap().push(format!("read {f}"));
            Ok(vec![1, 2, 3, 4])
        })),
        command: Some(Box::new(move |(name, args, check)| {
            l3.lock().unwrap().push(format!("cmd {name}({args}) {check}"));
            Ok((name == "mycmd").then(|| format!("cmdval:\n  dd {args}\n")))
        })),
        prologue: Some(Box::new(move |(s, check)| {
            l4.lock().unwrap().push(format!("prologue {check}"));
            Ok(s.replace("#PATCHME#", "90"))
        })),
        epilogue: Some(Box::new(move |(enable, check)| {
            l5.lock().unwrap().push(format!("epilogue {enable} {check}"));
            Ok(())
        })),
        ..Default::default()
    }
}

#[test]
fn aa_new_directives_enable_disable_restores_memory() {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    syms.register("already", 1);
    let (log, l) = logger();
    let mut hooks = new_directive_hooks(&l);
    assert_eq!(aa_check(&p, &syms, NEW_DIRECTIVES, &mut hooks), None);
    assert_eq!(p.snapshot(), before, "check must not write");
    {
        let got = log.lock().unwrap();
        assert!(got.iter().all(|x| !x.starts_with("luacall") && !x.starts_with("read")), "{got:?}");
        assert!(got.contains(&"cmd mycmd(7) true".to_string()), "{got:?}");
        assert!(got.contains(&"epilogue false true".to_string()), "{got:?}");
    }
    log.lock().unwrap().clear();

    let st = aa_execute(&p, &mut syms, NEW_DIRECTIVES, true, None, &mut hooks).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        [
            "prologue false",
            "luacall print('hi')",
            "cmd mycmd(7) false",
            "read file.bin",
            "epilogue true false"
        ]
    );
    let hook = GAME64 + 0x1005;
    assert_eq!(syms.get("aobhit"), Some(hook));
    assert_eq!(
        st.scans,
        vec![AaScan {
            name: "aobhit".into(),
            addr: hook,
            matches: None
        }]
    );
    let newmem = st.allocs.iter().find(|a| a.name == "newmem").unwrap().addr;
    let data = st.allocs.iter().find(|a| a.name == "data").unwrap().addr;
    // sub (6) + jmp rel32 (5), padded with CC up to 16.
    let mut b = [0u8; 16];
    p.read(newmem, &mut b).unwrap();
    assert_eq!(&b[11..], &[0xCC; 5]);
    let flt = syms.get("flt").unwrap();
    assert_eq!(flt, newmem + 0x10);
    let mut f = [0u8; 4];
    p.read(flt, &mut f).unwrap();
    assert_eq!(f32::from_le_bytes(f), 1.5);
    p.read(flt + 4, &mut f[..1]).unwrap();
    assert_eq!(f[0], 0x90, "prologue patched the script, implicit label placed");
    assert!(syms.get("seenalready").is_some(), "{{$ifdef}} saw the registered symbol");
    let mut d = [0u8; 20];
    p.read(data, &mut d).unwrap();
    assert_eq!(&d[..4], &0x1234u32.to_le_bytes(), "numbers are hex");
    assert_eq!(&d[4..8], &7u32.to_le_bytes(), "custom command output");
    assert_eq!(&d[8..12], &0x5678u32.to_le_bytes(), "org");
    assert_eq!(&d[16..20], &[1, 2, 3, 4], "loadbinary");
    let l = disassemble(&p, &syms, hook, 1).unwrap();
    assert_eq!(l[0].text, format!("jmp {newmem:X}"));
    let log2 = p.alloc_log.lock().unwrap().clone();
    assert!(log2.iter().any(|(pr, _)| !pr.x && pr.w), "allocnx is not executable: {log2:?}");

    aa_execute(&p, &mut syms, NEW_DIRECTIVES, false, Some(&st), &mut hooks).unwrap();
    assert_eq!(p.snapshot(), before, "memory restored byte for byte");
    for n in ["aobhit", "flt", "cmdval", "seenalready"] {
        assert_eq!(syms.get(n), None, "{n}");
    }
}

#[test]
fn aa_conditionals() {
    let p = game64();
    let syms = SymbolTable::default();
    let h = &mut AaHooks {
        lua: Some(Box::new(|_| panic!("{{$lua}} in a skipped branch must not run"))),
        ..Default::default()
    };
    let ok = "[ENABLE]\n{$ifdef nothing}\n{$lua}\nreturn ''\n{$asm}\n{$ifdef x}\ngarbage\n{$else}\nmore garbage\n{$endif}\n{$endif}\n[DISABLE]\n";
    assert_eq!(check_msg(&p, ok, h), "");
    // A define's name is tested before replacement; redefinition replaces.
    let s = "define(A,B)\ndefine(A,C)\n[ENABLE]\n{$ifdef A}\nalloc(C,10)\nC:\n  nop\n{$endif}\n[DISABLE]\n";
    let mut syms2 = SymbolTable::default();
    let st = aa_execute(&p, &mut syms2, s, true, None, &mut AaHooks::default()).unwrap();
    assert_eq!(st.allocs[0].name, "C");
    // 32-bit targets see CPU32, not CPU64.
    let p32 = TestProc::new(4).module("game.exe", 0x40_0000, vec![0; 0x100]);
    let s = "[ENABLE]\n{$ifdef CPU64}\ngarbage\n{$endif}\n{$ifndef CPU32}\ngarbage\n{$endif}\n[DISABLE]\n";
    assert_eq!(check_msg(&p32, s, &mut AaHooks::default()), "");
    let cases = [
        ("[ENABLE]\n{$ifdef a}\n[DISABLE]\n", 2, "without {$endif}"),
        ("[ENABLE]\n{$endif}\n[DISABLE]\n", 2, "without {$ifdef}"),
        ("[ENABLE]\n{$else}\n[DISABLE]\n", 2, "without {$ifdef}"),
        ("[ENABLE]\n{$ifdef a}\n{$else}\n{$else}\n{$endif}\n[DISABLE]\n", 4, "without"),
        ("[ENABLE]\n{$ifdef}\n[DISABLE]\n", 2, "unsupported directive"),
    ];
    for (s, line, msg) in cases {
        let e = aa_check(&p, &syms, s, &mut AaHooks::default()).unwrap();
        assert_eq!(e.line, line, "{s:?}: {}", e.message);
        assert!(e.message.contains(msg), "{s:?}: {}", e.message);
    }
    let deep = format!(
        "[ENABLE]\n{}{}[DISABLE]\n",
        "{$ifdef x}\n".repeat(65),
        "{$endif}\n".repeat(65)
    );
    assert!(check_msg(&p, &deep, &mut AaHooks::default()).contains("nested deeper"));
}

#[test]
fn aa_strict_and_implicit_labels() {
    let p = game64();
    let h = &mut AaHooks::default();
    // Default: `exit:` declares itself; `1000:` stays an address.
    let s = "[ENABLE]\nalloc(m,100)\nm:\n  jmp exit\n  nop\nexit:\n  ret\n[DISABLE]\n";
    assert_eq!(check_msg(&p, s, h), "");
    let strict = s.replace("[ENABLE]\n", "[ENABLE]\n{$strict}\n");
    assert!(check_msg(&p, &strict, h).contains("not declared"));
    let back = s.replace("[ENABLE]\n", "[ENABLE]\n{$strict}\n{$nostrict}\n");
    assert_eq!(check_msg(&p, &back, h), "");
    // A typo in a use is still an error.
    let typo = s.replace("jmp exit", "jmp exti");
    assert!(check_msg(&p, &typo, h).contains("exti"), "{}", check_msg(&p, &typo, h));
    let mut syms = SymbolTable::default();
    let st = aa_execute(
        &p,
        &mut syms,
        "[ENABLE]\n20000010:\n  db 11\n[DISABLE]\n",
        true,
        None,
        h,
    )
    .unwrap();
    assert_eq!(st.originals[0].0, 0x2000_0010, "hex address, not a label");
}

#[test]
fn aa_align_and_org_forms() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let s = "[ENABLE]\nalloc(m,100)\nlabel(a,b,c)\nregistersymbol(a,b,c)\nm:\n  db 1\n  align 4\na:\n  db 2\n  align(8,0)\nb:\n  db 3\n  align 4,EE\nc:\norg m+40\n  db 55\n[DISABLE]\n";
    let st = aa_execute(&p, &mut syms, s, true, None, &mut AaHooks::default()).unwrap();
    let m = st.allocs[0].addr;
    assert_eq!(
        (syms.get("a"), syms.get("b"), syms.get("c")),
        (Some(m + 4), Some(m + 8), Some(m + 0xC))
    );
    let mut b = [0u8; 13];
    p.read(m, &mut b).unwrap();
    assert_eq!(b, [1, 0x90, 0x90, 0x90, 2, 0, 0, 0, 3, 0xEE, 0xEE, 0xEE, 0]);
    let mut x = [0u8];
    p.read(m + 0x40, &mut x).unwrap();
    assert_eq!(x[0], 0x55);
    for bad in ["align 0", "align 10001", "align 4,100", "align x", "align 4 1 2"] {
        let s = format!("[ENABLE]\nalloc(m,10)\nm:\n{bad}\n[DISABLE]\n");
        assert!(check_msg(&p, &s, &mut AaHooks::default()).contains("align"), "{bad}");
    }
    let s = "[ENABLE]\n  align 4\n[DISABLE]\n";
    assert!(check_msg(&p, s, &mut AaHooks::default()).contains("align"));
}

#[test]
fn aa_alloc_protection_and_near_hint() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let s = "[ENABLE]\nalloc(a,10)\nallocnx(b,10)\nallocxo(c,10)\nalloc(d,10,,r)\nalloc(e,10,PAGE_EXECUTE_READ)\ngame.exe+1005:\n  jmp a\n  nop\na:\n  jmp game.exe+100B\n[DISABLE]\n";
    let st = aa_execute(&p, &mut syms, s, true, None, &mut AaHooks::default()).unwrap();
    let log = p.alloc_log.lock().unwrap().clone();
    let prot = |r, w, x| Prot { r, w, x };
    assert_eq!(
        log.iter().map(|l| l.0).collect::<Vec<_>>(),
        [
            prot(true, true, true),
            prot(true, true, false),
            prot(true, false, true),
            prot(true, false, false),
            prot(true, false, true)
        ]
    );
    // No address given on 64-bit: allocated near the patched address, so the hook is 5 bytes.
    assert!(log.iter().all(|l| l.1 == Some(GAME64 + 0x1005)), "{log:?}");
    assert_eq!(
        disassemble(&p, &syms, GAME64 + 0x1005, 1).unwrap()[0].bytes.len(),
        5
    );
    aa_execute(&p, &mut syms, s, false, Some(&st), &mut AaHooks::default()).unwrap();
    let bad = "[ENABLE]\nalloc(a,10,,rwq)\n[DISABLE]\n";
    assert!(check_msg(&p, bad, &mut AaHooks::default()).contains("protection"));
}

#[test]
fn aa_aob_uniqueness() {
    let p = game64();
    let mut syms = SymbolTable::default();
    // CC filler occurs thousands of times; 29 81 once.
    let s = "[ENABLE]\naobscanmodule(many,game.exe,CC CC CC CC)\naobscan(one,29 81 E0 00)\n[DISABLE]\n";
    let run = |u: AobUnique, syms: &mut SymbolTable| {
        aa_execute(
            &p,
            syms,
            s,
            true,
            None,
            &mut AaHooks {
                aob_unique: u,
                ..Default::default()
            },
        )
    };
    let st = run(AobUnique::Off, &mut syms).unwrap();
    assert_eq!(st.scans.iter().map(|x| x.matches).collect::<Vec<_>>(), [None, None]);
    let st = run(AobUnique::Warn, &mut syms).unwrap();
    assert_eq!(st.scans[0].matches, Some(MAX_AOB_COUNT));
    assert_eq!(st.scans[1].matches, Some(1));
    assert_eq!(st.scans[1].addr, GAME64 + 0x1005);
    let e = run(AobUnique::Fail, &mut syms).unwrap_err().to_string();
    assert!(e.contains("not unique") && e.contains("line 2"), "{e}");
    let e = aa_check(
        &p,
        &syms,
        s,
        &mut AaHooks {
            aob_unique: AobUnique::Fail,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(e.message.contains("1000 or more matches"), "{}", e.message);
    // State without `scans` (saved by an older version) still loads.
    let old: AaState =
        serde_json::from_str(r#"{"allocs":[],"registered":[],"originals":[]}"#).unwrap();
    assert!(old.scans.is_empty());
}

#[test]
fn aa_assert_wildcards_lists_and_globalalloc() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let h = &mut AaHooks::default();
    assert_eq!(
        check_msg(&p, "[ENABLE]\nassert(game.exe+1005,29 ?? E? 00 * 00)\n[DISABLE]\n", h),
        ""
    );
    assert!(
        check_msg(&p, "[ENABLE]\nassert(game.exe+1005,29 ?? E? 01)\n[DISABLE]\n", h)
            .contains("assert failed")
    );
    let s = "[ENABLE]\nglobalalloc(g,100,game.exe)\nalloc(m,10)\nlabel(x,y)\nregistersymbol(x,y,m)\nm:\nx:\n  db 1\ny:\n  db 2\n[DISABLE]\nunregistersymbol(x,y,m)\ndealloc(m)\n";
    let st = aa_execute(&p, &mut syms, s, true, None, h).unwrap();
    let m = st.allocs[0].addr;
    assert_eq!((syms.get("x"), syms.get("y"), syms.get("m")), (Some(m), Some(m + 1), Some(m)));
    let g = syms.get("g").unwrap();
    aa_execute(&p, &mut syms, s, false, Some(&st), h).unwrap();
    assert_eq!((syms.get("x"), syms.get("y")), (None, None));
    // globalalloc survives disable and is reused by the next enable.
    assert_eq!(syms.get("g"), Some(g));
    let st = aa_execute(&p, &mut syms, s, true, None, h).unwrap();
    assert_eq!(syms.get("g"), Some(g));
    assert!(st.allocs.iter().all(|a| a.name != "g"));
}

#[test]
fn aa_lua_sections_and_nesting() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let (log, l) = logger();
    let mut hooks = AaHooks {
        lua: Some(Box::new(move |src: String| {
            l.lock().unwrap().push(src.trim().to_string());
            // Lua may emit another {$lua} block.
            Ok(if src.contains("outer") {
                "{$lua}\nreturn 'inner'\n{$asm}\n".into()
            } else {
                String::new()
            })
        })),
        ..Default::default()
    };
    let s = "{$lua}\nif syntaxcheck then return end\n[ENABLE]\nprint('on') -- outer\n[DISABLE]\nprint('off')\n{$asm}\n";
    let st = aa_execute(&p, &mut syms, s, true, None, &mut hooks).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        [
            "if syntaxcheck then return end",
            "print('on') -- outer",
            "return 'inner'"
        ]
    );
    log.lock().unwrap().clear();
    aa_execute(&p, &mut syms, s, false, Some(&st), &mut hooks).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        ["if syntaxcheck then return end", "print('off')"]
    );
    // Header directly before {$asm}: an empty part, not run.
    log.lock().unwrap().clear();
    let s = "[ENABLE]\n{$lua}\nprint(1)\n[DISABLE]\n{$asm}\n";
    aa_execute(&p, &mut syms, s, false, None, &mut hooks).unwrap();
    assert!(log.lock().unwrap().is_empty());
    // Lines stay right after a split block.
    let s = "{$lua}\n[ENABLE]\nx = 1\n{$asm}\n  bogus\n[DISABLE]\n";
    let e = aa_check(&p, &syms, s, &mut hooks).unwrap();
    assert_eq!(e.line, 5, "{}", e.message);
}

#[test]
fn aa_custom_commands_symbol_lookup_and_luacall() {
    let p = game64();
    let mut syms = SymbolTable::default();
    // A command expanding to itself is capped.
    let mut hooks = AaHooks {
        command: Some(Box::new(|(n, _, _)| Ok((n == "loop").then(|| "loop()\n".to_string())))),
        ..Default::default()
    };
    assert!(check_msg(&p, "[ENABLE]\nloop()\n[DISABLE]\n", &mut hooks).contains("custom command"));
    // Errors from a command carry the line; `None` falls through to the assembler.
    let mut hooks = AaHooks {
        command: Some(Box::new(|(n, _, _)| match n.as_str() {
            "boom" => Err(Error::Other("no".into())),
            _ => Ok(None),
        })),
        ..Default::default()
    };
    let e = aa_check(&p, &syms, "[ENABLE]\n\nboom(1)\n[DISABLE]\n", &mut hooks).unwrap();
    assert_eq!((e.line, e.message.as_str()), (3, "no"));
    let e = aa_check(&p, &syms, "[ENABLE]\nother(1)\n[DISABLE]\n", &mut hooks).unwrap();
    assert_eq!(e.line, 2);
    // The host's symbol lookup is asked last.
    let lookup: SymbolLookup = std::sync::Arc::new(|n: &str| (n == "magic").then_some(0x2000_0020));
    let mut hooks = AaHooks {
        symbol_lookup: Some(lookup.clone()),
        ..Default::default()
    };
    let st = aa_execute(&p, &mut syms, "[ENABLE]\nmagic:\n  dd magic\n[DISABLE]\n", true, None, &mut hooks)
        .unwrap();
    let mut b = [0u8; 4];
    p.read(0x2000_0020, &mut b).unwrap();
    assert_eq!(u32::from_le_bytes(b), 0x2000_0020);
    aa_execute(&p, &mut syms, "[ENABLE]\nmagic:\n  dd magic\n[DISABLE]\n", false, Some(&st), &mut hooks)
        .unwrap();
    assert_eq!(resolve_address_with(&p, &syms, "magic+4", &*lookup).unwrap(), 0x2000_0024);
    assert!(resolve_address(&p, &syms, "magic").is_err());
    // luacall without any Lua is an error, when checking too (the capability is missing).
    let s = "[ENABLE]\nluacall(x())\n[DISABLE]\n";
    assert!(check_msg(&p, s, &mut AaHooks::default()).contains(NOT_AVAILABLE));
    let e = aa_execute(&p, &mut syms, s, true, None, &mut AaHooks::default()).unwrap_err();
    assert!(e.to_string().contains("luacall"), "{e}");
    // ... and falls back to the {$lua} hook, its output ignored.
    let (log, l) = logger();
    let mut hooks = AaHooks {
        lua: Some(Box::new(move |s| {
            l.lock().unwrap().push(s);
            Ok("garbage that is not assembled".into())
        })),
        ..Default::default()
    };
    aa_execute(&p, &mut syms, s, true, None, &mut hooks).unwrap();
    assert_eq!(*log.lock().unwrap(), ["x()"]);
}

#[test]
fn aa_loadbinary_and_fullaccess_errors() {
    let p = game64();
    let h = &mut AaHooks::default();
    let s = "[ENABLE]\nalloc(m,10)\nloadbinary(m,x.bin)\n[DISABLE]\n";
    assert!(check_msg(&p, s, h).contains(NOT_AVAILABLE));
    let mut syms = SymbolTable::default();
    let mut hooks = AaHooks {
        read_file: Some(Box::new(|_| Err(Error::Other("denied by consent".into())))),
        ..Default::default()
    };
    assert_eq!(check_msg(&p, s, &mut hooks), "", "checking never reads the file");
    let e = aa_execute(&p, &mut syms, s, true, None, &mut hooks).unwrap_err();
    assert!(e.to_string().contains("denied by consent"), "{e}");
    let mut hooks = AaHooks {
        read_file: Some(Box::new(|_| Ok(vec![0; MAX_ASSEMBLED_BYTES + 1]))),
        ..Default::default()
    };
    let e = aa_execute(&p, &mut syms, s, true, None, &mut hooks).unwrap_err();
    assert!(e.to_string().contains("larger than"), "{e}");
    let s = "[ENABLE]\nfullaccess(game.exe,zz)\n[DISABLE]\n";
    assert!(check_msg(&p, s, h).contains("bad size"));
}

#[test]
fn aa_api_hook_template() {
    let p = game64();
    let before = p.snapshot();
    let mut syms = SymbolTable::default();
    let script = injection_template(&p, GAME64 + 0x1000, Template::ApiHook).unwrap();
    assert_eq!(aa_check(&p, &syms, &script, &mut AaHooks::default()), None, "{script}");
    let st = aa_execute(&p, &mut syms, &script, true, None, &mut AaHooks::default())
        .unwrap_or_else(|e| panic!("{e}\n{script}"));
    let newfunction = st.allocs[0].addr;
    let orig = syms.get("originalcall").expect("originalcall registered");
    let l = disassemble(&p, &syms, GAME64 + 0x1000, 1).unwrap();
    assert_eq!(l[0].text, format!("jmp {newfunction:X}"));
    assert_eq!(
        disassemble(&p, &syms, newfunction, 1).unwrap()[0].text,
        format!("jmp {orig:X}")
    );
    // The trampoline runs the moved entry and continues after it.
    let t = disassemble(&p, &syms, orig, 2).unwrap();
    assert_eq!(t[0].text, "mov [rsp+8],rbx");
    assert_eq!(t[1].text, format!("jmp {:X}", GAME64 + 0x1005));
    aa_execute(&p, &mut syms, &script, false, Some(&st), &mut AaHooks::default()).unwrap();
    assert_eq!(p.snapshot(), before);
    assert_eq!(syms.get("originalcall"), None);
}

/// Code that reads a pointer, a float and a string through absolute addresses.
fn typed_code() -> (TestProc, Addr) {
    let p = game64();
    p.write(GAME64 + 0x3030, &1.5f32.to_le_bytes()).unwrap();
    let syms = SymbolTable::default();
    let at = GAME64 + 0x2000;
    let code = assemble(
        &p,
        &syms,
        at,
        "mov rax,[140003000]\nmovss xmm0,[140003030]\nmov eax,[140003010]\nmov eax,[rcx+E0]",
    )
    .unwrap();
    p.write(at, &code).unwrap();
    (p, at)
}

#[test]
fn disassemble_with_options() {
    let (p, at) = typed_code();
    let syms = SymbolTable::default();
    let plain = disassemble(&p, &syms, at, 4).unwrap();
    assert_eq!(disassemble_with(&p, &syms, at, 4, &DisasmOptions::default()).unwrap(), plain);
    let opts = DisasmOptions {
        guess_types: true,
        ..Default::default()
    };
    let l = disassemble_with(&p, &syms, at, 3, &opts).unwrap();
    let c: Vec<&str> = l.iter().map(|x| x.comment.as_str()).collect();
    assert_eq!(
        c,
        [
            "[game.exe+3000]->20000000",
            "[game.exe+3030]=(float)1.5",
            "[game.exe+3010]='Hello'"
        ]
    );
    // The host's names come first.
    let opts = DisasmOptions {
        address_name: Some(std::sync::Arc::new(|a| {
            (a == GAME64 + 0x3000).then(|| "player".to_string())
        })),
        ..Default::default()
    };
    assert_eq!(
        disassemble_with(&p, &syms, at, 1, &opts).unwrap()[0].comment,
        "[player]=0000000020000000"
    );
    let att = DisasmOptions {
        syntax: Syntax::Att,
        ..Default::default()
    };
    let l = disassemble_with(&p, &syms, GAME64 + 0x1000, 2, &att).unwrap();
    assert_eq!(l[0].text, "mov %rbx,8(%rsp)");
    assert_eq!(l[1].text, "sub %eax,0xe0(%rcx)");
    for arch in [Arch::Arm, Arch::Arm64] {
        let e = disassemble_with(
            &p,
            &syms,
            at,
            1,
            &DisasmOptions {
                arch,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)), "{e}");
    }
    // 32-bit decoding of 64-bit code on request.
    let x86 = DisasmOptions {
        arch: Arch::X86,
        ..Default::default()
    };
    assert_eq!(
        disassemble_with(&p, &syms, GAME64 + 0x1000, 1, &x86).unwrap()[0].text,
        "dec eax"
    );
}

#[test]
fn guess_types_of_operands() {
    let (p, at) = typed_code();
    let g = |a: Addr, r: Option<&Registers>| guess_operand_type(&p, a, r).unwrap();
    assert_eq!(g(at, None), Some((GAME64 + 0x3000, ValueType::Pointer)));
    assert_eq!(g(at + 8, None), Some((GAME64 + 0x3030, ValueType::Float)));
    let third = disassemble(&p, &SymbolTable::default(), at, 3).unwrap()[2].addr;
    assert_eq!(g(third, None), Some((GAME64 + 0x3010, ValueType::String)));
    let fourth = disassemble(&p, &SymbolTable::default(), at, 4).unwrap()[3].addr;
    assert_eq!(g(fourth, None), None, "needs rcx");
    let r = regs(&[("rcx", GAME64 + 0x3020 - 0xE0)]);
    assert_eq!(g(fourth, Some(&r)), Some((GAME64 + 0x3020, ValueType::Dword)));
    // Plain values.
    p.write(0x2000_0010, &1.0f32.to_le_bytes()).unwrap();
    assert_eq!(guess_value_type(&p, 0x2000_0010, 4, false), Some(ValueType::Float));
    p.write(0x2000_0010, &2.5f64.to_le_bytes()).unwrap();
    assert_eq!(guess_value_type(&p, 0x2000_0010, 8, false), Some(ValueType::Double));
    p.write(0x2000_0010, &[b'h', 0, b'e', 0, b'l', 0, b'l', 0]).unwrap();
    assert_eq!(guess_value_type(&p, 0x2000_0010, 4, false), Some(ValueType::UnicodeString));
    p.write(0x2000_0010, &7u64.to_le_bytes()).unwrap();
    assert_eq!(guess_value_type(&p, 0x2000_0010, 8, false), Some(ValueType::Qword));
    assert_eq!(guess_value_type(&p, 0x2000_0010, 1, false), Some(ValueType::Byte));
    assert_eq!(guess_value_type(&p, 0x10, 4, false), None);
}

#[test]
fn assembly_scan_and_references() {
    let p = game64();
    let none = std::sync::atomic::AtomicBool::new(false);
    let scan = |pat: &str, max: usize| asm_scan(&p, 0, u64::MAX, pat, max, &none).unwrap();
    let addrs = |pg: &AsmScanPage| pg.hits.iter().map(|h| h.addr).collect::<Vec<_>>();
    assert_eq!(addrs(&scan("sub [r?x+*],e?x", 10)), [GAME64 + 0x1005]);
    assert_eq!(addrs(&scan("MOV  EAX , [RCX+E0]", 10)), [GAME64 + 0x100B]);
    let seq = scan("mov eax,[*]; ret", 10);
    assert_eq!(addrs(&seq), [GAME64 + 0x1011]);
    assert_eq!(seq.hits[0].text, "mov eax,[140003020]; ret");
    assert_eq!(seq.next, None);
    // Paging.
    let pg = scan("int3", 3);
    assert_eq!(addrs(&pg), [GAME64, GAME64 + 1, GAME64 + 2]);
    assert_eq!(pg.next, Some(GAME64 + 3));
    let pg2 = asm_scan(&p, pg.next.unwrap(), u64::MAX, "int3", 2, &none).unwrap();
    assert_eq!(addrs(&pg2), [GAME64 + 3, GAME64 + 4]);
    let stop = std::sync::atomic::AtomicBool::new(true);
    assert!(asm_scan(&p, 0, u64::MAX, "nop", 1, &stop).is_err());
    assert!(asm_scan(&p, 0, u64::MAX, " ; ", 1, &none).is_err());
    assert!(asm_scan(&p, 0, u64::MAX, &"nop;".repeat(17), 1, &none).is_err());
    assert!(asm_scan(&p, 0, u64::MAX, &"?".repeat(MAX_ASM_PATTERN + 1), 1, &none).is_err());
    // AOB scans page the same way: continue after the last hit.
    let a = aob_scan(&p, 0, u64::MAX, "CC CC", 2).unwrap();
    let b = aob_scan(&p, a[1] + 1, u64::MAX, "CC CC", 1).unwrap();
    assert_eq!(b, [a[1] + 1]);

    // References.
    let syms = SymbolTable::default();
    let jmp = assemble(&p, &syms, GAME64 + 0x2000, "jmp 140001000").unwrap();
    p.write(GAME64 + 0x2000, &jmp).unwrap();
    let r = |from, target, fwd| find_reference(&p, from, target, fwd, 1 << 20, &none).unwrap();
    assert_eq!(r(GAME64, GAME64 + 0x3020, true), Some(GAME64 + 0x1011));
    assert_eq!(r(GAME64 + 0x3000, GAME64 + 0x3020, false), Some(GAME64 + 0x1011));
    assert_eq!(r(GAME64 + 0x1011, GAME64 + 0x3020, true), None, "strictly after");
    assert_eq!(r(GAME64 + 0x3FFF, GAME64 + 0x1000, false), Some(GAME64 + 0x2000));
    assert_eq!(r(GAME64, GAME64 + 0x1000, true), Some(GAME64 + 0x2000));
    assert_eq!(r(GAME64, 0xDEAD_BEEF, true), None);
    assert!(find_reference(&p, GAME64, 1, true, 100, &stop).is_err());
}

#[test]
fn garbage_asm_patterns_never_panic() {
    let p = TestProc::new(8);
    let mut seed = 5u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let bytes: Vec<u8> = (0..0x4000).map(|_| next() as u8).collect();
    p.map(0x1000_0000, bytes);
    let chars: Vec<char> = "*?;[]+-, \nmovjeaxr0123456789".chars().collect();
    let none = std::sync::atomic::AtomicBool::new(false);
    let t = std::time::Instant::now();
    for _ in 0..300 {
        let len = next() % 40;
        let s: String = (0..len).map(|_| chars[next() % chars.len()]).collect();
        let _ = asm_scan(&p, 0, u64::MAX, &s, 5, &none);
    }
    assert!(t.elapsed().as_secs() < 60, "{:?}", t.elapsed());
}

#[test]
fn garbage_directives_never_panic_or_hang() {
    let p = game64();
    let mut syms = SymbolTable::default();
    syms.register("reg", 0x2000_0000);
    let frags = [
        "{$ifdef a}",
        "{$ifndef cpu64}",
        "{$ifdef reg}",
        "{$else}",
        "{$endif}",
        "{$strict}",
        "{$nostrict}",
        "{$lua}",
        "{$asm}",
        "[ENABLE]",
        "[DISABLE]",
        "define(a,b)",
        "undefine(a)",
        "undefine()",
        "align 10",
        "align(FFFFFFFF,FF)",
        "align 4 CC",
        "org m+10",
        "org",
        "allocnx(n,10)",
        "allocxo(n,10,PAGE_bogus)",
        "alloc(q,10,,rwx)",
        "loadbinary(m,f)",
        "luacall(x)",
        "luacall(",
        "custom(1,2)",
        "aobscanmodule(z,$process,\"CC CC\")",
        "assert(m,?? ** *)",
        "fullaccess(m,10,20)",
        "alloc(m,100)",
        "m:",
        "imp:",
        "jmp imp",
        "db 1",
        "label(a,b,c)",
        "registersymbol(a,b,c)",
    ];
    let mut seed = 13u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let t = std::time::Instant::now();
    for _ in 0..2_000 {
        let n = 1 + next() % 14;
        let body: Vec<&str> = (0..n).map(|_| frags[next() % frags.len()]).collect();
        let s = format!("[ENABLE]\n{}\n[DISABLE]\n", body.join("\n"));
        let mut hooks = AaHooks {
            lua: Some(Box::new(|_| Ok("{$ifdef a}\nalign 4\n".into()))),
            command: Some(Box::new(|(n, a, _)| Ok((n == "custom").then(|| format!("db {a}\ncustom({a})\n"))))),
            read_file: Some(Box::new(|_| Ok(vec![1; 16]))),
            aob_unique: AobUnique::Warn,
            ..Default::default()
        };
        let _ = aa_check(&p, &syms, &s, &mut hooks);
    }
    assert!(t.elapsed().as_secs() < 120, "{:?}", t.elapsed());
}

#[test]
fn symbol_list_filters_and_pages() {
    let base = 0x6200_0000_0000;
    let mut p = TestProc::new(8).module("libsym.so", base, build_elf(true, false, false));
    p.pid = 4242;
    let mut syms = SymbolTable::default();
    syms.register("zz_user", 0x10);
    syms.register("mall_user", 0x20);
    let all = symbol_list(&p, &syms, None, "", 0, 100);
    assert_eq!(all.total, 4);
    assert_eq!(
        all.rows.iter().map(|r| (r.name.as_str(), r.user)).collect::<Vec<_>>(),
        [("mall_user", true), ("zz_user", true), ("malloc", false), ("free", false)]
    );
    assert_eq!(all.rows[2].module, "libsym.so");
    let f = symbol_list(&p, &syms, None, "MALL", 0, 100);
    assert_eq!(f.total, 2);
    let page = symbol_list(&p, &syms, None, "", 1, 2);
    assert_eq!((page.total, page.rows.len()), (4, 2));
    assert_eq!(page.rows[0].name, "zz_user");
    let m = symbol_list(&p, &syms, Some("$process"), "", 0, 100);
    assert_eq!(m.total, 2);
    assert!(symbol_list(&p, &syms, Some("nope"), "", 0, 100).rows.is_empty());
}

#[test]
fn remote_targets_read_symbols_from_memory() {
    // The path names a real local ELF with `malloc`; the target's memory holds a PE with
    // `Sleep`. A remote target's paths are not local files.
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("hh_asm_remote_decoy.so");
    std::fs::write(&path, build_elf(true, false, true)).unwrap();
    let base = 0x6300_0000_0000;
    let img = build_pe(true, false);
    let mut p = TestProc::new(8);
    p.pid = 31337;
    p.mods.push(Module {
        name: "lib.so".into(),
        path: path.to_string_lossy().into(),
        base,
        size: img.len() as u64,
    });
    p.map(base, img);
    let syms = SymbolTable::default();
    assert_eq!(resolve_address(&p, &syms, "malloc").unwrap(), base + 0x1100);
    set_module_files_local(31337, false);
    assert_eq!(resolve_address(&p, &syms, "Sleep").unwrap(), base + 0x2100);
    assert!(resolve_address(&p, &syms, "malloc").is_err());
    set_module_files_local(31337, true);
    assert_eq!(resolve_address(&p, &syms, "malloc").unwrap(), base + 0x1100);
}

/// Hooks without capabilities: every route to Lua or to local files is an error carrying
/// `NOT_AVAILABLE`, when checking and when running, whatever the spelling hh-asm accepts.
#[test]
fn aa_without_capabilities_runs_nothing() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let scripts = [
        "[ENABLE]\n{$lua}\nreturn ''\n{$asm}\n[DISABLE]\n",
        "[ENABLE]\n  {$LUA}  \nreturn ''\n{$asm}\n[DISABLE]\n",
        "[ENABLE]\nluacall(x())\n[DISABLE]\n",
        "[ENABLE]\nLUACALL (x())\n[DISABLE]\n",
        "[ENABLE]\nalloc(m,10)\nloadbinary(m,/etc/hostname)\n[DISABLE]\n",
        "[ENABLE]\nalloc(m,10)\nload{}binary(m,/etc/hostname)\n[DISABLE]\n",
        "[ENABLE]\nalloc(m,10)\nload/* x */binary(m,/etc/hostname)\n[DISABLE]\n",
        "[ENABLE]\nalloc(m,10)\nLoadBinary  (m,/etc/hostname)\n[DISABLE]\n",
        "[ENABLE]\nalloc(m,10)\ndefine(lb,loadbinary)\nlb(m,/etc/hostname)\n[DISABLE]\n",
        "[ENABLE]\ninclude(x.cea)\n[DISABLE]\n",
    ];
    for s in scripts {
        let m = check_msg(&p, s, &mut AaHooks::default());
        assert!(m.contains(NOT_AVAILABLE), "check of {s:?}: {m}");
        let e = aa_execute(&p, &mut syms, s, true, None, &mut AaHooks::default()).unwrap_err();
        assert!(e.to_string().contains(NOT_AVAILABLE), "run of {s:?}: {e}");
    }
}

/// `loadbinary` stops at the file that crosses the total, before reading the rest.
#[test]
fn aa_loadbinary_total_is_capped_while_reading() {
    let p = game64();
    let mut syms = SymbolTable::default();
    let reads = std::sync::Arc::new(Mutex::new(0usize));
    let r = reads.clone();
    let mut hooks = AaHooks {
        read_file: Some(Box::new(move |_| {
            *r.lock().unwrap() += 1;
            Ok(vec![0; MAX_ASSEMBLED_BYTES / 2 + 1])
        })),
        ..Default::default()
    };
    let mut s = String::from("[ENABLE]\nalloc(m,10)\n");
    for _ in 0..10 {
        s.push_str("loadbinary(m,x.bin)\n");
    }
    s.push_str("[DISABLE]\n");
    let e = aa_execute(&p, &mut syms, &s, true, None, &mut hooks).unwrap_err();
    assert!(e.to_string().contains("in all"), "{e}");
    assert_eq!(*reads.lock().unwrap(), 2, "read past the limit");
}

/// A module name the target (or a remote server) controls never lands in the script text
/// unless it is a plain name.
#[test]
fn aa_template_never_embeds_hostile_module_names() {
    for name in ["a\"\n{$lua}\nluacall(os.exit())\n", "x{", "a//b", "a,b", "a b", "a)"] {
        let mut p = game64();
        p.mods.iter_mut().for_each(|m| m.name = name.into());
        for kind in [Template::CodeInjection, Template::AobInjection, Template::FullInjection, Template::ApiHook] {
            let s = injection_template(&p, GAME64 + 0x1005, kind).unwrap();
            assert!(!s.contains(name), "{kind:?} embedded {name:?}:\n{s}");
            assert!(!s.to_ascii_lowercase().contains("{$lua}") && !s.contains("luacall"), "{s}");
        }
    }
}
