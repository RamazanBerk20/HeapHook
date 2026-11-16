#![allow(dead_code)]
use std::sync::{Arc, Mutex, RwLock};

use hh_core::{Addr, Error, Memory, Module, Process, Prot, Region, RegionKind, Result};
use hh_lua::{Engine, EngineOptions, Host};

/// Sparse multi-region fake process with modules and alloc/free.
pub struct TestProc {
    regions: RwLock<Vec<(Addr, Vec<u8>)>>,
    mods: Vec<Module>,
    next: Mutex<u64>,
}

impl TestProc {
    pub fn map(&self, start: Addr, data: Vec<u8>) {
        self.regions.write().unwrap().push((start, data));
    }
    pub fn snapshot(&self) -> Vec<(Addr, Vec<u8>)> {
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
}

impl Process for TestProc {
    fn pid(&self) -> u32 {
        1
    }
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(self
            .snapshot()
            .into_iter()
            .map(|(start, d)| Region {
                start,
                size: d.len() as u64,
                prot: Prot { r: true, w: true, x: true },
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
    fn threads(&self) -> Result<Vec<u32>> {
        Ok(vec![1, 0x2A])
    }
    fn alloc(&self, size: u64, _prot: Prot, near: Option<Addr>) -> Result<Addr> {
        let mut n = self.next.lock().unwrap();
        let base = near.map_or(0x5000_0000, |a| (a & !0xFFFF) + 0x10_0000);
        let a = base + *n;
        *n += size.next_multiple_of(0x1000);
        self.map(a, vec![0; size as usize]);
        Ok(a)
    }
    fn free(&self, addr: Addr, _size: u64) -> Result<()> {
        let mut r = self.regions.write().unwrap();
        let i = r.iter().position(|x| x.0 == addr).ok_or(Error::NoAccess { addr })?;
        r.remove(i);
        Ok(())
    }
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
}

pub const GAME: Addr = 0x1_4000_0000;

/// game.exe: "health decrement" routine at +1000 (`sub [rcx+E0],eax` at +1005), a pointer
/// chain `[[game.exe+3000]+8]+8` -> 0x1234, "Hello" at +3010, 0x2A at +3020.
pub fn game() -> Arc<TestProc> {
    let mut img = vec![0xCCu8; 0x4000];
    let code = hex("48 89 5C 24 08 29 81 E0 00 00 00 8B 81 E0 00 00 00 8B 05 09 20 00 00 C3");
    img[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    img[0x3000..0x3008].copy_from_slice(&0x2000_0000u64.to_le_bytes());
    img[0x3010..0x3016].copy_from_slice(b"Hello\0");
    img[0x3020..0x3024].copy_from_slice(&0x2Au32.to_le_bytes());
    let p = TestProc {
        regions: RwLock::new(Vec::new()),
        mods: vec![Module { name: "game.exe".into(), path: "/x/game.exe".into(), base: GAME, size: img.len() as u64 }],
        next: Mutex::new(0),
    };
    p.map(GAME, img);
    let mut heap = vec![0u8; 0x100];
    heap[8..16].copy_from_slice(&0x2000_0080u64.to_le_bytes());
    heap[0x88..0x90].copy_from_slice(&0x1234u64.to_le_bytes());
    p.map(0x2000_0000, heap);
    Arc::new(p)
}

#[derive(Default)]
pub struct Cap {
    pub out: Mutex<Vec<String>>,
    pub hotkeys: Mutex<Vec<(u32, Vec<i64>)>>,
    pub speed: Mutex<Option<f64>>,
}

impl Host for Cap {
    fn print(&self, text: &str) {
        self.out.lock().unwrap().push(text.to_string());
    }
    fn register_hotkey(&self, id: u32, keys: &[i64]) -> Result<()> {
        self.hotkeys.lock().unwrap().push((id, keys.to_vec()));
        Ok(())
    }
    fn set_speed(&self, speed: f64) -> Result<()> {
        *self.speed.lock().unwrap() = Some(speed);
        Ok(())
    }
}

/// Engine bound to `game()` with a capturing host.
pub fn engine() -> (Engine, Arc<TestProc>, Arc<Cap>) {
    let e = Engine::new(EngineOptions::default()).unwrap();
    let p = game();
    e.set_process(Some(p.clone())).unwrap();
    let cap = Arc::new(Cap::default());
    e.set_host(cap.clone());
    (e, p, cap)
}

#[track_caller]
pub fn run(e: &Engine, src: &str) -> Vec<String> {
    e.exec(src, "test").unwrap_or_else(|err| panic!("script failed: {err}"))
}

pub fn read_u32(p: &dyn Process, a: Addr) -> u32 {
    let mut b = [0u8; 4];
    p.read_exact(a, &mut b).unwrap();
    u32::from_le_bytes(b)
}

pub const HEALTH_SCRIPT: &str = r#"
{ Game   : game.exe }
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
  xor eax,eax
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
