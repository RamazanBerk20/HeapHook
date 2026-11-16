//! Test double: a process with several regions (protection, kind, path) and modules.
#![allow(dead_code)]
use std::sync::RwLock;

use hh_core::{Addr, Error, Memory, Module, Process, Prot, Region, RegionKind, Result};

pub struct FakeProc {
    pub regions: RwLock<Vec<(Region, Vec<u8>)>>,
    pub modules: Vec<Module>,
    pub ptr: usize,
}

pub const RW: Prot = Prot { r: true, w: true, x: false };
pub const RX: Prot = Prot { r: true, w: false, x: true };
pub const R: Prot = Prot { r: true, w: false, x: false };

impl FakeProc {
    pub fn new() -> Self {
        FakeProc { regions: RwLock::new(Vec::new()), modules: Vec::new(), ptr: 8 }
    }
    pub fn add(&mut self, start: Addr, data: Vec<u8>, prot: Prot, kind: RegionKind, path: Option<&str>) {
        let r = Region { start, size: data.len() as u64, prot, kind, shared: false, path: path.map(Into::into) };
        let mut v = self.regions.write().unwrap();
        v.push((r, data));
        v.sort_by_key(|x| x.0.start);
    }
    pub fn module(&mut self, name: &str, base: Addr, size: u64) {
        self.modules.push(Module { name: name.into(), path: format!("/nonexistent/{name}"), base, size });
    }
    pub fn put(&self, addr: Addr, data: &[u8]) {
        self.write(addr, data).unwrap();
    }
    pub fn put_u64(&self, addr: Addr, v: u64) {
        self.put(addr, &v.to_le_bytes());
    }
}

impl Memory for FakeProc {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        let v = self.regions.read().unwrap();
        let mut n = 0;
        while n < buf.len() {
            let a = addr + n as u64;
            let Some((r, d)) = v.iter().find(|(r, _)| r.prot.r && a >= r.start && a < r.start + r.size) else { break };
            let o = (a - r.start) as usize;
            let k = (buf.len() - n).min(d.len() - o);
            buf[n..n + k].copy_from_slice(&d[o..o + k]);
            n += k;
        }
        if n == 0 { Err(Error::NoAccess { addr }) } else { Ok(n) }
    }
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        let mut v = self.regions.write().unwrap();
        for (i, b) in data.iter().enumerate() {
            let a = addr + i as u64;
            let (r, d) = v
                .iter_mut()
                .find(|(r, _)| a >= r.start && a < r.start + r.size)
                .ok_or(Error::NoAccess { addr: a })?;
            d[(a - r.start) as usize] = *b;
        }
        Ok(())
    }
    fn pointer_size(&self) -> usize {
        self.ptr
    }
}

impl Process for FakeProc {
    fn pid(&self) -> u32 {
        0
    }
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(self.regions.read().unwrap().iter().map(|x| x.0.clone()).collect())
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.modules.clone())
    }
}

/// Assembles `lines` (address, instruction) with hh-asm into the process memory.
pub fn asm(p: &FakeProc, lines: &[(Addr, &str)]) {
    let syms = hh_asm::SymbolTable::default();
    for (a, t) in lines {
        let b = hh_asm::assemble(p, &syms, *a, t).unwrap_or_else(|e| panic!("{t}: {e}"));
        p.put(*a, &b);
    }
}

/// Assembles `lines` one after another from `start`; returns each instruction's address.
pub fn asm_seq(p: &FakeProc, start: Addr, lines: &[&str]) -> Vec<Addr> {
    let syms = hh_asm::SymbolTable::default();
    let mut a = start;
    let mut out = Vec::new();
    for t in lines {
        let b = hh_asm::assemble(p, &syms, a, t).unwrap_or_else(|e| panic!("{t}: {e}"));
        p.put(a, &b);
        out.push(a);
        a += b.len() as u64;
    }
    out
}
