//! HeapHook core contract: the types and traits every other crate builds on.
//! Changing a signature here is an architecture decision — ask the main loop first.
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

pub mod platform;

pub type Addr = u64;
pub type Pid = u32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot access memory at {addr:#x}")]
    NoAccess { addr: Addr },
    #[error("permission denied: {0}")]
    Permission(String),
    #[error("process is gone")]
    ProcessGone,
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("{0}")]
    Other(String),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub name: String,
    pub exe: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Prot {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    Image,
    Mapped,
    Private,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub start: Addr,
    pub size: u64,
    pub prot: Prot,
    pub kind: RegionKind,
    /// True for shared mappings (Linux maps flag `s`); false for private / copy-on-write ones.
    pub shared: bool,
    /// True only for pages still in the write-copy state (Windows PAGE_WRITECOPY /
    /// PAGE_EXECUTE_WRITECOPY). Always false on Linux, where maps cannot tell.
    #[serde(default)]
    pub cow: bool,
    /// Backing file or tag such as "[heap]" / "[stack]".
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base: Addr,
    pub size: u64,
}

/// Anything bytes can be read from and written to: a live process, a mock, a dump file.
pub trait Memory: Send + Sync {
    /// Reads up to `buf.len()` bytes starting at `addr`. Returns how many contiguous bytes
    /// were read from the start (may be short at a region boundary). Err if none.
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize>;
    /// Writes all of `data` or fails.
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()>;
    /// 4 or 8.
    fn pointer_size(&self) -> usize {
        8
    }

    fn read_exact(&self, addr: Addr, buf: &mut [u8]) -> Result<()> {
        match self.read(addr, buf)? {
            n if n == buf.len() => Ok(()),
            n => Err(Error::NoAccess {
                addr: addr + n as u64,
            }),
        }
    }
    fn read_ptr(&self, addr: Addr) -> Result<Addr> {
        let mut b = [0u8; 8];
        let n = self.pointer_size();
        self.read_exact(addr, &mut b[..n])?;
        Ok(u64::from_le_bytes(b))
    }
}

pub trait Process: Memory {
    fn pid(&self) -> Pid;
    fn is_alive(&self) -> bool {
        true
    }
    fn regions(&self) -> Result<Vec<Region>>;
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(Vec::new())
    }
    /// Thread ids.
    fn threads(&self) -> Result<Vec<u32>> {
        Err(Error::Unsupported("threads"))
    }
    /// Allocates memory in the target, preferably within ±2 GiB of `near` (for rel32 jumps).
    fn alloc(&self, _size: u64, _prot: Prot, _near: Option<Addr>) -> Result<Addr> {
        Err(Error::Unsupported("alloc"))
    }
    fn free(&self, _addr: Addr, _size: u64) -> Result<()> {
        Err(Error::Unsupported("free"))
    }
    /// Changes protection; returns the previous one.
    fn protect(&self, _addr: Addr, _size: u64, _prot: Prot) -> Result<Prot> {
        Err(Error::Unsupported("protect"))
    }
    fn suspend(&self) -> Result<()> {
        Err(Error::Unsupported("suspend"))
    }
    fn resume(&self) -> Result<()> {
        Err(Error::Unsupported("resume"))
    }
}

pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    platform::list_processes()
}

pub fn open(pid: Pid) -> Result<Arc<dyn Process>> {
    platform::open(pid)
}

/// In-memory fake process for tests: one rw region at `base`.
pub struct MockProcess {
    pub base: Addr,
    pub mem: RwLock<Vec<u8>>,
}

impl MockProcess {
    pub fn new(base: Addr, mem: Vec<u8>) -> Self {
        Self {
            base,
            mem: RwLock::new(mem),
        }
    }
    fn offset(&self, addr: Addr, len: usize) -> Result<usize> {
        match addr.checked_sub(self.base) {
            Some(o) if (o as usize) < len => Ok(o as usize),
            _ => Err(Error::NoAccess { addr }),
        }
    }
}

impl Memory for MockProcess {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        let mem = self.mem.read().unwrap();
        let o = self.offset(addr, mem.len())?;
        let n = buf.len().min(mem.len() - o);
        buf[..n].copy_from_slice(&mem[o..o + n]);
        Ok(n)
    }
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        let mut mem = self.mem.write().unwrap();
        let o = self.offset(addr, mem.len())?;
        mem.get_mut(o..o + data.len())
            .ok_or(Error::NoAccess { addr })?
            .copy_from_slice(data);
        Ok(())
    }
}

impl Process for MockProcess {
    fn pid(&self) -> Pid {
        0
    }
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(vec![Region {
            start: self.base,
            size: self.mem.read().unwrap().len() as u64,
            prot: Prot {
                r: true,
                w: true,
                x: false,
            },
            kind: RegionKind::Private,
            shared: false,
            cow: false,
            path: None,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_roundtrip() {
        let p = MockProcess::new(0x1000, vec![0; 16]);
        p.write(0x1008, &7u64.to_le_bytes()).unwrap();
        assert_eq!(p.read_ptr(0x1008).unwrap(), 7);
        let mut b = [0u8; 32];
        assert_eq!(p.read(0x1008, &mut b).unwrap(), 8);
        assert!(p.read(0x2000, &mut b).is_err());
        assert!(p.write(0x100c, &[0; 8]).is_err());
    }
}
