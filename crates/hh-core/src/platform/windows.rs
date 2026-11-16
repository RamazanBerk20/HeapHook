//! Windows backend: Toolhelp snapshots for processes/modules/threads, Read/WriteProcessMemory,
//! VirtualQueryEx/AllocEx/FreeEx/ProtectEx, and NtSuspendProcess/NtResumeProcess.
use std::ffi::c_void;
use std::io;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH, ERROR_INVALID_PARAMETER, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CREATE_TOOLHELP_SNAPSHOT_FLAGS, CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW,
    Module32NextW, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
    Thread32Next,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_RELEASE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx,
    VirtualQueryEx,
};
use windows_sys::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    IsWow64Process, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};

use super::near_candidates;
use crate::{
    Addr, Error, Memory, Module, Pid, Process, ProcessInfo, Prot, Region, RegionKind, Result,
};

// Undocumented but stable since XP; not in windows-sys. raw-dylib: no import library needed.
#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())])
}

fn snapshot(flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, pid: Pid) -> Result<Handle> {
    for _ in 0..10 {
        let h = unsafe { CreateToolhelp32Snapshot(flags, pid) };
        if h != INVALID_HANDLE_VALUE {
            return Ok(Handle(h));
        }
        // ERROR_BAD_LENGTH: the module list changed while it was being copied; retry.
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_BAD_LENGTH as i32) {
            return Err(last_err(pid));
        }
    }
    Err(last_err(pid))
}

fn last_err(pid: Pid) -> Error {
    let e = io::Error::last_os_error();
    match e.raw_os_error().map(|c| c as u32) {
        Some(ERROR_ACCESS_DENIED) => Error::Permission(format!(
            "cannot access process {pid} ({e}). Run HeapHook as administrator to open elevated \
             processes; protected processes (anti-cheat, some system services) cannot be opened"
        )),
        _ => Error::Io(e),
    }
}

fn image_name(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    let ok =
        unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    let snap = snapshot(TH32CS_SNAPPROCESS, 0)?;
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
    while ok != 0 {
        let pid = e.th32ProcessID;
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        let exe = (!h.is_null()).then(|| image_name(Handle(h).0)).flatten();
        out.push(ProcessInfo {
            pid,
            name: wide(&e.szExeFile),
            exe,
        });
        ok = unsafe { Process32NextW(snap.0, &mut e) };
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

pub fn open(pid: Pid) -> Result<Arc<dyn Process>> {
    let access = PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION
        | PROCESS_QUERY_INFORMATION
        | PROCESS_SUSPEND_RESUME
        | PROCESS_SYNCHRONIZE;
    let h = unsafe { OpenProcess(access, 0, pid) };
    if h.is_null() {
        // OpenProcess reports a pid that does not exist as an invalid parameter.
        if io::Error::last_os_error().raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Err(Error::ProcessGone);
        }
        return Err(last_err(pid));
    }
    let h = Handle(h);
    let mut wow = 0;
    let ptr_size = if unsafe { IsWow64Process(h.0, &mut wow) } != 0 && wow != 0 {
        4
    } else {
        8
    };
    Ok(Arc::new(WinProcess { pid, h, ptr_size }))
}

struct WinProcess {
    pid: Pid,
    h: Handle,
    ptr_size: usize,
}

// SAFETY: a process handle is a kernel object reference, usable from any thread.
unsafe impl Send for WinProcess {}
unsafe impl Sync for WinProcess {}

fn prot_from(p: PAGE_PROTECTION_FLAGS) -> Prot {
    if p & (PAGE_GUARD | PAGE_NOACCESS) != 0 {
        return Prot::default();
    }
    let any = |m: PAGE_PROTECTION_FLAGS| p & m != 0;
    Prot {
        r: any(PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY),
        w: any(PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY),
        x: any(PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY),
    }
}

fn prot_to(p: Prot) -> PAGE_PROTECTION_FLAGS {
    // Windows has no write-only pages; w implies r.
    match (p.r, p.w, p.x) {
        (_, true, true) => PAGE_EXECUTE_READWRITE,
        (_, true, false) => PAGE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, false, true) => PAGE_EXECUTE,
        (true, false, false) => PAGE_READONLY,
        (false, false, false) => PAGE_NOACCESS,
    }
}

impl WinProcess {
    fn query(&self, addr: Addr) -> Option<MEMORY_BASIC_INFORMATION> {
        let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let n = unsafe {
            VirtualQueryEx(
                self.h.0,
                addr as *const c_void,
                &mut m,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        (n != 0).then_some(m)
    }

    /// Length of the run of committed, readable pages starting at `addr`, capped at `max`.
    fn readable_len(&self, addr: Addr, max: usize) -> usize {
        let mut end = addr;
        while end < addr + max as u64 {
            let Some(m) = self.query(end) else { break };
            if m.State != MEM_COMMIT || !prot_from(m.Protect).r {
                break;
            }
            end = m.BaseAddress as u64 + m.RegionSize as u64;
        }
        (end.saturating_sub(addr) as usize).min(max)
    }

    fn mem_err(&self, addr: Addr) -> Error {
        if self.is_alive() {
            Error::NoAccess { addr }
        } else {
            Error::ProcessGone
        }
    }

    fn status(&self, what: &str, status: i32) -> Result<()> {
        match status {
            0 => Ok(()),
            _ if !self.is_alive() => Err(Error::ProcessGone),
            s => Err(Error::Other(format!("{what} failed: NTSTATUS {s:#x}"))),
        }
    }

    fn mapped_name(&self, addr: Addr) -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let n = unsafe {
            GetMappedFileNameW(
                self.h.0,
                addr as *const c_void,
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
        // Device path form (\Device\HarddiskVolume3\...); good enough to identify the file.
        (n != 0).then(|| String::from_utf16_lossy(&buf[..n as usize]))
    }
}

impl Memory for WinProcess {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut n = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.h.0,
                addr as *const c_void,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut n,
            )
        };
        if ok != 0 || n > 0 {
            return Ok(n);
        }
        // ReadProcessMemory fails as a whole if any page is unreadable: retry up to the end of
        // the readable run so the caller gets the contiguous prefix.
        let len = self.readable_len(addr, buf.len());
        if len > 0 && len < buf.len() {
            let ok = unsafe {
                ReadProcessMemory(
                    self.h.0,
                    addr as *const c_void,
                    buf.as_mut_ptr().cast(),
                    len,
                    &mut n,
                )
            };
            if ok != 0 || n > 0 {
                return Ok(n);
            }
        }
        Err(self.mem_err(addr))
    }

    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let wpm = || {
            let mut n = 0usize;
            let ok = unsafe {
                WriteProcessMemory(
                    self.h.0,
                    addr as *const c_void,
                    data.as_ptr().cast(),
                    data.len(),
                    &mut n,
                )
            };
            ok != 0 && n == data.len()
        };
        if wpm() {
            return Ok(());
        }
        // Read-only pages (code): make them writable for the write, then put the old protection back.
        // shortcut: restores the first page's protection over the whole range; fine for patches
        // that do not straddle differently protected regions.
        let mut old = 0;
        if unsafe {
            VirtualProtectEx(
                self.h.0,
                addr as *const c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
        } == 0
        {
            return Err(self.mem_err(addr));
        }
        let ok = wpm();
        let mut tmp = 0;
        unsafe { VirtualProtectEx(self.h.0, addr as *const c_void, data.len(), old, &mut tmp) };
        if ok { Ok(()) } else { Err(self.mem_err(addr)) }
    }

    fn pointer_size(&self) -> usize {
        self.ptr_size
    }
}

impl Process for WinProcess {
    fn pid(&self) -> Pid {
        self.pid
    }

    fn is_alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.h.0, 0) == WAIT_TIMEOUT }
    }

    fn regions(&self) -> Result<Vec<Region>> {
        let mods = self.modules().unwrap_or_default();
        let mut out = Vec::new();
        let mut addr = 0u64;
        // VirtualQueryEx fails past the highest user address, which ends the walk.
        while let Some(m) = self.query(addr) {
            let (start, size) = (m.BaseAddress as u64, m.RegionSize as u64);
            if m.State == MEM_COMMIT {
                let kind = match m.Type {
                    MEM_IMAGE => RegionKind::Image,
                    MEM_MAPPED => RegionKind::Mapped,
                    _ => RegionKind::Private,
                };
                let path = match kind {
                    RegionKind::Image => mods
                        .iter()
                        .find(|md| md.base <= start && start < md.base + md.size)
                        .map(|md| md.path.clone()),
                    RegionKind::Mapped => self.mapped_name(start),
                    RegionKind::Private => None,
                };
                out.push(Region {
                    start,
                    size,
                    prot: prot_from(m.Protect),
                    kind,
                    shared: m.Type == MEM_MAPPED && m.Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY) == 0,
                    path,
                });
            }
            if start + size <= addr {
                break;
            }
            addr = start + size;
        }
        if out.is_empty() && !self.is_alive() {
            return Err(Error::ProcessGone);
        }
        Ok(out)
    }

    fn modules(&self) -> Result<Vec<Module>> {
        let snap = snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)?;
        let mut e: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = size_of::<MODULEENTRY32W>() as u32;
        let mut out = Vec::new();
        let mut ok = unsafe { Module32FirstW(snap.0, &mut e) };
        while ok != 0 {
            out.push(Module {
                name: wide(&e.szModule),
                path: wide(&e.szExePath),
                base: e.modBaseAddr as u64,
                size: e.modBaseSize as u64,
            });
            ok = unsafe { Module32NextW(snap.0, &mut e) };
        }
        out.sort_by_key(|m| m.base);
        Ok(out)
    }

    fn threads(&self) -> Result<Vec<u32>> {
        let snap = snapshot(TH32CS_SNAPTHREAD, 0)?;
        let mut e: THREADENTRY32 = unsafe { std::mem::zeroed() };
        e.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut out = Vec::new();
        let mut ok = unsafe { Thread32First(snap.0, &mut e) };
        while ok != 0 {
            if e.th32OwnerProcessID == self.pid {
                out.push(e.th32ThreadID);
            }
            ok = unsafe { Thread32Next(snap.0, &mut e) };
        }
        out.sort_unstable();
        Ok(out)
    }

    fn suspend(&self) -> Result<()> {
        self.status("NtSuspendProcess", unsafe { NtSuspendProcess(self.h.0) })
    }

    fn resume(&self) -> Result<()> {
        self.status("NtResumeProcess", unsafe { NtResumeProcess(self.h.0) })
    }

    fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> Result<Addr> {
        if size == 0 {
            return Err(Error::Other("alloc size is 0".into()));
        }
        let size_us = usize::try_from(size).map_err(|_| Error::Other("size too large".into()))?;
        let try_at = |at: Addr| unsafe {
            VirtualAllocEx(
                self.h.0,
                at as *const c_void,
                size_us,
                MEM_COMMIT | MEM_RESERVE,
                prot_to(prot),
            ) as Addr
        };
        let Some(near) = near else {
            return match try_at(0) {
                0 => Err(last_err(self.pid)),
                a => Ok(a),
            };
        };
        let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut si) };
        let gran = si.dwAllocationGranularity as u64;
        let (low, high) = (
            si.lpMinimumApplicationAddress as u64,
            si.lpMaximumApplicationAddress as u64 + 1,
        );
        // Everything that is not MEM_FREE (reserved counts as used) within reach of `near`.
        let mut used = Vec::new();
        let mut addr = near.saturating_sub(0x8000_0000).max(low);
        while addr < near.saturating_add(0x8000_0000).min(high) {
            let Some(m) = self.query(addr) else { break };
            let (start, end) = (
                m.BaseAddress as u64,
                m.BaseAddress as u64 + m.RegionSize as u64,
            );
            if m.State != MEM_FREE {
                used.push((start, end));
            }
            if end <= addr {
                break;
            }
            addr = end;
        }
        // The walk stopped early (end of address space): treat the rest as used.
        used.push((addr, u64::MAX));
        for at in near_candidates(&mut used, near, size, gran, low, high)
            .into_iter()
            .take(16)
        {
            match try_at(at) {
                0 => continue, // raced with another allocation
                a => return Ok(a),
            }
        }
        Err(Error::Other(format!(
            "no free memory within 2 GiB of {near:#x}"
        )))
    }

    /// Releases the whole allocation that starts at `addr`; Windows ignores `size` here.
    fn free(&self, addr: Addr, _size: u64) -> Result<()> {
        if unsafe { VirtualFreeEx(self.h.0, addr as *mut c_void, 0, MEM_RELEASE) } == 0 {
            return Err(last_err(self.pid));
        }
        Ok(())
    }

    fn protect(&self, addr: Addr, size: u64, prot: Prot) -> Result<Prot> {
        let mut old = 0;
        if unsafe {
            VirtualProtectEx(
                self.h.0,
                addr as *const c_void,
                size as usize,
                prot_to(prot),
                &mut old,
            )
        } == 0
        {
            return Err(last_err(self.pid));
        }
        Ok(prot_from(old))
    }
}
