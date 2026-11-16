//! Speedhack for processes HeapHook launches itself.
//!
//! [`launch`] starts the program with the speedhack library (`payload/`, a separate cdylib
//! crate) in `LD_PRELOAD`, so the dynamic loader maps it before `main` and its exported
//! clock/sleep functions interpose libc's. [`Speedhack::find`] then locates the library's
//! `HH_SPEEDHACK` control block in the child and [`Speedhack::set_speed`] changes the speed
//! with two ordinary memory writes. Nothing is injected into running processes. On Windows
//! there is no loader preload, so a speedhack launch returns `Unsupported`.
//!
//! What the speedhack cannot affect, and how fork/exec children behave, is documented in
//! the payload (`payload/src/lib.rs`). Short version: only calls that go through the
//! dynamic symbols `clock_gettime`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`,
//! `usleep`, `sleep`, `poll`, `epoll_wait`, `select` are scaled; raw syscalls, direct vDSO
//! calls, static/setuid binaries and `rdtsc` are not. Exec'd children inherit `LD_PRELOAD`
//! and run their own copy at speed 1.0.
//!
//! Shipping: build the payload with
//! `cargo build --release --manifest-path crates/hh-inject/payload/Cargo.toml` and put
//! `libhh_speedhack.so` next to the HeapHook executable (or point [`PAYLOAD_ENV`] at it when
//! the bundle format puts resources elsewhere). See [`payload_path`].
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use hh_core::{Addr, Error, Pid, Process, Result};
use serde::{Deserialize, Serialize};

/// File name of the speedhack library.
pub const PAYLOAD_FILE: &str = if cfg!(windows) {
    "hh_speedhack.dll"
} else {
    "libhh_speedhack.so"
};
/// Environment variable naming the speedhack library, checked after the executable's dir.
pub const PAYLOAD_ENV: &str = "HH_SPEEDHACK_LIB";
/// Largest accepted speed; beyond this the payload's i64 nanosecond math gets close to
/// saturating within a session.
pub const MAX_SPEED: f64 = 1000.0;

// Layout of the payload's `Control` (payload/src/lib.rs); keep in sync.
const SYMBOL: &str = "HH_SPEEDHACK";
const MAGIC: u32 = 0x4853_4848;
const OFF_MAGIC: Addr = 0;
const OFF_VERSION: Addr = 4;
const OFF_GENERATION: Addr = 8;
const OFF_SPEED: Addr = 16;

fn dev_payload() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("payload/target/release")
        .join(PAYLOAD_FILE)
}

/// The speedhack library: next to the current executable, else in `<prefix>/lib/HeapHook`,
/// else `$HH_SPEEDHACK_LIB`, else (debug builds only) the payload crate's release build
/// output. Absolute. On Unix a file other users could have replaced is refused.
pub fn payload_path() -> Result<PathBuf> {
    let next_to_exe = std::env::current_exe()
        .ok()
        .and_then(|e| Some(e.parent()?.join(PAYLOAD_FILE)));
    // Installed bundles (deb/rpm/AppImage) put Tauri resources in <prefix>/lib/HeapHook.
    let bundled = std::env::current_exe()
        .ok()
        .and_then(|e| Some(e.parent()?.parent()?.join("lib/HeapHook").join(PAYLOAD_FILE)));
    let env = std::env::var_os(PAYLOAD_ENV).map(PathBuf::from);
    // Release builds run on users' machines, where the build machine's path means nothing
    // and anyone could create it.
    let dev = cfg!(debug_assertions).then(dev_payload);
    let path = [next_to_exe, bundled, env, dev]
        .into_iter()
        .flatten()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            Error::Other(format!(
                "{PAYLOAD_FILE} not found next to the executable, in <prefix>/lib/HeapHook, in \
                 ${PAYLOAD_ENV} or (debug builds) in the payload build output; build it with \
                 `cargo build --release --manifest-path crates/hh-inject/payload/Cargo.toml`"
            ))
        })?;
    let path = path.canonicalize()?;
    check_not_replaceable(&path)?;
    Ok(path)
}

/// The library is preloaded into every launched program: refuse one another user could
/// replace. See [`check_path_owners`].
#[cfg(unix)]
fn check_not_replaceable(lib: &Path) -> Result<()> {
    check_path_owners(lib, unsafe { libc::geteuid() })
}

/// `lib` (a canonical path) and every directory above it must be owned by `me` or root and
/// not writable by group or others. A group/world-writable directory is acceptable only with
/// the sticky bit, as an ancestor whose next component is owned by `me` or root (then nobody
/// else can rename or delete that component): `/tmp/<my dir>/lib.so` passes.
#[cfg(unix)]
fn check_path_owners(lib: &Path, me: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let trusted = |uid: u32| uid == me || uid == 0;
    let refuse = |what: &Path, why: String| {
        Err(Error::Permission(format!(
            "refusing speedhack library {}: {} {why}",
            lib.display(),
            what.display()
        )))
    };
    let m = std::fs::metadata(lib)?;
    if !trusted(m.uid()) {
        return refuse(lib, format!("is owned by another user (uid {})", m.uid()));
    }
    if m.mode() & 0o022 != 0 {
        return refuse(lib, format!("is writable by group or others (mode {:o}); fix with `chmod go-w`", m.mode() & 0o7777));
    }
    // Every component checked so far (the next one below `dir`) is owned by `me` or root.
    for dir in lib.ancestors().skip(1) {
        let m = std::fs::metadata(dir)?;
        if !trusted(m.uid()) {
            return refuse(dir, format!("(a directory above it) is owned by another user (uid {})", m.uid()));
        }
        if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
            return refuse(
                dir,
                format!(
                    "(a directory above it) is writable by group or others without the sticky bit (mode {:o}), so they could replace it",
                    m.mode() & 0o7777
                ),
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_not_replaceable(_lib: &Path) -> Result<()> {
    Ok(())
}

/// Speedhack works only in x86-64 programs: refuse ELF files of another class or machine.
/// Non-ELF programs (scripts) and unreadable paths are left for the spawn to handle.
fn check_speedhack_arch(o: &LaunchOptions) -> Result<()> {
    let p = &o.program;
    let path = if p.components().count() > 1 {
        // The child chdirs before exec, so a relative path is relative to `cwd`.
        match &o.cwd {
            Some(dir) => dir.join(p),
            None => p.clone(),
        }
    } else {
        let search = match o.env.iter().rfind(|(k, _)| k == "PATH") {
            Some((_, v)) => Some(OsString::from(v)),
            None => std::env::var_os("PATH"),
        };
        let Some(found) = search
            .iter()
            .flat_map(std::env::split_paths)
            .map(|d| d.join(p))
            .find(|c| c.is_file())
        else {
            return Ok(());
        };
        found
    };
    let mut h = [0u8; 20];
    let Ok(()) = std::fs::File::open(&path).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut h)) else {
        return Ok(());
    };
    if h[..4] != *b"\x7fELF" {
        return Ok(());
    }
    // EI_CLASS 2 = 64-bit, EI_DATA 1 = little endian, e_machine 62 = x86-64.
    let machine = u16::from_le_bytes([h[18], h[19]]);
    if h[4] != 2 || h[5] != 1 || machine != 62 {
        return Err(Error::Other(format!(
            "speedhack supports x86-64 programs only; {} is a {} ELF (machine {machine})",
            path.display(),
            if h[4] == 1 { "32-bit" } else { "non-x86-64" }
        )));
    }
    Ok(())
}

/// Builds the payload in release mode with cargo (for tests and dev setups); returns its path.
pub fn build_payload() -> Result<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("payload");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "--release", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(dir.join("target"))
        .status()?;
    if !status.success() {
        return Err(Error::Other(format!("building the speedhack payload failed: {status}")));
    }
    Ok(dev_payload())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LaunchOptions {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// Added to (or overriding) HeapHook's own environment.
    pub env: Vec<(String, String)>,
    pub speedhack: bool,
    /// Pipe stdin/stdout/stderr (taken from `Launched::child`) instead of inheriting them.
    pub pipe_stdio: bool,
}

#[derive(Debug)]
pub struct Launched {
    pub pid: Pid,
    /// Keep it to wait for the child / use its pipes; dropping it does not kill the child.
    pub child: Child,
}

/// Spawns the program, with the speedhack library preloaded when `speedhack` is set.
pub fn launch(o: &LaunchOptions) -> Result<Launched> {
    let mut cmd = Command::new(&o.program);
    cmd.args(&o.args).envs(o.env.iter().map(|(k, v)| (k, v)));
    if let Some(dir) = &o.cwd {
        cmd.current_dir(dir);
    }
    if o.pipe_stdio {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }
    if o.speedhack {
        if cfg!(windows) {
            return Err(Error::Unsupported(
                "speedhack on Windows needs library injection, which is not implemented",
            ));
        }
        check_speedhack_arch(o)?;
        let existing = match o.env.iter().rfind(|(k, _)| k == "LD_PRELOAD") {
            Some((_, v)) => Some(OsString::from(v)),
            None => std::env::var_os("LD_PRELOAD"),
        };
        cmd.env("LD_PRELOAD", preload_value(existing.as_deref(), &payload_path()?)?);
    }
    // Without a pre_exec hook std spawns with posix_spawn (vfork), which resumes us when the
    // child releases our address space, before the kernel has switched it to the new image:
    // a handle opened then (`/proc/<pid>/mem`, comm, exe) still describes HeapHook itself.
    // With a hook std forks and waits for its close-on-exec pipe to close, which happens only
    // after the new image is installed.
    #[cfg(unix)]
    unsafe {
        // SAFETY: the hook does nothing, so it is trivially async-signal-safe.
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || Ok(()));
    }
    let child = cmd.spawn()?;
    Ok(Launched {
        pid: child.id(),
        child,
    })
}

/// `existing` with `lib` appended.
fn preload_value(existing: Option<&OsStr>, lib: &Path) -> Result<OsString> {
    let s = lib.as_os_str();
    // ld.so splits LD_PRELOAD on both.
    if s.as_encoded_bytes().iter().any(|b| matches!(b, b':' | b' ')) {
        return Err(Error::Other(format!(
            "speedhack library path {} contains ':' or ' ', which LD_PRELOAD cannot express",
            lib.display()
        )));
    }
    let mut v = existing.map(OsString::from).unwrap_or_default();
    if !v.is_empty() {
        v.push(":");
    }
    v.push(s);
    Ok(v)
}

/// The speedhack control block inside a process that loaded the payload.
pub struct Speedhack {
    process: Arc<dyn Process>,
    addr: Addr,
    /// Where the library was mapped when found: an exec or a reused pid moves or drops it.
    module: (Addr, String),
}

/// Error text while the loader has not finished mapping or initializing the library.
pub const NOT_READY: &str = "speedhack library not ready yet";
/// Error text once the process behind a [`Speedhack`] exec'd, exited or its pid was reused.
pub const PROCESS_CHANGED: &str = "process changed since the speedhack was found (exec'd, exited or pid reused)";
const BLOCK_LEN: u64 = 32;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeedhackStatus {
    pub pid: Pid,
    /// Control block address, hex string.
    pub addr: String,
    pub speed: f64,
    /// Number of speed changes so far.
    pub generation: u32,
}

impl Speedhack {
    /// The payload's control block, or None when the library is not (yet) loaded or not
    /// ready: mapped readable and writable, initialized (magic and version present), and the
    /// same on two looks a few ms apart. Right after `launch` use [`Speedhack::wait`].
    pub fn find(process: Arc<dyn Process>) -> Result<Option<Speedhack>> {
        let Some(s) = Self::look(process)? else {
            return Ok(None);
        };
        // The loader maps a library one segment at a time; a second look confirms the
        // module and block did not move under us.
        std::thread::sleep(std::time::Duration::from_millis(5));
        Ok(Self::look(s.process.clone())?.filter(|again| again.addr == s.addr && again.module == s.module))
    }

    /// Calls [`Speedhack::find`] until it succeeds, or returns None once the process exited
    /// or `timeout` passed without the library loading (e.g. a static or setuid binary).
    pub fn wait(process: Arc<dyn Process>, timeout: std::time::Duration) -> Result<Option<Speedhack>> {
        let t0 = std::time::Instant::now();
        loop {
            match Self::find(process.clone()) {
                Ok(Some(s)) => return Ok(Some(s)),
                Ok(None) if process.is_alive() && t0.elapsed() <= timeout => {}
                Ok(None) | Err(Error::ProcessGone) => return Ok(None),
                Err(e) => return Err(e),
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn look(process: Arc<dyn Process>) -> Result<Option<Speedhack>> {
        let Some(m) = process
            .modules()?
            .into_iter()
            .find(|m| m.name == PAYLOAD_FILE)
        else {
            return Ok(None);
        };
        let addr = hh_asm::module_symbols(&*process, &m)
            .into_iter()
            .find(|s| s.name == SYMBOL)
            .map(|s| s.addr)
            .ok_or_else(|| Error::Other(format!("{} exports no {SYMBOL}", m.path)))?;
        let s = Speedhack { process, addr, module: (m.base, m.path) };
        match s.block_ready() {
            Ok(()) => Ok(Some(s)),
            Err(Error::Other(e)) if e == NOT_READY => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The block is mapped readable and writable and carries the magic; version checked.
    fn block_ready(&self) -> Result<()> {
        let not_ready = || Error::Other(NOT_READY.into());
        let end = self.addr + BLOCK_LEN;
        let mapped = self.process.regions()?.iter().any(|r| {
            r.start <= self.addr && end <= r.start + r.size && r.prot.r && r.prot.w
        });
        if !mapped || self.read_u32(OFF_MAGIC).map_err(|_| not_ready())? != MAGIC {
            return Err(not_ready());
        }
        match self.read_u32(OFF_VERSION).map_err(|_| not_ready())? {
            1 => Ok(()),
            v => Err(Error::Other(format!("speedhack control block version {v}, want 1"))),
        }
    }

    /// Before every access: the library is still where it was found (else
    /// [`PROCESS_CHANGED`]) and the block is ready (else [`NOT_READY`]).
    fn validate(&self) -> Result<()> {
        let here = self
            .process
            .modules()?
            .into_iter()
            .any(|m| m.name == PAYLOAD_FILE && (m.base, &m.path) == (self.module.0, &self.module.1));
        if !here {
            return Err(if self.process.is_alive() {
                Error::Other(PROCESS_CHANGED.into())
            } else {
                Error::ProcessGone
            });
        }
        self.block_ready()
    }

    fn read_u32(&self, off: Addr) -> Result<u32> {
        let mut b = [0; 4];
        self.process.read_exact(self.addr + off, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Sets the speed (1.0 = normal); accepts finite values in (0, [`MAX_SPEED`]].
    pub fn set_speed(&self, speed: f64) -> Result<()> {
        if !(speed > 0.0 && speed <= MAX_SPEED) {
            return Err(Error::Other(format!(
                "invalid speed {speed}: must be > 0 and <= {MAX_SPEED}"
            )));
        }
        self.validate()?;
        // Speed first, then the generation bump the payload polls for.
        self.process
            .write(self.addr + OFF_SPEED, &speed.to_le_bytes())?;
        let g = self.read_u32(OFF_GENERATION)?.wrapping_add(1);
        self.process
            .write(self.addr + OFF_GENERATION, &g.to_le_bytes())
    }

    /// The speed last written to the control block.
    pub fn speed(&self) -> Result<f64> {
        self.validate()?;
        let mut b = [0; 8];
        self.process.read_exact(self.addr + OFF_SPEED, &mut b)?;
        Ok(f64::from_le_bytes(b))
    }

    pub fn status(&self) -> Result<SpeedhackStatus> {
        // speed() validates.
        Ok(SpeedhackStatus {
            pid: self.process.pid(),
            addr: format!("{:#x}", self.addr),
            speed: self.speed()?,
            generation: self.read_u32(OFF_GENERATION)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hh_core::Memory;

    /// Second release audit I1. Trees under the temp directory; another user's ownership is
    /// simulated by checking as a different uid (real foreign-owned files need root).
    #[cfg(unix)]
    #[test]
    fn library_path_ownership_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        let me = unsafe { libc::geteuid() };
        let base = std::env::temp_dir().join(format!("hh-inject-perm-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let base = base.canonicalize().unwrap();
        let chmod = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        chmod(&base, 0o700);
        if check_path_owners(&base, me).is_err() {
            // The temp directory itself is not trustworthy here; nothing below it can pass.
            eprintln!("skipping: {} fails the check", base.display());
            return;
        }
        let (outer, inner) = (base.join("outer"), base.join("outer/inner"));
        std::fs::create_dir_all(&inner).unwrap();
        let lib = inner.join("lib.so");
        std::fs::write(&lib, b"x").unwrap();
        let set = |o: u32, i: u32, f: u32| {
            chmod(&outer, o);
            chmod(&inner, i);
            chmod(&lib, f);
        };
        let ok = |what: &str| check_path_owners(&lib, me).unwrap_or_else(|e| panic!("{what}: {e}"));
        let bad = |what: &str, needle: &str| {
            let e = check_path_owners(&lib, me).expect_err(what).to_string();
            assert!(e.contains(needle), "{what}: {e}");
        };
        set(0o755, 0o755, 0o644);
        ok("plain tree");
        set(0o755, 0o755, 0o664);
        bad("group-writable file", "writable by group or others");
        set(0o755, 0o775, 0o644);
        bad("group-writable parent", "without the sticky bit");
        // Above the immediate parent: missed before.
        set(0o777, 0o755, 0o644);
        bad("world-writable grandparent", "without the sticky bit");
        // Sticky like /tmp, with our own directory below it: fine.
        set(0o1777, 0o755, 0o644);
        ok("sticky grandparent");
        set(0o755, 0o1777, 0o644);
        ok("sticky parent, file owned by us");
        // A file (and directories) owned by someone else: checked as another uid.
        set(0o755, 0o755, 0o644);
        let e = check_path_owners(&lib, me.wrapping_add(4242)).unwrap_err().to_string();
        if me != 0 {
            assert!(e.contains("owned by another user"), "{e}");
        }
        chmod(&outer, 0o755);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn preload_appends() {
        let lib = Path::new("/opt/hh/libhh_speedhack.so");
        assert_eq!(preload_value(None, lib).unwrap(), lib.as_os_str());
        assert_eq!(
            preload_value(Some(OsStr::new("")), lib).unwrap(),
            lib.as_os_str()
        );
        assert_eq!(
            preload_value(Some(OsStr::new("/a.so")), lib).unwrap(),
            OsStr::new("/a.so:/opt/hh/libhh_speedhack.so")
        );
        assert!(preload_value(None, Path::new("/my dir/x.so")).is_err());
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hh-inject-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    #[test]
    fn replaceable_payload_refused() {
        use std::os::unix::fs::PermissionsExt;
        let set = |p: &Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        let d = scratch("perm");
        let lib = d.join(PAYLOAD_FILE);
        std::fs::write(&lib, b"x").unwrap();
        set(&d, 0o755);
        set(&lib, 0o644);
        check_not_replaceable(&lib).unwrap();
        set(&lib, 0o664);
        assert!(check_not_replaceable(&lib).unwrap_err().to_string().contains("group or others"));
        set(&lib, 0o644);
        set(&d, 0o777);
        assert!(check_not_replaceable(&lib).unwrap_err().to_string().contains("sticky"));
        set(&d, 0o1777);
        check_not_replaceable(&lib).unwrap();
        set(&d, 0o755);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(target_os = "linux")] // speedhack launch exists on Linux only
    #[test]
    fn speedhack_refuses_non_x86_64_elf() {
        let d = scratch("elf");
        let elf = |class: u8, machine: u16| {
            let mut h = vec![0u8; 64];
            h[..4].copy_from_slice(b"\x7fELF");
            (h[4], h[5]) = (class, 1);
            h[18..20].copy_from_slice(&machine.to_le_bytes());
            h
        };
        let launch_it = |name: &str, bytes: Vec<u8>| {
            std::fs::write(d.join(name), bytes).unwrap();
            check_speedhack_arch(&LaunchOptions { program: name.into(), cwd: Some(d.clone()), env: vec![("PATH".into(), d.display().to_string())], speedhack: true, ..Default::default() })
        };
        let e = launch_it("x86", elf(1, 3)).unwrap_err().to_string();
        assert!(e.contains("x86-64 programs only") && e.contains("32-bit"), "{e}");
        assert!(launch_it("arm64", elf(2, 183)).is_err());
        launch_it("x64", elf(2, 62)).unwrap();
        launch_it("script.sh", b"#!/bin/sh\n".to_vec()).unwrap();
        // Through launch itself, with a relative path resolved against cwd.
        let e = launch(&LaunchOptions { program: "./x86".into(), cwd: Some(d.clone()), speedhack: true, ..Default::default() }).unwrap_err();
        assert!(e.to_string().contains("32-bit"), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A mock process whose payload module (base 0x1000) and writable block can be changed.
    struct Mapped {
        mem: hh_core::MockProcess,
        module_base: std::sync::Mutex<Addr>,
        writable: std::sync::atomic::AtomicBool,
    }
    impl hh_core::Memory for Mapped {
        fn read(&self, a: Addr, b: &mut [u8]) -> Result<usize> {
            self.mem.read(a, b)
        }
        fn write(&self, a: Addr, d: &[u8]) -> Result<()> {
            self.mem.write(a, d)
        }
        fn pointer_size(&self) -> usize {
            8
        }
    }
    impl Process for Mapped {
        fn pid(&self) -> Pid {
            1
        }
        fn regions(&self) -> Result<Vec<hh_core::Region>> {
            let w = self.writable.load(std::sync::atomic::Ordering::Relaxed);
            Ok(vec![hh_core::Region {
                start: 0x1000,
                size: 32,
                prot: hh_core::Prot { r: true, w, x: false },
                kind: hh_core::RegionKind::Image,
                shared: false,
                cow: false,
                path: None,
            }])
        }
        fn modules(&self) -> Result<Vec<hh_core::Module>> {
            let base = *self.module_base.lock().unwrap();
            Ok(vec![hh_core::Module { name: PAYLOAD_FILE.into(), path: "/x".into(), base, size: 32 }])
        }
    }

    #[test]
    fn control_block_roundtrip_on_mock() {
        let mut block = vec![0; 32];
        block[..4].copy_from_slice(&MAGIC.to_le_bytes());
        block[4] = 1;
        let p = Arc::new(Mapped {
            mem: hh_core::MockProcess::new(0x1000, block),
            module_base: std::sync::Mutex::new(0x1000),
            writable: true.into(),
        });
        let s = Speedhack {
            process: p.clone(),
            addr: 0x1000,
            module: (0x1000, "/x".into()),
        };
        s.set_speed(2.5).unwrap();
        assert_eq!(s.speed().unwrap(), 2.5);
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, MAX_SPEED * 2.0] {
            assert!(s.set_speed(bad).is_err());
        }
        let st = s.status().unwrap();
        assert_eq!((st.speed, st.generation, st.addr.as_str()), (2.5, 1, "0x1000"));
        // A block that is not writable (yet), or lost its magic, is "not ready", not a raw
        // memory error.
        p.writable.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(s.set_speed(1.0).unwrap_err().to_string(), NOT_READY);
        p.writable.store(true, std::sync::atomic::Ordering::Relaxed);
        p.mem.write(0x1000, &[0; 4]).unwrap();
        assert_eq!(s.speed().unwrap_err().to_string(), NOT_READY);
        p.mem.write(0x1000, &MAGIC.to_le_bytes()).unwrap();
        s.set_speed(1.0).unwrap();
        // The library moved (exec, pid reuse): the handle refuses.
        *p.module_base.lock().unwrap() = 0x2000;
        assert_eq!(s.set_speed(1.0).unwrap_err().to_string(), PROCESS_CHANGED);
        assert_eq!(s.status().unwrap_err().to_string(), PROCESS_CHANGED);
    }
}
