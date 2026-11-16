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

/// The speedhack library: next to the current executable, else `$HH_SPEEDHACK_LIB`, else
/// the payload crate's release build output (development checkouts). Absolute.
pub fn payload_path() -> Result<PathBuf> {
    let next_to_exe = std::env::current_exe()
        .ok()
        .and_then(|e| Some(e.parent()?.join(PAYLOAD_FILE)));
    let env = std::env::var_os(PAYLOAD_ENV).map(PathBuf::from);
    let path = [next_to_exe, env, Some(dev_payload())]
        .into_iter()
        .flatten()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            Error::Other(format!(
                "{PAYLOAD_FILE} not found next to the executable, in ${PAYLOAD_ENV} or in the \
                 payload build output; build it with `cargo build --release --manifest-path \
                 crates/hh-inject/payload/Cargo.toml`"
            ))
        })?;
    Ok(path.canonicalize()?)
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
        let existing = match o.env.iter().rfind(|(k, _)| k == "LD_PRELOAD") {
            Some((_, v)) => Some(OsString::from(v)),
            None => std::env::var_os("LD_PRELOAD"),
        };
        cmd.env("LD_PRELOAD", preload_value(existing.as_deref(), &payload_path()?)?);
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
}

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
    /// The payload's control block, or None when the library is not (yet) loaded or its
    /// initializer has not run yet (right after `launch`; retry shortly).
    pub fn find(process: Arc<dyn Process>) -> Result<Option<Speedhack>> {
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
        let s = Speedhack { process, addr };
        if s.read_u32(OFF_MAGIC)? != MAGIC {
            return Ok(None);
        }
        match s.read_u32(OFF_VERSION)? {
            1 => Ok(Some(s)),
            v => Err(Error::Other(format!("speedhack control block version {v}, want 1"))),
        }
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
        // Speed first, then the generation bump the payload polls for.
        self.process
            .write(self.addr + OFF_SPEED, &speed.to_le_bytes())?;
        let g = self.read_u32(OFF_GENERATION)?.wrapping_add(1);
        self.process
            .write(self.addr + OFF_GENERATION, &g.to_le_bytes())
    }

    /// The speed last written to the control block.
    pub fn speed(&self) -> Result<f64> {
        let mut b = [0; 8];
        self.process.read_exact(self.addr + OFF_SPEED, &mut b)?;
        Ok(f64::from_le_bytes(b))
    }

    pub fn status(&self) -> Result<SpeedhackStatus> {
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

    #[test]
    fn control_block_roundtrip_on_mock() {
        let p = Arc::new(hh_core::MockProcess::new(0x1000, vec![0; 32]));
        let s = Speedhack {
            process: p,
            addr: 0x1000,
        };
        s.set_speed(2.5).unwrap();
        assert_eq!(s.speed().unwrap(), 2.5);
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, MAX_SPEED * 2.0] {
            assert!(s.set_speed(bad).is_err());
        }
        let st = s.status().unwrap();
        assert_eq!((st.speed, st.generation, st.addr.as_str()), (2.5, 1, "0x1000"));
    }
}
