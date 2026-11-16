//! "Create process" and the speedhack over hh-inject. The speedhack lives in the Lua
//! console's slot so Lua's `speedhack_setSpeed` and the UI drive the same control block.
use std::path::PathBuf;
use std::process::Child;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hh_inject::{LaunchOptions, Speedhack, SpeedhackStatus};
use serde::Deserialize;

use crate::commands::{App, Opened, R, lock, s};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CreateReq {
    pub program: String,
    /// Shell-like: split on whitespace, `"..."` groups.
    pub args: String,
    pub cwd: String,
    pub speedhack: bool,
}

/// `a "b c" d` -> `[a, b c, d]`.
fn split_args(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut q, mut any) = (Vec::new(), String::new(), false, false);
    for c in s.chars() {
        match c {
            '"' => (q, any) = (!q, true),
            c if c.is_whitespace() && !q => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => (cur.push(c), any = true).1,
        }
    }
    if any {
        out.push(cur);
    }
    out
}

impl App {
    /// Launches `program` (with the speedhack library preloaded when asked) and opens it.
    pub fn process_create(&self, req: &CreateReq) -> R<Opened> {
        if req.program.trim().is_empty() {
            return Err("no program given".into());
        }
        let o = LaunchOptions {
            program: PathBuf::from(req.program.trim()),
            args: split_args(&req.args),
            cwd: Some(req.cwd.trim()).filter(|c| !c.is_empty()).map(PathBuf::from),
            speedhack: req.speedhack,
            ..LaunchOptions::default()
        };
        let l = hh_inject::launch(&o).map_err(s)?;
        let pid = l.pid;
        self.keep_child(l.child);
        let info = match self.open_process(pid) {
            Ok(i) => i,
            Err(e) => {
                self.kill_child(pid);
                return Err(e);
            }
        };
        if req.speedhack {
            // The control block appears once the loader has run the library's initializer.
            let t0 = Instant::now();
            loop {
                let err = match self.speed_find() {
                    Ok(Some(_)) => break,
                    Ok(None) if t0.elapsed() <= Duration::from_secs(2) => None,
                    Ok(None) => Some(format!("{} (pid {pid}) was stopped: the speedhack library did not load (static or setuid binary?)", info.name)),
                    Err(e) => Some(e),
                };
                if let Some(e) = err {
                    // Do not leave a half-started process open that the UI does not show.
                    let _ = self.close_process();
                    self.kill_child(pid);
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        Ok(info)
    }

    /// Children we launched are reaped here so they do not linger as zombies.
    fn keep_child(&self, c: Child) {
        self.reap_children();
        lock(&self.x.children).push(c);
    }

    /// Reaps launched children that exited. A child the debugger traces is never waited on:
    /// `waitpid` on a tracee takes the ptrace stops the debugger thread must see. The
    /// session's debugger lock is held throughout, so no attach can start in between; the
    /// traced child is reaped on a later call, after detach. Only a real exit drops a
    /// `Child` (`try_wait` on an untraced child reports nothing else).
    pub fn reap_children(&self) {
        let sess = self.session().ok();
        let dbg = sess.as_ref().map(|s| lock(&s.dbg));
        let traced = sess.as_ref().filter(|_| dbg.as_ref().is_some_and(|d| d.is_some())).map(|s| s.info.pid);
        lock(&self.x.children).retain_mut(|c| Some(c.id()) == traced || !matches!(c.try_wait(), Ok(Some(_))));
        drop(dbg);
    }

    /// Kills a launched child that is not (or no longer) the debugged target and reaps it.
    fn kill_child(&self, pid: u32) {
        if self.session().is_ok_and(|s| s.info.pid == pid && lock(&s.dbg).is_some()) {
            let _ = self.debug_detach();
        }
        let c = {
            let mut g = lock(&self.x.children);
            g.iter().position(|c| c.id() == pid).map(|i| g.remove(i))
        };
        if let Some(mut c) = c {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Looks the control block up in the opened process (cached in the console slot).
    fn speed_find(&self) -> R<Option<Arc<Speedhack>>> {
        let slot = &self.x.lua.console.speedhack;
        if let Some(s) = lock(slot).clone() {
            return Ok(Some(s));
        }
        let found = Speedhack::find(self.session()?.proc.clone()).map_err(s)?.map(Arc::new);
        *lock(slot) = found.clone();
        Ok(found)
    }

    /// `None` when the process has no speedhack.
    pub fn speed_get(&self) -> R<Option<SpeedhackStatus>> {
        match self.speed_find()? {
            Some(sh) => sh.status().map(Some).map_err(s),
            None => Ok(None),
        }
    }

    pub fn speed_set(&self, speed: f64) -> R<SpeedhackStatus> {
        let sh = self.speed_find()?.ok_or("this process was not started with the speedhack (use Create process)")?;
        sh.set_speed(speed).map_err(s)?;
        sh.status().map_err(s)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn args() {
        assert_eq!(super::split_args(r#"-a "b c"  d """#), ["-a", "b c", "d", ""]);
        assert!(super::split_args("  ").is_empty());
    }
}
