//! Remote targets over hh-net: connect to an `hh-server`, list and open its processes. The
//! opened `RemoteProcess` becomes the session's process, so scanner, table, memory view,
//! pointer scanner and tools work unchanged. Authentication is challenge-response (the
//! token is never sent) but traffic is not encrypted after it.
use std::io::ErrorKind;
use std::path::PathBuf;

use hh_core::{Error, ProcessInfo};
use hh_net::RemoteHost;
use serde::{Deserialize, Serialize};

use crate::commands::{App, Opened, R, lock, s};

/// hh-server's default port, for an address typed without one.
const DEFAULT_PORT: u16 = 52736;

pub(crate) struct Conn {
    host: RemoteHost,
    addr: String,
}

/// `remote.json` in the config dir: the last server, and its token only when the user asked.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    addr: String,
    token: String,
}

#[derive(Debug, Serialize)]
pub struct SavedOut {
    pub addr: String,
    pub has_token: bool,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub addr: String,
    pub connected: bool,
}

/// Words for an hh-net error; a dropped connection says so plainly.
fn why(e: &Error) -> String {
    match e {
        Error::Io(io) if io.kind() == ErrorKind::ConnectionAborted => io.to_string().trim_start_matches("hh-net: ").to_string(),
        e => e.to_string(),
    }
}

fn is_lost(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == ErrorKind::ConnectionAborted)
}

impl App {
    fn remote_file(&self) -> Option<PathBuf> {
        self.config_dir().map(|d| d.join("remote.json"))
    }

    fn remote_load(&self) -> Saved {
        self.remote_file().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    /// Written owner-only (0600): it may hold a token.
    fn remote_store(&self, v: &Saved) -> R<()> {
        let Some(p) = self.remote_file() else { return Ok(()) };
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let text = serde_json::to_string_pretty(v).map_err(s)?;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        // An existing file keeps its old mode on open; tighten it.
        #[cfg(unix)]
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).map_err(|e| format!("{}: {e}", p.display()))?;
        std::io::Write::write_all(&mut f, text.as_bytes()).map_err(|e| format!("{}: {e}", p.display()))
    }

    pub fn remote_saved(&self) -> R<SavedOut> {
        let v = self.remote_load();
        Ok(SavedOut { has_token: !v.token.is_empty(), addr: v.addr })
    }

    pub fn remote_forget(&self) -> R<()> {
        self.remote_store(&Saved::default())
    }

    /// Connects (replacing an earlier connection; a remote target of it is closed first).
    /// An empty `token` uses the remembered one of that address.
    pub fn remote_connect(&self, addr: &str, token: &str, remember: bool) -> R<Status> {
        let mut addr = addr.trim().to_string();
        if addr.is_empty() {
            return Err("enter the server address (host:port)".into());
        }
        if !addr.contains(':') || addr.ends_with(']') {
            addr = format!("{addr}:{DEFAULT_PORT}");
        }
        let saved = self.remote_load();
        let token = if token.is_empty() && saved.addr == addr { saved.token.clone() } else { token.to_string() };
        if token.is_empty() {
            return Err("enter the server's token (hh-server prints it at start)".into());
        }
        let host = hh_net::connect(addr.as_str(), &token).map_err(|e| format!("{addr}: {}", why(&e)))?;
        self.remote_disconnect()?;
        *lock(&self.x.remote) = Some(Conn { host, addr: addr.clone() });
        let keep = if remember { token } else { String::new() };
        self.remote_store(&Saved { addr: addr.clone(), token: keep })?;
        Ok(Status { addr, connected: true })
    }

    fn host(&self) -> R<(RemoteHost, String)> {
        lock(&self.x.remote).as_ref().map(|c| (c.host.clone(), c.addr.clone())).ok_or_else(|| "not connected to a server".into())
    }

    pub fn remote_status(&self) -> R<Option<Status>> {
        let Ok((host, addr)) = self.host() else { return Ok(None) };
        let connected = !matches!(host.list_processes(), Err(ref e) if is_lost(e));
        Ok(Some(Status { addr, connected }))
    }

    pub fn remote_processes(&self) -> R<Vec<ProcessInfo>> {
        let (host, addr) = self.host()?;
        host.list_processes().map_err(|e| format!("{addr}: {}", why(&e)))
    }

    pub fn remote_open(&self, pid: u32) -> R<Opened> {
        let (host, addr) = self.host()?;
        let name = host.list_processes().ok().and_then(|l| l.into_iter().find(|p| p.pid == pid)).map_or_else(|| pid.to_string(), |p| p.name);
        let raw = host.open(pid).map_err(|e| format!("{addr}: {}", why(&e)))?;
        self.install_process(raw, pid, name, Some(addr))
    }

    /// Closes a remote target, then drops the connection.
    pub fn remote_disconnect(&self) -> R<()> {
        if self.session().is_ok_and(|s| s.info.remote.is_some()) {
            self.close_process()?;
        }
        *lock(&self.x.remote) = None;
        Ok(())
    }

    /// Why the remote target's connection is gone (`None`: local, or still connected).
    pub(crate) fn remote_lost(&self) -> Option<String> {
        self.session().ok()?.info.remote.as_ref()?;
        let (host, _) = self.host().ok()?;
        match host.list_processes() {
            // The UI names the server itself.
            Err(e) if is_lost(&e) => Some(why(&e)),
            _ => None,
        }
    }

    /// Refuses features that need the local machine while the target is remote.
    pub(crate) fn local_only(&self, what: &str) -> R<()> {
        match self.session().ok().and_then(|s| s.info.remote.clone()) {
            Some(addr) => Err(format!("{what} works on local processes only; the target is on {addr}")),
            None => Ok(()),
        }
    }
}
