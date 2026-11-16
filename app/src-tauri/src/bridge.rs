//! Development-only HTTP bridge (cargo feature `dev-bridge`, flag `--dev-bridge <port>`):
//! serves `app/ui` and runs every IPC command over HTTP on 127.0.0.1, so the real frontend
//! can be driven in a normal browser against the real backend. No Tauri window is created;
//! native file dialogs and global hotkeys are unavailable (the UI falls back like the mock).
//!
//! Auth: a random token printed at startup. Page and assets need it as `?hh_token=` or the
//! cookie set when the page is first loaded with it; `POST /invoke/<cmd>` needs it in the
//! `x-hh-token` header. Body: the Tauri-style args object; answer `{"ok": v}` / `{"err": s}`.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use heaphook::commands::{App, R};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

type Dispatch = fn(&App, &str, &Value) -> Option<R<Value>>;

const MAX_BODY: usize = 256 << 20;

/// `--dev-bridge <port>` from the command line.
pub fn port_arg() -> Option<u16> {
    let mut it = std::env::args().skip_while(|a| a != "--dev-bridge").skip(1);
    let p = it.next()?;
    Some(p.parse().unwrap_or_else(|_| panic!("--dev-bridge needs a port number, got {p:?}")))
}

/// Tauri's argument naming: Rust `field_addr` arrives as JS `fieldAddr`.
fn camel(name: &str) -> String {
    let mut out = String::new();
    for (i, part) in name.split('_').enumerate() {
        let mut c = part.chars();
        match c.next() {
            Some(f) if i > 0 => out.extend(f.to_uppercase().chain(c)),
            _ => out.push_str(part),
        }
    }
    out
}

/// One command argument, decoded the way Tauri does (a missing key is `null`, so
/// `Option` arguments may be left out).
pub fn arg<T: DeserializeOwned>(args: &Value, cmd: &str, name: &str) -> R<T> {
    let key = camel(name);
    let v = args.get(&key).cloned().unwrap_or(Value::Null);
    serde_json::from_value(v).map_err(|e| format!("invalid args `{key}` for command `{cmd}`: {e}"))
}

fn token() -> String {
    // Unpredictable enough for a localhost dev tool: OS-seeded SipHash keys + time + pid.
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    for i in 0..2u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i);
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        h.write_u32(std::process::id());
        out += &format!("{:016x}", h.finish());
    }
    out
}

pub fn serve(port: u16, dispatch: Dispatch) {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ui").canonicalize().expect("app/ui directory");
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| panic!("dev bridge: cannot listen on 127.0.0.1:{port}: {e}"));
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let tok = token();
    let app = App::default();
    // A private per-run config dir: settings start at the defaults every run.
    let mut b = tempfile::Builder::new();
    b.prefix("heaphook-dev-bridge-");
    #[cfg(unix)]
    b.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let cfg_dir = b.tempdir().expect("temp dir");
    let cfg = cfg_dir.path();
    app.set_config_dir(cfg);
    app.start_driver();
    println!("HeapHook dev bridge (development only; never ship this build)");
    println!("  open:   http://127.0.0.1:{port}/?hh_token={tok}");
    println!("  token:  {tok}");
    println!("  config: {}", cfg.display());
    let _ = std::io::stdout().flush();
    for conn in listener.incoming().flatten() {
        let (app, tok, ui) = (app.clone(), tok.clone(), ui.clone());
        std::thread::spawn(move || {
            let _ = handle(conn, &app, &tok, &ui, dispatch);
        });
    }
}

struct Req {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    fn query_param(&self, name: &str) -> Option<&str> {
        self.query.split('&').find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
    }
    fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?.split(';').find_map(|kv| kv.trim().strip_prefix(name)?.strip_prefix('='))
    }
}

fn read_req(r: &mut BufReader<&TcpStream>) -> std::io::Result<Option<Req>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("/").to_string());
    let (path, query) = target.split_once('?').map_or((target.clone(), String::new()), |(p, q)| (p.to_string(), q.to_string()));
    let mut headers = Vec::new();
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut req = Req { method, path, query, headers, body: Vec::new() };
    let len: usize = req.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY {
        return Err(std::io::Error::other("body too large"));
    }
    req.body.resize(len, 0);
    r.read_exact(&mut req.body)?;
    Ok(Some(req))
}

fn respond(mut s: &TcpStream, status: &str, ctype: &str, extra: &str, body: &[u8]) -> std::io::Result<()> {
    write!(s, "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{extra}\r\n", body.len())?;
    s.write_all(body)?;
    s.flush()
}

fn handle(conn: TcpStream, app: &App, tok: &str, ui: &Path, dispatch: Dispatch) -> std::io::Result<()> {
    let _ = conn.set_nodelay(true);
    let mut r = BufReader::new(&conn);
    // Keep-alive: the browser reuses the connection for the next request.
    while let Some(req) = read_req(&mut r)? {
        if let Some(cmd) = req.path.strip_prefix("/invoke/") {
            if req.method != "POST" || req.header("x-hh-token") != Some(tok) {
                respond(&conn, "403 Forbidden", "text/plain", "", b"bad token")?;
                continue;
            }
            let args: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let out = match dispatch(app, cmd, &args) {
                Some(Ok(v)) => json!({ "ok": v }),
                Some(Err(e)) => json!({ "err": e }),
                None if cmd == "pick_path" => json!({ "err": "file dialogs need the desktop app" }),
                None => json!({ "err": format!("unknown command '{cmd}'") }),
            };
            respond(&conn, "200 OK", "application/json", "", out.to_string().as_bytes())?;
            continue;
        }
        let by_query = req.query_param("hh_token") == Some(tok);
        if req.method != "GET" || !(by_query || req.cookie("hh_token") == Some(tok)) {
            respond(&conn, "403 Forbidden", "text/plain", "", b"open the URL with ?hh_token= printed by the bridge")?;
            continue;
        }
        let name = req.path.trim_start_matches('/');
        let name = if name.is_empty() { "index.html" } else { name };
        let file: Option<PathBuf> = (!name.contains("..") && !name.contains('/') && !name.contains('\\')).then(|| ui.join(name));
        let cookie = if by_query { format!("Set-Cookie: hh_token={tok}; Path=/; HttpOnly; SameSite=Strict\r\n") } else { String::new() };
        match file.and_then(|f| std::fs::read(&f).ok().map(|b| (f, b))) {
            Some((f, body)) => {
                let ctype = match f.extension().and_then(|e| e.to_str()) {
                    Some("html") => "text/html; charset=utf-8",
                    Some("js") => "text/javascript; charset=utf-8",
                    Some("css") => "text/css; charset=utf-8",
                    Some("svg") => "image/svg+xml",
                    Some("png") => "image/png",
                    _ => "application/octet-stream",
                };
                respond(&conn, "200 OK", ctype, &cookie, &body)?;
            }
            None => respond(&conn, "404 Not Found", "text/plain", "", b"not found")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn camel_case_matches_tauri() {
        assert_eq!(super::camel("pass_signal"), "passSignal");
        assert_eq!(super::camel("field_addr"), "fieldAddr");
        assert_eq!(super::camel("addr"), "addr");
    }
}
