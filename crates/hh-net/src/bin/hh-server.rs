//! hh-server: serves this machine's processes to HeapHook clients over TCP.
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;

use hh_net::{LocalBackend, Server, ServerConfig, proto};

const USAGE: &str = "usage: hh-server [--listen ADDR:PORT] [--allow-remote] [--token TOKEN] [--read-only]

  --listen ADDR:PORT  address to listen on (default 127.0.0.1:52736)
  --allow-remote      required to listen on anything but a loopback address
  --token TOKEN       shared secret, at least 16 characters (default: $HH_SERVER_TOKEN, else a
                      random one is printed). Prefer the environment variable: command lines
                      are visible to other users.
  --read-only         reject write, alloc, free, protect, suspend and resume

The server exposes the memory of every process this user can access. Authentication is
challenge-response (the token is never sent) but traffic is NOT encrypted: use it on a
trusted network or through an SSH tunnel (ssh -L 52736:127.0.0.1:52736 host).";

/// Shortest user-supplied token; a weak one is the only real way past the authentication.
const MIN_TOKEN: usize = 16;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hh-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut listen = format!("127.0.0.1:{}", proto::DEFAULT_PORT);
    let (mut allow_remote, mut read_only) = (false, false);
    let mut token = std::env::var("HH_SERVER_TOKEN").ok().filter(|t| !t.is_empty());
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().ok_or(USAGE)?,
            "--token" => token = Some(args.next().ok_or(USAGE)?),
            "--allow-remote" => allow_remote = true,
            "--read-only" => read_only = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            _ => return Err(format!("unknown argument {a:?}\n{USAGE}")),
        }
    }
    let addrs: Vec<SocketAddr> = listen.to_socket_addrs().map_err(|e| format!("{listen}: {e}"))?.collect();
    if !allow_remote && addrs.iter().any(|a| !a.ip().is_loopback()) {
        return Err(format!("{listen} is not a loopback address; pass --allow-remote to expose process memory on the network"));
    }
    if let Some(t) = &token
        && t.chars().count() < MIN_TOKEN
    {
        return Err(format!(
            "the token must be at least {MIN_TOKEN} characters long (got {}); omit --token and \
             $HH_SERVER_TOKEN to have a random one generated",
            t.chars().count()
        ));
    }
    let generated = token.is_none();
    let token = match token {
        Some(t) => t,
        None => proto::generate_token().map_err(|e| e.to_string())?,
    };
    let mut cfg = ServerConfig::new(token.clone());
    cfg.read_only = read_only;
    let server = Server::bind(&addrs[..], cfg, Arc::new(LocalBackend)).map_err(|e| e.to_string())?;
    let addr = server.local_addr().map_err(|e| e.to_string())?;
    println!("hh-server listening on {addr}{}", if read_only { " (read-only)" } else { "" });
    if generated {
        println!("token: {token}");
    }
    server.run().map_err(|e| e.to_string())
}
