//! Command-line arguments: a table to open, a process to attach to or a program to launch.
//! The UI acts on them at start (`app_args`), through the same steps as its own buttons, so
//! a table from the command line gets the same consent question as one opened by hand.
use serde::Serialize;

pub const USAGE: &str = "Usage: heaphook [TABLE] [--pid PID | --attach NAME] [--launch PROGRAM [ARGS...]]

  TABLE            a cheat table to open (.CT or HeapHook .json); nothing in it runs without asking
  --pid PID        open the process with this id
  --attach NAME    open the first process whose name is NAME (exact, then case-insensitive)
  --launch PROGRAM start PROGRAM (everything after it are its arguments) and open it
  -h, --help       this text";

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct StartArgs {
    pub table: Option<String>,
    pub pid: Option<u32>,
    pub attach: Option<String>,
    pub launch: Option<Launch>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Launch {
    pub program: String,
    /// Shell-like string, as `process_create` takes it.
    pub args: String,
}

/// `Ok(None)` for `--help`. `argv` without the program name.
pub fn parse(argv: &[String]) -> Result<Option<StartArgs>, String> {
    let mut a = StartArgs::default();
    let mut it = argv.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "-h" | "--help" => return Ok(None),
            "--pid" => {
                let v = it.next().ok_or("--pid needs a process id")?;
                a.pid = Some(v.parse().map_err(|_| format!("--pid: {v:?} is not a process id"))?);
            }
            "--attach" => a.attach = Some(it.next().ok_or("--attach needs a process name")?.clone()),
            "--launch" => {
                let program = it.next().ok_or("--launch needs a program")?.clone();
                if let Some(bad) = it.clone().find(|s| s.contains('"')) {
                    return Err(format!("--launch: an argument with a double quote cannot be passed on ({bad})"));
                }
                let args = it.by_ref().map(|s| quote(s)).collect::<Vec<_>>().join(" ");
                a.launch = Some(Launch { program, args });
            }
            // Development bridge flags are handled before (see bridge.rs).
            "--dev-bridge" => {
                it.next();
            }
            f if f.starts_with('-') => return Err(format!("unknown option {f}\n\n{USAGE}")),
            t if a.table.is_none() => a.table = Some(t.to_string()),
            t => return Err(format!("more than one table given ({t})\n\n{USAGE}")),
        }
    }
    if [a.pid.is_some(), a.attach.is_some(), a.launch.is_some()].iter().filter(|x| **x).count() > 1 {
        return Err(format!("give only one of --pid, --attach and --launch\n\n{USAGE}"));
    }
    if let Some(t) = &a.table {
        // Relative to where HeapHook was started, not to wherever the UI asks from.
        if let Ok(p) = std::path::Path::new(t).canonicalize() {
            a.table = Some(p.to_string_lossy().into_owned());
        }
    }
    Ok(Some(a))
}

/// One argument for the string `process_create` splits again (double quotes group, no escapes).
fn quote(s: &str) -> String {
    if !s.is_empty() && !s.chars().any(char::is_whitespace) { s.to_string() } else { format!("\"{s}\"") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Result<Option<StartArgs>, String> {
        parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn arguments() {
        assert_eq!(p(&[]).unwrap(), Some(StartArgs::default()));
        assert_eq!(p(&["--help"]).unwrap(), None);
        let a = p(&["/nonexistent/x.CT", "--pid", "42"]).unwrap().unwrap();
        assert_eq!((a.table.as_deref(), a.pid), (Some("/nonexistent/x.CT"), Some(42)));
        assert_eq!(p(&["--attach", "game"]).unwrap().unwrap().attach.as_deref(), Some("game"));
        let l = p(&["--launch", "/bin/game", "--windowed", "My Save", ""]).unwrap().unwrap().launch.unwrap();
        assert_eq!((l.program.as_str(), l.args.as_str()), ("/bin/game", "--windowed \"My Save\" \"\""));
        assert!(p(&["--launch", "/bin/game", "a\"b"]).is_err());
        assert!(p(&["--pid", "x"]).is_err());
        assert!(p(&["--pid", "1", "--attach", "g"]).is_err());
        assert!(p(&["a.CT", "b.CT"]).is_err());
        assert!(p(&["--bogus"]).is_err());
        assert_eq!(p(&["--dev-bridge", "8000"]).unwrap(), Some(StartArgs::default()));
    }
}
