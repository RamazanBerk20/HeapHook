//! Live speedhack tests: launch the test target with the payload preloaded and drive it.
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hh_core::Process;
use hh_inject::{LaunchOptions, PAYLOAD_FILE, Speedhack, build_payload, launch};

struct Target {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
    process: Arc<dyn Process>,
}

impl Target {
    fn start(speedhack: bool) -> Target {
        static BUILT: OnceLock<()> = OnceLock::new();
        BUILT.get_or_init(|| {
            build_payload().expect("build payload");
        });
        let mut l = launch(&LaunchOptions {
            program: env!("CARGO_BIN_EXE_hh-speedhack-target").into(),
            speedhack,
            pipe_stdio: true,
            ..Default::default()
        })
        .expect("launch");
        let mut t = Target {
            stdin: l.child.stdin.take().unwrap(),
            out: BufReader::new(l.child.stdout.take().unwrap()),
            process: hh_core::open(l.pid).expect("open child"),
            child: l.child,
        };
        assert_eq!(t.line(), "ready");
        t
    }

    fn line(&mut self) -> String {
        let mut s = String::new();
        self.out.read_line(&mut s).unwrap();
        s.trim().to_owned()
    }

    fn cmd(&mut self, c: &str) -> Vec<i64> {
        writeln!(self.stdin, "{c}").unwrap();
        self.line()
            .split_whitespace()
            .map(|w| w.parse().unwrap())
            .collect()
    }

    fn has_payload(&self) -> bool {
        let mods = self.process.modules().unwrap();
        mods.iter().any(|m| m.name == PAYLOAD_FILE)
    }

    fn quit(mut self) {
        writeln!(self.stdin, "quit").unwrap();
        assert!(self.child.wait().unwrap().success());
    }
}

/// Perceived advance of [monotonic, realtime, gettimeofday] per real ns over ~400 ms.
/// Every monotonic reading goes into `seen`.
fn rates(t: &mut Target, seen: &mut Vec<i64>) -> [f64; 3] {
    let (a, h0) = (t.cmd("clocks"), Instant::now());
    std::thread::sleep(Duration::from_millis(400));
    let (b, h1) = (t.cmd("clocks"), Instant::now());
    seen.extend([a[0], b[0]]);
    let real = (h1 - h0).as_nanos() as f64;
    [
        (b[0] - a[0]) as f64 / real,
        (b[1] - a[1]) as f64 / real,
        (b[2] - a[2]) as f64 * 1000.0 / real,
    ]
}

/// (perceived ms, real ms) of a 200 ms sleep of `kind`.
fn sleep(t: &mut Target, kind: &str) -> (f64, f64) {
    let h = Instant::now();
    let perceived = t.cmd(&format!("{kind} 200"))[0] as f64 / 1e6;
    (perceived, h.elapsed().as_secs_f64() * 1000.0)
}

fn near(v: f64, want: f64, tol: f64) -> bool {
    (v - want).abs() <= want * tol
}

#[test]
fn speedhack_scales_time() {
    let mut t = Target::start(true);
    assert!(t.has_payload(), "payload not in the module list");
    let sh = Speedhack::find(t.process.clone())
        .unwrap()
        .expect("control block");
    assert_eq!(sh.speed().unwrap(), 1.0);
    let mut seen = Vec::new();

    for speed in [1.0, 2.0, 0.5, 1.0] {
        sh.set_speed(speed).unwrap();
        assert_eq!(sh.speed().unwrap(), speed);
        let r = rates(&mut t, &mut seen);
        assert!(r.iter().all(|&r| near(r, speed, 0.25)), "speed {speed}: rates {r:?}");
        for kind in ["nanosleep", "usleep"] {
            let (perceived, real) = sleep(&mut t, kind);
            assert!(
                (195.0..=200.0 * 1.4).contains(&perceived),
                "speed {speed} {kind}: perceived {perceived} ms"
            );
            assert!(
                (200.0 / speed * 0.9..=200.0 / speed * 1.5 + 30.0).contains(&real),
                "speed {speed} {kind}: real {real} ms"
            );
        }
        seen.push(t.cmd("clocks")[0]);
    }
    assert!(seen.windows(2).all(|w| w[0] <= w[1]), "monotonic went back: {seen:?}");
    let stats = t.cmd("stats");
    assert!(stats[0] > 1000, "hammer thread barely ran: {stats:?}");
    assert_eq!(stats[1], 0, "hammer thread saw the monotonic clock go back");

    for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e9] {
        assert!(sh.set_speed(bad).is_err(), "accepted {bad}");
    }
    assert_eq!(sh.speed().unwrap(), 1.0);
    let st = sh.status().unwrap();
    assert_eq!((st.pid, st.speed, st.generation), (t.process.pid(), 1.0, 4));
    t.quit();
}

#[test]
fn no_speedhack_no_payload() {
    let t = Target::start(false);
    assert!(!t.has_payload());
    assert!(Speedhack::find(t.process.clone()).unwrap().is_none());
    t.quit();
}
