//! Live test against hh-target spawned as a child (ptrace_scope=1 only allows children).
#![cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use hh_lua::{Engine, EngineOptions};
use serde_json::Value;

fn target_exe() -> PathBuf {
    // This test binary lives in <target>/<profile>/deps/; build hh-target to match.
    let dir = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
    let mut args = vec!["build", "-q", "-p", "hh-target"];
    if dir.ends_with("release") {
        args.push("--release");
    }
    let ok = Command::new(env!("CARGO"))
        .args(&args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run cargo")
        .success();
    assert!(ok, "cargo build -p hh-target failed");
    dir.join("hh-target")
}

struct Target {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    info: Value,
}

impl Target {
    fn spawn() -> Self {
        let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let info = serde_json::from_str(&line).unwrap();
        Target { child, stdin, stdout, info }
    }
    fn hex(&self, v: &Value) -> String {
        v.as_str().unwrap().to_string()
    }
    fn cmd(&mut self, c: &str) -> Value {
        writeln!(self.stdin, "{c}").unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[track_caller]
fn run(e: &Engine, src: &str) -> Vec<String> {
    e.exec(src, "live").unwrap_or_else(|err| panic!("script failed: {err}"))
}

#[test]
fn live_target_from_lua() {
    let mut t = Target::spawn();
    let e = Engine::new(EngineOptions::default()).unwrap();
    let offs: Vec<String> = t.info["chain_offsets"].as_array().unwrap().iter().map(|v| t.hex(v)).collect();
    let prelude = format!(
        "PID, I32, I64, F32, F64, STR, STR16, AOB, CHAIN = {}, {}, {}, {}, {}, {}, {}, {}, {}\nO1, O2, O3 = {}, {}, {}\n",
        t.child.id(),
        t.hex(&t.info["i32"]),
        t.hex(&t.info["i64"]),
        t.hex(&t.info["f32"]),
        t.hex(&t.info["f64"]),
        t.hex(&t.info["str"]),
        t.hex(&t.info["str16"]),
        t.hex(&t.info["aob"]),
        t.hex(&t.info["chain"]),
        offs[0],
        offs[1],
        offs[2],
    );
    run(&e, &prelude);
    run(
        &e,
        r#"
        opened = 0
        function onOpenProcess(pid) opened = pid end
        assert(openProcess(PID), 'openProcess by pid')
        assert(getOpenedProcessID() == PID and opened == PID)
        assert(process == 'hh-target', tostring(process))
        assert(getProcessIDFromProcessName('hh-target') ~= nil)
        assert(targetIs64Bit())
        assert(#enumModules() > 0)

        assert(readInteger(I32) == 123456)
        assert(readQword(I64) == 1234567890123)
        assert(readFloat(F32) == 3.5 and readDouble(F64) == 2.25)
        assert(readString(STR, 64) == 'HeapHook test string')
        assert(readString(STR16, 64, true) == 'HeapHook UTF-16 string')
        local b = readBytes(AOB, 8, true)
        assert(b[1] == 0xDE and b[8] == 0xDE)

        -- pointer chain, by hand and as an address expression
        local p = readPointer(CHAIN)
        p = readPointer(p + O1)
        p = readPointer(p + O2)
        assert(readInteger(p + O3) == 4242)
        assert(readInteger(string.format('[[[%X]+%X]+%X]+%X', CHAIN, O1, O2, O3)) == 4242)
        CHAIN_VALUE = p + O3

        assert(writeInteger(I32, 777) and readInteger(I32) == 777)
        assert(writeFloat(F32, 7.25) and readFloat(F32) == 7.25)

        ms = createMemScan()
        ms.firstScan(soExactValue, vtDword, rtRounded, '777', '', 0, 0x7fffffffffffffff, '+W',
                     fsmAligned, '4', false, false, false, false)
        ms.waitTillDone()
        fl = createFoundList(ms)
        fl.initialize()
        assert(fl.Count >= 1)

        local hits = AOBScan('DE AD BE EF 13 37 C0 DE', '+W')
        local found = false
        for i = 0, hits.Count - 1 do if tonumber(hits[i], 16) == AOB then found = true end end
        assert(found, 'AOBScan finds the target array')

        mem = allocateMemory(4096)
        assert(mem and writeInteger(mem, 31337) and readInteger(mem) == 31337)

        -- threads, copies and symbols in a real process
        local tl = getThreadlist()
        assert(tl.Count >= 2, 'main + idle thread, got ' .. tl.Count)
        assert(tonumber(tl[0], 16) == PID, 'first thread is the main one')
        assert(copyMemory(STR, 20, mem + 64) == mem + 64 and readString(mem + 64, 20) == 'HeapHook test string')
        assert(compareMemory(STR, mem + 64, 20))
        local mine = copyMemory(STR, 20, nil, 1)
        assert(readStringLocal(mine, 20) == 'HeapHook test string')
        assert(compareMemory(STR, mine, 20, 1))
        local si = getSymbolInfo('malloc')
        assert(si and si.address ~= 0 and si.modulename:find('libc'), 'malloc found in libc')
        assert(inModule(si.address) and getModuleSize(si.modulename) > 0)
        assert(enumExports(si.modulename).malloc == si.address)
        assert(getAddress('libc.malloc') == si.address)
        local regions = enumMemoryRegions()
        assert(#regions > 5 and getMemoryProtection(I32).W)
    "#,
    );
    let r = t.cmd("inc");
    assert_eq!(r["i32"], 778);
    run(
        &e,
        r#"
        ms.nextScan(soIncreasedValue, rtRounded, '', '', false, false, false, false, false)
        fl.initialize()
        local mine = false
        for i = 0, fl.Count - 1 do
          if tonumber(fl.Address[i], 16) == I32 then mine = true; assert(fl.Value[i] == '778') end
        end
        assert(mine and fl.Count >= 1, 'increased-value scan keeps the counter')
        ms.nextScan(soExactValue, rtRounded, '778')
        fl.initialize()
        assert(fl.Count >= 1)
        assert(readInteger(CHAIN_VALUE) == 4243)
        writeInteger(CHAIN_VALUE, 100)
        assert(deAlloc(mem))
    "#,
    );
    let r = t.cmd("get");
    assert_eq!(r["chain_value"], 100);
    assert_eq!(r["f32"], 8.25);
}
