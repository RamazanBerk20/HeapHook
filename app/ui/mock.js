// In-browser fake backend. Implements every IPC command of docs/CONTRACT.md against a fake
// process so the UI runs in a plain browser. Errors are thrown as strings, like Tauri does.
// Addresses are JS numbers internally (all fake addresses are < 2^53) and hex strings on the wire.

const rng = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const PROCS = [
  [1, 'systemd', '/usr/lib/systemd/systemd'], [312, 'systemd-journald', '/usr/lib/systemd/systemd-journald'],
  [655, 'dbus-broker', '/usr/bin/dbus-broker'], [702, 'NetworkManager', '/usr/bin/NetworkManager'],
  [1180, 'pipewire', '/usr/bin/pipewire'], [1183, 'wireplumber', '/usr/bin/wireplumber'],
  [1201, 'pipewire-pulse', '/usr/bin/pipewire-pulse'], [1320, 'kwin_wayland', '/usr/bin/kwin_wayland'],
  [1355, 'plasmashell', '/usr/bin/plasmashell'], [1402, 'Xwayland', '/usr/bin/Xwayland'],
  [2210, 'fish', '/usr/bin/fish'], [2244, 'konsole', '/usr/bin/konsole'], [2301, 'bash', '/usr/bin/bash'],
  [3050, 'firefox', '/usr/lib/firefox/firefox'], [3112, 'Isolated Web Co', '/usr/lib/firefox/firefox'],
  [3140, 'Isolated Web Co', '/usr/lib/firefox/firefox'], [3188, 'RDD Process', '/usr/lib/firefox/firefox'],
  [4022, 'steam', '/home/user/.local/share/Steam/ubuntu12_32/steam'],
  [4090, 'steamwebhelper', '/home/user/.local/share/Steam/ubuntu12_64/steamwebhelper'],
  [5120, 'supertuxkart', '/usr/bin/supertuxkart'], [5377, 'openttd', '/usr/bin/openttd'],
  [6001, 'game.x86_64', '/home/user/Games/demo/game.x86_64'], [6420, 'Game.exe', 'Z:\\games\\demo\\Game.exe'],
  [7002, 'code', '/opt/visual-studio-code/code'], [7310, 'heaphook-target', '/home/user/HeapHook/target/debug/hh-target'],
];

const MNEMONICS = new Set(('mov lea add sub cmp test xor and or imul inc dec push pop call jmp je jne jg jl ja jb jz jnz ' +
  'nop ret int3 movss movsd movaps cvtsi2ss shl shr sar not neg movzx movsx cdq leave').split(' '));

let P = null;        // the opened fake process
let ticker = 0;
const frozen = [];   // set_frozen list, values pre-parsed
const overrides = new Map(); // addr -> {hex, text}: instructions written via assemble()
let fs = null;       // fake file system for table_load/table_save

const SIZE = { byte: 1, binary: 1, '2bytes': 2, '4bytes': 4, all: 4, '8bytes': 8, float: 4, double: 8 };
const hx = (n) => '0x' + n.toString(16);
const err = (m) => { throw m; };

function parseAddr(s) {
  if (typeof s !== 'string' || !/^0x[0-9a-f]+$/i.test(s)) err(`invalid address '${s}'`);
  return parseInt(s, 16);
}
const need = () => P || err('no process opened');

// ---------- fake process image ----------
function build(proc) {
  const R = [];
  let flat = 0;
  const add = (start, size, prot, kind, path) => { R.push({ start, size, prot, kind, path, flat }); flat += size; };
  const B = 0x55d4a2c00000, L = 0x7f1234000000;
  const lib = '/usr/lib/libc.so.6';
  add(B, 0x1000, 'r--', 'Image', proc.exe);
  add(B + 0x1000, 0x40000, 'r-x', 'Image', proc.exe);
  add(B + 0x41000, 0x10000, 'r--', 'Image', proc.exe);
  add(B + 0x51000, 0x20000, 'rw-', 'Image', proc.exe);
  add(0x55d4a4e00000, 0x800000, 'rw-', 'Private', '[heap]');
  add(0x7f1233a00000, 0x100000, 'r--', 'Mapped', '/usr/share/fonts/noto/NotoSans-Regular.ttf');
  add(0x7f1233c00000, 0x40000, 'rw-', 'Mapped', '/usr/lib/locale/locale-archive');
  add(L, 0x1000, 'r--', 'Image', lib);
  add(L + 0x1000, 0x80000, 'r-x', 'Image', lib);
  add(L + 0x81000, 0x10000, 'r--', 'Image', lib);
  add(L + 0x91000, 0x8000, 'rw-', 'Image', lib);
  add(0x7ffd12300000, 0x100000, 'rw-', 'Private', '[stack]');
  const mem = new Uint8Array(flat);
  const dv = new DataView(mem.buffer);
  const rnd = rng(proc.pid);
  const heap = R[4];
  for (const r of R) {
    if (r.prot[2] === 'x') {
      for (let i = 0; i < r.size; i++) mem[r.flat + i] = (rnd() * 256) | 0;
      // plant real calls/jumps so "follow" lands somewhere mapped
      for (let i = 16; i < r.size - 16; i += 24 + ((rnd() * 40) | 0)) {
        const target = r.start + ((rnd() * (r.size - 64)) | 0);
        mem[r.flat + i] = rnd() < 0.6 ? 0xe8 : 0xe9;
        dv.setInt32(r.flat + i + 1, target - (r.start + i + 5), true);
      }
    } else {
      for (let i = 0; i + 8 <= r.size; i += 8) {
        const o = r.flat + i, x = rnd();
        if (x < 0.7) continue;
        if (x < 0.82) dv.setUint32(o, (rnd() * 1000) | 0, true);
        else if (x < 0.9) dv.setFloat32(o, (rnd() - 0.5) * 2000, true);
        else if (x < 0.96) dv.setBigUint64(o, BigInt(heap.start + ((rnd() * heap.size) & ~7)), true);
        else for (let k = 0; k < 8; k++) mem[o + k] = (rnd() * 256) | 0;
      }
    }
  }
  const obj = heap.start + 0x1a3f0;
  const p = {
    pid: proc.pid, name: proc.name, exe: proc.exe, R, mem, dv, rnd, obj, tick: 0, hitAt: Date.now(),
    mods: [
      { name: proc.name, path: proc.exe, base: B, size: 0x71000 },
      { name: 'libc.so.6', path: lib, base: L, size: 0x99000 },
    ],
    syms: { player_base: B + 0x5a2b0, memcpy: L + 0x1a40, malloc: L + 0x2c80, free: L + 0x2f10, printf: L + 0x5010 },
  };
  P = p;
  const o = flatOf(obj);
  dv.setUint32(o, 100, true); dv.setUint32(o + 4, 100, true); dv.setUint32(o + 8, 1500, true);
  dv.setUint16(o + 12, 30, true); dv.setUint16(o + 14, 7, true);
  dv.setFloat32(o + 16, 12.5, true); dv.setFloat32(o + 20, -3.25, true); dv.setFloat32(o + 24, 0, true);
  dv.setFloat64(o + 32, 5.5, true);
  mem.set(new TextEncoder().encode('Player1\0'), o + 40);
  for (let i = 0; i < 7; i++) dv.setUint16(o + 56 + i * 2, 'Player1'.charCodeAt(i), true);
  dv.setUint32(o + 88, 0, true);
  dv.setBigUint64(flatOf(p.syms.player_base), BigInt(obj), true);
  for (let i = 0; i < 40; i++) dv.setUint32(heap.flat + ((rnd() * heap.size) & ~3), 100, true); // decoys
  dv.setUint32(heap.flat + 0x1a3f0 + 0x200, 100, true); // a decoy near the object
  return p;
}

function regionOf(addr) {
  const R = P.R;
  let lo = 0, hi = R.length - 1;
  while (lo <= hi) {
    const m = (lo + hi) >> 1, r = R[m];
    if (addr < r.start) hi = m - 1;
    else if (addr >= r.start + r.size) lo = m + 1;
    else return r;
  }
  return null;
}
function flatOf(addr) { const r = regionOf(addr); return r ? r.flat + (addr - r.start) : -1; }
function addrOfFlat(f) {
  const R = P.R;
  let lo = 0, hi = R.length - 1;
  while (lo < hi) { const m = (lo + hi + 1) >> 1; if (R[m].flat <= f) lo = m; else hi = m - 1; }
  return R[lo].start + (f - R[lo].flat);
}
/** Contiguous view of `len` bytes or null when any is unreadable. */
function view(addr, len, buf = P.mem) {
  const r = regionOf(addr);
  if (!r || addr + len > r.start + r.size) return null;
  const f = r.flat + (addr - r.start);
  return buf.subarray(f, f + len);
}

function step() {
  const p = P, dv = p.dv, o = flatOf(p.obj), rnd = p.rnd;
  p.tick++;
  dv.setUint32(o + 88, dv.getUint32(o + 88, true) + 1, true);
  if (Date.now() - p.hitAt >= 2000) { // wall clock: background tabs throttle intervals
    p.hitAt = Date.now();
    let h = dv.getUint32(o, true) - 1 - ((rnd() * 6) | 0);
    dv.setUint32(o, h < 20 ? 100 : h, true);
  }
  dv.setFloat32(o + 16, 12.5 + Math.sin(p.tick / 15) * 4, true);
  dv.setFloat32(o + 20, -3.25 + Math.cos(p.tick / 15) * 4, true);
  const heap = p.R[4];
  for (let i = 0; i < 50; i++) {
    const off = 0x40000 + ((rnd() * (heap.size - 0x40000)) & ~3);
    dv.setUint32(heap.flat + off, (rnd() * 5000) | 0, true);
  }
  dbgTick();
  for (const f of frozen) {
    const cur = view(f.addr, f.bytes.length);
    if (!cur) continue;
    if (f.mode !== 'exact' && SIZE[f.vtype]) {
      const c = num(cur, f.vtype), v = num(f.bytes, f.vtype);
      if (f.mode === 'allow_increase' ? c > v : c < v) { f.bytes = cur.slice(); continue; }
    }
    cur.set(f.bytes);
  }
}

// ---------- values ----------
function num(bytes, vtype) {
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  switch (vtype) {
    case 'byte': case 'binary': return d.getUint8(0);
    case '2bytes': return d.getUint16(0, true);
    case '4bytes': case 'all': return d.getUint32(0, true);
    case '8bytes': return Number(d.getBigUint64(0, true));
    case 'float': return d.getFloat32(0, true);
    case 'double': return d.getFloat64(0, true);
  }
  return NaN;
}
const fmtFloat = (v, p) => (Number.isFinite(v) ? String(+v.toPrecision(p)) : String(v));

function fmt(bytes, vtype, o = {}) {
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  let v, bits;
  switch (vtype) {
    case 'byte': v = o.signed ? d.getInt8(0) : d.getUint8(0); bits = 8; break;
    case '2bytes': v = o.signed ? d.getInt16(0, true) : d.getUint16(0, true); bits = 16; break;
    case '4bytes': case 'all': v = o.signed ? d.getInt32(0, true) : d.getUint32(0, true); bits = 32; break;
    case '8bytes': v = o.signed ? d.getBigInt64(0, true) : d.getBigUint64(0, true); bits = 64; break;
    case 'float': return o.hex ? d.getUint32(0, true).toString(16).toUpperCase() : fmtFloat(d.getFloat32(0, true), 7);
    case 'double': return o.hex ? d.getBigUint64(0, true).toString(16).toUpperCase() : fmtFloat(d.getFloat64(0, true), 15);
    case 'binary': return d.getUint8(0).toString(2).padStart(8, '0');
    case 'aob': return [...bytes].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
    case 'string': {
      if (o.utf16) {
        let s = '';
        for (let i = 0; i + 1 < bytes.length; i += 2) { const c = d.getUint16(i, true); if (!c) break; s += String.fromCharCode(c); }
        return s;
      }
      const z = bytes.indexOf(0);
      return new TextDecoder().decode(z < 0 ? bytes : bytes.subarray(0, z));
    }
    default: err(`unsupported value type '${vtype}'`);
  }
  if (o.hex) return BigInt.asUintN(bits, BigInt(v)).toString(16).toUpperCase();
  return String(v);
}

function parseInt64(s, hex) {
  s = String(s).trim();
  const neg = s.startsWith('-');
  if (neg) s = s.slice(1);
  if (/^0x/i.test(s)) { s = s.slice(2); hex = true; }
  if (!(hex ? /^[0-9a-f]+$/i : /^[0-9]+$/).test(s)) err(`'${s}' is not a valid ${hex ? 'hex ' : ''}integer`);
  const v = BigInt((hex ? '0x' : '') + s);
  return neg ? -v : v;
}

/** Value string -> bytes (+ mask for aob wildcards). */
function encode(vtype, s, o = {}) {
  const size = SIZE[vtype];
  if (vtype === 'float' || vtype === 'double') {
    const b = new Uint8Array(size), d = new DataView(b.buffer);
    let v;
    if (o.hex) v = vtype === 'float' ? new DataView(new Uint32Array([Number(parseInt64(s, true))]).buffer).getFloat32(0, true) : NaN;
    else v = Number(String(s).trim());
    if (String(s).trim() === '' || Number.isNaN(v)) err(`'${s}' is not a number`);
    vtype === 'float' ? d.setFloat32(0, v, true) : d.setFloat64(0, v, true);
    return { bytes: b };
  }
  if (vtype === 'binary') {
    if (!/^[01]{1,8}$/.test(String(s).trim())) err(`'${s}' is not a binary byte`);
    return { bytes: new Uint8Array([parseInt(s, 2)]) };
  }
  if (size) {
    const v = parseInt64(s, o.hex), bits = BigInt(size * 8);
    if (v >= 1n << bits || v < -(1n << (bits - 1n))) err(`${s} does not fit in ${size} byte(s)`);
    const b = new Uint8Array(size), u = BigInt.asUintN(size * 8, v);
    for (let i = 0; i < size; i++) b[i] = Number((u >> BigInt(i * 8)) & 0xffn);
    return { bytes: b };
  }
  if (vtype === 'string') {
    if (o.utf16) {
      const b = new Uint8Array(s.length * 2);
      for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 255; b[i * 2 + 1] = s.charCodeAt(i) >> 8; }
      return { bytes: b };
    }
    return { bytes: new TextEncoder().encode(s) };
  }
  if (vtype === 'aob') {
    const t = String(s).trim().split(/\s+/).filter(Boolean);
    if (!t.length) err('empty byte array');
    const bytes = new Uint8Array(t.length), mask = new Uint8Array(t.length);
    t.forEach((x, i) => {
      if (/^\?\??$|^\*$/.test(x)) return;
      if (!/^[0-9a-f]{1,2}$/i.test(x)) err(`'${x}' is not a byte`);
      bytes[i] = parseInt(x, 16); mask[i] = 1;
    });
    return { bytes, mask };
  }
  err(`unsupported value type '${vtype}'`);
}

function cleanHex(h) {
  h = String(h).replace(/\s+/g, '');
  if (!/^([0-9a-f]{2})*$/i.test(h)) err(`invalid hex '${h}'`);
  return Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
}

// ---------- address expressions ----------
function resolveExpr(expr) {
  expr = String(expr).replace(/"/g, ''); // CE quotes module names: "game.exe"+1A2B
  const toks = String(expr).match(/\s*([\[\]()+\-*]|[A-Za-z0-9_.!]+)/g)?.map((t) => t.trim());
  if (!toks || toks.join('') !== String(expr).replace(/\s+/g, '')) err(`cannot parse '${expr}'`);
  let i = 0;
  const peek = () => toks[i], next = () => toks[i++];
  const expect = (t) => (next() === t ? 0 : err(`expected '${t}' in '${expr}'`));
  function atom() {
    const t = next();
    if (t === '[') {
      const a = sum(); expect(']');
      const v = view(a, 8);
      if (!v) err(`cannot read pointer at ${hx(a)}`);
      return num(v, '8bytes');
    }
    if (t === '(') { const a = sum(); expect(')'); return a; }
    if (t === '-') return -atom();
    if (t == null) err(`unexpected end of '${expr}'`);
    const us = T?.table?.symbols?.find((s) => s.name === t);
    if (us) return resolveExpr(us.address);
    const low = t.toLowerCase();
    const m = P.mods.find((m) => m.name.toLowerCase() === low);
    if (m) return m.base;
    if (P.syms[t] != null) return P.syms[t];
    if (/^(0x)?[0-9a-f]+$/i.test(t)) return parseInt(t.replace(/^0x/i, ''), 16);
    err(`unknown symbol '${t}'`);
  }
  function prod() { let a = atom(); while (peek() === '*') { next(); a *= atom(); } return a; }
  function sum() {
    let a = prod();
    while (peek() === '+' || peek() === '-') a = next() === '+' ? a + prod() : a - prod();
    return a;
  }
  const a = sum();
  if (i !== toks.length) err(`unexpected '${toks[i]}' in '${expr}'`);
  if (a < 0 || !Number.isSafeInteger(a)) err(`'${expr}' is out of range`);
  return a;
}

// ---------- disassembly ----------
const REGS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r12', 'r13', 'eax', 'ecx', 'edx', 'esi'];
const TPL = [
  (x, y, d) => `mov ${x},${y}`, (x, y, d) => `mov ${x},[${y}+${d}]`, (x, y, d) => `mov [${y}+${d}],${x}`,
  (x, y, d) => `lea ${x},[${y}+${d}]`, (x, y, d) => `add ${x},${d}`, (x, y, d) => `sub ${x},${d}`,
  (x, y, d) => `cmp ${x},${d}`, (x, y) => `test ${x},${y}`, (x) => `xor ${x},${x}`,
  (x, y, d) => `movss xmm0,[${y}+${d}]`, (x, y) => `imul ${x},${y}`, (x, y, d) => `and ${x},${d}`,
];
function symbolize(a) {
  for (const [k, v] of Object.entries(P.syms)) if (v === a) return k;
  const m = P.mods.find((m) => a >= m.base && a < m.base + m.size);
  return m ? `${m.name}+${(a - m.base).toString(16).toUpperCase()}` : '';
}
function decode(a) {
  const ov = overrides.get(a);
  if (ov) { const v = view(a, ov.bytes.length); if (v && v.every((b, i) => b === ov.bytes[i])) return { len: ov.bytes.length, text: ov.text }; overrides.delete(a); }
  const v = view(a, 8);
  if (!v) { const b = view(a, 1); if (!b) return null; }
  const b = (i) => (v ? v[i] : 0);
  const op = b(0);
  const rel = (n) => { const d = new DataView(v.buffer, v.byteOffset + 1, n); return n === 1 ? d.getInt8(0) : d.getInt32(0, true); };
  const branch = (m, n) => { const t = a + 1 + n + rel(n); return { len: 1 + n, text: `${m} ${t.toString(16).toUpperCase()}`, target: t }; };
  switch (op) {
    case 0x90: return { len: 1, text: 'nop' };
    case 0xc3: return { len: 1, text: 'ret' };
    case 0xcc: return { len: 1, text: 'int 3' };
    case 0x55: return { len: 1, text: 'push rbp' };
    case 0x5d: return { len: 1, text: 'pop rbp' };
    case 0xe8: return branch('call', 4);
    case 0xe9: return branch('jmp', 4);
    case 0xeb: return branch('jmp', 1);
    case 0x74: return branch('je', 1);
    case 0x75: return branch('jne', 1);
  }
  const x = REGS[b(1) & 15], y = REGS[b(1) >> 4], d = b(2).toString(16).toUpperCase().padStart(2, '0');
  return { len: 2 + (op % 6), text: TPL[op % TPL.length](x, y, d) };
}

// ---------- auto assembler ----------
function aaCheck(script) {
  const lines = String(script).split('\n');
  const en = lines.findIndex((l) => /^\s*\[enable\]\s*$/i.test(l));
  const dis = lines.findIndex((l) => /^\s*\[disable\]\s*$/i.test(l));
  if (en < 0) return { line: 1, message: 'missing [ENABLE] section' };
  if (dis < 0) return { line: lines.length, message: 'missing [DISABLE] section' };
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].replace(/\/\/.*$/, '').replace(/\{.*?\}/g, '').trim();
    if (!l || /^\[(enable|disable)\]$/i.test(l)) continue;
    if (/^(alloc|dealloc|label|registersymbol|unregistersymbol|define|assert|aobscan\w*|globalalloc|createthread|loadlibrary|fullaccess|readmem)\s*\(/i.test(l)) continue;
    if (/^[\w.+\-\[\]]+:$/.test(l)) continue;
    const w = l.split(/[\s,]/)[0].toLowerCase();
    if (['db', 'dw', 'dd', 'dq'].includes(w) || MNEMONICS.has(w)) continue;
    return { line: i + 1, message: `unknown instruction '${w}'` };
  }
  return null;
}

// ---------- scanning ----------
let S = null; // current scan
let prog = { done: 0, total: 0, found: 0, running: false, paused: false };
let cancelled = false;
// yield to the UI between chunks; MessageChannel is not clamped like setTimeout
const tick = () => new Promise((r) => { const c = new MessageChannel(); c.port1.onmessage = () => r(); c.port2.postMessage(0); });
const FIRST_TYPES = ['exact', 'bigger', 'smaller', 'between', 'unknown'];
const NEXT_TYPES = [...FIRST_TYPES, 'increased', 'increased_by', 'decreased', 'decreased_by', 'changed', 'unchanged', 'same_as_first'];

function makeTest(sc, req) {
  const { vtype, opts } = sc;
  const t = req.scan_type;
  if (vtype === 'string' || vtype === 'aob') {
    if (t !== 'exact') err(`scan type '${t}' is not supported for ${vtype}`);
    let { bytes, mask } = encode(vtype, req.value, { utf16: opts.utf16 });
    const ci = vtype === 'string' && !opts.case_sensitive;
    if (ci) bytes = bytes.map((c) => (c >= 65 && c <= 90 ? c + 32 : c));
    sc.size = bytes.length;
    return (m, f) => {
      for (let k = 0; k < bytes.length; k++) {
        if (mask && !mask[k]) continue;
        let c = m[f + k];
        if (ci && c >= 65 && c <= 90) c += 32;
        if (c !== bytes[k]) return false;
      }
      return true;
    };
  }
  const isF = vtype === 'float' || vtype === 'double';
  const parse = (s) => {
    if (s == null || String(s).trim() === '') err('enter a value');
    if (isF) { const v = Number(s); if (Number.isNaN(v)) err(`'${s}' is not a number`); return v; }
    return Number(BigInt.asUintN(SIZE[vtype] * 8, parseInt64(s, opts.hex)));
  };
  const rd = (m, f) => num(m.subarray(f, f + sc.size), vtype);
  const dec = isF ? (String(req.value ?? '').split('.')[1] || '').length : 0;
  const p = 10 ** dec;
  const eq = (v, x) => {
    if (!isF) return v === x;
    if (opts.rounding === 'truncated') return Math.trunc(v * p) === Math.trunc(x * p);
    if (opts.rounding === 'extreme') return Math.abs(v - x) < 1;
    return Math.round(v * p) === Math.round(x * p);
  };
  const prev = sc.prev, first = sc.first;
  let a, b;
  switch (t) {
    case 'exact': a = parse(req.value); return (m, f) => eq(rd(m, f), a);
    case 'bigger': a = parse(req.value); return (m, f) => rd(m, f) > a;
    case 'smaller': a = parse(req.value); return (m, f) => rd(m, f) < a;
    case 'between': a = parse(req.value); b = parse(req.value2); if (a > b) [a, b] = [b, a]; return (m, f) => { const v = rd(m, f); return v >= a && v <= b; };
    case 'unknown': return null;
    case 'increased': return (m, f) => rd(m, f) > rd(prev, f);
    case 'decreased': return (m, f) => rd(m, f) < rd(prev, f);
    case 'changed': return (m, f) => rd(m, f) !== rd(prev, f);
    case 'unchanged': return (m, f) => rd(m, f) === rd(prev, f);
    case 'same_as_first': return (m, f) => rd(m, f) === rd(first, f);
    case 'increased_by': a = parse(req.value); return (m, f) => eq(rd(m, f) - rd(prev, f), a);
    case 'decreased_by': a = parse(req.value); return (m, f) => eq(rd(prev, f) - rd(m, f), a);
  }
  err(`unknown scan type '${t}'`);
}

async function runScan(fn) {
  if (prog.running) err('a scan is already running');
  cancelled = false;
  prog = { done: 0, total: 0, found: 0, running: true, paused: false };
  try { return await fn(); } finally { prog.running = false; prog.paused = false; }
}

const tri = (v, flag) => v === 'any' || v == null || (v === 'yes') === flag;

async function scanFirst(req) {
  need();
  const { scan_type } = req;
  const opts = req.opts || {};
  const vtype = opts.custom ? customVtype(opts.custom) : req.vtype;
  if (vtype === 'grouped') err('grouped scans are not supported by the mock backend');
  if (!SIZE[vtype] && vtype !== 'string' && vtype !== 'aob') err(`unknown value type '${vtype}'`);
  if (!FIRST_TYPES.includes(scan_type)) err(`'${scan_type}' needs a previous scan`);
  return runScan(async () => {
    const sc = { vtype, opts, size: SIZE[vtype] || 1, first: null, prev: null };
    const base = makeTest(sc, req);
    const test = req.not && base ? (m, f) => !base(m, f) : base;
    const align = Math.max(1, opts.alignment | 0 || 1);
    const lo = opts.start ? parseAddr(opts.start) : 0, hi = opts.stop ? parseAddr(opts.stop) : Infinity;
    const regs = P.R.filter((r) => r.prot[0] === 'r' && tri(opts.writable, r.prot[1] === 'w') &&
      tri(opts.executable, r.prot[2] === 'x') && tri(opts.copy_on_write, r.kind === 'Mapped' && r.prot[1] === 'w') &&
      r.start + r.size > lo && r.start < hi);
    prog.total = regs.reduce((s, r) => s + r.size, 0);
    let out = new Uint32Array(Math.ceil(prog.total / align) + regs.length);
    let n = 0, doneBase = 0;
    const m = P.mem.slice(); // scan a snapshot so "first"/"previous" match what was compared
    for (const r of regs) {
      const s = Math.max(r.start, lo), e = Math.min(r.start + r.size, hi) - sc.size;
      let a = Math.ceil(s / align) * align;
      while (a <= e) {
        const stop = Math.min(e, a + 0x40000);
        for (let f = r.flat + (a - r.start); a <= stop; a += align, f += align) if (!test || test(m, f)) out[n++] = f;
        prog.done = doneBase + (a - r.start); prog.found = n;
        await tick();
        while (prog.paused && !cancelled) await new Promise((r) => setTimeout(r, 100));
        if (cancelled) err('scan cancelled');
      }
      doneBase += r.size;
    }
    prog.done = prog.total;
    sc.results = out.subarray(0, n);
    sc.saved = new Map();
    sc.first = sc.prev = m;
    sc.undo = null;
    S = sc;
    return { count: n };
  });
}

async function scanNext(req) {
  need();
  if (!S) err('no first scan');
  if (!NEXT_TYPES.includes(req.scan_type)) err(`unknown scan type '${req.scan_type}'`);
  const cmp = req.compare_to, sv = cmp && cmp !== 'first' ? S.saved.get(cmp) || err(`no saved scan named "${cmp}"`) : null;
  const ref = cmp === 'first' ? S.first : sv ? sv.mem : null;
  return runScan(async () => {
    const tst = makeTest(ref ? { ...S, prev: ref } : S, req);
    const base = sv && tst ? (m, f) => sv.set.has(f) && tst(m, f) : tst;
    const test = base && req.not ? (m, f) => !base(m, f) : base;
    const src = S.results, out = new Uint32Array(src.length), m = P.mem.slice();
    prog.total = src.length;
    let n = 0;
    for (let i = 0; i < src.length;) {
      const stop = Math.min(src.length, i + 0x40000);
      for (; i < stop; i++) if (!test || test(m, src[i])) out[n++] = src[i];
      prog.done = i; prog.found = n;
      await tick();
      while (prog.paused && !cancelled) await new Promise((r) => setTimeout(r, 100));
      if (cancelled) err('scan cancelled');
    }
    S.undo = { results: S.results, prev: S.prev };
    S.results = out.subarray(0, n);
    S.prev = m;
    return { count: n };
  });
}

// ---------- command table ----------
const C = {
  list_processes: () => PROCS.map(([pid, name, exe]) => ({ pid, name, exe })),
  open_process({ pid }, pr = PROCS.find((p) => p[0] === pid) || err(`no process with pid ${pid}`)) {
    if (pid < 1000) err(`cannot attach to pid ${pid}: ptrace: Operation not permitted (os error 1)`);
    clearInterval(ticker);
    S = null; frozen.length = 0; overrides.clear(); D = null; PS = null; DIS = null; SNAPS.length = 0;
    const p = build({ pid: pr[0], name: pr[1], exe: pr[2] });
    plantCode();
    // Scripts patched the old process: off. Value entries stay frozen to their values.
    liveWalk(T.table.entries, (e) => { if (typeof e.script === 'string') e.frozen = false; });
    T.version++;
    liveFreeze();
    ticker = setInterval(step, 200);
    return { pid: p.pid, name: p.name, is_64bit: true };
  },
  regions: () => need().R.map((r) => ({
    start: hx(r.start), size: r.size, prot: { r: r.prot[0] === 'r', w: r.prot[1] === 'w', x: r.prot[2] === 'x' }, kind: r.kind, path: r.path,
  })),
  modules: () => need().mods.map((m) => ({ name: m.name, path: m.path, base: hx(m.base), size: m.size })),
  read_memory({ addr, len }) {
    need();
    const a = parseAddr(addr);
    if (!(len >= 0 && len <= 1 << 20)) err('len out of range');
    let s = '';
    for (let i = 0; i < len;) {
      const r = regionOf(a + i);
      if (!r) { s += '??'; i++; continue; }
      const end = Math.min(len, r.start + r.size - a);
      for (let f = r.flat + (a + i - r.start); i < end; i++, f++) s += P.mem[f].toString(16).padStart(2, '0');
    }
    return s;
  },
  write_bytes({ addr, hex }) {
    need();
    const b = cleanHex(hex), v = view(parseAddr(addr), b.length);
    if (!v) err(`cannot access memory at ${addr}`);
    v.set(b);
    return null;
  },
  read_values({ reqs }) {
    need();
    return reqs.map((q) => {
      const len = q.vtype === 'string' ? (q.len || 16) * (q.utf16 ? 2 : 1) : q.vtype === 'aob' ? q.len || 8 : SIZE[q.vtype];
      if (!len) return null;
      let a;
      try { a = parseAddr(q.addr); } catch { return null; }
      const v = view(a, len);
      return v ? fmt(v, q.vtype, q) : null;
    });
  },
  write_value({ addr, vtype, value, utf16, hex }) {
    need();
    const { bytes, mask } = encode(vtype, value, { utf16, hex });
    if (mask && mask.includes(0)) err('wildcards cannot be written');
    const v = view(parseAddr(addr), bytes.length);
    if (!v) err(`cannot access memory at ${addr}`);
    v.set(bytes);
    return null;
  },
  resolve_address: ({ expr }) => (need(), hx(resolveExpr(expr))),
  scan_first: ({ req }) => scanFirst(req),
  scan_next: ({ req }) => scanNext(req),
  scan_undo() {
    if (!S?.undo) err('nothing to undo');
    S.results = S.undo.results; S.prev = S.undo.prev; S.undo = null;
    return null;
  },
  scan_new() { S = null; return null; },
  scan_cancel() { if (prog.running) cancelled = true; return null; },
  scan_progress: () => ({ ...prog, spilled: prog.found > 3_000_000 ? prog.found * 8 : 0, spill_dir: loadSettings().scan_spill_dir || '/tmp/heaphook-scan' }),
  scan_results({ offset, limit, saved }) {
    if (!S) return [];
    const sv = saved ? S.saved.get(saved) || err(`no saved scan named "${saved}"`) : null;
    const out = [], end = Math.min(S.results.length, offset + limit);
    const o = { hex: S.opts.hex, utf16: S.opts.utf16 };
    for (let i = offset; i < end; i++) {
      const f = S.results[i], z = S.size;
      // "all" scans: the mock calls small values 2-byte matches (the real scanner records the type that matched)
      const vt = S.vtype !== 'all' ? S.vtype : num(P.mem.subarray(f, f + 4), '4bytes') < 65536 ? '2bytes' : '4bytes';
      out.push({
        addr: hx(addrOfFlat(f)), value: fmt(P.mem.subarray(f, f + z), vt, o),
        previous: fmt(S.prev.subarray(f, f + z), vt, o), first: fmt(S.first.subarray(f, f + z), vt, o), vtype: vt,
        ...(S.vtype === 'binary' ? { bit: S.opts.bit_start ?? 0 } : {}),
        ...(sv ? { saved: sv.set.has(f) ? fmt(sv.mem.subarray(f, f + z), vt, o) : null } : {}),
      });
    }
    return out;
  },
  set_frozen({ entries }) {
    need();
    const next = entries.map((e) => {
      if (!['exact', 'allow_increase', 'allow_decrease'].includes(e.mode)) err(`unknown freeze mode '${e.mode}'`);
      return { addr: parseAddr(e.addr), vtype: e.vtype, mode: e.mode, bytes: encode(e.vtype, e.value, e).bytes };
    });
    frozen.length = 0;
    frozen.push(...next);
    return null;
  },
  disassemble({ addr, count }) {
    need();
    let a = parseAddr(addr);
    const out = [];
    for (let i = 0; i < Math.min(count, 2000); i++) {
      const d = decode(a);
      if (!d) { out.push({ addr: hx(a), bytes: '??', text: '??', comment: '' }); a += 1; continue; }
      const v = view(a, d.len) || new Uint8Array(0);
      out.push({
        addr: hx(a), bytes: [...v].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join(' '),
        text: d.text, comment: d.target != null ? symbolize(d.target) : '', ...xrefsAt(a),
      });
      a += d.len;
    }
    return out;
  },
  assemble({ addr, text }) {
    need();
    const a = parseAddr(addr), t = String(text).trim().toLowerCase().replace(/\s+/g, ' ');
    const [m, ...rest] = t.split(' ');
    const arg = rest.join(' ');
    const out = (bytes) => { overrides.set(a, { bytes, text: t }); return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''); };
    const fixed = { nop: [0x90], ret: [0xc3], int3: [0xcc], 'int 3': [0xcc], 'push rbp': [0x55], 'pop rbp': [0x5d] }[t];
    if (fixed) return out(Uint8Array.from(fixed));
    if (['call', 'jmp', 'je', 'jne'].includes(m)) {
      const target = resolveExpr(arg.replace(/^0x/, '') || err('missing jump target'));
      const short = { je: 0x74, jne: 0x75, jmp: 0xeb }[m];
      const r8 = target - (a + 2);
      if (short && r8 >= -128 && r8 <= 127) return out(Uint8Array.from([short, r8 & 255]));
      if (m !== 'call' && m !== 'jmp') err(`${m} target out of short range`);
      const b = new Uint8Array(5); b[0] = m === 'call' ? 0xe8 : 0xe9;
      new DataView(b.buffer).setInt32(1, target - (a + 5), true);
      return out(b);
    }
    if (!MNEMONICS.has(m)) err(`unknown instruction '${m}'`);
    let h = 7;
    for (const c of t) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    const len = 3 + (h % 4);
    let op = 0x80;
    while (2 + (op % 6) !== len || [0x90, 0xc3, 0xcc, 0x55, 0x5d, 0xe8, 0xe9, 0xeb, 0x74, 0x75].includes(op)) op++;
    const b = new Uint8Array(len); b[0] = op;
    for (let i = 1; i < len; i++) b[i] = (h >>> (i * 5)) & 255;
    return out(b);
  },
  aa_check: ({ script }) => aaCheck(script),
  aa_execute({ script, enable, state }) {
    need();
    const e = aaCheck(script);
    if (e) err(`line ${e.line}: ${e.message}`);
    return enable ? { mock_handle: Date.now() } : (void state, null);
  },
  table_load({ path }) {
    fs ??= loadFs();
    if (/\.ct$/i.test(path) && !fs[path]) err('Cheat Engine .CT import needs the real backend');
    return fs[path] ?? err(`file not found: ${path}`);
  },
  table_save({ path, table }) {
    if (!path) err('empty path');
    fs ??= loadFs();
    fs[path] = table;
    try { localStorage.setItem('hh.mockfs', JSON.stringify(fs)); } catch { /* storage unavailable: keep in memory */ }
    return null;
  },
};
// ---------- debugger ----------
// Plausible code at fixed spots of the executable for the fake hit records.
let CODE = null;
function plantCode() {
  const t = P.mods[0].base + 0x1000;
  CODE = {
    w1: [t + 0x3a10, [0x89, 0x43, 0x58], 'mov [rbx+58],eax'], w2: [t + 0x3c84, [0x29, 0x0b], 'sub [rbx],ecx'],
    r1: [t + 0x41f0, [0x8b, 0x43, 0x58], 'mov eax,[rbx+58]'], r2: [t + 0x5520, [0x83, 0x3b, 0x00], 'cmp dword ptr [rbx],00'],
  };
  for (const [a, b, text] of Object.values(CODE)) { view(a, b.length).set(b); overrides.set(a, { bytes: Uint8Array.from(b), text }); }
}
let D = null; // attached debugger: {state, tid, rip, reason, bps, next, ctx, susp}
const dneed = () => (need(), D || err('the debugger is not attached'));
const REGN = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rflags', 'fs_base', 'gs_base'];
function fakeCtx(rip, rbx) {
  const c = {}, rnd = rng(rip + rbx);
  for (const n of REGN) c[n] = hx(Math.floor(rnd() * 0xffffff) * 16);
  Object.assign(c, { rip: hx(rip), rbx: hx(rbx), rsp: hx(0x7ffd123ff000 - 0x200), rbp: hx(0x7ffd123ff000 - 0x100), rflags: hx(0x246), rax: hx(100), rcx: hx(3) });
  Object.assign(c, { cs: '0033', ds: '0000', es: '0000', fs: '0000', gs: '0000', ss: '002B' });
  c.fpu = {
    fcw: '037F', fsw: '0000', ftw: '0000', fop: '0000', fip: '0x0', fdp: '0x0', mxcsr: '00001F80',
    st: Array.from({ length: 8 }, (_, i) => ({ hex: i ? '00000000000000000000' : '3FFF8000000000000000', value: i ? '0' : '1' })),
    xmm: Array.from({ length: 16 }, (_, i) => (i < 2 ? '0000803f000000400000404000008040' : '0'.repeat(32))),
  };
  return c;
}
function dbgTick() {
  if (!D || D.state !== 'running') return;
  const obj = P.obj;
  for (const b of D.bps) {
    if (!b.enabled) continue;
    const o = b.options || {};
    // Options like hh-debug: skip the first hits, switch off after one action or at max hits.
    const done = (why) => { b.enabled = false; b.note = why; D.log.push({ seq: D.log.length + 1, text: `breakpoint ${b.id} disabled: ${why}` }); };
    if (o.max_hits && b.hits >= o.max_hits) { done(`stopped after ${b.hits} hits`); continue; }
    if (b.action === 'break' && o.skip_hits && b.cn < o.skip_hits && Date.now() - b.armed > 3000) { b.cn++; b.hits++; b.armed = Date.now(); continue; }
    if (b.action === 'break' && o.one_shot && b.hits > (o.skip_hits || 0)) { done('one-shot: it ran once'); continue; }
    if (b.range) {
      const r = b.recs.get('w1') || { addr: CODE.w1[0], ip: CODE.w1[0] + 3, text: CODE.w1[2], bytes: CODE.w1[1], count: 0, address: b.addr + 0x10 };
      r.count++; b.hits++; r.context = fakeCtx(CODE.w1[0], b.addr - 0x48); b.recs.set('w1', r);
      continue;
    }
    if (b.action === 'record') {
      const rec = (key, code, address) => {
        const [a, bytes, text] = CODE[code];
        let r = b.recs.get(key);
        if (!r) b.recs.set(key, (r = { addr: a, ip: a + bytes.length, text, bytes, count: 0, address }));
        r.count += 1 + ((P.rnd() * 3) | 0); b.hits++;
        r.context = fakeCtx(a, b.addr - (code === 'w2' || code === 'r2' ? 0 : 0x58));
      };
      if (b.ea) { rec('a' + (P.tick % 3), 'w1', obj + 0x58 + (P.tick % 3) * 0x100); continue; }
      rec('w1', 'w1');
      if (P.tick % 10 === 0) rec('w2', 'w2');
      if (b.kind === 'access') { rec('r1', 'r1'); if (P.tick % 4 === 0) rec('r2', 'r2'); }
    } else if (b.action === 'trace' && !b.trace.length && P.tick % 10 === 0) {
      b.hits++;
      let a = b.addr;
      for (let i = 0; i < Math.min(b.steps, 2000); i++) {
        const d = decode(a) || { len: 1, text: '??' };
        const c = fakeCtx(a, obj); delete c.fpu;
        b.trace.push({ addr: hx(a), text: d.text, context: c });
        a = d.target && /^(jmp|call)/.test(d.text) && !b.step_over_calls ? d.target : a + d.len;
      }
    } else if (b.action === 'break' && Date.now() - b.armed > 3000) {
      if (b.condition && ++b.cn % 3) { b.armed = Date.now(); continue; } // mock: the condition holds every 3rd hit
      b.hits++;
      brk(b.addr, `breakpoint ${b.id}`);
      return;
    }
  }
}
function brk(rip, reason) {
  Object.assign(D, { state: 'broken', tid: P.pid, rip, reason, ctx: fakeCtx(rip, P.obj) });
  for (const b of D.bps) b.armed = Date.now();
}
const BPK = { execute: 1, write: 1, access: 1 };
const DBG = {
  debug_attach() { need(); D ??= { state: 'running', tid: null, rip: null, reason: null, bps: [], next: 1, ctx: null, susp: new Set(), log: [] }; return DBG.debug_status(); },
  debug_detach() { need(); D = null; return null; },
  debug_status() {
    if (!P || !D) return { attached: false, state: 'detached', tid: null, reason: null, rip: null, exit_code: null };
    const b = D.state === 'broken';
    return { attached: true, state: D.state, tid: b ? D.tid : null, reason: b ? D.reason : null, rip: b ? hx(D.rip) : null, exit_code: null };
  },
  debug_add_breakpoint({ req }) {
    const d = dneed(), kind = req.kind || 'execute';
    if (!BPK[kind]) err(`unknown breakpoint kind "${kind}"`);
    const method = kind === 'execute' ? req.method || 'software' : 'hardware';
    if (method === 'hardware' && d.bps.filter((b) => b.enabled && b.method === 'hardware').length >= 4) err('all 4 debug registers are in use');
    let size = kind === 'execute' ? 1 : req.size || 4;
    const addr = parseAddr(req.addr);
    while (addr % size) size /= 2;
    const b = { id: d.next++, addr, kind, size, len: size, method, action: req.action || 'break', ea: !!req.ea, enabled: true, hits: 0, recs: new Map(), trace: [], steps: req.steps || 1000, step_over_calls: !!req.step_over_calls, armed: Date.now(), cn: 0, condition: checkCond(req.condition),
      options: { skip_hits: req.skip_hits || 0, one_shot: !!req.one_shot, max_hits: req.max_hits || null }, owner: 'user', note: null, dropped: 0 };
    d.bps.push(b);
    return b.id;
  },
  debug_remove_breakpoint({ id }) { const d = dneed(), i = d.bps.findIndex((b) => b.id === id); if (i < 0) err(`no breakpoint ${id}`); d.bps.splice(i, 1); return null; },
  // In place, like hh-debug: hits and records stay.
  debug_set_enabled({ id, enabled }) { const b = dneed().bps.find((x) => x.id === id) || err(`no breakpoint ${id}`); b.enabled = enabled; if (enabled) b.note = null; b.armed = Date.now(); return null; },
  debug_set_options({ id, options }) { const b = dneed().bps.find((x) => x.id === id) || err(`no breakpoint ${id}`); b.options = { skip_hits: options.skip_hits || 0, one_shot: !!options.one_shot, max_hits: options.max_hits || null }; return null; },
  debug_watch_range({ req }) {
    const d = dneed(), addr = parseAddr(req.addr), len = Number(req.len);
    if (!(len >= 1)) err('the range is empty');
    if (regionOf(addr)?.path === '[stack]') err(`${hx(addr)}..${hx(addr + len)} is on a thread's stack: a page watch there would fault on every call and local variable. Watch it with a hardware watchpoint (8 bytes or less) instead`);
    const b = { id: d.next++, addr, kind: req.kind || 'write', size: Math.min(255, len), len, method: 'page', action: 'record', ea: false, enabled: true, hits: 0, recs: new Map(), trace: [], armed: Date.now(), cn: 0, condition: null,
      options: { skip_hits: 0, one_shot: false, max_hits: req.max_hits || null }, owner: 'user', note: null, dropped: 0, range: true };
    d.bps.push(b);
    return b.id;
  },
  debug_backtrace({ tid, max = 64 }) {
    const d = dneed();
    if (d.state !== 'broken') err(`thread ${tid} is running`);
    const exe = P.mods[0];
    return [d.rip, CODE.w2[0] + 2, CODE.r1[0] + 7, exe.base + 0x1450].slice(0, max).map((a) => ({ addr: hx(a), module: modOf(a)?.name ?? null, symbol: symbolize(a) || null }));
  },
  debug_log({ since }) { const d = dneed(); return { lines: d.log.filter((l) => l.seq > since), next: d.log.length }; },
  debug_breakpoints: () => dneed().bps.map((b, i) => ({ id: b.id, addr: hx(b.addr), kind: b.kind, size: b.size, len: b.len ?? b.size, method: b.method, action: b.action, ea: b.ea, enabled: b.enabled, hits: b.hits,
    condition: b.condition || null, slot: b.method === 'hardware' && b.enabled ? i % 4 : null, options: b.options, records_dropped: b.dropped || 0, owner: b.owner || 'user', note: b.enabled ? null : b.note })),
  debug_records({ id }) {
    const b = dneed().bps.find((x) => x.id === id) || err(`no breakpoint ${id}`);
    return [...b.recs.values()].map((r) => ({ addr: hx(r.addr), ip: hx(r.ip), bytes: r.bytes.map((x) => x.toString(16).toUpperCase().padStart(2, '0')).join(' '), text: r.text, count: r.count, address: r.address != null ? hx(r.address) : null, context: r.context }));
  },
  debug_clear_records({ id }) { const b = dneed().bps.find((x) => x.id === id); b?.recs.clear(); return null; },
  debug_trace({ id }) { return (dneed().bps.find((x) => x.id === id) || err(`no breakpoint ${id}`)).trace; },
  debug_threads() { const d = dneed(); return [P.pid, P.pid + 1, P.pid + 2].map((tid) => ({ tid, suspended: d.susp.has(tid) })); },
  debug_suspend_thread({ tid, suspend }) { const d = dneed(); suspend ? d.susp.add(tid) : d.susp.delete(tid); return null; },
  debug_context({ tid }) {
    const d = dneed();
    if (d.state !== 'broken') err(`thread ${tid} is running`);
    return tid === d.tid ? d.ctx : fakeCtx(CODE.r2[0], tid);
  },
  debug_set_register({ tid, name, value }) {
    const d = dneed();
    if (d.state !== 'broken') err(`thread ${tid} is running`);
    if (!REGN.includes(name)) err(`unknown register "${name}"`);
    d.ctx[name] = hx(parseAddr(value));
    if (name === 'rip') d.rip = parseAddr(value);
    return null;
  },
  debug_stack({ count }) {
    const d = dneed(), rsp = parseAddr(d.ctx?.rsp || err('the process is running'));
    return Array.from({ length: Math.min(count, 256) }, (_, i) => {
      const v = view(rsp + i * 8, 8), x = v ? num(v, '8bytes') : 0, val = i % 5 === 1 ? CODE.w1[0] + 3 : x;
      return { addr: hx(rsp + i * 8), value: hx(val), comment: symbolize(val) };
    });
  },
  debug_continue() { const d = dneed(); if (d.state !== 'broken') err('the process is not stopped'); Object.assign(d, { state: 'running', rip: null }); d.bps.forEach((b) => (b.armed = Date.now())); return null; },
  debug_pause() { const d = dneed(); if (d.state === 'running') brk(CODE.w1[0], 'paused'); return null; },
  debug_step({ kind }) {
    const d = dneed();
    if (d.state !== 'broken') err('the process is not stopped');
    const ins = decode(d.rip) || { len: 1 };
    const to = kind === 'out' ? CODE.w2[0] : kind === 'into' && ins.target ? ins.target : d.rip + ins.len;
    brk(to, 'step');
    return null;
  },
  debug_run_to({ addr, tid }) { const d = dneed(); void tid; if (d.state !== 'broken') err('the process is not stopped'); brk(parseAddr(addr), 'step'); return null; },
  nop_instruction({ addr }) {
    need();
    const a = parseAddr(addr), ins = decode(a) || err(`no valid instruction at ${addr}`), v = view(a, ins.len);
    const orig = [...v].map((b) => b.toString(16).padStart(2, '0')).join('');
    v.fill(0x90);
    return orig;
  },
  pick_path() { err('file dialogs need the desktop app'); },
};

// ---------- pointer scanner ----------
let PS = null; // {count, max_level, target, seed}
let pprog = { running: false, phase: '', done: 0, total: 0, found: 0 };
let pcancel = false;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function ptrRun(phase, steps, total, f) {
  if (pprog.running) err('a pointer scan is already running');
  pcancel = false;
  pprog = { running: true, phase, done: 0, total, found: 0 };
  try {
    for (let i = 1; i <= steps; i++) {
      await sleep(60);
      if (pcancel) { if (phase === 'collect') err('cancelled'); break; }
      pprog.done = Math.round((total * i) / steps);
      pprog.found = f(i / steps);
    }
    return pprog.found;
  } finally { pprog.running = false; pprog.phase = ''; }
}
const ptrInfo = () => ({ count: PS.count, max_level: PS.max_level, target: hx(PS.target) });
/** Row i of the fake result set: row 0 is the real "<exe>"+5A2B0 -> object path. */
function ptrPath(i) {
  const L = PS.max_level, base = P.syms.player_base - P.mods[0].base, last = PS.target - P.obj;
  if (i === 0 && last >= 0 && last < 0x1000) return { module: P.name, base_off: base, offsets: [last] };
  const r = rng(PS.seed + i * 7919), n = 1 + ((r() * L) | 0);
  const offsets = Array.from({ length: n }, (_, k) => (k === n - 1 ? Math.max(0, last) : ((r() * 0x200) | 0) * 8));
  const m = r() < 0.8 ? P.mods[0] : P.mods[1];
  return { module: m.name, base_off: ((r() * m.size) | 0) & ~7, offsets };
}
const shex = (o) => (o < 0 ? '-' + (-o).toString(16).toUpperCase() : o.toString(16).toUpperCase());
const baseText = (p) => `"${p.module}"+${p.base_off.toString(16).toUpperCase().padStart(8, '0')}`;
const pathText = (p) => '['.repeat(p.offsets.length) + baseText(p) + p.offsets.map((o) => `]+${shex(o)}`).join('');
const ptrIdx = (i) => PS.order?.[i] ?? i;
function ptrRow(idx, vtype) {
  const p = ptrPath(idx), r = rng(idx)();
  let a = null;
  try { a = resolveExpr(pathText(p)); } catch { /* unreadable hop */ }
  if (a == null && r > 0.1) a = PS.target; // pretend the rest still leads to the target
  const [value] = a == null ? [null] : C.read_values({ reqs: [{ addr: hx(a), vtype }] });
  return { p, a, value };
}
function ptrNeed() { need(); return PS || err('no pointer scan results'); }
const PTR = {
  async ptr_scan({ req }) {
    need();
    const target = parseAddr(req.target), L = Math.max(1, Math.min(16, req.opts?.max_level || 5));
    for (const c of req.compare || []) if (!fs?.[c.path] && !loadFs()[c.path]) err(`${c.path}: file not found`);
    await ptrRun('collect', 12, 400, () => 0);
    const cap = req.opts?.max_results || Infinity, full = Math.min(cap, 180_000 * L * (req.compare?.length ? 0.1 : 1));
    const found = await ptrRun('scan', 25, 1000, (f) => Math.round(full * f));
    PS = { count: Math.max(1, found), max_level: L, target, seed: Date.now() & 0xffff };
    return ptrInfo();
  },
  async ptr_rescan({ req }) {
    const ps = ptrNeed(), from = ps.count;
    const found = await ptrRun('rescan', 15, from, (f) => Math.max(1, Math.round((from * f) / 9)));
    ps.count = found; ps.order = null;
    if (req.target) ps.target = parseAddr(req.target);
    return ptrInfo();
  },
  ptr_progress: () => ({ ...pprog }),
  ptr_cancel() { pcancel = true; return null; },
  ptr_results({ offset, limit, vtype }) {
    const ps = ptrNeed(), out = [];
    for (let i = offset; i < Math.min(ps.count, offset + limit); i++) {
      const { p, a, value } = ptrRow(ptrIdx(i), vtype);
      out.push({ base: baseText(p), offsets: p.offsets.map(shex), text: pathText(p), address: a == null ? null : hx(a), value });
    }
    return out;
  },
  ptr_entry({ index, vtype, description }) {
    const p = ptrPath(ptrIdx(+index));
    return { id: 0, description, addr: baseText(p), offsets: p.offsets.map(shex), vtype, len: 0, utf16: false, signed: false, hex: false, frozen: false, freeze_mode: 'exact', color: null, dropdown: null, hotkeys: [], script: null, children: [] };
  },
  ptr_save_map({ path }) { need(); return C.table_save({ path, table: { pointer_map: P.name } }); },
  ptr_save_results({ path }) { return C.table_save({ path, table: { pointer_results: { ...ptrNeed() } } }); },
  ptr_open_results({ path }) {
    need();
    fs ??= loadFs();
    const r = fs[path]?.pointer_results || err(`not a HeapHook pointer result file: ${path}`);
    PS = { ...r };
    return ptrInfo();
  },
};
// ---------- live cheat table, Lua console, hotkeys, settings ----------
// The table lives "in the backend" here too: versioned, activation owned by these commands.
let T = { version: 0, table: { entries: [], lua_script: '', comments: '', codes: [] }, trust: 'own' };
// The backend's consent gate, in short: a loaded table's Lua runs only once it is trusted.
const trusted = () => T.trust === 'own' || T.trust === 'agreed';
const runsLua = (e) => /\{\$lua\}/i.test(e.script || '') || (e.children || []).some(runsLua);
function gate(what) {
  if (trusted()) return;
  if (loadSettings().table_script === 'never') err(`${what}: not run: it runs Lua from a loaded table and Settings say never to run a table's Lua`);
  err(T.trust === 'declined' ? `${what}: not run: you chose not to run this table's Lua (open the table again to be asked again)` : `needs consent: ${what}: this table runs Lua code, which can use your files and the process`);
}
const fvals = new Map(); // id -> value the entry is frozen to
const liveWalk = (list, f, parent = null) => list.forEach((e) => { f(e, parent); liveWalk(e.children || [], f, e); });
function liveFind(id) { let r = null; liveWalk(T.table.entries, (e) => { if (e.id === id) r = e; }); return r; }
const liveGroup = (e) => typeof e.script !== 'string' && !e.addr;
const bump = () => { T.version++; liveFreeze(); };
const entryAddr = (e) => resolveExpr((e.offsets || []).reduce((x, o) => `[${x}]+${o}`, e.addr));
function liveRead(e) {
  const a = entryAddr(e), len = e.vtype === 'string' ? (e.len || 16) * (e.utf16 ? 2 : 1) : e.vtype === 'aob' ? e.len || 8 : SIZE[e.vtype];
  const v = view(a, len) || err(`cannot read ${hx(a)}`);
  return fmt(v, e.vtype, e);
}
/** The mock "freezer": every active value entry, re-resolved. */
function liveFreeze() {
  if (!P) return;
  const list = [];
  liveWalk(T.table.entries, (e) => {
    if (!e.frozen || liveGroup(e) || typeof e.script === 'string' || !fvals.has(e.id)) return;
    try { list.push({ ...e, addr: hx(entryAddr(e)), value: fvals.get(e.id), mode: e.freeze_mode || 'exact' }); } catch { /* unresolved */ }
  });
  try { C.set_frozen({ entries: list }); } catch (x) { luaLog('err', `freeze: ${x}`); }
}
function liveActivate(e, on) {
  if (e.frozen === on) return;
  if (typeof e.script === 'string') {
    need();
    const x = aaCheck(e.script);
    if (x) err(`${e.description}: line ${x.line}: ${x.message}`);
  } else if (!liveGroup(e)) {
    if (on) fvals.set(e.id, liveRead(e)); else fvals.delete(e.id);
  }
  e.frozen = on;
  const o = e.options || [];
  if (o.includes(on ? 'moActivateChildrenAsWell' : 'moDeactivateChildrenAsWell')) for (const c of e.children) liveActivate(c, on);
}
function liveSetValue(e, value) {
  if (liveGroup(e) || typeof e.script === 'string') {
    if ((e.options || []).includes('moRecursiveSetValue')) for (const c of e.children) liveSetValue(c, value);
    return;
  }
  C.write_value({ ...e, addr: hx(entryAddr(e)), value });
  if (e.frozen) fvals.set(e.id, value);
}

// ---------- Lua forms (mock): a small retained tree like hh-lua's, with JS handlers ----------
const UI = { nodes: new Map(), changes: [], seq: 0, next: 1, handlers: new Map() };
function uiChange(c) { UI.changes.push({ seq: ++UI.seq, ...c }); if (UI.changes.length > 5000) UI.changes.shift(); }
function uiCreate(cls, parent, props, handlers = {}) {
  const id = UI.next++;
  const c = { id, class: cls, parent: parent ?? null, props: { Visible: true, Enabled: true, Left: 0, Top: 0, ...props }, events: Object.keys(handlers) };
  UI.nodes.set(id, c);
  UI.handlers.set(id, handlers);
  uiChange({ op: 'create', control: JSON.parse(JSON.stringify(c)) });
  return id;
}
function uiSet(id, prop, value, echo = true) {
  const c = UI.nodes.get(id);
  if (!c || c.props[prop] === value) return false;
  c.props[prop] = value;
  if (echo) uiChange({ op: 'update', id, prop, value });
  return true;
}
function uiDestroy(id) {
  if (!UI.nodes.has(id)) return;
  for (const c of [...UI.nodes.values()]) if (c.parent === id) uiDestroy(c.id);
  UI.nodes.delete(id); UI.handlers.delete(id);
  uiChange({ op: 'destroy', id });
}
function uiSnapshot() {
  const node = (c) => ({ ...c, children: [...UI.nodes.values()].filter((x) => x.parent === c.id).map(node) });
  return { roots: [...UI.nodes.values()].filter((c) => c.parent == null).map(node) };
}
/** createForm() in the mock console: one form with every control kind HeapHook draws. */
function demoForm(caption) {
  const f = uiCreate('TCEForm', null, { Caption: caption || 'Demo form', Width: 360, Height: 300, Position: 4 }, { OnClose: () => { uiSet(f, 'Visible', false); } });
  const mm = uiCreate('TMainMenu', f, {}), root = uiCreate('TMenuItem', mm, {});
  const file = uiCreate('TMenuItem', root, { Caption: '&File' });
  uiCreate('TMenuItem', file, { Caption: 'Say hello' }, { OnClick: () => luaLog('out', 'hello from the menu') });
  uiCreate('TMenuItem', file, { Caption: '-' });
  uiCreate('TMenuItem', file, { Caption: 'Close' }, { OnClick: () => uiSet(f, 'Visible', false) });
  uiSet(f, 'Menu', mm);
  uiCreate('TLabel', f, { Caption: 'Name', Left: 12, Top: 14 });
  const ed = uiCreate('TEdit', f, { Left: 70, Top: 10, Width: 160, Height: 24, Text: 'Player' }, { OnChange: () => luaLog('out', 'name: ' + UI.nodes.get(ed).props.Text) });
  const pb = uiCreate('TProgressBar', f, { Left: 12, Top: 46, Width: 218, Height: 8, Position: 40 });
  uiCreate('TButton', f, { Caption: 'Step', Left: 240, Top: 10, Width: 100, Height: 26 }, { OnClick: () => uiSet(pb, 'Position', (UI.nodes.get(pb).props.Position + 10) % 110) });
  uiCreate('TCheckBox', f, { Caption: 'God mode', Left: 12, Top: 64, Width: 150, Height: 20, Checked: false }, { OnClick: () => luaLog('out', 'god mode toggled') });
  uiCreate('TRadioGroup', f, { Caption: 'Difficulty', Left: 12, Top: 92, Width: 160, Height: 96, Items: ['Easy', 'Normal', 'Hard'], ItemIndex: 1 }, { OnClick: () => luaLog('out', 'difficulty changed') });
  uiCreate('TListBox', f, { Left: 184, Top: 64, Width: 156, Height: 84, Items: ['Sword', 'Shield', 'Potion', 'Bow'], ItemIndex: 0 });
  uiCreate('TComboBox', f, { Left: 184, Top: 156, Width: 156, Height: 26, Items: ['Slot 1', 'Slot 2', 'Slot 3'], ItemIndex: 0 });
  uiCreate('TTrackBar', f, { Left: 12, Top: 200, Width: 160, Height: 24, Min: 0, Max: 10, Position: 3 });
  const gb = uiCreate('TGroupBox', f, { Caption: 'Notes', Left: 184, Top: 192, Width: 156, Height: 96 });
  uiCreate('TMemo', gb, { Align: 5, Lines: ['Mock form', 'Edits go back to Lua'] });
  return f;
}
/** The mock runs a generated trainer block by reading its item list. */
function mockTrainer(src) {
  const items = [...src.matchAll(/\{ id = (\d+), label = "((?:[^"\\]|\\.)*)", keys = \{ ([\d, ]*) \}/g)].map((m) => ({ id: +m[1], label: m[2], keys: m[3].split(',').map(Number).filter(Boolean) }));
  const title = (src.match(/local title, about, beepOn, showKeys = "((?:[^"\\]|\\.)*)"/) || [])[1] || 'Trainer';
  for (const c of [...UI.nodes.values()]) if (c.parent == null && c.props.trainer) uiDestroy(c.id);
  const f = uiCreate('TCEForm', null, { Caption: title, Width: 320, Height: items.length * 26 + 22, trainer: true }, { OnClose: () => uiSet(f, 'Visible', false) });
  items.forEach((it, i) => {
    const e = liveFind(it.id);
    const cb = uiCreate('TCheckBox', f, { Caption: it.label + (it.keys.length ? '   ' + it.keys.join('+') : ''), Left: 12, Top: 12 + i * 26, Width: 296, Height: 22, Checked: !!e?.frozen },
      { OnClick: () => { const x = liveFind(it.id); if (x) { try { liveActivate(x, UI.nodes.get(cb).props.Checked); bump(); } catch (er) { luaLog('err', er); } } } });
  });
}

const LOG = [];
let logSeq = 0, luaBusy = false, luaStop = false, sound = 0, dlg = null, dlgSeq = 0;
const luaHotkeys = new Map(); // createHotkey id -> keys
function luaLog(kind, text) { LOG.push({ seq: ++logSeq, kind, text: String(text) }); if (LOG.length > 2000) LOG.shift(); }
function luaAsk(d) { return new Promise((resolve) => { dlg = { id: ++dlgSeq, title: '', text: '', dlg_type: 2, buttons: [], initial: '', ...d, resolve }; }); }
const strArg = (s) => (s.trim().match(/^(['"])(.*)\1$/) || [])[2];
/** A few Cheat Engine calls, line by line; the real backend runs full Lua 5.3. */
async function mockLua(src, name) {
  const lines = src.split('\n');
  let result = null;
  const fail = (ln, msg) => err(`${name}:${ln}: ${msg}\nstack traceback:\n\t[C]: in function 'error'\n\t${name}:${ln}: in main chunk`);
  const val = (x) => {
    x = x.trim();
    const s = strArg(x);
    if (s != null) return s;
    let m;
    if ((m = /^read(Integer|Float|Bytes)\((.+)\)$/.exec(x))) {
      need();
      const a = /^(0x)?[0-9a-f]+$/i.test(m[2].trim()) ? parseInt(m[2].trim(), 16) : resolveExpr(strArg(m[2]) ?? m[2]);
      const v = view(a, 4);
      return v ? fmt(v, m[1] === 'Float' ? 'float' : '4bytes', {}) : 'nil';
    }
    if ((m = /^speedhack_setSpeed\((.+)\)$/.exec(x))) { shSet(Number(m[1])); return 'true'; }
    if (/^-?[\d.]+$/.test(x)) return String(Number(x));
    if (/^[\d\s+\-*/().]+$/.test(x)) return String(Function(`return (${x})`)());
    return x;
  };
  for (let i = 0; i < lines.length; i++) {
    const ln = i + 1, l = lines[i].trim();
    if (luaStop) fail(ln, 'script interrupted');
    let m;
    if (!l || l.startsWith('--')) continue;
    if ((m = /^print\((.*)\)$/.exec(l))) luaLog('out', m[1].split(/,(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/).map(val).join(' '));
    else if ((m = /^showMessage\((.*)\)$/.exec(l))) await luaAsk({ kind: 'message', text: val(m[1]) });
    else if ((m = /^messageDialog\((.*)\)$/.exec(l))) {
      const a = m[1].split(',');
      const mb = { mbYes: 0, mbNo: 1, mbOK: 2, mbCancel: 3 };
      luaLog('out', 'messageDialog -> ' + await luaAsk({ kind: 'dialog', text: val(a[0]), dlg_type: 3, buttons: a.slice(2).map((b) => mb[b.trim()] ?? 2) }));
    } else if ((m = /^inputQuery\((.*)\)$/.exec(l))) {
      const a = m[1].split(',').map(val);
      luaLog('out', 'inputQuery -> ' + await luaAsk({ kind: 'input', title: a[0] || '', text: a[1] || '', initial: a[2] || '' }));
    } else if ((m = /^error\((.*)\)$/.exec(l))) fail(ln, val(m[1]));
    else if (/^while true do/.test(l)) {
      while (!luaStop) await sleep(50);
      fail(ln, 'script interrupted');
    } else if (l === 'beep()') sound++;
    else if ((m = /^getAddressList\(\)\.getMemoryRecordByDescription\((.+)\)\.Active\s*=\s*(true|false)$/.exec(l))) {
      let e = null;
      liveWalk(T.table.entries, (x) => { if (!e && x.description === val(m[1])) e = x; });
      if (!e) fail(ln, 'attempt to index a nil value');
      liveActivate(e, m[2] === 'true'); bump();
    } else if ((m = /^createHotkey\(.*,\s*(.+)\)$/.exec(l))) {
      const vk = { VK_CONTROL: 17, VK_SHIFT: 16, VK_MENU: 18 };
      const keys = m[1].split(',').map((k) => k.trim()).map((k) => vk[k] ?? (/^VK_F(\d+)$/.test(k) ? 111 + +k.slice(4) : /^VK_[A-Z0-9]$/.test(k) ? k.charCodeAt(3) : 0));
      luaHotkeys.set(luaHotkeys.size + 1, keys);
    } else if ((m = /^return (.+)$/.exec(l))) { result = val(m[1]); break; }
    else if ((m = /(?:^|=\s*)createForm\((.*)\)/.exec(l))) demoForm(strArg(m[1] || ''));
    else if (l === '-- BEGIN HEAPHOOK TRAINER') { mockTrainer(lines.slice(i).join('\n')); i = lines.findIndex((x, k) => k > i && x.trim() === '-- END HEAPHOOK TRAINER'); if (i < 0) break; }
    else if (/^speedhack_setSpeed\(/.test(l)) val(l);
    else luaLog('info', `mock backend: '${l}' is not simulated (the real backend runs full Lua)`);
  }
  if (result != null) luaLog('result', result);
}
async function luaRun(src, name) {
  luaBusy = true; luaStop = false;
  try { await mockLua(src, name); } catch (x) { luaLog('err', x); throw x; } finally { luaBusy = false; }
}
const hkBindings = () => {
  const out = [];
  liveWalk(T.table.entries, (e) => (e.hotkeys || []).forEach((k, i) => out.push([[...k.keys].sort((a, b) => a - b), e.id, i])));
  for (const [id, k] of luaHotkeys) out.push([[...k].sort((a, b) => a - b), null, id]);
  return out;
};
const SETTINGS = { scan_priority: 'normal', scan_spill_dir: '', hotkey_delay_ms: 150, freeze_interval_ms: 100, live_update_ms: 300, fast_scan: true, scan_alignment: 4, scan_writable: 'yes', scan_executable: 'any',
  scan_copy_on_write: 'no', scan_threads: 0, lua_budget_ms: 30000, lua_memory_mb: 1024, table_script: 'ask', lua_allow_os: true, bp_method: 'software', hotkey_sound: false, theme: 'system', signals: {} };
function loadSettings() { try { return { ...SETTINGS, ...JSON.parse(localStorage.getItem('hh.mocksettings')) }; } catch { return { ...SETTINGS }; } }

/** Seeded once so the table features can be tried without the real backend. */
const DEMO = {
  entries: [
    { id: 1, description: 'Player', addr: '', options: ['moActivateChildrenAsWell', 'moDeactivateChildrenAsWell'], children: [
      { id: 2, description: 'Health', addr: 'player_base', offsets: ['0'], vtype: '4bytes', color: '#346538',
        hotkeys: [{ action: 'Toggle Activation', keys: [17, 112] }, { action: 'Set Value', keys: [17, 113], value: '100' }], children: [] },
      { id: 3, description: 'Gold', addr: 'player_base', offsets: ['8'], vtype: '4bytes',
        hotkeys: [{ action: 'Increase Value', keys: [17, 114], value: '100' }], children: [] },
      { id: 4, description: 'Difficulty', addr: 'player_base', offsets: ['E'], vtype: '2bytes',
        dropdown: { options: [{ value: '1', text: 'Easy' }, { value: '7', text: 'Normal' }, { value: '10', text: 'Hard' }], read_only: true, description_only: false, display_value_as_item: true }, children: [] },
    ] },
    { id: 5, description: 'Infinite health', script: '[ENABLE]\n{$lua}\nprint("enabling " .. memrec.Description)\n{$asm}\nalloc(newmem,1024)\n\n[DISABLE]\ndealloc(newmem)\n', children: [] },
    { id: 6, description: 'Cheats (shown when active)', addr: '', options: ['moHideChildren', 'moActivateChildrenAsWell', 'moDeactivateChildrenAsWell'], children: [
      { id: 7, description: 'Ammo', addr: 'player_base', offsets: ['C'], vtype: '2bytes', children: [] },
    ] },
  ],
  lua_script: 'print("Demo table script ran")\nshowMessage("Hello from the demo table\'s Lua script")\n',
  comments: 'Demo table for the in-browser mock backend.',
  codes: [],
};

const LIVE = {
  table_get: () => T,
  table_put({ table, base }) {
    if (base !== T.version) err(`stale table version ${base} (current ${T.version})`);
    const was = new Map();
    liveWalk(T.table.entries, (e) => was.set(e.id, !!e.frozen));
    const ids = new Set();
    liveWalk(table.entries, (e) => { if (ids.has(e.id) || !(e.id > 0)) err(`bad or duplicate entry id ${e.id}`); ids.add(e.id); e.frozen = was.get(e.id) || false; });
    for (const id of fvals.keys()) if (!ids.has(id)) fvals.delete(id);
    const prev = JSON.stringify(T.table);
    liveWalk(T.table.entries, (e) => { if (typeof e.script === 'string' && e.frozen && !ids.has(e.id)) try { liveActivate(e, false); } catch { e.frozen = false; } });
    if (prev !== JSON.stringify(table)) pushUndo(JSON.parse(prev));
    // Raw .CT fragments never come in through a put (the real backend keeps only its own).
    const held = new Map();
    liveWalk(T.table.entries, (e) => held.set(e.id, JSON.stringify(e.ct_extra || [])));
    liveWalk(table.entries, (e) => { if (e.ct_extra?.length && held.get(e.id) !== JSON.stringify(e.ct_extra)) e.ct_extra = []; });
    if (JSON.stringify(table.ct_extra || []) !== JSON.stringify(T.table.ct_extra || [])) table.ct_extra = [];
    T = { ...T, version: T.version + 1, table };
    liveFreeze();
    return T.version;
  },
  // The mock's scripts cannot fail to disable, so `force` changes nothing.
  table_trust({ trust }) {
    if (trust && loadSettings().table_script === 'never' && T.trust !== 'own') err('Settings say never to run a table\'s Lua: change "Lua script in a loaded table" first');
    T = { ...T, version: T.version + 1, trust: T.trust === 'own' ? 'own' : trust ? 'agreed' : 'declined' };
    return null;
  },
  table_open({ path }) {
    for (const c of [...UI.nodes.values()]) if (c.parent == null) uiDestroy(c.id); // forms go with the table
    fs ??= loadFs();
    if (path === 'demo.json' && !fs[path]) fs[path] = DEMO;
    const t = fs[path] ?? err(/\.ct$/i.test(path) ? `file not found: ${path} (.CT parsing needs the real backend)` : `file not found: ${path}`);
    const table = JSON.parse(JSON.stringify({ lua_script: '', comments: '', codes: [], ...(Array.isArray(t) ? { entries: t } : t) }));
    liveWalk(table.entries, (e) => { e.frozen = false; e.ct_extra = []; });
    table.ct_extra = [];
    fvals.clear(); undo.length = redo.length = 0;
    T = { version: T.version + 1, table, trust: 'ask' };
    liveFreeze();
    return T;
  },
  table_export({ path }) { return C.table_save({ path, table: T.table }); },
  table_set_active({ ids, active }) {
    const errs = [];
    if (active) for (const id of ids) { const e = liveFind(id); if (e && runsLua(e)) gate(e.description); }
    for (const id of ids) { const e = liveFind(id); if (e) try { liveActivate(e, active); } catch (x) { errs.push(String(x)); } }
    bump();
    if (errs.length) err(errs.join('\n'));
  },
  table_set_value({ ids, value }) {
    need();
    for (const id of ids) { const e = liveFind(id); if (e) liveSetValue(e, value); }
    liveFreeze();
  },
  table_hotkey({ id, index }) {
    const e = liveFind(id) || err(`no table entry ${id}`), k = e.hotkeys[index] || err('no such hotkey');
    if (/^(Toggle Activation|Activate|Deactivate)/.test(k.action) && runsLua(e)) gate(e.description);
    const step = (sign) => {
      const cur = Number(liveRead(e)), d = Number(k.value);
      liveSetValue(e, String(e.vtype === 'float' || e.vtype === 'double' ? cur + sign * d : Math.trunc(cur + sign * d)));
    };
    switch (k.action) {
      case 'Toggle Activation': case 'Toggle Activation Allow Increase': case 'Toggle Activation Allow Decrease':
        if (k.action !== 'Toggle Activation') e.freeze_mode = k.action.endsWith('Increase') ? 'allow_increase' : 'allow_decrease';
        liveActivate(e, !e.frozen); break;
      case 'Activate': liveActivate(e, true); break;
      case 'Deactivate': liveActivate(e, false); break;
      case 'Set Value': liveSetValue(e, k.value); break;
      case 'Increase Value': step(1); break;
      case 'Decrease Value': step(-1); break;
      default: err(`unknown hotkey action '${k.action}'`);
    }
    bump();
  },
  async table_run_script() {
    if (!T.table.lua_script.trim()) return;
    gate("The table's Lua script");
    luaLog('info', "-- running the table's Lua script");
    await luaRun(T.table.lua_script, 'table script');
  },
  hotkey_press({ keys }) {
    const k = [...keys].sort((a, b) => a - b).join(',');
    let n = 0;
    for (const [combo, id, i] of hkBindings()) {
      if (combo.join(',') !== k) continue;
      n++;
      if (id == null) luaLog('out', `hotkey ${i} fired`); else LIVE.table_hotkey({ id, index: i });
    }
    if (n && loadSettings().hotkey_sound) sound++;
    return n;
  },
  async lua_exec({ code }) {
    luaLog('in', code);
    await luaRun(code, 'console');
  },
  lua_interrupt() { luaStop = true; if (dlg) { dlg.resolve(null); dlg = null; } },
  lua_poll({ since }) {
    const keys = [...new Set(hkBindings().map((b) => b[0].join(',')))].map((s) => s.split(',').map(Number));
    const { resolve, ...d } = dlg || {};
    return { log: LOG.filter((l) => l.seq > since), next: logSeq, dialog: dlg ? d : null, table_version: T.version, hotkeys: keys, busy: luaBusy, sound,
      process: P ? { pid: P.pid, name: P.name, is_64bit: true, alive: true } : null, selection: { seq: 0, ids: [] }, ui_seq: UI.seq };
  },
  ui_poll({ since }) {
    const behind = UI.changes.length && UI.changes[0].seq > since + 1;
    if (!since || behind || since > UI.seq) return { next: UI.seq, changes: [], snapshot: uiSnapshot() };
    return { next: UI.seq, changes: UI.changes.filter((c) => c.seq > since), snapshot: null };
  },
  ui_event({ id, event }) { const f = UI.handlers.get(id)?.[event]; if (f) f(); else if (event === 'OnClose') uiSet(id, 'Visible', false); return []; },
  ui_input({ id, prop, value }) {
    const c = UI.nodes.get(id);
    if (!c) return null;
    const key = prop === 'Text' && c.class === 'TMemo' ? 'Lines' : prop;
    const v = key === 'Lines' && typeof value === 'string' ? value.split('\n') : value;
    if (uiSet(id, key, v, false)) {
      const hs = UI.handlers.get(id) || {};
      hs.OnChange?.();
      if (key === 'Checked' || (key === 'ItemIndex' && c.class === 'TRadioGroup')) hs.OnClick?.();
    }
    return null;
  },
  ui_image() { err('images need the real backend (it reads the file)'); },
  key_state() { return null; },
  table_select() { return null; },
  trainer_script({ req }) {
    if (!req.entries?.length) err('pick at least one table entry for the trainer');
    const q = (x) => JSON.stringify(String(x));
    const items = req.entries.map((it) => { const e = liveFind(it.id) || err(`no table entry ${it.id}`); return `    { id = ${it.id}, label = ${q(it.label || e.description)}, keys = { ${(it.keys || []).join(', ')} }, own = true },`; });
    return `-- BEGIN HEAPHOOK TRAINER\n-- Generated by HeapHook's trainer generator (mock backend: the real one writes the full script).\ndo\n  local items = {\n${items.join('\n')}\n  }\n  local title, about, beepOn, showKeys = ${q(req.title || 'Trainer')}, ${q(req.about || '')}, ${!!req.beep}, ${!!req.show_keys}\nend\n-- END HEAPHOOK TRAINER\n`;
  },
  lua_dialog_reply({ id, value }) { if (dlg?.id === id) { dlg.resolve(value); dlg = null; } },
  settings_get: () => loadSettings(),
  settings_set({ settings }) {
    const s = { ...SETTINGS, ...settings };
    try { localStorage.setItem('hh.mocksettings', JSON.stringify(s)); } catch { /* storage blocked: session only */ }
    if (s.table_script === 'never' && T.trust === 'agreed') T = { ...T, version: T.version + 1, trust: 'declined' };
    return s;
  },
};

// ---------- tools: history, jobs, structures, dissector, memory tools, code list ----------
const undo = [], redo = [];
const clone = (x) => JSON.parse(JSON.stringify(x));
function pushUndo(t) { undo.push(t); redo.length = 0; if (undo.length > 100) undo.shift(); }
/** Edit the live table in place with undo support (structures, codes). */
function tEdit(fn) { pushUndo(clone(T.table)); fn(T.table); bump(); }
function applyTable(t) {
  const was = new Map(), ids = new Set();
  liveWalk(T.table.entries, (e) => was.set(e.id, !!e.frozen));
  liveWalk(t.entries, (e) => { ids.add(e.id); e.frozen = was.get(e.id) || false; });
  liveWalk(T.table.entries, (e) => { if (typeof e.script === 'string' && e.frozen && !ids.has(e.id)) try { liveActivate(e, false); } catch { e.frozen = false; } });
  for (const id of fvals.keys()) if (!ids.has(id)) fvals.delete(id);
  T = { ...T, version: T.version + 1, table: t };
  liveFreeze();
  return T;
}
const A = (s) => (/^0x[0-9a-f]+$/i.test(s) ? parseAddr(s) : resolveExpr(s));
const hexs = (u) => [...u].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
function readMem(a, len) {
  const out = new Uint8Array(len);
  for (let i = 0; i < len;) {
    const r = regionOf(a + i);
    if (!r) return null;
    const n = Math.min(len - i, r.start + r.size - (a + i)), f = r.flat + (a + i - r.start);
    out.set(P.mem.subarray(f, f + n), i); i += n;
  }
  return out;
}
function writeMem(a, b) {
  for (let i = 0; i < b.length;) {
    const r = regionOf(a + i);
    if (!r) return false;
    const n = Math.min(b.length - i, r.start + r.size - (a + i)), f = r.flat + (a + i - r.start);
    P.mem.set(b.subarray(i, i + n), f); i += n;
  }
  return true;
}
/** Readable parts of the requested ranges as {addr, data}. */
function grab(ranges) {
  const out = [];
  for (const { start, size } of ranges) {
    const a = typeof start === 'string' ? A(start) : start, e = a + size;
    for (const r of P.R) {
      const s = Math.max(a, r.start), t = Math.min(e, r.start + r.size);
      if (r.prot[0] === 'r' && s < t) out.push({ addr: s, data: P.mem.slice(r.flat + s - r.start, r.flat + t - r.start) });
    }
  }
  return out;
}

// long-running jobs share one progress object
let JOB = { running: false, job: '', done: 0, total: 0, found: 0 }, jobCancel = false;
async function runJob(job, compute, cnt = (r) => r.length) {
  if (JOB.running) err('another long-running job is in progress');
  jobCancel = false; JOB = { running: true, job, done: 0, total: 1000, found: 0 };
  try {
    const res = compute(), n = cnt(res);
    for (let i = 1; i <= 20; i++) {
      await sleep(40);
      if (jobCancel) err('cancelled');
      JOB.done = i * 50; JOB.found = Math.round((n * i) / 20);
    }
    return res;
  } finally { JOB = { ...JOB, running: false, job: '' }; }
}

// speedhack
const shStat = () => (P?.sh ? { pid: P.pid, addr: '0x7f1235000000', speed: P.sh.speed, generation: P.sh.generation } : null);
function shSet(speed) {
  const s = need().sh || err('this process was not started with the speedhack (use Create process)');
  if (!(speed > 0 && speed <= 1000)) err(`invalid speed ${speed}: must be > 0 and <= 1000`);
  s.speed = speed; s.generation++;
  return shStat();
}

// structure dissector
const FSZ = { byte: 1, '2bytes': 2, '4bytes': 4, float: 4, '8bytes': 8, double: 8, pointer: 8 };
const elSize = (e) => FSZ[e.vtype] || e.size || (e.vtype === 'struct' ? 8 : 16);
const structs = () => T.table.structures || [];
const findSt = (n) => structs().find((s) => s.name === n);
function guessStruct(name, a, size) {
  const v = view(a, size) || err(`cannot read ${size} bytes at ${hx(a)}`);
  const d = new DataView(v.buffer, v.byteOffset, v.length), elements = [];
  const plaus = (o) => { const x = d.getFloat32(o, true), u = d.getUint32(o, true), ab = Math.abs(x); return Number.isFinite(x) && ab >= 1e-4 && ab <= 1e7 && !(Number.isInteger(x) && ab < 1e6 && u < 65536); };
  const el = (offset, vtype, sz) => elements.push({ offset, description: '', vtype, size: sz, hex: vtype === 'pointer', signed: false, utf16: false });
  for (let o = 0; o + 8 <= size; o += 8) {
    const b = d.getBigUint64(o, true), t = Number(b), r = b < 1n << 53n ? regionOf(t) : null;
    if (r && r.prot[0] === 'r' && t >= 0x10000) { el(o, 'pointer', 8); continue; }
    let n = 0;
    while (n < 8 && v[o + n] >= 0x20 && v[o + n] < 0x7f) n++;
    if (n >= 4) el(o, 'string', n);
    else for (const h of [0, 4]) el(o + h, plaus(o + h) ? 'float' : '4bytes', 4);
  }
  return { name, elements };
}
const putStruct = (t, s) => { t.structures ??= []; const i = t.structures.findIndex((x) => x.name === s.name); i < 0 ? t.structures.push(s) : (t.structures[i] = s); };
function evalStruct(st, base) {
  return st.elements.map((el, index) => {
    const size = elSize(el), addr = base + el.offset, v = view(addr, size * (el.vtype === 'string' && el.utf16 ? 2 : 1));
    let value = null, target = null;
    if (v && el.vtype === 'pointer') {
      const b = new DataView(v.buffer, v.byteOffset, 8).getBigUint64(0, true);
      value = b.toString(16).toUpperCase();
      if (b < 1n << 53n && regionOf(Number(b))) target = hx(Number(b));
    } else if (v && el.vtype !== 'struct') value = fmt(v, el.vtype, el);
    return { offset: el.offset, addr: hx(addr), description: el.description || '', vtype: el.vtype, size, value, target, child: el.child || null, owner: st.name, index, children: [] };
  });
}
const hh = (n) => n.toString(16).toUpperCase();

// code dissection
let DIS = null;
const SNAPS = [];
let snapSeq = 0;
const STR_T = ['Player %d health: %d', 'config.ini', 'Failed to open %s', 'Level %d', 'Loading %s...', 'Enemy %d spawned', 'Save game', 'Invalid state: %d',
  'Unable to allocate %zu bytes', 'assets/%s.png', 'Gold: %d', 'Mission %d complete', 'Press any key', 'Game over', '%s: %d/%d', 'shader compile error: %s', 'audio device %d', 'score'];
const STR_W = ['player', 'enemy', 'texture', 'inventory', 'network', 'timeout', 'menu', 'physics'];
function genDissect(mods) {
  const r = rng(P.pid * 31 + 7), funcs = [], strs = [], caves = [], xr = [];
  let code = 0;
  for (const m of mods) {
    const inMod = (x) => x.start >= m.base && x.start < m.base + m.size;
    const rx = P.R.filter((x) => x.prot[2] === 'x' && inMod(x));
    const ro = P.R.filter((x) => x.prot === 'r--' && inMod(x)).sort((a, b) => b.size - a.size)[0];
    const mf = [], codeAddr = () => { const g = rx[(r() * rx.length) | 0]; return g.start + ((r() * (g.size - 8)) | 0); };
    for (const g of rx) {
      code += g.size;
      const n = Math.min(300 + ((r() * 1700) | 0), g.size >> 5), sp = Math.floor(g.size / n), gf = [];
      for (let i = 0; i < n; i++) gf.push({ addr: g.start + i * sp + (((r() * sp) / 2) & ~15), callers: r() < 0.4 ? 0 : 1 + ((r() * r() * 40) | 0), internal: true, name: null });
      const named = Object.entries(P.syms).filter(([k, v]) => k !== 'player_base' && v >= g.start && v < g.start + g.size);
      if (m === P.mods[0]) named.push(['main', g.start + 0x100], ['update_player', CODE.w1[0] - 0x10]);
      for (const [name, a] of named) { const f = gf[Math.min(n - 1, Math.floor((a - g.start) / sp))]; f.addr = a; f.name = name; f.callers = Math.max(f.callers, 3); }
      mf.push(...gf);
      for (let i = 0; i < 30 / rx.length; i++) caves.push({ addr: g.start + (((r() * (g.size - 512)) | 0) & ~15), len: 32 + ((r() * 480) | 0), byte: r() < 0.5 ? 0 : 0xcc });
    }
    for (let i = 0; i < 400 && rx.length; i++) xr.push({ from: codeAddr(), to: codeAddr(), kind: r() < 0.5 ? 'jump' : 'cond_jump' });
    for (const f of mf) for (let i = 0; i < f.callers; i++) xr.push({ from: codeAddr(), to: f.addr, kind: 'call' });
    funcs.push(...mf);
    if (ro) {
      let cur = ro.start + 0x40;
      for (let i = 0; i < 200; i++) {
        const text = STR_T[(r() * STR_T.length) | 0] + (r() < 0.3 ? ' ' + STR_W[(r() * STR_W.length) | 0] : '');
        if (cur + text.length + 2 > ro.start + ro.size) break;
        const refs = r() < 0.25 ? 0 : 1 + ((r() * r() * 6) | 0);
        writeMem(cur, new TextEncoder().encode(text + '\0'));
        strs.push({ addr: cur, text, utf16: false, refs });
        for (let k = 0; k < refs && rx.length; k++) xr.push({ from: codeAddr(), to: cur, kind: 'data' });
        cur += (text.length + 4) & ~3;
      }
    }
  }
  funcs.sort((a, b) => a.addr - b.addr); strs.sort((a, b) => a.addr - b.addr); caves.sort((a, b) => a.addr - b.addr); xr.sort((a, b) => a.to - b.to);
  const summary = { modules: mods.map((m) => m.name), code_bytes: code, instructions: Math.floor(code / 3.8), functions: funcs.length, refs: xr.length, strings: strs.length, caves: caves.length };
  return { summary, funcs, strs, caves, xr };
}
const xrLower = (to) => { let lo = 0, hi = DIS.xr.length; while (lo < hi) { const m = (lo + hi) >> 1; if (DIS.xr[m].to < to) lo = m + 1; else hi = m; } return lo; };
function xrefsAt(a) {
  if (!DIS) return {};
  const x = { calls: 0, jumps: 0, data: 0 };
  for (let i = xrLower(a); i < DIS.xr.length && DIS.xr[i].to === a; i++) { const k = DIS.xr[i].kind; x[k === 'call' ? 'calls' : k === 'data' ? 'data' : 'jumps']++; }
  return x.calls + x.jumps + x.data ? { xrefs: x } : {};
}
const dissNeed = () => DIS || err('no code dissection yet');
const dfilter = (list, filter, text) => {
  if (!filter) return list;
  const f = String(filter).toLowerCase(), h = f.replace(/^0x/, '');
  return list.filter((x) => (text(x) || '').toLowerCase().includes(f) || x.addr.toString(16).includes(h));
};

// code list
const codeState = (c) => {
  let a = null, cur = '';
  try { a = A(c.address); } catch { /* unresolved */ }
  const orig = cleanHex(c.bytes.replace(/\s+/g, '')), v = a == null ? null : view(a, orig.length);
  const state = !v ? 'unreadable' : v.every((b, i) => b === orig[i]) ? 'original' : v.every((b) => b === 0x90) ? 'nopped' : 'changed';
  return { a, orig, v, state, cur: v ? hexs(v) : cur };
};
const codeAt = (i) => (T.table.codes || [])[i] || err(`no code entry ${i}`);
function checkCond(c) {
  c = String(c || '').trim();
  if (!c) return null;
  const bad = c.match(/[^\w\s=!<>&|()+\-*^]/);
  if (bad) err(`condition: unexpected '${bad[0]}'`);
  let d = 0;
  for (const ch of c) if (ch === '(') d++; else if (ch === ')' && --d < 0) err("condition: unexpected ')'");
  if (d) err("condition: unexpected end (missing ')')");
  return c;
}
const modOf = (a) => P.mods.find((m) => a >= m.base && a < m.base + m.size);

const TOOLS = {
  close_process() {
    clearInterval(ticker);
    P = D = PS = S = DIS = null; SNAPS.length = 0; frozen.length = 0; overrides.clear();
    liveWalk(T.table.entries, (e) => { if (typeof e.script === 'string') e.frozen = false; });
    T.version++;
    return null;
  },
  table_undo() { if (!undo.length) err('nothing to undo'); const t = undo.pop(); redo.push(clone(T.table)); return applyTable(t); },
  table_redo() { if (!redo.length) err('nothing to redo'); const t = redo.pop(); undo.push(clone(T.table)); return applyTable(t); },
  process_create({ req }) {
    if (!req?.program) err('no program given');
    const pid = 9000 + PROCS.filter((p) => p[0] >= 9000).length;
    PROCS.push([pid, req.program.split(/[\\/]/).pop(), req.program]);
    const r = C.open_process({ pid });
    if (req.speedhack) P.sh = { speed: 1, generation: 0 };
    return r;
  },
  speed_get: () => shStat(),
  speed_set: ({ speed }) => shSet(speed),

  tools_progress: () => ({ ...JOB }),
  tools_cancel() { if (JOB.running) jobCancel = true; return null; },

  struct_get: () => structs(),
  struct_set({ structs: list }) {
    const seen = new Set();
    for (const s of list) {
      if (!String(s.name || '').trim()) err('structure name is empty');
      if (seen.has(s.name)) err(`duplicate structure name "${s.name}"`);
      seen.add(s.name);
    }
    tEdit((t) => { t.structures = clone(list); });
    return null;
  },
  struct_guess({ name, addr, size }) {
    need();
    const s = guessStruct(name, A(addr), size);
    tEdit((t) => putStruct(t, s));
    return s;
  },
  struct_eval({ reqs }) {
    need();
    return reqs.map(({ name, addr }) => {
      try { return { Ok: evalStruct(findSt(name) || err(`no such structure "${name}"`), A(addr)) }; } catch (e) { return { Err: String(e) }; }
    });
  },
  struct_expand({ owner, index, fieldAddr: field_addr, size }) {
    need();
    const st = findSt(owner) || err(`no such structure "${owner}"`), el = st.elements[index];
    if (el?.vtype !== 'pointer') err('element is not a pointer');
    const v = view(A(field_addr), 8) || err(`cannot read pointer at ${field_addr}`), target = num(v, '8bytes');
    if (el.child && findSt(el.child)) return { name: el.child, addr: hx(target) };
    let name = `${owner}_${hh(el.offset)}`;
    while (findSt(name)) name += '_';
    const s = guessStruct(name, target, size);
    tEdit((t) => { putStruct(t, s); t.structures.find((x) => x.name === owner).elements[index].child = name; });
    return { name, addr: hx(target) };
  },
  struct_entries({ name, root, path = [], only }) {
    const st = findSt(name) || err(`no such structure "${name}"`);
    return st.elements.flatMap((el, i) => {
      if (el.vtype === 'struct' || (only && !only.includes(i))) return [];
      const addr = `${root}+${hh(path.length ? path[0] : el.offset)}`, offsets = path.length ? [...path.slice(1).map(hh), hh(el.offset)] : [];
      const ptr = el.vtype === 'pointer', sl = el.vtype === 'string' || el.vtype === 'aob';
      return [{ id: 0, description: el.description || `${name}+${hh(el.offset)}`, addr, offsets, vtype: ptr ? '8bytes' : el.vtype, len: sl ? elSize(el) : 0,
        utf16: !!el.utf16, signed: !!el.signed, hex: ptr || !!el.hex, frozen: false, freeze_mode: 'exact', color: null, dropdown: null, hotkeys: [], script: null, children: [] }];
    });
  },
  async struct_spider({ groups, opts = {} }) {
    need();
    const size = opts.size || 0x200, w = opts.width || 4, max = opts.max_results || 1000;
    const gs = groups.map((g) => g.map((a) => A(a)));
    return runJob('spider', () => {
      const hits = [];
      for (let off = 0; off + w <= size && hits.length < max; off += w) {
        const vals = gs.map((g) => g.map((a) => view(a + off, w)).map((v) => (v ? hexs(v) : null)));
        if (vals.some((g) => g.includes(null) || new Set(g).size > 1)) continue;
        if (new Set(vals.map((g) => g[0])).size === vals.length) hits.push({ path: [off], values: vals });
      }
      return hits;
    });
  },

  dissect_run({ modules = [] }) {
    need();
    const sel = modules.length ? modules.map((n) => P.mods.find((m) => m.name.toLowerCase() === String(n).toLowerCase()) || err('no such module')) : P.mods;
    return runJob('dissect', () => genDissect(sel), (d) => d.summary.functions).then((d) => { DIS = d; return d.summary; });
  },
  dissect_summary: () => DIS?.summary || null,
  dissect_list({ kind, filter, offset = 0, limit = 100 }) {
    dissNeed();
    let rows;
    if (kind === 'functions') rows = dfilter(DIS.funcs, filter, (f) => f.name);
    else if (kind === 'called') rows = dfilter(DIS.funcs, filter, (f) => f.name).filter((f) => f.callers > 0).sort((a, b) => b.callers - a.callers || a.addr - b.addr);
    else if (kind === 'strings') rows = dfilter(DIS.strs, filter, (s) => s.text);
    else if (kind === 'caves') rows = dfilter(DIS.caves, filter, () => '');
    else err(`unknown list kind "${kind}"`);
    return { total: rows.length, rows: rows.slice(offset, offset + limit).map((x) => ({ ...x, addr: hx(x.addr) })) };
  },
  dissect_xrefs({ addr, len = 1, offset = 0, limit = 100 }) {
    need(); dissNeed();
    const a = A(addr), e = a + Math.max(len, 1), rows = [];
    for (let i = xrLower(a); i < DIS.xr.length && DIS.xr[i].to < e; i++) rows.push(DIS.xr[i]);
    return {
      total: rows.length,
      rows: rows.slice(offset, offset + limit).map((x) => {
        let lo = 0, hi = DIS.funcs.length;
        while (lo < hi) { const m = (lo + hi) >> 1; if (DIS.funcs[m].addr <= x.from) lo = m + 1; else hi = m; }
        const f = DIS.funcs[lo - 1], rg = regionOf(x.from);
        return { from: hx(x.from), to: hx(x.to), kind: x.kind, text: decode(x.from)?.text ?? '??', func: f && rg && f.addr >= rg.start ? hx(f.addr) : null };
      }),
    };
  },

  regions_info: () => need().R.map((r) => {
    const m = modOf(r.start);
    return { start: hx(r.start), size: r.size, prot: { r: r.prot[0] === 'r', w: r.prot[1] === 'w', x: r.prot[2] === 'x' }, prot_text: r.prot + 'p', kind: r.kind, shared: false, path: r.path,
      module: m ? m.name : null, tag: r.path === '[heap]' ? 'heap' : r.path.startsWith('[stack') ? 'stack' : m ? 'image' : r.kind === 'Mapped' ? 'mapped' : 'private' };
  }),
  mem_protect({ addr, prot }) {
    need();
    const r = regionOf(A(addr)) || err(`no memory region at ${addr}`), old = { r: r.prot[0] === 'r', w: r.prot[1] === 'w', x: r.prot[2] === 'x' };
    r.prot = (prot.r ? 'r' : '-') + (prot.w ? 'w' : '-') + (prot.x ? 'x' : '-');
    return old;
  },
  async mem_save({ ranges, path }) {
    need();
    if (!path) err('empty path');
    const blocks = await runJob('save', () => grab(ranges).map((b) => ({ addr: hx(b.addr), hex: [...b.data].map((x) => x.toString(16).padStart(2, '0')).join('') })));
    C.table_save({ path, table: { blocks } });
    return { blocks: blocks.length, bytes: blocks.reduce((s, b) => s + b.hex.length / 2, 0) };
  },
  mem_load({ path, relocate }) {
    need();
    fs ??= loadFs();
    const f = fs[path]?.blocks ? fs[path] : err(`file not found: ${path}`);
    const delta = relocate && f.blocks.length ? A(relocate) - parseAddr(f.blocks[0].addr) : 0;
    let blocks = 0, bytes = 0;
    const failed = [];
    for (const b of f.blocks) {
      const data = cleanHex(b.hex), a = parseAddr(b.addr) + delta;
      if (writeMem(a, data)) { blocks++; bytes += data.length; } else failed.push(hx(a));
    }
    return { blocks, bytes, failed };
  },
  mem_fill({ addr, len, pattern }) {
    need();
    const h = String(pattern).replace(/\s+/g, '');
    if (!h || !/^([0-9a-f]{2})+$/i.test(h)) err(`bad hex pattern "${pattern}"`);
    if (!(len > 0 && len <= 1 << 24)) err('len out of range');
    const p = cleanHex(h), b = new Uint8Array(len);
    for (let i = 0; i < len; i++) b[i] = p[i % p.length];
    writeMem(A(addr), b) || err(`cannot access memory at ${addr}`);
    return null;
  },
  mem_copy({ src, dst, len }) {
    need();
    if (!(len >= 0 && len <= 1 << 24)) err('len out of range');
    const b = readMem(A(src), len) || err(`cannot read memory at ${src}`);
    writeMem(A(dst), b) || err(`cannot access memory at ${dst}`);
    return null;
  },
  async snapshot_take({ ranges = [], label = '' }) {
    need();
    const rs = ranges.length ? ranges : P.R.filter((r) => r.prot[0] === 'r' && r.prot[1] === 'w').map((r) => ({ start: r.start, size: r.size }));
    const blocks = await runJob('snapshot', () => grab(rs));
    const s = { id: ++snapSeq, label, blocks, bytes: blocks.reduce((n, b) => n + b.data.length, 0) };
    SNAPS.push(s);
    return { id: s.id, label, blocks: blocks.length, bytes: s.bytes };
  },
  snapshot_list: () => SNAPS.map((s) => ({ id: s.id, label: s.label, blocks: s.blocks.length, bytes: s.bytes })),
  snapshot_delete({ id }) { const i = SNAPS.findIndex((s) => s.id === id); if (i < 0) err(`no snapshot ${id}`); SNAPS.splice(i, 1); return null; },
  snapshot_diff({ id, max = 1000 }) {
    need();
    const s = SNAPS.find((x) => x.id === id) || err(`no snapshot ${id}`);
    return runJob('diff', () => {
      const out = [];
      for (const b of s.blocks) {
        const cur = view(b.addr, b.data.length), n = b.data.length;
        if (!cur) continue;
        for (let i = 0; i < n && out.length < max; i++) {
          if (cur[i] === b.data[i]) continue;
          let j = i + 1;
          while (j < n && j - i < 256 && cur[j] !== b.data[j]) j++;
          out.push({ addr: hx(b.addr + i), len: j - i, old: hexs(b.data.subarray(i, j)), new: hexs(cur.subarray(i, j)) });
          i = j - 1;
        }
      }
      return out.sort((a, b) => parseInt(a.addr, 16) - parseInt(b.addr, 16));
    });
  },
  find_pointers({ query }) {
    need();
    const target = A(query.target), lo = target - (query.max_offset ?? 0x1000), max = query.max_results || 1000;
    return runJob('pointers', () => {
      const out = [];
      for (const r of P.R) {
        if (r.prot[0] !== 'r' || (query.writable_only && r.prot[1] !== 'w')) continue;
        const m = modOf(r.start);
        if (query.static_only && !m) continue;
        for (let i = 0; i + 8 <= r.size && out.length < max; i += 8) {
          const f = r.flat + i, hi = P.dv.getUint32(f + 4, true);
          if (!hi) continue;
          const v = hi * 4294967296 + P.dv.getUint32(f, true);
          if (v < lo || v > target) continue;
          const a = r.start + i;
          out.push({ addr: hx(a), value: hx(v), offset: target - v, module: m ? `"${m.name}"+${hh(a - m.base)}` : null });
        }
      }
      return out;
    });
  },
  module_header({ name }) {
    need();
    const m = P.mods.find((x) => x.name.toLowerCase() === String(name).toLowerCase()) || err(`no such module "${name}"`);
    const pe = /\.(exe|dll)$/i.test(m.name), seen = {};
    const sections = P.R.filter((r) => r.start >= m.base && r.start < m.base + m.size).map((r) => {
      const n = r.prot[2] === 'x' ? '.text' : r.prot[1] === 'w' ? '.data' : '.rodata';
      seen[n] = (seen[n] || 0) + 1;
      return { name: seen[n] > 1 ? `${n}.${seen[n] - 1}` : n, addr: hx(r.start), size: r.size, prot: { r: r.prot[0] === 'r', w: r.prot[1] === 'w', x: r.prot[2] === 'x' } };
    });
    const exe = m === P.mods[0];
    return { format: pe ? 'pe' : 'elf', is_64: true, machine: 'x86-64', kind: exe ? 'executable' : 'shared object', entry: hx(m.base + 0x1100), image_base: hx(m.base),
      sections, imports: exe ? 84 : 12, import_libs: exe ? 6 : 1, exports: exe ? 0 : 2294, source: 'memory' };
  },
  aob_signature({ addr }) {
    need();
    const a = A(addr), m = modOf(a) || err(`${addr} is not inside a module`), v = view(a, 16) || err(`cannot read memory at ${addr}`);
    const pat = [];
    for (let i = 0; i < 16; i++) {
      pat.push(v[i].toString(16).toUpperCase().padStart(2, '0'));
      if (v[i] === 0xe8 || v[i] === 0xe9) for (let k = 0; k < 4 && i + 1 < 16; k++) { i++; pat.push('??'); }
    }
    return { pattern: pat.join(' '), addr: hx(a), module: m.name, module_offset: a - m.base, unique: true, matches: 1, found: [hx(a)] };
  },
  aa_template({ addr, kind }) {
    need();
    const a = A(addr), s = C.aob_signature({ addr }), ins = decode(a) || err(`no valid instruction at ${addr}`), orig = hexs(view(a, ins.len));
    const direct = kind === 'code', at = direct ? `${s.module}+${hh(s.module_offset)}` : 'INJECT';
    return ['[ENABLE]', direct ? '' : `aobscanmodule(INJECT,${s.module},${s.pattern})`, `alloc(newmem,$1000,${at})`, 'label(code)', 'label(return)', '',
      'newmem:', 'code:', `  ${ins.text}`, '  jmp return', '', `${at}:`, '  jmp newmem', ...Array(Math.max(0, ins.len - 5)).fill('  nop'), 'return:',
      ...(direct ? [] : ['registersymbol(INJECT)']), '', '[DISABLE]', `${at}:`, `  db ${orig}`, ...(direct ? [] : ['unregistersymbol(INJECT)']), 'dealloc(newmem)', ''].filter((l, i) => l !== '' || i > 1 || !direct).join('\n');
  },

  code_list: () => (need(), (T.table.codes || []).map((c) => { const s = codeState(c); return { ...c, addr: s.a == null ? null : hx(s.a), state: s.state, current: s.cur }; })),
  code_add({ addr, description }) {
    need();
    const a = A(addr), ins = decode(a) || err(`no valid instruction at ${addr}`), m = modOf(a);
    const c = { description: description || '', address: m ? `"${m.name}"+${hh(a - m.base)}` : hx(a), bytes: hexs(view(a, ins.len)),
      before: hexs(readMem(a - 8, 8) || []), after: hexs(readMem(a + ins.len, 8) || []) };
    let i;
    tEdit((t) => { t.codes ??= []; i = t.codes.push(c) - 1; });
    return i;
  },
  code_remove({ index }) { codeAt(index); tEdit((t) => t.codes.splice(index, 1)); return null; },
  code_nop({ index }) {
    need();
    const c = codeAt(index), s = codeState(c);
    if (s.state === 'unreadable') err(`cannot read memory at ${c.address}`);
    if (s.state === 'changed') err(`bytes at ${hx(s.a)} (${s.cur}) differ from the recorded original; not patching`);
    s.v.fill(0x90);
    return null;
  },
  code_restore({ index, force }) {
    need();
    const c = codeAt(index), s = codeState(c);
    if (s.state === 'unreadable') err(`cannot read memory at ${c.address}`);
    if (s.state === 'changed' && !force) err(`bytes at ${hx(s.a)} (${s.cur}) differ from the recorded original; not patching`);
    s.v.set(s.orig);
    return null;
  },

  debug_set_condition({ id, condition }) { if (typeof condition !== 'string') err('invalid args `condition` for command `debug_set_condition`: expected a string'); const b = dneed().bps.find((x) => x.id === id) || err(`no breakpoint ${id}`); b.condition = checkCond(condition); b.cn = 0; return null; },
  // [code, name, default, current (attached debugger) | null], like hh-debug's signal_table().
  debug_signals: () => [[1, 'SIGHUP', 'pass'], [2, 'SIGINT', 'pass'], [3, 'SIGQUIT', 'pass'], [4, 'SIGILL', 'break'], [5, 'SIGTRAP', 'break'], [6, 'SIGABRT', 'pass'], [7, 'SIGBUS', 'break'],
    [8, 'SIGFPE', 'break'], [10, 'SIGUSR1', 'pass'], [11, 'SIGSEGV', 'break'], [12, 'SIGUSR2', 'pass'], [13, 'SIGPIPE', 'pass'], [14, 'SIGALRM', 'pass'], [15, 'SIGTERM', 'pass'],
    [17, 'SIGCHLD', 'pass'], [28, 'SIGWINCH', 'pass'], [29, 'SIGIO', 'pass']].map(([c, n, a]) => [c, n, a, D ? loadSettings().signals?.[c] ?? a : null]),

  ptr_sort({ key, desc, vtype = '4bytes' }) {
    const ps = ptrNeed();
    if (!['base', 'offset', 'value'].includes(key)) err(`unknown sort key "${key}"`);
    const n = Math.min(ps.count, 20000); // the mock only reorders the first rows
    const rows = Array.from({ length: n }, (_, i) => {
      const p = ptrPath(i);
      const k = key === 'base' ? [p.module, p.base_off] : key === 'offset' ? [p.offsets[p.offsets.length - 1]] : [ptrRow(i, vtype).value];
      return { i, k };
    });
    const cmp = (x, y) => {
      for (let j = 0; j < x.length; j++) {
        const a = x[j], b = y[j];
        if (a == null || b == null) { if (a !== b) return a == null ? 1 : -1; continue; }
        const na = Number(a), nb = Number(b), c = Number.isNaN(na) || Number.isNaN(nb) ? String(a).localeCompare(String(b)) : na - nb;
        if (c) return c;
      }
      return 0;
    };
    rows.sort((x, y) => (desc ? -1 : 1) * cmp(x.k, y.k) || x.i - y.i);
    ps.order = rows.map((r) => r.i);
    return ptrInfo();
  },
};

// ---------- 1.0: saved scans, custom types, remote targets, code/memory/structure helpers ----------
/** Mock only: a custom type behaves like the plain type of its size (no endianness, scale or bits). */
function customVtype(ct) { return ct.float ? (ct.size === 8 ? 'double' : 'float') : { 1: 'byte', 2: '2bytes', 4: '4bytes', 8: '8bytes' }[ct.size] || '4bytes'; }
const withCustom = (q) => (q.custom ? { ...q, vtype: customVtype(q.custom), signed: q.custom.signed } : q);
const PRESET = { scale: 1, offset: 0, bit_start: 0, bit_len: 0, binary: false, signed: false };
const PRESETS = [
  { name: '2 Byte Big Endian', size: 2, big_endian: true, float: false, ...PRESET },
  { name: '4 Byte Big Endian', size: 4, big_endian: true, float: false, ...PRESET },
  { name: 'Float Big Endian', size: 4, big_endian: true, float: true, ...PRESET },
];
let REMOTE = null, LOST = null;
const REMOTE_PROCS = [[811, 'sshd', '/usr/sbin/sshd'], [1402, 'gamesrv', '/srv/game/gamesrv'], [1890, 'Game.exe', 'C:\\Games\\Demo\\Game.exe'], [2004, 'hh-server', '/usr/local/bin/heaphook-server']];
const remoteSaved = () => { try { return JSON.parse(localStorage.getItem('hh.mockremote')) || {}; } catch { return {}; } };
const localOnly = (f, what) => (args) => (P?.remote ? err(`${what} works on local processes only (the target is remote)`) : f(args));
function funcAt(a) {
  if (DIS) { const f = DIS.funcs.filter((x) => x.addr <= a).at(-1); if (f && a - f.addr < 0x400) return { start: f.addr, name: f.name, source: 'dissection' }; }
  for (let s = a, i = 0; i < 0x200; i++, s--) { const v = view(s, 1); if (v && v[0] === 0x55) return { start: s, name: symbolize(s), source: 'heuristic' }; }
  return { start: a, name: symbolize(a), source: 'heuristic' };
}
const NEW = {
  scan_save({ name }) {
    if (!S) err('no scan to save');
    name = String(name || '').trim();
    if (!name) err('the name is empty');
    if (name === 'first') err('"first" is reserved for the first scan');
    const r = S.results.slice();
    const has = (f) => { let lo = 0, hi = r.length; while (lo < hi) { const m = (lo + hi) >> 1; if (r[m] < f) lo = m + 1; else hi = m; } return r[lo] === f; };
    S.saved.set(name, { mem: P.mem.slice(), set: { has }, count: r.length });
    return null;
  },
  scan_saved: () => (S ? [...S.saved].map(([name, v]) => ({ name, count: v.count, kept: Math.min(v.count, 200000) })) : []),
  scan_delete_saved({ name }) { if (!S?.saved.delete(name)) err(`no saved scan named "${name}"`); return null; },
  scan_pause() { if (prog.running) prog.paused = true; return null; },
  scan_resume() { prog.paused = false; return null; },
  custom_presets: () => PRESETS,
  custom_validate({ custom: c }) {
    if (!c || !(c.size >= 1 && c.size <= 8)) return 'size must be 1 to 8 bytes';
    if (c.float && c.size !== 4 && c.size !== 8) return 'a float type must be 4 or 8 bytes';
    if (!Number.isFinite(c.scale) || c.scale === 0) return 'scale must be a number other than 0';
    if (!Number.isFinite(c.offset)) return 'offset must be a number';
    if (c.bit_start < 0 || c.bit_len < 0 || c.bit_start + c.bit_len > c.size * 8) return `bits ${c.bit_start}..${c.bit_start + c.bit_len} do not fit in ${c.size} byte(s)`;
    if (c.float && (c.bit_len || c.binary)) return 'a float type cannot use bit fields or binary display';
    return null;
  },
  read_values: ({ reqs }) => C_read_values({ reqs: reqs.map(withCustom) }),
  write_value: (a) => C_write_value(withCustom(a)),
  set_frozen: ({ entries }) => C_set_frozen({ entries: entries.map(withCustom) }),
  resolve_many: ({ exprs }) => exprs.map((e) => { try { return P ? hx(resolveExpr(e)) : null; } catch { return null; } }),

  remote_saved: () => { const r = remoteSaved(); return { addr: r.addr || '', has_token: !!r.token }; },
  remote_forget() { try { localStorage.removeItem('hh.mockremote'); } catch { /* storage blocked */ } return null; },
  async remote_connect({ addr, token, remember }) {
    await sleep(400);
    if (!/^[\w.-]+:\d+$/.test(addr || '')) err(`invalid server address "${addr}" (host:port)`);
    const tok = token || remoteSaved().token || err('no token given and none is remembered');
    if (tok === 'wrong') err('authentication failed: the server rejected the token');
    if (addr.startsWith('down')) err(`could not connect to ${addr}: Connection refused (os error 111)`);
    REMOTE = { addr };
    try { localStorage.setItem('hh.mockremote', JSON.stringify({ addr, ...(remember ? { token: tok } : {}) })); } catch { /* storage blocked */ }
    return { addr };
  },
  remote_status: () => (REMOTE ? { addr: REMOTE.addr, connected: true } : null),
  remote_processes: () => (REMOTE || err('not connected to a server'), REMOTE_PROCS.map(([pid, name, exe]) => ({ pid, name, exe }))),
  remote_open({ pid }) {
    if (!REMOTE) err('not connected to a server');
    const pr = REMOTE_PROCS.find((p) => p[0] === pid) || err(`no process with pid ${pid} on ${REMOTE.addr}`);
    const r = C.open_process({ pid: pid + 1000 }, pr);
    P.remote = REMOTE.addr; LOST = null;
    return { ...r, pid, remote: REMOTE.addr };
  },
  remote_disconnect() { if (P?.remote) TOOLS.close_process(); REMOTE = null; return null; },
  lua_poll: (a) => {
    const r = C_lua_poll(a);
    if (r.process && P?.remote) Object.assign(r.process, { pid: P.pid, remote: P.remote }, LOST ? { alive: false, lost: LOST } : {});
    return r;
  },
  debug_attach: localOnly(DBG.debug_attach, 'The debugger'),
  module_header: localOnly(TOOLS.module_header, 'Reading module headers'),
  speed_set: localOnly(TOOLS.speed_set, 'The speedhack'),

  code_function({ addr }) { need(); const f = funcAt(A(addr)); return { ...f, start: hx(f.start) }; },
  code_targets({ addr }) {
    need();
    const f = funcAt(A(addr)), rows = [];
    let a = f.start;
    for (let i = 0; i < 400; i++) {
      const d = decode(a);
      if (!d) break;
      if (d.target != null) rows.push({ from: hx(a), to: hx(d.target), kind: d.text.startsWith('call') ? 'call' : d.text.startsWith('jmp') ? 'jump' : 'cond_jump', text: d.text, name: symbolize(d.target) || null });
      a += d.len;
      if (d.text === 'ret') break;
    }
    return { start: hx(f.start), end: hx(a), source: f.source, rows };
  },
  mem_compare({ path, max = 10000 }) {
    need();
    fs ??= loadFs();
    const file = fs[path]?.blocks ? fs[path] : err(`file not found: ${path}`), out = [];
    for (const b of file.blocks) {
      const old = cleanHex(b.hex), a0 = parseAddr(b.addr), cur = readMem(a0, old.length);
      for (let i = 0; i < old.length && out.length < max; i++) {
        if (cur && cur[i] === old[i]) continue;
        let j = i + 1;
        while (j < old.length && j - i < 256 && !(cur && cur[j] === old[j])) j++;
        out.push({ addr: hx(a0 + i), len: j - i, old: hexs(old.subarray(i, j)), new: cur ? hexs(cur.subarray(i, j)) : '' });
        i = j - 1;
      }
    }
    return out;
  },
  struct_export({ path, names = [] }) {
    const list = structs().filter((x) => !names.length || names.includes(x.name));
    if (!list.length) err('no structures to export');
    return C.table_save({ path, table: { structures: list } });
  },
  struct_import({ path }) {
    fs ??= loadFs();
    const list = fs[path]?.structures || err(`no structures in ${path}`);
    tEdit((t) => list.forEach((x) => putStruct(t, clone(x))));
    return list.map((x) => x.name);
  },
  app_info: () => ({ version: '1.0.0-rc.1 (mock)', license: 'Apache-2.0', remote_ok: true, platform: 'linux-x86_64', lua_allow_os: loadSettings().lua_allow_os !== false }),
};
const C_read_values = C.read_values, C_write_value = C.write_value, C_set_frozen = C.set_frozen;
let C_lua_poll = null;
// Mock-only switch for trying the "connection lost" path from the console: __hhMock.dropRemote()
globalThis.__hhMock = { dropRemote(why = 'connection reset by peer') { if (P?.remote) { LOST = why; REMOTE = null; } } };

Object.assign(C, DBG, PTR, LIVE, TOOLS);
C_lua_poll = C.lua_poll;
Object.assign(C, NEW);

// ---------- 1.0: search, memory, pause, per-entry trust, files ----------
const TAINT = new Set(); // Lua script texts from untrusted sources (files, other tables)
let PAUSED = false, SAVED = null;
const plainJson = (t) => JSON.stringify(t, (k, v) => (k === 'frozen' ? undefined : v));
const untrusted = () => (T.untrusted ||= []);
function parsePattern(p) {
  const out = [];
  for (const tok of String(p).trim().split(/\s+/)) {
    if (/^\?+$/.test(tok)) { for (let i = 0; i < Math.ceil(tok.length / 2); i++) out.push(null); continue; }
    const t = tok.replace(/^0x/i, '');
    if (t.length % 2 || !/^([0-9a-f]{2}|\?\?)+$/i.test(t)) err(`bad byte "${tok}" in the pattern`);
    for (let i = 0; i < t.length; i += 2) out.push(t.slice(i, i + 2) === '??' ? null : parseInt(t.slice(i, i + 2), 16));
  }
  if (!out.some((b) => b != null)) err('the pattern needs at least one byte that is not ??');
  return out;
}
/** New ids for pasted / merged entries; the ones that run Lua wait for their own consent. */
function insertForeign(entries, after) {
  let max = 0;
  liveWalk(T.table.entries, (e) => { max = Math.max(max, e.id); });
  const reid = (e) => ({ ...clone(e), id: ++max, frozen: false, ct_extra: [], children: (e.children || []).map(reid) });
  const items = entries.map(reid);
  pushUndo(clone(T.table));
  const list = (() => { let r = null; liveWalk(T.table.entries, (e, p) => { if (e.id === after) r = p ? p.children : T.table.entries; }); return r; })();
  if (list) list.splice(list.findIndex((e) => e.id === after) + 1, 0, ...items); else T.table.entries.push(...items);
  liveWalk(items, (e) => { if (/\{\$lua\}/i.test(e.script || '')) { untrusted().push(e.id); TAINT.add(e.script); } });
  T.version++;
  return items.map((e) => e.id);
}
const RC = {
  mem_search({ req }) {
    need();
    const pat = parsePattern(req.pattern), start = parseAddr(req.start), lim = Math.min(req.limit || 1, 1000);
    const end = req.end ? parseAddr(req.end) : null, hits = [];
    const R = P.R.filter((r) => r.prot[0] === 'r');
    for (const r of req.backward ? [...R].reverse() : R) {
      const lo = Math.max(r.start, req.backward ? end ?? 0 : start), hi = Math.min(r.start + r.size, req.backward ? start : end ?? Infinity);
      if (lo >= hi) continue;
      const v = view(lo, hi - lo);
      if (!v) continue;
      const found = [];
      for (let i = 0; i + pat.length <= v.length; i++) if (pat.every((b, k) => b == null || v[i + k] === b)) found.push(lo + i);
      for (const a of req.backward ? found.reverse() : found) { hits.push(hx(a)); if (hits.length >= lim) return hits; }
    }
    return hits;
  },
  disasm_search({ req }) {
    need();
    const needle = String(req.text || '').trim().toLowerCase();
    if (!needle) err('nothing to search for');
    const start = parseAddr(req.start), end = parseAddr(req.end), lim = Math.min(req.limit || 100, 1000), hits = [];
    if (end <= start) err('the range is empty');
    if (end - start > 64 * 1024 * 1024) err('the range is larger than 64 MiB; search a module or a smaller range');
    for (let a = start, n = 0; a < end && n < 400000; n++) {
      const d = decode(a);
      if (!d) { a = Math.floor(a / 4096) * 4096 + 4096; continue; }
      if (d.text.toLowerCase().includes(needle)) { hits.push({ addr: hx(a), text: d.text }); if (hits.length >= lim) break; }
      a += d.len || 1;
    }
    return hits;
  },
  mem_alloc({ size }) { need(); if (!(size > 0)) err('size must be between 1 byte and 4 GiB'); const h = P.R.find((r) => r.path === '[heap]'); return hx(h.start + h.size - Math.ceil(size / 4096) * 4096); },
  mem_free() { need(); return null; },
  process_pause({ pause }) { need(); if (pause && D) err('the debugger is attached: use Break (Shift F9) and Continue (F9) instead'); PAUSED = !!pause; return null; },
  trace_save({ path, trace }) { return C.table_save({ path, table: { heaphook_trace: 1, trace } }); },
  trace_load({ path }) { fs ??= loadFs(); const f = fs[path] ?? err(`file not found: ${path}`); if (f.heaphook_trace !== 1) err(`${path}: not a HeapHook trace file`); return f.trace; },
  table_export_text({ path }) {
    const lines = ['Description\tAddress\tType\tValue'];
    const go = (list, d) => list.forEach((e) => { lines.push(['  '.repeat(d) + e.description, e.script ? '' : e.addr, e.script ? 'script' : liveGroup(e) ? 'group' : e.vtype].join('\t')); go(e.children || [], d + 1); });
    go(T.table.entries, 0);
    return C.table_save({ path, table: lines.join('\n') + '\n' });
  },
  table_merge({ path }) {
    fs ??= loadFs();
    const t = fs[path] ?? err(`file not found: ${path}`);
    insertForeign(Array.isArray(t) ? t : t.entries || [], null);
    if (!T.table.lua_script?.trim() && t.lua_script?.trim()) T = { ...T, table: { ...T.table, lua_script: t.lua_script }, trust: 'ask' };
    return T;
  },
  table_paste({ entries, after, base }) {
    if (base != null && base !== T.version) err(`stale table version ${base} (current ${T.version})`);
    return { ids: insertForeign(entries, after ?? null), version: T.version };
  },
  table_trust_entries({ ids }) {
    if (loadSettings().table_script === 'never') err('Settings say never to run a table\'s Lua: change "Lua script in a loaded table" first');
    const sub = new Set();
    for (const id of ids) { const e = liveFind(id); if (e) liveWalk([e], (x) => sub.add(x.id)); }
    T.untrusted = untrusted().filter((id) => !sub.has(id));
    T.version++;
    return null;
  },
  table_dirty: () => SAVED == null ? T.table.entries.length > 0 || !!T.table.lua_script : plainJson(T.table) !== SAVED,
  table_open_data({ name, data }) {
    if (/\.ct$/i.test(name)) err('Cheat Engine .CT import needs the real backend');
    let t;
    try { t = JSON.parse(data); } catch (e) { err(`${name}: not a table: ${e.message}`); }
    C.table_save({ path: '\u0000drop', table: t });
    return RC.table_open({ path: '\u0000drop' });
  },
  table_open(a) { const r = LIVE_open(a); T.untrusted = []; liveWalk(T.table.entries, (e) => { if (e.script) TAINT.add(e.script); }); SAVED = plainJson(T.table); return r; },
  table_export(a) { const r = C_export(a); SAVED = plainJson(T.table); return r; },
  table_set_active(a) {
    if (a.active) for (const id of a.ids) {
      const e = liveFind(id);
      if (!e) continue;
      let bad = null;
      liveWalk([e], (x) => { if (!bad && untrusted().includes(x.id)) bad = x; });
      if (bad) err(loadSettings().table_script === 'never' ? `${bad.description}: not run: it runs Lua from another table and Settings say never to run a table's Lua`
        : `needs consent: entries: ${bad.description}: this entry came from another table (pasted, merged or dropped in) and runs Lua code, which can use your files and the process`);
    }
    return LIVE_active(a);
  },
  aa_load_file({ path }) { fs ??= loadFs(); const t = fs[path] ?? err(`file not found: ${path}`); const s = typeof t === 'string' ? t : t.script ?? err(`${path}: not a script`); if (/\{\$lua\}/i.test(s)) TAINT.add(s); return s; },
  aa_trust({ script }) { if (loadSettings().table_script === 'never') err('Settings say never to run a table\'s Lua: change "Lua script in a loaded table" first'); TAINT.delete(script); return null; },
  aa_execute(a) { if (/\{\$lua\}/i.test(a.script) && TAINT.has(a.script)) err('needs consent: this script: this table runs Lua code, which can use your files and the process'); return C_aa(a); },
  app_args: () => null,
  app_quit: () => null,
  debug_set_register(a) {
    const m = /^(st|xmm)(\d+)$|^(mxcsr|fcw|fsw)$/.exec(a.name);
    if (!m) return C_setreg(a);
    const d = dneed();
    if (d.state !== 'broken') err(`thread ${a.tid} is running`);
    const f = d.ctx.fpu;
    if (m[1] === 'st') { const v = Number(a.value); if (!Number.isFinite(v) || +m[2] > 7) err(`${a.name}: "${a.value}" is not a number`); f.st[+m[2]] = { hex: f.st[+m[2]].hex, value: String(v) }; }
    else if (m[1] === 'xmm') { const h = String(a.value).replace(/\s+/g, ''); if (!/^[0-9a-f]{32}$/i.test(h) || +m[2] > 15) err(`${a.name}: give 32 hex digits`); f.xmm[+m[2]] = h.toLowerCase(); }
    else f[m[3]] = parseAddr(a.value).toString(16).toUpperCase().padStart(m[3] === 'mxcsr' ? 8 : 4, '0');
    return null;
  },
  debug_add_breakpoint(a) { const id = C_addbp(a); const b = D.bps.find((x) => x.id === id); if (b && a.req.action === 'trace' && a.req.stop_when?.trim()) b.stop_when = checkCond(a.req.stop_when); return id; },
  debug_breakpoints() { return C_bps().map((r) => ({ ...r, ...(D.bps.find((b) => b.id === r.id)?.stop_when ? { stop_when: D.bps.find((b) => b.id === r.id).stop_when } : {}) })); },
  lua_poll(a) {
    const r = C_poll(a);
    if (r.process) r.process.paused = PAUSED;
    r.window = { close_seq: 0, drop_seq: 0, drops: [] };
    return r;
  },
};
const LIVE_open = C.table_open, C_export = C.table_export, LIVE_active = C.table_set_active, C_aa = C.aa_execute, C_setreg = C.debug_set_register;
const C_addbp = C.debug_add_breakpoint, C_bps = C.debug_breakpoints, C_poll = C.lua_poll;
Object.assign(C, RC);
// The table's get carries the untrusted list too.
const C_get = C.table_get;
C.table_get = () => ({ ...C_get(), untrusted: untrusted() });

function loadFs() { try { return JSON.parse(localStorage.getItem('hh.mockfs')) || {}; } catch { return {}; } }

/** invoke() look-alike: async, rejects with a string, returns JSON-cloned data. */
export async function mockInvoke(cmd, args = {}) {
  const f = C[cmd];
  if (!f) throw `unknown command '${cmd}'`;
  try {
    const r = await f(args);
    return r === undefined ? null : JSON.parse(JSON.stringify(r));
  } catch (e) {
    throw typeof e === 'string' ? e : String(e?.message || e);
  }
}
