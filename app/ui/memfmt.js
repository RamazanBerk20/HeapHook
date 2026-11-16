// Memory viewer helpers with no DOM: search patterns, value encoding, the data inspector's
// conversions, branch / operand targets and AOB wildcards. Plain functions, testable in node.

export const TYPE_SIZE = { byte: 1, '2bytes': 2, '4bytes': 4, '8bytes': 8, float: 4, double: 8 };

/** Bytes (Uint8Array) -> "48 8B 05". */
export const toHex = (u8) => [...u8].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');

/** "48 8b ?? 05", "488B??05", "48 8B ? 05" -> "48 8B ?? 05"; throws on anything else. */
export function parsePattern(s) {
  const t = String(s).trim().replace(/\s+/g, ' ');
  const parts = t.includes(' ') ? t.split(' ') : t.match(/\?\?|\?|[0-9a-f]{1,2}/gi) || [];
  if (!parts.length || parts.join('') !== t.replace(/ /g, '')) throw new Error('A byte pattern is hex bytes separated by spaces, ?? for any byte (48 8B ?? 05)');
  const out = parts.map((p) => {
    if (p === '?' || p === '??') return '??';
    if (!/^[0-9a-f]{1,2}$/i.test(p)) throw new Error(`"${p}" is not a hex byte or ??`);
    return p.toUpperCase().padStart(2, '0');
  });
  if (out.every((p) => p === '??')) throw new Error('The pattern needs at least one known byte');
  return out.join(' ');
}

/** Text -> bytes in UTF-8 or UTF-16LE. */
export function textBytes(s, enc) {
  if (!s) throw new Error('Nothing to search for');
  if (enc === 'utf8') return new TextEncoder().encode(s);
  const u = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); u[2 * i] = c & 255; u[2 * i + 1] = c >> 8; }
  return u;
}

/** A typed value (decimal, or 0x hex for integers) -> its little-endian bytes. */
export function valueBytes(type, s) {
  const t = String(s).trim();
  if (!t) throw new Error('Type a value');
  const n = TYPE_SIZE[type], dv = new DataView(new ArrayBuffer(n));
  if (type === 'float' || type === 'double') {
    const f = Number(t);
    if (!Number.isFinite(f)) throw new Error(`"${t}" is not a number`);
    type === 'float' ? dv.setFloat32(0, f, true) : dv.setFloat64(0, f, true);
  } else {
    let v;
    try { v = BigInt(/^-/.test(t) ? '-' + t.slice(1).trim() : t); } catch { throw new Error(`"${t}" is not an integer`); }
    const bits = BigInt(n * 8);
    if (v < -(1n << (bits - 1n)) || v >= 1n << bits) throw new Error(`${t} does not fit in ${n} byte${n > 1 ? 's' : ''}`);
    v = BigInt.asUintN(n * 8, v);
    for (let i = 0; i < n; i++) dv.setUint8(i, Number((v >> BigInt(8 * i)) & 255n));
  }
  return new Uint8Array(dv.buffer);
}

/** One hex view cell (type != byte) from its bytes, as memview shows it. */
export function cellValue(type, u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.length);
  switch (type) {
    case '2bytes': return String(dv.getUint16(0, true));
    case '4bytes': return String(dv.getUint32(0, true));
    case '8bytes': return String(dv.getBigUint64(0, true));
    case 'float': return String(+dv.getFloat32(0, true).toPrecision(7));
    case 'double': return String(+dv.getFloat64(0, true).toPrecision(12));
  }
  return toHex(u8.subarray(0, 1));
}

const printable = (c) => (c >= 0x20 && c < 0x7f) || c > 0x9f;
/** Data inspector rows for the bytes at the cursor (an array of numbers, -1 = unreadable): [label, little-endian, big-endian | null]. */
export function convRows(u8) {
  const have = (n) => u8 && u8.length >= n && !u8.slice(0, n).includes(-1);
  const dv = u8 ? new DataView(Uint8Array.from(u8, (b) => b & 255).buffer) : null;
  const both = (n, f) => (have(n) ? [f(true), f(false)] : ['—', '—']);
  const fl = (x) => (Number.isFinite(x) ? String(+x.toPrecision(x === Math.fround(x) ? 7 : 15)) : String(x));
  const rows = [
    ['u8', have(1) ? String(dv.getUint8(0)) : '—', null],
    ['i8', have(1) ? String(dv.getInt8(0)) : '—', null],
    ['u16', ...both(2, (le) => String(dv.getUint16(0, le)))],
    ['i16', ...both(2, (le) => String(dv.getInt16(0, le)))],
    ['u32', ...both(4, (le) => String(dv.getUint32(0, le)))],
    ['i32', ...both(4, (le) => String(dv.getInt32(0, le)))],
    ['u64', ...both(8, (le) => String(dv.getBigUint64(0, le)))],
    ['i64', ...both(8, (le) => String(dv.getBigInt64(0, le)))],
    ['float', ...both(4, (le) => fl(dv.getFloat32(0, le)))],
    ['double', ...both(8, (le) => String(dv.getFloat64(0, le)))],
    ['hex', have(8) ? '0x' + dv.getBigUint64(0, true).toString(16).toUpperCase() : '—', have(8) ? '0x' + dv.getBigUint64(0, false).toString(16).toUpperCase() : '—'],
    ['bin8', have(1) ? dv.getUint8(0).toString(2).padStart(8, '0') : '—', null],
    ['bin16', ...both(2, (le) => dv.getUint16(0, le).toString(2).padStart(16, '0').replace(/(.{8})/, '$1 '))],
  ];
  let c8 = '—', c16 = '—';
  if (have(1)) {
    const bad = u8.indexOf(-1), n = Math.min(4, bad < 0 ? u8.length : bad);
    const t = new TextDecoder('utf-8').decode(Uint8Array.from(u8.slice(0, n)));
    const cp = t.codePointAt(0);
    c8 = cp === 0xfffd ? 'invalid' : printable(cp) ? `'${String.fromCodePoint(cp)}' U+${cp.toString(16).toUpperCase().padStart(4, '0')}` : `U+${cp.toString(16).toUpperCase().padStart(4, '0')} (control)`;
  }
  if (have(2)) {
    const cp = dv.getUint16(0, true);
    c16 = cp >= 0xd800 && cp < 0xe000 ? `surrogate U+${cp.toString(16).toUpperCase()}` : printable(cp) ? `'${String.fromCharCode(cp)}' U+${cp.toString(16).toUpperCase().padStart(4, '0')}` : `U+${cp.toString(16).toUpperCase().padStart(4, '0')} (control)`;
  }
  rows.push(['UTF-8', c8, null], ['UTF-16', c16, null]);
  return rows;
}

// ---------- instructions ----------
const BRANCH = /^(j[a-z]+|call|loop[a-z]*|jrcxz|jecxz)\b/i;
/** Unconditional transfer (jmp / call) versus conditional (jcc / loop). */
export const isUncond = (text) => /^(jmp|call)\b/i.test(text);
/** Direct branch target of an instruction ("je 7FF61000", "call game.exe+10 (7FF6...)") as BigInt, or null. */
export function branchTarget(text) {
  if (!BRANCH.test(text) || /\[/.test(text)) return null;
  const m = text.match(/\b(?:0x)?([0-9a-f]{4,16})\b/i);
  return m ? BigInt('0x' + m[1]) : null;
}
/** Static address of a memory operand: [HEX] (absolute; the disassembler prints rip-relative this way) or [rip+HEX]. */
export function memTarget(row) {
  const m = row.text.match(/\[([^\]]+)\]/);
  if (!m) return null;
  const inner = m[1].replace(/\s+/g, '');
  if (/^(?:0x)?[0-9a-f]{5,16}$/i.test(inner)) return BigInt('0x' + inner.replace(/^0x/i, ''));
  const r = inner.match(/^rip([+-])(?:0x)?([0-9a-f]+)$/i);
  if (!r) return null;
  const next = BigInt(row.addr) + BigInt(row.bytes.split(' ').length), d = BigInt('0x' + r[2]);
  return r[1] === '+' ? next + d : next - d;
}
/** Size keyword of a memory operand in bytes (4 when the text does not say). */
export const memSize = (text) => ({ byte: 1, word: 2, dword: 4, qword: 8 })[(text.match(/\b(byte|word|dword|qword)\b/i) || [])[1]?.toLowerCase()] || 4;

/**
 * AOB pattern for one instruction: the rel32 of a branch / call and the disp32 of a
 * rip-relative operand become ??. The 4 bytes are found by recomputing them (target minus the
 * next instruction's address); when that fails, the last 4 bytes are wildcarded.
 */
export function aobOf(row, is64 = true) {
  const b = row.bytes.split(' ');
  if (b.includes('??')) return b.join(' ');
  const tgt = branchTarget(row.text) ?? (is64 ? memTarget(row) : null);
  if (tgt == null || b.length < 5) return b.join(' ');
  const next = BigInt(row.addr) + BigInt(b.length), rel = BigInt.asUintN(32, tgt - next);
  const want = [0, 1, 2, 3].map((i) => Number((rel >> BigInt(8 * i)) & 255n).toString(16).toUpperCase().padStart(2, '0'));
  let at = -1;
  for (let i = 1; i + 4 <= b.length; i++) if (want.every((w, k) => b[i + k].toUpperCase() === w)) at = i;
  if (at < 0) at = b.length - 4;
  return b.map((x, i) => (i >= at && i < at + 4 ? '??' : x.toUpperCase())).join(' ');
}

/** A C string at the start of `b` (numbers, -1 unreadable): {text, wide} when 4+ printable ASCII characters (or UTF-16 code units) end in a 0 or the buffer. */
export function stringAt(b) {
  const ok = (c) => c >= 0x20 && c < 0x7f;
  let n = 0;
  while (n < b.length && ok(b[n])) n++;
  if (n >= 4 && (n === b.length || b[n] === 0)) return { text: String.fromCharCode(...b.slice(0, n)), wide: false };
  let w = 0;
  while (2 * w + 1 < b.length && ok(b[2 * w]) && b[2 * w + 1] === 0) w++;
  if (w >= 4 && (2 * w + 1 >= b.length || (b[2 * w] === 0 && b[2 * w + 1] === 0))) return { text: String.fromCharCode(...b.filter((_, i) => i % 2 === 0).slice(0, w)), wide: true };
  return null;
}

/** "48 8B 05", "488b05", "0x48, 0x8B" -> bytes; throws when it is not whole hex bytes. */
export function hexBytes(s) {
  const t = String(s).replace(/0x/gi, '').replace(/[\s,]/g, '');
  if (!t || t.length % 2 || !/^[0-9a-f]+$/i.test(t)) throw new Error('Not hex bytes (an even number of hex digits)');
  return Uint8Array.from(t.match(/../g), (x) => parseInt(x, 16));
}
