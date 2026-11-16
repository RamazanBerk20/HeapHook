// Calculator / converter: an integer (or float) expression shown in every base and as the
// bit patterns of the value types. Integers are 64-bit BigInt (two's complement); a float
// literal anywhere makes the expression a double.
import { h, store } from './util.js';

const TOK = /\s*(0x[0-9a-f]+|0b[01]+|0o[0-7]+|\d+\.\d*(?:e[+-]?\d+)?|\.\d+(?:e[+-]?\d+)?|\d+e[+-]?\d+|[0-9a-f]+h\b|\d+|<<|>>|[-+*/%&|^~()])/iy;

/** Parses and evaluates `src`; returns a BigInt or a Number (float mode); throws a message. */
export function evaluate(src) {
  const toks = [];
  TOK.lastIndex = 0;
  let pos = 0;
  const text = src.trim();
  while (pos < text.length) {
    TOK.lastIndex = pos;
    const m = TOK.exec(text);
    if (!m) throw `unexpected "${text.slice(pos, pos + 8)}"`;
    toks.push(m[1]);
    pos = TOK.lastIndex;
  }
  if (!toks.length) throw 'empty';
  const float = toks.some((t) => /^(\d+\.|\.\d|\d+e)/i.test(t));
  const lit = (t) => {
    if (/h$/i.test(t) && !/^\d+$/.test(t)) t = '0x' + t.slice(0, -1); // CE style 1Ah
    if (float) return /^0[xbo]/i.test(t) ? Number(BigInt(t)) : Number(t);
    return BigInt(t);
  };
  let i = 0;
  const peek = () => toks[i], take = () => toks[i++];
  const zero = float ? 0 : 0n;
  const bin = (a, op, b) => {
    if (float && '&|^<<>>%'.includes(op) && op !== '%') throw `"${op}" needs integers`;
    switch (op) {
      case '+': return a + b; case '-': return a - b; case '*': return a * b;
      case '/': if (b === zero) throw 'division by zero'; return a / b;
      case '%': if (b === zero) throw 'division by zero'; return a % b;
      case '&': return a & b; case '|': return a | b; case '^': return a ^ b;
      case '<<': return BigInt.asIntN(64, a << b); case '>>': return a >> b;
    }
    throw `unknown operator ${op}`;
  };
  const LEVELS = [['|'], ['^'], ['&'], ['<<', '>>'], ['+', '-'], ['*', '/', '%']];
  const level = (n) => {
    if (n === LEVELS.length) return unary();
    let a = level(n + 1);
    while (LEVELS[n].includes(peek())) { const op = take(); a = bin(a, op, level(n + 1)); }
    return a;
  };
  const unary = () => {
    const t = take();
    if (t === '-') return -unary();
    if (t === '+') return unary();
    if (t === '~') { if (float) throw '"~" needs integers'; return ~unary(); }
    if (t === '(') { const v = level(0); if (take() !== ')') throw 'missing )'; return v; }
    if (t == null || /^[-+*/%&|^)<>]/.test(t)) throw t == null ? 'unexpected end' : `unexpected "${t}"`;
    return lit(t);
  };
  const v = level(0);
  if (i < toks.length) throw `unexpected "${toks[i]}"`;
  return float ? v : BigInt.asIntN(64, v);
}

const hex = (n, bits) => BigInt.asUintN(bits, n).toString(16).toUpperCase().padStart(bits / 4, '0');

/** Rows of [label, text] for a value. */
export function conversions(v) {
  const dv = new DataView(new ArrayBuffer(8));
  if (typeof v === 'number') {
    dv.setFloat64(0, v);
    const d = dv.getBigUint64(0);
    dv.setFloat32(0, v);
    const f = dv.getUint32(0);
    return [['Value', String(v)], ['Double bits', hex(d, 64)], ['Float bits', f.toString(16).toUpperCase().padStart(8, '0') + (Math.fround(v) === v ? '' : `  (rounds to ${Math.fround(v)})`)],
      ['Truncated', Number.isFinite(v) ? String(BigInt(Math.trunc(v))) : '–']];
  }
  const u = BigInt.asUintN(64, v);
  dv.setBigUint64(0, u);
  const asF32 = new DataView(new Uint32Array([Number(BigInt.asUintN(32, v))]).buffer).getFloat32(0, true);
  return [
    ['Decimal', v.toString()], ['Unsigned 64', u.toString()], ['Hex 64', hex(v, 64)], ['Hex 32', hex(v, 32)],
    ['Signed 32', String(BigInt.asIntN(32, v))], ['Signed 16', String(BigInt.asIntN(16, v))], ['Signed 8', String(BigInt.asIntN(8, v))],
    ['Octal', u.toString(8)], ['Binary', u.toString(2).replace(/(.{4})(?=.)/g, '$1 ')],
    ['Bits as float', String(+asF32.toPrecision(9))], ['Bits as double', String(dv.getFloat64(0))],
    ['Bytes (little end.)', [...new Uint8Array(dv.buffer)].reverse().map((b) => b.toString(16).padStart(2, '0')).join(' ').toUpperCase()],
  ];
}

let dlg = null;
/** Non-blocking dialog; Esc closes, Enter keeps the result in the field for the next step. */
export function openCalculator() {
  if (dlg?.open) { dlg.querySelector('input').focus(); return; }
  const input = h('input.mono', { type: 'text', value: store.get('calc.expr', ''), spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Expression', placeholder: '0x1A2B + 100 * 4, 1.5, -1, 1 << 12' });
  const out = h('dl.calc-out', { 'aria-live': 'polite' });
  const err = h('p.hint.err', { role: 'status' });
  let last = null;
  const run = () => {
    store.set('calc.expr', input.value);
    err.textContent = '';
    if (!input.value.trim()) { out.replaceChildren(); last = null; return; }
    try { last = evaluate(input.value); } catch (e) { err.textContent = String(e); return; }
    out.replaceChildren(...conversions(last).flatMap(([k, v]) => [h('dt', null, k), h('dd.mono', null, h('span', null, v),
      h('button.btn.ghost.calc-copy', { type: 'button', 'aria-label': `Copy ${k}`, title: 'Copy', onclick: () => navigator.clipboard?.writeText(v.replace(/ \s*\(.*$/, '')).catch(() => {}) }, 'Copy'))]));
  };
  input.addEventListener('input', run);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); if (last != null) { input.value = String(last); run(); } } });
  dlg = h('dialog.dlg.dlg-sm.calc', { 'aria-labelledby': 'calc-title' }, h('form', { method: 'dialog' },
    h('h2#calc-title', null, 'Calculator'),
    h('p.hint', null, 'Integers are 64-bit (0x hex, 0b binary, 1Ah); a decimal point makes it a double. + - * / % & | ^ ~ << >> and parentheses.'),
    h('label.field', null, h('span', null, 'Expression'), input), err, out,
    h('div.dlg-actions', null, h('button.btn.primary', { value: 'ok' }, 'Close ', h('kbd', null, 'Esc')))));
  document.body.append(dlg);
  dlg.addEventListener('close', () => { dlg.remove(); dlg = null; });
  dlg.showModal();
  input.select();
  run();
}

// Self-check in development: a few values that must hold.
if (globalThis.location?.search.includes('selftest')) {
  console.assert(evaluate('0x10 + 2 * 3') === 22n && evaluate('-1') === -1n && evaluate('1 << 4 | 1') === 17n && evaluate('1Ah') === 26n, 'calc ints');
  console.assert(evaluate('1.5 * 2') === 3 && conversions(1.5)[1][1] === '3FF8000000000000', 'calc floats');
}
