// Script editor over a plain <textarea>: highlighted mirror, find / replace, own undo history,
// auto-indent, completion, error line. Plus the standalone Auto Assemble window.
// The textarea stays the real input; the mirror behind it only paints (aria-hidden, no events).
import { h, icon, modal, codeView, helpAdd, excerpt, fmtAddr } from './util.js';
import { api, askPath } from './backend.js';
import { state } from './core.js';

// ---------- word lists ----------
const AA_DIR = ('alloc allocnx allocxo globalalloc kalloc sharedallocate dealloc label registersymbol unregistersymbol define undefine '
  + 'include luacall aobscan aobscanmodule aobscanregion assert fullaccess createthread loadlibrary loadbinary readmem reassemble '
  + 'struct ends db dw dd dq resb resw resd resq').split(' ');
const AA_BRACE = ['{$lua}', '{$asm}', '{$strict}', '{$nostrict}', '{$try}', '{$except}', '{$ifdef }', '{$ifndef }', '{$else}', '{$endif}'];
const MNEM = ('mov movzx movsx movsxd lea add adc sub sbb cmp test xor and or not neg inc dec imul mul idiv div push pop pushad popad '
  + 'pushfd popfd pushfq popfq call jmp ret retn nop int3 leave enter cdq cqo cwde cdqe shl shr sar sal rol ror xchg cmpxchg lock rep '
  + 'movss movsd movaps movups movapd movupd movd movq addss subss mulss divss addsd subsd mulsd divsd minss maxss sqrtss sqrtsd '
  + 'cvtsi2ss cvtsi2sd cvttss2si cvttsd2si cvtss2sd cvtsd2ss comiss comisd ucomiss ucomisd xorps andps orps pxor '
  + 'fld fst fstp fild fistp fadd fsub fmul fdiv fxch fldz fld1 bt bts btr stc clc std cld').split(' ');
const MNEM_SET = new Set(MNEM);
const JCC = /^(j|set|cmov)(n?(a|ae|b|be|c|e|g|ge|l|le|o|p|s|z)|pe|po)$|^j[er]?cxz$/;
const REG = /^(r(ax|bx|cx|dx|si|di|bp|sp|ip)|e(ax|bx|cx|dx|si|di|bp|sp|ip)|[abcd][xlh]|si|di|bp|sp|sil|dil|bpl|spl|r(8|9|1[0-5])[dwb]?|[xy]mm(\d|1[0-5])|st\d?|[cdefgs]s)$/;
const LUA_KW = ('and break do else elseif end false for function goto if in local nil not or repeat return then true until while').split(' ');
const LUA_KW_SET = new Set(LUA_KW);
const LUA_FN = ('readByte readSmallInteger readShortInteger readInteger readQword readPointer readFloat readDouble readString readBytes '
  + 'writeByte writeSmallInteger writeShortInteger writeInteger writeQword writePointer writeFloat writeDouble writeString writeBytes '
  + 'getAddress getAddressSafe getAddressList getNameFromAddress inModule getModuleSize enumModules enumExports enumMemoryRegions '
  + 'getOpenedProcessID getProcessIDFromProcessName getProcessList openProcess getPointerSize getInstructionSize getPreviousOpcode '
  + 'autoAssemble autoAssembleCheck registerSymbol unregisterSymbol getSymbolInfo allocateMemory deAlloc aobscan '
  + 'readRegionFromFile writeRegionToFile getMemoryProtection getTickCount getCPUCount getTempFolder getSettings '
  + 'showMessage messageDialog inputQuery print sleep beep isKeyPressed speedhack_setSpeed speedhack_getSpeed '
  + 'createForm createTimer createButton createLabel createEdit createCheckBox createMemo createListView createTreeView '
  + 'createStringStream createMemoryStream createFileStream registerAutoAssemblerCommand registerCustomTypeLua '
  + 'tostring tonumber pairs ipairs type pcall error assert select string.format string.sub string.len string.byte string.char '
  + 'string.find string.match string.gsub string.rep table.insert table.remove table.concat table.sort math.floor math.ceil '
  + 'math.abs math.min math.max math.random').split(' ');
const LUA_FN_SET = new Set(LUA_FN);
/** Characters that hide or reorder text (as util.js codeView marks them); tab and newline excluded. */
const HIDDEN = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]/g;

helpAdd('Script editor', [
  ['Ctrl F', 'Find · F3 / Shift F3 next / previous'],
  ['Ctrl H', 'Replace (in the editor) · Ctrl Alt Enter replace all'],
  ['Ctrl Z', 'Undo · Ctrl Y / Ctrl Shift Z redo'],
  ['Tab', 'Indent · Shift Tab outdent (selected lines)'],
  ['Ctrl Space', 'Complete · ↑↓ choose · Enter / Tab insert'],
  ['Esc', 'Close the find bar or the completion list'],
  ['Ctrl Enter', 'Execute · Ctrl Shift Enter run [DISABLE] (Auto Assemble window)'],
]);

// ---------- tokenizer ----------
// A line starts in one state: 'a' AA code, 'b' inside { }, 'c' inside /* */, 'l' Lua,
// 'ls<n>' / 'lc<n>' inside a Lua long string / comment of level n, 't' plain text.
// push(from, to, cls) receives only the coloured runs.
const LONG = /\[(=*)\[/y, LNUM = /0[xX][\da-fA-F.]*(?:[pP][+-]?\d+)?|\d*\.?\d+(?:[eE][+-]?\d+)?/y, LID = /[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?/y;
const ANUM = /(?:#-?\d+|\$[\da-fA-F]+|\d[\da-fA-FxX.]*h?)\b/y, AID = /[A-Za-z_@][\w@]*/y;

function lexLua(s, i, st, push) {
  const n = s.length;
  const longTo = (from, at, level, cls) => {
    const close = ']' + '='.repeat(level) + ']', j = s.indexOf(close, at);
    if (j < 0) { push(from, n, cls); return -1; }
    push(from, j + close.length, cls);
    return j + close.length;
  };
  if (st.length > 1) {
    const at = longTo(i, i, +st.slice(2), st[1] === 's' ? 'str' : 'com');
    if (at < 0) return st;
    i = at;
  }
  while (i < n) {
    const c = s[i];
    if (c === '-' && s[i + 1] === '-') {
      LONG.lastIndex = i + 2;
      const m = LONG.exec(s);
      if (!m) { push(i, n, 'com'); return 'l'; }
      const at = longTo(i, LONG.lastIndex, m[1].length, 'com');
      if (at < 0) return 'lc' + m[1].length;
      i = at; continue;
    }
    if (c === '[') {
      LONG.lastIndex = i;
      const m = LONG.exec(s);
      if (m) {
        const at = longTo(i, LONG.lastIndex, m[1].length, 'str');
        if (at < 0) return 'ls' + m[1].length;
        i = at; continue;
      }
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && s[j] !== c) j += s[j] === '\\' ? 2 : 1;
      push(i, Math.min(j + 1, n), 'str'); i = j + 1; continue;
    }
    if (/[\d.]/.test(c)) {
      LNUM.lastIndex = i;
      const m = LNUM.exec(s);
      if (m && m[0] !== '.') { push(i, LNUM.lastIndex, 'num'); i = LNUM.lastIndex; continue; }
    }
    if (/[A-Za-z_]/.test(c)) {
      LID.lastIndex = i;
      const w = LID.exec(s)[0];
      if (LUA_KW_SET.has(w)) push(i, i + w.length, 'kw');
      else if (LUA_FN_SET.has(w)) push(i, i + w.length, 'fn');
      i += w.length; continue;
    }
    i++;
  }
  return 'l';
}

function lexAA(s, st, push) {
  const n = s.length;
  if (st[0] === 'l') {
    if (/^\s*\{\$asm\}\s*$/i.test(s)) { push(0, n, 'dir'); return 'a'; }
    return lexLua(s, 0, st, push);
  }
  if (st === 'a' && /^\s*\{\$lua\}\s*$/i.test(s)) { push(0, n, 'dir'); return 'l'; }
  let i = 0;
  if (st === 'b' || st === 'c') {
    const close = st === 'b' ? '}' : '*/', j = s.indexOf(close);
    if (j < 0) { push(0, n, 'com'); return st; }
    push(0, j + close.length, 'com'); i = j + close.length;
  } else {
    const lab = /^\s*([\w@.+\-]+):(?!:)/.exec(s);
    if (lab) { push(lab[0].length - lab[1].length - 1, lab[0].length, 'lab'); i = lab[0].length; }
  }
  while (i < n) {
    const c = s[i];
    if (c === '/' && s[i + 1] === '/') { push(i, n, 'com'); return 'a'; }
    if (c === '/' && s[i + 1] === '*') {
      const j = s.indexOf('*/', i + 2);
      if (j < 0) { push(i, n, 'com'); return 'c'; }
      push(i, j + 2, 'com'); i = j + 2; continue;
    }
    if (c === '{') {
      const j = s.indexOf('}', i + 1);
      if (s[i + 1] === '$') { const e = j < 0 ? n : j + 1; push(i, e, 'dir'); i = e; continue; }
      if (j < 0) { push(i, n, 'com'); return 'b'; }
      push(i, j + 1, 'com'); i = j + 1; continue;
    }
    if (c === '"' || c === "'") {
      const j = s.indexOf(c, i + 1), e = j < 0 ? n : j + 1;
      push(i, e, 'str'); i = e; continue;
    }
    if (c === '[') {
      const m = /\[(enable|disable)\]/iy; m.lastIndex = i;
      if (m.test(s)) { push(i, m.lastIndex, 'dir'); i = m.lastIndex; continue; }
    }
    if (/[\d#$]/.test(c)) {
      ANUM.lastIndex = i;
      if (ANUM.test(s)) { push(i, ANUM.lastIndex, 'num'); i = ANUM.lastIndex; continue; }
    }
    if (/[A-Za-z_@]/.test(c)) {
      AID.lastIndex = i;
      const w = AID.exec(s)[0], l = w.toLowerCase();
      const cls = AA_DIR.includes(l) ? 'dir' : REG.test(l) ? 'reg' : MNEM_SET.has(l) || JCC.test(l) ? 'mn' : '';
      if (cls) push(i, i + w.length, cls);
      i += w.length; continue;
    }
    i++;
  }
  return 'a';
}

const lex = (lang, s, st, push) => (lang === 'aa' ? lexAA(s, st, push) : lang === 'lua' ? lexLua(s, 0, st, push) : 't');
const startState = (lang) => (lang === 'aa' ? 'a' : lang === 'lua' ? 'l' : 't');
const noop = () => {};

// ---------- the editor ----------
const handles = new WeakMap();
let uid = 0;

export function attachEditor(ta, { lang = 'aa', gutter = null, symbols = null } = {}) {
  const had = handles.get(ta);
  if (had) { had.configure({ lang, gutter, symbols }); return had.api; }

  const id = 'ed' + ++uid;
  const opts = { lang, gutter, symbols };
  const host = ta.parentElement, dlg = ta.closest('dialog');
  const inner = h('div.ed-in');
  const mirror = h('div.ed-hl', { 'aria-hidden': 'true' }, inner);
  const errNote = h('span.sr-only', { id: id + '-err' });
  const hiddenNote = h('div.ed-hidden', { role: 'status', hidden: true });
  const pop = h('ul.ed-pop', { role: 'listbox', id: id + '-pop', 'aria-label': 'Completions', hidden: true });
  const wrap = h('div.ed-wrap');
  host.insertBefore(wrap, ta);
  wrap.append(mirror, ta, pop, hiddenNote, errNote);
  host.classList.add('ed-host');
  ta.classList.add('ed-ta');
  ta.setAttribute('aria-autocomplete', 'list');
  const describedBy = ta.getAttribute('aria-describedby');
  ta.setAttribute('aria-describedby', [describedBy, errNote.id].filter(Boolean).join(' '));

  // ---------- model ----------
  let text = '', lines = [''], starts = [0], states = [], validTo = 0, version = 0;
  let errLine = 0, errMsg = '';
  let m = { lh: 18, pt: 8, pl: 10, tab: 2, font: '' };
  const cvs = document.createElement('canvas').getContext('2d');

  function measure() {
    const cs = getComputedStyle(ta);
    const lh = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.4;
    m = { lh, pt: parseFloat(cs.paddingTop) || 0, pl: parseFloat(cs.paddingLeft) || 0, tab: parseInt(cs.tabSize, 10) || 8, font: `${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}` };
    Object.assign(inner.style, { font: m.font, lineHeight: lh + 'px', letterSpacing: cs.letterSpacing, tabSize: cs.tabSize, paddingLeft: m.pl + 'px', paddingRight: cs.paddingRight });
    inner.style.setProperty('--ed-lh', lh + 'px');
    cvs.font = m.font;
  }

  function load(v) {
    const nl = v.split('\n');
    let k = 0;
    const lim = Math.min(nl.length, lines.length);
    while (k < lim && nl[k] === lines[k]) k++;
    const countChanged = nl.length !== lines.length;
    text = v; lines = nl; version++;
    validTo = Math.min(validTo, k);
    starts = new Array(nl.length);
    for (let i = 0, o = 0; i < nl.length; i++) { starts[i] = o; o += nl[i].length + 1; }
    if (countChanged) paintGutter();
    const hid = v.match(HIDDEN)?.length || 0;
    hiddenNote.hidden = !hid;
    hiddenNote.textContent = hid ? `${hid} hidden or direction-changing character${hid === 1 ? '' : 's'}, marked in red` : '';
    if (find.open) findAll();
    schedule();
  }
  const lineOf = (off) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; }
    return lo;
  };
  function stateAt(line) {
    if (validTo === 0) states[0] = startState(opts.lang);
    for (; validTo < line; validTo++) states[validTo + 1] = lex(opts.lang, lines[validTo], states[validTo], noop);
    return states[line];
  }
  /** 'lua' | 'aa' | 'text' at a line: AA scripts switch to Lua inside {$lua} blocks. */
  const langAt = (line) => (opts.lang === 'aa' ? (stateAt(line)[0] === 'l' ? 'lua' : 'aa') : opts.lang === 'lua' ? 'lua' : 'text');
  function tokensOf(line) {
    const out = [];
    lex(opts.lang, lines[line], stateAt(line), (a, b, c) => out.push([a, b, c]));
    return out;
  }

  // ---------- painting (only the visible lines) ----------
  let queued = false, painted = '';
  function schedule() {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => { queued = false; paint(); });
  }
  function paint() {
    if (!ta.isConnected) return;
    const top = ta.scrollTop;
    const first = Math.max(0, Math.floor((top - m.pt) / m.lh) - 2);
    const last = Math.min(lines.length, Math.ceil((top + ta.clientHeight) / m.lh) + 2);
    const key = [first, last, version, errLine, find.version, find.cur].join();
    if (key !== painted) {
      painted = key;
      const frag = document.createDocumentFragment();
      for (let i = first; i < last; i++) frag.append(renderLine(i));
      inner.replaceChildren(frag);
    }
    inner.style.width = ta.scrollWidth + 'px';
    inner.style.transform = `translate(${-ta.scrollLeft}px, ${m.pt + first * m.lh - top}px)`;
    if (opts.gutter) opts.gutter.scrollTop = top;
  }
  function renderLine(i) {
    const s = lines[i], el = h('div.ed-ln' + (i + 1 === errLine ? '.ed-err' : ''));
    const toks = opts.lang === 'text' ? [] : tokensOf(i);
    const marks = find.marksIn(starts[i], s.length);
    const cuts = new Set([0, s.length]);
    for (const [a, b] of toks) { cuts.add(a); cuts.add(b); }
    for (const [a, b] of marks) { cuts.add(a); cuts.add(b); }
    const pts = [...cuts].filter((p) => p <= s.length).sort((a, b) => a - b);
    let ti = 0, mi = 0;
    for (let k = 0; k + 1 < pts.length; k++) {
      const a = pts[k], b = pts[k + 1];
      while (ti < toks.length && toks[ti][1] <= a) ti++;
      while (mi < marks.length && marks[mi][1] <= a) mi++;
      const cls = [ti < toks.length && toks[ti][0] <= a ? 'ed-' + toks[ti][2] : '', mi < marks.length && marks[mi][0] <= a ? marks[mi][2] : ''].filter(Boolean);
      const target = cls.length ? h('span.' + cls.join('.')) : el;
      appendText(target, s.slice(a, b));
      if (target !== el) el.append(target);
    }
    return el;
  }
  // Hidden characters become a zero-width red bar: the textarea draws them with no width, so the
  // mirror must too to stay aligned; the bar makes them visible.
  function appendText(el, s) {
    let last = 0;
    for (const x of s.matchAll(HIDDEN)) {
      if (x.index > last) el.append(s.slice(last, x.index));
      el.append(h('span.ed-hid'));
      last = x.index + 1;
    }
    if (last < s.length) el.append(s.slice(last));
  }
  function paintGutter() {
    const g = opts.gutter;
    if (!g) return;
    const n = lines.length;
    const num = (a, b) => Array.from({ length: Math.max(0, b - a) }, (_, i) => a + i + 1).join('\n');
    if (errLine >= 1 && errLine <= n) {
      g.replaceChildren(num(0, errLine - 1) + (errLine > 1 ? '\n' : ''), h('span.ed-gerr', { title: errMsg }, String(errLine)), errLine < n ? '\n' + num(errLine, n) : '');
    } else g.textContent = num(0, n);
    g.scrollTop = ta.scrollTop;
  }

  // ---------- undo history ----------
  let undo = [], redo = [], selBefore = [0, 0], inputType = '';
  const sel = () => [ta.selectionStart, ta.selectionEnd];
  function record(old, now, kind, selB) {
    let s = 0;
    const lim = Math.min(old.length, now.length);
    while (s < lim && old.charCodeAt(s) === now.charCodeAt(s)) s++;
    let e = 0;
    while (e < lim - s && old.charCodeAt(old.length - 1 - e) === now.charCodeAt(now.length - 1 - e)) e++;
    const rec = { pos: s, del: old.slice(s, old.length - e), ins: now.slice(s, now.length - e), selB, selA: sel(), kind, t: Date.now() };
    const last = undo.at(-1);
    redo = [];
    if (last && last.kind === kind && kind !== 'x' && rec.t - last.t < 1500) {
      if (kind === 'ins' && !rec.del && !last.del && rec.pos === last.pos + last.ins.length && !(/\s/.test(rec.ins) && !/\s$/.test(last.ins))) {
        last.ins += rec.ins; last.selA = rec.selA; last.t = rec.t; return;
      }
      if (kind === 'del' && !rec.ins && !last.ins && rec.pos + rec.del.length === last.pos) {
        last.pos = rec.pos; last.del = rec.del + last.del; last.selA = rec.selA; last.t = rec.t; return;
      }
      if (kind === 'del' && !rec.ins && !last.ins && rec.pos === last.pos) {
        last.del += rec.del; last.selA = rec.selA; last.t = rec.t; return;
      }
    }
    undo.push(rec);
    if (undo.length > 500) undo.shift();
  }
  function step(back) {
    const rec = (back ? undo : redo).pop();
    if (!rec) return;
    (back ? redo : undo).push(rec);
    if (back) ta.setRangeText(rec.del, rec.pos, rec.pos + rec.ins.length);
    else ta.setRangeText(rec.ins, rec.pos, rec.pos + rec.del.length);
    ta.setSelectionRange(...(back ? rec.selB : rec.selA));
    rec.t = 0; // never merge into a step that was undone and redone
    load(ta.value);
    reveal(ta.selectionStart);
    notify();
  }
  /** Our own edits: recorded as one undo step, then announced like typing (host input handlers run). */
  function edit(from, to, str, s0 = from + str.length, s1 = s0) {
    const before = sel(), old = text;
    ta.setRangeText(str, from, to);
    ta.setSelectionRange(s0, s1);
    record(old, ta.value, 'x', before);
    load(ta.value);
    notify();
  }
  const notify = () => ta.dispatchEvent(new Event('input', { bubbles: true }));

  // ---------- caret geometry ----------
  function caretXY(off) {
    const line = lineOf(off), col = off - starts[line];
    const prefix = lines[line].slice(0, col).replace(HIDDEN, '');
    let vis = '';
    for (const ch of prefix) vis += ch === '\t' ? ' '.repeat(m.tab - (vis.length % m.tab)) : ch;
    return { line, x: m.pl + cvs.measureText(vis).width, y: m.pt + line * m.lh };
  }
  function reveal(off) {
    const { x, y } = caretXY(off);
    if (y < ta.scrollTop || y + m.lh > ta.scrollTop + ta.clientHeight) ta.scrollTop = y - ta.clientHeight / 2;
    if (x < ta.scrollLeft + m.pl || x > ta.scrollLeft + ta.clientWidth - 24) ta.scrollLeft = Math.max(0, x - ta.clientWidth / 2);
    schedule();
  }

  // ---------- find / replace ----------
  const fIn = h('input.mono.ed-find-in', { type: 'text', 'aria-label': 'Find', placeholder: 'Find', spellcheck: 'false', autocomplete: 'off' });
  const rIn = h('input.mono.ed-find-in', { type: 'text', 'aria-label': 'Replace with', placeholder: 'Replace', spellcheck: 'false', autocomplete: 'off' });
  const fCase = h('input', { type: 'checkbox', 'aria-label': 'Match case' });
  const fCount = h('span.ed-count', { 'aria-live': 'polite' });
  const ibtn = (ic, label, kbd, onclick) => h('button.btn.ghost.icon', { type: 'button', title: `${label} (${kbd})`, 'aria-label': label, onclick, html: icon(ic) });
  const rRow = h('div.ed-find-row', { hidden: true },
    rIn,
    h('button.btn.ghost', { type: 'button', title: 'Replace (Enter)', onclick: () => replaceOne() }, 'Replace'),
    h('button.btn.ghost', { type: 'button', title: 'Replace all (Ctrl Alt Enter)', onclick: () => replaceAll() }, 'All'));
  const bar = h('div.ed-find', { role: 'search', 'aria-label': 'Find in script', hidden: true },
    h('div.ed-find-row', null, fIn,
      h('label.ed-case', { title: 'Match case (Alt C)' }, fCase, h('span', { 'aria-hidden': 'true' }, 'Aa')),
      fCount,
      ibtn('up', 'Previous match', 'Shift F3', () => go(-1)),
      ibtn('down', 'Next match', 'F3', () => go(1)),
      ibtn('x', 'Close', 'Esc', () => closeFind(true))),
    rRow);
  wrap.append(bar);

  const find = {
    open: false, list: [], len: 0, cur: -1, version: 0,
    marksIn(from, n) {
      if (!this.open || !this.list.length) return [];
      const out = [];
      let lo = 0, hi = this.list.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (this.list[mid] + this.len <= from) lo = mid + 1; else hi = mid; }
      for (let k = lo; k < this.list.length && this.list[k] < from + n; k++) {
        out.push([Math.max(0, this.list[k] - from), Math.min(n, this.list[k] + this.len - from), k === this.cur ? 'ed-cur' : 'ed-match']);
      }
      return out;
    },
  };
  const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const findRe = () => (fIn.value ? new RegExp(escRe(fIn.value), fCase.checked ? 'g' : 'gi') : null);
  function findAll() {
    const re = findRe();
    find.list = []; find.len = fIn.value.length; find.version++;
    if (re) for (const x of text.matchAll(re)) { find.list.push(x.index); if (find.list.length >= 20000) break; }
    const at = ta.selectionStart;
    find.cur = find.list.length ? Math.max(0, find.list.findIndex((p) => p >= at)) : -1;
    if (find.cur < 0 && find.list.length) find.cur = 0;
    countText();
    schedule();
  }
  function countText() {
    const n = find.list.length;
    fCount.textContent = !fIn.value ? '' : n ? `${find.cur + 1} of ${n}${n >= 20000 ? '+' : ''}` : 'No results';
    fCount.classList.toggle('none', !!fIn.value && !n);
  }
  function go(d, from = null) {
    if (!find.list.length) return;
    if (from != null) {
      const k = find.list.findIndex((p) => p >= from);
      find.cur = k < 0 ? 0 : k;
    } else find.cur = (find.cur + d + find.list.length) % find.list.length;
    const p = find.list[find.cur];
    ta.setSelectionRange(p, p + find.len);
    find.version++;
    countText();
    reveal(p);
  }
  function openFind(replace) {
    const s = text.slice(ta.selectionStart, ta.selectionEnd);
    if (s && !s.includes('\n')) fIn.value = s;
    find.open = true; bar.hidden = false;
    if (replace) rRow.hidden = false;
    findAll();
    (replace && fIn.value ? rIn : fIn).focus();
    (replace && fIn.value ? rIn : fIn).select();
  }
  function closeFind(focus) {
    find.open = false; bar.hidden = true; rRow.hidden = true; find.version++;
    schedule();
    if (focus) ta.focus();
  }
  function replaceOne() {
    if (!find.list.length) return;
    const p = find.list[find.cur], re = findRe();
    re.lastIndex = 0;
    const atSel = ta.selectionStart === p && ta.selectionEnd === p + find.len;
    if (!atSel) { go(0, ta.selectionStart); return; }
    edit(p, p + find.len, rIn.value);
    findAll();
    go(0, p + rIn.value.length);
  }
  function replaceAll() {
    const re = findRe();
    if (!re) return;
    let n = 0;
    const out = text.replace(re, () => { n++; return rIn.value; });
    if (!n) return;
    const c = Math.min(ta.selectionStart, out.length);
    edit(0, text.length, out, c);
    findAll();
    fCount.textContent = `Replaced ${n}`;
    fCount.classList.remove('none');
  }
  fIn.addEventListener('input', () => { findAll(); if (find.list.length) go(0, ta.selectionStart); });
  fCase.addEventListener('change', findAll);

  // ---------- completion ----------
  const comp = { open: false, items: [], idx: 0, from: 0, pool: null };
  let modNames = [], modFor = null, modAt = 0;
  function moduleNames() {
    if (!state.proc) return [];
    if (modFor !== state.proc || Date.now() - modAt > 10000) {
      modFor = state.proc; modAt = Date.now();
      api.modules().then((ms) => { modNames = (ms || []).map((x) => x.name); comp.pool = null; if (comp.open) filter(); }).catch(() => {});
    }
    return modNames;
  }
  function pool(ctx) {
    const seen = new Map();
    const add = (w, k) => { if (w && !seen.has(w)) seen.set(w, k); };
    if (ctx === 'lua') {
      LUA_KW.forEach((w) => add(w, 'keyword'));
      LUA_FN.forEach((w) => add(w, 'function'));
      for (const x of text.matchAll(/\b(?:function\s+([\w.:]+)|local\s+(?:function\s+)?(\w+))/g)) add(x[1] || x[2], 'name');
    } else {
      for (const x of text.matchAll(/^[ \t]*([\w@.]+):(?!:)/gm)) add(x[1], 'label');
      for (const x of text.matchAll(/\b(alloc\w*|globalalloc|kalloc|sharedallocate|label|define|registersymbol|aobscan\w*|createthread)\s*\(([^)\n]*)\)/gi)) {
        const args = x[2].split(',').map((a) => a.trim()).filter((a) => /^[\w@.]+$/.test(a));
        const kind = x[1].toLowerCase();
        (kind === 'label' || kind === 'registersymbol' ? args : args.slice(0, 1)).forEach((a) => add(a, kind === 'label' ? 'label' : kind.startsWith('aob') ? 'aob' : kind));
      }
      (opts.symbols?.() || []).forEach((w) => add(String(w), 'symbol'));
      moduleNames().forEach((w) => add(w, 'module'));
      AA_DIR.forEach((w) => add(w, 'directive'));
      AA_BRACE.forEach((w) => add(w, 'directive'));
      MNEM.forEach((w) => add(w, 'instruction'));
    }
    return [...seen];
  }
  const wordRe = (ctx) => (ctx === 'lua' ? /[\w.]*$/ : /[{$\w@.]*$/);
  function wordBefore() {
    const c = ta.selectionStart, line = lineOf(c), ctx = langAt(line);
    const w = wordRe(ctx).exec(text.slice(starts[line], c))[0];
    return { w, from: c - w.length, ctx };
  }
  function openComp(auto) {
    if (opts.lang === 'text' || ta.selectionStart !== ta.selectionEnd) return closeComp();
    const { w, from, ctx } = wordBefore();
    if (auto && (w.length < 2 || !/^[A-Za-z_{]/.test(w))) return closeComp();
    if (!comp.open || comp.ctx !== ctx || !comp.pool) comp.pool = pool(ctx);
    comp.ctx = ctx; comp.from = from; comp.open = true;
    filter(w);
  }
  function filter(w = wordBefore().w) {
    const q = w.toLowerCase();
    const pre = [], mid = [];
    for (const [word, kind] of comp.pool) {
      const l = word.toLowerCase(), k = l.indexOf(q);
      if (k === 0) pre.push([word, kind]); else if (k > 0 && q) mid.push([word, kind]);
    }
    comp.items = [...pre, ...mid].filter(([word]) => word !== w).slice(0, 60);
    if (!comp.items.length) return closeComp();
    comp.idx = 0;
    pop.replaceChildren(...comp.items.map(([word, kind], i) => h('li', {
      role: 'option', id: `${id}-o${i}`, 'aria-selected': 'false',
      onmousedown: (e) => { e.preventDefault(); comp.idx = i; accept(); },
    }, h('span.ed-pop-w', null, word), h('span.ed-pop-k', null, kind))));
    pop.hidden = false;
    ta.setAttribute('aria-controls', pop.id);
    select(0);
    placePop();
  }
  function select(i) {
    comp.idx = (i + comp.items.length) % comp.items.length;
    [...pop.children].forEach((li, k) => li.setAttribute('aria-selected', String(k === comp.idx)));
    const li = pop.children[comp.idx];
    ta.setAttribute('aria-activedescendant', li.id);
    li.scrollIntoView({ block: 'nearest' });
  }
  function placePop() {
    const { x, y } = caretXY(comp.from);
    const left = Math.max(0, Math.min(x - ta.scrollLeft, wrap.clientWidth - pop.offsetWidth - 4));
    let top = y - ta.scrollTop + m.lh + 2;
    if (top + pop.offsetHeight > wrap.clientHeight && y - ta.scrollTop - pop.offsetHeight > 0) top = y - ta.scrollTop - pop.offsetHeight - 2;
    pop.style.left = left + 'px'; pop.style.top = top + 'px';
  }
  function closeComp() {
    if (!comp.open) return;
    comp.open = false; pop.hidden = true; pop.replaceChildren();
    ta.removeAttribute('aria-activedescendant'); ta.removeAttribute('aria-controls');
  }
  function accept() {
    const [word] = comp.items[comp.idx];
    const from = comp.from, to = ta.selectionStart;
    closeComp();
    edit(from, to, word);
  }
  /** No automatic popup while typing inside a comment or string. */
  function inProse() {
    const c = ta.selectionStart, line = lineOf(c), col = c - starts[line];
    if (opts.lang === 'text' || !col) return true;
    return tokensOf(line).some(([a, b, cls]) => (cls === 'com' || cls === 'str') && a < col && col <= b);
  }

  // ---------- keys ----------
  let swallowCancel = false;
  const swallow = () => { swallowCancel = true; setTimeout(() => { swallowCancel = false; }, 0); };
  function onKey(e) {
    const ctrl = e.ctrlKey || e.metaKey, k = e.key, inTa = e.target === ta, inBar = bar.contains(e.target);
    if (e.isComposing || (!inTa && !inBar)) return;
    let done = true;
    if (comp.open && inTa && !ctrl && !e.altKey) {
      if (k === 'ArrowDown') select(comp.idx + 1);
      else if (k === 'ArrowUp') select(comp.idx - 1);
      else if (k === 'PageDown') select(Math.min(comp.items.length - 1, comp.idx + 8));
      else if (k === 'PageUp') select(Math.max(0, comp.idx - 8));
      else if ((k === 'Enter' || k === 'Tab') && !e.shiftKey) accept();
      else if (k === 'Escape') { closeComp(); swallow(); }
      else done = false;
      if (done) { e.preventDefault(); e.stopPropagation(); return; }
      done = true;
      if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(k)) closeComp();
    }
    const lk = k.toLowerCase();
    if (ctrl && !e.altKey && lk === 'f') openFind(false);
    else if (ctrl && !e.altKey && lk === 'h') openFind(true);
    else if (k === 'F3' && !ctrl) { if (!find.open) openFind(false); else go(e.shiftKey ? -1 : 1); }
    else if (k === 'Escape' && find.open) { closeFind(true); swallow(); }
    else if (inBar) {
      if (k === 'Enter' && ctrl && e.altKey) replaceAll();
      else if (k === 'Enter' && !ctrl && e.target === rIn) replaceOne();
      else if (k === 'Enter' && !ctrl) go(e.shiftKey ? -1 : 1);
      else if (e.altKey && lk === 'c') { fCase.checked = !fCase.checked; findAll(); }
      else done = false;
    } else if (ctrl && !e.altKey && lk === 'z') step(!e.shiftKey);
    else if (ctrl && !e.altKey && lk === 'y') step(false);
    else if (ctrl && k === ' ') openComp(false);
    else if (k === 'Tab' && !ctrl && !e.altKey) indent(e.shiftKey);
    else if (k === 'Enter' && !ctrl && !e.altKey && !e.shiftKey) newline();
    else done = false;
    if (done) { e.preventDefault(); e.stopPropagation(); }
  }
  function indent(out) {
    const s = ta.selectionStart, e = ta.selectionEnd;
    const multi = text.slice(s, e).includes('\n');
    if (!out && !multi) { edit(s, e, '  '); return; }
    const a = text.lastIndexOf('\n', s - 1) + 1;
    const b = e > s && text[e - 1] === '\n' ? e - 1 : e;
    const z = text.indexOf('\n', b), end = z < 0 ? text.length : z;
    const old = text.slice(a, end).split('\n');
    const now = old.map((l) => (out ? l.replace(/^( {1,2}|\t)/, '') : l ? '  ' + l : l));
    const block = now.join('\n');
    if (multi) edit(a, end, block, a, a + block.length);
    else { const cut = old[0].length - now[0].length; edit(a, end, block, Math.max(a, s - cut), Math.max(a, e - cut)); }
  }
  function newline() {
    const s = ta.selectionStart, line = lineOf(s), before = text.slice(starts[line], s);
    let ind = /^[ \t]*/.exec(before)[0];
    const ctx = langAt(line);
    if (ctx === 'lua') {
      const c = before.replace(/--.*$/, '').trimEnd(), f = c.lastIndexOf('function');
      if (/(\b(then|do|repeat|else)|\{)$/.test(c) || (f >= 0 && /\)$/.test(c) && !/\bend\b/.test(c.slice(f)))) ind += '  ';
    } else if (ctx === 'aa' && /^\s*[\w@.+\-]+:\s*(\/\/.*)?$/.test(before)) ind += '  ';
    edit(s, ta.selectionEnd, '\n' + ind);
    reveal(ta.selectionStart);
  }

  // ---------- events ----------
  const L = [];
  const listen = (el, ev, fn, o) => { el.addEventListener(ev, fn, o); L.push([el, ev, fn, o]); };
  // Capture on the wrapper: the keys handled here never reach the host's own textarea handlers.
  listen(wrap, 'keydown', onKey, true);
  listen(ta, 'beforeinput', (e) => {
    if (e.inputType === 'historyUndo' || e.inputType === 'historyRedo') { e.preventDefault(); step(e.inputType === 'historyUndo'); return; }
    selBefore = sel(); inputType = e.inputType;
  });
  listen(ta, 'input', (e) => {
    if (ta.value === text) { schedule(); return; }
    const kind = inputType === 'insertText' ? 'ins' : /^delete(Content|Word)/.test(inputType) ? 'del' : 'x';
    record(text, ta.value, kind, selBefore);
    inputType = '';
    load(ta.value);
    if (comp.open) openComp(false);
    else if (kind === 'ins' && e.data && /[\w@.$]$/.test(e.data) && !inProse()) openComp(true);
  });
  listen(ta, 'scroll', () => { schedule(); if (comp.open) closeComp(); });
  listen(ta, 'blur', closeComp);
  listen(ta, 'mousedown', closeComp);
  listen(ta, 'mousemove', (e) => {
    if (!errLine) return;
    const line = Math.floor((e.offsetY + ta.scrollTop - m.pt) / m.lh) + 1;
    if (line === errLine) ta.title = errMsg; else ta.removeAttribute('title');
  });
  if (dlg) listen(dlg, 'cancel', (e) => { if (swallowCancel) e.preventDefault(); });
  const ro = new ResizeObserver(() => { measure(); painted = ''; schedule(); });
  ro.observe(ta);

  const api_ = {
    refresh() {
      measure();
      undo = []; redo = [];
      closeComp();
      lines = [''];
      validTo = 0; states = [];
      load(ta.value);
      paintGutter();
      painted = '';
      schedule();
    },
    markError(line, message = '') {
      errLine = Math.max(0, line | 0); errMsg = errLine ? String(message || 'Error') : '';
      errNote.textContent = errLine ? `Error on line ${errLine}: ${errMsg}` : '';
      if (!errLine) ta.removeAttribute('title');
      paintGutter();
      schedule();
    },
    destroy() {
      for (const [el, ev, fn, o] of L) el.removeEventListener(ev, fn, o);
      ro.disconnect();
      closeComp();
      host.insertBefore(ta, wrap);
      wrap.remove();
      host.classList.remove('ed-host');
      ta.classList.remove('ed-ta');
      for (const a of ['aria-autocomplete', 'aria-activedescendant', 'aria-controls', 'title']) ta.removeAttribute(a);
      if (describedBy) ta.setAttribute('aria-describedby', describedBy); else ta.removeAttribute('aria-describedby');
      handles.delete(ta);
    },
  };
  handles.set(ta, {
    api: api_,
    configure(o) {
      Object.assign(opts, o);
      api_.refresh();
    },
  });
  api_.refresh();
  return api_;
}

// ---------- standalone Auto Assemble window ----------
const NEEDS = 'needs consent:';
let win = null;

export function openAaWindow() {
  win ??= buildAaWindow();
  win.dlg.showModal();
  win.ta.focus();
}

function buildAaWindow() {
  const id = 'aaw' + ++uid;
  const ta = h('textarea.mono', { spellcheck: 'false', wrap: 'off', 'aria-label': 'Auto Assembler script', 'aria-describedby': id + '-status' });
  const gut = h('pre.aa-gutter.mono', { 'aria-hidden': 'true' });
  const status = h('button.aa-status', { type: 'button', id: id + '-status', 'aria-live': 'polite' });
  const src = h('span.hint.ed-src');
  const scansEl = h('div.ed-scans', { role: 'status', 'aria-label': 'AOB scan matches', hidden: true });
  const btn = (label, kbd, onclick, cls = '') => h('button.btn' + cls, { type: 'button', onclick }, label, ' ', h('kbd', null, kbd));
  const bExec = btn('Execute', 'Ctrl Enter', () => run(true), '.primary');
  const bUndo = btn('Run [DISABLE]', 'Ctrl Shift Enter', () => run(false));
  const bCheck = btn('Check', 'Ctrl K', () => check(true));
  const bOpen = h('button.btn.ghost', { type: 'button', onclick: () => openFile(), html: icon('folder') }, 'Open file ', h('kbd', null, 'Ctrl O'));
  const dlg = h('dialog.dlg.dlg-script.ed-aawin', { 'aria-labelledby': id + '-title' },
    h('form', { method: 'dialog' },
      h('div.dlg-head', null,
        h('div.ed-aawin-title', null, h('h2', { id: id + '-title' }, 'Auto Assemble'), src),
        bOpen),
      h('div.aa-editor', null, gut, ta),
      status, scansEl,
      h('div.dlg-actions', null, bExec, bUndo, bCheck,
        h('button.btn', { value: 'cancel', formnovalidate: true }, 'Close ', h('kbd', null, 'Esc')))));
  document.body.append(dlg);
  ta.value = '[ENABLE]\n\n[DISABLE]\n';
  const ed = attachEditor(ta, { lang: 'aa', gutter: gut });
  let path = null, loaded = null, execState = null, executed = false, errLine = 0, checkT = 0;

  const show = (msg, kind) => { status.textContent = msg; status.className = 'aa-status ' + kind; };
  const syncSrc = () => { src.textContent = path ? `From file: ${excerpt(path, 90)}${ta.value !== loaded ? ' (edited)' : ''}` : 'Typed here, not saved in the table'; };
  const syncBtns = () => { bUndo.disabled = !executed; };
  const errText = (e) => String(e?.message || e);
  function fail(msg) {
    const n = +(/\bline (\d+)/i.exec(msg)?.[1] || 0);
    errLine = n; ed.markError(n, msg);
    show(msg, 'err');
  }
  async function check(explicit) {
    try {
      const r = await api.aaCheck(ta.value);
      errLine = r ? r.line : 0;
      ed.markError(errLine, r?.message);
      if (r) show(`Line ${r.line}: ${r.message}`, 'err'); else if (explicit || status.classList.contains('err')) show('No errors', 'ok');
    } catch (e) { fail(errText(e)); }
  }
  async function askLua(script) {
    const info = await api.appInfo().catch(() => null);
    const lua = /\{\$lua\}/i.test(script), bin = /loadbinary/i.test(script);
    const r = await modal({
      title: lua ? 'Run this script\'s Lua?' : 'Let this script read a file?',
      text: (lua
        ? 'This Auto Assembler script came from a file and has {$lua} blocks. Lua runs with your user account\'s rights. '
          + (info?.lua_allow_os === false
            ? 'Settings turn off Lua\'s access to files and programs: it can still read and change the attached process and run Auto Assembler in it.'
            : 'It can read, change and delete your files, start programs, use the network, and read and change the attached process.')
        : '')
        + (bin ? (lua ? ' ' : 'This Auto Assembler script came from a file. ') + 'Its loadbinary reads a file from this computer (up to 64 MiB, any file your account can read) and writes it into the attached process.' : '')
        + ' Run it only if you trust where the file came from.',
      quote: path, quoteLabel: 'File',
      body: h('div', null, h('p.hint', null, 'Start of the script:'), codeView(script, 12)),
      buttons: [
        { label: 'Trust and run', value: 'trust' },
        { label: 'Do not run', value: 'cancel', kbd: 'Esc', primary: true, focus: true },
      ],
    });
    return r.value === 'trust';
  }
  async function run(enable) {
    if (!enable && !executed) return;
    const script = ta.value;
    const go = () => api.aaExecute(script, enable, enable ? null : execState);
    let r;
    showScans(null);
    try { r = await go(); } catch (e) {
      const msg = errText(e);
      if (!msg.startsWith(NEEDS) || msg.includes('Settings say never')) return failRun(msg);
      if (!(await askLua(script))) { ta.focus(); return show(/\{\$lua\}/i.test(script) ? 'Not run: its Lua needs your consent' : 'Not run: its loadbinary needs your consent', 'err'); }
      try { await api.aaTrust(script); r = await go(); } catch (e2) { ta.focus(); return failRun(errText(e2)); }
      ta.focus();
    }
    execState = enable ? r : null;
    executed = enable;
    errLine = 0; ed.markError(0);
    const multi = (r?.scans || []).filter((x) => x.matches > 1);
    show(enable ? (multi.length ? `Executed [ENABLE], but ${multi.length} AOB pattern${multi.length > 1 ? 's match' : ' matches'} more than once: the first match was used. Run [DISABLE] undoes it.` : 'Executed [ENABLE]. Run [DISABLE] undoes it.') : 'Ran [DISABLE].', multi.length ? 'warn' : 'ok');
    if (enable) showScans(r?.scans);
    syncBtns();
  }
  /** Errors the user fixes in Settings rather than in the script get a pointer there. */
  function failRun(msg) {
    fail(/do not allow Lua and scripts to access files/.test(msg) ? msg + '. To allow it, tick "Allow Lua scripts to access files and run programs" in Settings (Ctrl ,).' : msg);
  }
  /** Each aobscan's match count after Execute; more than one is flagged (the script used the first). */
  function showScans(scans) {
    scansEl.hidden = !scans?.length;
    if (!scans?.length) { scansEl.replaceChildren(); return; }
    const counted = scans.some((x) => x.matches != null);
    scansEl.replaceChildren(
      h('span.muted', null, counted ? 'AOB scans: ' : 'AOB scans (match counts are off in Settings, aobscan that matches more than once): '),
      ...scans.map((x) => h('span' + (x.matches > 1 ? '.ed-scan.multi' : '.ed-scan'), { title: x.matches > 1 ? 'Matches more than once: the script used the first match, which may be the wrong place' : '' },
        excerpt(x.name, 40), ' ', h('span.mono', null, fmtAddr(x.addr)), x.matches == null ? '' : ` · ${x.matches >= 1000 ? '1,000 or more' : x.matches} match${x.matches === 1 ? '' : 'es'}`)));
  }
  async function openFile() {
    const p = await askPath({ save: false, title: 'Open Auto Assembler script', filters: [['Auto Assembler script', ['cea', 'aa', 'txt']], ['All files', ['*']]] });
    if (!p) return ta.focus();
    try {
      const r = await api.aaLoadFile(p);
      ta.value = typeof r === 'string' ? r : r?.script ?? '';
      path = p; loaded = ta.value;
      ed.refresh(); ed.markError(0); errLine = 0;
      show('', '');
      syncSrc(); check(false);
    } catch (e) { fail(errText(e)); }
    ta.focus();
  }
  ta.addEventListener('input', () => { syncSrc(); clearTimeout(checkT); checkT = setTimeout(() => check(false), 400); });
  status.addEventListener('click', () => {
    if (!errLine) return;
    const off = ta.value.split('\n').slice(0, errLine - 1).reduce((n, l) => n + l.length + 1, 0);
    ta.focus(); ta.setSelectionRange(off, off);
  });
  dlg.addEventListener('keydown', (e) => {
    const ctrl = e.ctrlKey || e.metaKey, k = e.key.toLowerCase();
    if (ctrl && k === 'enter') run(!e.shiftKey);
    else if (ctrl && k === 'o') openFile();
    else if (ctrl && k === 'k') check(true);
    else return;
    e.preventDefault(); e.stopPropagation();
  });
  syncSrc(); syncBtns();
  return { dlg, ta };
}
