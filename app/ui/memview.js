// Memory viewer: disassembler (top), hex dump (bottom), regions and modules (side).
// Both panes page by address (no native scrollbar) so the whole 64-bit space is reachable.
import { api, askPath } from './backend.js';
import { $, $$, h, icon, fmtAddr, fmtSize, wire, attempt, toast, prompt, rafThrottle, contextMenu, store, busy, modal, excerpt, helpAdd } from './util.js';
import { state, addTicker, on, emit } from './core.js';
import { vlist, pager } from './vlist.js';
import * as tools from './memtools.js';
import { editTableMeta } from './table.js';
import * as F from './memfmt.js';
import { initSecondViewer } from './memview2.js';

/** Row height of both panes in px: follows the text size (Ctrl = / Ctrl -), --row-mem in CSS. */
let ROW = 20;
const TYPES = F.TYPE_SIZE;
const big = (s) => BigInt(s);
// Icons util.js does not have (same 24px grid and stroke as icon()).
const svg = (d) => `<svg class="ic" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const IC = {
  fwd: svg('<path d="M5 12h14M13 6l6 6-6 6"/>'),
  lock: svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
  unlock: svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.7-1.5"/>'),
};
/** Back / forward stacks of places; the caller passes where it is when it leaves. */
function navHistory(backBtn, fwdBtn) {
  const b = [], f = [];
  const sync = () => { backBtn.disabled = !b.length; fwdBtn.disabled = !f.length; };
  return {
    push(here) { if (here == null) return; b.push(here); if (b.length > 200) b.shift(); f.length = 0; sync(); },
    back(here) { const p = b.pop(); if (p !== undefined) f.push(here); sync(); return p; },
    fwd(here) { const p = f.pop(); if (p !== undefined) b.push(here); sync(); return p; },
    clear() { b.length = 0; f.length = 0; sync(); },
  };
}
/** Clipboard write with a toast either way. */
const copyText = (s, what) => navigator.clipboard.writeText(s).then(() => toast(`Copied ${what}`, 'info'), (e) => toast(`Could not copy: ${e?.message || e}`));

export function initMemview() {
  const da = $('#da-list'), hx = $('#hx-list'), hxType = $('#hx-type');
  const visOf = (el) => Math.max(1, Math.floor(el.clientHeight / ROW));

  // ---------- disassembler ----------
  let daTop = null, daRows = [], daSel = 0, editing = false;
  /** Shift selection: the anchor line's address; the selection runs from it to the cursor line. */
  let daAnchor = null;
  let modRel = store.get('da.modrel', false), showBytes = store.get('da.bytes', true);
  // AT&T is display only (assembling still takes Intel); typed adds operand type comments.
  let att = store.get('da.att', false), typed = store.get('da.typed', false);
  const dopts = () => (att || typed ? { att, typed } : null);
  /** Branch target of a line; AT&T indirect forms (*, parentheses) carry no direct target. */
  const branchTarget = (t) => (att && /[*(]/.test(t) ? null : F.branchTarget(t));
  const daFwd = h('button.btn.ghost.icon#da-fwd', { type: 'button', disabled: true, 'aria-label': 'Forward (Alt →)', title: 'Forward (Alt →)', html: IC.fwd });
  $('#da-back').after(daFwd);
  const daHist = navHistory($('#da-back'), daFwd);
  async function daLoad() {
    if (daTop == null || editing) return;
    const top = daTop;
    const rows = await api.disassemble(wire(top), visOf(da) + 4, dopts()).catch((e) => { toast(e); return null; });
    if (rows && top === daTop) { daRows = rows; daRender(); probeFunctions(); }
  }
  const daPool = [];
  let shownN = 0; // instruction rows on screen (label lines take room too)
  /** Pool element showing instruction row i, if it is on screen. */
  const rowEl = (i) => daPool.find((r) => !r.hidden && !r.classList.contains('da-label') && +r.dataset.i === i);
  /** [low, high] addresses of the selected lines (the cursor line alone without a selection). */
  function daRange() {
    const a = cur();
    if (a == null) return null;
    const c = big(a), o = daAnchor ?? c;
    return o < c ? [o, c] : [c, o];
  }
  // Jump lines: an SVG in the left gutter, one lane per overlapping branch.
  const jumps = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  jumps.setAttribute('class', 'da-jumps');
  jumps.setAttribute('aria-hidden', 'true');
  da.prepend(jumps);
  function drawJumps() {
    const at = new Map();
    daPool.forEach((r) => { if (!r.hidden && !r.classList.contains('da-label')) at.set(big(daRows[+r.dataset.i].addr), r); });
    const arrows = [];
    for (const [a, r] of at) {
      const d = daRows[+r.dataset.i];
      if (/^call\b/i.test(d.text)) continue;
      const t = branchTarget(d.text);
      if (t == null || !at.has(t)) continue;
      arrows.push({ y1: r.offsetTop + ROW / 2, y2: at.get(t).offsetTop + ROW / 2, cond: !F.isUncond(d.text), hot: +r.dataset.i === daSel || +at.get(t).dataset.i === daSel });
    }
    arrows.sort((p, q) => Math.abs(p.y1 - p.y2) - Math.abs(q.y1 - q.y2));
    const lanes = [];
    let out = '';
    for (const j of arrows) {
      const lo = Math.min(j.y1, j.y2), hi = Math.max(j.y1, j.y2);
      let L = lanes.findIndex((ls) => ls.every(([a, b]) => hi < a || lo > b));
      if (L < 0) L = lanes.length < 4 ? lanes.push([]) - 1 : 3;
      lanes[L].push([lo, hi]);
      const x = 30 - L * 5, e = 34;
      out += `<path class="jl${j.cond ? ' cond' : ''}${j.hot ? ' hot' : ''}" d="M${e} ${j.y1}H${x}V${j.y2}H${e - 1}M${e - 4} ${j.y2 - 3}l3 3-3 3"/>`;
    }
    jumps.setAttribute('height', da.clientHeight);
    jumps.innerHTML = out;
  }
  // Function starts (dissection, else the backend's guess) get a separator line with the name.
  const fnCache = new Map(); // addr string -> name | null | false (asking)
  async function probeFunctions() {
    const ask = [];
    daRows.slice(0, shownN + 1).forEach((d, i) => {
      if (d.text === '??' || fnCache.has(d.addr)) return;
      const prev = daRows[i - 1]?.text || '';
      if (i === 0 || /^(ret|int3?|jmp|nop)\b/i.test(prev) || d.xrefs?.calls || labelsAt(d.addr).length) ask.push(d.addr);
    });
    if (!ask.length) return;
    ask.forEach((a) => fnCache.set(a, false));
    const got = await Promise.all(ask.slice(0, 12).map((a) => api.codeFunction(a).catch(() => null)));
    ask.slice(12).forEach((a) => fnCache.delete(a));
    let any = false;
    got.forEach((f, k) => {
      const hit = f && big(f.start) === big(ask[k]);
      fnCache.set(ask[k], hit ? excerpt(f.name || 'sub_' + fmtAddr(ask[k]), 60) : null);
      any ||= hit;
    });
    if (any) daRender();
  }
  /** "game.exe+1A2B" for addresses inside a module, else plain hex. */
  function relName(a) {
    const n = big(a), m = mods.find((x) => n >= big(x.base) && n < big(x.base) + BigInt(x.size));
    return m ? `${m.name}+${(n - big(m.base)).toString(16).toUpperCase()}` : fmtAddr(a);
  }
  function daRender() {
    const vis = visOf(da);
    const lines = [];
    for (let i = 0; i < daRows.length && lines.length < vis; i++) {
      const fn = fnCache.get(daRows[i].addr);
      if (fn && lines.length < vis - 1) lines.push({ label: fn, fn: true, i });
      for (const name of labelsAt(daRows[i].addr)) if (lines.length < vis - 1 && name !== fn) lines.push({ label: name, i });
      lines.push({ i });
    }
    shownN = lines.filter((l) => !l.label).length;
    daSel = Math.max(0, Math.min(daSel, shownN - 1));
    while (daPool.length < lines.length) {
      const r = h('div.da-row', { role: 'row', id: 'da-r' + daPool.length },
        h('span.c-addr', { role: 'gridcell' }), h('span.c-bytes', { role: 'gridcell' }), h('span.c-text', { role: 'gridcell' }), h('span.c-cmt', { role: 'gridcell' }));
      daPool.push(r); da.append(r);
    }
    let selId = '';
    const range = daAnchor != null ? daRange() : null;
    daPool.forEach((r, k) => {
      const ln = lines[k];
      r.hidden = !ln;
      if (!ln) return;
      const d = daRows[ln.i], [a, b, t, c] = r.children;
      r.dataset.i = ln.i;
      r.classList.toggle('da-label', !!ln.label);
      r.classList.toggle('da-fn', !!ln.fn);
      if (ln.label) {
        r.setAttribute('aria-selected', 'false');
        r.classList.remove('bp', 'rip', 'in-sel');
        r.removeAttribute('aria-description');
        a.textContent = ''; b.textContent = ''; c.textContent = '';
        t.textContent = ln.fn ? ln.label : ln.label + ':'; t.dataset.v = '';
        return;
      }
      const isSel = ln.i === daSel;
      if (isSel) selId = r.id;
      r.setAttribute('aria-selected', String(isSel));
      r.classList.toggle('in-sel', !!range && big(d.addr) >= range[0] && big(d.addr) <= range[1]);
      const isBp = !!state.dbg?.bpAddrs?.has(big(d.addr)), isRip = state.dbg?.rip != null && big(d.addr) === state.dbg.rip;
      r.classList.toggle('bp', isBp);
      r.classList.toggle('rip', isRip);
      r.setAttribute('aria-description', [isBp && 'breakpoint', isRip && 'current instruction'].filter(Boolean).join(', '));
      const txt = modRel ? relName(d.addr) : fmtAddr(d.addr);
      if (a.textContent !== txt) a.textContent = txt;
      if (b.textContent !== d.bytes) b.textContent = d.bytes;
      if (t.dataset.v !== d.text) {
        t.dataset.v = d.text;
        t.replaceChildren(...highlight(d.text));
        t.classList.toggle('branch', /^(j|call|ret|loop)/.test(d.text));
      }
      const x = d.xrefs, xr = x ? [x.calls && `${x.calls} call${x.calls > 1 ? 's' : ''}`, x.jumps && `${x.jumps} jump${x.jumps > 1 ? 's' : ''}`, x.data && `${x.data} read${x.data > 1 ? 's' : ''}`].filter(Boolean).join(' · ') : '';
      const user = commentAt(d.addr);
      const ck = xr + '|' + (d.comment || '') + '|' + user;
      if (c.dataset.v !== ck) {
        c.dataset.v = ck;
        c.replaceChildren(
          xr ? h('span.xr', { title: 'Referenced from (code dissection); X lists them' }, '← ' + xr + '  ') : '',
          user ? h('span.da-ucmt', { title: 'Your comment (;)' }, '; ' + user + (d.comment ? '  ' : '')) : '',
          d.comment || '');
      }
    });
    if (selId) da.setAttribute('aria-activedescendant', selId); else da.removeAttribute('aria-activedescendant');
    drawJumps();
    renderDaState();
    syncFromDa();
  }
  async function backN(n) {
    if (daTop == null) return daTop;
    const from = daTop > BigInt(n * 8) ? daTop - BigInt(n * 8) : 0n;
    const rows = await api.disassemble(wire(from), n * 3, dopts()).catch(() => []);
    const before = rows.filter((r) => big(r.addr) < daTop);
    return before.length ? big(before[Math.max(0, before.length - n)].addr) : daTop;
  }
  async function daScroll(n) {
    if (!daRows.length) return;
    if (n > 0) daTop = big(daRows[Math.min(n, daRows.length - 1)].addr);
    else daTop = await backN(-n);
    await daLoad();
  }
  async function daGoto(addr, { push = true } = {}) {
    if (push && daTop != null) daHist.push([daTop, daSel]);
    daTop = big(addr); daSel = 0; daAnchor = null;
    await daLoad();
  }
  function follow() {
    const d = daRows[daSel], t = d && branchTarget(d.text);
    if (t != null) daGoto(t);
  }
  function back() {
    const p = daHist.back([daTop, daSel]);
    if (p) { [daTop, daSel] = p; daAnchor = null; daLoad(); }
  }
  function forward() {
    const p = daHist.fwd([daTop, daSel]);
    if (p) { [daTop, daSel] = p; daAnchor = null; daLoad(); }
  }
  async function assembleLine() {
    const d = daRows[daSel];
    if (!d || !rowEl(daSel) || editing) return;
    editing = true;
    // The assembler takes Intel syntax only: with AT&T on, edit the Intel form of the line.
    const orig = att ? ((await api.disassemble(d.addr, 1).catch(() => []))[0]?.text ?? d.text) : d.text;
    const row = rowEl(daSel);
    if (!row) { editing = false; return; }
    const cell = row.children[2];
    const input = h('input.cell-input.mono', { value: orig, spellcheck: 'false', 'aria-label': `Assemble at ${fmtAddr(d.addr)}${att ? ' (Intel syntax)' : ''}` });
    cell.replaceChildren(input, att ? h('span.da-intel', { title: 'AT&T is display only: the assembler takes Intel syntax' }, 'Intel syntax') : '');
    delete cell.dataset.v;
    input.focus(); input.select();
    let done = false;
    const finish = async (ok) => {
      if (done) return;
      done = true;
      if (ok && input.value.trim() && input.value.trim() !== orig) {
        await attempt(async () => {
          let hex = (await api.assemble(d.addr, input.value)).replace(/\s+/g, '');
          const old = d.bytes.split(' ').length;
          if (hex.length / 2 < old) hex += '90'.repeat(old - hex.length / 2); // pad the rest of the old instruction with nops
          await api.writeBytes(d.addr, hex);
        });
      }
      editing = false;
      da.focus();
      daLoad();
    };
    input.addEventListener('keydown', (e) => {
      e.stopPropagation();
      if (e.key === 'Enter') { e.preventDefault(); finish(true); } else if (e.key === 'Escape') { e.preventDefault(); finish(false); }
    });
    input.addEventListener('blur', () => finish(false));
  }
  async function gotoPrompt(which) {
    const cur = which === 'da' ? daTop : hxCur;
    const s = await prompt('Go to address', cur != null ? fmtAddr(cur) : '', { label: 'Address or expression', hint: 'Examples: 7FFD12340000, game.exe+1A2B, [[player_base]+8]' });
    if (!s) { (which === 'da' ? da : hx).focus(); return; }
    const a = await attempt(() => api.resolveAddress(s));
    if (a) which === 'da' ? daGoto(a) : hxJump(a);
    (which === 'da' ? da : hx).focus();
  }
  const cur = () => daRows[daSel]?.addr;

  // ---------- syntax highlighting ----------
  const REG = /^(?:[re]?[abcd]x|[abcd][lh]|[re]?(?:si|di|sp|bp|ip)|(?:si|di|sp|bp)l|r(?:[89]|1[0-5])[dwb]?|[xyz]mm\d+|st\d?|[cdefgs]s|cr\d|dr\d|k[0-7])$/i;
  /** Instruction text -> nodes: mnemonic bold, memory operands, immediates and size keywords marked. */
  function highlight(text) {
    const i = text.indexOf(' '), m = i < 0 ? text : text.slice(0, i), ops = i < 0 ? '' : text.slice(i);
    const out = [h('b', null, m)];
    for (const part of ops.split(/(\[[^\]]*\]|\b(?:byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword|ptr|short|near|far)\b|\b0x[0-9a-f]+\b|\b\d+\b|\b[a-z][a-z0-9]*\b)/i)) {
      if (!part) continue;
      if (part[0] === '[') out.push(h('span.tk-mem', null, part));
      else if (REG.test(part)) out.push(h('span.tk-reg', null, part));
      else if (/^(0x[0-9a-f]+|[0-9a-f]+h?)$/i.test(part)) out.push(h('span.tk-imm', null, part)); // bare hex too (the disassembler may omit 0x)
      else if (/^(byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword|ptr|short|near|far)$/i.test(part)) out.push(h('span.tk-kw', null, part));
      else out.push(part);
    }
    return out;
  }

  // ---------- user comments and labels (saved with the table) ----------
  let userCmts = [], userSyms = [], cmtBy = new Map(), symBy = new Map(), exprAddr = new Map();
  /** Bookmarks [{address, name}] and their resolved addresses (BigInt | null), same order. */
  let bms = [], bmAt = [];
  const commentAt = (a) => cmtBy.get(big(a)) || '';
  const labelsAt = (a) => symBy.get(big(a)) || [];
  async function resolveUser() {
    const exprs = [...userCmts.map((c) => c.address), ...userSyms.map((x) => x.address), ...bms.map((b) => b.address)];
    const got = state.proc && exprs.length ? await api.resolveMany(exprs).catch(() => exprs.map(() => null)) : exprs.map(() => null);
    cmtBy = new Map(); symBy = new Map(); exprAddr = new Map(exprs.map((x, i) => [x, got[i] == null ? null : big(got[i])]));
    userCmts.forEach((c, i) => { if (got[i] != null) cmtBy.set(big(got[i]), c.comment); });
    userSyms.forEach((x, i) => { const a = got[userCmts.length + i]; if (a != null) symBy.set(big(a), [...(symBy.get(big(a)) || []), x.name]); });
    bmAt = bms.map((b, i) => { const a = got[userCmts.length + userSyms.length + i]; return a == null ? null : big(a); });
    daRender(); hxSchedule();
  }
  on('table:meta', (m) => {
    const c = m.disasm_comments || [], y = m.symbols || [], b = m.bookmarks || [];
    if (JSON.stringify([c, y, b]) === JSON.stringify([userCmts, userSyms, bms])) return;
    userCmts = c.map((x) => ({ ...x })); userSyms = y.map((x) => ({ ...x })); bms = b.map((x) => ({ ...x }));
    resolveUser();
  });
  /** Module-relative form (CE style) so the note survives a restart of the game. */
  function stableAddr(a) {
    const n = big(a), m = mods.find((x) => n >= big(x.base) && n < big(x.base) + BigInt(x.size));
    return m ? `"${m.name}"+${(n - big(m.base)).toString(16).toUpperCase()}` : fmtAddr(a);
  }
  async function editComment() {
    const d = daRows[daSel];
    if (!d) return;
    const v = await prompt(`Comment at ${fmtAddr(d.addr)}`, commentAt(d.addr), { label: 'Comment (empty removes it)', mono: false, hint: 'Saved with the cheat table (Cheat Engine: disassembler comments).' });
    da.focus();
    if (v == null) return;
    const a = big(d.addr), text = v.trim(), where = stableAddr(d.addr);
    await editTableMeta((t) => {
      t.disasm_comments = (t.disasm_comments || []).filter((c) => c.address !== where && exprAddr.get(c.address) !== a);
      if (text) t.disasm_comments.push({ address: where, comment: text });
    });
  }
  async function editLabel() {
    const d = daRows[daSel];
    if (!d) return;
    const had = labelsAt(d.addr)[0] || '';
    const v = await prompt(`Label at ${fmtAddr(d.addr)}`, had, { label: 'Name (empty removes it)', hint: 'Usable in every address field, e.g. ' + (had || 'player_update') + '+10. Saved with the cheat table.' });
    da.focus();
    if (v == null) return;
    const name = v.trim(), where = stableAddr(d.addr);
    if (name && !/^[A-Za-z_][\w.]*$/.test(name)) { toast('A label is letters, digits, _ and ., not starting with a digit'); return; }
    await editTableMeta((t) => {
      t.symbols = (t.symbols || []).filter((x) => x.name !== name && x.name !== had);
      if (name) t.symbols.push({ name, address: where });
    });
  }

  // ---------- code navigation ----------
  async function gotoFunctionStart() {
    const a = cur();
    if (!a) return;
    const f = await attempt(() => busy('Finding the function start', api.codeFunction(a)));
    if (!f) return;
    await daGoto(f.start);
    da.focus();
    toast(`${f.name || fmtAddr(f.start)}: ${f.source === 'dissection' ? 'function start from the code dissection' : 'guessed from the code (no dissection covers it; run Code analysis for exact starts)'}`, 'info');
  }
  async function branchTargets() {
    const a = cur();
    if (!a) return;
    const r = await attempt(() => busy('Finding call and jump targets', api.codeTargets(a)));
    if (!r) return;
    const KIND = { call: 'call', jump: 'jump', cond_jump: 'cond. jump' };
    const { dialog, body } = tools.listDialog(`Branches in the function at ${fmtAddr(r.start)}`);
    const host = h('div.tool-list');
    const list = vlist(host, {
      cols: '128px 84px minmax(0, 1.4fr) 128px minmax(0, 1fr)', head: ['From', 'Kind', 'Instruction', 'Target', 'Target name'], label: 'Call and jump targets',
      empty: 'This function has no direct calls or jumps.', count: () => r.rows.length, item: (i) => r.rows[i],
      cells: (x) => [fmtAddr(x.from), KIND[x.kind] || x.kind, h('span', { role: 'gridcell', class: 'c-text' }, ...highlight(x.text)), fmtAddr(x.to), x.name || ''],
      onActivate: (i, x, e) => { if (!x) return; dialog.close(); daGoto(e?.shiftKey ? x.from : x.to); da.focus(); },
    });
    body.append(h('p.hint', null, `${fmtAddr(r.start)} – ${fmtAddr(r.end)} · ${r.rows.length} branch${r.rows.length === 1 ? '' : 'es'} · ${r.source === 'dissection' ? 'from the code dissection' : 'function bounds guessed'} · `,
      h('kbd', null, 'Enter'), ' go to the target · ', h('kbd', null, 'Shift Enter'), ' go to the branch'), host);
    list.focus();
    if (r.rows.length) list.select(0);
  }

  // ---------- disassembler state messages ----------
  const daMsg = h('div.empty.mv-msg', { role: 'status', hidden: true });
  da.after(daMsg);
  function renderDaState() {
    const unread = daRows.length > 0 && daRows.every((r) => r.text === '??');
    const show = !state.proc || daTop == null || unread;
    daMsg.hidden = !show;
    da.classList.toggle('mv-dim', !state.proc);
    daMsg.classList.toggle('mv-strip', !!state.proc);
    if (!show) return;
    daMsg.replaceChildren(...(!state.proc
      ? [h('b', null, 'Memory viewer'), h('br'), 'Disassemble code, browse and edit bytes, set breakpoints and inspect regions of the target. Open a process with ', h('kbd', null, 'Ctrl P'), ' to start.']
      : daTop == null
      ? ['No code to show. Pick a module or an executable region on the right, or ', h('kbd', null, 'Ctrl G'), ' go to an address.']
      : [`Nothing readable at ${fmtAddr(daTop)}. Pick a module or an executable region on the right, or `, h('kbd', null, 'Ctrl G'), ' go to another address.']));
  }
  // ---------- disassembler: copy, info tip, search, view ----------
  /** The selected lines (disassembled again when the selection reaches past the screen). */
  async function selLines(intel = false) {
    const r = daRange();
    if (!r) return [];
    const [lo, hi] = r, shown = daRows.filter((d) => big(d.addr) >= lo && big(d.addr) <= hi);
    if (!(intel && att) && shown.length && big(shown[0].addr) === lo && big(shown.at(-1).addr) === hi) return shown;
    const rows = await api.disassemble(wire(lo), Math.min(2000, Number(hi - lo) + 1), intel ? null : dopts()).catch((e) => { toast(e); return []; });
    return rows.filter((d) => big(d.addr) <= hi);
  }
  async function daCopy(kind) {
    const rows = await selLines(kind === 'aob');
    if (!rows.length) return;
    const is64 = state.proc?.is_64bit !== false;
    const s = kind === 'text' ? rows.map((d) => `${(modRel ? relName(d.addr) : fmtAddr(d.addr)).padEnd(16)} ${d.bytes.padEnd(24)} ${d.text}${d.comment ? '  ; ' + d.comment : ''}`).join('\n')
      : kind === 'bytes' ? rows.map((d) => d.bytes).join(' ')
      : rows.map((d) => F.aobOf(d, is64)).join(' ');
    copyText(s, `${rows.length} line${rows.length > 1 ? 's' : ''} as ${{ text: 'text', bytes: 'bytes', aob: 'an AOB pattern' }[kind]}`);
  }

  // Info tip: the branch target's instruction, or the value (and string) at a static memory operand.
  const tip = h('div.da-tip.mono#da-tip', { role: 'tooltip', hidden: true });
  document.body.append(tip);
  let tipFor = null, hoverI = -1, tipTimer = 0;
  function hideTip() { clearTimeout(tipTimer); tipFor = null; hoverI = -1; tip.hidden = true; da.removeAttribute('aria-describedby'); }
  async function tipLines(d) {
    const t = branchTarget(d.text);
    if (t != null) {
      const [x] = await api.disassemble(wire(t), 1, dopts()).catch(() => []);
      const name = labelsAt(t)[0] || (x && fnCache.get(x.addr)) || relName(t);
      return [[h('span.muted', null, /^call/i.test(d.text) ? 'Calls ' : 'Jumps to '), fmtAddr(t), name !== fmtAddr(t) ? h('span.muted', null, ' · ' + excerpt(name, 60)) : ''],
        [x && x.text !== '??' ? h('span', null, ...highlight(x.text)) : 'unreadable']];
    }
    const m = F.memTarget(d);
    if (m == null) return null;
    const s = await api.readMemory(wire(m), 64).catch(() => null);
    const b = (s?.match(/../g) || []).map((x) => (x === '??' ? -1 : parseInt(x, 16)));
    const head = [h('span.muted', null, 'Memory at '), excerpt(relName(m), 60)];
    if (!b.length || b[0] < 0) return [head, ['unreadable']];
    const n = F.memSize(d.text), u8 = b.slice(0, n), out = [head];
    if (u8.length === n && !u8.includes(-1)) {
      const dv = new DataView(Uint8Array.from(u8).buffer);
      const v = n === 1 ? dv.getUint8(0) : n === 2 ? dv.getUint16(0, true) : n === 4 ? dv.getUint32(0, true) : dv.getBigUint64(0, true);
      out.push([`= ${v} (0x${v.toString(16).toUpperCase()})`, n === 4 ? h('span.muted', null, ` · float ${+dv.getFloat32(0, true).toPrecision(7)}`) : n === 8 ? h('span.muted', null, ` · double ${+dv.getFloat64(0, true).toPrecision(12)}`) : '']);
    }
    const str = F.stringAt(b);
    if (str) out.push([h('span.muted', null, str.wide ? 'UTF-16 text ' : 'Text '), `"${excerpt(str.text, 56)}"`]);
    return out;
  }
  async function showTip(i, how) {
    const d = daRows[i], r = rowEl(i);
    if (!d || !r) return;
    tipFor = d.addr;
    const lines = await tipLines(d).catch(() => null);
    if (tipFor !== d.addr || !rowEl(i)) return;
    if (!lines) { hideTip(); if (how === 'key') toast('No branch target or static memory operand on this line', 'info'); return; }
    tip.replaceChildren(...lines.map((l) => h('div', null, ...l)));
    tip.hidden = false;
    const rc = r.children[2].getBoundingClientRect(), tr = tip.getBoundingClientRect();
    tip.style.left = Math.max(8, Math.min(rc.left, innerWidth - tr.width - 8)) + 'px';
    tip.style.top = (rc.bottom + tr.height + 8 > innerHeight ? rc.top - tr.height - 4 : rc.bottom + 4) + 'px';
    if (how === 'key') da.setAttribute('aria-describedby', 'da-tip');
  }
  da.addEventListener('mouseover', (e) => {
    const r = e.target.closest('.da-row:not(.da-label)');
    if (!r || editing || +r.dataset.i === hoverI) return;
    hideTip();
    hoverI = +r.dataset.i;
    tipTimer = setTimeout(() => showTip(hoverI, 'hover'), 450);
  });
  da.addEventListener('mouseleave', hideTip);

  // Search over the module (or region) under the cursor; results step with F3 / Shift F3.
  let daFound = null; // {rows: [{addr, text}], i, what}
  async function daSearch() {
    const a = cur() ?? daTop;
    if (a == null) return;
    const n = big(a), m = mods.find((x) => n >= big(x.base) && n < big(x.base) + BigInt(x.size)), r = regionAt(n);
    const opts = [m && ['module', `Module ${excerpt(m.name, 40)} (${fmtSize(m.size)})`], r && ['region', `This region ${fmtAddr(r.start)} (${fmtSize(r.size)})`]].filter(Boolean);
    if (!opts.length) { toast('The cursor is not in a module or a mapped region'); return; }
    const last = store.get('da.find', { q: '', kind: 'text', scope: 'module' });
    const v = await tools.formDialog('Search the disassembly', [
      { name: 'q', label: 'Find', value: last.q, hint: 'Instruction text: any part, any case (call, eax,[rcx+10). Bytes: hex with ?? wildcards (48 8B ?? 05).' },
      { name: 'kind', label: 'Search by', type: 'select', value: last.kind, options: [['text', 'Instruction text'], ['aob', 'Bytes (AOB pattern)']] },
      { name: 'scope', label: 'Where', type: 'select', value: opts.some((o) => o[0] === last.scope) ? last.scope : opts[0][0], options: opts },
    ], { ok: 'Search' });
    da.focus();
    if (!v || !v.q) return;
    store.set('da.find', v);
    const s0 = v.scope === 'module' ? big(m.base) : big(r.start);
    let end = s0 + BigInt(v.scope === 'module' ? m.size : r.size), rows;
    if (v.kind === 'aob') {
      let pattern;
      try { pattern = F.parsePattern(v.q); } catch (e) { toast(e.message); return; }
      const got = await attempt(() => busy('Searching the bytes', api.memSearch({ start: wire(s0), end: wire(end), pattern, backward: false, limit: 1000 })));
      if (!got) return;
      rows = got.map((x) => ({ addr: x, text: '' }));
    } else {
      const cap = BigInt(64 << 20);
      if (end - s0 > cap) { end = s0 + cap; toast('Searched the first 64 MiB of the range (the most one search covers)', 'info'); }
      rows = await attempt(() => busy('Searching the disassembly', api.disasmSearch({ start: wire(s0), end: wire(end), text: v.q, limit: 1000 })));
      if (!rows) return;
    }
    daFound = { rows, i: -1, what: `"${excerpt(v.q, 40)}" in ${v.scope === 'module' ? excerpt(m.name, 40) : 'region ' + fmtAddr(r.start)}` };
    if (!rows.length) { toast(`No match for ${daFound.what}`, 'info'); return; }
    daResults();
  }
  function daResults() {
    const f = daFound;
    if (!f?.rows.length) { daSearch(); return; }
    const { dialog, body } = tools.listDialog(`Search results: ${f.what}`);
    const host = h('div.tool-list');
    const list = vlist(host, {
      cols: '128px minmax(0, 1fr) minmax(0, 1.4fr)', head: ['Address', 'Where', 'Instruction'], label: 'Search results',
      count: () => f.rows.length, item: (i) => f.rows[i],
      cells: (x) => [fmtAddr(x.addr), relName(x.addr), h('span', { role: 'gridcell', class: 'c-text' }, ...(x.text ? highlight(x.text) : ['(bytes match)']))],
      onActivate: (i, x) => { if (!x) return; dialog.close(); f.i = i; daGoto(x.addr); da.focus(); },
    });
    body.append(h('p.hint', null, `${f.rows.length} match${f.rows.length === 1 ? '' : 'es'}${f.rows.length >= 1000 ? ' (the first 1,000)' : ''} · `,
      h('kbd', null, 'Enter'), ' go to it · in the disassembler ', h('kbd', null, 'F3'), ' / ', h('kbd', null, 'Shift F3'), ' next / previous match'), host);
    list.focus();
    list.select(Math.max(0, f.i));
  }
  function daStep(dir) {
    const f = daFound;
    if (!f?.rows.length) { daSearch(); return; }
    f.i = (f.i + dir + f.rows.length) % f.rows.length;
    daGoto(f.rows[f.i].addr);
    toast(`Match ${f.i + 1} of ${f.rows.length}`, 'info');
  }

  // ---------- references by scanning (no dissection needed), assembly scan, symbols ----------
  let refTarget = null; // address (hex string) R / Shift R step through
  /** Next (dir 1) / previous (-1) instruction whose operand references refTarget; ask = choose a new target. */
  async function findRef(dir, ask = false) {
    const a = cur();
    if (a == null) return;
    if (ask || !refTarget) {
      const s = await prompt('Find instructions referencing an address', refTarget ? fmtAddr(refTarget) : fmtAddr(a), {
        label: 'Address or expression',
        hint: 'Scans the code from the cursor, up to 64 MiB each way: works without a code dissection. X lists every reference, but only inside a dissected module.',
      });
      da.focus();
      if (!s) return;
      const t = await attempt(() => api.resolveAddress(s));
      if (!t) return;
      refTarget = t;
    }
    const what = excerpt(relName(refTarget), 48);
    const r = await attempt(() => busy(`Looking for ${dir > 0 ? 'the next' : 'the previous'} reference to ${what}`, api.findReference(a, refTarget, dir > 0), { cancel: () => api.toolsCancel() }));
    if (r === undefined) return;
    if (r == null) { toast(`No instruction ${dir > 0 ? 'after' : 'before'} the cursor references ${what} (searched 64 MiB)`, 'info'); return; }
    await daGoto(r);
    da.focus();
    toast(`References ${what} · R next, Shift R previous`, 'info');
  }

  async function apiHook(a) {
    const script = await attempt(() => api.aaTemplate(a, 'api'));
    if (script) emit('table:script', { description: `API hook at ${relName(a)}`, script });
  }

  /** Instruction patterns (? one character, * any run, ; chains) over a module, a region or all code. */
  async function asmScan() {
    if (!state.proc) return;
    const a = cur() ?? daTop, n = a == null ? null : big(a);
    const m = n == null ? null : mods.find((x) => n >= big(x.base) && n < big(x.base) + BigInt(x.size)), r = regionAt(n);
    const scopes = [m && ['module', `Module ${excerpt(m.name, 40)} (${fmtSize(m.size)})`], r && ['region', `This region ${fmtAddr(r.start)} (${fmtSize(r.size)})`], ['all', 'All executable memory (slow)']].filter(Boolean);
    const last = store.get('da.asm', { pattern: '', scope: 'module' });
    const v = await tools.formDialog('Assembly scan', [
      { name: 'pattern', label: 'Instructions', value: last.pattern, placeholder: 'mov [r?x+*],e?x; ret', hint: '? matches one character, * any run of characters, ; chains instructions that follow each other. Intel syntax, any case.' },
      { name: 'scope', label: 'Where', type: 'select', value: scopes.some((o) => o[0] === last.scope) ? last.scope : scopes[0][0], options: scopes },
    ], { ok: 'Scan', text: 'Matches the disassembled text of every instruction, so it finds code a byte pattern cannot (any register, any offset). It is slower than an AOB search.' });
    da.focus();
    if (!v || !v.pattern) return;
    store.set('da.asm', v);
    const start = v.scope === 'module' ? big(m.base) : v.scope === 'region' ? big(r.start) : 0n;
    const end = v.scope === 'module' ? wire(start + BigInt(m.size)) : v.scope === 'region' ? wire(start + BigInt(r.size)) : '';
    const where = v.scope === 'module' ? excerpt(m.name, 40) : v.scope === 'region' ? 'region ' + fmtAddr(r.start) : 'all executable memory';
    const rows = [], what = `"${excerpt(v.pattern, 40)}" in ${where}`;
    let next = null, running = false;
    const { dialog, body } = tools.listDialog(`Assembly scan: ${excerpt(v.pattern, 50)}`);
    const strip = tools.progressStrip('Assembly scan progress');
    const host = h('div.tool-list'), info = h('p.hint', { role: 'status' });
    const more = h('button.btn', { type: 'button', hidden: true, onclick: () => scan(next) }, 'Find more ', h('kbd', null, 'Ctrl Enter'));
    const list = vlist(host, {
      cols: '128px minmax(0, 1fr) minmax(0, 1.6fr)', head: ['Address', 'Where', 'Instructions'], label: 'Assembly scan results',
      empty: () => (running ? 'Scanning…' : 'No match.'), count: () => rows.length, item: (i) => rows[i],
      cells: (x) => [fmtAddr(x.addr), relName(x.addr), h('span', { role: 'gridcell', class: 'c-text' }, ...highlight(x.text))],
      onActivate: (i, x) => { if (!x) return; daFound = { rows: rows.slice(), i, what }; dialog.close(); daGoto(x.addr); da.focus(); },
    });
    body.append(info, h('div.tool-bar', null, more), strip.wrap, host);
    // Esc cancels a running scan first; a second Esc closes the window.
    dialog.addEventListener('cancel', (e) => { if (running) { e.preventDefault(); tools.jobs.cancel(); } });
    dialog.addEventListener('close', () => { if (running) tools.jobs.cancel(); });
    dialog.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && next && !running) { e.preventDefault(); scan(next); } });
    async function scan(from) {
      running = true; more.disabled = true; list.refresh();
      const got = await tools.runJob(() => api.asmScan({ start: typeof from === 'string' ? from : wire(from), end, pattern: v.pattern, max: 1000 }), strip, 'Scanning');
      running = false; more.disabled = false;
      if (got) { rows.push(...got.hits); next = got.next; }
      more.hidden = !next;
      info.replaceChildren(`${rows.length.toLocaleString('en-US')} match${rows.length === 1 ? '' : 'es'} for ${what}${next ? ' so far (stopped at 1,000 per pass)' : ''} · `,
        h('kbd', null, 'Enter'), ' go to it · then ', h('kbd', null, 'F3'), ' / ', h('kbd', null, 'Shift F3'), ' step through them');
      list.refresh();
      if (dialog.open) { list.focus(); if (list.sel < 0 && rows.length) list.select(0); }
    }
    await scan(start);
  }

  /** Every known symbol (your labels and script symbols first, then the modules'), paged. */
  function symbolList() {
    if (!state.proc) return;
    const { dialog, body } = tools.listDialog('Symbols');
    const filt = h('input.mono', { type: 'text', placeholder: 'Filter by name (Ctrl F)', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Filter symbols' });
    const modSel = h('select', { 'aria-label': 'Module' }, h('option', { value: '' }, 'Your symbols and every module'), ...mods.map((x) => h('option', { value: x.name }, x.name)));
    const count = h('span.hint.mono', { role: 'status' });
    const src = pager((off, lim) => api.symbolList(modSel.value || null, filt.value, off, lim), (e) => { if (e) toast(e); count.textContent = `${src.count().toLocaleString('en-US')} symbol${src.count() === 1 ? '' : 's'}`; list.refresh(); });
    const host = h('div.tool-list');
    const list = vlist(host, {
      cols: '128px minmax(0, 1.6fr) minmax(0, 1fr) 80px', head: ['Address', 'Name', 'Module', 'Size'], label: 'Symbols',
      empty: 'No symbols match.', count: src.count, item: src.item,
      cells: (x) => [fmtAddr(x.addr), h('span', { role: 'gridcell', class: x.user ? 'sym-user' : '', title: x.user ? 'Your label or a script symbol' : '' }, x.name), x.module || '', x.size ? fmtSize(x.size) : ''],
      onActivate: (i, x) => { if (!x) return; dialog.close(); daGoto(x.addr); da.focus(); },
    });
    const reload = () => { src.reset(); list.refresh({ reset: true }); };
    filt.addEventListener('input', rafThrottle(reload));
    filt.addEventListener('keydown', (e) => { if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); list.focus(); list.select(Math.max(0, list.sel)); } });
    modSel.addEventListener('change', reload);
    dialog.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') { e.preventDefault(); filt.focus(); filt.select(); } });
    body.append(h('div.tool-bar.sym-bar', null, filt, modSel, count), h('p.hint', null, h('kbd', null, 'Enter'), ' disassembles at the symbol · ', h('kbd', null, '↓'), ' from the filter goes to the list'), host);
    reload();
    filt.focus();
  }

  function applyDaView() {
    da.classList.toggle('modrel', modRel);
    da.classList.toggle('nobytes', !showBytes);
    daRender();
  }
  function toggleModRel() { modRel = !modRel; store.set('da.modrel', modRel); applyDaView(); toast(modRel ? 'Addresses as module + offset' : 'Absolute addresses', 'info'); }
  function toggleBytes() { showBytes = !showBytes; store.set('da.bytes', showBytes); applyDaView(); }
  function toggleAtt() { att = !att; store.set('da.att', att); daLoad(); toast(att ? 'AT&T syntax (display only: assembling a line still takes Intel syntax)' : 'Intel syntax', 'info'); }
  function toggleTyped() { typed = !typed; store.set('da.typed', typed); daLoad(); }
  const daView = h('button.btn.ghost#da-view', { type: 'button', 'aria-haspopup': 'menu', title: 'View options: addresses, bytes, sync, text size, second viewer', html: icon('gear') }, h('span.bl', null, 'View'));
  daView.addEventListener('click', () => { const r = daView.getBoundingClientRect(); viewMenu(r.left, r.bottom + 4, da); });
  $('#da-goto').after(daView);
  $('#disasm-pane .hints').append(' · ', h('kbd', null, 'Ctrl F'), ' search · ', h('kbd', null, 'I'), ' info');
  function daMenu(x, y) {
    const a = cur(), att = !!state.dbg?.attached, d = daRows[daSel];
    contextMenu(x, y, [
      { label: 'Toggle breakpoint', kbd: 'F5', disabled: !a, run: () => emit('debug:toggle-bp', a) },
      { label: 'Run to cursor', kbd: 'F4', disabled: !a || state.dbg?.state !== 'broken', run: () => emit('debug:run-to', a) },
      { label: 'Run to cursor, this thread only', kbd: 'Shift F4', disabled: !a || state.dbg?.state !== 'broken', run: () => emit('debug:run-to-thread', a) },
      { label: 'Run until this is reached N times…', disabled: !a || state.dbg?.state !== 'broken', run: () => emit('debug:run-to-count', { addr: a }) },
      { label: 'Set instruction pointer here…', disabled: !a || state.dbg?.state !== 'broken', run: () => emit('debug:set-ip', { addr: a }) },
      { label: 'Find out what addresses this instruction accesses', disabled: !a || !/\[/.test(d?.text || ''), run: () => emit('debug:ea', { addr: a, text: d.text }) },
      { label: 'Break and trace…', disabled: !a, run: () => emit('debug:trace', { addr: a, text: d.text }) },
      { label: 'Set breakpoint…', disabled: !a, run: () => emit('debug:bp-dialog', a) },
      '-',
      { label: 'What references this address (from the code dissection)', kbd: 'X', disabled: !a, run: () => emit('code:xrefs', a) },
      { label: refTarget ? `Next instruction referencing ${excerpt(relName(refTarget), 32)} (scan)` : 'Next instruction referencing an address (scan)…', kbd: 'R', disabled: !a, run: () => findRef(1) },
      { label: 'Previous instruction referencing it (scan)', kbd: 'Shift R', disabled: !a || !refTarget, run: () => findRef(-1) },
      { label: 'Find references to another address (scan)…', kbd: 'Alt R', disabled: !a, run: () => findRef(1, true) },
      { label: 'Generate AOB signature', disabled: !a, run: () => tools.signatureDialog(a) },
      { label: 'Create AOB injection script', disabled: !a, run: () => tools.aobScript(a) },
      { label: 'Create code injection script', disabled: !a, run: () => tools.injectScript(a, 'code') },
      { label: 'Create full injection script', disabled: !a, run: () => tools.injectScript(a, 'full') },
      { label: 'Create API hook script', disabled: !a, run: () => apiHook(a) },
      '-',
      { label: 'Go to function start', kbd: 'Ctrl Home', disabled: !a, run: gotoFunctionStart },
      { label: 'Find call / jump targets…', kbd: 'T', disabled: !a, run: branchTargets },
      { label: commentAt(a || 0) ? 'Edit comment…' : 'Add comment…', kbd: ';', disabled: !a, run: editComment },
      { label: labelsAt(a || 0).length ? 'Rename label…' : 'Add label…', kbd: ':', disabled: !a, run: editLabel },
      '-',
      { label: 'Replace with code that does nothing', disabled: !a, run: () => emit('debug:nop', { addr: a, text: d.text }) },
      { label: 'Add to code list', disabled: !a, run: () => emit('debug:codelist', { addr: a, text: d.text, bytes: d.bytes }) },
      '-',
      { label: 'Assemble', kbd: 'Enter', disabled: !a, run: assembleLine },
      { label: 'Follow', kbd: 'Space', disabled: branchTarget(d?.text || '') == null, run: follow },
      { label: 'Show target / operand info', kbd: 'I', disabled: !a, run: () => showTip(daSel, 'key') },
      { label: 'Go to address…', kbd: 'Ctrl G', run: () => gotoPrompt('da') },
      '-',
      { label: daAnchor != null ? 'Copy the selected lines' : 'Copy this line', kbd: 'Ctrl C', disabled: !a, run: () => daCopy('text') },
      { label: 'Copy as bytes', disabled: !a, run: () => daCopy('bytes') },
      { label: 'Copy as AOB pattern (wildcards)', kbd: 'Ctrl Shift C', disabled: !a, run: () => daCopy('aob') },
      { label: 'Search the module…', kbd: 'Ctrl F', disabled: !a, run: daSearch },
      { label: daFound?.rows.length ? `Search results (${daFound.rows.length})…` : 'Search results…', kbd: 'F3', disabled: !daFound?.rows.length, run: daResults },
      { label: 'Assembly scan (instruction patterns)…', kbd: 'Ctrl Shift F', disabled: !state.proc, run: asmScan },
      { label: 'Symbol list…', kbd: 'N', disabled: !state.proc, run: symbolList },
      { label: 'Bookmark this line…', kbd: 'Ctrl B', disabled: !a, run: () => bmAdd(a, da) },
      { label: 'View…', run: () => { const r = (rowEl(daSel) || da).getBoundingClientRect(); viewMenu(r.left + 120, r.bottom, da); } },
      ...(att ? [] : ['-', { label: 'Attach debugger', kbd: 'Ctrl Shift D', run: () => emit('debug:attach') }]),
    ], da);
  }
  da.addEventListener('contextmenu', (e) => {
    const r = e.target.closest('.da-row:not(.da-label)');
    e.preventDefault();
    if (r && (daAnchor == null || !r.classList.contains('in-sel'))) { daAnchor = null; daSel = +r.dataset.i; daRender(); }
    daMenu(e.clientX, e.clientY);
  });
  /** Shift extends the line selection from where the cursor was; other moves drop it. */
  const daExtend = (ext) => { if (!ext) daAnchor = null; else if (daAnchor == null && cur() != null) daAnchor = big(cur()); };
  da.addEventListener('keydown', (e) => {
    const vis = Math.max(1, shownN), ctrl = e.ctrlKey || e.metaKey, plain = !ctrl && !e.altKey, k = e.key.toLowerCase();
    if (k !== 'i') hideTip();
    if (sharedKeys(e, 'da')) { /* handled */ }
    else if (e.key === 'ArrowDown' && !e.altKey) { daExtend(e.shiftKey); daSel < vis - 1 ? (daSel++, daRender()) : daScroll(1); }
    else if (e.key === 'ArrowUp' && !e.altKey) { daExtend(e.shiftKey); daSel > 0 ? (daSel--, daRender()) : daScroll(-1); }
    else if (e.key === 'PageDown') { daExtend(e.shiftKey); daScroll(vis - 1); }
    else if (e.key === 'PageUp') { daExtend(e.shiftKey); daScroll(-(vis - 1)); }
    else if (e.key === ' ') follow();
    else if (e.key === 'Backspace' || (e.altKey && e.key === 'ArrowLeft')) back();
    else if (e.altKey && e.key === 'ArrowRight') forward();
    else if (ctrl && e.shiftKey && k === 'f') asmScan();
    else if (ctrl && k === 'f') daSearch();
    else if (e.altKey && !ctrl && k === 'r') findRef(1, true);
    else if (!ctrl && !e.altKey && k === 'r') findRef(e.shiftKey ? -1 : 1);
    else if (plain && !e.shiftKey && k === 'n') symbolList();
    else if (e.key === 'F3' && !ctrl) daStep(e.shiftKey ? -1 : 1);
    else if (ctrl && k === 'c') daCopy(e.shiftKey ? 'aob' : 'text');
    else if (plain && k === 'm') toggleModRel();
    else if (plain && k === 'b') toggleBytes();
    else if (plain && k === 'i') tip.hidden ? showTip(daSel, 'key') : hideTip();
    else if (e.key === 'Escape' && daAnchor != null) { daAnchor = null; daRender(); }
    else if (e.key === 'Enter') assembleLine();
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'g') gotoPrompt('da');
    else if (e.key === 'F5' && cur()) emit('debug:toggle-bp', cur());
    else if (e.key === 'F4' && cur()) emit(e.shiftKey ? 'debug:run-to-thread' : 'debug:run-to', cur());
    else if (e.key.toLowerCase() === 'x' && !e.ctrlKey && cur()) emit('code:xrefs', cur());
    else if (e.key === 'Home' && (e.ctrlKey || e.metaKey)) gotoFunctionStart();
    else if (e.key.toLowerCase() === 't' && !e.ctrlKey && !e.altKey && !e.metaKey) branchTargets();
    else if (e.key === ';') editComment();
    else if (e.key === ':') editLabel();
    else if (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) {
      const r = (rowEl(daSel) || da).getBoundingClientRect();
      daMenu(r.left + 120, r.bottom);
    } else return;
    e.preventDefault(); e.stopPropagation();
  });
  da.addEventListener('wheel', (e) => { e.preventDefault(); hideTip(); daScroll(e.deltaY > 0 ? 3 : -3); }, { passive: false });
  da.addEventListener('mousedown', (e) => {
    const r = e.target.closest('.da-row:not(.da-label)');
    if (!r || e.button !== 0) return;
    daExtend(e.shiftKey);
    daSel = +r.dataset.i; daRender();
  });
  da.addEventListener('dblclick', (e) => { if (e.target.closest('.da-row')) assembleLine(); });
  $('#da-back').addEventListener('click', back);
  daFwd.addEventListener('click', forward);
  $('#da-goto').addEventListener('click', () => gotoPrompt('da'));

  // ---------- hex ----------
  let hxTop = null, hxCur = null, bytes = [], chgUntil = [], lastTop = null, nib = null;
  /** Selection anchor (Shift with arrows or click); the selection runs from it to the cursor. */
  let hxAnchor = null;
  const hxSel = () => (hxAnchor == null || hxCur == null || hxAnchor === hxCur ? null
    : hxAnchor < hxCur ? [hxAnchor, hxCur + BigInt(unit()) - 1n] : [hxCur, hxAnchor + BigInt(unit()) - 1n]);
  const unit = () => TYPES[hxType.value];
  // Bytes per row and the text column's encoding (remembered).
  let bpr = [8, 16, 32].includes(store.get('hx.bpr', 16)) ? store.get('hx.bpr', 16) : 16;
  let enc = ['ascii', 'utf8', 'utf16', 'none'].includes(store.get('hx.enc', 'ascii')) ? store.get('hx.enc', 'ascii') : 'ascii';
  const rowStart = (a) => a - (a % BigInt(bpr));
  const CELL_W = { 1: '2.4ch', 2: '7ch', 4: '13ch', 8: '22ch' };
  const decoders = { utf8: new TextDecoder('utf-8'), utf16: new TextDecoder('utf-16le') };
  /** The row's bytes as text in the chosen encoding; unreadable and control characters show as dots. */
  function textOf(base) {
    if (enc === 'none') return '';
    const raw = bytes.slice(base, base + bpr).map((b) => (b && b !== '??' ? parseInt(b, 16) : -1));
    if (enc === 'ascii') return raw.map((v) => (v >= 32 && v < 127 ? String.fromCharCode(v) : '.')).join('');
    const t = decoders[enc].decode(new Uint8Array(raw.map((v) => (v < 0 ? 0 : v))));
    return t.replace(/[\u0000-\u001f\u007f-\u009f\ufffd]/g, '.');
  }
  const opt = (v, l, cur) => h('option', { value: v, selected: String(v) === String(cur) }, l);
  const bprSel = h('select.compact#hx-bpr', { 'aria-label': 'Bytes per row', title: 'Bytes per row' }, [8, 16, 32].map((n) => opt(n, `${n}/row`, bpr)));
  const encSel = h('select.compact#hx-enc', { 'aria-label': 'Text column encoding', title: 'Text column' }, opt('ascii', 'ASCII', enc), opt('utf8', 'UTF-8', enc), opt('utf16', 'UTF-16LE', enc), opt('none', 'No text', enc));
  const hxBack = h('button.btn.ghost.icon', { type: 'button', disabled: true, 'aria-label': 'Back (Alt ←)', title: 'Back (Alt ← or Backspace)', html: icon('back') });
  const hxFwd = h('button.btn.ghost.icon', { type: 'button', disabled: true, 'aria-label': 'Forward (Alt →)', title: 'Forward (Alt →)', html: IC.fwd });
  const hxHist = navHistory(hxBack, hxFwd);
  const lockBtn = h('button.btn.ghost.icon#hx-lock', { type: 'button', 'aria-pressed': 'false' });
  $('#hx-goto').before(hxBack, hxFwd, bprSel, encSel, lockBtn);
  $('#hex-pane .hints').append(' · ', h('kbd', null, 'Ctrl F'), ' search · ', h('kbd', null, 'Ctrl B'), ' bookmark');
  bprSel.addEventListener('change', () => { bpr = +bprSel.value; store.set('hx.bpr', bpr); if (hxCur != null) hxTop = rowStart(hxCur); lastTop = null; hxLoad(); hx.focus(); });
  encSel.addEventListener('change', () => { enc = encSel.value; store.set('hx.enc', enc); hxRender(); hx.focus(); });
  const hxStatus = h('div.hx-status.mono', { role: 'status', 'aria-live': 'off' });
  hx.after(hxStatus);
  async function hxLoad() {
    if (hxTop == null) return;
    const top = hxTop, n = visOf(hx) * bpr + 8; // 8 more for the data inspector at the last row
    const s = await api.readMemory(wire(top), n).catch(() => null);
    if (s == null || top !== hxTop) return;
    const nb = s.match(/../g) || [];
    const now = performance.now();
    if (lastTop === top) nb.forEach((b, i) => { if (bytes[i] != null && b !== bytes[i]) chgUntil[i] = now + 1000; });
    else chgUntil = [];
    bytes = nb; lastTop = top;
    hxRender();
  }
  const hxPool = [];
  let builtFor = '';
  function cellText(i, u) {
    const g = bytes.slice(i, i + u);
    if (g.length < u) return '';
    if (u === 1) return g[0].toUpperCase();
    if (g.includes('??')) return '?'.repeat(Math.min(8, u * 2));
    const dv = new DataView(new Uint8Array(g.map((x) => parseInt(x, 16))).buffer);
    switch (hxType.value) {
      case '2bytes': return String(dv.getUint16(0, true));
      case '4bytes': return String(dv.getUint32(0, true));
      case '8bytes': return String(dv.getBigUint64(0, true));
      case 'float': return String(+dv.getFloat32(0, true).toPrecision(7));
      case 'double': return String(+dv.getFloat64(0, true).toPrecision(12));
    }
    return '';
  }
  function hxRender() {
    if (hxTop == null) return;
    const vis = visOf(hx), u = unit(), key = vis + ':' + u + ':' + bpr + ':' + enc;
    if (builtFor !== key) {
      builtFor = key;
      hxPool.length = 0;
      hx.replaceChildren();
      for (let r = 0; r < vis; r++) {
        const cells = [];
        for (let c = 0; c < bpr; c += u) cells.push(h('span.hb', { role: 'gridcell', 'data-o': c }));
        const row = h('div.hx-row', { role: 'row' }, h('span.c-addr', { role: 'rowheader' }),
          h('span.hx-bytes', { 'data-u': u, style: `grid-template-columns:repeat(${bpr / u}, ${CELL_W[u]})` }, cells), h('span.hx-ascii', { 'aria-hidden': 'true', hidden: enc === 'none' }));
        hxPool.push(row); hx.append(row);
      }
    }
    const now = performance.now(), curOff = hxCur != null ? Number(hxCur - hxTop) : -1, sel = hxSel();
    hxPool.forEach((row, r) => {
      const base = r * bpr, [a, bs, asc] = row.children;
      const t = fmtAddr(hxTop + BigInt(base));
      if (a.textContent !== t) a.textContent = t;
      for (const c of bs.children) {
        const i = base + +c.dataset.o, txt = cellText(i, u);
        if (c.textContent !== txt) c.textContent = txt;
        let chg = false;
        for (let k = 0; k < u; k++) if (chgUntil[i + k] > now) chg = true;
        c.classList.toggle('chg', chg);
        const isCur = curOff >= i && curOff < i + u, at = hxTop + BigInt(i);
        c.classList.toggle('cursor', isCur);
        c.classList.toggle('sel', !!sel && at >= sel[0] && at <= sel[1]);
        c.classList.toggle('pending', isCur && nib != null);
        c.classList.toggle('bm', bmAt.some((b) => b != null && b >= at && b < at + BigInt(u)));
        if (isCur) { c.id = 'hx-cur'; } else if (c.id) c.removeAttribute('id');
      }
      const s = textOf(base);
      if (asc.textContent !== s) asc.textContent = s;
    });
    hx.setAttribute('aria-activedescendant', curOff >= 0 ? 'hx-cur' : '');
    $('#hx-pos').textContent = sel ? `${fmtAddr(sel[0])} · ${Number(sel[1] - sel[0] + 1n)} bytes` : hxCur != null ? fmtAddr(hxCur) : '';
    renderStatus();
    renderInsp();
    syncFromHx();
  }
  /** Status line: protection and kind / path of the region under the cursor. */
  function renderStatus() {
    if (!state.proc) { hxStatus.replaceChildren('No process. ', h('kbd', null, 'Ctrl P'), ' opens one.'); hxStatus.classList.remove('err'); return; }
    const r = regionAt(hxCur);
    const unread = bytes.length > 0 && bytes.every((b) => b === '??');
    const sel = hxSel(), lead = sel ? `${Number(sel[1] - sel[0] + 1n)} bytes selected · ` : '';
    const t = lead + (hxCur == null ? 'Pick a region on the right or press Ctrl G to browse memory.' : !r ? `${fmtAddr(hxCur)} · not in a mapped region${unread ? ' · unreadable' : ''}`
      : `${fmtAddr(hxCur)} · ${r.prot_text.slice(0, 3)} · ${r.tag}${r.module ? ' · ' + r.module : ''}${r.path ? ' · ' + r.path : r.module ? '' : ' · ' + String(r.kind).toLowerCase()} · region ${fmtAddr(r.start)} +${fmtSize(r.size)}${unread ? ' · unreadable' : ''}`) + (locked ? ' · editing locked' : '');
    if (hxStatus.textContent !== t) hxStatus.textContent = t;
    hxStatus.classList.toggle('err', unread);
  }
  const hxSchedule = rafThrottle(hxRender);
  /** A jump the back button returns from (go to, follow, search hits, bookmarks). */
  function hxJump(addr) {
    if (hxCur != null && big(addr) !== hxCur) hxHist.push(hxCur);
    hxGoto(addr);
  }
  function hxGoto(addr) {
    hxAnchor = null;
    hxCur = big(addr);
    hxTop = rowStart(hxCur);
    nib = null;
    hxLoad();
  }
  function hxMove(delta, extend = false) {
    if (hxCur == null) return;
    if (extend) hxAnchor ??= hxCur; else hxAnchor = null;
    const n = hxCur + BigInt(delta);
    hxCur = n < 0n ? 0n : n;
    nib = null;
    const vis = BigInt(visOf(hx) * bpr);
    if (hxCur < hxTop) hxTop = rowStart(hxCur);
    else if (hxCur >= hxTop + vis) hxTop = rowStart(hxCur) - vis + BigInt(bpr);
    if (hxTop !== lastTop) hxLoad(); else hxSchedule();
  }
  async function hxEditValue() {
    if (hxCur == null || !canEdit()) return;
    const u = unit(), t = hxType.value, at = hxCur - (hxCur % BigInt(u));
    const cur = cellText(Number(at - hxTop), u);
    const v = await prompt(`Edit ${t === 'byte' ? 'byte' : t} at ${fmtAddr(at)}`, cur, { label: t === 'byte' ? 'Hex byte' : 'Value' });
    hx.focus();
    if (v == null) return;
    await attempt(() => (t === 'byte' ? api.writeBytes(wire(at), v.trim().padStart(2, '0')) : api.writeValue(wire(at), t, v)));
    hxLoad();
  }
  hx.addEventListener('keydown', async (e) => {
    const u = unit(), vis = visOf(hx), ctrl = e.ctrlKey || e.metaKey, k = e.key.toLowerCase();
    const ext = e.shiftKey;
    if (sharedKeys(e, 'hx')) { /* handled */ }
    else if (e.key === 'ArrowRight' && !e.altKey) hxMove(u, ext);
    else if (e.key === 'ArrowLeft' && !e.altKey) hxMove(-u, ext);
    else if (e.key === 'Backspace' || (e.altKey && e.key === 'ArrowLeft')) hxBackFwd(-1);
    else if (e.altKey && e.key === 'ArrowRight') hxBackFwd(1);
    else if (ctrl && !e.shiftKey && k === 'f') hxSearchDialog();
    else if (e.key === 'F3' && !ctrl) hxFind(e.shiftKey ? -1 : 1);
    else if (ctrl && !e.shiftKey && k === 'c') hxCopy('hex');
    else if (ctrl && k === 'v') { pasteAsText = e.shiftKey; armPaste(); return; } // the paste event follows
    else if (e.key === ' ' && hxCur != null) followPointer();
    else if (e.key === 'Insert') addToTable();
    else if (e.key === 'Escape' && nib == null && hxAnchor != null) { hxAnchor = null; hxSchedule(); }
    else if (e.key === 'ArrowDown') hxMove(bpr, ext);
    else if (e.key === 'ArrowUp') hxMove(-bpr, ext);
    else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'r') watchSel();
    else if (e.key === 'PageDown') { hxTop += BigInt(vis * bpr); hxMove(vis * bpr); }
    else if (e.key === 'PageUp') { hxTop = hxTop > BigInt(vis * bpr) ? hxTop - BigInt(vis * bpr) : 0n; hxMove(-vis * bpr); }
    else if (e.key === 'Enter') hxEditValue();
    else if (e.key === 'F5') breakHere(hxCurWire());
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'g') gotoPrompt('hx');
    else if (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) { const r = ($('#hx-cur') || hx).getBoundingClientRect(); hxMenu(r.left, r.bottom); }
    else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'f') fill();
    else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'c') copyMem();
    else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 's') tools.snapshotsDialog({ at: hxCurWire(), region: regionAt(hxCur) });
    else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'p') tools.pointersDialog(hxCurWire());
    else if (u === 1 && /^[0-9a-f]$/i.test(e.key) && !e.ctrlKey && !e.altKey && !e.metaKey && hxCur != null) {
      if (!canEdit()) { /* refused with a toast */ } else if (nib == null) { nib = e.key; hxSchedule(); }
      else {
        const v = nib + e.key, at = hxCur;
        nib = null;
        if (await attempt(async () => { await api.writeBytes(wire(at), v); return true; })) { lastTop = null; hxMove(1); }
        else hxSchedule();
      }
    } else if (e.key === 'Escape' && nib != null) { nib = null; hxSchedule(); }
    else return;
    e.preventDefault(); e.stopPropagation();
  });
  hx.addEventListener('wheel', (e) => {
    e.preventDefault();
    if (hxTop == null) return;
    const d = BigInt((e.deltaY > 0 ? 3 : -3) * bpr);
    hxTop = hxTop + d < 0n ? 0n : hxTop + d;
    hxLoad();
  }, { passive: false });
  hx.addEventListener('mousedown', (e) => {
    const c = e.target.closest('.hb');
    if (!c) return;
    const r = hxPool.indexOf(c.closest('.hx-row'));
    if (e.shiftKey) hxAnchor ??= hxCur; else hxAnchor = null;
    hxCur = hxTop + BigInt(r * bpr + +c.dataset.o);
    nib = null;
    hxSchedule();
  });
  /** Range watch over the selection (or the value under the cursor). */
  function watchSel(kind = 'write') {
    const sel = hxSel();
    if (hxCur == null) return;
    emit('debug:watch-range', sel ? { addr: wire(sel[0]), len: Number(sel[1] - sel[0] + 1n), kind } : { addr: wire(hxCur), len: unit() === 1 ? 4 : unit(), kind });
  }
  hx.addEventListener('dblclick', (e) => { if (e.target.closest('.hb')) hxEditValue(); });
  const hxCurWire = () => (hxCur != null ? wire(hxCur) : null);
  const after = (p) => p.then((ok) => { if (ok) { lastTop = null; hxLoad(); } hx.focus(); });
  const fill = () => canEdit() && after(tools.fillDialog(hxCurWire()));
  const copyMem = () => canEdit() && after(tools.copyDialog(hxCurWire()));
  function hxMenu(x, y) {
    const a = hxCurWire(), r = regionAt(hxCur);
    contextMenu(x, y, [
      { label: 'Edit value', kbd: 'Enter', disabled: !a || locked, run: hxEditValue },
      { label: 'Set breakpoint here', kbd: 'F5', disabled: !a, run: () => breakHere(a) },
      { label: 'Go to address…', kbd: 'Ctrl G', run: () => gotoPrompt('hx') },
      { label: 'Follow pointer', kbd: 'Space', disabled: !a, run: followPointer },
      { label: 'Disassemble here', disabled: !a, run: () => daGoto(a) },
      { label: `Add to the table as ${hxType.selectedOptions[0].textContent}`, kbd: 'Ins', disabled: !a, run: addToTable },
      '-',
      { label: 'Search memory…', kbd: 'Ctrl F', disabled: !a, run: hxSearchDialog },
      { label: 'Find next', kbd: 'F3', disabled: !a || !hxFindLast, run: () => hxFind(1) },
      { label: 'Find previous', kbd: 'Shift F3', disabled: !a || !hxFindLast, run: () => hxFind(-1) },
      { label: hxSel() ? 'Copy the selection as hex' : 'Copy as hex', kbd: 'Ctrl C', disabled: !a, run: () => hxCopy('hex') },
      { label: hxSel() ? 'Copy the selection as text' : 'Copy as text', disabled: !a, run: () => hxCopy('text') },
      { label: 'Paste hex or text…', kbd: 'Ctrl V', disabled: !a || locked, run: pasteDialog },
      { label: 'Bookmark this address…', kbd: 'Ctrl B', disabled: !a, run: () => bmAdd(a, hx) },
      { label: 'Bookmarks…', kbd: 'Ctrl Shift B', run: bmList },
      { label: 'Data inspector', kbd: 'Ctrl I', checked: inspOn, run: toggleInsp },
      { label: 'Lock editing', kbd: 'Ctrl L', checked: locked, run: toggleLock },
      { label: 'View…', run: () => { const r = ($('#hx-cur') || hx).getBoundingClientRect(); viewMenu(r.left, r.bottom, hx); } },
      '-',
      { label: 'Open in structure dissector', disabled: !a, run: () => emit('struct:open', { addr: a }) },
      { label: 'Find what points to this address…', kbd: 'Ctrl Shift P', disabled: !a, run: () => tools.pointersDialog(a) },
      { label: 'What references this address (code)', disabled: !a, run: () => emit('code:xrefs', a) },
      { label: 'Find out what accesses this address', disabled: !a, run: () => emit('debug:accesses', { addr: a, vtype: hxType.value === 'byte' ? '4bytes' : hxType.value }) },
      { label: 'Find out what writes to this address', disabled: !a, run: () => emit('debug:writes', { addr: a, vtype: hxType.value === 'byte' ? '4bytes' : hxType.value }) },
      { label: hxSel() ? 'Watch the selected range for writes…' : 'Watch a range for writes…', kbd: 'Ctrl Shift R', disabled: !a, run: () => watchSel('write') },
      { label: hxSel() ? 'Watch the selected range for accesses…' : 'Watch a range for accesses…', disabled: !a, run: () => watchSel('access') },
      '-',
      { label: 'Fill memory…', kbd: 'Ctrl Shift F', disabled: !state.proc, run: fill },
      { label: 'Copy memory…', kbd: 'Ctrl Shift C', disabled: !state.proc, run: copyMem },
      { label: 'Snapshots and compare…', kbd: 'Ctrl Shift S', disabled: !state.proc, run: () => tools.snapshotsDialog({ at: a, region: r }) },
      { label: 'Save this region to a file…', disabled: !r, run: () => tools.saveRegions([{ start: r.start, size: r.size }], 'region ' + fmtAddr(r.start)) },
      { label: 'Load memory file…', disabled: !state.proc, run: () => canEdit() && after(tools.loadMemoryFile()) },
      { label: 'Compare with saved file…', disabled: !state.proc, run: compareFile },
      { label: 'Search in a memory file…', run: () => tools.searchFileDialog() },
      { label: 'Region statistics…', disabled: !state.proc, run: () => tools.regionStatsDialog() },
      '-',
      { label: 'Allocate memory…', disabled: !state.proc, run: () => tools.allocDialog().then((p) => { if (p) hxGoto(p); hx.focus(); }) },
      { label: 'Free memory…', disabled: !state.proc, run: () => tools.freeDialog(a).then(() => { lastTop = null; hxLoad(); hx.focus(); }) },
    ], hx);
  }
  /** Plain execute breakpoint on the byte under the cursor (debugger is local only). */
  async function breakHere(a) {
    if (!a) return;
    if (state.proc?.remote) { toast(`The debugger works on local processes only; this target is on ${state.proc.remote}`); return; }
    if (!state.dbg?.attached) { toast('Attach the debugger first (Ctrl Shift D), then set the breakpoint', 'info'); return; }
    const id = await attempt(() => api.debugAddBreakpoint({ addr: a, kind: 'execute', size: 1, method: state.settings.bp_method || 'software', action: 'break', steps: 0, step_over_calls: false, ea: false }));
    if (id == null) return;
    emit('debug:bps-changed');
    toast(`Breakpoint set at ${fmtAddr(a)}`, 'info');
  }
  /** Live memory against a saved .hhmem file: the ranges that differ. */
  async function compareFile() {
    const p = await askPath({ save: false, title: 'Compare with saved memory file', filters: [['HeapHook memory', ['hhmem']], ['All files', ['*']]], dflt: 'memory.hhmem' });
    if (!p) { hx.focus(); return; }
    const diffs = await attempt(() => busy('Comparing memory with the file', api.memCompare(p)));
    if (!diffs) { hx.focus(); return; }
    const { dialog, body } = tools.listDialog(`Differences from ${p.replace(/^.*[\\/]/, '')}`);
    const host = h('div.tool-list');
    const list = vlist(host, {
      cols: '128px 64px minmax(0, 1fr) minmax(0, 1fr)', head: ['Address', 'Bytes', 'In the file', 'Now'], label: 'Differences',
      empty: 'No differences: live memory matches the file.', count: () => diffs.length, item: (i) => diffs[i],
      cells: (d) => [fmtAddr(d.addr), String(d.len), d.old, h('span', { role: 'gridcell', class: 'chg' }, d.new || 'unreadable')],
      onActivate: (i, d) => { if (!d) return; dialog.close(); hxGoto(d.addr); hx.focus(); },
    });
    body.append(h('p.hint', null, `${diffs.length} differing range${diffs.length === 1 ? '' : 's'}${diffs.length >= 10000 ? ' (first 10,000)' : ''} · `, h('kbd', null, 'Enter'), ' shows it in the hex view'), host);
    list.focus();
    if (diffs.length) list.select(0);
  }
  hx.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    const c = e.target.closest('.hb');
    if (c) {
      const r = hxPool.indexOf(c.closest('.hx-row')), at = hxTop + BigInt(r * bpr + +c.dataset.o), sel = hxSel();
      // Right-clicking inside the selection keeps it.
      if (!sel || at < sel[0] || at > sel[1]) { hxAnchor = null; hxCur = at; }
      nib = null; hxSchedule();
    }
    hxMenu(e.clientX, e.clientY);
  });
  $('#hx-tools').addEventListener('click', () => { const r = $('#hx-tools').getBoundingClientRect(); hxMenu(r.left, r.bottom + 4); });
  hxType.addEventListener('change', () => { if (hxCur != null) hxCur -= hxCur % BigInt(unit()); hxRender(); });
  $('#hx-goto').addEventListener('click', () => gotoPrompt('hx'));
  new ResizeObserver(() => { hxSchedule(); hxLoad(); daLoad(); }).observe($('#view-mem'));

  // ---------- hex: search, copy / paste, pointers, table ----------
  function hxBackFwd(dir) { const p = dir < 0 ? hxHist.back(hxCur) : hxHist.fwd(hxCur); if (p != null) hxGoto(p); }
  hxBack.addEventListener('click', () => { hxBackFwd(-1); hx.focus(); });
  hxFwd.addEventListener('click', () => { hxBackFwd(1); hx.focus(); });
  let hxFindLast = null; // {pattern, what}
  const FIND_KINDS = [['bytes', 'Bytes (hex, ?? = any byte)'], ['utf8', 'Text, UTF-8'], ['utf16', 'Text, UTF-16'], ['byte', 'Value: byte'], ['2bytes', 'Value: 2 bytes'],
    ['4bytes', 'Value: 4 bytes'], ['8bytes', 'Value: 8 bytes'], ['float', 'Value: float'], ['double', 'Value: double']];
  async function hxSearchDialog() {
    if (hxCur == null) return;
    const last = store.get('hx.find', { q: '', kind: 'bytes' });
    const v = await tools.formDialog('Search memory', [
      { name: 'q', label: 'Find', value: last.q, hint: 'From the cursor on, through all readable memory. Text matches case exactly; values are little-endian and exact (a float matches its exact bits).' },
      { name: 'kind', label: 'As', type: 'select', value: last.kind, options: FIND_KINDS },
    ], { ok: 'Find' });
    hx.focus();
    if (!v || !v.q) return;
    store.set('hx.find', v);
    let pattern;
    try { pattern = v.kind === 'bytes' ? F.parsePattern(v.q) : F.toHex(v.kind.startsWith('utf') ? F.textBytes(v.q, v.kind) : F.valueBytes(v.kind, v.q)); } catch (e) { toast(e.message); return; }
    hxFindLast = { pattern, what: `"${excerpt(v.q, 40)}"` };
    hxFind(1);
  }
  /** Next (1) or previous (-1) match from the cursor; the match is selected. */
  async function hxFind(dir) {
    if (hxCur == null) return;
    if (!hxFindLast) { hxSearchDialog(); return; }
    const f = hxFindLast, from = dir > 0 ? hxCur + 1n : hxCur;
    const got = await attempt(() => busy(`Searching memory for ${f.what}`, api.memSearch({ start: wire(from), end: null, pattern: f.pattern, backward: dir < 0, limit: 1 })));
    if (!got) return;
    if (!got.length) { toast(`No ${dir > 0 ? 'later' : 'earlier'} match for ${f.what}`, 'info'); return; }
    const a = big(got[0]), end = a + BigInt(f.pattern.split(' ').length) - 1n, u = BigInt(unit());
    hxJump(a);
    if (end - (end % u) > a) { hxAnchor = end - (end % u); hxSchedule(); }
  }
  async function hxCopy(kind) {
    if (hxCur == null) return;
    const sel = hxSel(), at = sel ? sel[0] : hxCur, n = sel ? Number(sel[1] - sel[0] + 1n) : unit();
    if (n > 0x100000) { toast('Copy at most 1 MiB at a time (Tools > Save region for more)'); return; }
    const s = await attempt(() => api.readMemory(wire(at), n));
    if (s == null) return;
    const b = s.match(/../g) || [];
    if (kind === 'hex') { copyText(b.join(' '), `${n} byte${n > 1 ? 's' : ''} as hex`); return; }
    const wide = enc === 'utf16', t = new TextDecoder(wide ? 'utf-16le' : 'utf-8').decode(Uint8Array.from(b, (x) => (x === '??' ? 0 : parseInt(x, 16))));
    copyText(t.replace(/\u0000/g, ''), `${n} byte${n > 1 ? 's' : ''} as ${wide ? 'UTF-16' : 'UTF-8'} text`);
  }
  // Ctrl V: the browser's paste event carries the clipboard; reading it directly is the fallback.
  let pasteAsText = false, pasteTimer = 0;
  function armPaste() {
    clearTimeout(pasteTimer);
    pasteTimer = setTimeout(async () => {
      const t = await navigator.clipboard?.readText?.().catch(() => null);
      t != null ? pasteText(t, pasteAsText) : pasteDialog();
    }, 150);
  }
  document.addEventListener('paste', (e) => {
    if (document.activeElement !== hx) return;
    clearTimeout(pasteTimer);
    e.preventDefault();
    pasteText(e.clipboardData?.getData('text/plain') || '', pasteAsText);
  });
  const textEnc = () => (enc === 'utf16' ? 'utf16' : 'utf8');
  /** Clipboard text as hex bytes when it reads as hex (unless asText), else as text in the text column's encoding. */
  function pasteText(t, asText) {
    if (!t) { toast('The clipboard has no text', 'info'); return; }
    let u8 = null;
    if (!asText) try { u8 = F.hexBytes(t); } catch { /* not hex: text */ }
    writeAt(u8 || F.textBytes(t, textEnc()), u8 ? 'hex bytes' : textEnc() === 'utf16' ? 'UTF-16 text' : 'UTF-8 text');
  }
  async function pasteDialog() {
    if (hxCur == null || !canEdit()) return;
    const clip = (await navigator.clipboard?.readText?.().catch(() => '')) || '';
    let auto = textEnc();
    try { F.hexBytes(clip); auto = 'hex'; } catch { /* text */ }
    const v = await tools.formDialog(`Paste at ${fmtAddr(hxSel()?.[0] ?? hxCur)}`, [
      { name: 'q', label: 'Hex bytes or text', value: clip.slice(0, 4096) },
      { name: 'kind', label: 'Paste as', type: 'select', value: auto, options: [['hex', 'Hex bytes'], ['utf8', 'Text, UTF-8'], ['utf16', 'Text, UTF-16']] },
    ], { ok: 'Paste' });
    hx.focus();
    if (!v || !v.q) return;
    let u8;
    try { u8 = v.kind === 'hex' ? F.hexBytes(v.q) : F.textBytes(v.q, v.kind); } catch (e) { toast(e.message); return; }
    writeAt(u8, v.kind === 'hex' ? 'hex bytes' : v.kind === 'utf16' ? 'UTF-16 text' : 'UTF-8 text');
  }
  /** Writes at the selection (or the cursor); asks first when it is more than the selection. */
  async function writeAt(u8, what) {
    if (hxCur == null || !canEdit()) return;
    if (u8.length > 0x10000) { toast('Paste at most 64 KiB at a time'); return; }
    const sel = hxSel(), at = sel ? sel[0] : hxCur, room = sel ? Number(sel[1] - sel[0] + 1n) : 0;
    if (u8.length > room) {
      const r = await modal({
        title: `Write ${u8.length} byte${u8.length > 1 ? 's' : ''}?`,
        text: `Pasting ${what} writes ${u8.length} byte${u8.length > 1 ? 's' : ''} at ${fmtAddr(at)}${sel ? `, more than the ${room} selected` : ''}. The target's memory changes right away.`,
        pre: F.toHex(u8.slice(0, 512)) + (u8.length > 512 ? ` … and ${u8.length - 512} more` : ''),
        buttons: [{ label: 'Write', value: 'ok', primary: true, kbd: 'Enter' }, { label: 'Cancel', value: 'cancel', kbd: 'Esc' }],
      });
      hx.focus();
      if (r.value !== 'ok') return;
    }
    if (await attempt(async () => { await api.writeBytes(wire(at), F.toHex(u8).replace(/ /g, '')); return true; })) {
      lastTop = null; hxLoad();
      toast(`Wrote ${u8.length} byte${u8.length > 1 ? 's' : ''} at ${fmtAddr(at)}`, 'info');
    }
  }
  /** Jumps to the pointer (4 or 8 bytes, the target's width) under the cursor. */
  async function followPointer() {
    if (hxCur == null) return;
    const s = await attempt(() => api.readMemory(hxCurWire(), state.proc?.is_64bit === false ? 4 : 8));
    if (s == null) return;
    if (s.includes('??')) { toast('The pointer is unreadable'); return; }
    const v = BigInt('0x' + s.match(/../g).reverse().join(''));
    if (!regionAt(v)) { toast(`${fmtAddr(v)} is not in a mapped region`, 'info'); return; }
    hxJump(v);
  }
  function addToTable() {
    if (hxCur == null) return;
    const at = hxSel()?.[0] ?? hxCur - (hxCur % BigInt(unit())), t = hxType.selectedOptions[0].textContent;
    emit('table:add', [{ description: `Memory viewer ${relName(at)}`, addr: fmtAddr(at), vtype: hxType.value }]);
    toast(`Added ${fmtAddr(at)} to the table as ${t}`, 'info');
  }

  // ---------- lock, data inspector, text size, sync ----------
  let locked = !!store.get('hx.locked', false);
  function renderLock() {
    const l = locked ? 'Editing locked (Ctrl L unlocks)' : 'Editing unlocked (Ctrl L locks)';
    lockBtn.setAttribute('aria-pressed', String(locked));
    lockBtn.setAttribute('aria-label', l);
    lockBtn.title = l;
    lockBtn.innerHTML = locked ? IC.lock : IC.unlock;
    lockBtn.classList.toggle('has', locked);
  }
  function toggleLock() { locked = !locked; store.set('hx.locked', locked); renderLock(); toast(locked ? 'Hex editing locked' : 'Hex editing unlocked', 'info'); }
  lockBtn.addEventListener('click', toggleLock);
  renderLock();
  /** False (with a toast) while hex editing is locked. */
  function canEdit() { if (locked) toast('Editing is locked. Ctrl L in the hex view (or the lock button) unlocks it.'); return !locked; }

  let inspOn = !!store.get('hx.insp', false), inspKey = '';
  const insp = h('div.hx-insp.mono', { role: 'group', 'aria-label': 'Data inspector: the bytes at the cursor', hidden: true });
  hxStatus.before(insp);
  function renderInsp() {
    insp.hidden = !inspOn || hxCur == null;
    if (insp.hidden) return;
    const off = hxTop != null ? Number(hxCur - hxTop) : -1;
    const raw = off >= 0 ? bytes.slice(off, off + 8).map((b) => (b === '??' ? -1 : parseInt(b, 16))) : [];
    const key = raw.join(',');
    if (key === inspKey) return;
    inspKey = key;
    insp.replaceChildren(h('div.cv-legend.muted', { 'aria-hidden': 'true' }, 'little endian', h('span.cv-be', null, 'big endian')),
      ...F.convRows(raw.length ? raw : null).map(([k, le, be]) => h('div.cv-item', null, h('span.cv-k', null, k), h('span.cv-v', null, le),
        be != null ? h('span.cv-v.cv-be', null, h('span.sr-only', null, 'big endian '), be) : h('span.cv-v.cv-be', { 'aria-hidden': 'true' }))));
  }
  function toggleInsp() { inspOn = !inspOn; store.set('hx.insp', inspOn); inspKey = ''; renderInsp(); hxLoad(); }

  const FS_DEFAULT = 12;
  let fs = Math.max(11, Math.min(16, +store.get('mem.fs', FS_DEFAULT) || FS_DEFAULT));
  function applyFs() {
    ROW = fs + 8;
    const v = $('#view-mem');
    v.style.setProperty('--row-mem', ROW + 'px');
    v.style.setProperty('--mem-fs', fs + 'px');
  }
  function setFs(n) {
    const was = fs;
    fs = Math.max(11, Math.min(16, n));
    store.set('mem.fs', fs);
    applyFs();
    builtFor = ''; hxLoad(); daLoad(); mv2.refresh();
    toast(fs === was ? `Text size stays ${fs}px (11 to 16)` : `Text size ${fs}px`, 'info');
  }
  applyFs();

  // Sync: moving in one pane moves the other to the same address (compared by address, so no ping-pong).
  let syncOn = !!store.get('mem.sync', false), lastDa = null, lastHx = null;
  function toggleSync(from) {
    syncOn = !syncOn; store.set('mem.sync', syncOn); lastDa = lastHx = null;
    toast(syncOn ? 'Disassembler and hex view move together' : 'Disassembler and hex view move separately', 'info');
    if (syncOn) from === 'hx' ? syncFromHx() : syncFromDa();
  }
  function syncFromDa() {
    if (!syncOn || editing) return;
    const a = cur();
    if (a == null || big(a) === lastDa) return;
    lastDa = big(a);
    if (hxCur !== lastDa) { lastHx = lastDa; hxGoto(lastDa); }
  }
  function syncFromHx() {
    if (!syncOn || hxCur == null || hxCur === lastHx || !daRows.length) return;
    lastHx = hxCur;
    const i = daRows.findIndex((r, k) => k < shownN && big(r.addr) <= hxCur && daRows[k + 1] && hxCur < big(daRows[k + 1].addr));
    if (i >= 0) { lastDa = big(daRows[i].addr); if (i !== daSel) { daSel = i; daAnchor = null; daRender(); } } else { lastDa = hxCur; daGoto(hxCur, { push: false }); }
  }

  // ---------- bookmarks (saved with the table: bookmarks [{address, name}]) ----------
  const digit = (n) => (n + 1) % 10;
  /** Bookmark slot of a digit key (1 -> 0 ... 0 -> 9), by key position so any layout works. */
  const slotOf = (code) => { const m = /^Digit(\d)$/.exec(code || ''); return m ? (+m[1] + 9) % 10 : -1; };
  function bmGo(n, pane) {
    const b = bms[n], a = bmAt[n];
    if (!b) { toast(`No bookmark ${digit(n)}. Ctrl Shift ${digit(n)} sets it at the cursor.`, 'info'); return; }
    if (a == null) { toast(`Bookmark "${excerpt(b.name, 40)}" (${excerpt(b.address, 40)}) does not resolve in this process`); return; }
    pane === 'da' ? daGoto(a) : hxJump(a);
  }
  const bmRemove = (address) => attempt(() => editTableMeta((t) => { t.bookmarks = (t.bookmarks || []).filter((x) => x.address !== address); }));
  /** Ctrl Shift digit: bookmark n here (or remove it when it already points here). */
  async function bmSet(n, a) {
    if (a == null) return;
    if (bmAt[n] != null && bmAt[n] === big(a)) { await bmRemove(bms[n].address); toast(`Bookmark ${digit(n)} removed`, 'info'); return; }
    const slot = Math.min(n, bms.length), e = { address: stableAddr(a), name: `Bookmark ${digit(slot)}` };
    await attempt(() => editTableMeta((t) => {
      const b = (t.bookmarks ||= []);
      if (n < b.length) b[n] = e; else if (!b.some((x) => x.address === e.address && x.name === e.name)) b.push(e);
    }));
    toast(`Bookmark ${digit(slot)} set at ${fmtAddr(a)}: Shift ${digit(slot)} goes there`, 'info');
  }
  /** Ctrl B: add a named bookmark here, or offer to remove the one already here. */
  async function bmAdd(a, back) {
    if (a == null) return;
    const i = bmAt.findIndex((x) => x != null && x === big(a));
    if (i >= 0) {
      const r = await modal({ title: 'Remove this bookmark?', text: `${fmtAddr(a)} is bookmark ${i + 1}.`, quote: bms[i].name, quoteLabel: 'Name',
        buttons: [{ label: 'Remove', value: 'ok', primary: true, kbd: 'Enter' }, { label: 'Keep', value: 'cancel', kbd: 'Esc' }] });
      back.focus();
      if (r.value === 'ok') await bmRemove(bms[i].address);
      return;
    }
    const v = await prompt(`Bookmark ${fmtAddr(a)}`, relName(a), { label: 'Name', mono: false, hint: `Saved with the cheat table${bms.length < 10 ? `; Shift ${digit(bms.length)} will go to it` : ''}. Ctrl Shift B lists the bookmarks.` });
    back.focus();
    if (v == null) return;
    const e = { address: stableAddr(a), name: v.trim() || relName(a) };
    await attempt(() => editTableMeta((t) => { const b = (t.bookmarks ||= []); if (!b.some((x) => x.address === e.address && x.name === e.name)) b.push(e); }));
  }
  function bmList() {
    const pane = document.activeElement === da ? 'da' : 'hx', back = pane === 'da' ? da : hx;
    const { dialog, body } = tools.listDialog('Bookmarks');
    const host = h('div.tool-list');
    const later = () => setTimeout(() => list.refresh(), 200); // after table:meta and the address lookup
    const rename = async (b) => {
      const v = await prompt('Rename bookmark', b.name, { label: 'Name', mono: false });
      list.focus();
      if (v == null || !v.trim()) return;
      await attempt(() => editTableMeta((t) => { const x = (t.bookmarks || []).find((y) => y.address === b.address && y.name === b.name); if (x) x.name = v.trim(); }));
      later();
    };
    const del = async (b) => { await bmRemove(b.address); later(); };
    const list = vlist(host, {
      cols: '48px minmax(0, 1fr) minmax(0, 1fr) 128px', head: ['Key', 'Name', 'Address', 'Now at'], label: 'Bookmarks',
      empty: 'No bookmarks yet. Ctrl B adds one at the cursor; Ctrl Shift 1…0 sets a numbered one.',
      count: () => bms.length, item: (i) => bms[i],
      cells: (b, i) => [i < 10 ? String(digit(i)) : '', excerpt(b.name, 60), excerpt(b.address, 60), bmAt[i] != null ? fmtAddr(bmAt[i]) : 'unresolved'],
      onActivate: (i) => { if (!bms[i]) return; dialog.close(); bmGo(i, pane); back.focus(); },
      onKey: (e, i, b) => {
        if (!b) return false;
        if (e.key === 'F2') rename(b); else if (e.key === 'Delete') del(b); else return false;
        return true;
      },
      onMenu: (x, y, i, b) => b && contextMenu(x, y, [
        { label: 'Go to', kbd: 'Enter', run: () => { dialog.close(); bmGo(i, pane); back.focus(); } },
        { label: 'Rename…', kbd: 'F2', run: () => rename(b) },
        { label: 'Delete', kbd: 'Del', run: () => del(b) },
      ], list.el),
    });
    body.append(h('p.hint', null, h('kbd', null, 'Enter'), ' go to · ', h('kbd', null, 'F2'), ' rename · ', h('kbd', null, 'Del'), ' delete · ',
      h('kbd', null, 'Shift 1…0'), ' go to the first ten from the hex view or the disassembler · saved with the cheat table'), host);
    dialog.addEventListener('close', () => back.focus());
    list.focus();
    if (bms.length) list.select(0);
  }

  // ---------- second viewer, view menu, keys shared by both panes ----------
  const mv2 = initSecondViewer($('#view-mem'), { rowPx: () => ROW, onLeave: () => hx.focus() });
  function openMv2() { if (state.proc) mv2.show(hxCur ?? (cur() != null ? big(cur()) : null)); }
  function viewMenu(x, y, back) {
    contextMenu(x, y, [
      { label: 'Module + offset addresses', kbd: 'M', checked: modRel, run: toggleModRel },
      { label: 'Bytes column', kbd: 'B', checked: showBytes, run: toggleBytes },
      { label: 'AT&T syntax (display only)', checked: att, run: toggleAtt },
      { label: 'Typed operand comments', checked: typed, run: toggleTyped },
      { label: 'Sync disassembler and hex view', kbd: 'S', checked: syncOn, run: () => toggleSync(back === hx ? 'hx' : 'da') },
      { label: 'Data inspector (hex view)', kbd: 'Ctrl I', checked: inspOn, run: toggleInsp },
      { label: 'Lock hex editing', kbd: 'Ctrl L', checked: locked, run: toggleLock },
      '-',
      { label: 'Larger text', kbd: 'Ctrl =', disabled: fs >= 16, run: () => setFs(fs + 1) },
      { label: 'Smaller text', kbd: 'Ctrl -', disabled: fs <= 11, run: () => setFs(fs - 1) },
      { label: `Default text size (${FS_DEFAULT}px)`, kbd: 'Ctrl 0', disabled: fs === FS_DEFAULT, run: () => setFs(FS_DEFAULT) },
      '-',
      { label: 'Bookmarks…', kbd: 'Ctrl Shift B', run: bmList },
      { label: mv2.open ? 'Go to the second viewer' : 'Open a second memory viewer', kbd: 'Ctrl Shift M', disabled: !state.proc, run: openMv2 },
    ], back);
  }
  /** Keys that work the same in the disassembler and the hex view; true when handled. */
  function sharedKeys(e, pane) {
    const ctrl = e.ctrlKey || e.metaKey, k = e.key.toLowerCase(), slot = slotOf(e.code), el = pane === 'da' ? da : hx;
    const here = pane === 'da' ? cur() : hxCurWire();
    if (e.altKey) return false;
    if (ctrl && e.shiftKey && slot >= 0) bmSet(slot, here);
    else if (!ctrl && e.shiftKey && slot >= 0 && !/^[0-9]$/.test(e.key)) bmGo(slot, pane); // Shift digit (not a layout where Shift types digits)
    else if (ctrl && (k === '=' || k === '+' || e.code === 'NumpadAdd')) setFs(fs + 1);
    else if (ctrl && (k === '-' || k === '_' || e.code === 'NumpadSubtract')) setFs(fs - 1);
    else if (ctrl && !e.shiftKey && (k === '0' || e.code === 'Numpad0')) setFs(FS_DEFAULT);
    else if (ctrl && k === 'b') e.shiftKey ? bmList() : bmAdd(here, el);
    else if (ctrl && !e.shiftKey && k === 'i') toggleInsp();
    else if (ctrl && !e.shiftKey && k === 'l') toggleLock();
    else if (ctrl && e.shiftKey && k === 'm') openMv2();
    else if (!ctrl && !e.shiftKey && k === 's') toggleSync(pane);
    else return false;
    return true;
  }
  helpAdd('Memory viewer', [
    ['Ctrl F', 'Search memory (hex view) / the module (disassembler)'],
    ['F3 / Shift F3', 'Next / previous match'],
    ['Alt ← / Alt →', 'Back / forward (Backspace: back)'],
    ['Shift ↑↓', 'Select lines (disassembler)'],
    ['Ctrl C', 'Copy the selection: hex (hex view), text (disassembler)'],
    ['Ctrl Shift C', 'Copy lines as an AOB pattern (disassembler)'],
    ['Ctrl V / Ctrl Shift V', 'Paste hex or text / always as text (hex view)'],
    ['Ctrl B / Ctrl Shift B', 'Bookmark here / list bookmarks'],
    ['Shift 1…0 / Ctrl Shift 1…0', 'Go to / set a numbered bookmark'],
    ['Space', 'Follow the pointer (hex view)'],
    ['Ins', 'Add to the table with the display type (hex view)'],
    ['Ctrl I / Ctrl L', 'Data inspector / lock editing (hex view)'],
    ['Ctrl = / Ctrl - / Ctrl 0', 'Larger / smaller / default text'],
    ['Ctrl Shift M', 'Second memory viewer (Esc closes it)'],
    ['S', 'Sync disassembler and hex view'],
    ['M / B / I', 'Module + offset addresses / bytes column / target info (disassembler)'],
    ['Ctrl Shift F', 'Assembly scan: instruction patterns with ? and * (disassembler)'],
    ['R / Shift R', 'Next / previous instruction referencing an address (Alt R: another address)'],
    ['X', 'What references this address, from the code dissection'],
    ['N', 'Symbol list (disassembler)'],
  ]);

  // ---------- regions / modules ----------
  const listNav = (list) => list.addEventListener('keydown', (e) => {
    const items = $$('button', list), i = items.indexOf(document.activeElement);
    if ((e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) && i >= 0) { e.preventDefault(); const r = items[i].getBoundingClientRect(); modMenu(r.left + 40, r.bottom, mods[i]); return; }
    const j = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: items.length - 1 }[e.key];
    if (j == null) return;
    e.preventDefault();
    items[Math.max(0, Math.min(items.length - 1, j))]?.focus();
  });
  listNav($('#mod-list'));
  let regs = [], shownRegs = [], mods = [];
  const regionAt = (a) => { if (a == null) return null; const n = big(a); return regs.find((r) => n >= big(r.start) && n < big(r.start) + BigInt(r.size)) || null; };
  const regFilter = $('#reg-filter');
  function filterRegs() {
    const q = regFilter.value.trim().toLowerCase().replace(/^0x/, '');
    shownRegs = !q ? regs : regs.filter((r) => [r.start.replace(/^0x/, ''), r.prot_text, r.tag, r.path || '', r.module || '', r.kind].some((s) => String(s).toLowerCase().includes(q)));
    regList.refresh({ reset: true });
    $('#reg-count').textContent = shownRegs.length === regs.length ? regs.length : `${shownRegs.length}/${regs.length}`;
  }
  const regList = vlist($('#reg-vl'), {
    cols: '104px 60px 38px 54px minmax(0, 1fr)', label: 'Memory regions', row: 24, empty: 'No regions.',
    count: () => shownRegs.length, item: (i) => shownRegs[i],
    cells: (r) => [fmtAddr(r.start), fmtSize(r.size), h('span', { role: 'gridcell', class: 'prot' }, r.prot_text.slice(0, 3)),
      h('span', { role: 'gridcell', class: 'tag tag-' + r.tag }, r.tag), h('span', { role: 'gridcell', class: 'path', title: r.path || '' }, r.module || (r.path ? r.path.split(/[\\/]/).pop() : String(r.kind).toLowerCase()))],
    onActivate: (i, r) => { hxGoto(r.start); if (r.prot.x) daGoto(r.start); hx.focus(); },
    onMenu: (x, y, i, r) => regMenu(x, y, r),
  });
  regFilter.addEventListener('input', filterRegs);
  regFilter.addEventListener('keydown', (e) => { if (e.key === 'ArrowDown') { e.preventDefault(); regList.focus(); regList.select(0); } });
  function regMenu(x, y, r) {
    if (!r) return;
    contextMenu(x, y, [
      { label: 'Browse', kbd: 'Enter', run: () => { hxGoto(r.start); hx.focus(); } },
      { label: 'Disassemble', disabled: !r.prot.x, run: () => { daGoto(r.start); da.focus(); } },
      { label: 'Change protection…', run: async () => { if (await tools.protectDialog(r)) loadLists(false); } },
      '-',
      { label: 'Save this region to a file…', run: () => tools.saveRegions([{ start: r.start, size: r.size }], 'region ' + fmtAddr(r.start)) },
      { label: `Save the ${shownRegs.length} listed regions…`, disabled: !shownRegs.length, run: () => tools.saveRegions(shownRegs.map((x) => ({ start: x.start, size: x.size })), `${shownRegs.length} regions`) },
      { label: 'Load memory file…', run: () => tools.loadMemoryFile().then(() => hxLoad()) },
      { label: 'Snapshots and compare…', run: () => tools.snapshotsDialog({ at: r.start, region: r }) },
    ], regList.el);
  }
  function modMenu(x, y, m) {
    if (!m) return;
    contextMenu(x, y, [
      { label: 'Disassemble', kbd: 'Enter', run: () => { daGoto(m.base); da.focus(); } },
      { label: 'Browse', run: () => { hxGoto(m.base); hx.focus(); } },
      { label: 'Header summary…', run: () => tools.headerDialog(m) },
      { label: 'Dissect code', run: () => emit('code:dissect', m.name) },
      { label: 'Save module memory to a file…', run: () => tools.saveRegions([{ start: m.base, size: m.size }], m.name) },
    ], $('#mod-list'));
  }
  async function loadLists(reset = true) {
    const [rs, ms] = await Promise.all([api.regionsInfo(), api.modules()]).catch((e) => { toast(e); return [[], []]; });
    regs = rs; mods = ms;
    filterRegs();
    $('#mod-list').replaceChildren(...mods.map((m) => h('button.li', { type: 'button', onclick: () => { daGoto(m.base); hxGoto(m.base); da.focus(); },
      oncontextmenu: (e) => { e.preventDefault(); modMenu(e.clientX, e.clientY, m); } },
    h('span.name', { title: m.path }, m.name), h('span.mono', null, fmtAddr(m.base)), h('span.mono.muted', null, fmtSize(m.size)))));
    $('#mod-count').textContent = mods.length;
    if (!reset) return;
    daHist.clear(); hxHist.clear(); fnCache.clear();
    const code = regs.find((r) => r.prot.x), data = regs.find((r) => r.prot.w);
    daTop = code ? big(code.start) : mods[0] ? big(mods[0].base) : null; daSel = 0;
    if (data) hxGoto(data.start);
    daLoad();
  }
  // Registers: open their value in the dissector or the hex view.
  $('#cpu-list').addEventListener('contextmenu', (e) => {
    const b = e.target.closest('button.reg');
    if (!b) return;
    e.preventDefault();
    const v = '0x' + b.querySelector('.rv').textContent.trim();
    contextMenu(e.clientX, e.clientY, [
      { label: 'Open in structure dissector', run: () => emit('struct:open', { addr: v }) },
      { label: 'Browse memory here', run: () => goto({ addr: v, pane: 'hex' }) },
      { label: 'Disassemble here', run: () => goto({ addr: v, pane: 'da' }) },
    ], b);
  });
  for (const t of $$('#mem-side [role=tab]')) t.addEventListener('click', () => {
    for (const o of $$('#mem-side [role=tab]')) { const sel = o === t; o.setAttribute('aria-selected', String(sel)); o.tabIndex = sel ? 0 : -1; $('#' + o.getAttribute('aria-controls')).hidden = !sel; }
    emit('mem:side', t.getAttribute('aria-controls'));
  });
  $('#mem-side [role=tablist]').addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    const tabs = $$('#mem-side [role=tab]:not([hidden])'), i = tabs.indexOf(document.activeElement);
    const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length]; n.focus(); n.click();
  });

  on('process:opened', () => { loadLists(); resolveUser(); });
  on('process:closed', () => {
    daTop = null; daRows = []; daAnchor = null; daHist.clear(); hxHist.clear(); fnCache.clear(); hxTop = hxCur = hxAnchor = null; bytes = []; lastTop = null; regs = []; shownRegs = []; mods = [];
    builtFor = ''; hxPool.length = 0; hx.replaceChildren();
    regList.refresh({ reset: true }); $('#mod-list').replaceChildren(); $('#reg-count').textContent = ''; $('#mod-count').textContent = '';
    daFound = null; refTarget = null; hideTip(); bmAt = [];
    daRender(); renderStatus();
  });
  applyDaView(); renderStatus();
  on('debug:marks', () => daRender());
  addTicker(() => (state.view === 'mem' ? Promise.all([hxLoad(), daLoad()]) : null));

  function goto({ addr, pane }) { if (pane === 'hex') { hxGoto(addr); hx.focus(); } else { daGoto(addr); da.focus(); } }
  return {
    goto,
    refresh() { hxLoad(); daLoad(); },
    /** Show a side-panel list by its element id (reg-list, cpu-list, ...). */
    side(id) { $(`#mem-side [aria-controls="${id}"]`)?.click(); },
    /** Selected disassembler line's address, if any. */
    cursor: () => cur(),
  };
}
