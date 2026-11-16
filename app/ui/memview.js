// Memory viewer: disassembler (top), hex dump (bottom), regions and modules (side).
// Both panes page by address (no native scrollbar) so the whole 64-bit space is reachable.
import { api, askPath } from './backend.js';
import { $, $$, h, fmtAddr, fmtSize, wire, attempt, toast, prompt, rafThrottle, contextMenu, store, busy } from './util.js';
import { state, addTicker, on, emit } from './core.js';
import { vlist } from './vlist.js';
import * as tools from './memtools.js';
import { editTableMeta } from './table.js';

const ROW = 20;
const TYPES = { byte: 1, '2bytes': 2, '4bytes': 4, '8bytes': 8, float: 4, double: 8 };
const big = (s) => BigInt(s);

export function initMemview() {
  const da = $('#da-list'), hx = $('#hx-list'), hxType = $('#hx-type');
  const visOf = (el) => Math.max(1, Math.floor(el.clientHeight / ROW));

  // ---------- disassembler ----------
  let daTop = null, daRows = [], daSel = 0, hist = [], editing = false;
  async function daLoad() {
    if (daTop == null || editing) return;
    const top = daTop;
    const rows = await api.disassemble(wire(top), visOf(da) + 4).catch((e) => { toast(e); return null; });
    if (rows && top === daTop) { daRows = rows; daRender(); }
  }
  const daPool = [];
  let shownN = 0; // instruction rows on screen (label lines take room too)
  /** Pool element showing instruction row i, if it is on screen. */
  const rowEl = (i) => daPool.find((r) => !r.hidden && !r.classList.contains('da-label') && +r.dataset.i === i);
  function daRender() {
    const vis = visOf(da);
    const lines = [];
    for (let i = 0; i < daRows.length && lines.length < vis; i++) {
      for (const name of labelsAt(daRows[i].addr)) if (lines.length < vis - 1) lines.push({ label: name, i });
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
    daPool.forEach((r, k) => {
      const ln = lines[k];
      r.hidden = !ln;
      if (!ln) return;
      const d = daRows[ln.i], [a, b, t, c] = r.children;
      r.dataset.i = ln.i;
      r.classList.toggle('da-label', !!ln.label);
      if (ln.label) {
        r.setAttribute('aria-selected', 'false');
        r.classList.remove('bp', 'rip');
        r.removeAttribute('aria-description');
        a.textContent = ''; b.textContent = ''; c.textContent = '';
        t.textContent = ln.label + ':'; t.dataset.v = '';
        return;
      }
      const isSel = ln.i === daSel;
      if (isSel) selId = r.id;
      r.setAttribute('aria-selected', String(isSel));
      const isBp = !!state.dbg?.bpAddrs?.has(big(d.addr)), isRip = state.dbg?.rip != null && big(d.addr) === state.dbg.rip;
      r.classList.toggle('bp', isBp);
      r.classList.toggle('rip', isRip);
      r.setAttribute('aria-description', [isBp && 'breakpoint', isRip && 'current instruction'].filter(Boolean).join(', '));
      const txt = fmtAddr(d.addr);
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
    renderDaState();
  }
  async function backN(n) {
    if (daTop == null) return daTop;
    const from = daTop > BigInt(n * 8) ? daTop - BigInt(n * 8) : 0n;
    const rows = await api.disassemble(wire(from), n * 3).catch(() => []);
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
    if (push && daTop != null) hist.push([daTop, daSel]);
    daTop = big(addr); daSel = 0;
    $('#da-back').disabled = !hist.length;
    await daLoad();
  }
  function follow() {
    const d = daRows[daSel];
    if (!d || !/^(j|call)/.test(d.text)) return;
    const m = d.text.match(/\b(?:0x)?([0-9a-f]{6,16})\b/i);
    if (m) daGoto('0x' + m[1]);
  }
  function back() {
    const p = hist.pop();
    $('#da-back').disabled = !hist.length;
    if (p) { [daTop, daSel] = p; daLoad(); }
  }
  function assembleLine() {
    const d = daRows[daSel], row = rowEl(daSel);
    if (!d || !row) return;
    editing = true;
    const cell = row.children[2];
    const input = h('input.cell-input.mono', { value: d.text, spellcheck: 'false', 'aria-label': `Assemble at ${fmtAddr(d.addr)}` });
    cell.replaceChildren(input);
    delete cell.dataset.v;
    input.focus(); input.select();
    let done = false;
    const finish = async (ok) => {
      if (done) return;
      done = true;
      if (ok && input.value.trim() && input.value.trim() !== d.text) {
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
    if (a) which === 'da' ? daGoto(a) : hxGoto(a);
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
  const commentAt = (a) => cmtBy.get(big(a)) || '';
  const labelsAt = (a) => symBy.get(big(a)) || [];
  async function resolveUser() {
    const exprs = [...userCmts.map((c) => c.address), ...userSyms.map((x) => x.address)];
    const got = state.proc && exprs.length ? await api.resolveMany(exprs).catch(() => exprs.map(() => null)) : exprs.map(() => null);
    cmtBy = new Map(); symBy = new Map(); exprAddr = new Map(exprs.map((x, i) => [x, got[i] == null ? null : big(got[i])]));
    userCmts.forEach((c, i) => { if (got[i] != null) cmtBy.set(big(got[i]), c.comment); });
    userSyms.forEach((x, i) => { const a = got[userCmts.length + i]; if (a != null) symBy.set(big(a), [...(symBy.get(big(a)) || []), x.name]); });
    daRender();
  }
  on('table:meta', (m) => {
    const c = m.disasm_comments || [], y = m.symbols || [];
    if (JSON.stringify([c, y]) === JSON.stringify([userCmts, userSyms])) return;
    userCmts = c.map((x) => ({ ...x })); userSyms = y.map((x) => ({ ...x }));
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
  function daMenu(x, y) {
    const a = cur(), att = !!state.dbg?.attached, d = daRows[daSel];
    contextMenu(x, y, [
      { label: 'Toggle breakpoint', kbd: 'F5', disabled: !a, run: () => emit('debug:toggle-bp', a) },
      { label: 'Run to cursor', kbd: 'F4', disabled: !a || state.dbg?.state !== 'broken', run: () => emit('debug:run-to', a) },
      { label: 'Run to cursor, this thread only', kbd: 'Shift F4', disabled: !a || state.dbg?.state !== 'broken', run: () => emit('debug:run-to-thread', a) },
      { label: 'Find out what addresses this instruction accesses', disabled: !a || !/\[/.test(d?.text || ''), run: () => emit('debug:ea', { addr: a, text: d.text }) },
      { label: 'Break and trace…', disabled: !a, run: () => emit('debug:trace', { addr: a, text: d.text }) },
      { label: 'Set breakpoint…', disabled: !a, run: () => emit('debug:bp-dialog', a) },
      '-',
      { label: 'What references this address', kbd: 'X', disabled: !a, run: () => emit('code:xrefs', a) },
      { label: 'Generate AOB signature', disabled: !a, run: () => tools.signatureDialog(a) },
      { label: 'Create AOB injection script', disabled: !a, run: () => tools.aobScript(a) },
      { label: 'Create code injection script', disabled: !a, run: () => tools.injectScript(a, 'code') },
      { label: 'Create full injection script', disabled: !a, run: () => tools.injectScript(a, 'full') },
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
      { label: 'Follow', kbd: 'Space', disabled: !/^(j|call)/.test(d?.text || ''), run: follow },
      { label: 'Go to address…', kbd: 'Ctrl G', run: () => gotoPrompt('da') },
      ...(att ? [] : ['-', { label: 'Attach debugger', kbd: 'Ctrl Shift D', run: () => emit('debug:attach') }]),
    ], da);
  }
  da.addEventListener('contextmenu', (e) => {
    const r = e.target.closest('.da-row:not(.da-label)');
    e.preventDefault();
    if (r) { daSel = +r.dataset.i; daRender(); }
    daMenu(e.clientX, e.clientY);
  });
  da.addEventListener('keydown', (e) => {
    const vis = Math.max(1, shownN);
    if (e.key === 'ArrowDown') daSel < vis - 1 ? (daSel++, daRender()) : daScroll(1);
    else if (e.key === 'ArrowUp') daSel > 0 ? (daSel--, daRender()) : daScroll(-1);
    else if (e.key === 'PageDown') daScroll(vis - 1);
    else if (e.key === 'PageUp') daScroll(-(vis - 1));
    else if (e.key === ' ') follow();
    else if (e.key === 'Backspace' || (e.altKey && e.key === 'ArrowLeft')) back();
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
  da.addEventListener('wheel', (e) => { e.preventDefault(); daScroll(e.deltaY > 0 ? 3 : -3); }, { passive: false });
  da.addEventListener('mousedown', (e) => { const r = e.target.closest('.da-row:not(.da-label)'); if (r) { daSel = +r.dataset.i; daRender(); } });
  da.addEventListener('dblclick', (e) => { if (e.target.closest('.da-row')) assembleLine(); });
  $('#da-back').addEventListener('click', back);
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
  $('#hx-goto').before(bprSel, encSel);
  bprSel.addEventListener('change', () => { bpr = +bprSel.value; store.set('hx.bpr', bpr); if (hxCur != null) hxTop = rowStart(hxCur); lastTop = null; hxLoad(); hx.focus(); });
  encSel.addEventListener('change', () => { enc = encSel.value; store.set('hx.enc', enc); hxRender(); hx.focus(); });
  const hxStatus = h('div.hx-status.mono', { role: 'status', 'aria-live': 'off' });
  hx.after(hxStatus);
  async function hxLoad() {
    if (hxTop == null) return;
    const top = hxTop, n = visOf(hx) * bpr;
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
        if (isCur) { c.id = 'hx-cur'; } else if (c.id) c.removeAttribute('id');
      }
      const s = textOf(base);
      if (asc.textContent !== s) asc.textContent = s;
    });
    hx.setAttribute('aria-activedescendant', curOff >= 0 ? 'hx-cur' : '');
    $('#hx-pos').textContent = sel ? `${fmtAddr(sel[0])} · ${Number(sel[1] - sel[0] + 1n)} bytes` : hxCur != null ? fmtAddr(hxCur) : '';
    renderStatus();
  }
  /** Status line: protection and kind / path of the region under the cursor. */
  function renderStatus() {
    if (!state.proc) { hxStatus.replaceChildren('No process. ', h('kbd', null, 'Ctrl P'), ' opens one.'); hxStatus.classList.remove('err'); return; }
    const r = regionAt(hxCur);
    const unread = bytes.length > 0 && bytes.every((b) => b === '??');
    const t = hxCur == null ? 'Pick a region on the right or press Ctrl G to browse memory.' : !r ? `${fmtAddr(hxCur)} · not in a mapped region${unread ? ' · unreadable' : ''}`
      : `${fmtAddr(hxCur)} · ${r.prot_text.slice(0, 3)} · ${r.tag}${r.module ? ' · ' + r.module : ''}${r.path ? ' · ' + r.path : r.module ? '' : ' · ' + String(r.kind).toLowerCase()} · region ${fmtAddr(r.start)} +${fmtSize(r.size)}${unread ? ' · unreadable' : ''}`;
    if (hxStatus.textContent !== t) hxStatus.textContent = t;
    hxStatus.classList.toggle('err', unread);
  }
  const hxSchedule = rafThrottle(hxRender);
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
    if (hxCur == null) return;
    const u = unit(), t = hxType.value, at = hxCur - (hxCur % BigInt(u));
    const cur = cellText(Number(at - hxTop), u);
    const v = await prompt(`Edit ${t === 'byte' ? 'byte' : t} at ${fmtAddr(at)}`, cur, { label: t === 'byte' ? 'Hex byte' : 'Value' });
    hx.focus();
    if (v == null) return;
    await attempt(() => (t === 'byte' ? api.writeBytes(wire(at), v.trim().padStart(2, '0')) : api.writeValue(wire(at), t, v)));
    hxLoad();
  }
  hx.addEventListener('keydown', async (e) => {
    const u = unit(), vis = visOf(hx);
    const ext = e.shiftKey;
    if (e.key === 'ArrowRight') hxMove(u, ext);
    else if (e.key === 'ArrowLeft') hxMove(-u, ext);
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
      if (nib == null) { nib = e.key; hxSchedule(); }
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
  const fill = () => after(tools.fillDialog(hxCurWire()));
  const copyMem = () => after(tools.copyDialog(hxCurWire()));
  function hxMenu(x, y) {
    const a = hxCurWire(), r = regionAt(hxCur);
    contextMenu(x, y, [
      { label: 'Edit value', kbd: 'Enter', disabled: !a, run: hxEditValue },
      { label: 'Set breakpoint here', kbd: 'F5', disabled: !a, run: () => breakHere(a) },
      { label: 'Go to address…', kbd: 'Ctrl G', run: () => gotoPrompt('hx') },
      { label: 'Disassemble here', disabled: !a, run: () => daGoto(a) },
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
      { label: 'Load memory file…', disabled: !state.proc, run: () => after(tools.loadMemoryFile()) },
      { label: 'Compare with saved file…', disabled: !state.proc, run: compareFile },
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
    hist = []; $('#da-back').disabled = true;
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
    daTop = null; daRows = []; hist = []; hxTop = hxCur = hxAnchor = null; bytes = []; lastTop = null; regs = []; shownRegs = []; mods = [];
    builtFor = ''; hxPool.length = 0; hx.replaceChildren();
    regList.refresh({ reset: true }); $('#mod-list').replaceChildren(); $('#reg-count').textContent = ''; $('#mod-count').textContent = '';
    daRender(); renderStatus();
  });
  daRender(); renderStatus();
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
