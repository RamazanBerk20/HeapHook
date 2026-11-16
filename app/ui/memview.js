// Memory viewer: disassembler (top), hex dump (bottom), regions and modules (side).
// Both panes page by address (no native scrollbar) so the whole 64-bit space is reachable.
import { api } from './backend.js';
import { $, $$, h, fmtAddr, fmtSize, wire, attempt, toast, prompt, rafThrottle, contextMenu } from './util.js';
import { state, addTicker, on, emit } from './core.js';
import { vlist } from './vlist.js';
import * as tools from './memtools.js';

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
  function daRender() {
    const n = Math.min(visOf(da), daRows.length);
    daSel = Math.min(daSel, n - 1);
    while (daPool.length < n) {
      const r = h('div.da-row', { role: 'row', id: 'da-r' + daPool.length },
        h('span.c-addr', { role: 'gridcell' }), h('span.c-bytes', { role: 'gridcell' }), h('span.c-text', { role: 'gridcell' }), h('span.c-cmt', { role: 'gridcell' }));
      daPool.push(r); da.append(r);
    }
    daPool.forEach((r, i) => {
      const d = daRows[i];
      r.hidden = i >= n;
      if (r.hidden) return;
      r.dataset.i = i;
      r.setAttribute('aria-selected', String(i === daSel));
      const isBp = !!state.dbg?.bpAddrs?.has(big(d.addr)), isRip = state.dbg?.rip != null && big(d.addr) === state.dbg.rip;
      r.classList.toggle('bp', isBp);
      r.classList.toggle('rip', isRip);
      r.setAttribute('aria-description', [isBp && 'breakpoint', isRip && 'current instruction'].filter(Boolean).join(', '));
      const [a, b, t, c] = r.children;
      const txt = fmtAddr(d.addr);
      if (a.textContent !== txt) a.textContent = txt;
      if (b.textContent !== d.bytes) b.textContent = d.bytes;
      if (t.dataset.v !== d.text) {
        t.dataset.v = d.text;
        const [m, ...rest] = d.text.split(' ');
        t.replaceChildren(h('b', null, m), rest.length ? ' ' + rest.join(' ') : '');
        t.classList.toggle('branch', /^(j|call|ret)/.test(m));
      }
      const x = d.xrefs, xr = x ? [x.calls && `${x.calls} call${x.calls > 1 ? 's' : ''}`, x.jumps && `${x.jumps} jump${x.jumps > 1 ? 's' : ''}`, x.data && `${x.data} read${x.data > 1 ? 's' : ''}`].filter(Boolean).join(' · ') : '';
      const ck = xr + '|' + (d.comment || '');
      if (c.dataset.v !== ck) {
        c.dataset.v = ck;
        c.replaceChildren(xr ? h('span.xr', { title: 'Referenced from (code dissection); X lists them' }, '← ' + xr + (d.comment ? '  ' : '')) : '', d.comment || '');
      }
    });
    da.setAttribute('aria-activedescendant', 'da-r' + daSel);
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
    const d = daRows[daSel], row = daPool[daSel];
    if (!d) return;
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
  function daMenu(x, y) {
    const a = cur(), att = !!state.dbg?.attached, d = daRows[daSel];
    contextMenu(x, y, [
      { label: 'Toggle breakpoint', kbd: 'F5', disabled: !a, run: () => emit('debug:toggle-bp', a) },
      { label: 'Run to cursor', kbd: 'F4', disabled: !a || state.dbg?.state !== 'broken', run: () => emit('debug:run-to', a) },
      { label: 'Find out what addresses this instruction accesses', disabled: !a || !/\[/.test(d?.text || ''), run: () => emit('debug:ea', { addr: a, text: d.text }) },
      { label: 'Break and trace…', disabled: !a, run: () => emit('debug:trace', { addr: a, text: d.text }) },
      { label: 'Set breakpoint…', disabled: !a, run: () => emit('debug:bp-dialog', a) },
      '-',
      { label: 'What references this address', kbd: 'X', disabled: !a, run: () => emit('code:xrefs', a) },
      { label: 'Generate AOB signature', disabled: !a, run: () => tools.signatureDialog(a) },
      { label: 'Create AOB injection script', disabled: !a, run: () => tools.aobScript(a) },
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
    const r = e.target.closest('.da-row');
    e.preventDefault();
    if (r) { daSel = +r.dataset.i; daRender(); }
    daMenu(e.clientX, e.clientY);
  });
  da.addEventListener('keydown', (e) => {
    const vis = visOf(da);
    if (e.key === 'ArrowDown') daSel < vis - 1 ? (daSel++, daRender()) : daScroll(1);
    else if (e.key === 'ArrowUp') daSel > 0 ? (daSel--, daRender()) : daScroll(-1);
    else if (e.key === 'PageDown') daScroll(vis - 1);
    else if (e.key === 'PageUp') daScroll(-(vis - 1));
    else if (e.key === ' ') follow();
    else if (e.key === 'Backspace' || (e.altKey && e.key === 'ArrowLeft')) back();
    else if (e.key === 'Enter') assembleLine();
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'g') gotoPrompt('da');
    else if (e.key === 'F5' && cur()) emit('debug:toggle-bp', cur());
    else if (e.key === 'F4' && cur()) emit('debug:run-to', cur());
    else if (e.key.toLowerCase() === 'x' && !e.ctrlKey && cur()) emit('code:xrefs', cur());
    else if (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) {
      const r = (daPool[daSel] || da).getBoundingClientRect();
      daMenu(r.left + 120, r.bottom);
    } else return;
    e.preventDefault(); e.stopPropagation();
  });
  da.addEventListener('wheel', (e) => { e.preventDefault(); daScroll(e.deltaY > 0 ? 3 : -3); }, { passive: false });
  da.addEventListener('mousedown', (e) => { const r = e.target.closest('.da-row'); if (r) { daSel = +r.dataset.i; daRender(); } });
  da.addEventListener('dblclick', (e) => { if (e.target.closest('.da-row')) assembleLine(); });
  $('#da-back').addEventListener('click', back);
  $('#da-goto').addEventListener('click', () => gotoPrompt('da'));

  // ---------- hex ----------
  let hxTop = null, hxCur = null, bytes = [], chgUntil = [], lastTop = null, nib = null;
  const unit = () => TYPES[hxType.value];
  async function hxLoad() {
    if (hxTop == null) return;
    const top = hxTop, n = visOf(hx) * 16;
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
    const vis = visOf(hx), u = unit(), key = vis + ':' + u;
    if (builtFor !== key) {
      builtFor = key;
      hxPool.length = 0;
      hx.replaceChildren();
      for (let r = 0; r < vis; r++) {
        const cells = [];
        for (let c = 0; c < 16; c += u) cells.push(h('span.hb', { role: 'gridcell', 'data-o': c }));
        const row = h('div.hx-row', { role: 'row' }, h('span.c-addr', { role: 'rowheader' }), h('span.hx-bytes', { 'data-u': u }, cells), h('span.hx-ascii', { 'aria-hidden': 'true' }));
        hxPool.push(row); hx.append(row);
      }
    }
    const now = performance.now(), curOff = hxCur != null ? Number(hxCur - hxTop) : -1;
    hxPool.forEach((row, r) => {
      const base = r * 16, [a, bs, asc] = row.children;
      const t = fmtAddr(hxTop + BigInt(base));
      if (a.textContent !== t) a.textContent = t;
      for (const c of bs.children) {
        const i = base + +c.dataset.o, txt = cellText(i, u);
        if (c.textContent !== txt) c.textContent = txt;
        let chg = false;
        for (let k = 0; k < u; k++) if (chgUntil[i + k] > now) chg = true;
        c.classList.toggle('chg', chg);
        const isCur = curOff >= i && curOff < i + u;
        c.classList.toggle('cursor', isCur);
        c.classList.toggle('pending', isCur && nib != null);
        if (isCur) { c.id = 'hx-cur'; } else if (c.id) c.removeAttribute('id');
      }
      let s = '';
      for (let k = 0; k < 16; k++) { const b = bytes[base + k]; const v = b && b !== '??' ? parseInt(b, 16) : -1; s += v >= 32 && v < 127 ? String.fromCharCode(v) : '.'; }
      if (asc.textContent !== s) asc.textContent = s;
    });
    hx.setAttribute('aria-activedescendant', curOff >= 0 ? 'hx-cur' : '');
    $('#hx-pos').textContent = hxCur != null ? fmtAddr(hxCur) : '';
  }
  const hxSchedule = rafThrottle(hxRender);
  function hxGoto(addr) {
    hxCur = big(addr);
    hxTop = hxCur & ~0xfn;
    nib = null;
    hxLoad();
  }
  function hxMove(delta) {
    if (hxCur == null) return;
    const n = hxCur + BigInt(delta);
    hxCur = n < 0n ? 0n : n;
    nib = null;
    const vis = BigInt(visOf(hx) * 16);
    if (hxCur < hxTop) hxTop = hxCur & ~0xfn;
    else if (hxCur >= hxTop + vis) hxTop = (hxCur & ~0xfn) - vis + 16n;
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
    if (e.key === 'ArrowRight') hxMove(u);
    else if (e.key === 'ArrowLeft') hxMove(-u);
    else if (e.key === 'ArrowDown') hxMove(16);
    else if (e.key === 'ArrowUp') hxMove(-16);
    else if (e.key === 'PageDown') { hxTop += BigInt(vis * 16); hxMove(vis * 16); }
    else if (e.key === 'PageUp') { hxTop = hxTop > BigInt(vis * 16) ? hxTop - BigInt(vis * 16) : 0n; hxMove(-vis * 16); }
    else if (e.key === 'Enter') hxEditValue();
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
    const d = BigInt((e.deltaY > 0 ? 3 : -3) * 16);
    hxTop = hxTop + d < 0n ? 0n : hxTop + d;
    hxLoad();
  }, { passive: false });
  hx.addEventListener('mousedown', (e) => {
    const c = e.target.closest('.hb');
    if (!c) return;
    const r = hxPool.indexOf(c.closest('.hx-row'));
    hxCur = hxTop + BigInt(r * 16 + +c.dataset.o);
    nib = null;
    hxSchedule();
  });
  hx.addEventListener('dblclick', (e) => { if (e.target.closest('.hb')) hxEditValue(); });
  const hxCurWire = () => (hxCur != null ? wire(hxCur) : null);
  const after = (p) => p.then((ok) => { if (ok) { lastTop = null; hxLoad(); } hx.focus(); });
  const fill = () => after(tools.fillDialog(hxCurWire()));
  const copyMem = () => after(tools.copyDialog(hxCurWire()));
  function hxMenu(x, y) {
    const a = hxCurWire(), r = regionAt(hxCur);
    contextMenu(x, y, [
      { label: 'Edit value', kbd: 'Enter', disabled: !a, run: hxEditValue },
      { label: 'Go to address…', kbd: 'Ctrl G', run: () => gotoPrompt('hx') },
      { label: 'Disassemble here', disabled: !a, run: () => daGoto(a) },
      '-',
      { label: 'Open in structure dissector', disabled: !a, run: () => emit('struct:open', { addr: a }) },
      { label: 'Find what points to this address…', kbd: 'Ctrl Shift P', disabled: !a, run: () => tools.pointersDialog(a) },
      { label: 'What references this address (code)', disabled: !a, run: () => emit('code:xrefs', a) },
      { label: 'Find out what accesses this address', disabled: !a, run: () => emit('debug:accesses', { addr: a, vtype: hxType.value === 'byte' ? '4bytes' : hxType.value }) },
      { label: 'Find out what writes to this address', disabled: !a, run: () => emit('debug:writes', { addr: a, vtype: hxType.value === 'byte' ? '4bytes' : hxType.value }) },
      '-',
      { label: 'Fill memory…', kbd: 'Ctrl Shift F', disabled: !state.proc, run: fill },
      { label: 'Copy memory…', kbd: 'Ctrl Shift C', disabled: !state.proc, run: copyMem },
      { label: 'Snapshots and compare…', kbd: 'Ctrl Shift S', disabled: !state.proc, run: () => tools.snapshotsDialog({ at: a, region: r }) },
      { label: 'Save this region to a file…', disabled: !r, run: () => tools.saveRegions([{ start: r.start, size: r.size }], 'region ' + fmtAddr(r.start)) },
      { label: 'Load memory file…', disabled: !state.proc, run: () => after(tools.loadMemoryFile()) },
    ], hx);
  }
  hx.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    const c = e.target.closest('.hb');
    if (c) { const r = hxPool.indexOf(c.closest('.hx-row')); hxCur = hxTop + BigInt(r * 16 + +c.dataset.o); nib = null; hxSchedule(); }
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

  on('process:opened', loadLists);
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
