// Structure dissector: a tree of a structure's fields evaluated at one or more addresses
// (columns, in groups like Cheat Engine), pointer fields expanding into child structures,
// type / description / size edits, in-place value edits, "add to cheat table" with the
// pointer path, and the structure spider. Definitions live in the backend's table.
import { api } from './backend.js';
import { $, h, icon, fmtAddr, wire, attempt, toast, prompt, contextMenu, nf } from './util.js';
import { state, emit, on, addTicker } from './core.js';
import { vlist } from './vlist.js';
import { formDialog, progressStrip, runJob, hexNum } from './memtools.js';

const TYPES = [['byte', 'Byte'], ['2bytes', '2 Bytes'], ['4bytes', '4 Bytes'], ['8bytes', '8 Bytes'], ['float', 'Float'], ['double', 'Double'],
  ['string', 'String'], ['aob', 'Array of byte'], ['pointer', 'Pointer'], ['struct', 'Structure']];
const TNAME = Object.fromEntries(TYPES);
const SIZED = new Set(['string', 'aob']);
const INT = new Set(['byte', '2bytes', '4bytes', '8bytes']);
const hex = (n) => Number(n).toString(16).toUpperCase();

/** How a field's values compare across groups (Cheat Engine colors the two interesting kinds). */
function classify(vals, groups) {
  const per = groups.map((g) => g.map((ci) => vals[ci]));
  if (per.flat().length < 2) return '';
  if (per.flat().some((v) => v == null)) return 'st-unread';
  const reps = [];
  for (const g of per) {
    if (!g.length) continue;
    if (g.some((v) => v !== g[0])) return 'st-mixed';
    reps.push(g[0]);
  }
  if (reps.every((r) => r === reps[0])) return '';
  return new Set(reps).size === reps.length ? 'st-differ' : 'st-mixed';
}

export function initStructs({ showView }) {
  const view = $('#view-struct'), sel = $('#st-sel'), colsBar = $('#st-cols'), host = $('#st-tree');
  let structs = [], cur = null, groups = [[]], rows = [], list = null, ncols = -1, editing = false, gen = 0;
  const expanded = new Set();
  const columns = () => groups.flatMap((g, gi) => g.map((c) => ({ ...c, gi })));
  const groupIdx = () => { let k = 0; return groups.map((g) => g.map(() => k++)); };

  // ---------- structures ----------
  async function loadStructs() {
    structs = (await attempt(() => api.structGet())) || [];
    if (cur && !structs.some((s) => s.name === cur)) cur = null;
    if (!cur && structs.length) cur = structs[0].name;
    sel.replaceChildren(...(structs.length ? structs.map((s) => h('option', { value: s.name, selected: s.name === cur }, s.name)) : [h('option', { value: '' }, 'No structures')]));
    sel.disabled = !structs.length;
  }
  const save = async () => { if (await attempt(async () => { await api.structSet(structs); return true; })) { await loadStructs(); await evalTree(); } };
  const elemOf = (r) => structs.find((s) => s.name === r.owner)?.elements[r.index];
  sel.addEventListener('change', () => { cur = sel.value; expanded.clear(); evalTree(); });

  // ---------- evaluation ----------
  async function evalTree() {
    const g = ++gen, cols = columns();
    if (!cur || !cols.length) { rows = []; render(); return; }
    const out = [];
    async function level(name, bases, depth, prefix, path) {
      const live = bases.map((b, i) => (b ? i : -1)).filter((i) => i >= 0);
      if (!live.length) return;
      const res = await api.structEval(live.map((i) => ({ name, addr: bases[i] })));
      const per = bases.map(() => null);
      live.forEach((ci, k) => { per[ci] = res[k]?.Ok || null; });
      const proto = per.find(Boolean);
      if (!proto) { out.push({ key: prefix + 'err', depth, error: res[0]?.Err || 'unreadable' }); return; }
      const walk = async (fields, at, d, pre, getter) => {
        for (let i = 0; i < fields.length; i++) {
          const f = fields[i], key = pre + i, vals = cols.map((_, ci) => getter(ci)?.[i] ?? null);
          const kids = f.vtype === 'struct' ? f.children.length > 0 : f.vtype === 'pointer' && vals.some((v) => v?.target);
          out.push({ key, depth: d, owner: f.owner, index: f.index, offset: f.offset, vtype: f.vtype, size: f.size, description: f.description, child: f.child, vals, kids, path: at });
          if (!kids || !expanded.has(key)) continue;
          if (f.vtype === 'struct') await walk(f.children, at, d + 1, key + '.', (ci) => getter(ci)?.[i]?.children);
          else if (f.child) await level(f.child, vals.map((v) => v?.target || null), d + 1, key + '/', [...at, f.offset]);
        }
      };
      await walk(proto, path, depth, prefix, (ci) => per[ci]);
    }
    try { await level(cur, cols.map((c) => c.addr), 0, '', []); } catch (e) { if (g === gen) toast(e); }
    if (g !== gen) return;
    rows = out;
    render();
  }

  // ---------- rendering ----------
  function build() {
    const cols = columns();
    ncols = cols.length;
    host.replaceChildren();
    const colW = cols.map(() => 'minmax(120px, 1fr)').join(' ');
    list = vlist(host, {
      cols: `minmax(130px, 0.6fr) 96px minmax(140px, 1fr) ${colW}`,
      head: ['Offset', 'Type', 'Description', ...cols.map((c) => h('span', { class: 'st-colhead', title: c.expr }, `${groups.length > 1 ? 'G' + (c.gi + 1) + ' · ' : ''}${fmtAddr(c.addr)}`))],
      label: 'Structure fields', row: 22,
      empty: () => (!structs.length ? 'No structure yet. Open one at an address: the cheat table, scan results, memory view and registers have "Open in structure dissector", or press G here.' : !cols.length ? 'Add an address column (A).' : 'No fields.'),
      count: () => rows.length, item: (i) => rows[i],
      rowClass: (r) => (r.error ? 'st-errrow' : ''),
      cells(r) {
        if (r.error) return [h('span', { role: 'gridcell', style: `padding-left:${r.depth * 14}px` }, r.error)];
        const gi = groupIdx(), cls = classify(r.vals.map((v) => v?.value ?? null), gi);
        const caret = r.kids ? h('span.st-caret', { html: icon(expanded.has(r.key) ? 'chevD' : 'chevR') }) : h('span.st-caret');
        return [
          h('span', { role: 'gridcell', class: 'st-off', style: `padding-left:${r.depth * 14}px` }, caret, hex(r.offset)),
          h('span', { role: 'gridcell', class: 'st-type' }, (TNAME[r.vtype] || r.vtype) + (SIZED.has(r.vtype) ? `[${r.size}]` : '') + (r.child && r.vtype === 'pointer' ? ` → ${r.child}` : '')),
          h('span', { role: 'gridcell', class: 'st-desc' }, r.description || ''),
          ...r.vals.map((v) => h('span', { role: 'gridcell', class: 'st-val ' + cls }, v == null ? '??' : v.value ?? (r.vtype === 'struct' ? '' : '??'))),
        ];
      },
      onActivate: (i, r, e) => (e?.type === 'dblclick' && r?.kids ? toggle(r, true) : editValue(i, 0)),
      onMenu: (x, y, i, r) => menu(x, y, r),
      onKey: keys,
    });
  }
  function render() {
    if (columns().length !== ncols || !list) build();
    renderCols();
    list.refresh({ force: true });
  }
  function renderCols() {
    colsBar.replaceChildren(...groups.map((g, gi) => h('div.st-group', { role: 'group', 'aria-label': `Group ${gi + 1}` },
      h('span.st-glabel', null, groups.length > 1 ? `Group ${gi + 1}` : 'Addresses'),
      ...g.map((c, ci) => h('span.st-chip.mono', { title: c.expr }, c.expr === fmtAddr(c.addr) ? c.expr : `${c.expr} = ${fmtAddr(c.addr)}`,
        h('button.st-x', { type: 'button', 'aria-label': `Remove ${c.expr}`, html: icon('x'), onclick: () => { g.splice(ci, 1); if (!g.length && groups.length > 1) groups.splice(gi, 1); render(); evalTree(); } }))),
      h('button.btn.ghost.icon', { type: 'button', 'aria-label': `Add an address to group ${gi + 1}`, title: 'Add address (A)', html: icon('plus'), onclick: () => addColumn(gi) }))),
    h('button.btn.ghost', { type: 'button', onclick: () => { groups.push([]); addColumn(groups.length - 1); } }, h('span', { html: icon('group') }), 'Group'));
  }

  // ---------- columns ----------
  async function addColumn(gi = 0, expr) {
    expr ??= await prompt('Add address column', '', { label: 'Address or expression', hint: 'e.g. 7FFD12340000, [player_base], game.exe+1A2B' });
    if (!expr) { if (!groups[gi]?.length && groups.length > 1) { groups.splice(gi, 1); render(); } return; }
    const a = await attempt(() => api.resolveAddress(expr));
    if (!a) return;
    groups[gi].push({ expr: expr.trim(), addr: a });
    render(); evalTree();
  }

  // ---------- opening ----------
  async function openAt(addr, expr) {
    if (!state.proc) { toast('Open a process first'); return; }
    showView('struct');
    await loadStructs();
    const v = await formDialog(`Dissect ${fmtAddr(addr)}`, [
      { name: 'use', label: 'Structure', type: 'select', value: '', options: [['', 'New: auto-guess the layout'], ...structs.map((s) => [s.name, s.name])] },
      { name: 'name', label: 'New structure name', value: `struct_${fmtAddr(addr).replace(/^0+/, '')}`, mono: false },
      { name: 'size', label: 'Size to guess (hex bytes)', value: '100' },
      { name: 'mode', label: 'Address', type: 'select', value: 'replace', options: [['replace', 'Show only this address'], ['column', 'Add as a column'], ['group', 'Add as a new group']] },
    ], { ok: 'Open' });
    if (!v) return;
    let name = v.use;
    if (!name) {
      if (!v.name) { toast('Give the new structure a name'); return; }
      const st = await attempt(() => api.structGuess(v.name, wire(BigInt(addr)), hexNum(v.size) || 0x100));
      if (!st) return;
      name = st.name;
    }
    cur = name;
    const c = { expr: expr || fmtAddr(addr), addr: wire(BigInt(addr)) };
    if (v.mode === 'replace' || !columns().length) groups = [[c]];
    else if (v.mode === 'group') groups.push([c]);
    else groups[0].push(c);
    expanded.clear();
    await loadStructs();
    render();
    await evalTree();
    list.focus();
  }
  async function newStructure() {
    const a = await prompt('Dissect a structure at', columns()[0]?.expr || '', { label: 'Address or expression' });
    if (!a) return;
    const r = await attempt(() => api.resolveAddress(a));
    if (r) openAt(r, a);
  }

  // ---------- tree actions ----------
  const rowAt = () => rows[list?.sel];
  async function toggle(r, open) {
    if (!r?.kids) return;
    if (!open) { expanded.delete(r.key); await evalTree(); return; }
    if (r.vtype === 'pointer' && !r.child) {
      // Guess a child structure at the first column's target and link it.
      const ci = r.vals.findIndex((v) => v?.target);
      const c = await attempt(() => api.structExpand(r.owner, r.index, r.vals[ci].addr, 0x100));
      if (!c) return;
      await loadStructs();
    }
    expanded.add(r.key);
    await evalTree();
  }
  function parentIndex(i) {
    const d = rows[i]?.depth;
    for (let j = i - 1; j >= 0; j--) if (rows[j].depth < d) return j;
    return -1;
  }
  async function editElem(r, f) {
    const e = elemOf(r);
    if (!e) return;
    f(e);
    await save();
  }
  function changeType(r, x, y) {
    contextMenu(x, y, TYPES.filter(([t]) => t !== 'struct').map(([t, l]) => ({ label: l, checked: r.vtype === t, run: () => editElem(r, (e) => {
      e.vtype = t;
      if (SIZED.has(t) && !e.size) e.size = 16;
      if (t !== 'pointer') e.child = undefined;
    }).then(() => list.focus()) })), list.el);
  }
  async function changeSize(r) {
    const v = await prompt(`Size of ${r.description || hex(r.offset)}`, String(r.size), { label: 'Bytes (decimal)' });
    list.focus();
    if (v != null && +v > 0) editElem(r, (e) => { e.size = Math.min(4096, Math.floor(+v)); });
  }
  async function addElement(r) {
    const st = structs.find((s) => s.name === (r?.owner || cur));
    if (!st) return;
    const v = await formDialog(`Add element to ${st.name}`, [
      { name: 'offset', label: 'Offset (hex)', value: hex(r ? elemOf(r).offset + Math.max(1, r.size) : 0) },
      { name: 'vtype', label: 'Type', type: 'select', value: '4bytes', options: TYPES.filter(([t]) => t !== 'struct') },
      { name: 'description', label: 'Description', value: '', mono: false },
    ], { ok: 'Add' });
    list.focus();
    if (!v) return;
    const off = hexNum(v.offset);
    if (!(off >= 0)) { toast('Offset must be hex'); return; }
    st.elements.push({ offset: off, description: v.description, vtype: v.vtype, size: SIZED.has(v.vtype) ? 16 : 0, hex: false, signed: false, utf16: false });
    st.elements.sort((a, b) => a.offset - b.offset);
    await save();
  }
  async function removeElement(r) {
    const st = structs.find((s) => s.name === r.owner);
    if (!st) return;
    st.elements.splice(r.index, 1);
    await save();
  }
  /** Inline editor over cell `col` (`desc` or a value column index) of row i. */
  function inlineEdit(i, col, initial, done) {
    const rowEl = list.el.querySelector(`.vl-row[data-i="${i}"]`);
    if (!rowEl) return;
    const cell = rowEl.children[col === 'desc' ? 2 : 3 + col];
    if (!cell) return;
    editing = true;
    const input = h('input.cell-input.mono', { value: initial, spellcheck: 'false', 'aria-label': col === 'desc' ? 'Description' : 'New value' });
    cell.replaceChildren(input);
    input.focus(); input.select();
    let fin = false;
    const finish = async (ok) => {
      if (fin) return;
      fin = true;
      editing = false;
      if (ok && input.value !== initial) await done(input.value);
      list.focus();
      list.refresh({ force: true });
      evalTree();
    };
    input.addEventListener('keydown', (e) => { e.stopPropagation(); if (e.key === 'Enter') { e.preventDefault(); finish(true); } else if (e.key === 'Escape') { e.preventDefault(); finish(false); } });
    input.addEventListener('blur', () => finish(false));
  }
  function editValue(i, col) {
    const r = rows[i], v = r?.vals[col];
    if (!r || !v || r.vtype === 'struct') return;
    const e = elemOf(r);
    const vtype = r.vtype === 'pointer' ? '8bytes' : r.vtype;
    inlineEdit(i, col, r.vtype === 'pointer' ? '0x' + (v.value || '0') : v.value ?? '', (val) => attempt(() => api.writeValue(v.addr, vtype, val, {
      len: SIZED.has(r.vtype) ? (r.vtype === 'string' && e?.utf16 ? r.size / 2 : r.size) : undefined, utf16: !!e?.utf16,
      hex: r.vtype === 'pointer' || (!!e?.hex && INT.has(vtype)), signed: !!e?.signed,
    })));
  }
  function editDesc(i) {
    const r = rows[i];
    if (r && !r.error) inlineEdit(i, 'desc', r.description || '', (val) => editElem(r, (e) => { e.description = val; }));
  }
  async function addToTable(r) {
    const c = columns()[0];
    if (!r || !c) return;
    const es = await attempt(() => api.structEntries(r.owner, c.expr, r.path, [r.index]));
    if (!es?.length) return;
    emit('table:add', es);
    toast(`Added ${es.length} entr${es.length > 1 ? 'ies' : 'y'} to the table`, 'info');
  }
  async function renameStruct() {
    if (!cur) return;
    const n = await prompt('Rename structure', cur, { label: 'Name', mono: false });
    if (!n || n === cur) return;
    for (const s of structs) {
      if (s.name === cur) s.name = n;
      for (const e of s.elements) if (e.child === cur) e.child = n;
    }
    cur = n;
    await save();
  }
  async function deleteStruct() {
    if (!cur) return;
    structs = structs.filter((s) => s.name !== cur);
    for (const s of structs) for (const e of s.elements) if (e.child === cur) e.child = undefined;
    cur = null;
    await save();
    toast('Structure deleted (Ctrl Z in the cheat table restores it)', 'info');
  }
  function menu(x, y, r) {
    const ok = r && !r.error, v0 = r?.vals.find(Boolean);
    contextMenu(x, y, [
      { label: 'Change value', kbd: 'Enter', disabled: !ok || !v0 || r.vtype === 'struct', run: () => editValue(list.sel, 0) },
      { label: 'Change description', kbd: 'F2', disabled: !ok, run: () => editDesc(list.sel) },
      { label: 'Change type…', kbd: 'T', disabled: !ok, run: () => changeType(r, x, y) },
      { label: 'Change size…', kbd: 'S', disabled: !ok || !SIZED.has(r.vtype), run: () => changeSize(r) },
      { label: 'Show as hexadecimal', checked: !!(ok && elemOf(r)?.hex), disabled: !ok || !INT.has(r.vtype), run: () => editElem(r, (e) => { e.hex = !e.hex; }) },
      { label: 'Show as signed', checked: !!(ok && elemOf(r)?.signed), disabled: !ok || !INT.has(r.vtype), run: () => editElem(r, (e) => { e.signed = !e.signed; }) },
      '-',
      { label: 'Add element…', kbd: 'Ins', run: () => addElement(ok ? r : null) },
      { label: 'Remove element', kbd: 'Del', disabled: !ok, run: () => removeElement(r) },
      '-',
      { label: 'Add to cheat table', kbd: 'Ctrl Enter', disabled: !ok, run: () => addToTable(r) },
      { label: 'Browse this address', kbd: 'Ctrl M', disabled: !v0, run: () => emit('mem:goto', { addr: v0.addr, pane: 'hex' }) },
      { label: 'Find out what accesses this address', disabled: !v0, run: () => emit('debug:accesses', { addr: v0.addr, vtype: r.vtype === 'pointer' ? '8bytes' : r.vtype }) },
      { label: 'Find out what writes to this address', disabled: !v0, run: () => emit('debug:writes', { addr: v0.addr, vtype: r.vtype === 'pointer' ? '8bytes' : r.vtype }) },
      { label: 'Watch the whole structure for writes…', disabled: !columns().length, run: () => watchStruct() },
    ], list.el);
  }
  /** Range watch over the structure at the first address column (its full size). */
  function watchStruct() {
    const st = structs.find((x) => x.name === cur), c = columns()[0];
    if (!st || !c) return;
    const len = Math.max(1, ...st.elements.map((e) => Number(e.offset) + (Number(e.size) || 8)));
    emit('debug:watch-range', { addr: c.addr, len, kind: 'write' });
  }
  function keys(e, i, r) {
    const k = e.key, ctrl = e.ctrlKey || e.metaKey;
    if (ctrl && k === 'Enter') addToTable(r);
    else if (ctrl && k.toLowerCase() === 'm' && r?.vals[0]) emit('mem:goto', { addr: r.vals[0].addr, pane: 'hex' });
    else if (ctrl || e.altKey) return false;
    else if (k === 'ArrowRight') { if (r?.kids && !expanded.has(r.key)) toggle(r, true); else if (r?.kids) list.select(i + 1); }
    else if (k === 'ArrowLeft') { if (r?.kids && expanded.has(r.key)) toggle(r, false); else { const p = parentIndex(i); if (p >= 0) list.select(p); } }
    else if (k === 'F2') editDesc(i);
    else if (k.toLowerCase() === 't' && r && !r.error) { const b = list.el.getBoundingClientRect(); changeType(r, b.left + 200, b.top + 40); }
    else if (k.toLowerCase() === 's' && r && SIZED.has(r.vtype)) changeSize(r);
    else if (k === 'Insert') addElement(r && !r.error ? r : null);
    else if (k === 'Delete' && r && !r.error) removeElement(r);
    else if (k.toLowerCase() === 'a') addColumn(0);
    else if (k.toLowerCase() === 'g') newStructure();
    else if (/^[1-9]$/.test(k) && +k <= columns().length) editValue(i, +k - 1);
    else return false;
    return true;
  }

  // ---------- spider ----------
  const strip = progressStrip('Structure spider progress');
  $('#st-spider-host').append(strip.wrap);
  let hits = [];
  const spHost = $('#st-spider');
  const spList = vlist($('#st-spider-list'), {
    cols: 'minmax(160px, 1fr) minmax(0, 2fr)', head: ['Path', 'Values per group'], label: 'Spider results',
    empty: 'Spider results appear here.', count: () => hits.length, item: (i) => hits[i],
    cells: (x) => [x.path.map((o, j) => (j < x.path.length - 1 ? `[+${hex(o)}]` : `+${hex(o)}`)).join(' '), x.values.map((g) => g.join(' | ')).join('   ·   ')],
    onActivate: (i) => {
      // Enter: the field at the first address as a table entry.
      const x = hits[i], c = columns()[0];
      if (!x || !c) return;
      const [p0, ...rest] = x.path;
      const width = (x.values[0]?.[0] || '').split(' ').length;
      // path [o0, o1, o2] = [[base+o0]+o1]+o2 = entry base+o0 with offsets o1, o2.
      emit('table:add', [{ description: `Spider ${x.path.map(hex).join(' ')}`, addr: `${c.expr}+${hex(p0)}`, offsets: rest.map(hex),
        vtype: { 1: 'byte', 2: '2bytes', 8: '8bytes' }[width] || '4bytes' }]);
      toast('Added to the table', 'info');
    },
  });
  async function spider() {
    const g = groups.filter((x) => x.length);
    if (g.length < 2 && !(g.length === 1 && g[0].length > 1)) { toast('Spider compares address groups: add at least two addresses (two groups, or a group with the others differing).'); return; }
    const v = await formDialog('Structure spider', [
      { name: 'size', label: 'Bytes per structure (hex)', value: '200' },
      { name: 'depth', label: 'Pointer levels to follow', value: '2' },
      { name: 'width', label: 'Value width', type: 'select', value: '4', options: [['1', '1 byte'], ['2', '2 bytes'], ['4', '4 bytes'], ['8', '8 bytes']] },
    ], { ok: 'Search', text: 'Finds fields that are equal within each group and differ between groups, following pointers.' });
    if (!v) return;
    spHost.hidden = false;
    const r = await runJob(() => api.structSpider(g.map((x) => x.map((c) => c.addr)), { size: hexNum(v.size) || 0x200, max_depth: +v.depth || 0, width: +v.width, max_results: 10000 }), strip, 'Spidering');
    if (!r) return;
    hits = r;
    $('#st-spider-count').textContent = nf.format(r.length);
    spList.refresh({ reset: true });
    spList.focus();
  }

  // ---------- wiring ----------
  $('#st-open').addEventListener('click', newStructure);
  $('#st-addcol').addEventListener('click', () => addColumn(0));
  $('#st-spider-btn').addEventListener('click', spider);
  $('#st-rename').addEventListener('click', renameStruct);
  $('#st-delete').addEventListener('click', deleteStruct);
  $('#st-spider-close').addEventListener('click', () => { spHost.hidden = true; list?.focus(); });
  on('struct:open', ({ addr, expr }) => openAt(addr, expr));
  on('process:opened', () => { groups = [[]]; expanded.clear(); rows = []; hits = []; loadStructs().then(render); });
  let structVer = null;
  on('table:version', (v) => { if (!view.hidden && v !== structVer) { structVer = v; loadStructs(); } });
  addTicker(() => (!view.hidden && !editing && state.proc && columns().length ? evalTree() : null));
  view.addEventListener('keydown', (e) => {
    if (e.target.closest('input,select,textarea')) return;
    const k = e.key.toLowerCase();
    if (e.altKey && k === 's') spider();
    else return;
    e.preventDefault();
  });
  loadStructs().then(render);
  return { focus: () => list?.focus(), refresh: () => loadStructs().then(evalTree) };
}
