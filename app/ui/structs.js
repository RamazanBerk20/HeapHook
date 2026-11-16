// Structure dissector: a tree of a structure's fields evaluated at one or more addresses
// (columns, in groups like Cheat Engine), pointer fields expanding into child structures,
// type / description / size edits, in-place value edits, "add to cheat table" with the
// pointer path, and the structure spider. Definitions live in the backend's table.
import { api, askPath } from './backend.js';
import { $, h, icon, fmtAddr, wire, attempt, toast, prompt, contextMenu, nf, busy, store, modal, helpAdd } from './util.js';
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
  // Lock and change highlighting come from the engine (struct_view): a locked column shows its
  // frozen copy and flags the leaves live memory differs in; otherwise leaves that changed since
  // the previous view. chgAt only holds a flag on screen briefly between refreshes.
  let info = []; // per column: {locked, cls} of the root structure view
  let hilite = store.get('st.hilite', true);
  const chgAt = new Map(); // `${key}|${ci}` -> time the engine last reported a change
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
  // struct_set validates every definition; on refusal its error is toasted and the local edit is
  // dropped by reloading the backend's copy.
  const save = async () => {
    const ok = await attempt(async () => { await api.structSet(structs); return true; });
    await loadStructs();
    if (ok) await evalTree(); else render();
    return !!ok;
  };
  const elemOf = (r) => structs.find((s) => s.name === r.owner)?.elements[r.index];
  sel.addEventListener('change', () => { cur = sel.value; expanded.clear(); chgAt.clear(); evalTree(); });

  // ---------- evaluation ----------
  const isBox = (f) => f.vtype === 'struct' || f.children.length > 0; // flattened, not a leaf
  const leafCount = (fs) => fs.reduce((n, f) => n + (isBox(f) ? leafCount(f.children) : 1), 0);
  async function evalTree() {
    const g = ++gen, cols = columns();
    if (!cur || !cols.length) { rows = []; render(); return; }
    const out = [], now = performance.now(), inf = cols.map(() => ({ locked: false, cls: null }));
    // name: the structure evaluated at `bases` (one per column); fp: element path from the root.
    async function level(name, bases, depth, prefix, path, fp) {
      const live = bases.map((b, i) => (b ? i : -1)).filter((i) => i >= 0);
      if (!live.length) return;
      const res = await api.structView(live.map((i) => ({ name, addr: bases[i] })));
      const per = bases.map(() => null);
      live.forEach((ci, k) => { per[ci] = res[k]?.Ok || null; });
      if (!depth) per.forEach((v, ci) => { if (v) inf[ci] = { locked: !!v.locked, cls: v.class || null }; });
      const proto = per.find(Boolean)?.fields;
      if (!proto) { out.push({ key: prefix + 'err', depth, error: res[0]?.Err || 'unreadable' }); return; }
      const chg = per.map((v) => new Set(v?.changed || []));
      const lv = { name, bases };
      let leaf = 0; // index in the engine's flattened leaf order (depth-first)
      const walk = async (fields, d, pre, getter, fpre, items) => {
        for (let i = 0; i < fields.length; i++) {
          const f = fields[i], key = pre + i, vals = cols.map((_, ci) => getter(ci)?.[i] ?? null);
          const e = elemOf(f), box = isBox(f), fpath = [...fpre, items ? i : f.index];
          const ln = box ? null : leaf++;
          const ch = cols.map((_, ci) => ln != null && chg[ci].has(ln));
          ch.forEach((c, ci) => { if (c) chgAt.set(key + '|' + ci, now); });
          const kids = box ? f.children.length > 0 : f.vtype === 'pointer' && vals.some((v) => v?.target);
          out.push({ key, depth: d, owner: f.owner, index: f.index, offset: f.offset, vtype: f.vtype, size: f.size, description: f.description, child: f.child,
            vals, kids, path, lv, leaf: ln, chg: ch, fpath, item: items, arr: !items && e?.count > 1 });
          if (box) {
            if (kids && expanded.has(key)) await walk(f.children, d + 1, key + '.', (ci) => getter(ci)?.[i]?.children, fpath, !items && e?.count > 1);
            else leaf += leafCount(f.children);
          } else if (kids && expanded.has(key) && f.child) {
            // The child starts child_start bytes before where the pointer points.
            const cs = BigInt(e?.child_start || 0);
            const tb = vals.map((v) => { const t = v?.target ? BigInt(v.target) : null; return t != null && t >= cs ? wire(t - cs) : null; });
            await level(f.child, tb, d + 1, key + '/', [...path, f.offset], fpath);
          }
        }
      };
      await walk(proto, depth, prefix, (ci) => per[ci]?.fields, fp, false);
    }
    try { await level(cur, cols.map((c) => c.addr), 0, '', [], []); } catch (e) { if (g === gen) toast(e); }
    if (g !== gen) return;
    info = inf;
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
      head: ['Offset', 'Type', 'Description', ...(heads = cols.map((c) => h('span', { class: 'st-colhead', title: c.expr })))],
      label: 'Structure fields', row: 22,
      empty: () => (!state.proc ? ['No process. Open one with ', h('kbd', null, 'Ctrl P'), ', then dissect a structure at an address.']
        : !structs.length ? ['No structure yet. Press ', h('kbd', null, 'G'), ' to dissect at an address, or use "Open in structure dissector" in the cheat table, scan results, memory view or registers. ', h('kbd', null, 'Ctrl I'), ' imports structures from a file.']
          : !cols.length ? ['Add an address column with ', h('kbd', null, 'A'), '.'] : 'No fields.'),
      count: () => rows.length, item: (i) => rows[i],
      rowClass: (r) => (r.error ? 'st-errrow' : ''),
      cells(r) {
        if (r.error) return [h('span', { role: 'gridcell', style: `padding-left:${r.depth * 14}px` }, r.error)];
        const gi = groupIdx(), cls = classify(r.vals.map((v) => v?.value ?? null), gi);
        const caret = r.kids ? h('span.st-caret', { html: icon(expanded.has(r.key) ? 'chevD' : 'chevR') }) : h('span.st-caret');
        return [
          h('span', { role: 'gridcell', class: 'st-off', style: `padding-left:${r.depth * 14}px` }, caret, hex(r.offset)),
          (() => { const t = typeText(r); return h('span', { role: 'gridcell', class: 'st-type', title: t }, t); })(),
          h('span', { role: 'gridcell', class: 'st-desc' }, r.description || ''),
          ...r.vals.map((v, ci) => {
            const txt = v == null ? '??' : v.value ?? (r.leaf == null ? '' : '??');
            const changed = hilite && r.leaf != null && (r.chg[ci] || performance.now() - (chgAt.get(r.key + '|' + ci) || 0) < 1500);
            const lockedCol = info[ci]?.locked;
            return h('span', { role: 'gridcell', class: 'st-val ' + cls + (changed ? ' chg' : ''), title: changed ? (lockedCol ? 'Live memory differs from this locked value' : 'Changed since the previous refresh') : null }, txt);
          }),
        ];
      },
      onActivate: (i, r, e) => (e?.type === 'dblclick' && r?.kids ? toggle(r, true) : editValue(i, 0)),
      onMenu: (x, y, i, r) => menu(x, y, r),
      onKey: keys,
    });
  }
  /** Type column: bit fields, arrays and the child structure (with its start offset). */
  function typeText(r) {
    const e = elemOf(r);
    let t = (TNAME[r.vtype] || r.vtype) + (SIZED.has(r.vtype) ? `[${e?.size || r.size}]` : '');
    if (r.arr) t += ` × ${e?.count}`;
    if (e?.bit_len) t += e.bit_len === 1 ? ` bit ${e.bit_offset || 0}` : ` bits ${e.bit_offset || 0}-${(e.bit_offset || 0) + e.bit_len - 1}`;
    if (r.child && r.vtype === 'pointer') t += ` → ${r.child}` + (e?.child_start ? ` -${hex(e.child_start)}` : '');
    return t;
  }
  let heads = [];
  /** Column headers: address, C++ class (RTTI, from the target: text only) and lock state. */
  function renderHeads() {
    columns().forEach((c, ci) => {
      const el = heads[ci], inf = info[ci] || {};
      if (!el) return;
      el.replaceChildren(...[`${groups.length > 1 ? 'G' + (c.gi + 1) + ' · ' : ''}${fmtAddr(c.addr)}`,
        inf.cls ? h('span.st-class', null, ' ' + inf.cls) : null, inf.locked ? h('span.st-locked', null, ' · locked') : null].filter(Boolean));
      el.title = c.expr + (inf.cls ? ` · class ${inf.cls}` : '') + (inf.locked ? ' · locked' : '');
    });
  }
  function render() {
    if (columns().length !== ncols || !list) build();
    renderHeads();
    renderCols();
    list.refresh({ force: true });
  }
  function renderCols() {
    colsBar.replaceChildren(...groups.map((g, gi) => h('div.st-group', { role: 'group', 'aria-label': `Group ${gi + 1}` },
      h('span.st-glabel', null, groups.length > 1 ? `Group ${gi + 1}` : 'Addresses'),
      ...g.map((c, ci) => h('span.st-chip.mono', { title: c.expr }, c.expr === fmtAddr(c.addr) ? c.expr : `${c.expr} = ${fmtAddr(c.addr)}`,
        h('button.st-lock', { type: 'button', 'aria-pressed': String(!!info[flatIdx(gi, ci)]?.locked), title: 'Lock: show a frozen copy and highlight where live memory differs (L)', onclick: () => toggleLock(flatIdx(gi, ci)) }, info[flatIdx(gi, ci)]?.locked ? 'Locked' : 'Lock'),
        h('button.st-x', { type: 'button', 'aria-label': `Remove ${c.expr}`, html: icon('x'), onclick: () => removeColumn(gi, ci) }))),
      h('button.btn.ghost.icon', { type: 'button', 'aria-label': `Add an address to group ${gi + 1}`, title: 'Add address (A)', html: icon('plus'), onclick: () => addColumn(gi) }))),
    h('button.btn.ghost', { type: 'button', onclick: () => { groups.push([]); addColumn(groups.length - 1); } }, h('span', { html: icon('group') }), 'Group'));
  }

  const flatIdx = (gi, ci) => groups.slice(0, gi).reduce((n, g) => n + g.length, 0) + ci;
  async function toggleLock(ci) {
    const c = columns()[ci];
    if (!c || !cur) return;
    const on = !info[ci]?.locked;
    if (!(await attempt(async () => { await api.structLock(cur, c.addr, on); return true; }))) return;
    await evalTree();
    toast(on ? 'Column locked: it shows the values at lock time; fields where live memory differs are highlighted' : 'Column unlocked', 'info');
  }
  function removeColumn(gi, ci) {
    const fi = flatIdx(gi, ci), c = groups[gi][ci];
    if (info[fi]?.locked && cur) api.structLock(cur, c.addr, false).catch(() => {});
    groups[gi].splice(ci, 1);
    info.splice(fi, 1);
    if (!groups[gi].length && groups.length > 1) groups.splice(gi, 1);
    render(); evalTree();
  }
  function toggleHilite() {
    hilite = !hilite; store.set('st.hilite', hilite);
    hlBtn.setAttribute('aria-pressed', String(hilite));
    render();
  }
  // ---------- element editor ----------
  /** Every element field: offset, type, size, array count, bit field, pointer child start. */
  async function editElement(r) {
    const e = elemOf(r);
    if (!e) return;
    const v = await formDialog(`Element at +${hex(e.offset)} of ${r.owner}`, [
      { name: 'offset', label: 'Offset (hex)', value: hex(e.offset) },
      { name: 'description', label: 'Description', value: e.description || '', mono: false },
      { name: 'vtype', label: 'Type', type: 'select', value: e.vtype, options: TYPES.filter(([t]) => t !== 'struct' || e.vtype === 'struct') },
      { name: 'size', label: 'Size in bytes (strings, byte arrays)', value: String(e.size || 0) },
      { name: 'count', label: 'Array: number of items (0 or 1 = a single value)', value: String(e.count || 0) },
      { name: 'bit_offset', label: 'Bit field: first bit (0 = least significant)', value: String(e.bit_offset || 0), hint: 'Bit fields need an integer type (Byte to 8 Bytes)' },
      { name: 'bit_len', label: 'Bit field: number of bits (0 = the whole value)', value: String(e.bit_len || 0) },
      { name: 'child_start', label: 'Pointer: child structure starts this far before the target (hex)', value: hex(e.child_start || 0) },
      { name: 'hex', label: 'Show as hexadecimal', type: 'checkbox', value: !!e.hex },
      { name: 'signed', label: 'Show as signed', type: 'checkbox', value: !!e.signed },
      { name: 'utf16', label: 'String is UTF-16', type: 'checkbox', value: !!e.utf16 },
    ], { ok: 'Apply' });
    list.focus();
    if (!v) return;
    const dec = (x) => (/^\d+$/.test(x) ? +x : NaN);
    const n = { offset: hexNum(v.offset), size: dec(v.size), count: dec(v.count), bit_offset: dec(v.bit_offset), bit_len: dec(v.bit_len), child_start: hexNum(v.child_start) };
    const bad = Object.entries(n).find(([, x]) => !(x >= 0));
    if (bad) { toast(`${bad[0].replace('_', ' ')}: not a valid number`); return; }
    if ((n.bit_len || n.bit_offset) && !INT.has(v.vtype)) { toast('Bit fields need an integer type (Byte, 2, 4 or 8 Bytes)'); return; }
    Object.assign(e, n, { description: v.description, vtype: v.vtype, hex: v.hex, signed: v.signed, utf16: v.utf16 });
    if (v.vtype !== 'pointer' && v.vtype !== 'struct') { e.child = undefined; e.child_start = 0; }
    if (SIZED.has(v.vtype) && !e.size) e.size = 16;
    const st = structs.find((s) => s.name === r.owner);
    st?.elements.sort((a, b) => a.offset - b.offset);
    await save(); // struct_set validates; its error is shown and the edit dropped
    list.focus();
  }

  // ---------- C / C# ----------
  async function exportCode() {
    if (!structs.length) { toast('No structures to export'); return; }
    const v = await formDialog('Export as source code', [
      { name: 'lang', label: 'Language', type: 'select', value: store.get('st.lang', 'c'), options: [['c', 'C'], ['csharp', 'C#']] },
      { name: 'which', label: 'Structures', type: 'select', value: cur ? 'cur' : 'all', options: [...(cur ? [['cur', `${cur} and the structures it uses`]] : []), ['all', `All ${structs.length} structures`]] },
    ], { ok: 'Generate' });
    if (!v) { list?.focus(); return; }
    store.set('st.lang', v.lang);
    const text = await attempt(() => api.structCode(v.which === 'cur' ? [cur] : [], v.lang));
    if (text == null) { list?.focus(); return; }
    const ext = v.lang === 'c' ? 'h' : 'cs';
    const r = await modal({ title: `${v.lang === 'c' ? 'C' : 'C#'} definitions`, pre: text, label: 'Source code',
      buttons: [{ label: 'Copy', value: 'copy', primary: true, kbd: 'Enter' }, { label: 'Save…', value: 'save' }, { label: 'Close', value: 'cancel', kbd: 'Esc' }] });
    if (r.value === 'copy') { if (await attempt(async () => { await navigator.clipboard.writeText(text); return true; })) toast('Copied', 'info'); }
    else if (r.value === 'save') {
      const p = await askPath({ save: true, title: 'Save source code', filters: [[v.lang === 'c' ? 'C header' : 'C# source', [ext]]], dflt: `${v.which === 'cur' ? cur : 'structures'}.${ext}` });
      if (p && (await attempt(async () => { await api.structCode(v.which === 'cur' ? [cur] : [], v.lang, p); return true; }))) toast(`Saved ${p}`, 'info');
    }
    list?.focus();
  }

  // ---------- export / import ----------
  const ST_FILTERS = [['Structures', ['json', 'xml']], ['HeapHook JSON', ['json']], ['Cheat Engine XML', ['xml']]];
  async function exportStructs() {
    if (!structs.length) { toast('No structures to export'); return; }
    const v = await formDialog('Export structures', [{ name: 'which', label: 'Export', type: 'select', value: cur ? 'cur' : 'all', options: [...(cur ? [['cur', `Only ${cur}`]] : []), ['all', `All ${structs.length} structures`]] }],
      { ok: 'Choose file', text: '.json keeps HeapHook\'s format; .xml is Cheat Engine\'s <Structures>.' });
    if (!v) return;
    const p = await askPath({ save: true, title: 'Export structures', filters: ST_FILTERS, dflt: (v.which === 'cur' ? cur : 'structures') + '.json' });
    if (!p) return;
    if (await attempt(async () => { await api.structExport(p, v.which === 'cur' ? [cur] : []); return true; })) toast(`Exported to ${p}`, 'info');
    list?.focus();
  }
  async function importStructs() {
    const p = await askPath({ save: false, title: 'Import structures', filters: [...ST_FILTERS, ['All files', ['*']]], dflt: 'structures.json' });
    if (!p) return;
    const names = await attempt(() => api.structImport(p));
    if (!names) return;
    if (names.length) cur = names[0];
    await loadStructs();
    render(); evalTree();
    toast(names.length ? `Imported ${names.join(', ')}` : 'The file had no structures', 'info');
    list?.focus();
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
      const st = await attempt(() => busy('Guessing the structure layout', api.structGuess(v.name, wire(BigInt(addr)), hexNum(v.size) || 0x100)));
      if (!st) return;
      name = st.name;
    }
    cur = name;
    const c = { expr: expr || fmtAddr(addr), addr: wire(BigInt(addr)) };
    if (v.mode === 'replace' || !columns().length) groups = [[c]];
    else if (v.mode === 'group') groups.push([c]);
    else groups[0].push(c);
    expanded.clear(); chgAt.clear();
    await loadStructs();
    render();
    await busy('Reading the structure', evalTree());
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
  /** Writes through the engine (struct_write): bit fields keep their other bits, array items work. */
  function editValue(i, col) {
    const r = rows[i], v = r?.vals[col], base = r?.lv?.bases[col];
    if (!r || !v || r.leaf == null || !base) return;
    inlineEdit(i, col, r.vtype === 'pointer' ? '0x' + (v.value || '0') : v.value ?? '', (val) => attempt(() => api.structWrite(r.lv.name, base, r.leaf, val)));
  }
  function editDesc(i) {
    const r = rows[i];
    if (r && !r.error) inlineEdit(i, 'desc', r.description || '', (val) => editElem(r, (e) => { e.description = val; }));
  }
  async function addToTable(r) {
    const c = columns()[0];
    if (!r || r.error || !c) return;
    if (r.leaf != null) {
      // One field, reached from the root structure through nested structures, array items and pointers.
      const en = await attempt(() => api.structFieldEntry(cur, c.expr, r.fpath));
      if (!en) return;
      emit('table:add', [en]);
      toast('Added the field to the table', 'info');
      return;
    }
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
      { label: 'Edit element…', kbd: 'E', disabled: !ok, run: () => editElement(r) },
      { label: 'Change size…', kbd: 'S', disabled: !ok || !SIZED.has(r.vtype), run: () => changeSize(r) },
      { label: 'Show as hexadecimal', checked: !!(ok && elemOf(r)?.hex), disabled: !ok || !INT.has(r.vtype), run: () => editElem(r, (e) => { e.hex = !e.hex; }) },
      { label: 'Show as signed', checked: !!(ok && elemOf(r)?.signed), disabled: !ok || !INT.has(r.vtype), run: () => editElem(r, (e) => { e.signed = !e.signed; }) },
      '-',
      { label: 'Add element…', kbd: 'Ins', run: () => addElement(ok ? r : null) },
      { label: 'Remove element', kbd: 'Del', disabled: !ok, run: () => removeElement(r) },
      '-',
      { label: r?.leaf != null ? 'Add this field to the cheat table' : 'Add its fields to the cheat table', kbd: 'Ctrl Enter', disabled: !ok, run: () => addToTable(r) },
      { label: 'Export as C / C#…', kbd: 'C', disabled: !structs.length, run: () => exportCode() },
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
    else if (k.toLowerCase() === 'l' && columns().length) toggleLock(Math.max(0, info.findIndex((x) => x?.locked)));
    else if (k.toLowerCase() === 'e' && r && !r.error) editElement(r);
    else if (k.toLowerCase() === 'c') exportCode();
    else if (k.toLowerCase() === 'h') toggleHilite();
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
  const hlBtn = h('button.btn.ghost#st-hilite', { type: 'button', 'aria-pressed': String(hilite), title: 'Highlight values that changed, or differ from live memory in a locked column (H)', onclick: toggleHilite }, h('span.bl', null, 'Highlight changes'), ' ', h('kbd', null, 'H'));
  $('#st-rename').before(hlBtn,
    h('button.btn.ghost.icon#st-import', { type: 'button', 'aria-label': 'Import structures (Ctrl I)', title: 'Import structures (Ctrl I)', html: icon('folder'), onclick: importStructs }),
    h('button.btn.ghost.icon#st-export', { type: 'button', 'aria-label': 'Export structures (Ctrl Shift E)', title: 'Export structures (Ctrl Shift E)', html: icon('save'), onclick: exportStructs }));
  $('#st-spider-close').addEventListener('click', () => { spHost.hidden = true; list?.focus(); });
  on('struct:open', ({ addr, expr }) => openAt(addr, expr));
  on('process:opened', () => { groups = [[]]; expanded.clear(); rows = []; hits = []; info = []; chgAt.clear(); loadStructs().then(render); });
  on('process:closed', () => { groups = [[]]; rows = []; info = []; render(); });
  let structVer = null;
  on('table:version', (v) => { if (!view.hidden && v !== structVer) { structVer = v; loadStructs(); } });
  addTicker(() => (!view.hidden && !editing && state.proc && columns().length ? evalTree() : null));
  view.addEventListener('keydown', (e) => {
    if (e.target.closest('input,select,textarea')) return;
    const k = e.key.toLowerCase();
    if (e.altKey && k === 's') spider();
    else if ((e.ctrlKey || e.metaKey) && e.shiftKey && k === 'e') exportStructs();
    else if ((e.ctrlKey || e.metaKey) && k === 'i') importStructs();
    else return;
    e.preventDefault();
  });
  helpAdd('Structures', [
    ['E', 'Edit element: bit field, array count, pointer child start'],
    ['C', 'Export as C / C# (copy or save)'],
    ['Ctrl Enter', 'Add the field under the cursor to the cheat table (with its pointer path)'],
  ]);
  loadStructs().then(render);
  return { focus: () => list?.focus(), refresh: () => loadStructs().then(evalTree) };
}
