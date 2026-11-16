// Cheat table: tree of address / script / group entries with inline edit, freeze,
// multi-select, drag reorder, copy/paste, colors, hotkeys, dropdown lists, group options,
// table Lua script and comments, save/load.
//
// The backend owns the table (Lua scripts and hotkeys change it too). This module keeps a
// mirror: it refetches when the backend's version moves (lua.js polls it) and sends every
// edit as a whole-table put based on the version it saw; a stale put is refetched and the
// edit replayed. Activation and value writes are backend commands.
import { api, askPath } from './backend.js';
import { $, h, icon, fmtAddr, wire, isHexAddr, attempt, toast, contextMenu, store, modal, rafThrottle, excerpt, codeView } from './util.js';
import { listCustomTypes, editCustomType, ctLabel } from './custom.js';
import { state, addSource, addTicker, emit, on, TICK_MS } from './core.js';
import { comboOf, comboText, MODS } from './keys.js';

const ROW = 24;
export const VTYPES = [['byte', 'Byte'], ['2bytes', '2 Bytes'], ['4bytes', '4 Bytes'], ['8bytes', '8 Bytes'], ['float', 'Float'],
  ['double', 'Double'], ['string', 'String'], ['aob', 'Array of byte'], ['binary', 'Binary']];
const VNAME = Object.fromEntries(VTYPES);
const INT = new Set(['byte', '2bytes', '4bytes', '8bytes']);
const COLORS = [['Default', null], ['Red', '#9F2F2D'], ['Blue', '#1F6C9F'], ['Green', '#346538'], ['Yellow', '#956400']];
// The palette colors follow the theme; any other color is shown as stored.
const COLOR_VAR = { '#9F2F2D': 'var(--red)', '#1F6C9F': 'var(--blue)', '#346538': 'var(--green)', '#956400': 'var(--yellow)' };
const MODES = [['exact', 'Freeze'], ['allow_increase', 'Allow increase'], ['allow_decrease', 'Allow decrease']];
const HK_ACTIONS = [['Toggle Activation', 'Toggle activation'], ['Toggle Activation Allow Increase', 'Toggle, allow increase'],
  ['Toggle Activation Allow Decrease', 'Toggle, allow decrease'], ['Activate', 'Activate'], ['Deactivate', 'Deactivate'],
  ['Set Value', 'Set value to'], ['Increase Value', 'Increase value by'], ['Decrease Value', 'Decrease value by']];
const HK_VALUE = new Set(['Set Value', 'Increase Value', 'Decrease Value']);
const GROUP_DEFAULT = ['moActivateChildrenAsWell', 'moDeactivateChildrenAsWell'];
const SCRIPT_TEMPLATE = `[ENABLE]
// code that runs when the entry is activated
alloc(newmem,1024)

[DISABLE]
// undo everything [ENABLE] did
dealloc(newmem)
`;

let editMetaHook = null;
/**
 * Edits table-level fields (symbols, disasm_comments, ...) in place: `fn(table)` mutates them and
 * must be safe to run again (a stale put replays it on the refetched table).
 */
export async function editTableMeta(fn) {
  if (editMetaHook) return editMetaHook(fn);
  for (let i = 0; ; i++) {
    const { version, table } = await api.tableGet();
    fn(table);
    try { await api.tablePut(table, version); return; } catch (e) { if (!/stale/.test(String(e)) || i >= 3) throw e; }
  }
}

export function initTable(root) {
  const grid = $('.tbl', root), body = $('.tbl-body', root);
  let roots = [], seq = 1, cursor = null, anchor = null, clip = null, tablePath = store.get('tablePath', 'table.json');
  let version = 0, meta = { lua_script: '', comments: '', codes: [], structures: [], ct_extra: [] };
  const sel = new Set(), collapsed = new Set();
  const rt = new Map(); // id -> {addr: BigInt|null, value, chgAt}
  const R = (id) => { let r = rt.get(id); if (!r) rt.set(id, (r = { addr: null, value: null, chgAt: 0 })); return r; };
  let flat = [];

  const entry = (p = {}) => ({
    id: seq++, description: 'No description', addr: '', offsets: [], vtype: '4bytes', len: 0, utf16: false, signed: false,
    hex: false, frozen: false, freeze_mode: 'exact', color: null, dropdown: null, hotkeys: [], script: null, children: [], options: [], ...p,
  });
  const isScript = (e) => typeof e.script === 'string';
  const isGroup = (e) => !isScript(e) && !e.addr;
  const isValue = (e) => !isScript(e) && !isGroup(e);
  /** A Cheat Engine custom type the table names but does not define: kept as is, never read or written. */
  const unsupported = (e) => !!e.custom_name && !e.custom;
  const opt = (e, o) => (e.options || []).includes(o);
  const walk = (list, f, parent = null) => list.forEach((e, i) => { f(e, list, i, parent); walk(e.children, f, e); });
  function find(id) { let r = null; walk(roots, (e, list, index, parent) => { if (e.id === id) r = { e, list, index, parent }; }); return r; }
  const byId = (id) => find(id)?.e;
  const all = () => { const out = []; walk(roots, (e) => out.push(e)); return out; };
  const isDesc = (a, b) => { let hit = false; walk(a.children, (e) => { if (e === b) hit = true; }); return hit; };
  /** Children are not listed: always hidden, or hidden while inactive (CE group options). */
  const kidsHidden = (e) => opt(e, 'moAlwaysHideChildren') || (opt(e, 'moHideChildren') && !e.frozen && !opt(e, 'moAllowManualCollapseAndExpand'));
  const showsKids = (e) => e.children.length > 0 && !kidsHidden(e);

  function flatten() {
    flat = [];
    const go = (list, depth) => list.forEach((e) => { flat.push({ e, depth }); if (showsKids(e) && !collapsed.has(e.id)) go(e.children, depth + 1); });
    go(roots, 1);
  }
  /** Selected entries, ancestors only (a selected group carries its children). */
  function topSelected() {
    const out = [];
    const go = (list) => list.forEach((e) => (sel.has(e.id) ? out.push(e) : go(e.children)));
    go(roots);
    return out;
  }
  const selectedAll = () => all().filter((e) => sel.has(e.id));
  const selIds = () => selectedAll().map((e) => e.id);

  // ---------- sync with the backend ----------
  const norm = (x) => ({ ...entry(), ...x, offsets: x.offsets || [], hotkeys: x.hotkeys || [], options: x.options || [], children: (x.children || []).map(norm) });
  const strip = (e) => ({ ...e, children: e.children.map(strip) });
  const snapshot = () => ({ ...meta, entries: roots.map(strip) });
  function adopt(st) {
    version = st.version;
    state.tableTrust = st.trust || 'own';
    const t = st.table;
    roots = (t.entries || []).map(norm);
    // Every table field rides along in puts (custom_types, symbols, disasm_comments, ...), not only the ones edited here.
    const { entries: _e, ...rest } = t;
    meta = { ...rest, lua_script: t.lua_script || '', comments: t.comments || '', codes: t.codes || [], structures: t.structures || [], ct_extra: t.ct_extra || [] };
    emit('table:meta', meta);
    let max = 0;
    walk(roots, (e) => { max = Math.max(max, e.id); });
    seq = max + 1;
    const ids = new Set(all().map((e) => e.id));
    for (const id of [...sel]) if (!ids.has(id)) sel.delete(id);
    for (const id of [...rt.keys()]) if (!ids.has(id)) rt.delete(id);
    render();
  }
  let inflight = 0;
  async function refetch() { const st = await attempt(() => api.tableGet()); if (st) adopt(st); }
  /** Applies `fn` (which must find entries by id) locally, then puts; replays on a stale put. */
  async function doCommit(fn) {
    inflight++;
    try {
      fn(); render();
      for (let i = 0; i < 4; i++) {
        try { version = await api.tablePut(snapshot(), version); return; } catch (e) {
          if (!/stale/.test(String(e))) { toast(e?.message || e); await refetch(); return; } // e.g. a script entry whose disable section failed
          await refetch(); fn(); render();
        }
      }
      toast('The table kept changing; your last edit was not saved');
      await refetch();
    } finally { inflight--; }
  }
  let chain = Promise.resolve();
  /** Edits land one after another, in order. */
  const commit = (fn) => (chain = chain.then(() => doCommit(fn)).catch((e) => toast(e?.message || e)));
  on('table:version', (v) => { if (v !== version && !inflight) chain = chain.then(refetch); });

  // ---------- rendering ----------
  const typeText = (e) => isScript(e) ? 'Auto Assembler script' : isGroup(e) ? '' :
    unsupported(e) ? `Custom: ${e.custom_name} (unsupported)` : e.custom ? ctLabel(e.custom_name, e.custom) :
    e.vtype === 'string' ? `String[${e.len || 16}]${e.utf16 ? ' UTF-16' : ''}` : e.vtype === 'aob' ? `Array of byte[${e.len || 8}]` : VNAME[e.vtype] || e.vtype;
  const addrText = (e) => {
    if (isScript(e)) return '<script>';
    if (isGroup(e)) return '';
    const a = R(e.id).addr;
    if (e.offsets.length) return 'P->' + (a == null ? '????????' : fmtAddr(a));
    return isHexAddr(e.addr) ? fmtAddr('0x' + e.addr.replace(/^0x/i, '')) : `${e.addr} = ${a == null ? '????????' : fmtAddr(a)}`;
  };
  const same = (a, b) => String(a).trim().toLowerCase().replace(/^0x/, '') === String(b).trim().toLowerCase().replace(/^0x/, '');
  /** The dropdown item matching the live value. */
  const itemOf = (e, v) => (v == null ? null : e.dropdown?.options.find((o) => same(o.value, v)) ?? null);
  const shown = (e, v) => {
    if (v == null) return '??';
    const it = e.dropdown?.display_value_as_item && itemOf(e, v);
    return it ? it.text : v;
  };
  const valueText = (e) => !isValue(e) ? '' : unsupported(e) ? 'unsupported' : shown(e, R(e.id).value);

  function rowEl({ e, depth }) {
    const r = R(e.id), active = e.frozen;
    const caret = showsKids(e)
      ? h('button.caret', { tabindex: '-1', 'aria-hidden': 'true', html: icon(collapsed.has(e.id) ? 'chevR' : 'chevD'), 'data-act': 'toggle' })
      : h('span.caret');
    const mode = isValue(e) && e.freeze_mode !== 'exact'
      ? h('span.mode', { title: MODES.find((m) => m[0] === e.freeze_mode)[1], html: icon(e.freeze_mode === 'allow_increase' ? 'up' : 'down') }) : null;
    const marks = [
      e.hotkeys.length ? h('span.mark', { title: e.hotkeys.map((k) => comboText(k.keys)).join(', '), html: icon('key') }) : null,
      e.children.length && !showsKids(e) ? h('span.mark.muted', { title: `${e.children.length} hidden`, html: icon('group') }) : null,
    ];
    const row = h('div.trow', {
      role: 'row', id: 'te-' + e.id, 'aria-level': depth, 'aria-selected': String(sel.has(e.id)),
      'aria-expanded': showsKids(e) ? String(!collapsed.has(e.id)) : null, draggable: 'true', 'data-id': e.id,
    },
    h('span.c-act', { role: 'gridcell' }, h('span.box', { 'data-act': 'active', 'aria-label': active ? 'Active' : 'Inactive', html: active ? icon('check') : '' }), mode),
    h('span.c-desc', { role: 'gridcell', 'data-col': 'description', style: `padding-left:${(depth - 1) * 16 + 4}px` }, caret, h('span.txt', null, e.description), ...marks),
    h('span.c-addr.mono', { role: 'gridcell', 'data-col': 'addr' }, addrText(e)),
    h('span.c-type', { role: 'gridcell', 'data-col': 'vtype' }, typeText(e)),
    h('span.c-val.mono', { role: 'gridcell', 'data-col': 'value' }, valueText(e)));
    row.classList.toggle('active', active);
    row.classList.toggle('group', isGroup(e));
    row.classList.toggle('cursor', cursor === e.id);
    if (e.color) row.style.setProperty('--entry-color', COLOR_VAR[e.color.toUpperCase()] || e.color);
    if (performance.now() - r.chgAt < 1000) row.querySelector('.c-val').classList.add('chg');
    return row;
  }
  /** Lua's SelectedRecords reads the backend's copy of the selection. */
  let selKey = '';
  function syncSel() {
    const k = [...sel].sort((a, b) => a - b).join(',');
    if (k === selKey) return;
    selKey = k;
    api.tableSelect([...sel]).catch(() => {});
  }
  // A script set the selection (getAddressList().SelectedRecords = ...).
  let luaSel = 0;
  on('table:selection', (s) => {
    if (!s || s.seq === luaSel) return;
    const first = !luaSel && s.seq;
    luaSel = s.seq;
    if (first && !s.ids.length) return;
    sel.clear(); s.ids.forEach((id) => sel.add(id));
    selKey = [...sel].sort((a, b) => a - b).join(',');
    if (s.ids.length) cursor = s.ids[0];
    render();
  });
  // Virtualized: only the rows in view (plus a few) exist; the spacer gives the scroll height.
  const spacer = h('div.tbl-spacer', { 'aria-hidden': 'true' }), layer = h('div.tbl-layer', { role: 'presentation' });
  body.replaceChildren(spacer, layer);
  const OVER = 6;
  let first = 0, editingId = null;
  function paint() {
    if (editingId != null) return; // an inline editor lives in a row; repaint after it closes
    const vis = Math.ceil(body.clientHeight / ROW) + 1;
    first = Math.max(0, Math.min(Math.floor(body.scrollTop / ROW) - OVER, flat.length - vis - OVER));
    const end = Math.min(flat.length, first + vis + OVER * 2);
    spacer.style.height = flat.length * ROW + 'px';
    layer.style.transform = `translateY(${first * ROW}px)`;
    const rows = [];
    for (let i = first; i < end; i++) { const r = rowEl(flat[i]); r.setAttribute('aria-rowindex', i + 2); rows.push(r); }
    layer.replaceChildren(...rows);
    grid.setAttribute('aria-activedescendant', cursor != null && rowOf(cursor) ? 'te-' + cursor : '');
    resolveVisible();
  }
  const paintSoon = rafThrottle(paint);
  body.addEventListener('scroll', paintSoon, { passive: true });
  new ResizeObserver(paintSoon).observe(body);
  function render() {
    flatten();
    if (cursor != null && !flat.some((f) => f.e.id === cursor)) cursor = flat[0]?.e.id ?? null;
    grid.setAttribute('aria-rowcount', flat.length + 1);
    paint();
    $('#tbl-empty').hidden = flat.length > 0;
    $('#tbl-count').textContent = flat.length ? String(all().length) : '';
    $('#tb-lua').classList.toggle('has', !!meta.lua_script.trim());
    $('#tb-comments').classList.toggle('has', !!meta.comments.trim());
    $('#tb-labels')?.classList.toggle('has', !!meta.symbols?.length);
    syncSel();
  }
  function rowOf(id) { return document.getElementById('te-' + id); }
  /** Scrolls the cursor row into view and makes sure it is rendered. */
  function scrollToCursor() {
    const i = cursorIdx();
    if (i < 0) return;
    const top = i * ROW, h_ = body.clientHeight;
    if (top < body.scrollTop) body.scrollTop = top;
    else if (top + ROW > body.scrollTop + h_) body.scrollTop = top + ROW - h_;
    if (!rowOf(cursor)) paint();
  }

  // ---------- addresses (display only; the backend resolves for freezing) ----------
  const exprOf = (e) => e.offsets.reduce((x, off) => `[${x}]+${off}`, e.addr);
  let resolving = false, resolveAgain = false;
  /** One resolve_many call for the rows in view (the backend resolves what it freezes itself). */
  async function resolveVisible() {
    if (!state.proc) return;
    if (resolving) { resolveAgain = true; return; }
    resolving = true;
    try {
      const es = [];
      for (let i = first; i < Math.min(flat.length, first + layer.childElementCount); i++) if (isValue(flat[i].e)) es.push(flat[i].e);
      const lit = (e) => !e.offsets.length && isHexAddr(e.addr);
      const ask = es.filter((e) => !lit(e));
      const got = ask.length ? await api.resolveMany(ask.map(exprOf)).catch(() => ask.map(() => null)) : [];
      const res = new Map(ask.map((e, i) => [e, got[i]]));
      for (const e of es) {
        const r = R(e.id), s = lit(e) ? '0x' + e.addr.trim().replace(/^0x/i, '') : res.get(e);
        const a = s == null ? null : BigInt(s);
        if (a !== r.addr) { r.addr = a; const c = rowOf(e.id)?.querySelector('.c-addr'); if (c && !c.querySelector('input')) c.textContent = addrText(e); }
      }
    } finally {
      resolving = false;
      if (resolveAgain) { resolveAgain = false; resolveVisible(); }
    }
  }
  let tickN = 0;
  addTicker(() => { if (++tickN % Math.max(1, Math.round(1000 / TICK_MS)) === 0) return resolveVisible(); });

  // ---------- live values ----------
  addSource({
    ids: [],
    collect() {
      this.ids = [];
      if (state.view !== 'scan' || !flat.length) return [];
      const lo = Math.floor(body.scrollTop / ROW), hi = Math.min(flat.length, lo + Math.ceil(body.clientHeight / ROW) + 1);
      const reqs = [];
      for (const { e } of flat.slice(lo, hi)) {
        const a = R(e.id).addr;
        if (!isValue(e) || a == null || unsupported(e)) continue;
        this.ids.push(e);
        reqs.push({ addr: wire(a), vtype: e.vtype, len: e.len || undefined, utf16: e.utf16, signed: e.signed, hex: e.hex, custom: e.custom || undefined });
      }
      return reqs;
    },
    apply(vals) {
      const now = performance.now();
      this.ids.forEach((e, i) => {
        const r = R(e.id), v = vals[i];
        if (r.value != null && v !== r.value) r.chgAt = now;
        r.value = v;
        const c = rowOf(e.id)?.querySelector('.c-val');
        if (!c || c.querySelector('input, select')) return; // being edited
        const t = shown(e, v);
        if (c.textContent !== t) c.textContent = t;
        c.classList.toggle('chg', now - r.chgAt < 1000);
      });
    },
  });

  /** Display string -> string the backend parses (hex ints need a 0x prefix). */
  const wireValue = (e, v) => (e.hex && INT.has(e.vtype) && !/^-?0x/i.test(v) ? '0x' + v.trim() : v.trim());

  // ---------- actions ----------
  async function toggleActive(targets = topSelected()) {
    const bad = targets.filter(unsupported);
    if (bad.length) { toast(`${bad.length > 1 ? bad.length + ' entries use' : '"' + bad[0].description + '" uses'} a custom type HeapHook cannot read; ${bad.length > 1 ? 'they are' : 'it is'} not frozen`, 'info'); targets = targets.filter((t) => !unsupported(t)); }
    if (!targets.length) return;
    const on_ = !targets[0].frozen;
    await chain; // pending edits first
    try { await setActive(targets.map((t) => t.id), on_); } catch (err) { toast(err); }
    chain = chain.then(refetch);
  }
  /** Activation; a loaded table's {$lua} needs the user's yes once (the backend asks via the error). */
  async function setActive(ids, on_) {
    await withConsent(() => api.tableSetActive(ids, on_), { what: ids.map(byId).find((e) => e && hasLua(e))?.description });
  }
  const NEEDS = 'needs consent:';
  const LUA_RE = /\{\$lua\}/i;
  const hasLua = (e) => LUA_RE.test(e.script || '') || e.children.some(hasLua);
  /** Runs `fn`; when the backend answers that the table's Lua needs consent, asks and, agreed, runs it again. */
  async function withConsent(fn, ask = {}) {
    try { return await fn(); } catch (err) {
      if (!String(err?.message || err).startsWith(NEEDS)) throw err;
      if (await askTrust(ask)) return fn();
    }
  }

  // ---------- consent for a loaded table's Lua ----------
  let asking = null;
  /**
   * The one question for a loaded table: may its Lua run (table script, {$lua} in entries) and
   * its hotkeys work system-wide. HeapHook's warning comes first and stays in view; what the
   * table wrote follows as a short quote or behind "View". Resolves true when trusted.
   */
  function askTrust(opts = {}) {
    asking ??= askTrustNow(opts).finally(() => { asking = null; });
    return asking;
  }
  async function askTrustNow({ what = '', open = false } = {}) {
    if (state.settings.table_script === 'never') {
      toast('Not run: this table\'s Lua needs your consent, and Settings say never to run a table\'s Lua', 'info');
      return false;
    }
    const info = await api.appInfo().catch(() => null);
    const script = meta.lua_script || '', lines = script ? script.split('\n').length : 0;
    const luaEntries = all().filter((e) => LUA_RE.test(e.script || '')).length;
    const hks = all().flatMap((e) => e.hotkeys.map((k) => ({ e, k })));
    const sysWide = (keys) => keys.some((k) => MODS.has(k) || (k >= 160 && k <= 165));
    const hkList = h('ul.trust-hks', { hidden: true, 'aria-label': 'Hotkeys this table defines' }, hks.map(({ e, k }) =>
      h('li', null, h('span.mono', null, comboText(k.keys) || 'no keys'), h('span', null, (HK_ACTIONS.find((a) => a[0] === k.action)?.[1] || excerpt(k.action, 30)) + (HK_VALUE.has(k.action) && k.value ? ' ' + excerpt(k.value, 16) : '')),
        h('q', null, excerpt(e.description, 60)), h('span.muted', null, sysWide(k.keys) ? 'system-wide once trusted' : 'only in HeapHook'))));
    const hkBtn = h('button.btn.ghost', { type: 'button', 'aria-expanded': 'false', onclick: () => { hkList.hidden = !hkList.hidden; hkBtn.setAttribute('aria-expanded', String(!hkList.hidden)); hkBtn.firstChild.textContent = hkList.hidden ? 'Show hotkeys' : 'Hide hotkeys'; } }, 'Show hotkeys');
    const facts = h('ul.trust-facts', null,
      script ? h('li', null, `Table script: ${lines} line${lines === 1 ? '' : 's'}, ${script.length} characters `, h('button.btn.ghost', { type: 'button', onclick: () => viewScript(script) }, 'View full script')) : null,
      luaEntries ? h('li', null, `${luaEntries} entr${luaEntries === 1 ? 'y runs' : 'ies run'} Lua when activated`) : null,
      h('li', null, `This table defines ${hks.length} hotkey${hks.length === 1 ? '' : 's'}`, hks.length ? ' ' : null, hks.length ? hkBtn : null),
    );
    const body = h('div.trust-body', null, facts, hkList,
      script ? h('div', null, h('p.hint', null, 'Start of the table script:'), codeView(script, 8)) : null);
    const r = await modal({
      title: 'Trust this table?',
      label: 'Trust this table?',
      text: 'Lua in a cheat table runs with your user account\'s rights. '
        + (info?.lua_allow_os === false
          ? 'Settings turn off Lua\'s access to files and programs: it can still read and change the attached process and run Auto Assembler in it.'
          : 'It can read, change and delete your files, start programs, use the network, and read and change the attached process.')
        + ' Trust a table only if you trust where it came from. Hotkeys with Ctrl, Shift or Alt work system-wide only after you trust it.',
      quote: what || null, quoteLabel: 'Wanted by the entry',
      body,
      buttons: [
        { label: open && script ? 'Trust and run its script' : 'Trust this table', value: 'trust' },
        { label: 'Do not trust', value: 'cancel', kbd: 'Esc', primary: true, focus: true },
      ],
    });
    const yes = r.value === 'trust';
    await attempt(() => api.tableTrust(yes));
    chain = chain.then(refetch);
    return yes;
  }
  /** The whole table script, before any choice: line numbers, wrapped, hidden characters shown. */
  function viewScript(script) {
    const lines = script.split('\n').length;
    return modal({ title: 'Table script', text: `The complete script: ${lines} lines, ${script.length} characters. Long runs of blanks and invisible characters are marked.`,
      body: codeView(script), buttons: [{ label: 'Close', value: 'cancel', kbd: 'Esc', primary: true }] });
  }
  const edit = (ids, f) => commit(() => ids.forEach((id) => { const e = byId(id); if (e) f(e); }));
  function setMode(mode) { edit(selIds(), (e) => { e.freeze_mode = mode; }); }
  function setFlag(flag) { const s = selectedAll(), v = !s[0]?.[flag]; edit(s.map((e) => e.id), (e) => { e[flag] = v; }); }
  function setColor(c) { edit(selIds(), (e) => { e.color = c; }); }

  /** Inserts after the cursor (or at the end); returns the new ids. */
  function add(items, { edit: editNow, then } = {}) {
    const at = cursor;
    let made = [];
    commit(() => {
      made = items.map((p) => entry(p));
      const f = at != null ? find(at) : null;
      if (f) f.list.splice(f.index + 1, 0, ...made); else roots.push(...made);
      sel.clear(); made.forEach((e) => sel.add(e.id));
      cursor = anchor = made[made.length - 1].id;
    }).then(() => {
      scrollToCursor();
      if (editNow) editCell(cursor, 'description');
      then?.(byId(cursor));
    });
  }
  function removeIds(ids) {
    const out = [];
    const go = (list) => { for (let i = list.length - 1; i >= 0; i--) if (ids.has(list[i].id)) out.unshift(...list.splice(i, 1)); else go(list[i].children); };
    go(roots);
    return out;
  }
  function deleteSelected() {
    const top = topSelected();
    if (!top.length) return;
    const idx = flat.findIndex((f) => sel.has(f.e.id)), ids = new Set(top.map((e) => e.id));
    commit(() => {
      removeIds(ids);
      sel.clear();
      flatten();
      cursor = anchor = flat[Math.min(idx, flat.length - 1)]?.e.id ?? null;
      if (cursor != null) sel.add(cursor);
    });
    toast(`Deleted ${top.length} entr${top.length > 1 ? 'ies' : 'y'} (Ctrl Z to undo)`, 'info');
  }
  /** The backend keeps the edit history; pending edits land first. */
  async function history(redo) {
    await chain;
    try { adopt(await (redo ? api.tableRedo() : api.tableUndo())); } catch (e) {
      const m = e?.message || String(e);
      toast(m, /nothing to/i.test(m) ? 'info' : 'error');
    }
  }
  function copy(cut) {
    const top = topSelected();
    if (!top.length) return;
    clip = JSON.stringify(top.map(strip));
    navigator.clipboard?.writeText(clip).catch(() => {});
    if (cut) deleteSelected();
  }
  function paste() {
    if (!clip) return;
    const src = JSON.parse(clip), at = cursor;
    commit(() => {
      const reid = (e) => ({ ...norm(e), id: seq++, frozen: false, children: e.children.map(reid) });
      const items = src.map(reid);
      const f = at != null ? find(at) : null;
      if (f) f.list.splice(f.index + 1, 0, ...items); else roots.push(...items);
      sel.clear(); items.forEach((e) => sel.add(e.id));
      cursor = anchor = items[items.length - 1].id;
    });
  }
  function groupSelected() {
    const ids = topSelected().map((e) => e.id);
    if (!ids.length) return;
    let gid = null;
    commit(() => {
      const at = find(ids[0]);
      if (!at) return;
      const g = entry({ description: 'Group', options: [...GROUP_DEFAULT] });
      at.list.splice(at.index, 0, g);
      g.children = removeIds(new Set(ids));
      sel.clear(); sel.add(g.id); cursor = anchor = gid = g.id;
    }).then(() => gid != null && editCell(gid, 'description'));
  }
  function move(dir) {
    const id = cursor;
    if (id == null) return;
    commit(() => {
      const at = find(id);
      const j = at ? at.index + dir : -1;
      if (j < 0 || j >= at.list.length) return;
      [at.list[at.index], at.list[j]] = [at.list[j], at.list[at.index]];
    }).then(scrollToCursor);
  }
  /** Browse / disassemble the memory region of the entry under the cursor. */
  function browse(pane = 'hex') {
    const e = cursor != null && byId(cursor);
    const a = e && R(e.id).addr;
    if (a != null && a !== false) emit('mem:goto', { addr: wire(a), pane }); else toast('Address not resolved');
  }
  /** Debugger / pointer scanner actions on the entry under the cursor. */
  function onAddr(event) {
    const e = cursor != null && byId(cursor);
    const a = e && isValue(e) && R(e.id).addr;
    if (a == null || a === false) { toast('Address not resolved'); return; }
    emit(event, { addr: wire(a), vtype: e.vtype, len: e.len, utf16: e.utf16, description: e.description });
  }

  /** Range watch prefilled with the entry's address and size. */
  function watchRange() {
    const e = cursor != null && byId(cursor);
    const a = e && isValue(e) && R(e.id).addr;
    if (a == null || a === false) { toast('Address not resolved'); return; }
    const SZ = { byte: 1, binary: 1, '2bytes': 2, '4bytes': 4, '8bytes': 8, float: 4, double: 8 };
    const len = e.vtype === 'string' ? (e.len || 16) * (e.utf16 ? 2 : 1) : e.vtype === 'aob' ? e.len || 8 : SZ[e.vtype] || 4;
    emit('debug:watch-range', { addr: wire(a), len, kind: 'write' });
  }

  // ---------- selection & keyboard ----------
  function select(id, { extend, toggle } = {}) {
    if (id == null) return;
    if (extend && anchor != null) {
      const i = flat.findIndex((f) => f.e.id === anchor), j = flat.findIndex((f) => f.e.id === id);
      sel.clear();
      for (let k = Math.min(i, j); k <= Math.max(i, j); k++) sel.add(flat[k].e.id);
    } else if (toggle) { sel.has(id) ? sel.delete(id) : sel.add(id); anchor = id; }
    else { sel.clear(); sel.add(id); anchor = id; }
    cursor = id;
    for (const r of layer.children) {
      const rid = +r.dataset.id;
      r.setAttribute('aria-selected', String(sel.has(rid)));
      r.classList.toggle('cursor', rid === cursor);
    }
    scrollToCursor();
    grid.setAttribute('aria-activedescendant', 'te-' + cursor);
    syncSel();
  }
  const cursorIdx = () => flat.findIndex((f) => f.e.id === cursor);
  function step(n, extend) {
    if (!flat.length) return;
    const i = Math.max(0, Math.min(flat.length - 1, (cursorIdx() < 0 ? 0 : cursorIdx()) + n));
    select(flat[i].e.id, { extend });
  }
  function toggleCollapse(e) { collapsed.has(e.id) ? collapsed.delete(e.id) : collapsed.add(e.id); render(); }
  function openEntry(e, col) {
    if (isScript(e)) editScript(e.id);
    else if (isGroup(e)) { if (showsKids(e)) toggleCollapse(e); }
    else editCell(e.id, col || 'value');
  }

  grid.addEventListener('keydown', (ev) => {
    if (ev.target !== grid) return;
    const k = ev.key, ctrl = ev.ctrlKey || ev.metaKey, cur = cursor != null ? find(cursor) : null, kl = k.toLowerCase();
    const pageN = Math.max(1, Math.floor(body.clientHeight / ROW) - 1);
    if (k === 'ArrowDown' && ev.altKey) move(1);
    else if (k === 'ArrowUp' && ev.altKey) move(-1);
    else if (k === 'ArrowDown') step(1, ev.shiftKey);
    else if (k === 'ArrowUp') step(-1, ev.shiftKey);
    else if (k === 'PageDown') step(pageN, ev.shiftKey);
    else if (k === 'PageUp') step(-pageN, ev.shiftKey);
    else if (k === 'Home') step(-1e9, ev.shiftKey);
    else if (k === 'End') step(1e9, ev.shiftKey);
    else if (k === 'ArrowRight' && cur) {
      if (showsKids(cur.e) && collapsed.has(cur.e.id)) toggleCollapse(cur.e); else if (showsKids(cur.e)) step(1);
    } else if (k === 'ArrowLeft' && cur) {
      if (showsKids(cur.e) && !collapsed.has(cur.e.id)) toggleCollapse(cur.e); else if (cur.parent) select(cur.parent.id);
    } else if (k === ' ') toggleActive();
    else if (k === 'Enter' && cur) openEntry(cur.e);
    else if (k === 'F2' && cur) editCell(cur.e.id, 'description');
    else if (k === 'Delete') deleteSelected();
    else if (ctrl && kl === 'e' && cur) isScript(cur.e) ? editScript(cur.e.id) : isValue(cur.e) ? entryDialog(cur.e.id) : editCell(cur.e.id, 'description');
    else if (ctrl && kl === 'h' && cur) hotkeyDialog(cur.e.id);
    else if (ctrl && kl === 'c') copy(false);
    else if (ctrl && kl === 'x') copy(true);
    else if (ctrl && kl === 'v') paste();
    else if (ctrl && kl === 'g') groupSelected();
    else if (ctrl && kl === 'z') history(ev.shiftKey);
    else if (ctrl && kl === 'y') history(true);
    else if (ctrl && kl === 'm') browse('hex');
    else if (ctrl && kl === 'd') browse('da');
    else if (k === 'F5') onAddr('debug:accesses');
    else if (k === 'F6') onAddr('debug:writes');
    else if (ctrl && !ev.shiftKey && kl === 'a') { flat.forEach((f) => sel.add(f.e.id)); render(); }
    else if (k === 'ContextMenu' || (ev.shiftKey && k === 'F10')) {
      const r = (rowOf(cursor) || grid).getBoundingClientRect();
      menu(r.left + 60, r.bottom);
    } else return;
    ev.preventDefault();
    ev.stopPropagation();
  });
  grid.addEventListener('focus', () => { if (cursor == null && flat.length) select(flat[0].e.id); });

  body.addEventListener('mousedown', (ev) => {
    const row = ev.target.closest('.trow');
    if (!row || ev.target.closest('input,select')) return;
    const id = +row.dataset.id, act = ev.target.closest('[data-act]')?.dataset.act;
    if (ev.button === 2 && sel.has(id)) { cursor = id; return; }
    if (act === 'toggle') { ev.preventDefault(); cursor = id; toggleCollapse(byId(id)); grid.focus(); return; }
    if (act === 'active') { ev.preventDefault(); if (!sel.has(id)) select(id); grid.focus(); toggleActive(); return; }
    select(id, { extend: ev.shiftKey, toggle: ev.ctrlKey || ev.metaKey });
  });
  body.addEventListener('dblclick', (ev) => {
    const row = ev.target.closest('.trow');
    if (!row || ev.target.closest('[data-act],input,select')) return;
    const e = byId(+row.dataset.id), col = ev.target.closest('[data-col]')?.dataset.col;
    if (!e) return;
    if (isScript(e) && col !== 'description') editScript(e.id);
    else if (col === 'description' || (isGroup(e) && col)) editCell(e.id, 'description');
    else openEntry(e, col);
  });
  body.addEventListener('contextmenu', (ev) => {
    const row = ev.target.closest('.trow');
    ev.preventDefault();
    if (row && !sel.has(+row.dataset.id)) select(+row.dataset.id);
    menu(ev.clientX, ev.clientY);
  });

  function menu(x, y) {
    const cur = cursor != null ? byId(cursor) : null, any = sel.size > 0, addrE = cur && isValue(cur);
    contextMenu(x, y, [
      { label: 'Add address…', kbd: 'Ctrl Shift A', run: () => entryDialog() },
      { label: 'Add script…', run: addScript },
      '-',
      cur && isScript(cur)
        ? { label: 'Change script…', kbd: 'Enter', run: () => editScript(cur.id) }
        : { label: 'Change value', kbd: 'Enter', disabled: !addrE, run: () => editCell(cur.id, 'value') },
      { label: 'Edit entry…', kbd: 'Ctrl E', disabled: !addrE, run: () => entryDialog(cur.id) },
      { label: 'Change description', kbd: 'F2', disabled: !cur, run: () => editCell(cur.id, 'description') },
      { label: cur?.frozen ? 'Deactivate' : 'Activate / freeze', kbd: 'Space', disabled: !any, run: () => toggleActive() },
      { label: 'Hotkeys…', kbd: 'Ctrl H', disabled: !cur, run: () => hotkeyDialog(cur.id) },
      { label: 'Dropdown list…', disabled: !addrE, run: () => dropdownDialog(cur.id) },
      { label: 'Group options…', disabled: !cur || !(cur.children.length || isGroup(cur)), run: () => groupDialog(cur.id) },
      '-',
      ...MODES.map(([m, l]) => ({ label: l, checked: cur?.freeze_mode === m, disabled: !addrE, run: () => setMode(m) })),
      '-',
      { label: 'Show as hexadecimal', checked: !!cur?.hex, disabled: !addrE, run: () => setFlag('hex') },
      { label: 'Show as signed', checked: !!cur?.signed, disabled: !addrE, run: () => setFlag('signed') },
      ...COLORS.map(([l, c]) => ({ label: 'Color: ' + l, swatch: c ? COLOR_VAR[c] : 'var(--text)', disabled: !any, run: () => setColor(c) })),
      '-',
      { label: 'Browse this memory region', kbd: 'Ctrl M', disabled: !addrE, run: () => browse('hex') },
      { label: 'Disassemble this memory region', kbd: 'Ctrl D', disabled: !addrE, run: () => browse('da') },
      { label: 'Find out what accesses this address', kbd: 'F5', disabled: !addrE, run: () => onAddr('debug:accesses') },
      { label: 'Find out what writes to this address', kbd: 'F6', disabled: !addrE, run: () => onAddr('debug:writes') },
      { label: 'Watch this memory range for writes…', disabled: !addrE, run: () => watchRange() },
      { label: 'Pointer scan for this address…', disabled: !addrE, run: () => onAddr('ptr:scan') },
      { label: 'Open in structure dissector', disabled: !addrE || R(cur.id).addr == null, run: () => emit('struct:open', { addr: wire(R(cur.id).addr) }) },
      '-',
      { label: 'Group selected', kbd: 'Ctrl G', disabled: !any, run: groupSelected },
      { label: 'Cut', kbd: 'Ctrl X', disabled: !any, run: () => copy(true) },
      { label: 'Copy', kbd: 'Ctrl C', disabled: !any, run: () => copy(false) },
      { label: 'Paste', kbd: 'Ctrl V', disabled: !clip, run: paste },
      { label: 'Undo', kbd: 'Ctrl Z', run: () => history(false) },
      { label: 'Redo', kbd: 'Ctrl Y', run: () => history(true) },
      { label: 'Delete', kbd: 'Del', disabled: !any, run: deleteSelected },
      '-',
      { label: 'Table Lua script…', run: editTableScript },
      { label: 'Generate a trainer…', run: trainerDialog },
      { label: 'Table comments…', run: editComments },
      { label: 'Labels…', run: labelsDialog },
    ], grid);
  }

  // ---------- inline edit ----------
  async function editCell(id, col) {
    const e = byId(id);
    if (!e || editingId != null) return;
    if (col !== 'description' && !isValue(e)) return;
    if (col === 'value' && unsupported(e)) { toast(`${typeText(e)}: HeapHook has no definition for this custom type, so the value cannot be read or changed`, 'info'); return; }
    const customs = col === 'vtype' ? await listCustomTypes().catch(() => []) : null;
    const i = flat.findIndex((f) => f.e.id === id);
    if (i < 0) return;
    if (i * ROW < body.scrollTop || (i + 1) * ROW > body.scrollTop + body.clientHeight) body.scrollTop = Math.max(0, i * ROW - body.clientHeight / 2);
    paint();
    const row = rowOf(id);
    if (!row) return;
    editingId = id;
    const cell = row.querySelector(`[data-col="${col}"]`);
    row.draggable = false;
    const dd = col === 'value' ? e.dropdown : null;
    let input;
    if (col === 'vtype') {
      const curCt = e.custom_name || (e.custom ? ctLabel(null, e.custom) : null);
      input = h('select.cell-input', { 'aria-label': 'Value type' },
        h('optgroup', { label: 'Types' }, VTYPES.map(([v, l]) => h('option', { value: v, selected: !curCt && v === e.vtype }, l))),
        h('optgroup', { label: 'Custom types' },
          customs.map((c) => h('option', { value: 'ct:' + c.name, selected: c.name === e.custom_name }, ctLabel(c.name, c.ct))),
          e.custom_name && !customs.some((c) => c.name === e.custom_name) ? h('option', { value: 'keep', selected: true }, typeText(e)) : null,
          h('option', { value: 'ct-new' }, 'New custom type…')));
      input._customs = customs;
    } else if (dd?.read_only && dd.options.length) {
      const cur = itemOf(e, R(e.id).value);
      input = h('select.cell-input.mono', { 'aria-label': 'Value' }, dd.options.map((o) =>
        h('option', { value: o.value, selected: o === cur }, dd.description_only ? o.text : `${o.value} : ${o.text}`)));
    } else {
      const v = col === 'description' ? e.description : col === 'addr' ? e.addr : R(e.id).value ?? '';
      input = h('input.cell-input', { value: v, spellcheck: 'false', autocomplete: 'off', 'aria-label': col === 'addr' ? 'Address' : col === 'value' ? 'Value' : 'Description' });
      if (col !== 'description') input.classList.add('mono');
      if (dd?.options.length) {
        const list = h('datalist', { id: 'dd-list-' + id }, dd.options.map((o) => h('option', { value: o.value, label: o.text })));
        cell.append(list);
        input.setAttribute('list', list.id);
      }
    }
    const keep = [...cell.childNodes];
    if (col === 'description') cell.querySelector('.txt').replaceWith(input); else cell.replaceChildren(input, ...cell.querySelectorAll('datalist'));
    input.focus();
    input.select?.();
    let done = false;
    const finish = async (ok) => {
      if (done) return;
      done = true;
      editingId = null;
      const v = input.value;
      if (!ok || v === 'keep') { cell.replaceChildren(...keep); row.draggable = true; grid.focus(); paintSoon(); return; }
      if (col === 'value') { await writeValue(e, v); render(); }
      else if (col === 'description') edit([id], (x) => { x.description = v; });
      else if (col === 'addr') { R(id).addr = null; edit([id], (x) => { x.addr = v.trim(); }); }
      else if (col === 'vtype' && v.startsWith('ct')) {
        const pick = v === 'ct-new' ? await editCustomType(null) : input._customs.find((c) => 'ct:' + c.name === v);
        if (pick) edit([id], (x) => { x.custom = pick.ct; x.custom_name = pick.name; }); else render();
      } else if (col === 'vtype') edit([id], (x) => { x.vtype = v; delete x.custom; delete x.custom_name; if (v === 'string' && !x.len) x.len = 16; if (v === 'aob' && !x.len) x.len = 8; });
      grid.focus();
    };
    input.addEventListener('keydown', (ev) => {
      ev.stopPropagation();
      if (ev.key === 'Enter') { ev.preventDefault(); finish(true); }
      else if (ev.key === 'Escape') { ev.preventDefault(); finish(false); }
    });
    input.addEventListener('blur', () => finish(true));
    if (input.tagName === 'SELECT') input.addEventListener('change', () => finish(true));
  }
  /** Writes through the backend, so frozen entries freeze to the new value. */
  async function writeValue(e, v) {
    const targets = (sel.has(e.id) ? selectedAll().filter((x) => isValue(x) || opt(x, 'moRecursiveSetValue')) : [e]).filter((x) => !unsupported(x));
    // One write per flag set: hex entries need the 0x prefix, decimal ones must not get it.
    const groups = new Map();
    for (const t of targets) { const w = wireValue(t, v); groups.set(w, [...(groups.get(w) || []), t.id]); }
    for (const [w, ids] of groups) await attempt(() => api.tableSetValue(ids, w));
    for (const t of targets) R(t.id).value = null;
  }

  // ---------- drag reorder ----------
  let dragIds = null;
  body.addEventListener('dragstart', (ev) => {
    const row = ev.target.closest('.trow');
    if (!row) return;
    const id = +row.dataset.id;
    if (!sel.has(id)) select(id);
    dragIds = new Set(topSelected().map((e) => e.id));
    ev.dataTransfer.effectAllowed = 'move';
    ev.dataTransfer.setData('text/plain', 'heaphook-entries');
  });
  const zone = (ev, row) => { const r = row.getBoundingClientRect(), y = (ev.clientY - r.top) / r.height; return y < 0.3 ? 'before' : y > 0.7 ? 'after' : 'into'; };
  const clearDrop = () => body.querySelectorAll('.drop-before,.drop-after,.drop-into').forEach((r) => r.classList.remove('drop-before', 'drop-after', 'drop-into'));
  body.addEventListener('dragover', (ev) => {
    const row = ev.target.closest('.trow');
    if (!dragIds || !row) return;
    ev.preventDefault();
    clearDrop();
    row.classList.add('drop-' + zone(ev, row));
  });
  body.addEventListener('dragleave', (ev) => { if (!body.contains(ev.relatedTarget)) clearDrop(); });
  body.addEventListener('dragend', () => { dragIds = null; clearDrop(); });
  body.addEventListener('drop', (ev) => {
    const row = ev.target.closest('.trow');
    clearDrop();
    if (!dragIds || !row) return;
    ev.preventDefault();
    const tid = +row.dataset.id, z = zone(ev, row), ids = dragIds;
    dragIds = null;
    commit(() => {
      const target = byId(tid);
      const moving = topSelected().filter((e) => ids.has(e.id));
      if (!target || moving.some((m) => m === target || isDesc(m, target))) return;
      const marker = { id: -1, children: [] };
      if (z === 'into') { removeIds(new Set(moving.map((m) => m.id))); target.children.push(...moving); collapsed.delete(target.id); }
      else {
        const at = find(target.id);
        at.list.splice(at.index + (z === 'after' ? 1 : 0), 0, marker);
        removeIds(new Set(moving.map((m) => m.id)));
        const m = find(-1);
        m.list.splice(m.index, 1, ...moving);
      }
    });
  });

  // ---------- dialogs ----------
  function entryDialog(id) {
    const e = id != null ? byId(id) : null;
    const d = $('#dlg-entry'), f = d.querySelector('form');
    const offs = $('#ed-offsets');
    d.querySelector('h2').textContent = e ? 'Edit entry' : 'Add address';
    f.elements.description.value = e?.description ?? 'No description';
    f.elements.addr.value = e?.addr ?? '';
    f.elements.vtype.value = e?.vtype ?? '4bytes';
    f.elements.len.value = e?.len || 16;
    f.elements.utf16.checked = !!e?.utf16;
    f.elements.signed.checked = !!e?.signed;
    f.elements.hex.checked = !!e?.hex;
    f.elements.pointer.checked = !!e?.offsets?.length;
    offs.replaceChildren();
    const addOff = (v = '0') => {
      const row = h('div.off-row', null, h('input.mono', { value: v, 'aria-label': 'Offset (hex)', spellcheck: 'false', oninput: preview }),
        h('button.btn.icon', { type: 'button', 'aria-label': 'Remove offset', html: icon('x'), onclick: () => { row.remove(); preview(); } }));
      offs.append(row);
    };
    (e?.offsets?.length ? e.offsets : ['0']).forEach(addOff);
    const syncVis = () => {
      $('#ed-ptr').hidden = !f.elements.pointer.checked;
      const t = f.elements.vtype.value;
      $('#ed-len-wrap').hidden = t !== 'string' && t !== 'aob';
      $('#ed-utf16-wrap').hidden = t !== 'string';
      preview();
    };
    const offsets = () => (f.elements.pointer.checked ? [...offs.querySelectorAll('input')].map((i) => i.value.trim().replace(/^0x/i, '') || '0') : []);
    let pv = 0;
    async function preview() {
      const my = ++pv, out = $('#ed-preview'), a = f.elements.addr.value.trim();
      if (!a || !state.proc) { out.textContent = ''; return; }
      const fake = { addr: a, offsets: offsets() };
      try { const r = await api.resolveAddress(exprOf(fake)); if (my === pv) { out.textContent = '= ' + fmtAddr(r); out.classList.remove('err'); } }
      catch (err) { if (my === pv) { out.textContent = String(err); out.classList.add('err'); } }
    }
    f.elements.pointer.onchange = syncVis;
    f.elements.vtype.onchange = syncVis;
    f.elements.addr.oninput = preview;
    $('#ed-add-off').onclick = () => { addOff(); preview(); offs.lastElementChild.querySelector('input').focus(); };
    syncVis();
    d.onclose = () => {
      if (d.returnValue !== 'ok') return;
      const p = {
        description: f.elements.description.value, addr: f.elements.addr.value.trim(), offsets: offsets(),
        vtype: f.elements.vtype.value, len: ['string', 'aob'].includes(f.elements.vtype.value) ? +f.elements.len.value || 0 : 0, utf16: f.elements.utf16.checked,
        signed: f.elements.signed.checked, hex: f.elements.hex.checked,
      };
      if (!p.addr) { toast('Address is empty'); return; }
      // The dialog has no custom types: picking another type there drops the custom one.
      if (e) { R(e.id).addr = null; edit([e.id], (x) => { if (p.vtype !== x.vtype) { delete x.custom; delete x.custom_name; } Object.assign(x, p); }); } else add([p]);
      grid.focus();
    };
    d.returnValue = '';
    grid.focus(); // the dialog restores focus to this on close, not to the toolbar button
    d.showModal();
    f.elements.addr.focus();
  }

  function addScript() {
    add([{ description: 'Auto Assembler script', script: SCRIPT_TEMPLATE }], { then: (e) => e && editScript(e.id) });
  }
  /** Line-numbered editor; `gut` follows the textarea. */
  function gutter(ta, gut) {
    const lines = () => {
      const n = ta.value.split('\n').length;
      gut.textContent = Array.from({ length: n }, (_, i) => i + 1).join('\n');
      gut.scrollTop = ta.scrollTop;
    };
    ta.onscroll = () => { gut.scrollTop = ta.scrollTop; };
    return lines;
  }
  const indentTab = (ta, ev, after) => {
    if (ev.key === 'Tab' && !ev.shiftKey && !ev.ctrlKey) { ev.preventDefault(); ta.setRangeText('  ', ta.selectionStart, ta.selectionEnd, 'end'); after(); return true; }
    return false;
  };
  function editScript(id) {
    const e = byId(id);
    if (!e) return;
    const d = $('#dlg-script'), ta = $('#aa-text'), status = $('#aa-status');
    ta.value = e.script ?? '';
    $('#aa-title').textContent = `Auto Assembler script · ${e.description}`;
    let checkT = 0, errLine = 0;
    const lines = gutter(ta, $('#aa-gutter'));
    const check = async () => {
      try {
        const r = await api.aaCheck(ta.value);
        errLine = r ? r.line : 0;
        status.textContent = r ? `Line ${r.line}: ${r.message}` : 'No errors';
        status.className = 'aa-status ' + (r ? 'err' : 'ok');
      } catch (err) { status.textContent = String(err); status.className = 'aa-status err'; }
    };
    ta.oninput = () => { lines(); clearTimeout(checkT); checkT = setTimeout(check, 300); };
    ta.onkeydown = (ev) => {
      if (indentTab(ta, ev, ta.oninput)) return;
      if ((ev.ctrlKey || ev.metaKey) && ev.key === 's') { ev.preventDefault(); ev.stopPropagation(); d.close('ok'); }
    };
    status.onclick = () => {
      if (!errLine) return;
      const off = ta.value.split('\n').slice(0, errLine - 1).join('\n').length + (errLine > 1 ? 1 : 0);
      ta.focus(); ta.setSelectionRange(off, off);
    };
    $('#aa-check').onclick = check;
    d.onclose = () => { clearTimeout(checkT); if (d.returnValue === 'ok') { const v = ta.value; edit([id], (x) => { x.script = v; }); } grid.focus(); };
    lines(); check();
    d.returnValue = '';
    grid.focus(); // the dialog restores focus to this on close, not to the toolbar button
    d.showModal();
    ta.focus();
  }

  /** Shared text editor dialog: table Lua script (with "save and run") and comments. */
  function textDialog({ title, hint, value, runnable, mono = true, onSave }) {
    const d = $('#dlg-text'), ta = $('#tx-text');
    $('#tx-title').textContent = title;
    $('#tx-hint').textContent = hint;
    $('#tx-run').hidden = !runnable;
    ta.classList.toggle('mono', mono);
    ta.value = value;
    const lines = gutter(ta, $('#tx-gutter'));
    ta.oninput = lines;
    ta.onkeydown = (ev) => {
      if (indentTab(ta, ev, lines)) return;
      const ctrl = ev.ctrlKey || ev.metaKey;
      if (ctrl && ev.key === 's') { ev.preventDefault(); ev.stopPropagation(); d.close('ok'); }
      else if (ctrl && ev.key === 'Enter' && runnable) { ev.preventDefault(); ev.stopPropagation(); d.close('run'); }
    };
    d.onclose = () => { if (d.returnValue === 'ok' || d.returnValue === 'run') onSave(ta.value, d.returnValue === 'run'); grid.focus(); };
    lines();
    d.returnValue = '';
    d.showModal();
    ta.focus();
  }
  function editTableScript() {
    textDialog({
      title: 'Table Lua script', hint: 'Saved with the table; runs only when you choose to.', value: meta.lua_script, runnable: true,
      onSave: (v, run) => commit(() => { meta.lua_script = v; }).then(() => run && runTableScript()),
    });
  }
  function editComments() {
    textDialog({ title: 'Table comments', hint: 'Saved with the table.', value: meta.comments, mono: false, onSave: (v) => commit(() => { meta.comments = v; }) });
  }
  async function runTableScript() {
    await chain;
    await attempt(() => withConsent(() => api.tableRunScript()));
    chain = chain.then(refetch);
  }

  const keyOf = (keys) => [...(keys || [])].sort((a, b) => a - b).join('+');
  function hotkeyDialog(id) {
    const e = byId(id);
    if (!e) return;
    const d = $('#dlg-hotkeys'), rows = $('#hk-rows');
    $('#hk-title').textContent = `Hotkeys · ${e.description}`;
    rows.replaceChildren();
    const addRow = (hk = { action: 'Toggle Activation', keys: [], value: null, description: null }) => {
      let keys = [...hk.keys];
      const act = h('select', { 'aria-label': 'Action' }, HK_ACTIONS.filter(([a]) => isValue(e) || !HK_VALUE.has(a) || opt(e, 'moRecursiveSetValue'))
        .map(([a, l]) => h('option', { value: a, selected: a === hk.action }, l)));
      const keyBtn = h('button.btn.hk-keys.mono', { type: 'button', 'aria-label': 'Key combination; focus and press keys' }, comboText(keys));
      const val = h('input.mono', { value: hk.value ?? '', 'aria-label': 'Value', spellcheck: 'false', autocomplete: 'off' });
      const desc = h('input', { value: hk.description ?? '', 'aria-label': 'Description', autocomplete: 'off' });
      const warn = h('p.hk-warn', { role: 'status', hidden: true });
      const sync = () => {
        val.disabled = !HK_VALUE.has(act.value); keyBtn.textContent = keys.length ? comboText(keys) : 'Press keys…';
        // Same combination on another entry: allowed (CE fires both), but worth knowing.
        const k = keyOf(keys), clash = k ? all().filter((x) => x.id !== id && x.hotkeys.some((hk2) => keyOf(hk2.keys) === k)) : [];
        warn.hidden = !clash.length;
        warn.textContent = clash.length ? `${comboText(keys)} is also the hotkey of ${clash.slice(0, 3).map((x) => '"' + x.description + '"').join(', ')}${clash.length > 3 ? ` and ${clash.length - 3} more` : ''}. Both fire when you press it.` : '';
      };
      act.onchange = sync;
      keyBtn.onkeydown = (ev) => {
        if (ev.key === 'Tab' && !ev.ctrlKey && !ev.altKey) return;
        ev.preventDefault(); ev.stopPropagation();
        if ((ev.key === 'Backspace' || ev.key === 'Delete') && !ev.ctrlKey && !ev.altKey && !ev.shiftKey) { keys = []; sync(); return; }
        const c = comboOf(ev);
        if (c.some((k) => !MODS.has(k))) { keys = c; sync(); }
        else keyBtn.textContent = comboText(c) + ' …';
      };
      keyBtn.onblur = sync;
      const row = h('div.hk-row', null, act, keyBtn, val, desc,
        h('button.btn.icon', { type: 'button', 'aria-label': 'Remove hotkey', html: icon('x'), onclick: () => { row.remove(); warn.remove(); } }));
      // The id stays: Lua's MemoryRecordHotkey objects find their hotkey by it.
      row.read = () => ({ ...(hk.id != null ? { id: hk.id } : {}), action: act.value, keys, value: HK_VALUE.has(act.value) ? val.value.trim() : null, description: desc.value.trim() || null });
      rows.append(row, warn);
      sync();
      return keyBtn;
    };
    e.hotkeys.forEach((k) => addRow(k));
    $('#hk-add').onclick = () => addRow().focus();
    d.onkeydown = (ev) => { if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter' && !ev.target.classList.contains('hk-keys')) { ev.preventDefault(); d.close('ok'); } };
    d.onclose = () => {
      if (d.returnValue !== 'ok') { grid.focus(); return; }
      const list = [...rows.children].filter((r) => r.read).map((r) => r.read()).filter((k) => k.keys.length);
      edit([id], (x) => { x.hotkeys = list; });
      grid.focus();
    };
    d.returnValue = '';
    d.showModal();
    if (!e.hotkeys.length) addRow().focus();
  }

  function dropdownDialog(id) {
    const e = byId(id);
    if (!e) return;
    const d = $('#dlg-dropdown'), f = d.querySelector('form'), dd = e.dropdown;
    $('#dd-title').textContent = `Dropdown list · ${e.description}`;
    f.elements.items.value = (dd?.options || []).map((o) => `${o.value}:${o.text}`).join('\n');
    f.elements.read_only.checked = !!dd?.read_only;
    f.elements.description_only.checked = !!dd?.description_only;
    f.elements.display_value_as_item.checked = dd ? !!dd.display_value_as_item : true;
    $('#dd-remove').hidden = !dd;
    f.elements.items.onkeydown = (ev) => { if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') { ev.preventDefault(); d.close('ok'); } };
    d.onclose = () => {
      if (d.returnValue === 'remove') edit([id], (x) => { x.dropdown = null; });
      else if (d.returnValue === 'ok') {
        const options = f.elements.items.value.split('\n').filter((l) => l.trim()).map((l) => {
          const i = l.indexOf(':');
          return i < 0 ? { value: l.trim(), text: '' } : { value: l.slice(0, i).trim(), text: l.slice(i + 1).trim() };
        });
        const next = { options, read_only: f.elements.read_only.checked, description_only: f.elements.description_only.checked,
          display_value_as_item: f.elements.display_value_as_item.checked };
        edit([id], (x) => { x.dropdown = next; });
      }
      grid.focus();
    };
    d.returnValue = '';
    d.showModal();
    f.elements.items.focus();
  }

  function groupDialog(id) {
    const e = byId(id);
    if (!e) return;
    const d = $('#dlg-gopts'), f = d.querySelector('form');
    const names = [...f.querySelectorAll('input[type=checkbox]')].map((i) => i.name);
    $('#go-title').textContent = `Group options · ${e.description}`;
    for (const n of names) f.elements[n].checked = opt(e, n);
    d.onclose = () => {
      if (d.returnValue === 'ok') {
        const on_ = names.filter((n) => f.elements[n].checked);
        // Options HeapHook has no checkbox for stay as they were.
        edit([id], (x) => { x.options = [...(x.options || []).filter((o) => !names.includes(o)), ...on_]; });
      }
      grid.focus();
    };
    d.returnValue = '';
    d.showModal();
  }

  // ---------- user-defined symbols (labels) ----------
  /** Table labels (CE <UserdefinedSymbols>): name = address expression, usable in every address field. */
  function labelsDialog() {
    const rowsEl = h('div.lb-rows', { role: 'group', 'aria-label': 'Labels' });
    const err = h('p.hint.err', { role: 'alert' });
    const addRow = (s = { name: '', address: '' }) => {
      const name = h('input.mono', { value: s.name, 'aria-label': 'Label name', spellcheck: 'false', autocomplete: 'off', placeholder: 'player_hp' });
      const addr = h('input.mono', { value: s.address, 'aria-label': 'Address expression', spellcheck: 'false', autocomplete: 'off', placeholder: 'game.exe+1A2B' });
      const out = h('span.lb-res.mono.muted');
      const check = async () => { const v = addr.value.trim(); out.textContent = !v || !state.proc ? '' : await api.resolveAddress(v).then(fmtAddr, () => '??'); };
      addr.addEventListener('input', check);
      const row = h('div.lb-row', null, name, addr, out, h('button.btn.icon', { type: 'button', 'aria-label': 'Remove label', html: icon('x'), onclick: () => row.remove() }));
      row.read = () => ({ name: name.value.trim(), address: addr.value.trim() });
      rowsEl.append(row);
      check();
      return name;
    };
    (meta.symbols || []).forEach(addRow);
    const form = h('form', { method: 'dialog' },
      h('h2', null, 'Labels'),
      h('p.hint', null, 'Names for addresses, saved with the table. Every address field and the disassembler understand them (game.exe+1A2B becomes player_hp).'),
      h('div.lb-head', { 'aria-hidden': 'true' }, h('span', null, 'Name'), h('span', null, 'Address'), h('span', null, 'Now'), h('span')),
      rowsEl,
      h('button.btn.ghost', { type: 'button', onclick: () => addRow().focus() }, h('span', { html: icon('plus') }), 'Add label'),
      err,
      h('div.dlg-actions', null,
        h('button.btn.primary', { value: 'ok', type: 'submit' }, 'Save ', h('kbd', null, 'Ctrl Enter')),
        h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc'))));
    const d = h('dialog.dlg', { 'aria-label': 'Labels' }, form);
    d.onkeydown = (ev) => { if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') { ev.preventDefault(); form.requestSubmit(form.querySelector('[value=ok]')); } };
    form.addEventListener('submit', (ev) => {
      if (ev.submitter?.value !== 'ok') return;
      const list = [...rowsEl.children].map((r) => r.read()).filter((s) => s.name || s.address);
      const bad = list.find((s) => !/^[A-Za-z_][\w.]*$/.test(s.name) || !s.address);
      const dup = list.find((s, i) => list.findIndex((t) => t.name === s.name) !== i);
      if (bad || dup) { ev.preventDefault(); err.textContent = bad ? `"${bad.name || bad.address}": a label needs a name (letters, digits, _ and ., not starting with a digit) and an address` : `"${dup.name}" is listed twice`; return; }
      commit(() => { meta.symbols = list; });
    });
    d.addEventListener('close', () => { d.remove(); grid.focus(); });
    document.body.append(d);
    d.showModal();
    if (!meta.symbols?.length) addRow().focus(); else rowsEl.querySelector('input')?.focus();
  }

  // ---------- trainer generator ----------
  const TR_BEGIN = '-- BEGIN HEAPHOOK TRAINER', TR_END = '-- END HEAPHOOK TRAINER';
  /** Pick entries and their hotkeys, a title and options; generates a Lua trainer into the table script. */
  function trainerDialog() {
    const cands = all().filter((e) => !isGroup(e) || e.children.length);
    if (!cands.length) { toast('Add entries to the table first: the trainer toggles table entries'); return; }
    const picked = new Set(selectedAll().map((e) => e.id));
    const titleI = h('input', { type: 'text', value: tablePath.replace(/^.*[\\/]/, '').replace(/\.[^.]*$/, '') + ' trainer', autocomplete: 'off', 'aria-label': 'Title' });
    const aboutI = h('input', { type: 'text', value: '', autocomplete: 'off', placeholder: 'optional, e.g. which game version it is for', 'aria-label': 'Text above the toggles' });
    const beepI = h('input', { type: 'checkbox', checked: true }), keysI = h('input', { type: 'checkbox', checked: true });
    const rows = cands.map((e) => {
      const tog = e.hotkeys.find((k) => k.action.startsWith('Toggle Activation'));
      let keys = tog ? [...tog.keys] : [];
      const on_ = h('input', { type: 'checkbox', checked: picked.has(e.id), 'aria-label': `Include ${e.description}` });
      const label = h('input', { type: 'text', value: e.description, autocomplete: 'off', 'aria-label': `Label for ${e.description}` });
      const keyBtn = h('button.btn.hk-keys.mono', { type: 'button', 'aria-label': `Hotkey for ${e.description}; focus and press keys, Backspace clears` }, keys.length ? comboText(keys) : 'none');
      keyBtn.onkeydown = (ev) => {
        if (ev.key === 'Tab' && !ev.ctrlKey && !ev.altKey) return;
        ev.preventDefault(); ev.stopPropagation();
        if ((ev.key === 'Backspace' || ev.key === 'Delete') && !ev.ctrlKey && !ev.altKey && !ev.shiftKey) { keys = []; keyBtn.textContent = 'none'; return; }
        const c = comboOf(ev);
        if (c.some((k) => !MODS.has(k))) { keys = c; keyBtn.textContent = comboText(keys); on_.checked = true; } else keyBtn.textContent = comboText(c) + ' …';
      };
      keyBtn.onblur = () => { keyBtn.textContent = keys.length ? comboText(keys) : 'none'; };
      const el = h('div.tr-row', null, on_, label, keyBtn, h('span.muted.tr-kind', null, isScript(e) ? 'script' : isGroup(e) ? 'group' : typeText(e)));
      return { el, read: () => (on_.checked ? { id: e.id, label: label.value.trim(), keys } : null) };
    });
    const err = h('p.hint.mono', { role: 'alert' });
    const form = h('form', { method: 'dialog' },
      h('h2', null, 'Generate a trainer'),
      h('p.hint', null, 'Builds a Lua form with one toggle per entry, plus its hotkey, into the table script. The trainer runs inside HeapHook when the table script runs; standalone .exe trainers are not built.'),
      h('div.row2.row2-even', null, h('label.field', null, h('span', null, 'Title'), titleI), h('label.field', null, h('span', null, 'Text above the toggles'), aboutI)),
      h('div.tr-head', { 'aria-hidden': 'true' }, h('span'), h('span', null, 'Label'), h('span', null, 'Hotkey'), h('span', null, 'Entry')),
      h('div.tr-rows', { role: 'group', 'aria-label': 'Entries in the trainer' }, rows.map((r) => r.el)),
      h('div.checks', null, h('label.check', null, beepI, ' Beep when a hotkey toggles'), h('label.check', null, keysI, ' Show hotkeys on the form')),
      h('p.hint', null, 'A hotkey the entry already has (Toggle activation) is shown, not registered twice. Generating again replaces the earlier trainer block.'), err,
      h('div.dlg-actions', null,
        h('button.btn.primary', { value: 'run', type: 'submit' }, 'Generate and run ', h('kbd', null, 'Ctrl Enter')),
        h('button.btn', { value: 'ok', type: 'submit' }, 'Generate'),
        h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc'))));
    const d = h('dialog.dlg.dlg-wide', { 'aria-label': 'Generate a trainer' }, form);
    d.onkeydown = (ev) => { if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter' && !ev.target.classList.contains('hk-keys')) { ev.preventDefault(); form.requestSubmit(form.querySelector('[value=run]')); } };
    form.addEventListener('submit', async (ev) => {
      const how = ev.submitter?.value;
      if (how === 'cancel') return;
      ev.preventDefault();
      err.textContent = '';
      const entries = rows.map((r) => r.read()).filter(Boolean);
      if (!entries.length) { err.textContent = 'Pick at least one entry'; return; }
      let script;
      try { script = await api.trainerScript({ title: titleI.value.trim(), about: aboutI.value.trim(), beep: beepI.checked, show_keys: keysI.checked, entries }); } catch (x) { err.textContent = String(x?.message || x); return; }
      d.close();
      const cur = meta.lua_script, i = cur.indexOf(TR_BEGIN), j = cur.indexOf(TR_END);
      const next = i >= 0 && j > i ? cur.slice(0, i) + script.trimEnd() + cur.slice(j + TR_END.length) : (cur.trim() ? cur.trimEnd() + '\n\n' : '') + script;
      await commit(() => { meta.lua_script = next; });
      toast('Trainer written to the table script', 'info');
      if (how === 'run') await runTableScript();
    });
    d.addEventListener('close', () => { d.remove(); grid.focus(); });
    document.body.append(d);
    d.showModal();
    titleI.select();
  }

  // ---------- save / load ----------
  const FILTERS = [['Cheat tables', ['CT', 'ct', 'json']], ['Cheat Engine table', ['CT', 'ct']], ['HeapHook table', ['json']], ['All files', ['*']]];
  async function save() {
    const p = await askPath({ save: true, title: 'Save table', filters: [['Cheat Engine table', ['CT']], ['HeapHook table', ['json']]], dflt: tablePath });
    if (!p) return;
    await chain;
    const ok = await attempt(async () => { await api.tableExport(p); return true; });
    if (ok) { tablePath = p; store.set('tablePath', p); toast(`Saved ${p}`, 'info'); }
  }
  async function load() {
    const p = await askPath({ save: false, title: 'Open table', filters: FILTERS, dflt: tablePath });
    if (!p) return;
    await chain;
    let st;
    try { st = await api.tableOpen(p); } catch (e) {
      const m = String(e?.message || e);
      if (!/could not be disabled/.test(m)) { toast(m); return; }
      // The details name entries (table text): after HeapHook's own words, in a scroll box.
      const r = await modal({ title: 'Scripts are still active',
        text: 'Some active scripts of the current table could not be disabled, so their changes are still in the process. Open anyway to keep them, still active, in a group of the new table, where you can disable them later.',
        pre: m, buttons: [{ label: 'Open anyway', value: 'force' }, { label: 'Cancel', value: 'cancel', kbd: 'Esc', primary: true, focus: true }] });
      if (r.value !== 'force') return;
      st = await attempt(() => api.tableOpen(p, true));
    }
    if (!st) return;
    rt.clear(); sel.clear(); collapsed.clear(); cursor = anchor = null; tablePath = p; store.set('tablePath', p);
    adopt(st);
    toast(`Loaded ${p}`, 'info');
    await offerTrust();
  }
  /** Never runs code from a file, nor lets its hotkeys work system-wide, without asking (Settings can turn the question into "no"). */
  async function offerTrust() {
    if (state.tableTrust !== 'ask') return;
    const lua = !!meta.lua_script.trim() || roots.some(hasLua), hks = all().some((e) => e.hotkeys.length);
    if (!lua && !hks) return;
    if (state.settings.table_script === 'never') {
      if (lua) toast('This table has Lua. It was not run (Settings: never run a table\'s Lua).', 'info');
      return;
    }
    if (await askTrust({ open: true }) && meta.lua_script.trim()) await runTableScript();
  }

  // The code list is backend-owned (the debugger view shows it); meta.codes only rides along in puts.
  on('table:script', ({ description, script }) => add([{ description, script }], { then: (e) => e && editScript(e.id) }));
  // Pointer entries come with an id from the backend; the table assigns its own.
  on('table:add', (items) => add(items.map(({ id, ...x }) => ({ ...x, len: x.len || 0 }))));
  // A hotkey pressed (lua.js) for an entry whose Lua needs consent.
  on('table:consent', () => askTrust());
  on('process:opened', () => { for (const r of rt.values()) { r.addr = null; r.value = null; } chain = chain.then(refetch); });

  $('#tb-add').addEventListener('click', () => entryDialog());
  $('#tb-script').addEventListener('click', addScript);
  $('#tb-group').addEventListener('click', groupSelected);
  $('#tb-delete').addEventListener('click', deleteSelected);
  $('#tb-lua').addEventListener('click', editTableScript);
  $('#tb-comments').addEventListener('click', editComments);
  $('#tb-trainer').addEventListener('click', trainerDialog);
  $('#tb-comments').before(h('button.btn.ghost#tb-labels', { type: 'button', title: 'Names for addresses, saved with the table', onclick: labelsDialog, html: icon('note') + 'Labels' }));
  $('.tbl-head', root).setAttribute('aria-rowindex', '1');
  // Other views (the disassembler's comments and labels) edit table fields through the same ordered commit.
  editMetaHook = (fn) => commit(() => { fn(meta); }).then(() => emit('table:meta', meta));
  refetch();

  return { addDialog: () => entryDialog(), save, load, focus: () => grid.focus(), editTableScript };
}
