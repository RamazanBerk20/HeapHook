// Scan panel: value inputs, scan/value type, options, First/Next/Undo/New, progress, cancel.
import { api } from './backend.js';
import { $, $$, h, nf, toast } from './util.js';
import { state, on } from './core.js';

const FIRST = [['exact', 'Exact value'], ['bigger', 'Bigger than'], ['smaller', 'Smaller than'], ['between', 'Value between'], ['unknown', 'Unknown initial value']];
const NEXT = [...FIRST.slice(0, 4), ['increased', 'Increased'], ['increased_by', 'Increased by'], ['decreased', 'Decreased'],
  ['decreased_by', 'Decreased by'], ['changed', 'Changed'], ['unchanged', 'Unchanged'], ['same_as_first', 'Same as first scan']];
const NO_VALUE = new Set(['unknown', 'increased', 'decreased', 'changed', 'unchanged', 'same_as_first']);
const ALIGN = { byte: 1, binary: 1, '2bytes': 2, '4bytes': 4, '8bytes': 4, float: 4, double: 4, string: 1, aob: 1, all: 1, grouped: 1 };
const TRI_NEXT = { yes: 'no', no: 'any', any: 'yes' };
const TRI_ARIA = { yes: 'true', no: 'false', any: 'mixed' };

export function initScan(results) {
  const el = (id) => document.getElementById(id);
  const v1 = el('v1'), v2 = el('v2'), st = el('scan-type'), vt = el('vtype');
  const bFirst = el('btn-first'), bNext = el('btn-next'), bUndo = el('btn-undo'), bCancel = el('btn-cancel');
  const bar = el('scan-bar'), progWrap = el('scan-progress'), found = el('found');
  // Extra memory options built here: last hex digits of the address, and the grouped-scan syntax hint.
  const ldOn = h('input', { type: 'checkbox' }), ld = h('input.mono.num', { type: 'text', maxlength: '8', placeholder: 'A0', 'aria-label': 'Last digits of the address (hex)', spellcheck: 'false', autocomplete: 'off', style: 'width:72px' });
  el('o-fast').closest('.align-row').after(h('div.align-row', null, h('label.check', null, ldOn, ' Last digits (hex)'), ld));
  const gHint = h('p.hint.mono', { hidden: true }, "Grouped: 4:100 2:7 f:12.5 d:2.25 s:'text' su:'wide' w:8 2:*  (1 2 4 8 f d numbers, s / su text, w:n skips n bytes, * = any; BA:n OOO BS:n)");
  v1.after(gHint);
  let hasScan = false, running = false, canUndo = false, count = 0, prevCount = 0, scanMeta = {};

  // tri-state option buttons
  const setTri = (b, v) => { b.dataset.v = v; b.setAttribute('aria-checked', TRI_ARIA[v]); b.querySelector('.tri-v').textContent = v; };
  for (const b of $$('.tri')) {
    setTri(b, b.dataset.v);
    b.addEventListener('click', () => setTri(b, TRI_NEXT[b.dataset.v]));
  }
  // Defaults come from Settings; changes made here last for the session.
  on('settings', (s) => {
    for (const b of $$('.tri')) setTri(b, s['scan_' + b.dataset.key] ?? b.dataset.v);
    el('o-fast').checked = s.fast_scan;
    el('o-align').value = s.scan_alignment;
  });

  function fillTypes() {
    const list = hasScan ? NEXT : FIRST, cur = st.value;
    st.replaceChildren(...list.map(([v, l]) => h('option', { value: v }, l)));
    st.value = list.some((x) => x[0] === cur) ? cur : 'exact';
    sync();
  }
  function sync() {
    const t = st.value, ty = vt.value;
    el('v1-wrap').hidden = NO_VALUE.has(t);
    el('v2-wrap').hidden = t !== 'between';
    el('v1-label').textContent = t === 'between' ? 'From' : t.endsWith('_by') ? 'By' : 'Value';
    vt.disabled = hasScan || running;
    el('opt-float').hidden = !['float', 'double', 'all'].includes(ty);
    el('opt-string').hidden = ty !== 'string';
    gHint.hidden = ty !== 'grouped';
    el('opt-percent').hidden = !['between', 'increased_by', 'decreased_by'].includes(t) || hasScan;
    v1.placeholder = { string: 'text', aob: '8B 45 ?? 89', binary: '01001011' }[ty] || (el('o-hex').checked ? 'hex' : 'decimal');
    bFirst.innerHTML = hasScan ? 'New scan <kbd>Ctrl N</kbd>' : 'First scan <kbd>Enter</kbd>';
    bFirst.classList.toggle('primary', !hasScan);
    bNext.classList.toggle('primary', hasScan);
    bFirst.disabled = running;
    bNext.disabled = running || !hasScan;
    bUndo.disabled = running || !canUndo;
    progWrap.hidden = !running;
    found.textContent = running ? 'Scanning…' : hasScan ? `${nf.format(count)} found` : 'No scan yet';
  }

  function opts() {
    const tri = (k) => $(`.tri[data-key="${k}"]`).dataset.v;
    const fast = el('o-fast').checked, digits = ld.value.trim().replace(/^0x/i, '');
    const last = ldOn.checked && digits;
    if (last && !/^[0-9a-f]{1,8}$/i.test(last)) throw 'Last digits must be hex (0-9, A-F)';
    return {
      ...(last ? { last_digits: last } : {}),
      start: '0x' + (el('o-start').value.trim().replace(/^0x/i, '') || '0'),
      stop: '0x' + (el('o-stop').value.trim().replace(/^0x/i, '') || '7fffffffffff'),
      writable: tri('writable'), executable: tri('executable'), copy_on_write: tri('copy_on_write'),
      alignment: fast ? Math.max(1, +el('o-align').value || 1) : 1,
      hex: el('o-hex').checked, case_sensitive: el('o-case').checked, utf16: el('o-utf16').checked,
      rounding: el('o-round').value, percent: el('o-percent').checked, pause_while_scanning: el('o-pause').checked, threads: state.settings.scan_threads || null,
    };
  }

  async function run(kind) {
    if (running) return;
    if (!state.proc) { toast('Open a process first (Ctrl P)'); return; }
    const t = st.value;
    if (!NO_VALUE.has(t) && !v1.value.trim()) { toast('Enter a value to scan for'); v1.focus(); return; }
    const req = { scan_type: t, value: v1.value, value2: t === 'between' ? v2.value : null, not: el('o-not').checked };
    running = true; sync();
    bar.style.transform = 'scaleX(0)';
    const poll = setInterval(async () => {
      const p = await api.scanProgress().catch(() => null);
      if (!p || !p.total) return;
      bar.style.transform = `scaleX(${Math.min(1, p.done / p.total)})`;
      el('scan-bar-wrap').setAttribute('aria-valuenow', Math.round((100 * p.done) / p.total));
      found.textContent = `Scanning… ${nf.format(p.found)} so far`;
    }, 100);
    try {
      let r;
      if (kind === 'first') {
        const o = opts();
        r = await api.scanFirst({ vtype: vt.value, ...req, opts: o });
        const ty = vt.value;
        scanMeta = {
          vtype: ty, hex: o.hex, utf16: o.utf16 && ty === 'string',
          len: ty === 'string' ? v1.value.length : ty === 'aob' ? v1.value.trim().split(/\s+/).length : 0,
        };
        canUndo = false;
      } else {
        r = await api.scanNext(req);
        prevCount = count; canUndo = true;
      }
      hasScan = true;
      count = r.count;
      results.set({ count, ...scanMeta });
    } catch (e) {
      toast(e);
    } finally {
      clearInterval(poll);
      running = false;
      fillTypes();
    }
  }
  async function newScan() {
    if (running) return;
    try { await api.scanNew(); } catch (e) { toast(e); }
    hasScan = false; canUndo = false; count = 0;
    results.set({ count: 0 });
    fillTypes();
    v1.focus();
  }
  async function undo() {
    if (running || !canUndo) return;
    try {
      await api.scanUndo();
      canUndo = false; count = prevCount;
      results.set({ count, ...scanMeta });
      sync();
    } catch (e) { toast(e); }
  }
  const cancel = () => running && api.scanCancel().catch(toast);

  bFirst.addEventListener('click', () => (hasScan ? newScan() : run('first')));
  bNext.addEventListener('click', () => run('next'));
  bUndo.addEventListener('click', undo);
  bCancel.addEventListener('click', cancel);
  st.addEventListener('change', sync);
  vt.addEventListener('change', () => { el('o-align').value = ALIGN[vt.value] || 1; sync(); });
  el('o-hex').addEventListener('change', sync);
  for (const i of [v1, v2]) i.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); run(hasScan ? 'next' : 'first'); }
  });
  on('process:opened', () => { hasScan = false; canUndo = false; count = 0; results.set({ count: 0 }); fillTypes(); });
  on('process:closed', () => { hasScan = false; canUndo = false; count = 0; results.set({ count: 0 }); fillTypes(); });

  fillTypes();
  return {
    run: () => run(hasScan ? 'next' : 'first'), newScan, undo, cancel,
    get running() { return running; },
    focusValue: () => (el('v1-wrap').hidden ? st : v1).focus(),
  };
}
