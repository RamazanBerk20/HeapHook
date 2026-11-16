// Small shared helpers: DOM, icons, storage, toasts, splitters, menus, prompts.

export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/** h('div.cls#id', {attr}, ...children) */
export function h(spec, attrs, ...kids) {
  const [, tag, rest] = spec.match(/^([a-z0-9]+)(.*)$/i);
  const el = document.createElement(tag);
  for (const m of rest.matchAll(/([.#])([\w-]+)/g)) m[1] === '.' ? el.classList.add(m[2]) : (el.id = m[2]);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'html') el.innerHTML = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null) el.append(k);
  return el;
}

export const store = {
  get(k, d) { try { const v = localStorage.getItem('hh.' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('hh.' + k, JSON.stringify(v)); } catch { /* storage blocked: sizes just are not remembered */ } },
};

// ---------- addresses ----------
export const toBig = (s) => BigInt(s);
export const wire = (b) => '0x' + b.toString(16);
export const fmtAddr = (s) => (s == null ? '' : BigInt(s).toString(16).toUpperCase().padStart(8, '0'));
export const isHexAddr = (s) => /^(0x)?[0-9a-f]+$/i.test(String(s).trim());
export const fmtSize = (n) => (n >= 1 << 20 ? (n / (1 << 20)).toFixed(n % (1 << 20) ? 1 : 0) + ' MiB' : n >= 1024 ? (n / 1024).toFixed(n % 1024 ? 1 : 0) + ' KiB' : n + ' B');
export const nf = new Intl.NumberFormat('en-US');

// ---------- rendering ----------
/** Coalesce calls into one per animation frame. */
export function rafThrottle(fn) {
  let queued = false;
  return () => { if (queued) return; queued = true; requestAnimationFrame(() => { queued = false; fn(); }); };
}

// ---------- icons (24px grid, 2px stroke) ----------
const P = {
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  undo: '<path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  folder: '<path d="M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/>',
  save: '<path d="M5 3h11l3 3v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1z"/><path d="M8 3v5h7V3M8 21v-7h8v7"/>',
  code: '<path d="m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/>',
  group: '<path d="M3 5h7l2 2h9v12H3z"/>',
  chevR: '<path d="m9 6 6 6-6 6"/>',
  chevD: '<path d="m6 9 6 6 6-6"/>',
  back: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
  target: '<circle cx="12" cy="12" r="8"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/>',
  keyboard: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>',
  up: '<path d="M12 19V5M6 11l6-6 6 6"/>',
  down: '<path d="M12 5v14M6 13l6 6 6-6"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2 6"/><path d="M20 4v7h-7"/>',
  memory: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 4v16"/>',
  scan: '<path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3M8 12h8"/>',
  check: '<path d="m5 12 5 5 9-10"/>',
  bug: '<rect x="8" y="6" width="8" height="14" rx="4"/><path d="M12 10v10M4 13h4M16 13h4M5 7l3 2M19 7l-3 2M5 19l3-2M19 19l-3-2M10 4l1 2M14 4l-1 2"/>',
  pointer: '<circle cx="5" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><circle cx="19" cy="6" r="2"/><path d="M6.5 7.5 11 16M17.5 7.5 13 16"/>',
  play: '<path d="M7 5v14l11-7z"/>',
  pause: '<path d="M8 5v14M16 5v14"/>',
  stepInto: '<path d="M12 3v11M7 9l5 5 5-5"/><circle cx="12" cy="20" r="1.5"/>',
  stepOver: '<path d="M4 14a8 8 0 0 1 15-4"/><path d="M20 4v6h-6"/><circle cx="12" cy="19" r="1.5"/>',
  stepOut: '<path d="M12 15V4M7 9l5-5 5 5"/><circle cx="12" cy="20" r="1.5"/>',
  runTo: '<path d="M4 12h12M12 7l5 5-5 5M20 5v14"/>',
  runToThread: '<path d="M3 9h10M9 5l4 4-4 4M17 3v12"/><path d="M5 20h14M12 17v6" stroke-width="1.8"/>',
  trainer: '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h2M8 12h2M8 16h2M13 8h3M13 12h3M13 16h3"/>',
  watch: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  nop: '<rect x="4" y="6" width="16" height="12" rx="2"/><path d="M8 10v4M12 10v4M16 10v4"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="1"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M12 15h5"/>',
  gear: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  note: '<path d="M6 3h9l4 4v14H6z"/><path d="M9 11h7M9 15h7M9 7h3"/>',
  key: '<circle cx="7" cy="12" r="3.5"/><path d="M10.5 12H21M17 12v3.5M20.5 12v2.5"/>',
  struct: '<rect x="3" y="4" width="7" height="5" rx="1"/><rect x="14" y="15" width="7" height="5" rx="1"/><path d="M6.5 9v8.5H14M6.5 13H14"/>',
  clock: '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
};
export const icon = (name, cls = '') =>
  `<svg class="ic ${cls}" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">${P[name]}</svg>`;

// ---------- toasts ----------
export function toast(msg, kind = 'error') {
  const t = h('div.toast', { role: kind === 'error' ? 'alert' : 'status' }, String(msg));
  t.classList.add(kind);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), kind === 'error' ? 6000 : 2500);
}
/** Run an async action and surface its error string as a toast. */
export async function attempt(fn) {
  try { return await fn(); } catch (e) { toast(e?.message || e); return undefined; }
}

// ---------- busy indicator ----------
// One indicator in the top bar for any operation that takes longer than 300 ms. Several
// operations stack; the newest is shown. `cancel` adds a Cancel button (and Esc) when the
// backend can stop the operation.
const busyOps = [];
function busyRender() {
  const el = $('#busy');
  if (!el) return;
  const op = busyOps.filter((o) => o.shown).at(-1);
  el.hidden = !op;
  if (!op) return;
  $('#busy-text').textContent = op.label + '…';
  const c = $('#busy-cancel');
  c.hidden = !op.cancel;
  c.onclick = () => op.cancel?.();
}
/** True while a cancellable busy operation is shown (Esc cancels it). */
export function busyCancel() {
  const op = busyOps.filter((o) => o.shown && o.cancel).at(-1);
  if (op) op.cancel();
  return !!op;
}
/** Awaits `work` (a promise or function returning one); shows `label` after 300 ms. */
export async function busy(label, work, { cancel = null } = {}) {
  const op = { label, cancel, shown: false };
  busyOps.push(op);
  const t = setTimeout(() => { op.shown = true; busyRender(); }, 300);
  try { return await (typeof work === 'function' ? work() : work); } finally {
    clearTimeout(t);
    busyOps.splice(busyOps.indexOf(op), 1);
    busyRender();
  }
}

// ---------- splitters ----------
/**
 * Make `div` drag-resize `target` along `axis` ('x' | 'y'). `sign` is +1 when dragging
 * right/down grows the target. Size stored under `key`.
 */
export function splitter(div, target, { axis, key, min, max, sign = 1, initial }) {
  const prop = axis === 'x' ? 'width' : 'height';
  const apply = (px) => {
    const lim = max();
    px = Math.max(min, Math.min(lim, px));
    target.style[prop] = px + 'px';
    div.setAttribute('aria-valuenow', Math.round(px));
    div.setAttribute('aria-valuemin', min);
    div.setAttribute('aria-valuemax', Math.round(lim));
    return px;
  };
  let size = store.get(key, initial); // the user's preference; the window may clamp what is shown
  apply(size);
  div.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    div.setPointerCapture(e.pointerId);
    const start = axis === 'x' ? e.clientX : e.clientY, s0 = target.getBoundingClientRect()[prop];
    document.body.classList.add('resizing', axis === 'x' ? 'rx' : 'ry');
    const move = rafThrottle(() => { size = apply(s0 + sign * (last - start)); });
    let last = start;
    const onMove = (ev) => { last = axis === 'x' ? ev.clientX : ev.clientY; move(); };
    const onUp = () => {
      div.removeEventListener('pointermove', onMove);
      div.removeEventListener('pointerup', onUp);
      document.body.classList.remove('resizing', 'rx', 'ry');
      store.set(key, size);
    };
    div.addEventListener('pointermove', onMove);
    div.addEventListener('pointerup', onUp);
  });
  div.addEventListener('keydown', (e) => {
    const d = { ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1 }[e.key];
    if (!d) return;
    e.preventDefault();
    size = apply(target.getBoundingClientRect()[prop] + sign * d * (e.shiftKey ? 64 : 16));
    store.set(key, size);
  });
  window.addEventListener('resize', rafThrottle(() => apply(size)));
}

// ---------- context menu ----------
let menuEl = null;
export function closeMenu() { menuEl?.remove(); menuEl = null; }
/** items: [{label, kbd?, run, checked?, disabled?} | '-'] */
export function contextMenu(x, y, items, returnFocus) {
  closeMenu();
  const el = h('div.menu', { role: 'menu' });
  for (const it of items) {
    if (it === '-') { el.append(h('div.menu-sep', { role: 'separator' })); continue; }
    const b = h('button.menu-item', {
      role: it.checked == null ? 'menuitem' : 'menuitemradio', 'aria-checked': it.checked == null ? null : String(!!it.checked),
      disabled: it.disabled, tabindex: '-1',
      onclick: () => { closeMenu(); returnFocus?.focus(); it.run(); },
    }, h('span.mi-check', { html: it.checked ? icon('check') : '' }), h('span.mi-label', null, it.label), it.kbd ? h('kbd', null, it.kbd) : null);
    if (it.swatch) b.querySelector('.mi-check').innerHTML = `<i class="swatch" style="background:${it.swatch}"></i>`;
    el.append(b);
  }
  document.body.append(el);
  const r = el.getBoundingClientRect();
  el.style.left = Math.min(x, innerWidth - r.width - 8) + 'px';
  el.style.top = Math.min(y, innerHeight - r.height - 8) + 'px';
  menuEl = el;
  const btns = $$('.menu-item:not([disabled])', el);
  btns[0]?.focus();
  el.addEventListener('keydown', (e) => {
    const i = btns.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') btns[(i + 1) % btns.length].focus();
    else if (e.key === 'ArrowUp') btns[(i - 1 + btns.length) % btns.length].focus();
    else if (e.key === 'Escape' || e.key === 'Tab') { closeMenu(); returnFocus?.focus(); }
    else return;
    e.preventDefault(); e.stopPropagation();
  });
}
document.addEventListener('pointerdown', (e) => { if (menuEl && !menuEl.contains(e.target)) closeMenu(); });

// ---------- modal prompt ----------
/** Small modal asking for one string. Resolves to the string or null. */
export function prompt(title, value = '', { label = title, hint = '', mono = true } = {}) {
  return new Promise((resolve) => {
    const input = h('input', { type: 'text', value, spellcheck: 'false', autocomplete: 'off', class: mono ? 'mono' : '' });
    const d = h('dialog.dlg.dlg-sm', { 'aria-label': title },
      h('form', { method: 'dialog' },
        h('h2', null, title),
        h('label.field', null, h('span', null, label), input),
        hint ? h('p.hint', null, hint) : null,
        h('div.dlg-actions', null,
          h('button.btn.primary', { value: 'ok', type: 'submit' }, 'OK ', h('kbd', null, 'Enter')),
          h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc')))));
    document.body.append(d);
    d.addEventListener('close', () => { resolve(d.returnValue === 'ok' ? input.value : null); d.remove(); });
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); d.close('ok'); } });
    d.showModal();
    input.select();
  });
}

export const kbdHint = (s) => h('kbd', null, s);

/** Characters that hide or reorder text (controls, zero-width, bidi overrides): never shown raw from untrusted text. */
const HIDDEN = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]/g;

/** Untrusted text (table, script, target) as one line of at most `n` characters. */
export function excerpt(s, n = 80) {
  const t = String(s ?? '').replace(HIDDEN, '').replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

/** The "Lua script" mark on every window and dialog a script opens (app-owned: a script cannot change it). */
export const luaBadge = () => h('span.badge.lua-badge', { title: 'Opened by a Lua script, not by HeapHook' }, 'Lua script');

/**
 * Untrusted source text for reading before a decision: wrapped, line numbers, long runs of
 * blanks and hidden characters spelled out so nothing can sit out of sight.
 */
export function codeView(text, maxLines = Infinity) {
  const lines = String(text ?? '').split('\n');
  const shown = lines.slice(0, maxLines);
  const row = (l, i) => {
    const parts = [];
    let last = 0;
    for (const m of l.matchAll(/[ \t]{16,}|[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]/g)) {
      parts.push(l.slice(last, m.index));
      const t = m[0];
      parts.push(h('span.cv-mark', null, /^[ \t]+$/.test(t) ? `⟨${t.length} blanks⟩` : `⟨U+${t.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}⟩`));
      last = m.index + t.length;
    }
    parts.push(l.slice(last));
    return h('div.cv-line', null, h('span.cv-num', { 'aria-hidden': 'true' }, String(i + 1)), h('span.cv-text', null, ...parts));
  };
  return h('div.code-view.mono', { tabindex: '0', role: 'region', 'aria-label': 'Script text' }, shown.map(row),
    lines.length > shown.length ? h('div.cv-more.muted', null, `… ${lines.length - shown.length} more lines`) : null);
}

/**
 * Modal: `text` is HeapHook's own words and always stays in view (with the buttons); what
 * a table, script or target supplied goes after it — `quote` as a one-line quoted excerpt,
 * `pre` (or `body`, an element) in a scroll box. `lua`: the dialog comes from a Lua script
 * (badge and frame). Buttons `[{label, value, primary?, kbd?, focus?}]`; resolves to
 * `{value, input}`; Esc resolves `cancel`.
 */
export function modal({ title, text = '', quote = null, quoteLabel = 'From the table', pre = null, body = null, input = null, buttons, cancel = 'cancel', label = title, lua = false }) {
  return new Promise((resolve) => {
    const inp = input == null ? null : h('input.mono', { type: 'text', value: input, spellcheck: 'false', autocomplete: 'off' });
    const btns = buttons.map((b) => h('button.btn' + (b.primary ? '.primary' : ''), { value: b.value, type: 'submit' }, b.label, b.kbd ? ' ' : null, b.kbd ? h('kbd', null, b.kbd) : null));
    const q = quote ? excerpt(quote) : '';
    const scroll = [
      q ? h('p.modal-quote', null, h('span.muted', null, quoteLabel + ': '), h('q', null, q)) : null,
      pre != null ? h('pre.modal-pre.mono', { tabindex: '0' }, pre) : null,
      body,
      inp ? h('label.field', null, h('span', null, 'Value'), inp) : null,
    ].filter(Boolean);
    const d = h('dialog.dlg.dlg-sm.dlg-modal' + (lua ? '.dlg-lua' : ''), { 'aria-label': (lua ? 'Lua script: ' : '') + excerpt(label), role: 'alertdialog' },
      h('form', { method: 'dialog' },
        title || lua ? h('div.modal-head', null, lua ? luaBadge() : null, title ? h('h2', null, lua ? excerpt(title) : title) : null) : null,
        text ? h('p.modal-text', null, text) : null,
        scroll.length ? h('div.modal-body', null, ...scroll) : null,
        h('div.dlg-actions', null, ...btns)));
    document.body.append(d);
    d.returnValue = cancel;
    d.addEventListener('close', () => { resolve({ value: d.returnValue || cancel, input: inp?.value ?? null }); d.remove(); });
    if (inp) inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); d.close(buttons.find((b) => b.primary)?.value ?? buttons[0].value); } });
    d.showModal();
    (inp || btns.find((_, i) => buttons[i].focus) || btns[0]).focus();
    inp?.select();
  });
}
