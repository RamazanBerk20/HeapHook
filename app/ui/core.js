// Shared app state, an event bus, and the live-value poller: one read_values call per tick
// covering every visible row of every registered source.
import { api } from './backend.js';

/** settings: what settings_get returned (defaults until it answers). */
export const state = { proc: null, view: 'scan', settings: { live_update_ms: 300, table_script: 'ask', bp_method: 'software', theme: 'system' } };

const bus = new EventTarget();
export const emit = (name, detail) => bus.dispatchEvent(new CustomEvent(name, { detail }));
export const on = (name, fn) => bus.addEventListener(name, (e) => fn(e.detail));

/** source: {collect(): reqs[], apply(values[])} */
const sources = new Set();
export const addSource = (s) => sources.add(s);
/** Other per-tick refreshers (memory viewer). Called after the value batch. */
const tickers = new Set();
export const addTicker = (f) => tickers.add(f);

/** The live-update interval (Settings); a live binding, importers see changes. */
export let TICK_MS = 300;
let busy = false;
async function poll() {
  if (busy || !state.proc || document.hidden) return;
  busy = true;
  try {
    const parts = [];
    for (const s of sources) { const r = s.collect(); if (r.length) parts.push([s, r]); }
    if (parts.length) {
      const vals = await api.readValues(parts.flatMap((p) => p[1]));
      let i = 0;
      for (const [s, r] of parts) s.apply(vals.slice(i, (i += r.length)));
    }
    await Promise.all([...tickers].map((f) => f()));
  } catch (e) {
    console.warn('poll failed:', e);
  } finally {
    busy = false;
  }
}
let timer = setInterval(poll, TICK_MS);
export function setTick(ms) {
  if (ms === TICK_MS) return;
  TICK_MS = ms;
  clearInterval(timer);
  timer = setInterval(poll, TICK_MS);
}
