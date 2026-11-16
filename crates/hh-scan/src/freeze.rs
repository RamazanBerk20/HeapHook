//! Freezer: a background thread that keeps a set of values written.
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hh_core::{Addr, Memory, Result};
use serde::{Deserialize, Serialize};

use crate::hexaddr;
use crate::value::{CustomType, Fmt, Num, Prim, VType, Val, merge, parse_value, with_num};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeMode {
    #[default]
    Exact,
    /// The value may grow (the frozen value follows it) but never drops below it.
    AllowIncrease,
    /// The value may shrink but never rises above it.
    AllowDecrease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenEntry {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub vtype: VType,
    pub value: String,
    #[serde(default)]
    pub mode: FreezeMode,
    #[serde(flatten)]
    pub fmt: Fmt,
}

/// A frozen entry that may use a custom type (same JSON as [`FrozenEntry`] plus `custom`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenEntryEx {
    #[serde(flatten)]
    pub entry: FrozenEntry,
    #[serde(default)]
    pub custom: Option<CustomType>,
}

impl From<FrozenEntry> for FrozenEntryEx {
    fn from(entry: FrozenEntry) -> Self {
        FrozenEntryEx { entry, custom: None }
    }
}

/// An entry whose last write (or the read it needs) failed, e.g. memory that was freed.
/// Its writes are retried every tick; the entry leaves this list once one succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeFailure {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub error: String,
}

#[derive(Clone)]
struct Item {
    key: (Addr, VType, String, FreezeMode),
    addr: Addr,
    bytes: Vec<u8>,
    num: Option<(Prim, bool)>,
    custom: Option<CustomType>,
    /// Bit-field entries only write these bits.
    wmask: Option<Vec<u8>>,
    mode: FreezeMode,
    /// Not written yet: the first tick writes the value whatever the mode.
    fresh: bool,
    /// Own rewrite interval; `None` = the freezer's.
    interval: Option<Duration>,
    due: Instant,
    err: Option<String>,
}

struct Shared {
    items: Vec<Item>,
    interval: Duration,
    stop: bool,
}

type Sync2 = Arc<(Mutex<Shared>, Condvar)>;

pub struct Freezer {
    sh: Sync2,
    th: Option<JoinHandle<()>>,
}

fn lock(sh: &Sync2) -> MutexGuard<'_, Shared> {
    sh.0.lock().unwrap_or_else(|e| e.into_inner())
}

impl Freezer {
    pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

    pub fn new(mem: Arc<dyn Memory>) -> Result<Self> {
        let sh: Sync2 = Arc::new((
            Mutex::new(Shared { items: Vec::new(), interval: Self::DEFAULT_INTERVAL, stop: false }),
            Condvar::new(),
        ));
        let s2 = sh.clone();
        let th = std::thread::Builder::new().name("hh-freezer".into()).spawn(move || {
            let mut g = lock(&s2);
            while !g.stop {
                let (now, iv) = (Instant::now(), g.interval);
                let mut next = now + iv;
                for it in g.items.iter_mut() {
                    if it.due <= now {
                        it.err = apply(&*mem, it).err().map(|e| e.to_string());
                        it.due = now + it.interval.unwrap_or(iv);
                    }
                    next = next.min(it.due);
                }
                let wait = next.saturating_duration_since(Instant::now());
                g = s2.1.wait_timeout(g, wait).unwrap_or_else(|e| e.into_inner()).0;
            }
        })?;
        Ok(Freezer { sh, th: Some(th) })
    }

    /// Replaces the whole frozen set. On a parse error the old set stays. Entries that were
    /// already frozen keep their state (an allow-increase value that has grown stays grown).
    pub fn set(&self, entries: &[FrozenEntry]) -> Result<()> {
        self.set_ex(&entries.iter().cloned().map(Into::into).collect::<Vec<_>>())
    }

    /// [`Freezer::set`] with custom types (`custom` overrides `vtype`).
    pub fn set_ex(&self, entries: &[FrozenEntryEx]) -> Result<()> {
        let items: Vec<Item> = entries.iter().map(|x| item(x, None)).collect::<Result<_>>()?;
        self.install(items, |_| false)
    }

    /// Adds `e`, or updates the entries at its address in place (no rebuild of the set). An
    /// entry with the same type, value and mode keeps its state; `interval` overrides the
    /// freezer's interval for this entry.
    pub fn put(&self, e: &FrozenEntryEx, interval: Option<Duration>) -> Result<()> {
        let it = item(e, interval)?;
        self.install(vec![it], |o| o.addr != e.entry.addr)
    }

    /// Freezes every address in `addrs` to `e`'s value (Cheat Engine's "freeze selected"),
    /// like [`Freezer::put`] for each (`e.entry.addr` is ignored). On a parse error nothing
    /// changes.
    pub fn freeze_many(&self, addrs: &[Addr], e: &FrozenEntryEx, interval: Option<Duration>) -> Result<()> {
        let it = item(e, interval)?;
        let items = addrs
            .iter()
            .map(|&a| Item { key: (a, it.key.1, it.key.2.clone(), it.key.3), addr: a, ..it.clone() })
            .collect();
        let mut sorted = addrs.to_vec();
        sorted.sort_unstable();
        self.install(items, |o| sorted.binary_search(&o.addr).is_err())
    }

    /// Stops freezing `addr`; false if nothing was frozen there.
    pub fn remove(&self, addr: Addr) -> bool {
        let mut g = lock(&self.sh);
        let n = g.items.len();
        g.items.retain(|o| o.addr != addr);
        n != g.items.len()
    }

    /// Number of frozen entries.
    pub fn len(&self) -> usize {
        lock(&self.sh).items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entries whose last write failed (unreadable or unwritable memory), in set order.
    pub fn failures(&self) -> Vec<FreezeFailure> {
        lock(&self.sh).items.iter().filter_map(|it| Some(FreezeFailure { addr: it.addr, error: it.err.clone()? })).collect()
    }

    /// Keeps the old items `keep` accepts, then adds `items`; an added item that matches a
    /// dropped one keeps its state.
    fn install(&self, mut items: Vec<Item>, keep: impl Fn(&Item) -> bool) -> Result<()> {
        let mut g = lock(&self.sh);
        let (kept, old): (Vec<Item>, Vec<Item>) = std::mem::take(&mut g.items).into_iter().partition(|o| keep(o));
        let mut by_key: std::collections::HashMap<_, &Item> = std::collections::HashMap::new();
        for o in &old {
            by_key.entry(&o.key).or_insert(o);
        }
        for it in &mut items {
            if let Some(old) = by_key.get(&it.key).filter(|o| o.custom == it.custom && o.bytes.len() == it.bytes.len()) {
                it.bytes.clone_from(&old.bytes);
                it.fresh = old.fresh;
                it.err.clone_from(&old.err);
            }
        }
        g.items = kept;
        g.items.extend(items);
        drop(g);
        self.sh.1.notify_all();
        Ok(())
    }

    pub fn set_interval(&self, d: Duration) {
        let mut g = lock(&self.sh);
        g.interval = d.max(Duration::from_millis(1));
        // Entries on the freezer's interval follow the new one right away.
        let soon = Instant::now() + g.interval;
        g.items.iter_mut().filter(|it| it.interval.is_none()).for_each(|it| it.due = it.due.min(soon));
        drop(g);
        self.sh.1.notify_all();
    }
}

impl Drop for Freezer {
    fn drop(&mut self) {
        lock(&self.sh).stop = true;
        self.sh.1.notify_all();
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
    }
}

fn item(x: &FrozenEntryEx, interval: Option<Duration>) -> Result<Item> {
    let e = &x.entry;
    Ok(Item {
        key: (e.addr, e.vtype, e.value.clone(), e.mode),
        addr: e.addr,
        bytes: match &x.custom {
            Some(c) => c.encode(&e.value, &e.fmt)?,
            None => parse_value(e.vtype, &e.value, &e.fmt)?,
        },
        num: Prim::of(e.vtype).filter(|_| x.custom.is_none()).map(|p| (p, e.fmt.signed)),
        custom: x.custom,
        wmask: x.custom.and_then(|c| c.write_mask()),
        mode: e.mode,
        fresh: true,
        interval: interval.map(|d| d.max(Duration::from_millis(1))),
        due: Instant::now(),
        err: None,
    })
}

/// One tick of one entry. Failures are reported ([`Freezer::failures`]) and retried: the
/// address may come back (e.g. a reallocated heap block).
fn apply(mem: &dyn Memory, it: &mut Item) -> Result<()> {
    let mut cur = vec![0u8; it.bytes.len()];
    let read = mem.read_exact(it.addr, &mut cur);
    let have = read.is_ok();
    let target = match (&it.wmask, read) {
        (Some(m), Ok(())) => merge(&cur, &it.bytes, m),
        (Some(_), Err(e)) => return Err(e),
        (None, _) => it.bytes.clone(),
    };
    if it.fresh {
        mem.write(it.addr, &target)?;
        it.fresh = false;
        return Ok(());
    }
    if !have {
        return mem.write(it.addr, &target);
    }
    if matches!(it.mode, FreezeMode::AllowIncrease | FreezeMode::AllowDecrease) {
        let ord = match (it.num, it.custom) {
            (_, Some(c)) => {
                let (a, b) = (c.decode(&cur), c.decode(&it.bytes));
                if a.float() { a.f().partial_cmp(&b.f()) } else { Some(a.i().cmp(&b.i())) }
            }
            (Some((p, signed)), None) => with_num!(p, signed, T => {
                let (a, b) = (T::rd(&cur), T::rd(&it.bytes));
                if T::FLOAT { a.f().partial_cmp(&b.f()) } else { Some(a.i().cmp(&b.i())) }
            }),
            (None, None) => None,
        };
        use std::cmp::Ordering::*;
        match (ord, it.mode) {
            (Some(Equal), _) => return Ok(()),
            (Some(Greater), FreezeMode::AllowIncrease) | (Some(Less), FreezeMode::AllowDecrease) => {
                // Keep only the field bits for bit fields so the next merge stays exact.
                it.bytes = match &it.wmask {
                    Some(m) => cur.iter().zip(m).map(|(c, m)| c & m).collect(),
                    None => cur,
                };
                return Ok(());
            }
            _ => {}
        }
    }
    if cur != target {
        mem.write(it.addr, &target)?;
    }
    Ok(())
}
