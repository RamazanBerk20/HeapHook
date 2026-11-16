//! Freezer: a background thread that keeps a set of values written.
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use hh_core::{Addr, Memory, Result};
use serde::{Deserialize, Serialize};

use crate::hexaddr;
use crate::value::{CustomType, Fmt, Num, Prim, VType, Val, merge, parse_value, with_num};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
                let iv = g.interval;
                g.items.iter_mut().for_each(|it| apply(&*mem, it));
                g = s2.1.wait_timeout(g, iv).unwrap_or_else(|e| e.into_inner()).0;
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
        let mut items: Vec<Item> = entries
            .iter()
            .map(|x| {
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
                })
            })
            .collect::<Result<_>>()?;
        let mut g = lock(&self.sh);
        for it in &mut items {
            if let Some(old) = g.items.iter().find(|o| o.key == it.key && o.custom == it.custom && o.bytes.len() == it.bytes.len()) {
                it.bytes.clone_from(&old.bytes);
                it.fresh = old.fresh;
            }
        }
        g.items = items;
        drop(g);
        self.sh.1.notify_all();
        Ok(())
    }

    pub fn set_interval(&self, d: Duration) {
        lock(&self.sh).interval = d.max(Duration::from_millis(1));
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

/// Write errors are ignored: the address may come back (e.g. a reallocated heap block).
fn apply(mem: &dyn Memory, it: &mut Item) {
    let mut cur = vec![0u8; it.bytes.len()];
    let have = mem.read_exact(it.addr, &mut cur).is_ok();
    let target = match (&it.wmask, have) {
        (Some(m), true) => merge(&cur, &it.bytes, m),
        (Some(_), false) => return,
        (None, _) => it.bytes.clone(),
    };
    if it.fresh {
        it.fresh = mem.write(it.addr, &target).is_err();
        return;
    }
    if !have {
        let _ = mem.write(it.addr, &target);
        return;
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
            (Some(Equal), _) => return,
            (Some(Greater), FreezeMode::AllowIncrease) | (Some(Less), FreezeMode::AllowDecrease) => {
                // Keep only the field bits for bit fields so the next merge stays exact.
                it.bytes = match &it.wmask {
                    Some(m) => cur.iter().zip(m).map(|(c, m)| c & m).collect(),
                    None => cur,
                };
                return;
            }
            _ => {}
        }
    }
    if cur != target {
        let _ = mem.write(it.addr, &target);
    }
}
