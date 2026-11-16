//! HeapHook memory scanner: value types, first/next/undo scans with disk-spilling result
//! storage, value parsing/formatting, and the freezer.
//!
//! The IPC layer drives a [`Scanner`] (one per opened process) from a worker thread and
//! polls [`Scanner::progress`] / calls [`Scanner::cancel`] from others.

mod freeze;
mod plan;
mod scanner;
mod store;
mod value;

pub use freeze::{FreezeMode, FrozenEntry, Freezer};
pub use freeze::FrozenEntryEx;
pub use plan::{FirstScan, NextScan, NextScanEx, Priority, ScanOptions, ScanType, Tri};
pub use scanner::{ResultRow, ScanCount, ScanProgress, Scanner};
pub use value::{
    CustomType, Fmt, Rounding, VType, ValueRef, ValueRefEx, format_value, parse_value, read_values, read_values_ex, value_size,
    write_custom, write_value,
};

/// Serde helpers: addresses travel as `"0x..."` strings (JS numbers lose precision).
pub mod hexaddr {
    use hh_core::Addr;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        N(u64),
        S(String),
    }

    fn conv<E: Error>(r: Raw) -> Result<Addr, E> {
        match r {
            Raw::N(n) => Ok(n),
            Raw::S(s) => {
                let t = s.trim();
                match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(h) => u64::from_str_radix(h, 16),
                    None => t.parse(),
                }
                .map_err(|_| E::custom(format!("bad address {s:?}")))
            }
        }
    }

    pub fn serialize<S: Serializer>(a: &Addr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{a:#x}"))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Addr, D::Error> {
        conv(Raw::deserialize(d)?)
    }

    pub mod opt {
        use super::*;
        pub fn serialize<S: Serializer>(a: &Option<Addr>, s: S) -> Result<S::Ok, S::Error> {
            match a {
                Some(a) => super::serialize(a, s),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Addr>, D::Error> {
            Option::<Raw>::deserialize(d)?.map(conv).transpose()
        }
    }
}
