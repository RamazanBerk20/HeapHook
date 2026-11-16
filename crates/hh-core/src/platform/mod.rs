//! OS backends, selected at compile time.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{list_processes, open};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{list_processes, open};

#[cfg(not(any(target_os = "linux", windows)))]
mod unsupported {
    use std::sync::Arc;

    use crate::{Error, Pid, Process, ProcessInfo, Result};

    pub fn list_processes() -> Result<Vec<ProcessInfo>> {
        Err(Error::Unsupported("this operating system"))
    }

    pub fn open(_pid: Pid) -> Result<Arc<dyn Process>> {
        Err(Error::Unsupported("this operating system"))
    }
}
#[cfg(not(any(target_os = "linux", windows)))]
pub use unsupported::{list_processes, open};

/// `align`ed addresses in the free gaps between the `used` (start, end) ranges where `size`
/// bytes fit within ±2 GiB of `near` and inside [low, high), closest to `near` first.
/// `align` must be a power of two.
#[cfg(any(target_os = "linux", windows))]
fn near_candidates(
    used: &mut [(u64, u64)],
    near: u64,
    size: u64,
    align: u64,
    low: u64,
    high: u64,
) -> Vec<u64> {
    // Slightly under 2 GiB so a rel32 from anywhere in the block back to `near` still reaches.
    const RANGE: u64 = 0x7fff_0000;
    let lo = near.saturating_sub(RANGE).max(low);
    let hi = near.saturating_add(RANGE).min(high);
    used.sort_unstable();
    let mut gaps = Vec::new();
    let mut prev = 0;
    for &(s, e) in used.iter() {
        gaps.push((prev, s));
        prev = prev.max(e);
    }
    gaps.push((prev, high));
    let mut out: Vec<(u64, u64)> = gaps
        .into_iter()
        .filter_map(|(gs, ge)| {
            let gs = gs.max(lo).checked_next_multiple_of(align)?;
            let last = ge.min(hi).checked_sub(size)? & !(align - 1);
            (last >= gs).then(|| {
                let c = (near & !(align - 1)).clamp(gs, last);
                (c.abs_diff(near), c)
            })
        })
        .collect();
    out.sort_unstable();
    out.into_iter().map(|(_, c)| c).collect()
}

#[cfg(all(test, any(target_os = "linux", windows)))]
mod tests {
    use super::near_candidates;

    #[test]
    fn near_gaps() {
        let mut used = [(0x1000_2000, 0x1000_3000), (0x1000_0000, 0x1000_1000)];
        let c = near_candidates(&mut used, 0x1000_0800, 0x1000, 0x1000, 0x10000, 1 << 47);
        assert_eq!(c[0], 0x1000_1000); // the one-page hole right next to `near`
        assert!(
            c.iter()
                .all(|&a| a.abs_diff(0x1000_0800) < 0x8000_0000 && a % 0x1000 == 0)
        );
        // 64 KiB alignment skips the small hole.
        let c = near_candidates(&mut used, 0x1000_0800, 0x1000, 0x10000, 0x10000, 1 << 47);
        assert!(c[0] == 0x0fff_0000 || c[0] == 0x1001_0000);
        assert!(
            near_candidates(&mut used, 0x1000_0800, 1 << 40, 0x1000, 0x10000, 1 << 47).is_empty()
        );
    }
}
