//! SmartShot taint cache: per-function SLOAD read sets plus cut-loss slots.

use std::collections::{HashMap, HashSet};

use revm::primitives::{Address, B256, U256};

use crate::baselines::smartshot::sload_inspector::{u256_to_b256, SLoadInspector};
use crate::dual_evm::DualEvm;

pub type FnId = (Address, [u8; 4]);
pub type ReadSet = HashSet<(Address, B256)>;

#[derive(Default)]
pub struct TaintCache {
    inner: HashMap<FnId, ReadSet>,
    /// True when populated from bridge metadata/root-cause slots instead of
    /// observed SLOADs.
    pub cut_loss_mode: bool,
}

impl TaintCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read_set_of(&self, fn_id: &FnId) -> Option<&ReadSet> {
        self.inner.get(fn_id)
    }

    pub fn insert(&mut self, fn_id: FnId, rs: ReadSet) {
        self.inner.insert(fn_id, rs);
    }

    pub fn total_slots(&self) -> usize {
        self.inner.values().map(|rs| rs.len()).sum()
    }

    pub fn all_slots(&self) -> ReadSet {
        self.inner
            .values()
            .flat_map(|rs| rs.iter().copied())
            .collect()
    }
}

/// Run a dry call through `SLoadInspector` and return observed SLOAD slots.
pub fn collect_read_set(dual: &mut DualEvm, addr: Address, selector: [u8; 4]) -> ReadSet {
    use crate::dual_evm::default_caller;

    let mut payload = vec![0u8; 44];
    payload[..20].copy_from_slice(default_caller().as_slice());
    payload[20..40].copy_from_slice(addr.as_slice());
    payload[40..44].copy_from_slice(&selector);

    if let Ok((_outcome, insp)) =
        dual.execute_on_source_with_inspector_return(&payload, SLoadInspector::new())
    {
        let rs = insp.into_read_set();
        if !rs.is_empty() {
            return rs;
        }
    }
    if let Ok((_outcome, insp)) =
        dual.execute_on_dest_with_inspector_return(&payload, SLoadInspector::new())
    {
        let rs = insp.into_read_set();
        if !rs.is_empty() {
            return rs;
        }
    }

    ReadSet::new()
}

fn slot(n: u64) -> B256 {
    u256_to_b256(U256::from(n))
}

pub fn hand_curated_slots(bridge_name: &str, target_addr: Address) -> ReadSet {
    let mut rs = ReadSet::new();

    match bridge_name.to_ascii_lowercase().as_str() {
        "nomad" => {
            rs.insert((target_addr, slot(0)));
            rs.insert((target_addr, slot(2)));
        }
        "qubit" => {
            rs.insert((target_addr, slot(0)));
            rs.insert((target_addr, slot(1)));
        }
        "multichain" | "polynetwork" | "socket" | "gempad" => {
            rs.insert((target_addr, slot(0)));
            rs.insert((target_addr, slot(1)));
            rs.insert((target_addr, slot(2)));
        }
        "ronin" | "harmony" | "orbit" => {
            for s in 0u64..6 {
                rs.insert((target_addr, slot(s)));
            }
        }
        "wormhole" | "fegtoken" => {
            rs.insert((target_addr, slot(0)));
        }
        "pgala" => {
            for s in 0u64..5 {
                rs.insert((target_addr, slot(s)));
            }
        }
        _ => {
            for s in 0u64..4 {
                rs.insert((target_addr, slot(s)));
            }
        }
    }

    rs
}

pub fn build_curated_taint_cache(
    bridge_name: &str,
    contracts: &[(Address, [u8; 4])],
) -> TaintCache {
    let mut cache = TaintCache::new();
    cache.cut_loss_mode = true;

    for (addr, selector) in contracts {
        let rs = hand_curated_slots(bridge_name, *addr);
        if !rs.is_empty() {
            cache.insert((*addr, *selector), rs);
        }
    }

    cache
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_slots_nomad_nonempty() {
        let rs = hand_curated_slots("nomad", Address::ZERO);
        assert!(!rs.is_empty());
    }

    #[test]
    fn curated_slots_unknown_bridge_fallback() {
        let rs = hand_curated_slots("unknown_xyz_bridge", Address::ZERO);
        assert_eq!(rs.len(), 4);
    }

    #[test]
    fn build_curated_cache_is_cut_loss() {
        let selector = [0xabu8, 0xcd, 0xef, 0x00];
        let cache = build_curated_taint_cache("nomad", &[(Address::ZERO, selector)]);
        assert!(cache.cut_loss_mode);
        assert!(cache.read_set_of(&(Address::ZERO, selector)).is_some());
    }

    #[test]
    fn taint_cache_all_slots_aggregates() {
        let mut cache = TaintCache::new();
        let addr1 = Address::from([1u8; 20]);
        let addr2 = Address::from([2u8; 20]);
        let mut rs1 = ReadSet::new();
        rs1.insert((addr1, B256::ZERO));
        let mut rs2 = ReadSet::new();
        rs2.insert((addr2, B256::ZERO));
        cache.insert((addr1, [0u8; 4]), rs1);
        cache.insert((addr2, [0u8; 4]), rs2);
        assert_eq!(cache.all_slots().len(), 2);
    }
}
