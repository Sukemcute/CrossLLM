//! SmartShot snapshot mutation logic.
//!
//! A snapshot mutation restores the captured DualEVM state, applies one or
//! more concrete mutations to the revm CacheDB/block env, then lets the fuzz
//! loop execute the candidate scenario from that mutated state.

use revm::primitives::{B256, U256};

use crate::dual_evm::DualEvm;

use super::mutable_snapshot::{MutableSnapshot, SnapshotMutation};

/// Apply a snapshot mutation to the DualEVM.
///
/// Returns true if at least one concrete mutation was applied.
pub fn apply_snapshot_mutation(dual: &mut DualEvm, snap: &MutableSnapshot) -> bool {
    dual.restore_snapshot(snap.base.clone());

    let mut applied = false;
    for mutation in &snap.mutation_log {
        match mutation {
            SnapshotMutation::SetStorage {
                contract,
                slot,
                value,
            } => {
                let slot_u = b256_to_u256(*slot);
                let value_u = b256_to_u256(*value);
                let src_ok = dual.set_source_storage(*contract, slot_u, value_u).is_ok();
                let dst_ok = dual.set_dest_storage(*contract, slot_u, value_u).is_ok();
                applied |= src_ok || dst_ok;
            }
            SnapshotMutation::SetBalance { address, value } => {
                dual.set_source_balance(*address, *value);
                dual.set_dest_balance(*address, *value);
                applied = true;
            }
            SnapshotMutation::AdvanceTimestamp {
                source_delta,
                dest_delta,
            } => {
                dual.advance_source_time(*source_delta);
                dual.advance_dest_time(*dest_delta);
                applied = true;
            }
            SnapshotMutation::AdvanceBlock {
                source_delta,
                dest_delta,
            } => {
                dual.advance_source_block(*source_delta);
                dual.advance_dest_block(*dest_delta);
                applied = true;
            }
            SnapshotMutation::Disabled { .. } => {}
        }
    }

    applied
}

/// Restore DualEVM to the original captured state.
pub fn restore_original(dual: &mut DualEvm, snap: &MutableSnapshot) {
    dual.restore_snapshot(snap.base.clone());
}

fn b256_to_u256(v: B256) -> U256 {
    U256::from_be_bytes(v.0)
}

// ---------------------------------------------------------------------------
// Data dependency tracking (mirrors env.data_dependencies)
// ---------------------------------------------------------------------------

/// Per-function read/write sets for data dependency analysis.
#[derive(Default, Debug, Clone)]
pub struct DataDependencyTracker {
    /// `function_selector -> { read_slots, write_slots }`
    deps: std::collections::HashMap<[u8; 4], ReadWriteSet>,
}

#[derive(Default, Debug, Clone)]
pub struct ReadWriteSet {
    pub read: std::collections::HashSet<u64>,
    pub write: std::collections::HashSet<u64>,
}

impl DataDependencyTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_read(&mut self, selector: [u8; 4], slot: u64) {
        self.deps.entry(selector).or_default().read.insert(slot);
    }

    pub fn record_write(&mut self, selector: [u8; 4], slot: u64) {
        self.deps.entry(selector).or_default().write.insert(slot);
    }

    pub fn has_dependency(&self, fn_a: &[u8; 4], fn_b: &[u8; 4]) -> bool {
        let a_writes = self.deps.get(fn_a).map(|s| &s.write);
        let b_reads = self.deps.get(fn_b).map(|s| &s.read);
        match (a_writes, b_reads) {
            (Some(w), Some(r)) => !w.is_disjoint(r),
            _ => false,
        }
    }

    pub fn num_functions(&self) -> usize {
        self.deps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dependency_tracker_basic() {
        let mut tracker = DataDependencyTracker::new();
        let fn_a = [0xabu8, 0xcd, 0xef, 0x01];
        let fn_b = [0x12u8, 0x34, 0x56, 0x78];

        tracker.record_write(fn_a, 5);
        tracker.record_read(fn_b, 5);
        assert!(tracker.has_dependency(&fn_a, &fn_b));
        assert!(!tracker.has_dependency(&fn_b, &fn_a));
    }

    #[test]
    fn data_dependency_no_overlap() {
        let mut tracker = DataDependencyTracker::new();
        let fn_a = [0xabu8, 0xcd, 0xef, 0x01];
        let fn_b = [0x12u8, 0x34, 0x56, 0x78];

        tracker.record_write(fn_a, 5);
        tracker.record_read(fn_b, 10);
        assert!(!tracker.has_dependency(&fn_a, &fn_b));
    }
}
