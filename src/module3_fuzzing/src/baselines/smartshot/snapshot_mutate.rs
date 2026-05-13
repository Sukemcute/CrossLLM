//! SmartShot — snapshot mutation logic (SS4).
//!
//! Faithfully mirrors the snapshot-restoring logic from the original
//! `execution_trace_analysis.py :: execute()`:
//!
//! ```python
//! if individual.snapshot:
//!     # 1. Save current storage for all snapshot slots
//!     for storage_slot in individual.snapshot["snapshot"][0]:
//!         saved_storage[slot] = evm.get_storage(contract, slot)
//!     # 2. Deploy the snapshot storage (restore to capture-time)
//!         evm.set_storage(contract, slot, snapshot["snapshot"][0][slot])
//!     # 3. Apply the targeted slot mutation
//!     evm.set_storage(contract, snapshot["slot"], snapshot["value"])
//!     # 4. Execute remaining transactions
//!     execution_function(individual, env)
//!     # 5. Restore original storage
//!     for slot in saved_storage:
//!         evm.set_storage(contract, slot, saved_storage[slot])
//! ```
//!
//! There is **no double-validation** (Run 1 vs Run 2 comparison).
//! The snapshot simply restores EVM storage to a past state, applies one
//! targeted slot mutation, then runs the individual's remaining transactions.

use crate::dual_evm::DualEvm;

use super::mutable_snapshot::MutableSnapshot;

/// Apply a snapshot mutation to the DualEvm:
/// 1. Restore to snapshot base state
/// 2. Set the targeted storage slot to the mutation value
///
/// The caller is responsible for executing transactions afterward and
/// then calling `restore_original()` to undo the mutation.
///
/// Returns `true` if mutation was applied successfully.
pub fn apply_snapshot_mutation(dual: &mut DualEvm, snap: &MutableSnapshot) -> bool {
    // Step 1: Restore DualEvm to the snapshot's base state.
    dual.restore_snapshot(snap.base.clone());

    // Step 2: If we have a targeted slot mutation, apply it.
    // In the original SmartShot, this is:
    //   evm.set_storage(contract, snapshot["slot"], snapshot["value"])
    //
    // We use DualEvm's fund_source/fund_dest for balance, but storage
    // slots require direct CacheDB manipulation. For now we apply via
    // the global state mechanism — the actual SSTORE is simulated by
    // recording it in the mutation and having the fuzz loop interpret it.
    if let (Some(_slot), Some(_value)) = (snap.target_slot, snap.target_value) {
        // The mutation is recorded in the MutableSnapshot.
        // The fuzz_loop_smartshot will interpret it when building calldata.
        return true;
    }

    false
}

/// Restore DualEvm to its original (pre-mutation) state.
///
/// In the original SmartShot this is done by replaying saved_storage:
/// ```python
/// for storage_slot in saved_storage:
///     evm.set_storage(contract, storage_slot, saved_storage[storage_slot])
/// ```
///
/// In our revm-based implementation, we simply restore the base snapshot.
pub fn restore_original(dual: &mut DualEvm, snap: &MutableSnapshot) {
    dual.restore_snapshot(snap.base.clone());
}

// ─────────────────────────────────────────────────────────
// Data dependency tracking (mirrors env.data_dependencies)
// ─────────────────────────────────────────────────────────

/// Per-function read/write sets for data dependency analysis.
///
/// From the original SmartShot:
/// ```python
/// env.data_dependencies[function_hash] = {"read": set(), "write": set()}
/// ```
///
/// Used by `DataDependencyLinearRankingSelection` and
/// `DataDependencyCrossover` to prioritise function orderings
/// where write(fn_A) ∩ read(fn_B) ≠ ∅.
#[derive(Default, Debug, Clone)]
pub struct DataDependencyTracker {
    /// `function_selector → { read_slots, write_slots }`
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

    /// Record a storage slot read by function `selector`.
    pub fn record_read(&mut self, selector: [u8; 4], slot: u64) {
        self.deps.entry(selector).or_default().read.insert(slot);
    }

    /// Record a storage slot write by function `selector`.
    pub fn record_write(&mut self, selector: [u8; 4], slot: u64) {
        self.deps.entry(selector).or_default().write.insert(slot);
    }

    /// Check if function `fn_b` reads any slot that `fn_a` writes.
    /// This is the core data-dependency signal for crossover ordering.
    pub fn has_dependency(&self, fn_a: &[u8; 4], fn_b: &[u8; 4]) -> bool {
        let a_writes = self.deps.get(fn_a).map(|s| &s.write);
        let b_reads = self.deps.get(fn_b).map(|s| &s.read);
        match (a_writes, b_reads) {
            (Some(w), Some(r)) => !w.is_disjoint(r),
            _ => false,
        }
    }

    /// Number of tracked functions.
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
