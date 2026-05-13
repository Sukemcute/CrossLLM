//! SmartShot re-implementation — mutable snapshot data structure (SS2).
//!
//! Faithfully mirrors the original `SCFuzzing/SmartShot` repo
//! (`fuzzer/engine/analysis/execution_trace_analysis.py`):
//!
//! - A snapshot stores the **contract storage dict** at a point-in-time.
//! - Mutation = overwrite **one storage slot** with a solver-generated or
//!   boundary value, then run the GA individual's remaining transactions.
//! - After execution the original storage is **restored** (undo).
//!
//! The 4 snapshot triggers from the paper (Table 3):
//!   1. `LastSstoreBeforeJumpi` — SSTORE whose PC is the last SSTORE before a JUMPI
//!   2. `TimestampAccess` — execution hits the TIMESTAMP opcode
//!   3. `BlockNumberAccess` — execution hits the NUMBER opcode
//!   4. `ExternalCall` — execution hits CALL / STATICCALL

use std::collections::HashMap;

use revm::primitives::{Address, B256, U256};

use crate::dual_evm::DualEvmSnapshot;
use crate::mock_relay::RelayState;

// ─────────────────────────────────────────────────────────
// Snapshot kind — 4 triggers from the real SmartShot
// ─────────────────────────────────────────────────────────

/// Why a snapshot was captured. Maps 1:1 to the 4 `take_snapshot()` call sites
/// in the original `execution_trace_analysis.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnapshotKind {
    /// SSTORE whose PC is the last SSTORE to a given slot before a JUMPI.
    /// `take_snapshot("storage", storage_slot, ...)`
    LastSstoreBeforeJumpi,
    /// TIMESTAMP opcode hit.
    /// `take_snapshot("timestamp", instruction["pc"], ...)`
    TimestampAccess,
    /// NUMBER (block number) opcode hit.
    /// `take_snapshot("blocknumber", instruction["pc"], ...)`
    BlockNumberAccess,
    /// CALL / STATICCALL opcode hit.
    /// `take_snapshot("call", instruction["pc"], ...)`
    ExternalCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationOperator {
    MS1SetStorage,
    MS2SetBalance,
    MS3SetCodeDisabled,
    MS4AdvanceTimestamp,
    MS5AdvanceBlock,
    MS6SetCallerNonceDisabled,
}

impl MutationOperator {
    pub fn id(self) -> &'static str {
        match self {
            MutationOperator::MS1SetStorage => "MS1",
            MutationOperator::MS2SetBalance => "MS2",
            MutationOperator::MS3SetCodeDisabled => "MS3",
            MutationOperator::MS4AdvanceTimestamp => "MS4",
            MutationOperator::MS5AdvanceBlock => "MS5",
            MutationOperator::MS6SetCallerNonceDisabled => "MS6",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MutationOperator::MS1SetStorage => "set_storage",
            MutationOperator::MS2SetBalance => "set_balance",
            MutationOperator::MS3SetCodeDisabled => "set_code_disabled",
            MutationOperator::MS4AdvanceTimestamp => "advance_timestamp",
            MutationOperator::MS5AdvanceBlock => "advance_block",
            MutationOperator::MS6SetCallerNonceDisabled => "set_caller_nonce_disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotMutation {
    SetStorage {
        contract: Address,
        slot: B256,
        value: B256,
    },
    SetBalance {
        address: Address,
        value: U256,
    },
    AdvanceTimestamp {
        source_delta: u64,
        dest_delta: u64,
    },
    AdvanceBlock {
        source_delta: u64,
        dest_delta: u64,
    },
    Disabled {
        operator: MutationOperator,
        reason: String,
    },
}

impl SnapshotMutation {
    pub fn operator(&self) -> MutationOperator {
        match self {
            SnapshotMutation::SetStorage { .. } => MutationOperator::MS1SetStorage,
            SnapshotMutation::SetBalance { .. } => MutationOperator::MS2SetBalance,
            SnapshotMutation::AdvanceTimestamp { .. } => MutationOperator::MS4AdvanceTimestamp,
            SnapshotMutation::AdvanceBlock { .. } => MutationOperator::MS5AdvanceBlock,
            SnapshotMutation::Disabled { operator, .. } => *operator,
        }
    }
}

// ─────────────────────────────────────────────────────────
// MutableSnapshot
// ─────────────────────────────────────────────────────────

/// A `DualEvmSnapshot` extended with a single storage-slot mutation
/// (the core SmartShot concept).
///
/// Per the original `execution_function()`:
/// ```python
/// if individual.snapshot:
///     evm.set_storage(contract, snapshot["slot"], snapshot["value"])
///     # run remaining transactions
///     # then restore original storage
/// ```
#[derive(Clone)]
pub struct MutableSnapshot {
    /// The original, unmodified dual-EVM snapshot to restore from.
    pub base: DualEvmSnapshot,
    /// Relay state at capture time.
    pub relay: RelayState,
    /// Why this snapshot was taken (which opcode trigger).
    pub kind: SnapshotKind,
    /// Storage state at capture time: `contract_addr → { slot → value }`.
    pub storage_at_capture: HashMap<Address, HashMap<B256, B256>>,
    /// The storage slot that was targeted for mutation (if any).
    pub target_slot: Option<B256>,
    /// The mutated value written to `target_slot` (Z3-solved or boundary).
    pub target_value: Option<B256>,
    /// Transaction index at capture time — used to truncate the individual's
    /// chromosome so we only replay from the snapshot point onward.
    pub tx_index: usize,
    /// Concrete SmartShot mutations applied to this snapshot.
    pub mutation_log: Vec<SnapshotMutation>,
}

impl MutableSnapshot {
    /// Wrap an existing `DualEvmSnapshot` with no slot mutation applied yet.
    pub fn from_snapshot(
        snap: DualEvmSnapshot,
        relay: RelayState,
        kind: SnapshotKind,
        tx_index: usize,
    ) -> Self {
        Self {
            base: snap,
            relay,
            kind,
            storage_at_capture: HashMap::new(),
            target_slot: None,
            target_value: None,
            tx_index,
            mutation_log: Vec::new(),
        }
    }

    /// Apply a storage slot mutation: set `slot` on `contract_addr` to `value`.
    /// This is the core SmartShot mutation operator.
    pub fn set_storage_mutation(&mut self, contract: Address, slot: B256, value: B256) {
        self.target_slot = Some(slot);
        self.target_value = Some(value);
        self.mutation_log.push(SnapshotMutation::SetStorage {
            contract,
            slot,
            value,
        });
    }

    pub fn set_balance_mutation(&mut self, address: Address, value: U256) {
        self.mutation_log
            .push(SnapshotMutation::SetBalance { address, value });
    }

    pub fn advance_timestamp_mutation(&mut self, source_delta: u64, dest_delta: u64) {
        self.mutation_log.push(SnapshotMutation::AdvanceTimestamp {
            source_delta,
            dest_delta,
        });
    }

    pub fn advance_block_mutation(&mut self, source_delta: u64, dest_delta: u64) {
        self.mutation_log.push(SnapshotMutation::AdvanceBlock {
            source_delta,
            dest_delta,
        });
    }

    /// Return `true` if a slot mutation has been applied.
    pub fn has_mutation(&self) -> bool {
        self.target_slot.is_some() || !self.mutation_log.is_empty()
    }

    /// Clear the applied mutation (for reuse with a different value).
    pub fn clear_mutation(&mut self) {
        self.target_slot = None;
        self.target_value = None;
        self.mutation_log.clear();
    }
}

// ─────────────────────────────────────────────────────────
// Boundary mutation pool (per paper §5.2)
// ─────────────────────────────────────────────────────────

/// Well-known boundary values for storage slot mutations.
///
/// When Z3 constraint solving is not available (our cut-loss path),
/// we randomly pick from these boundary values.
pub fn mutation_pool_values() -> Vec<B256> {
    [
        U256::ZERO,
        U256::from(1u8),
        U256::MAX,
        U256::from(u128::MAX),
        U256::from(1u128) << 127, // INT_MAX for signed 128-bit
        U256::from(u64::MAX),
        U256::from(10u64).pow(U256::from(18u64)), // 1 ether in wei
    ]
    .iter()
    .map(|v| {
        let bytes = v.to_be_bytes::<32>();
        B256::from(bytes)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_kind_all_4_variants() {
        let kinds = [
            SnapshotKind::LastSstoreBeforeJumpi,
            SnapshotKind::TimestampAccess,
            SnapshotKind::BlockNumberAccess,
            SnapshotKind::ExternalCall,
        ];
        assert_eq!(kinds.len(), 4);
        assert_ne!(kinds[0], kinds[1]);
        assert_ne!(kinds[2], kinds[3]);
    }

    #[test]
    fn mutation_pool_has_boundary_values() {
        let pool = mutation_pool_values();
        assert!(pool.len() >= 5);
        assert_eq!(pool[0], B256::ZERO); // first = 0
        assert_ne!(pool[1], B256::ZERO); // second = 1
    }

    #[test]
    fn mutation_pool_includes_u256_max() {
        let pool = mutation_pool_values();
        // U256::MAX → all bytes 0xFF
        let max_b256 = B256::from([0xFF; 32]);
        assert!(pool.contains(&max_b256), "pool should contain U256::MAX");
    }

    #[test]
    fn snapshot_kind_hash_eq() {
        // SnapshotKind implements Hash + Eq, so it can be used as HashMap key
        let mut set = std::collections::HashSet::new();
        set.insert(SnapshotKind::LastSstoreBeforeJumpi);
        set.insert(SnapshotKind::ExternalCall);
        set.insert(SnapshotKind::LastSstoreBeforeJumpi); // duplicate
        assert_eq!(set.len(), 2);
    }
}
