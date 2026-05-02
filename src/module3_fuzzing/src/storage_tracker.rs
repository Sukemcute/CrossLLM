//! Storage-write tracking via revm's [`Inspector`] hook.
//!
//! Records every `SSTORE` performed by the interpreter as an
//! `(address, slot, value)` triple. Used by the XScope I-6
//! authorisation-witness reconstruction (see
//! [`docs/REIMPL_XSCOPE_SPEC.md`] §3) — and reused later by VulSEye's
//! state-target backward analysis and SmartShot's symbolic-taint
//! cache. The same Inspector pattern as
//! [`crate::coverage_tracker::CoverageTracker`].
//!
//! `SSTORE` opcode is `0x55` in the EVM. The current revm interpreter
//! has the stack in pre-pop layout when `Inspector::step` fires:
//! `peek(0)` is the slot key (TOS), `peek(1)` is the value to write.
//! Both are `U256`; we cast the slot to a 32-byte `B256` for
//! map-keyed lookups (the natural shape for storage slots).

use std::collections::HashMap;

use revm::interpreter::Interpreter;
use revm::primitives::{db::Database, Address, B256, U256};
use revm::{EvmContext, Inspector};

const OPCODE_SSTORE: u8 = 0x55;

/// One observed `SSTORE` event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageWrite {
    /// Contract whose storage was written (the call's `target_address`).
    pub address: Address,
    /// Storage slot. Encoded as `B256` because that is the form Solidity
    /// uses for `mapping` keys (e.g. `keccak256(abi.encode(0))`) — which
    /// is exactly the value the XScope I-6 zero-root recipe inspects.
    pub slot: B256,
    /// New value being written. We record both the **last** value and a
    /// running `count` of writes per `(address, slot)` so callers can
    /// detect "is this slot non-zero now?" or "how many distinct
    /// signers have been admitted?" without having to replay the trace.
    pub value: U256,
}

/// Inspector that records every successful `SSTORE` opcode step.
///
/// The recorded log is **per-iteration** — the fuzz loop creates a
/// fresh tracker per scenario so violations are attributed to the
/// triggering trace.
#[derive(Default, Clone, Debug)]
pub struct StorageTracker {
    /// Ordered list of writes (oldest → newest). Useful when the
    /// caller cares about insertion order (e.g. distinguishing an
    /// initial set from a later overwrite).
    pub writes: Vec<StorageWrite>,
    /// `(addr, slot)` → most-recent value. Convenient O(1) lookup for
    /// auth-witness recipes that ask "is `acceptableRoot[bytes32(0)]`
    /// non-zero now?".
    pub latest: HashMap<(Address, B256), U256>,
    /// `(addr, slot)` → write count. Powers Ronin / Harmony multisig-
    /// threshold reconstruction by counting distinct signer-admit
    /// writes against the configured threshold.
    pub counts: HashMap<(Address, B256), u32>,
}

impl StorageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lookup the most recent write at `(addr, slot)`, or `None` if no
    /// SSTORE has hit it during this iteration. Used by recipe
    /// `slot_equals(addr, slot, expected)`.
    pub fn latest_value(&self, addr: Address, slot: B256) -> Option<U256> {
        self.latest.get(&(addr, slot)).copied()
    }

    /// Convenience: how many SSTOREs hit this slot this iteration. Used
    /// by recipes that count signer admits.
    pub fn write_count(&self, addr: Address, slot: B256) -> u32 {
        self.counts.get(&(addr, slot)).copied().unwrap_or(0)
    }

    /// Total number of SSTOREs across all (addr, slot) pairs.
    pub fn total_writes(&self) -> usize {
        self.writes.len()
    }

    /// Merge another tracker's writes into this one. Order is preserved
    /// (this tracker's writes first, then `other`'s).
    pub fn merge(&mut self, other: &StorageTracker) {
        for w in &other.writes {
            self.record(w.clone());
        }
    }

    /// Drop everything — used between independent runs.
    pub fn clear(&mut self) {
        self.writes.clear();
        self.latest.clear();
        self.counts.clear();
    }

    fn record(&mut self, w: StorageWrite) {
        let key = (w.address, w.slot);
        self.latest.insert(key, w.value);
        let count = self.counts.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        self.writes.push(w);
    }
}

impl<DB: Database> Inspector<DB> for StorageTracker {
    fn step(&mut self, interp: &mut Interpreter, _ctx: &mut EvmContext<DB>) {
        // Cheaper than calling current_opcode() since that re-reads the
        // pointer; we know the byte is at *instruction_pointer.
        if interp.current_opcode() != OPCODE_SSTORE {
            return;
        }
        // SSTORE pops `(value, slot)` per the YP — top of stack is the
        // slot key. Use `peek(0)` for slot, `peek(1)` for value.
        let slot = match interp.stack().peek(0) {
            Ok(s) => s,
            Err(_) => return,
        };
        let value = match interp.stack().peek(1) {
            Ok(v) => v,
            Err(_) => return,
        };
        self.record(StorageWrite {
            address: interp.contract.target_address,
            slot: B256::from(slot.to_be_bytes()),
            value,
        });
    }
}

// ============================================================================
// XScopeInspector — composite covering coverage + storage in one pass.
// ============================================================================

/// Composite inspector that delegates each `step` callback to an inner
/// [`crate::coverage_tracker::CoverageTracker`] **and** a
/// [`StorageTracker`]. revm only ships one external-context slot per
/// `Evm`, so when the XScope baseline mode wants both coverage hits
/// and SSTORE traces it passes one of these.
///
/// Lifetimes: borrowed mutably so the caller can read both trackers
/// after the EVM returns. The auto_impl on revm's `Inspector` lets us
/// pass `&mut XScopeInspector<'_, '_>` straight through
/// `with_external_context`.
pub struct XScopeInspector<'cov, 'sto> {
    pub coverage: &'cov mut crate::coverage_tracker::CoverageTracker,
    pub storage: &'sto mut StorageTracker,
}

impl<'cov, 'sto, DB: Database> Inspector<DB> for XScopeInspector<'cov, 'sto> {
    fn step(&mut self, interp: &mut Interpreter, ctx: &mut EvmContext<DB>) {
        self.coverage.step(interp, ctx);
        self.storage.step(interp, ctx);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use revm::db::BenchmarkDB;
    use revm::inspector_handle_register;
    use revm::primitives::{address, Bytecode, Bytes, TransactTo};
    use revm::Evm;

    /// End-to-end smoke: feed a bytecode that performs **two** SSTOREs
    /// (slot=1 ← 7, slot=1 ← 9) into revm with a `StorageTracker` as
    /// external context. After execution we expect:
    /// - `writes.len() == 2`
    /// - `latest_value(target, slot=1) == 9`
    /// - `write_count(target, slot=1) == 2`
    #[test]
    fn tracker_records_sstore_writes() {
        // Bytecode:
        //   PUSH1 0x07  PUSH1 0x01  SSTORE     (slot 1 := 7)
        //   PUSH1 0x09  PUSH1 0x01  SSTORE     (slot 1 := 9)
        //   STOP
        let bytecode = Bytecode::new_raw(Bytes::from(vec![
            0x60, 0x07, 0x60, 0x01, 0x55,
            0x60, 0x09, 0x60, 0x01, 0x55,
            0x00,
        ]));

        let mut evm: Evm<'_, StorageTracker, BenchmarkDB> = Evm::builder()
            .with_db(BenchmarkDB::new_bytecode(bytecode))
            .with_external_context(StorageTracker::default())
            .modify_tx_env(|tx| {
                tx.caller = address!("1000000000000000000000000000000000000000");
                tx.transact_to =
                    TransactTo::Call(address!("0000000000000000000000000000000000000000"));
                tx.gas_limit = 200_000;
            })
            .append_handler_register(inspector_handle_register)
            .build();

        evm.transact().expect("transact");
        let tracker = evm.into_context().external;

        assert_eq!(tracker.total_writes(), 2);
        let target = address!("0000000000000000000000000000000000000000");
        let slot_1 = B256::from(U256::from(1u64).to_be_bytes());
        assert_eq!(tracker.latest_value(target, slot_1), Some(U256::from(9u64)));
        assert_eq!(tracker.write_count(target, slot_1), 2);
    }

    #[test]
    fn merge_combines_in_order() {
        let target = Address::from([0x11; 20]);
        let slot_a = B256::from([0x01; 32]);
        let slot_b = B256::from([0x02; 32]);
        let mut a = StorageTracker::new();
        let mut b = StorageTracker::new();
        a.record(StorageWrite {
            address: target,
            slot: slot_a,
            value: U256::from(1u64),
        });
        b.record(StorageWrite {
            address: target,
            slot: slot_b,
            value: U256::from(2u64),
        });
        b.record(StorageWrite {
            address: target,
            slot: slot_a,
            value: U256::from(3u64),
        });
        a.merge(&b);
        assert_eq!(a.total_writes(), 3);
        assert_eq!(a.latest_value(target, slot_a), Some(U256::from(3u64)));
        assert_eq!(a.latest_value(target, slot_b), Some(U256::from(2u64)));
        assert_eq!(a.write_count(target, slot_a), 2);
    }

    #[test]
    fn clear_resets_tracker() {
        let mut t = StorageTracker::new();
        t.record(StorageWrite {
            address: Address::ZERO,
            slot: B256::ZERO,
            value: U256::from(1u64),
        });
        assert_eq!(t.total_writes(), 1);
        t.clear();
        assert_eq!(t.total_writes(), 0);
        assert!(t.latest.is_empty());
        assert!(t.counts.is_empty());
    }

    #[test]
    fn write_count_is_zero_for_unknown_slot() {
        let t = StorageTracker::new();
        assert_eq!(t.write_count(Address::ZERO, B256::ZERO), 0);
        assert_eq!(t.latest_value(Address::ZERO, B256::ZERO), None);
    }

    /// XScopeInspector should populate both coverage and storage from a
    /// single execution pass — the XScope baseline mode relies on this.
    #[test]
    fn xscope_inspector_populates_both_trackers() {
        // Same SSTORE×2 program as `tracker_records_sstore_writes`.
        let bytecode = Bytecode::new_raw(Bytes::from(vec![
            0x60, 0x07, 0x60, 0x01, 0x55,
            0x60, 0x09, 0x60, 0x01, 0x55,
            0x00,
        ]));
        let mut cov = crate::coverage_tracker::CoverageTracker::default();
        let mut storage = StorageTracker::default();
        {
            let composite = XScopeInspector {
                coverage: &mut cov,
                storage: &mut storage,
            };
            let mut evm = Evm::builder()
                .with_db(BenchmarkDB::new_bytecode(bytecode))
                .with_external_context(composite)
                .modify_tx_env(|tx| {
                    tx.caller = address!("1000000000000000000000000000000000000000");
                    tx.transact_to =
                        TransactTo::Call(address!("0000000000000000000000000000000000000000"));
                    tx.gas_limit = 200_000;
                })
                .append_handler_register(inspector_handle_register)
                .build();
            evm.transact().expect("transact");
        }
        // Coverage tracked: ≥ 5 PCs (2× PUSH1, 2× PUSH1, 2× SSTORE, STOP — actually
        // each instruction is one step so we get ≥ 11 PCs after JUMPDESTs etc.)
        assert!(
            cov.unique_pc_count() >= 4,
            "expected coverage to record opcode steps, got {}",
            cov.unique_pc_count()
        );
        // Storage tracked: 2 SSTOREs at slot 1.
        assert_eq!(storage.total_writes(), 2);
        let target = address!("0000000000000000000000000000000000000000");
        let slot_1 = B256::from(U256::from(1u64).to_be_bytes());
        assert_eq!(storage.latest_value(target, slot_1), Some(U256::from(9u64)));
    }
}
