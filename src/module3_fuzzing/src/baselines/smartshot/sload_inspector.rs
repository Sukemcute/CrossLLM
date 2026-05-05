//! SmartShot — SLoad inspector for taint collection (SS3).
//!
//! Per `docs/REIMPL_SMARTSHOT_SPEC.md §2.2`.
//!
//! `SLoadInspector` records every `(contract_address, storage_slot)` pair
//! that the EVM reads via the SLOAD opcode during a single call execution.
//! This is the "taint collection" phase that tells the fuzzer *which* slots
//! are worth mutating for a given function.

use std::collections::HashSet;

use revm::interpreter::{Interpreter, OpCode};
use revm::primitives::{db::Database, Address, B256, U256};
use revm::{EvmContext, Inspector};

/// Records every `(address, slot)` pair touched by SLOAD during one execution.
///
/// Usage:
/// ```ignore
/// let mut insp = SLoadInspector::default();
/// dual.execute_on_source_with_inspector_full(tx, &mut insp)?;
/// let read_set = insp.observed_sloads;
/// ```
#[derive(Default, Debug, Clone)]
pub struct SLoadInspector {
    /// Every `(contract_address, storage_slot)` read during the execution.
    pub observed_sloads: HashSet<(Address, B256)>,
}

impl SLoadInspector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of unique `(addr, slot)` pairs recorded.
    pub fn read_set_size(&self) -> usize {
        self.observed_sloads.len()
    }

    /// Consume the inspector and return the recorded read set.
    pub fn into_read_set(self) -> HashSet<(Address, B256)> {
        self.observed_sloads
    }
}

impl<DB: Database> Inspector<DB> for SLoadInspector {
    /// Fires before each EVM instruction. When the opcode is SLOAD (0x54)
    /// we peek the top of the stack (the slot key) and record it together
    /// with the contract address that issued the SLOAD.
    fn step(&mut self, interp: &mut Interpreter, _ctx: &mut EvmContext<DB>) {
        // SLOAD = 0x54
        if interp.current_opcode() == OpCode::SLOAD.get() {
            let addr = interp.contract.target_address;
            // Stack top is the storage key at SLOAD time.
            if let Ok(slot_u256) = interp.stack().peek(0) {
                let slot = u256_to_b256(slot_u256);
                self.observed_sloads.insert((addr, slot));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────

pub(crate) fn u256_to_b256(v: U256) -> B256 {
    let bytes = v.to_be_bytes::<32>();
    B256::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::db::BenchmarkDB;
    use revm::inspector_handle_register;
    use revm::primitives::{address, Bytecode, Bytes, TransactTo};
    use revm::Evm;

    #[test]
    fn new_inspector_is_empty() {
        let insp = SLoadInspector::new();
        assert_eq!(insp.read_set_size(), 0);
    }

    #[test]
    fn into_read_set_moves_ownership() {
        let mut insp = SLoadInspector::new();
        insp.observed_sloads.insert((Address::ZERO, B256::ZERO));
        let rs = insp.into_read_set();
        assert_eq!(rs.len(), 1);
    }

    /// Bytecode: PUSH1 0x00, SLOAD, STOP
    /// Slot 0x00 should be recorded.
    #[test]
    fn inspector_records_sload_slot() {
        // PUSH1 0x00 = 0x60 0x00; SLOAD = 0x54; STOP = 0x00
        let bytecode = Bytecode::new_raw(Bytes::from(vec![0x60, 0x00, 0x54, 0x00]));

        let mut evm: Evm<'_, SLoadInspector, BenchmarkDB> = Evm::builder()
            .with_db(BenchmarkDB::new_bytecode(bytecode))
            .with_external_context(SLoadInspector::default())
            .modify_tx_env(|tx| {
                tx.caller = address!("1000000000000000000000000000000000000000");
                tx.transact_to =
                    TransactTo::Call(address!("0000000000000000000000000000000000000000"));
                tx.gas_limit = 100_000;
            })
            .append_handler_register(inspector_handle_register)
            .build();

        evm.transact().expect("transact");
        let insp = evm.into_context().external;

        // The SLOAD on slot 0 should have been recorded.
        assert!(
            insp.observed_sloads
                .contains(&(address!("0000000000000000000000000000000000000000"), B256::ZERO)),
            "expected slot 0x00 to be recorded; got {:?}",
            insp.observed_sloads
        );
    }
}
