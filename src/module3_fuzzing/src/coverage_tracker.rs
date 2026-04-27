//! Bytecode coverage tracking via revm's [`Inspector`] hook.
//!
//! Approximates basic-block coverage (paper §7.3) by recording every unique
//! `(target_address, program_counter)` pair the interpreter visits. Each PC
//! lies inside exactly one basic block, so the count of unique PCs is an
//! over-approximation of basic blocks but a meaningful coverage proxy.
//!
//! Usage:
//! ```ignore
//! let mut tracker = CoverageTracker::default();
//! dual.execute_on_source_with_inspector(&payload, &mut tracker)?;
//! let (n_src_pcs, _) = tracker.split_by_address(&[router_addr]);
//! ```

use std::collections::HashSet;

use revm::interpreter::Interpreter;
use revm::primitives::{db::Database, Address};
use revm::{EvmContext, Inspector};

/// Records every unique `(address, pc)` pair the interpreter visits.
#[derive(Default, Clone, Debug)]
pub struct CoverageTracker {
    pub touched: HashSet<(Address, usize)>,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total unique `(address, pc)` pairs hit across all contracts.
    pub fn unique_pc_count(&self) -> usize {
        self.touched.len()
    }

    /// Merge another tracker's hits into this one (idempotent).
    pub fn merge(&mut self, other: &CoverageTracker) {
        self.touched.extend(other.touched.iter().copied());
    }

    /// Drop all recorded coverage (used between independent runs).
    pub fn clear(&mut self) {
        self.touched.clear();
    }
}

impl<DB: Database> Inspector<DB> for CoverageTracker {
    fn step(&mut self, interp: &mut Interpreter, _ctx: &mut EvmContext<DB>) {
        let addr = interp.contract.target_address;
        let pc = interp.program_counter();
        self.touched.insert((addr, pc));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use revm::db::BenchmarkDB;
    use revm::inspector_handle_register;
    use revm::primitives::{address, Bytecode, Bytes, TransactTo};
    use revm::Evm;

    #[test]
    fn new_tracker_is_empty() {
        let t = CoverageTracker::new();
        assert_eq!(t.unique_pc_count(), 0);
    }

    #[test]
    fn merge_combines_hits_idempotently() {
        let mut a = CoverageTracker::new();
        let mut b = CoverageTracker::new();
        let addr = Address::from([0x11; 20]);
        a.touched.insert((addr, 0));
        a.touched.insert((addr, 1));
        b.touched.insert((addr, 1));
        b.touched.insert((addr, 2));

        a.merge(&b);
        assert_eq!(a.unique_pc_count(), 3, "merged set should have 3 unique PCs");
        // Idempotent re-merge.
        a.merge(&b);
        assert_eq!(a.unique_pc_count(), 3, "re-merge does not duplicate");
    }

    #[test]
    fn clear_resets_tracker() {
        let mut t = CoverageTracker::new();
        t.touched.insert((Address::ZERO, 42));
        assert_eq!(t.unique_pc_count(), 1);
        t.clear();
        assert_eq!(t.unique_pc_count(), 0);
    }

    /// End-to-end: feed a hand-rolled bytecode (`PUSH1 1 PUSH1 2 ADD STOP`)
    /// through revm's [`Inspector`] register and confirm the tracker records
    /// at least one `(address, pc)` pair per executed opcode.
    #[test]
    fn tracker_records_pcs_during_simple_execution() {
        // PUSH1 0x01 PUSH1 0x02 ADD STOP — 4 distinct opcode steps.
        let bytecode = Bytecode::new_raw(Bytes::from(vec![
            0x60, 0x01, 0x60, 0x02, 0x01, 0x00,
        ]));

        let mut evm: Evm<'_, CoverageTracker, BenchmarkDB> = Evm::builder()
            .with_db(BenchmarkDB::new_bytecode(bytecode))
            .with_external_context(CoverageTracker::default())
            .modify_tx_env(|tx| {
                tx.caller = address!("1000000000000000000000000000000000000000");
                tx.transact_to =
                    TransactTo::Call(address!("0000000000000000000000000000000000000000"));
                tx.gas_limit = 100_000;
            })
            .append_handler_register(inspector_handle_register)
            .build();

        evm.transact().expect("transact");
        let tracker = evm.into_context().external;

        // 4 instructions → at least 4 unique PCs visited (PUSH1, PUSH1, ADD, STOP).
        assert!(
            tracker.unique_pc_count() >= 4,
            "tracker recorded {} unique PCs, expected >= 4",
            tracker.unique_pc_count()
        );
    }
}
