//! Synchronized Snapshot Management
//!
//! Global snapshot = (S_EVM_S, S_EVM_D, S_Relay)
//! All three components captured/restored atomically under global lock
//! to prevent inconsistent cross-chain state exploration.

/// Global snapshot containing state of both EVMs and the relay.
pub struct GlobalSnapshot {
    // TODO: Add EVM state snapshots + relay state
    // source_state: EvmSnapshot,
    // dest_state: EvmSnapshot,
    // relay_state: RelayState,
}

/// Pool of snapshots for backtracking during fuzzing.
pub struct SnapshotPool {
    snapshots: Vec<GlobalSnapshot>,
}

impl SnapshotPool {
    pub fn new() -> Self {
        Self { snapshots: Vec::new() }
    }

    /// Capture synchronized snapshot from both EVMs + relay.
    pub fn capture(&mut self /* dual_evm, relay */) -> usize {
        // TODO: Capture all three states under global lock
        todo!("Capture global snapshot")
    }

    /// Restore a snapshot by index (rollback both chains + relay).
    pub fn restore(&self, _index: usize /* dual_evm, relay */) {
        // TODO: Restore all three states in same order
        todo!("Restore global snapshot")
    }

    /// Select best snapshot for a given seed (shared prefix matching).
    pub fn select_for_seed(&self, _seed: &[u8]) -> usize {
        // TODO: Choose snapshot closest to seed's first action
        todo!("Select snapshot for seed")
    }
}
