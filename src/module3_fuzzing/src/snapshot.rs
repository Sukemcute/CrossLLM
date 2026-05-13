//! Synchronized Snapshot Management
//!
//! Global snapshot = (S_EVM_S, S_EVM_D, S_Relay) per paper; capture/restore in process order
//! (relay then dual-EVM) for a consistent rollback point.

use crate::dual_evm::{DualEvm, DualEvmSnapshot};
use crate::mock_relay::{MockRelay, RelayState};
use crate::types::{Action, Scenario};

/// Fingerprint one scenario action for shared-prefix snapshot selection (Alg. 1).
pub fn action_fingerprint(a: &Action) -> String {
    format!(
        "{}|{}|{}|{}",
        a.chain.to_lowercase(),
        a.contract.as_deref().unwrap_or(""),
        a.function.as_deref().unwrap_or(""),
        a.action.as_deref().unwrap_or("")
    )
}

/// One global checkpoint: optional dual-EVM DB clones + relay process state + action prefix metadata.
#[derive(Clone)]
pub struct GlobalSnapshot {
    pub evm: Option<DualEvmSnapshot>,
    pub relay: RelayState,
    /// Number of actions represented by `action_fingerprints` (redundant but handy for metrics).
    pub prefix_len: usize,
    /// Actions executed to reach this state; must be a prefix of any seed we restore into.
    pub action_fingerprints: Vec<String>,
}

/// Pool of snapshots for backtracking (paper Alg. 1).
#[derive(Default)]
pub struct SnapshotPool {
    snapshots: Vec<GlobalSnapshot>,
}

impl SnapshotPool {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.snapshots.clear();
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Capture relay + optional dual-EVM; `action_fingerprints` describes the executed prefix.
    pub fn capture(
        &mut self,
        dual: Option<&DualEvm>,
        relay: &MockRelay,
        prefix_len: usize,
        action_fingerprints: Vec<String>,
    ) -> usize {
        let evm = dual.map(DualEvm::capture_snapshot);
        let relay_state = relay.get_state();
        self.snapshots.push(GlobalSnapshot {
            evm,
            relay: relay_state,
            prefix_len,
            action_fingerprints,
        });
        self.snapshots.len() - 1
    }

    /// Restore snapshot `index`: relay first, then dual-EVM if present in snapshot and `dual` is Some.
    pub fn restore(
        &self,
        index: usize,
        dual: Option<&mut DualEvm>,
        relay: &mut MockRelay,
    ) -> Result<(), String> {
        let snap = self
            .snapshots
            .get(index)
            .ok_or_else(|| format!("snapshot index {index} out of bounds"))?;
        relay.restore_state(snap.relay.clone());
        if let (Some(ref evm_snap), Some(d)) = (&snap.evm, dual) {
            d.restore_snapshot(evm_snap.clone());
        }
        Ok(())
    }

    /// Paper Alg. 1: pick snapshot whose `action_fingerprints` is the longest **prefix** of the seed's actions.
    pub fn select_for_seed(&self, seed: &[u8]) -> usize {
        let Ok(scenario) = serde_json::from_slice::<Scenario>(seed) else {
            return 0;
        };
        let seed_fps: Vec<String> = scenario.actions.iter().map(action_fingerprint).collect();

        if self.snapshots.is_empty() {
            return 0;
        }

        let mut best_idx = 0usize;
        let mut best_len = 0usize;
        for (i, snap) in self.snapshots.iter().enumerate() {
            let mut l = 0usize;
            while l < snap.action_fingerprints.len()
                && l < seed_fps.len()
                && snap.action_fingerprints[l] == seed_fps[l]
            {
                l += 1;
            }
            if l == snap.action_fingerprints.len() && l >= best_len {
                if l > best_len || (l == best_len && i >= best_idx) {
                    best_len = l;
                    best_idx = i;
                }
            }
        }
        best_idx
    }

    /// Keep at most `max` snapshots by dropping from the front (FIFO). `max` should be >= 1.
    pub fn evict_oldest_if_over(&mut self, max: usize) {
        let cap = max.max(1);
        while self.snapshots.len() > cap {
            self.snapshots.remove(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_relay::{MockRelay, RelayMode};

    #[test]
    fn relay_only_capture_restore_roundtrip() {
        let mut pool = SnapshotPool::new();
        let mut relay = MockRelay::new(RelayMode::Faithful);
        relay.relay_message(b"hello").unwrap();

        let fps: Vec<String> = vec![];
        let idx = pool.capture(None, &relay, 0, fps.clone());
        relay.relay_message(b"world").unwrap();
        relay.set_mode(RelayMode::Tampered);

        pool.restore(idx, None, &mut relay).unwrap();
        let out = relay.relay_message(b"hello").unwrap_err(); // already processed id for "hello"
        assert!(out.contains("already processed") || out.contains("message"));
    }

    #[test]
    fn select_for_seed_longest_prefix() {
        let mut pool = SnapshotPool::new();
        let relay = MockRelay::new(RelayMode::Faithful);

        pool.capture(
            None,
            &relay,
            0,
            vec![], // initial
        );
        pool.capture(None, &relay, 2, vec!["a|x|f|".into(), "b|y|g|".into()]);
        pool.capture(
            None,
            &relay,
            3,
            vec!["a|x|f|".into(), "b|y|g|".into(), "c|z|h|".into()],
        );

        let seed = br#"{"scenario_id":"t","target_invariant":"","vulnerability_class":"","confidence":0,"actions":[
            {"step":1,"chain":"a","contract":"x","function":"f","params":{},"description":""},
            {"step":2,"chain":"b","contract":"y","function":"g","params":{},"description":""},
            {"step":3,"chain":"d","contract":"m","function":"n","params":{},"description":""}
        ],"waypoints":[],"retrieved_exploits":[]}"#;

        let i = pool.select_for_seed(seed);
        // Longest valid prefix: [a,x,f],[b,y,g] matches first two actions of seed; third snapshot not prefix (c!=d)
        assert_eq!(i, 1);
    }
}
