//! SmartShot — snapshot pool (SS2 part 2).
//!
//! Faithfully mirrors the `snapshot_reserved` dict from the original
//! `execution_trace_analysis.py`:
//!
//! ```python
//! env.snapshot_reserved[key] = []  # key = "storage_{slot}"
//! env.snapshot_reserved[key].append(solved_vars[...])
//! ```
//!
//! Each key (`"{kind}_{slot_or_pc}"`) maps to a FIFO queue of snapshot
//! entries. Per generation the engine pops up to 5 entries per slot,
//! creates new GA individuals from them, and injects them into the
//! population.

use std::collections::{HashMap, VecDeque};

use revm::primitives::{Address, B256};

use super::mutable_snapshot::{MutableSnapshot, MutationOperator, SnapshotKind};

/// One entry in the snapshot pool — represents a restorable state plus
/// the targeted mutation to apply before resuming execution.
#[derive(Clone)]
pub struct SnapshotEntry {
    /// The full dual-EVM snapshot at capture time.
    pub snapshot: MutableSnapshot,
    /// Contract address whose storage is being targeted.
    pub contract: Address,
    /// The targeted storage slot (for storage-type snapshots).
    pub slot: B256,
    /// The value to write into `slot` (Z3-solved or boundary).
    pub target_value: B256,
    /// Mutation operator represented by this entry.
    pub operator: MutationOperator,
}

/// Pool of pending snapshot-based mutations, keyed by trigger type + slot.
///
/// Mirrors `env.snapshot_reserved` from the original SmartShot:
/// ```python
/// key = f"storage_{slot}"   # or "timestamp_0", "blocknumber_0", "call_{pc}"
/// env.snapshot_reserved[key] = [solved_var_1, solved_var_2, ...]
/// ```
#[derive(Default)]
pub struct SnapshotPool {
    inner: HashMap<String, VecDeque<SnapshotEntry>>,
    /// Maximum entries per key (per the original: up to 5).
    pub max_per_key: usize,
}

impl SnapshotPool {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            max_per_key: 5,
        }
    }

    /// Build the string key for a snapshot, matching the original Python format.
    pub fn make_key(kind: SnapshotKind, discriminant: u64) -> String {
        let prefix = match kind {
            SnapshotKind::LastSstoreBeforeJumpi => "storage",
            SnapshotKind::TimestampAccess => "timestamp",
            SnapshotKind::BlockNumberAccess => "blocknumber",
            SnapshotKind::ExternalCall => "call",
        };
        format!("{}_{}", prefix, discriminant)
    }

    /// Push a new snapshot entry into the pool under `key`.
    /// If the queue for this key already has `max_per_key` entries,
    /// the push is silently dropped (no eviction — same as original).
    pub fn push(&mut self, key: &str, entry: SnapshotEntry) {
        let queue = self.inner.entry(key.to_string()).or_default();
        if queue.len() < self.max_per_key {
            queue.push_back(entry);
        }
    }

    /// Pop the oldest entry for `key` (FIFO). Returns `None` if empty.
    pub fn pop(&mut self, key: &str) -> Option<SnapshotEntry> {
        self.inner.get_mut(key).and_then(|q| q.pop_front())
    }

    /// Drain all entries across all keys, returning them as a flat `Vec`.
    /// Used at the start of each generation to inject snapshot-individuals.
    pub fn drain_all(&mut self) -> Vec<SnapshotEntry> {
        let mut out = Vec::new();
        for (_key, queue) in self.inner.iter_mut() {
            out.extend(queue.drain(..));
        }
        out
    }

    /// Total number of queued entries across all keys.
    pub fn total_entries(&self) -> usize {
        self.inner.values().map(|q| q.len()).sum()
    }

    /// Check if `key` has any pending entries.
    pub fn has_entries(&self, key: &str) -> bool {
        self.inner.get(key).map_or(false, |q| !q.is_empty())
    }

    /// Return all keys that currently have entries.
    pub fn active_keys(&self) -> Vec<String> {
        self.inner
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_key_format() {
        assert_eq!(
            SnapshotPool::make_key(SnapshotKind::LastSstoreBeforeJumpi, 7),
            "storage_7"
        );
        assert_eq!(
            SnapshotPool::make_key(SnapshotKind::TimestampAccess, 0),
            "timestamp_0"
        );
        assert_eq!(
            SnapshotPool::make_key(SnapshotKind::BlockNumberAccess, 42),
            "blocknumber_42"
        );
        assert_eq!(
            SnapshotPool::make_key(SnapshotKind::ExternalCall, 100),
            "call_100"
        );
    }

    #[test]
    fn pool_new_is_empty() {
        let pool = SnapshotPool::new();
        assert_eq!(pool.total_entries(), 0);
        assert!(!pool.has_entries("storage_0"));
        assert!(pool.active_keys().is_empty());
    }

    #[test]
    fn pool_max_per_key_default() {
        let pool = SnapshotPool::new();
        assert_eq!(pool.max_per_key, 5);
    }
}
