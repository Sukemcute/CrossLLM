//! SmartShot baseline re-implementation.
//!
//! Mutable-snapshot fuzzer for smart contracts (ISSTA 2025).
//! Original: <https://github.com/SCFuzzing/SmartShot>
//!
//! Key components:
//! - [`mutable_snapshot`] — storage-only snapshot with 4 opcode triggers
//! - [`snapshot_pool`] — FIFO pool of pending snapshot mutations
//! - [`snapshot_mutate`] — apply/restore storage mutations on DualEvm
//! - [`sload_inspector`] — revm Inspector recording SLOAD slots
//! - [`taint_cache`] — per-function read-set cache with cut-loss fallback
//! - [`fuzz_loop_smartshot`] — main GA loop with snapshot injection

pub mod fuzz_loop_smartshot;
pub mod mutable_snapshot;
pub mod sload_inspector;
pub mod snapshot_mutate;
pub mod snapshot_pool;
pub mod taint_cache;
