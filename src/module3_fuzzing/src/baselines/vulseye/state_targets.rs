//! State-target identification for VulSEye (VS3).
//!
//! **Implementation path**: concrete-trace approximation (cut-loss §8 of
//! `docs/REIMPL_VULSEYE_SPEC.md`). Instead of Z3-based backward symbolic
//! analysis (paper Algorithms 2+3), we:
//!
//! 1. **Static phase**: for each code target, walk backward through
//!    predecessor blocks to find `SLOAD` instructions. The storage slots
//!    they read are the "state variables". Nearby comparison opcodes
//!    (EQ, LT, GT, ISZERO) hint at expected value constraints.
//!
//! 2. **Runtime phase**: as the fuzzer runs, a `ConcreteTraceCollector`
//!    records `(slot, value)` pairs observed when execution hits a
//!    code-target basic block. The top-N most frequent pairs become
//!    approximate state targets, seeding the mutation pool (VS4).
//!
//! **Methodology note**: "VS3 used concrete-trace state-target
//! approximation in lieu of paper Algorithm 3 due to Z3 timeout >30s/JUMPI
//! on our bytecode set."

use std::collections::HashMap;

use revm::primitives::{Address, B256, U256};

use super::code_targets::{op, Cfg, CodeTarget};

// ============================================================================
// Types
// ============================================================================

/// Expected value constraint for a state variable.
#[derive(Clone, Debug, PartialEq)]
pub enum ValueConstraint {
    /// Slot must equal this exact value.
    Exact(U256),
    /// Slot must be zero (from ISZERO check).
    Zero,
    /// Slot must be non-zero.
    NonZero,
    /// Slot must be less than this bound.
    LessThan(U256),
    /// Slot must be greater than this bound.
    GreaterThan(U256),
    /// No constraint inferred — slot is relevant but value unknown.
    Any,
}

/// A state target: storage precondition for reaching a code target.
#[derive(Clone, Debug)]
pub struct StateTarget {
    /// Storage slot that must satisfy the constraint.
    pub slot: U256,
    /// Expected value constraint (static inference or concrete observation).
    pub constraint: ValueConstraint,
    /// Contract address owning the slot.
    pub contract: Address,
    /// Index of the code target this state target is associated with.
    pub code_target_idx: usize,
}

/// Static analysis result: map from code-target index to its state targets.
pub type StateTargetMap = HashMap<usize, Vec<StateTarget>>;

// ============================================================================
// Static phase: extract state targets from CFG
// ============================================================================

/// For each code target, walk backward through predecessor blocks to find
/// SLOAD instructions and infer value constraints from nearby comparisons.
///
/// Returns a map from code-target index (in `code_targets` slice) to the
/// state targets discovered.
pub fn identify_state_targets_static(
    cfg: &Cfg,
    code_targets: &[CodeTarget],
) -> StateTargetMap {
    let mut out = StateTargetMap::new();

    for (ct_idx, ct) in code_targets.iter().enumerate() {
        let mut targets = Vec::new();

        // Walk backward from the target BB through predecessors (depth 12).
        let ancestors = cfg.predecessors_within_depth(ct.bb_id, 12);

        for &bb_id in &ancestors {
            let bb = match cfg.blocks.get(bb_id) {
                Some(b) => b,
                None => continue,
            };

            for (i, inst) in bb.instructions.iter().enumerate() {
                if inst.opcode != op::SLOAD {
                    continue;
                }

                // Try to resolve the slot from a preceding PUSH.
                let slot = if i > 0 {
                    let prev = &bb.instructions[i - 1];
                    if op::is_push(prev.opcode) {
                        prev.push_value_usize()
                            .map(|v| U256::from(v))
                            .unwrap_or(U256::ZERO)
                    } else {
                        // Dynamic slot (e.g. from SHA3) — use 0 as placeholder.
                        U256::ZERO
                    }
                } else {
                    U256::ZERO
                };

                // Infer constraint from opcodes after the SLOAD.
                let constraint = infer_constraint_after_sload(bb, i);

                targets.push(StateTarget {
                    slot,
                    constraint,
                    contract: ct.contract,
                    code_target_idx: ct_idx,
                });
            }
        }

        if !targets.is_empty() {
            out.insert(ct_idx, targets);
        }
    }

    out
}

/// Look at instructions after an SLOAD (at position `sload_idx` in the
/// block) to infer what comparison is being made on the loaded value.
fn infer_constraint_after_sload(
    bb: &super::code_targets::BasicBlock,
    sload_idx: usize,
) -> ValueConstraint {
    // Scan the next few instructions for comparison opcodes.
    let remaining = &bb.instructions[sload_idx + 1..];
    let lookahead = remaining.iter().take(4);

    for inst in lookahead {
        match inst.opcode {
            op::ISZERO => return ValueConstraint::Zero,
            op::EQ => {
                // Try to find the comparison constant from a PUSH before EQ.
                // This is a heuristic — in practice the constant is often
                // on the stack from a PUSH a few instructions earlier.
                if let Some(val) = find_nearby_push_value(remaining) {
                    return ValueConstraint::Exact(val);
                }
                return ValueConstraint::Any;
            }
            op::LT => {
                if let Some(val) = find_nearby_push_value(remaining) {
                    return ValueConstraint::LessThan(val);
                }
                return ValueConstraint::Any;
            }
            op::GT => {
                if let Some(val) = find_nearby_push_value(remaining) {
                    return ValueConstraint::GreaterThan(val);
                }
                return ValueConstraint::Any;
            }
            _ => {}
        }
    }

    // No comparison found — slot is relevant but constraint unknown.
    ValueConstraint::NonZero
}

/// Find the first PUSH value in a slice of instructions.
fn find_nearby_push_value(
    instructions: &[super::code_targets::Instruction],
) -> Option<U256> {
    instructions
        .iter()
        .take(3)
        .find(|i| op::is_push(i.opcode))
        .and_then(|i| i.push_value_usize().map(|v| U256::from(v)))
}

// ============================================================================
// Runtime phase: concrete-trace collector
// ============================================================================

/// Collects `(slot, value)` pairs observed during fuzzer execution when
/// a code-target basic block is hit. After N iterations, the top-K most
/// frequent pairs become refined state targets for the mutation pool.
#[derive(Clone, Debug, Default)]
pub struct ConcreteTraceCollector {
    /// (code_target_idx, slot) → list of observed values.
    observations: HashMap<(usize, U256), Vec<U256>>,
}

impl ConcreteTraceCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observation: the fuzzer hit a code-target BB and the
    /// storage tracker shows `slot` held `value` at that moment.
    pub fn observe(&mut self, code_target_idx: usize, slot: U256, value: U256) {
        self.observations
            .entry((code_target_idx, slot))
            .or_default()
            .push(value);
    }

    /// Feed all writes from a `StorageTracker` that were observed during
    /// an iteration where `hit_bb_ids` (the set of visited basic-block
    /// IDs) intersects with code targets.
    pub fn ingest_from_tracker(
        &mut self,
        tracker: &crate::storage_tracker::StorageTracker,
        code_targets: &[CodeTarget],
        hit_pcs: &std::collections::HashSet<usize>,
    ) {
        for (ct_idx, ct) in code_targets.iter().enumerate() {
            // Did the fuzzer hit the code target's PC this iteration?
            if !hit_pcs.contains(&ct.pc) {
                continue;
            }
            // Record all storage reads/writes from this iteration.
            for (&(addr, slot), &value) in &tracker.latest {
                if addr == ct.contract {
                    let slot_u256 = U256::from_be_bytes(slot.0);
                    self.observe(ct_idx, slot_u256, value);
                }
            }
        }
    }

    /// Produce refined state targets from accumulated observations.
    /// For each (code_target, slot), the most frequent observed value
    /// becomes an `Exact` constraint. Returns targets sorted by
    /// observation frequency (most observed first).
    pub fn to_state_targets(
        &self,
        code_targets: &[CodeTarget],
        top_n: usize,
    ) -> Vec<StateTarget> {
        let mut all: Vec<(usize, StateTarget)> = Vec::new();

        for (&(ct_idx, slot), values) in &self.observations {
            if values.is_empty() {
                continue;
            }
            let contract = code_targets
                .get(ct_idx)
                .map(|ct| ct.contract)
                .unwrap_or(Address::ZERO);

            // Find the most frequent value.
            let mut freq: HashMap<U256, usize> = HashMap::new();
            for v in values {
                *freq.entry(*v).or_default() += 1;
            }
            let (best_value, count) = freq
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .unwrap();

            all.push((
                count,
                StateTarget {
                    slot,
                    constraint: ValueConstraint::Exact(best_value),
                    contract,
                    code_target_idx: ct_idx,
                },
            ));
        }

        // Sort by frequency descending, take top-N.
        all.sort_by(|a, b| b.0.cmp(&a.0));
        all.into_iter().take(top_n).map(|(_, st)| st).collect()
    }

    /// Total number of distinct (code_target, slot) pairs observed.
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

// ============================================================================
// State distance computation (used by VS4 fitness)
// ============================================================================

/// Compute the distance from the current storage state to a single state
/// target. Returns 0.0 if the constraint is satisfied, otherwise a
/// positive distance measure.
///
/// Used by VS4's `StateDistance(S)` (Eq. 5 in the paper).
pub fn state_target_distance(
    target: &StateTarget,
    current_storage: &HashMap<(Address, B256), U256>,
) -> f64 {
    let slot_key = (target.contract, B256::from(target.slot.to_be_bytes()));
    let current = current_storage
        .get(&slot_key)
        .copied()
        .unwrap_or(U256::ZERO);

    match &target.constraint {
        ValueConstraint::Exact(expected) => {
            if current == *expected {
                0.0
            } else {
                // Hamming-style distance on the 256-bit value.
                let diff = if current > *expected {
                    current - *expected
                } else {
                    *expected - current
                };
                // Normalize: log2(diff+1) / 256.
                let bits = (256 - diff.leading_zeros()) as f64;
                bits / 256.0
            }
        }
        ValueConstraint::Zero => {
            if current == U256::ZERO {
                0.0
            } else {
                let bits = (256 - current.leading_zeros()) as f64;
                bits / 256.0
            }
        }
        ValueConstraint::NonZero => {
            if current != U256::ZERO {
                0.0
            } else {
                1.0
            }
        }
        ValueConstraint::LessThan(bound) => {
            if current < *bound {
                0.0
            } else {
                let over = current - *bound;
                let bits = (256 - over.leading_zeros()) as f64;
                bits / 256.0
            }
        }
        ValueConstraint::GreaterThan(bound) => {
            if current > *bound {
                0.0
            } else {
                let under = *bound - current;
                let bits = (256 - under.leading_zeros()) as f64;
                (bits + 1.0) / 256.0
            }
        }
        ValueConstraint::Any => 0.0,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baselines::vulseye::code_targets::Cfg;

    #[test]
    fn static_extraction_finds_sload_slots() {
        // PUSH1 0x05  SLOAD  ISZERO  PUSH1 0x0A  JUMPI  STOP  JUMPDEST  STOP
        let bytecode = vec![
            0x60, 0x05, // PUSH1 5 (slot)
            op::SLOAD,
            op::ISZERO,
            0x60, 0x0A, // PUSH1 10 (jump target)
            op::JUMPI,
            op::STOP,
            op::JUMPDEST,
            op::STOP,
        ];
        let cfg = Cfg::from_bytecode(&bytecode, Address::ZERO);

        // Fake a code target at the JUMPI's BB.
        let jumpi_bb = cfg
            .blocks
            .iter()
            .find(|bb| bb.contains_opcode(op::JUMPI))
            .expect("should have JUMPI");
        let targets = vec![CodeTarget {
            pattern_id: "BP2".to_string(),
            bb_id: jumpi_bb.id,
            pc: jumpi_bb.end_pc,
            contract: Address::ZERO,
        }];

        let map = identify_state_targets_static(&cfg, &targets);
        assert!(!map.is_empty(), "should find state targets");
        let sts = &map[&0];
        assert_eq!(sts.len(), 1);
        assert_eq!(sts[0].slot, U256::from(5));
        assert_eq!(sts[0].constraint, ValueConstraint::Zero);
    }

    #[test]
    fn concrete_collector_picks_most_frequent() {
        let mut collector = ConcreteTraceCollector::new();
        let targets = vec![CodeTarget {
            pattern_id: "BP5".to_string(),
            bb_id: 0,
            pc: 0,
            contract: Address::ZERO,
        }];

        // Observe slot=1: value 42 appears 3 times, value 99 appears 1 time.
        let slot = U256::from(1);
        collector.observe(0, slot, U256::from(42));
        collector.observe(0, slot, U256::from(42));
        collector.observe(0, slot, U256::from(42));
        collector.observe(0, slot, U256::from(99));

        let refined = collector.to_state_targets(&targets, 10);
        assert_eq!(refined.len(), 1);
        assert_eq!(refined[0].constraint, ValueConstraint::Exact(U256::from(42)));
    }

    #[test]
    fn distance_exact_match_is_zero() {
        let target = StateTarget {
            slot: U256::from(1),
            constraint: ValueConstraint::Exact(U256::from(42)),
            contract: Address::ZERO,
            code_target_idx: 0,
        };
        let mut storage = HashMap::new();
        let key = (Address::ZERO, B256::from(U256::from(1).to_be_bytes()));
        storage.insert(key, U256::from(42));

        assert_eq!(state_target_distance(&target, &storage), 0.0);
    }

    #[test]
    fn distance_exact_mismatch_is_positive() {
        let target = StateTarget {
            slot: U256::from(1),
            constraint: ValueConstraint::Exact(U256::from(42)),
            contract: Address::ZERO,
            code_target_idx: 0,
        };
        let mut storage = HashMap::new();
        let key = (Address::ZERO, B256::from(U256::from(1).to_be_bytes()));
        storage.insert(key, U256::from(100));

        let d = state_target_distance(&target, &storage);
        assert!(d > 0.0, "distance should be positive for mismatch");
        assert!(d <= 1.0, "distance should be normalized to [0,1]");
    }

    #[test]
    fn distance_zero_constraint() {
        let target = StateTarget {
            slot: U256::from(1),
            constraint: ValueConstraint::Zero,
            contract: Address::ZERO,
            code_target_idx: 0,
        };
        let key = (Address::ZERO, B256::from(U256::from(1).to_be_bytes()));

        // Zero value → distance 0.
        let mut storage = HashMap::new();
        storage.insert(key, U256::ZERO);
        assert_eq!(state_target_distance(&target, &storage), 0.0);

        // Non-zero → positive distance.
        storage.insert(key, U256::from(1));
        assert!(state_target_distance(&target, &storage) > 0.0);
    }

    #[test]
    fn distance_nonzero_constraint() {
        let target = StateTarget {
            slot: U256::from(1),
            constraint: ValueConstraint::NonZero,
            contract: Address::ZERO,
            code_target_idx: 0,
        };
        let key = (Address::ZERO, B256::from(U256::from(1).to_be_bytes()));

        let mut storage = HashMap::new();
        storage.insert(key, U256::from(1));
        assert_eq!(state_target_distance(&target, &storage), 0.0);

        storage.insert(key, U256::ZERO);
        assert_eq!(state_target_distance(&target, &storage), 1.0);
    }
}
