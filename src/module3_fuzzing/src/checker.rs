//! Invariant checker (oracle) and reward signal for the fuzzing loop.
//!
//! Distances follow `types::CheckResult::distance`: **0.0 = violated**, larger values mean
//! farther from a violation (safer margin).

use crate::types::{CheckResult, GlobalState, Invariant, Waypoint};

/// Oracle + reward weights (α, β, γ from the project plan).
pub struct InvariantChecker {
    invariants: Vec<Invariant>,
    alpha: f64,
    beta: f64,
    gamma: f64,
}

impl InvariantChecker {
    pub fn new(invariants: Vec<Invariant>, alpha: f64, beta: f64, gamma: f64) -> Self {
        Self {
            invariants,
            alpha,
            beta,
            gamma,
        }
    }

    /// Update reward weights (paper: decay $\alpha$, shift mass to $\beta,\gamma$).
    pub fn set_reward_weights(&mut self, alpha: f64, beta: f64, gamma: f64) {
        self.alpha = alpha;
        self.beta = beta;
        self.gamma = gamma;
    }

    /// Evaluate all configured invariants against the current global state.
    pub fn check(&self, global_state: &GlobalState) -> Vec<CheckResult> {
        self.invariants
            .iter()
            .map(|inv| self.check_one(global_state, inv))
            .collect()
    }

    fn check_one(&self, state: &GlobalState, inv: &Invariant) -> CheckResult {
        let trace = vec![format!("check:{}", inv.invariant_id)];
        let (violated, description, distance) = match inv.category.as_str() {
            "asset_conservation" => self.check_asset_conservation(state, inv),
            "uniqueness" => self.check_uniqueness(state, inv),
            "authorization" | "timeliness" => {
                if inv.invariant_id.contains("root") {
                    self.check_root_validation(state, inv)
                } else {
                    self.check_authorization(state, inv)
                }
            }
            _ if inv.invariant_id.contains("root") => self.check_root_validation(state, inv),
            _ => self.check_generic(state, inv),
        };

        CheckResult {
            violated,
            invariant_id: inv.invariant_id.clone(),
            description,
            trace,
            distance,
        }
    }

    fn locked_total(state: &GlobalState) -> u128 {
        parse_balance(&state.source_state, "__locked__")
    }

    fn minted_total(state: &GlobalState) -> u128 {
        parse_balance(&state.dest_state, "__minted__")
    }

    fn saw_dispatch(state: &GlobalState) -> bool {
        meta_flag(&state.source_state, "saw_dispatch")
    }

    fn zero_root_accepted(state: &GlobalState) -> bool {
        slot_equals(
            &state.dest_state,
            "replica",
            "zero_root_accepted",
            "true",
        )
    }

    fn check_asset_conservation(
        &self,
        state: &GlobalState,
        _inv: &Invariant,
    ) -> (bool, Option<String>, f64) {
        let locked = Self::locked_total(state);
        let minted = Self::minted_total(state);
        let fee_tolerance = locked / 1000 + 1;

        if minted > locked.saturating_add(fee_tolerance) {
            (
                true,
                Some(format!(
                    "minted ({minted}) exceeds locked ({locked}) beyond tolerance"
                )),
                0.0,
            )
        } else {
            let margin = (locked.saturating_sub(minted)).max(1) as f64;
            (false, None, margin)
        }
    }

    fn check_uniqueness(
        &self,
        state: &GlobalState,
        _inv: &Invariant,
    ) -> (bool, Option<String>, f64) {
        let locked = Self::locked_total(state);
        let minted = Self::minted_total(state);
        let fee_tolerance = locked / 1000 + 1;
        let double_spend = minted > locked.saturating_add(fee_tolerance);

        let mut seen = std::collections::HashSet::new();
        let mut dup_processed = false;
        for id in &state.relay_state.processed_set {
            if !seen.insert(id.as_str()) {
                dup_processed = true;
                break;
            }
        }

        if double_spend || dup_processed {
            let msg = if dup_processed {
                "duplicate entries in relay processed set".to_string()
            } else {
                format!("replay / double process: minted={minted} locked={locked}")
            };
            (true, Some(msg), 0.0)
        } else {
            let margin = (locked.saturating_sub(minted).max(1) as f64) + 10.0;
            (false, None, margin)
        }
    }

    fn check_authorization(
        &self,
        state: &GlobalState,
        _inv: &Invariant,
    ) -> (bool, Option<String>, f64) {
        let minted = Self::minted_total(state);
        let locked = Self::locked_total(state);
        let saw = Self::saw_dispatch(state);

        let bad_mint_without_lock = minted > 0 && !saw && locked == 0;
        let bad_ratio = minted > locked.saturating_add(locked / 1000 + 1);

        if bad_mint_without_lock || bad_ratio {
            let msg = if bad_mint_without_lock {
                "mint activity without observed source deposit".to_string()
            } else {
                format!("unauthorized economic imbalance minted={minted} locked={locked}")
            };
            (true, Some(msg), 0.0)
        } else {
            let margin = if saw {
                (locked.saturating_sub(minted).max(1) as f64) + 5.0
            } else {
                50.0
            };
            (false, None, margin)
        }
    }

    fn check_root_validation(
        &self,
        state: &GlobalState,
        _inv: &Invariant,
    ) -> (bool, Option<String>, f64) {
        if Self::zero_root_accepted(state) {
            (
                true,
                Some("replica accepted an all-zero / invalid root path".to_string()),
                0.0,
            )
        } else {
            (false, None, 25.0)
        }
    }

    fn check_generic(&self, state: &GlobalState, inv: &Invariant) -> (bool, Option<String>, f64) {
        let (_, _, d) = self.check_asset_conservation(state, inv);
        if Self::minted_total(state) > Self::locked_total(state) {
            (
                true,
                Some("generic fallback: economic imbalance".to_string()),
                d,
            )
        } else {
            (false, None, d.max(1.0))
        }
    }

    /// Branch-distance style scalar for a single invariant and state.
    pub fn invariant_distance(&self, state: &GlobalState, inv: &Invariant) -> f64 {
        let (v, _, margin) = match inv.category.as_str() {
            "asset_conservation" => self.check_asset_conservation(state, inv),
            "uniqueness" => self.check_uniqueness(state, inv),
            "authorization" | "timeliness" => {
                if inv.invariant_id.contains("root") {
                    self.check_root_validation(state, inv)
                } else {
                    self.check_authorization(state, inv)
                }
            }
            _ if inv.invariant_id.contains("root") => self.check_root_validation(state, inv),
            _ => self.check_generic(state, inv),
        };
        if v {
            0.0
        } else {
            margin.max(1e-6)
        }
    }

    /// R(σ) ≈ α·coverage + β·waypoint_ratio + γ·mean(1 / (1 + distance_i)).
    pub fn reward(
        &self,
        coverage: f64,
        waypoints_reached: &[String],
        scenario_waypoints: &[Waypoint],
        state: &GlobalState,
    ) -> f64 {
        let wp_denom = scenario_waypoints.len().max(1) as f64;
        let wp_ratio = waypoints_reached.len() as f64 / wp_denom;

        let results = self.check(state);
        let n = results.len().max(1) as f64;
        let inv_signal: f64 = results
            .iter()
            .map(|r| {
                if r.violated {
                    1.0
                } else {
                    1.0 / (1.0 + r.distance)
                }
            })
            .sum::<f64>()
            / n;

        self.alpha * coverage.clamp(0.0, 1.0)
            + self.beta * wp_ratio.clamp(0.0, 1.0)
            + self.gamma * inv_signal.clamp(0.0, 1.0)
    }
}

fn parse_balance(chain: &crate::types::ChainState, key: &str) -> u128 {
    chain
        .balances
        .get(key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn meta_flag(chain: &crate::types::ChainState, key: &str) -> bool {
    chain
        .storage
        .get("__meta__")
        .and_then(|m| m.get(key))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

fn slot_equals(
    chain: &crate::types::ChainState,
    contract: &str,
    slot: &str,
    expected: &str,
) -> bool {
    chain
        .storage
        .get(contract)
        .and_then(|m| m.get(slot))
        .map(|v| v == expected)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::types::{ChainState, GlobalState, Invariant, RelaySnapshot, Waypoint};

    fn inv_asset() -> Invariant {
        Invariant {
            invariant_id: "inv_asset_conservation".into(),
            category: "asset_conservation".into(),
            description: "test".into(),
            predicate: "".into(),
            solidity_assertion: "".into(),
            related_edges: vec![],
        }
    }

    fn inv_unique() -> Invariant {
        Invariant {
            invariant_id: "inv_uniqueness".into(),
            category: "uniqueness".into(),
            description: "test".into(),
            predicate: "".into(),
            solidity_assertion: "".into(),
            related_edges: vec![],
        }
    }

    fn inv_root() -> Invariant {
        Invariant {
            invariant_id: "inv_root_validation".into(),
            category: "authorization".into(),
            description: "test".into(),
            predicate: "".into(),
            solidity_assertion: "".into(),
            related_edges: vec![],
        }
    }

    fn clean_state() -> GlobalState {
        GlobalState {
            source_state: ChainState {
                balances: HashMap::from([("__locked__".into(), "1000".into())]),
                storage: HashMap::from([(
                    "__meta__".into(),
                    HashMap::from([("saw_dispatch".into(), "true".into())]),
                )]),
                block_number: 1,
                timestamp: 1,
            },
            dest_state: ChainState {
                balances: HashMap::from([("__minted__".into(), "1000".into())]),
                storage: HashMap::new(),
                block_number: 1,
                timestamp: 1,
            },
            relay_state: RelaySnapshot {
                pending_messages: vec![],
                processed_set: vec!["a".into()],
                mode: "faithful".into(),
                message_count: 1,
            },
        }
    }

    fn violated_asset_state() -> GlobalState {
        let mut s = clean_state();
        s.dest_state
            .balances
            .insert("__minted__".into(), "9999".into());
        s
    }

    fn violated_root_state() -> GlobalState {
        let mut s = clean_state();
        s.dest_state.storage.insert(
            "replica".into(),
            HashMap::from([("zero_root_accepted".into(), "true".into())]),
        );
        s
    }

    #[test]
    fn feed_normal_state_asset_clean() {
        let c = InvariantChecker::new(vec![inv_asset()], 0.3, 0.4, 0.3);
        let r = c.check(&clean_state());
        assert_eq!(r.len(), 1);
        assert!(!r[0].violated);
        assert!(r[0].distance > 0.0);
    }

    #[test]
    fn feed_violated_asset_state() {
        let c = InvariantChecker::new(vec![inv_asset()], 0.3, 0.4, 0.3);
        let r = c.check(&violated_asset_state());
        assert!(r[0].violated);
        assert_eq!(r[0].distance, 0.0);
    }

    #[test]
    fn feed_violated_root_state() {
        let c = InvariantChecker::new(vec![inv_root()], 0.3, 0.4, 0.3);
        let r = c.check(&violated_root_state());
        assert!(r[0].violated);
    }

    #[test]
    fn reward_mixes_components() {
        let c = InvariantChecker::new(vec![inv_asset()], 0.3, 0.4, 0.3);
        let wps = vec!["w1".into()];
        let scenario_wp = vec![
            Waypoint {
                waypoint_id: "w1".into(),
                after_step: 1,
                predicate: "".into(),
                description: "".into(),
            },
            Waypoint {
                waypoint_id: "w2".into(),
                after_step: 2,
                predicate: "".into(),
                description: "".into(),
            },
        ];
        let r = c.reward(1.0, &wps, &scenario_wp, &clean_state());
        assert!(r > 0.0 && r <= 1.0 + f64::EPSILON);
    }

    #[test]
    fn uniqueness_detects_duplicate_processed_ids() {
        let mut s = clean_state();
        s.relay_state.processed_set = vec!["x".into(), "x".into()];
        let c = InvariantChecker::new(vec![inv_unique()], 0.3, 0.4, 0.3);
        let r = c.check(&s);
        assert!(r[0].violated);
    }
}
