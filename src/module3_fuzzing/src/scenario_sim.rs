//! Derives abstract [`crate::types::GlobalState`] fields (__locked__, __minted__, replica flags)
//! from a scenario alone. The caller should attach the real [`crate::types::RelaySnapshot`]
//! from [`crate::mock_relay::MockRelay`] after driving relay actions.

use std::collections::HashMap;

use crate::types::{ChainState, GlobalState, RelaySnapshot, Scenario, Waypoint};

/// Build oracle-facing state from the scenario text (no RPC).
pub fn global_state_from_scenario(scenario: &Scenario) -> GlobalState {
    let mut source_locked: u128 = 0;
    let mut dest_minted: u128 = 0;
    let mut saw_dispatch = false;
    let mut last_lock_amount: u128 = 0;
    let mut dest_storage: HashMap<String, HashMap<String, String>> = HashMap::new();

    for action in &scenario.actions {
        let op = normalized_operation(action);
        match action.chain.as_str() {
            "source" => {
                if matches!(op.as_str(), "dispatch" | "deposit" | "lock" | "send") {
                    saw_dispatch = true;
                    let amt = amount_from_action(action);
                    source_locked = source_locked.saturating_add(amt);
                    last_lock_amount = amt;
                }
            }
            "destination" => {
                if matches!(op.as_str(), "process" | "handle" | "release" | "processandrelease")
                {
                    if let Some(msg) = action.params.get("message") {
                        if let Some(s) = msg.as_str() {
                            if is_all_zero_hex_message(s) {
                                insert_slot(
                                    &mut dest_storage,
                                    "replica",
                                    "zero_root_accepted",
                                    "true",
                                );
                            }
                        }
                    }
                }

                if matches!(
                    op.as_str(),
                    "proveandprocess" | "processandrelease" | "handle" | "mint" | "release"
                ) {
                    let inc = if last_lock_amount > 0 {
                        last_lock_amount
                    } else {
                        amount_from_action(action)
                    };
                    dest_minted = dest_minted.saturating_add(inc);
                }
            }
            _ => {}
        }
    }

    let mut source_storage = HashMap::new();
    let mut meta = HashMap::new();
    if saw_dispatch {
        meta.insert("saw_dispatch".into(), "true".into());
    }
    source_storage.insert("__meta__".into(), meta);

    GlobalState {
        source_state: ChainState {
            balances: HashMap::from([("__locked__".into(), source_locked.to_string())]),
            storage: source_storage,
            block_number: 1,
            timestamp: 1,
        },
        dest_state: ChainState {
            balances: HashMap::from([("__minted__".into(), dest_minted.to_string())]),
            storage: dest_storage,
            block_number: 1,
            timestamp: 1,
        },
        relay_state: RelaySnapshot {
            pending_messages: vec![],
            processed_set: vec![],
            mode: "faithful".into(),
            message_count: 0,
        },
    }
}

/// Semantic waypoints satisfied by `state` for reward $R(\sigma)$ (paper Alg. 1).
/// Uses scenario-specific rules for mock fixtures; unknown predicates return false.
pub fn evaluate_waypoints(state: &GlobalState, scenario: &Scenario) -> Vec<String> {
    let steps = scenario.actions.len() as u32;
    let mut out = Vec::new();
    for wp in &scenario.waypoints {
        if wp.after_step > steps {
            continue;
        }
        if waypoint_predicate_holds(state, scenario, wp) {
            out.push(wp.waypoint_id.clone());
        }
    }
    out
}

fn waypoint_predicate_holds(state: &GlobalState, _scenario: &Scenario, wp: &Waypoint) -> bool {
    let pred = wp.predicate.as_str();
    let minted = u128_balance(&state.dest_state, "__minted__");
    let locked = u128_balance(&state.source_state, "__locked__");

    if pred.contains("acceptableRoot") {
        return dest_flag(state, "replica", "zero_root_accepted");
    }
    if pred.contains("totalMinted") && pred.contains("totalLocked") {
        return minted > locked;
    }

    if pred.contains("zero_root") || pred.contains("bytes32(0)") {
        return dest_flag(state, "replica", "zero_root_accepted");
    }
    if pred.contains("totalMinted") && (pred.contains("totalLocked") || pred.contains("deposits")) {
        return minted > locked;
    }
    false
}

fn u128_balance(chain: &ChainState, key: &str) -> u128 {
    chain
        .balances
        .get(key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn dest_flag(state: &GlobalState, contract: &str, slot: &str) -> bool {
    state
        .dest_state
        .storage
        .get(contract)
        .and_then(|m| m.get(slot))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

fn insert_slot(
    dest: &mut HashMap<String, HashMap<String, String>>,
    contract: &str,
    slot: &str,
    val: &str,
) {
    dest
        .entry(contract.into())
        .or_default()
        .insert(slot.into(), val.into());
}

fn amount_from_action(action: &crate::types::Action) -> u128 {
    if let Some(v) = action.params.get("amount") {
        return json_to_u128(v);
    }
    0
}

fn normalized_operation(action: &crate::types::Action) -> String {
    if let Some(raw) = action.function.as_deref() {
        return normalize_op(raw);
    }
    if let Some(raw) = action.action.as_deref() {
        return normalize_op(raw);
    }
    String::new()
}

fn normalize_op(raw: &str) -> String {
    raw.split('(')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase()
}

fn json_to_u128(v: &serde_json::Value) -> u128 {
    match v {
        serde_json::Value::String(s) => s.parse().unwrap_or(0),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0) as u128,
        _ => 0,
    }
}

fn is_all_zero_hex_message(s: &str) -> bool {
    let s = s.strip_prefix("0x").unwrap_or(s);
    !s.is_empty() && s.chars().all(|c| c == '0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn load_fixture(id: &str) -> Scenario {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/hypotheses_mock.json");
        let text = std::fs::read_to_string(&path).unwrap();
        let hypo: crate::types::HypothesesFile = serde_json::from_str(&text).unwrap();
        hypo.scenarios
            .into_iter()
            .find(|s| s.scenario_id == id)
            .unwrap()
    }

    #[test]
    fn zero_root_scenario_sets_flag() {
        let s = load_fixture("s1_zero_root_bypass");
        let g = global_state_from_scenario(&s);
        assert!(
            g.dest_state
                .storage
                .get("replica")
                .and_then(|m| m.get("zero_root_accepted"))
                == Some(&"true".to_string())
        );
    }

    #[test]
    fn replay_scenario_mints_more_than_locked() {
        let s = load_fixture("s2_replay_attack");
        let g = global_state_from_scenario(&s);
        let locked: u128 = g.source_state.balances["__locked__"].parse().unwrap();
        let minted: u128 = g.dest_state.balances["__minted__"].parse().unwrap();
        assert_eq!(locked, 1_000_000_000_000_000_000);
        assert_eq!(minted, 2_000_000_000_000_000_000);
    }

    #[test]
    fn evaluate_waypoints_s1_fixture() {
        let s = load_fixture("s1_zero_root_bypass");
        let g = global_state_from_scenario(&s);
        let w = evaluate_waypoints(&g, &s);
        assert!(w.contains(&"w1".to_string()));
        assert!(w.contains(&"w2".to_string()));
    }

    #[test]
    fn evaluate_waypoints_s2_fixture() {
        let s = load_fixture("s2_replay_attack");
        let g = global_state_from_scenario(&s);
        let w = evaluate_waypoints(&g, &s);
        assert!(w.contains(&"w1".to_string()));
        assert!(w.contains(&"w2".to_string()));
    }
}
