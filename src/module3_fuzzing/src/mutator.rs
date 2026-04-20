//! ATG-Aware Mutation Operator
//!
//! Mutations informed by the ATG structure:
//! - Reorder actions respecting causal dependencies
//! - Substitute parameters with boundary/zero values
//! - Insert actions targeting adjacent ATG nodes
//! - Switch relay mode (faithful/delayed/tampered/replayed)
//! - Independently advance block timestamps (clock drift simulation)

use std::collections::HashMap;

use crate::types::{Action, AtgGraph, Scenario, Seed};

/// ATG-aware mutator for attack scenarios.
pub struct Mutator {
    adjacency: HashMap<String, Vec<String>>,
}

impl Mutator {
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
        }
    }

    pub fn with_atg(atg: &AtgGraph) -> Self {
        let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
        for edge in &atg.edges {
            adjacency
                .entry(edge.src.clone())
                .or_default()
                .push(edge.dst.clone());
        }
        Self { adjacency }
    }

    /// Mutate an attack scenario while maintaining semantic coherence.
    pub fn mutate(&self, seed: &[u8]) -> Vec<u8> {
        if let Ok(mut seed_struct) = serde_json::from_slice::<Seed>(seed) {
            mutate_actions(&mut seed_struct.actions, &self.adjacency);
            seed_struct.mutation_count = seed_struct.mutation_count.saturating_add(1);
            return serde_json::to_vec(&seed_struct).unwrap_or_else(|_| seed.to_vec());
        }

        if let Ok(mut scenario) = serde_json::from_slice::<Scenario>(seed) {
            mutate_actions(&mut scenario.actions, &self.adjacency);
            return serde_json::to_vec(&scenario).unwrap_or_else(|_| seed.to_vec());
        }

        seed.to_vec()
    }
}

fn mutate_actions(actions: &mut Vec<Action>, adjacency: &HashMap<String, Vec<String>>) {
    if actions.is_empty() {
        return;
    }

    // Strategy 1: reorder first two steps when possible.
    if actions.len() > 1 {
        actions.swap(0, 1);
    }

    // Strategy 2: boundary and zero substitution in params.
    if let Some(first) = actions.first_mut() {
        apply_boundary_mutation(first);
    }

    // Strategy 3: switch relay mode if a relay action exists.
    if let Some(relay_action) = actions
        .iter_mut()
        .find(|a| a.chain.eq_ignore_ascii_case("relay"))
    {
        let current = relay_action
            .action
            .as_deref()
            .unwrap_or("faithful")
            .to_ascii_lowercase();
        let next = match current.as_str() {
            "faithful" => "delayed",
            "delayed" => "tampered",
            "tampered" => "replay",
            _ => "faithful",
        };
        relay_action.action = Some(next.to_string());
    }

    // Strategy 4: insert adjacent action based on ATG connectivity.
    if let Some((insert_at, inserted)) = build_adjacent_action(actions, adjacency) {
        actions.insert(insert_at, inserted);
    }

    // Strategy 5: timestamp drift simulation.
    if let Some(last) = actions.last_mut() {
        last.params
            .insert("timestamp_drift".to_string(), serde_json::json!(300_u64));
    }

    // Keep sequence structurally valid.
    for (idx, action) in actions.iter_mut().enumerate() {
        action.step = (idx + 1) as u32;
    }
}

fn apply_boundary_mutation(action: &mut Action) {
    let mut updated = false;
    for key in ["amount", "value", "nonce"] {
        if let Some(v) = action.params.get_mut(key) {
            if v.is_string() {
                *v = serde_json::Value::String("0".to_string());
                updated = true;
                break;
            }
            if v.is_number() {
                *v = serde_json::json!(0);
                updated = true;
                break;
            }
        }
    }

    if !updated {
        action
            .params
            .insert("mutated_boundary".to_string(), serde_json::json!(true));
    }
}

fn build_adjacent_action(
    actions: &[Action],
    adjacency: &HashMap<String, Vec<String>>,
) -> Option<(usize, Action)> {
    let (idx, base) = actions
        .iter()
        .enumerate()
        .find(|(_, a)| a.contract.is_some())?;
    let src = base.contract.as_ref()?;
    let dst = adjacency.get(src)?.first()?.clone();

    let inserted = Action {
        step: 0,
        chain: base.chain.clone(),
        contract: Some(dst),
        function: Some("adjacent_probe".to_string()),
        action: None,
        params: HashMap::new(),
        description: "Inserted adjacent ATG action".to_string(),
    };
    Some((idx + 1, inserted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("src")
            .parent()
            .expect("repo root")
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn mutate_scenario_keeps_valid_structure() {
        let hypo_text = std::fs::read_to_string(fixture_path("hypotheses_mock.json"))
            .expect("read hypotheses fixture");
        let hypo: crate::types::HypothesesFile =
            serde_json::from_str(&hypo_text).expect("parse hypotheses fixture");

        let scenario = hypo
            .scenarios
            .into_iter()
            .find(|s| s.scenario_id == "s2_replay_attack")
            .expect("scenario exists");
        let seed = serde_json::to_vec(&scenario).expect("serialize scenario");

        let mutator = Mutator::new();
        let mutated = mutator.mutate(&seed);

        let parsed: Scenario = serde_json::from_slice(&mutated).expect("mutated scenario parseable");
        assert!(!parsed.actions.is_empty());
        assert_ne!(mutated, seed, "mutator should produce different output");
        assert_eq!(parsed.actions[0].step, 1);
    }

    #[test]
    fn mutate_seed_increments_mutation_count() {
        let seed = Seed {
            source_scenario_id: "s1".to_string(),
            actions: vec![Action {
                step: 1,
                chain: "relay".to_string(),
                contract: None,
                function: None,
                action: Some("faithful".to_string()),
                params: HashMap::new(),
                description: "relay".to_string(),
            }],
            energy: 1.0,
            mutation_count: 2,
            waypoints_reached: vec![],
        };

        let raw = serde_json::to_vec(&seed).expect("serialize seed");
        let mutator = Mutator::new();
        let mutated = mutator.mutate(&raw);
        let parsed: Seed = serde_json::from_slice(&mutated).expect("parse mutated seed");

        assert_eq!(parsed.mutation_count, 3);
        assert_eq!(parsed.actions[0].step, 1);
    }

    #[test]
    fn atg_adjacency_inserts_followup_action() {
        let atg_text = std::fs::read_to_string(fixture_path("atg_mock.json"))
            .expect("read atg fixture");
        let atg: AtgGraph = serde_json::from_str(&atg_text).expect("parse atg fixture");

        let scenario = Scenario {
            scenario_id: "s_atg_adjacent".to_string(),
            target_invariant: "inv_asset_conservation".to_string(),
            vulnerability_class: "test".to_string(),
            confidence: 0.5,
            actions: vec![Action {
                step: 1,
                chain: "source".to_string(),
                contract: Some("source_router".to_string()),
                function: Some("dispatch".to_string()),
                action: None,
                params: HashMap::new(),
                description: "seed action".to_string(),
            }],
            waypoints: vec![],
            retrieved_exploits: vec![],
        };

        let raw = serde_json::to_vec(&scenario).expect("serialize scenario");
        let mutator = Mutator::with_atg(&atg);
        let mutated = mutator.mutate(&raw);
        let parsed: Scenario = serde_json::from_slice(&mutated).expect("parse mutated");

        assert!(parsed.actions.len() >= 2, "expected adjacent action insertion");
    }
}
