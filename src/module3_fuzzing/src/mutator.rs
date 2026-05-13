//! ATG-Aware Mutation Operator
//!
//! Two mutation surfaces live here:
//! 1. **`Mutator`** — legacy scenario-level mutator that rewrites the JSON
//!    representation of an attack `Scenario` (reorder, boundary substitution,
//!    relay-mode switch, adjacent-action insertion). Used by the simulator
//!    code path; will be retired in Phase A4.
//! 2. **`CalldataMutator`** — Phase A3, the calldata-level mutator. Operates
//!    directly on `Vec<u8>` calldata blobs targeting deployed contracts so
//!    revm's interpreter actually executes the bytecode. Mutations:
//!    bit/byte-flip, integer-boundary substitution at random 32-byte words,
//!    function-selector swap from the registry's known selectors, and
//!    seed concatenation. ATG-aware: prefers selectors from edges that
//!    have not been touched yet.

use std::collections::{HashMap, HashSet};

use rand::rngs::StdRng;
use rand::Rng;
use revm::primitives::Address;

use crate::contract_loader::{ChainSide, ContractRegistry};
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

// ============================================================================
// CalldataMutator — Phase A3: byte-level mutation against real bytecode
// ============================================================================

/// One fuzzer input: calldata bytes + the address (and chain side) the call
/// is meant to land on. Carries the originating `Action` for trace
/// reconstruction in violation reports.
#[derive(Clone, Debug)]
pub struct CalldataSeed {
    pub calldata: Vec<u8>,
    pub target: Address,
    pub chain: ChainSide,
    pub source_action: Option<Action>,
}

impl CalldataSeed {
    pub fn selector(&self) -> Option<[u8; 4]> {
        if self.calldata.len() < 4 {
            return None;
        }
        let mut s = [0u8; 4];
        s.copy_from_slice(&self.calldata[..4]);
        Some(s)
    }
}

/// Boundary words used by the integer-boundary mutator — aligned to 32 bytes.
const BOUNDARY_U256: &[[u8; 32]] = &[
    [0u8; 32], // 0
    {
        let mut x = [0u8; 32];
        x[31] = 1;
        x
    }, // 1
    [0xff; 32], // 2^256-1 (MAX_UINT)
    {
        let mut x = [0xff; 32];
        x[0] = 0x7f;
        x
    }, // INT256_MAX
];

/// Calldata-level fuzzer mutation engine. Stateless, threading-friendly:
/// callers own the RNG.
#[derive(Clone, Debug, Default)]
pub struct CalldataMutator {
    /// Every selector we've seen in the ATG (from edges) — the universe of
    /// candidates for selector-swap mutation.
    known_selectors: Vec<[u8; 4]>,
    /// Selectors that have already been exercised; used to bias toward
    /// untouched paths. Caller updates this set as fuzzing progresses.
    pub touched_selectors: HashSet<[u8; 4]>,
    /// node_id -> adjacent node_ids (forward edges only).
    adjacency: HashMap<String, Vec<String>>,
}

impl CalldataMutator {
    /// Build the mutator from an ATG and its derived registry. Selectors are
    /// gathered from every node's inbound edges (registry's `selectors_of`).
    pub fn from_registry(reg: &ContractRegistry, atg: &AtgGraph) -> Self {
        let mut known = HashSet::new();
        for node in &atg.nodes {
            for sel in reg.selectors_of(&node.node_id) {
                known.insert(*sel);
            }
        }
        let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
        for edge in &atg.edges {
            adjacency
                .entry(edge.src.clone())
                .or_default()
                .push(edge.dst.clone());
        }
        Self {
            known_selectors: known.into_iter().collect(),
            touched_selectors: HashSet::new(),
            adjacency,
        }
    }

    pub fn known_selectors(&self) -> &[[u8; 4]] {
        &self.known_selectors
    }

    /// Encode an `Action` from a Module-2 scenario into a `CalldataSeed`.
    /// Best-effort ABI encoding: `selector || zero-padded params (32 bytes
    /// each)`. Only static types we can recognise (uint, address, bytes32,
    /// bool) are folded in; unknown params land as 32-byte zero words. The
    /// fuzz loop relies on later mutations to populate them with realistic
    /// values; even invalid ABI is acceptable input — the contract simply
    /// reverts and the iteration is logged.
    pub fn encode_action(
        &self,
        action: &Action,
        registry: &ContractRegistry,
    ) -> Option<CalldataSeed> {
        let node_id = action.contract.as_deref()?;
        let target = registry.address_of(node_id)?;
        // Prefer the action's own `chain` field (Module-2 LLM scenarios are
        // explicit about source vs destination). The registry's `chain_of`
        // can be wrong when the ATG has duplicate node_ids with conflicting
        // chains (LLM artefacts). Fall back to registry only when the
        // action's chain is missing/blank.
        let chain = ChainSide::from_atg(action.chain.as_str());
        let chain = if matches!(chain, ChainSide::Relay) {
            registry.chain_of(node_id).unwrap_or(ChainSide::Relay)
        } else {
            chain
        };

        // Resolve selector: prefer the action's own function signature, then
        // any registry signature attached to the receiver.
        let selector = if let Some(fn_sig) = action.function.as_deref() {
            let canonical = crate::contract_loader::canonical_signature(fn_sig);
            if !canonical.is_empty() {
                crate::contract_loader::function_selector(&canonical)
            } else {
                *registry.selectors_of(node_id).first()?
            }
        } else {
            *registry.selectors_of(node_id).first()?
        };

        let params_blob = encode_params_blob(&action.params);
        let mut calldata = Vec::with_capacity(4 + params_blob.len());
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&params_blob);

        Some(CalldataSeed {
            calldata,
            target,
            chain,
            source_action: Some(action.clone()),
        })
    }

    /// Apply one random mutation operator to `bytes`, returning a fresh
    /// vector. The mutator is byte-level — it does not preserve ABI
    /// validity; that is intentional (fuzzers want malformed inputs too).
    pub fn mutate(&self, bytes: &[u8], rng: &mut StdRng) -> Vec<u8> {
        if bytes.is_empty() {
            return bytes.to_vec();
        }
        let strategy = rng.gen_range(0..5u8);
        match strategy {
            0 => self.flip_random_bit(bytes, rng),
            1 => self.replace_word_with_boundary(bytes, rng),
            2 => self.swap_selector(bytes, rng),
            3 => self.replace_address_word(bytes, rng),
            _ => self.flip_random_byte(bytes, rng),
        }
    }

    fn flip_random_bit(&self, bytes: &[u8], rng: &mut StdRng) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let i = rng.gen_range(0..out.len());
        let bit = rng.gen_range(0..8u8);
        out[i] ^= 1 << bit;
        out
    }

    fn flip_random_byte(&self, bytes: &[u8], rng: &mut StdRng) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let i = rng.gen_range(0..out.len());
        out[i] = rng.gen();
        out
    }

    /// Pick a random 32-byte word offset (after the 4-byte selector) and
    /// overwrite it with a boundary value (0, 1, MAX_UINT, INT_MAX).
    fn replace_word_with_boundary(&self, bytes: &[u8], rng: &mut StdRng) -> Vec<u8> {
        let mut out = bytes.to_vec();
        if out.len() < 4 + 32 {
            // No params word to replace — flip a byte instead.
            return self.flip_random_byte(bytes, rng);
        }
        let n_words = (out.len() - 4) / 32;
        let widx = rng.gen_range(0..n_words);
        let boundary = BOUNDARY_U256[rng.gen_range(0..BOUNDARY_U256.len())];
        let off = 4 + widx * 32;
        out[off..off + 32].copy_from_slice(&boundary);
        out
    }

    /// Replace the 4-byte selector with a different known selector.
    fn swap_selector(&self, bytes: &[u8], rng: &mut StdRng) -> Vec<u8> {
        let mut out = bytes.to_vec();
        if self.known_selectors.is_empty() || out.len() < 4 {
            return out;
        }
        let current_sel = {
            let mut s = [0u8; 4];
            s.copy_from_slice(&out[..4]);
            s
        };
        // Prefer untouched selectors, else any selector that differs from current.
        let candidates: Vec<&[u8; 4]> = if !self.touched_selectors.is_empty() {
            self.known_selectors
                .iter()
                .filter(|s| **s != current_sel && !self.touched_selectors.contains(*s))
                .collect()
        } else {
            self.known_selectors
                .iter()
                .filter(|s| **s != current_sel)
                .collect()
        };
        let pool = if candidates.is_empty() {
            self.known_selectors.iter().collect::<Vec<_>>()
        } else {
            candidates
        };
        if pool.is_empty() {
            return out;
        }
        let chosen = pool[rng.gen_range(0..pool.len())];
        out[..4].copy_from_slice(chosen);
        out
    }

    /// Substitute a random 32-byte word with the right-aligned encoding of a
    /// random 20-byte address (the rest of the word is zero, matching ABI).
    fn replace_address_word(&self, bytes: &[u8], rng: &mut StdRng) -> Vec<u8> {
        let mut out = bytes.to_vec();
        if out.len() < 4 + 32 {
            return self.flip_random_byte(bytes, rng);
        }
        let n_words = (out.len() - 4) / 32;
        let widx = rng.gen_range(0..n_words);
        let off = 4 + widx * 32;
        // Zero the upper 12 bytes, fill last 20 with random.
        out[off..off + 12].fill(0);
        for b in &mut out[off + 12..off + 32] {
            *b = rng.gen();
        }
        out
    }

    /// Concatenate two calldata seeds. Currently unused by the fuzz loop
    /// (single-tx model), but exposed for future multi-call scenarios.
    pub fn concat_seeds(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(a.len() + b.len());
        out.extend_from_slice(a);
        out.extend_from_slice(b);
        out
    }
}

/// Encode `action.params` into a tight 32-byte-per-arg blob. Best-effort:
/// recognises uints, hex-prefixed bytes/addresses, and booleans; unknowns
/// land as 32-byte zero words. Maintains insertion order — callers must rely
/// on the LLM/scenario keeping arg order canonical.
fn encode_params_blob(params: &HashMap<String, serde_json::Value>) -> Vec<u8> {
    let mut blob = Vec::with_capacity(params.len() * 32);
    for value in params.values() {
        let mut word = [0u8; 32];
        if let Some(s) = value.as_str() {
            let trimmed = s.trim_start_matches("0x");
            if let Ok(decoded) = hex::decode(trimmed) {
                let take = decoded.len().min(32);
                // Right-align (matches ABI uint/address encoding for length <= 32).
                let pad = 32 - take;
                word[pad..].copy_from_slice(&decoded[..take]);
            } else if let Ok(n) = s.parse::<u128>() {
                word[16..].copy_from_slice(&n.to_be_bytes());
            }
        } else if let Some(n) = value.as_u64() {
            word[24..].copy_from_slice(&n.to_be_bytes());
        } else if let Some(b) = value.as_bool() {
            word[31] = u8::from(b);
        }
        blob.extend_from_slice(&word);
    }
    blob
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

        let parsed: Scenario =
            serde_json::from_slice(&mutated).expect("mutated scenario parseable");
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

    // ========================================================================
    // CalldataMutator (Phase A3) tests
    // ========================================================================

    use rand::SeedableRng;

    fn fixture_atg() -> AtgGraph {
        let text = std::fs::read_to_string(fixture_path("atg_mock.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn calldata_mutator_collects_selectors_from_atg() {
        let atg = fixture_atg();
        let reg = ContractRegistry::from_atg(&atg);
        let mutator = CalldataMutator::from_registry(&reg, &atg);

        // ATG fixture has 4 distinct edge signatures (e1, e3, e4, e5; e2 is empty).
        assert_eq!(mutator.known_selectors().len(), 4);
        let dispatch_sel =
            crate::contract_loader::function_selector("dispatch(uint32,bytes32,uint256,bytes)");
        assert!(mutator.known_selectors().contains(&dispatch_sel));
    }

    /// Acceptance test for A3 (per plan):
    /// "verify selector mutation chuyển từ lock(...) selector sang
    ///  unlock(...) selector đúng."
    /// Adapted to fixture: dispatch -> proveAndProcess (both in known set).
    #[test]
    fn swap_selector_replaces_with_a_different_known_selector() {
        let atg = fixture_atg();
        let reg = ContractRegistry::from_atg(&atg);
        let mutator = CalldataMutator::from_registry(&reg, &atg);

        let dispatch_sel =
            crate::contract_loader::function_selector("dispatch(uint32,bytes32,uint256,bytes)");
        let mut seed = Vec::with_capacity(36);
        seed.extend_from_slice(&dispatch_sel);
        seed.extend_from_slice(&[0u8; 32]);

        let mut rng = StdRng::seed_from_u64(42);
        // Run the swap several times — every output must:
        //   (a) keep the params blob unchanged
        //   (b) replace the selector with one that exists in the ATG
        //   (c) differ from the input selector (when alternatives exist).
        for _ in 0..32 {
            let mutated = mutator.swap_selector(&seed, &mut rng);
            assert_eq!(mutated.len(), seed.len(), "length preserved");
            assert_eq!(&mutated[4..], &seed[4..], "params blob untouched");
            let mut new_sel = [0u8; 4];
            new_sel.copy_from_slice(&mutated[..4]);
            assert!(
                mutator.known_selectors().contains(&new_sel),
                "swap must yield a selector from the ATG-known set"
            );
            assert_ne!(new_sel, dispatch_sel, "swap must change the selector");
        }
    }

    #[test]
    fn boundary_mutation_writes_exact_32_byte_word() {
        let atg = fixture_atg();
        let reg = ContractRegistry::from_atg(&atg);
        let mutator = CalldataMutator::from_registry(&reg, &atg);

        // selector + 2 param words of 0x55.
        let mut seed = vec![0x12, 0x34, 0x56, 0x78];
        seed.extend_from_slice(&[0x55; 64]);

        let mut rng = StdRng::seed_from_u64(7);
        let mutated = mutator.replace_word_with_boundary(&seed, &mut rng);
        assert_eq!(mutated.len(), seed.len());
        // Selector preserved.
        assert_eq!(&mutated[..4], &seed[..4]);
        // At least one of the two 32-byte param words must be a boundary.
        let w1 = &mutated[4..36];
        let w2 = &mutated[36..68];
        let is_boundary = |w: &[u8]| BOUNDARY_U256.iter().any(|b| b.as_slice() == w);
        assert!(
            is_boundary(w1) || is_boundary(w2),
            "at least one word should be a boundary value"
        );
    }

    #[test]
    fn encode_action_produces_selector_plus_params_blob() {
        let atg = fixture_atg();
        let reg = ContractRegistry::from_atg(&atg);
        let mutator = CalldataMutator::from_registry(&reg, &atg);

        let mut params = HashMap::new();
        params.insert("amount".to_string(), serde_json::json!(1000u64));

        let action = Action {
            step: 1,
            chain: "destination".to_string(),
            contract: Some("replica".to_string()),
            function: Some("proveAndProcess(bytes,bytes,uint256)".to_string()),
            action: None,
            params,
            description: "encode test".to_string(),
        };

        let seed = mutator
            .encode_action(&action, &reg)
            .expect("encode succeeds");
        assert_eq!(seed.calldata.len(), 4 + 32);
        let want_sel =
            crate::contract_loader::function_selector("proveAndProcess(bytes,bytes,uint256)");
        assert_eq!(&seed.calldata[..4], &want_sel);
        // amount=1000 sits at the bottom of the right-aligned u64 slot.
        let mut expected_word = [0u8; 32];
        expected_word[24..].copy_from_slice(&1000u64.to_be_bytes());
        assert_eq!(&seed.calldata[4..], &expected_word);
        assert_eq!(seed.chain, ChainSide::Destination);
    }

    #[test]
    fn atg_adjacency_inserts_followup_action() {
        let atg_text =
            std::fs::read_to_string(fixture_path("atg_mock.json")).expect("read atg fixture");
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

        assert!(
            parsed.actions.len() >= 2,
            "expected adjacent action insertion"
        );
    }
}
