//! Shared Types for BridgeSentry Fuzzing Engine
//!
//! Central type definitions used across all modules:
//! - ATG (Asset Transfer Graph) types — deserialized from Module 1 output
//! - Hypothesis/Scenario types — deserialized from Module 2 output
//! - Execution types — internal state during fuzzing
//! - Result types — serialized as final output
//! - Config types — CLI and runtime configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Chain Identification
// ============================================================================

/// Identifies which chain a component belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainId {
    Source,
    Destination,
    #[serde(alias = "offchain")]
    Relay,
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainId::Source => write!(f, "source"),
            ChainId::Destination => write!(f, "destination"),
            ChainId::Relay => write!(f, "relay"),
        }
    }
}

// ============================================================================
// ATG Types — Deserialized from atg.json (Module 1 → Module 2 + Module 3)
// ============================================================================

/// Root structure of the Asset Transfer Graph.
/// Produced by Module 1 (Semantic Extraction), consumed by Module 2 (RAG) and Module 3 (Fuzzer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtgGraph {
    pub bridge_name: String,
    pub version: String,
    pub nodes: Vec<AtgNode>,
    pub edges: Vec<AtgEdge>,
    pub invariants: Vec<Invariant>,
}

/// A node in the ATG — represents a contract, user, or relay component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtgNode {
    pub node_id: String,
    pub node_type: String,
    pub chain: String,
    pub address: String,
    pub functions: Vec<String>,
}

/// A directed edge in the ATG — represents an asset transfer or message flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtgEdge {
    pub edge_id: String,
    pub src: String,
    pub dst: String,
    pub label: String,
    pub token: String,
    pub conditions: Vec<String>,
    pub function_signature: String,
}

/// A protocol invariant that should hold across the bridge.
/// Categories: asset_conservation, authorization, uniqueness, timeliness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub invariant_id: String,
    pub category: String,
    pub description: String,
    pub predicate: String,
    pub solidity_assertion: String,
    pub related_edges: Vec<String>,
}

// ============================================================================
// Hypothesis Types — Deserialized from hypotheses.json (Module 2 → Module 3)
// ============================================================================

/// Root structure of attack hypotheses file.
/// Produced by Module 2 (RAG Scenario Generation), consumed by Module 3 (Fuzzer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesesFile {
    pub bridge_name: String,
    pub scenarios: Vec<Scenario>,
}

/// A single attack scenario with action sequence and waypoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub scenario_id: String,
    pub target_invariant: String,
    pub vulnerability_class: String,
    pub confidence: f64,
    pub actions: Vec<Action>,
    pub waypoints: Vec<Waypoint>,
    pub retrieved_exploits: Vec<String>,
}

/// A single step in an attack scenario.
/// Can target a contract (with function call) or the relay (with action mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub step: u32,
    pub chain: String,
    /// Contract node_id — present when targeting a contract
    #[serde(default)]
    pub contract: Option<String>,
    /// Function to call on the contract
    #[serde(default)]
    pub function: Option<String>,
    /// Relay action mode (faithful, tamper, replay, delay) — present when targeting relay
    #[serde(default)]
    pub action: Option<String>,
    /// Parameters for the call or relay action
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
    pub description: String,
}

/// A checkpoint predicate that should become true during scenario execution.
/// Used by the reward function to guide the fuzzer toward deeper exploration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Waypoint {
    pub waypoint_id: String,
    pub after_step: u32,
    pub predicate: String,
    pub description: String,
}

// ============================================================================
// Execution Types — Internal fuzzer state
// ============================================================================

/// Result of executing a single transaction on one chain's EVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    /// Whether the transaction succeeded (did not revert)
    pub success: bool,
    /// Gas consumed by the transaction
    pub gas_used: u64,
    /// Return data (ABI-encoded bytes)
    pub output: Vec<u8>,
    /// Event log entries emitted during execution
    pub logs: Vec<LogEntry>,
    /// State changes caused by this transaction
    pub state_changes: Vec<StateChange>,
}

/// A single event log entry emitted by a contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

/// A single storage slot change caused by a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub address: String,
    pub slot: String,
    pub old_value: String,
    pub new_value: String,
}

/// Combined global state snapshot from both EVMs + relay.
/// GlobalSnapshot = (S_source, S_dest, S_relay)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalState {
    /// Balances and storage on the source chain
    pub source_state: ChainState,
    /// Balances and storage on the destination chain
    pub dest_state: ChainState,
    /// Relay internal state (message queue, processed set)
    pub relay_state: RelaySnapshot,
}

/// State of a single EVM chain — storage slots and balances for tracked addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Address → balance (in wei)
    pub balances: HashMap<String, String>,
    /// Address → (slot → value) storage mapping
    pub storage: HashMap<String, HashMap<String, String>>,
    /// Current block number
    pub block_number: u64,
    /// Current block timestamp
    pub timestamp: u64,
}

/// Serializable relay state for snapshot capture/restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySnapshot {
    /// Messages waiting to be relayed
    pub pending_messages: Vec<RelayMessage>,
    /// Nonces/hashes of already-processed messages
    pub processed_set: Vec<String>,
    /// Current relay mode
    pub mode: String,
    /// Message counter
    pub message_count: u64,
}

/// A cross-chain message in the relay queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMessage {
    pub nonce: u64,
    pub source_chain: String,
    pub dest_chain: String,
    pub sender: String,
    pub recipient: String,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

// ============================================================================
// Seed / Corpus Types — Fuzzer input representation
// ============================================================================

/// A fuzzer seed — a sequence of actions to execute, derived from a scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seed {
    /// The scenario this seed was derived from
    pub source_scenario_id: String,
    /// Ordered list of actions to execute
    pub actions: Vec<Action>,
    /// Energy (priority) for power scheduling
    pub energy: f64,
    /// Number of mutations applied to this seed
    pub mutation_count: u32,
    /// Waypoints reached by this seed in previous execution
    pub waypoints_reached: Vec<String>,
}

// ============================================================================
// Result Types — Serialized as results.json (Module 3 → Output)
// ============================================================================

/// Root structure of fuzzing results.
/// Produced by Module 3 (Fuzzer), consumed by Orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingResults {
    pub bridge_name: String,
    pub run_id: u32,
    pub time_budget_s: u64,
    pub violations: Vec<Violation>,
    pub coverage: Coverage,
    pub stats: FuzzingStats,
}

/// A detected invariant violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub invariant_id: String,
    pub detected_at_s: f64,
    pub trigger_scenario: String,
    pub trigger_trace: Vec<String>,
    pub state_diff: HashMap<String, String>,
}

/// Coverage metrics from the fuzzing run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    /// Fraction of ATG edges exercised (cross-chain coverage)
    pub xcc_atg: f64,
    /// Number of basic blocks covered on source chain
    pub basic_blocks_source: u64,
    /// Number of basic blocks covered on destination chain
    pub basic_blocks_dest: u64,
}

/// Aggregate statistics from the fuzzing run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingStats {
    pub total_iterations: u64,
    pub snapshots_captured: u64,
    pub mutations_applied: u64,
}

// ============================================================================
// Config Types — Runtime configuration
// ============================================================================

/// Fuzzer runtime configuration, parsed from CLI args + JSON config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    /// Path to ATG JSON file (from Module 1)
    pub atg_path: String,
    /// Path to hypotheses JSON file (from Module 2)
    pub scenarios_path: String,
    /// Path to write results JSON
    pub output_path: String,
    /// Time budget in seconds
    pub time_budget_s: u64,
    /// RPC URL for source chain fork
    pub source_rpc: String,
    /// RPC URL for destination chain fork
    pub dest_rpc: String,
    /// Block number to fork source chain at
    pub source_block: u64,
    /// Block number to fork destination chain at
    pub dest_block: u64,
    /// Number of fuzzing runs
    #[serde(default = "default_runs")]
    pub runs: u32,
    /// Reward function weight for coverage
    #[serde(default = "default_alpha")]
    pub alpha: f64,
    /// Reward function weight for waypoints
    #[serde(default = "default_beta")]
    pub beta: f64,
    /// Reward function weight for invariant distance
    #[serde(default = "default_gamma")]
    pub gamma: f64,
    /// Random seed for reproducibility
    #[serde(default)]
    pub random_seed: Option<u64>,
}

fn default_runs() -> u32 { 1 }
fn default_alpha() -> f64 { 0.3 }
fn default_beta() -> f64 { 0.4 }
fn default_gamma() -> f64 { 0.3 }

// ============================================================================
// Invariant check result (used by checker.rs)
// ============================================================================

/// Result of checking a single invariant against the current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Whether the invariant was violated
    pub violated: bool,
    /// ID of the invariant checked
    pub invariant_id: String,
    /// Human-readable description of the violation (if any)
    pub description: Option<String>,
    /// Transaction hashes that contributed to this check
    pub trace: Vec<String>,
    /// Numerical distance to violation (0.0 = violated, higher = further from violation)
    pub distance: f64,
}

// ============================================================================
// Tests — Validate serde round-trip with mock fixtures
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()  // src/
            .parent().unwrap()  // project root
            .join("tests")
            .join("fixtures")
    }

    #[test]
    fn test_deserialize_atg_mock() {
        let path = fixtures_dir().join("atg_mock.json");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let atg: AtgGraph = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse ATG: {}", e));

        assert_eq!(atg.bridge_name, "nomad");
        assert_eq!(atg.version, "1.0");
        assert_eq!(atg.nodes.len(), 6, "Expected 6 nodes in Nomad ATG");
        assert_eq!(atg.edges.len(), 5, "Expected 5 edges in Nomad ATG");
        assert_eq!(atg.invariants.len(), 4, "Expected 4 invariants in Nomad ATG");

        // Verify specific invariant categories
        let categories: Vec<&str> = atg.invariants.iter().map(|i| i.category.as_str()).collect();
        assert!(categories.contains(&"asset_conservation"));
        assert!(categories.contains(&"authorization"));
        assert!(categories.contains(&"uniqueness"));
    }

    #[test]
    fn test_deserialize_hypotheses_mock() {
        let path = fixtures_dir().join("hypotheses_mock.json");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        let hypo: HypothesesFile = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse hypotheses: {}", e));

        assert_eq!(hypo.bridge_name, "nomad");
        assert_eq!(hypo.scenarios.len(), 2, "Expected 2 scenarios");

        // Verify scenario 1: zero root bypass
        let s1 = &hypo.scenarios[0];
        assert_eq!(s1.scenario_id, "s1_zero_root_bypass");
        assert_eq!(s1.vulnerability_class, "fake_deposit");
        assert_eq!(s1.actions.len(), 2);
        assert_eq!(s1.waypoints.len(), 2);

        // Verify scenario 2: replay attack
        let s2 = &hypo.scenarios[1];
        assert_eq!(s2.scenario_id, "s2_replay_attack");
        assert_eq!(s2.vulnerability_class, "replay");
        assert_eq!(s2.actions.len(), 5);
        assert!(s2.retrieved_exploits.contains(&"nomad_2022".to_string()));
    }

    #[test]
    fn test_serialize_fuzzing_results() {
        let results = FuzzingResults {
            bridge_name: "nomad".to_string(),
            run_id: 1,
            time_budget_s: 600,
            violations: vec![Violation {
                invariant_id: "inv_asset_conservation".to_string(),
                detected_at_s: 11.3,
                trigger_scenario: "s1_zero_root_bypass".to_string(),
                trigger_trace: vec!["tx1".to_string(), "tx2".to_string()],
                state_diff: HashMap::from([
                    ("source_locked".to_string(), "1000000000000000000".to_string()),
                    ("dest_minted".to_string(), "999000000000000000000".to_string()),
                ]),
            }],
            coverage: Coverage {
                xcc_atg: 0.78,
                basic_blocks_source: 1234,
                basic_blocks_dest: 987,
            },
            stats: FuzzingStats {
                total_iterations: 15234,
                snapshots_captured: 47,
                mutations_applied: 14890,
            },
        };

        // Verify serialization round-trip
        let json = serde_json::to_string_pretty(&results).expect("Failed to serialize");
        let parsed: FuzzingResults = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(parsed.bridge_name, "nomad");
        assert_eq!(parsed.violations.len(), 1);
        assert_eq!(parsed.violations[0].detected_at_s, 11.3);
    }

    #[test]
    fn test_config_defaults() {
        let json = r#"{
            "atg_path": "atg.json",
            "scenarios_path": "hypotheses.json",
            "output_path": "results.json",
            "time_budget_s": 600,
            "source_rpc": "https://eth-mainnet.alchemyapi.io/v2/xxx",
            "dest_rpc": "https://eth-mainnet.alchemyapi.io/v2/xxx",
            "source_block": 15259100,
            "dest_block": 15259100
        }"#;

        let config: FuzzerConfig = serde_json::from_str(json).expect("Failed to parse config");
        assert_eq!(config.time_budget_s, 600);
        assert_eq!(config.runs, 1, "Default runs should be 1");
        assert!((config.alpha - 0.3).abs() < f64::EPSILON, "Default alpha should be 0.3");
        assert!((config.beta - 0.4).abs() < f64::EPSILON, "Default beta should be 0.4");
        assert!((config.gamma - 0.3).abs() < f64::EPSILON, "Default gamma should be 0.3");
        assert!(config.random_seed.is_none(), "Default random_seed should be None");
    }

    #[test]
    fn test_chain_id_serde() {
        let source: ChainId = serde_json::from_str("\"source\"").unwrap();
        assert_eq!(source, ChainId::Source);

        let dest: ChainId = serde_json::from_str("\"destination\"").unwrap();
        assert_eq!(dest, ChainId::Destination);

        let relay: ChainId = serde_json::from_str("\"relay\"").unwrap();
        assert_eq!(relay, ChainId::Relay);

        // Test alias
        let offchain: ChainId = serde_json::from_str("\"offchain\"").unwrap();
        assert_eq!(offchain, ChainId::Relay);
    }

    #[test]
    fn test_action_with_contract() {
        let json = r#"{
            "step": 1,
            "chain": "destination",
            "contract": "replica",
            "function": "process",
            "params": {"message": "0x00"},
            "description": "Submit message"
        }"#;

        let action: Action = serde_json::from_str(json).unwrap();
        assert_eq!(action.step, 1);
        assert_eq!(action.contract, Some("replica".to_string()));
        assert_eq!(action.function, Some("process".to_string()));
        assert!(action.action.is_none());
    }

    #[test]
    fn test_action_with_relay() {
        let json = r#"{
            "step": 2,
            "chain": "relay",
            "action": "replay",
            "params": {"replay_index": 0},
            "description": "Replay the same message"
        }"#;

        let action: Action = serde_json::from_str(json).unwrap();
        assert_eq!(action.step, 2);
        assert!(action.contract.is_none());
        assert!(action.function.is_none());
        assert_eq!(action.action, Some("replay".to_string()));
    }

    #[test]
    fn test_seed_creation() {
        let seed = Seed {
            source_scenario_id: "s1_zero_root_bypass".to_string(),
            actions: vec![],
            energy: 1.0,
            mutation_count: 0,
            waypoints_reached: vec![],
        };
        assert_eq!(seed.energy, 1.0);
        assert_eq!(seed.mutation_count, 0);
    }

    #[test]
    fn test_global_state() {
        let state = GlobalState {
            source_state: ChainState {
                balances: HashMap::from([
                    ("0xRouter".to_string(), "1000".to_string()),
                ]),
                storage: HashMap::new(),
                block_number: 15259100,
                timestamp: 1659171599,
            },
            dest_state: ChainState {
                balances: HashMap::new(),
                storage: HashMap::new(),
                block_number: 15259100,
                timestamp: 1659171599,
            },
            relay_state: RelaySnapshot {
                pending_messages: vec![],
                processed_set: vec![],
                mode: "faithful".to_string(),
                message_count: 0,
            },
        };

        // Verify JSON round-trip
        let json = serde_json::to_string(&state).unwrap();
        let parsed: GlobalState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source_state.block_number, 15259100);
        assert_eq!(parsed.relay_state.message_count, 0);
    }
}
