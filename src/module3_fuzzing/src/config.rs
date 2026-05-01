//! Configuration & CLI Parsing for BridgeSentry Fuzzer
//!
//! This module serves as the **bridge between the outside world and the fuzzer internals**.
//! It handles two key responsibilities:
//!
//! 1. **CLI Parsing** — Defines the exact command-line interface that Member A's Python
//!    orchestrator will call via subprocess:
//!    ```text
//!    ./bridgesentry-fuzzer --atg atg.json --scenarios hypotheses.json \
//!                          --budget 600 --output results.json
//!    ```
//!
//! 2. **Config Loading** — Reads and validates JSON input files (ATG from Module 1,
//!    hypotheses from Module 2), converts CLI args into a unified `FuzzerConfig`,
//!    and provides a single `RuntimeContext` struct with all deserialized data
//!    ready for the fuzzer loop.
//!
//! ## Design Decision: CLI-first with optional JSON config file
//!
//! - **CLI args** are always accepted (required paths, optional tuning parameters)
//! - **`--config` flag** can load a JSON config file for complex setups
//! - **CLI overrides JSON** — any CLI arg explicitly set takes precedence
//! - This ensures Member A can pass everything via subprocess args (simple integration)
//!   while Member B can use config files for local dev/benchmarking

use clap::{Parser, ValueEnum};
use eyre::{Context, Result};
use std::path::{Path, PathBuf};

use crate::types::{AtgGraph, FuzzerConfig, HypothesesFile};

/// Which detection algorithm the fuzzer drives. Default is BridgeSentry's
/// invariant checker; the other variants run re-implementations of
/// closed-source baselines for paper §5.3 RQ1 comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum BaselineMode {
    /// Stock BridgeSentry mode (Phase A real-bytecode + invariant checker).
    Bridgesentry,
    /// XScope re-implementation: rule-based detector, no calldata mutation.
    /// See `docs/REIMPL_XSCOPE_SPEC.md`.
    Xscope,
    /// XScope re-implementation in *replay* mode (X3-polish A3): instead
    /// of running LLM-generated scenarios, dispatches the actual exploit
    /// transactions cached at `benchmarks/<bridge>/exploit_replay/cache/`.
    /// Faithfully reproduces incident behaviour so the I-5 / I-6
    /// predicates fire on real on-chain SSTORE / log patterns.
    XscopeReplay,
}

impl Default for BaselineMode {
    fn default() -> Self {
        Self::Bridgesentry
    }
}

// ============================================================================
// CLI Argument Definition
// ============================================================================

/// BridgeSentry Dual-Chain Fuzzing Engine
///
/// Synchronized dual-EVM fuzzer for cross-chain bridge vulnerability discovery.
/// Takes ATG and attack hypotheses from Modules 1+2, runs guided fuzzing,
/// and outputs invariant violation reports.
#[derive(Parser, Debug)]
#[command(name = "bridgesentry-fuzzer")]
#[command(version = "0.1.0")]
#[command(about = "Cross-chain bridge vulnerability fuzzer")]
#[command(long_about = "BridgeSentry Fuzzing Engine: Takes ATG and attack hypotheses \
    from semantic analysis (Module 1) and RAG scenario generation (Module 2), \
    then runs synchronized dual-EVM fuzzing with ATG-aware mutations to discover \
    invariant violations in cross-chain bridge protocols.")]
pub struct CliArgs {
    /// Path to ATG JSON file (output from Module 1)
    #[arg(long, short = 'a', value_name = "FILE")]
    pub atg: PathBuf,

    /// Path to attack hypotheses JSON file (output from Module 2)
    #[arg(long, short = 's', value_name = "FILE")]
    pub scenarios: PathBuf,

    /// Path to write fuzzing results JSON
    #[arg(long, short = 'o', value_name = "FILE", default_value = "results.json")]
    pub output: PathBuf,

    /// Time budget in seconds for each fuzzing run
    #[arg(long, short = 'b', default_value_t = 600)]
    pub budget: u64,

    /// Optional JSON config file (CLI args override config file values)
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// RPC URL for source chain fork
    #[arg(long, env = "SOURCE_RPC_URL")]
    pub source_rpc: Option<String>,

    /// RPC URL for destination chain fork
    #[arg(long, env = "DEST_RPC_URL")]
    pub dest_rpc: Option<String>,

    /// Block number to fork source chain at
    #[arg(long)]
    pub source_block: Option<u64>,

    /// Block number to fork destination chain at
    #[arg(long)]
    pub dest_block: Option<u64>,

    /// Number of fuzzing runs to execute
    #[arg(long, default_value_t = 1)]
    pub runs: u32,

    /// Reward weight for code coverage (α in paper)
    #[arg(long, default_value_t = 0.3)]
    pub alpha: f64,

    /// Reward weight for waypoint progress (β in paper)
    #[arg(long, default_value_t = 0.4)]
    pub beta: f64,

    /// Reward weight for invariant distance (γ in paper)
    #[arg(long, default_value_t = 0.3)]
    pub gamma: f64,

    /// Random seed for reproducibility
    #[arg(long)]
    pub seed: Option<u64>,

    /// Reward threshold $R_{\text{th}}$: add scenario to corpus and snapshot pool when $R(\sigma)$ exceeds this (Alg. 1).
    #[arg(long)]
    pub r_threshold: Option<f64>,

    /// Maximum corpus size (including initial hypotheses).
    #[arg(long)]
    pub max_corpus: Option<usize>,

    /// Maximum snapshots kept in the pool (FIFO eviction).
    #[arg(long)]
    pub max_snapshots: Option<usize>,

    /// Do not add snapshots when reward is high (only use initial fork snapshot).
    #[arg(long, default_value_t = false)]
    pub no_dynamic_snapshots: bool,

    /// Enable verbose logging
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,

    /// Optional benchmark `metadata.json`. When supplied, real on-chain
    /// addresses listed under `contracts.<key>.address` are grafted onto
    /// ATG nodes whose `address` field is empty/invalid (e.g. LLM-produced
    /// ATGs). Match is case-insensitive substring on the contract key.
    #[arg(long, value_name = "FILE")]
    pub metadata: Option<PathBuf>,

    /// Detection algorithm. `bridgesentry` (default) runs the stock
    /// invariant checker; `xscope` runs the XScope re-implementation
    /// detector — see `docs/REIMPL_XSCOPE_SPEC.md`.
    #[arg(long, value_enum, default_value_t = BaselineMode::Bridgesentry)]
    pub baseline_mode: BaselineMode,
}

// ============================================================================
// Runtime Context — Everything the fuzzer needs to run
// ============================================================================

/// Per-bridge auth-witness recipe loaded from `metadata.auth_witness`.
/// Used by C3 wiring to translate the [`crate::storage_tracker::StorageTracker`]
/// trace into an XScope `AuthWitness` value for predicate I-6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthWitnessRecipe {
    /// `"zero_root" | "multisig" | "mpc" | "none"` — selects the
    /// `AuthWitness` variant C3 will construct. `"none"` means the
    /// bridge's predicted predicate doesn't need I-6.
    pub kind: String,
    /// Hex-form address of the contract whose storage trace is the
    /// witness source. Resolved from `auth_witness.contract_key` →
    /// `contracts.<key>.address`. None if the recipe is `"none"` or
    /// the metadata referenced a missing key.
    pub contract_address: Option<String>,
    /// Multisig quorum (only meaningful when kind == "multisig").
    pub threshold: Option<u32>,
}

/// Fully resolved runtime context with all data loaded and validated.
/// This is the single struct passed to the fuzzer loop — no more file I/O needed.
pub struct RuntimeContext {
    /// Resolved configuration (merged from CLI + config file)
    pub config: FuzzerConfig,
    /// Deserialized ATG (from Module 1)
    pub atg: AtgGraph,
    /// Deserialized attack hypotheses (from Module 2)
    pub hypotheses: HypothesesFile,
    /// Whether verbose logging is enabled
    pub verbose: bool,
    /// Optional `(contract_key, hex_address)` pairs grafted from
    /// `metadata.json`. Used by [`crate::contract_loader::ContractRegistry`]
    /// to resolve LLM-produced ATG nodes that lack on-chain addresses.
    pub address_overrides: Vec<(String, String)>,
    /// Direct ATG-node → contract-key alias map from
    /// `metadata.address_aliases`. Wins over the fuzzy substring match
    /// in `merge_address_overrides` when both are present.
    pub address_aliases: Vec<(String, String)>,
    /// Per-bridge auth-witness recipe (kind + resolved contract address +
    /// optional threshold). Empty `kind` ("none") when not required.
    pub auth_witness: Option<AuthWitnessRecipe>,
    /// Cache directory containing fetched exploit transactions used by
    /// the `xscope-replay` baseline mode (X3-polish A3). Resolved from
    /// the `--metadata` flag's parent dir + `exploit_replay/cache/`.
    /// `None` when `--metadata` was not supplied.
    pub replay_cache_dir: Option<std::path::PathBuf>,
    /// Optional EVM hard-fork override read from `metadata.fork.spec_id`.
    /// Lower-case spec name ("london", "shanghai", "cancun", "paris",
    /// "merge", "berlin"). When `None`, `DualEvm::new` defaults to
    /// `SpecId::LONDON`. Required for replays of post-Cancun blocks
    /// (e.g. Gempad fork 44946195 uses MCOPY which is a Cancun opcode).
    pub fork_spec_id: Option<String>,
    /// When `true`, the replay path synthesises a LockEvent with
    /// recipient=0x0 keyed on the tx hash whenever the tx targets a
    /// known bridge handler and the on-chain logs don't decode to a
    /// natural lock-side event. Read from
    /// `metadata.exploit_replay.synthesize_unauth_lock`. Used for
    /// bug-class-C1 incidents (Qubit) where the attacker's tx is
    /// itself a phantom deposit claim — predicate I-2 then fires.
    pub synthesize_unauth_lock: bool,
    /// When `true`, the replay path synthesises an UnlockEvent for
    /// the auth-witness contract on every successful tx, not just on
    /// txs whose top-level target matches the auth-witness address.
    /// Read from `metadata.exploit_replay.synthesize_unauth_unlock`.
    /// Used for bug-class-C3 incidents where the unlock happens via
    /// an internal call rather than at the top of the call tree
    /// (Gempad: drain tx targets an attack contract that
    /// internally calls `withdraw` on the GempadLocker).
    pub synthesize_unauth_unlock: bool,
    /// Which detection algorithm to run. Resolved from `--baseline-mode`.
    pub baseline_mode: BaselineMode,
}

// ============================================================================
// Config Resolution — Merge CLI args + JSON config file + env vars
// ============================================================================

/// Parse CLI arguments and resolve the full runtime context.
///
/// Resolution order (later overrides earlier):
/// 1. Built-in defaults
/// 2. JSON config file (if `--config` provided)
/// 3. CLI arguments
/// 4. Environment variables (for RPC URLs)
pub fn parse_and_load() -> Result<RuntimeContext> {
    let cli = CliArgs::parse();
    build_context_from_args(cli)
}

/// Build RuntimeContext from parsed CLI args.
/// Separated from `parse_and_load` for testability — tests can construct CliArgs directly.
pub fn build_context_from_args(cli: CliArgs) -> Result<RuntimeContext> {
    // Step 1: Load base config from JSON file (if provided)
    let base_config = if let Some(ref config_path) = cli.config {
        let content = std::fs::read_to_string(config_path)
            .wrap_err_with(|| format!("Failed to read config file: {}", config_path.display()))?;
        let config: FuzzerConfig = serde_json::from_str(&content)
            .wrap_err_with(|| format!("Failed to parse config JSON: {}", config_path.display()))?;
        Some(config)
    } else {
        None
    };

    // Step 2: Merge CLI args over base config
    let config = resolve_config(&cli, base_config)?;

    // Step 3: Load ATG
    let atg = load_atg(&cli.atg)?;

    // Step 4: Load hypotheses
    let hypotheses = load_hypotheses(&cli.scenarios)?;

    // Step 5: Validate cross-references
    validate_context(&config, &atg, &hypotheses)?;

    // Step 6: Optional metadata.json overrides for ATG node addresses.
    let (
        address_overrides,
        address_aliases,
        auth_witness,
        replay_cache_dir,
        fork_spec_id,
        synthesize_unauth_lock,
        synthesize_unauth_unlock,
    ) = if let Some(meta_path) = cli.metadata.as_ref() {
        let raw = std::fs::read_to_string(meta_path)
            .wrap_err_with(|| format!("Failed to read metadata: {}", meta_path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&raw)
            .wrap_err_with(|| format!("Failed to parse metadata: {}", meta_path.display()))?;
        // The replay cache lives next to metadata.json: bridge dir
        // is `meta_path.parent()`.
        let cache = meta_path
            .parent()
            .map(|p| p.join("exploit_replay").join("cache"));
        let spec = v
            .get("fork")
            .and_then(|f| f.get("spec_id"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_lowercase());
        let syn_unauth_lock = v
            .get("exploit_replay")
            .and_then(|r| r.get("synthesize_unauth_lock"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let syn_unauth_unlock = v
            .get("exploit_replay")
            .and_then(|r| r.get("synthesize_unauth_unlock"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        (
            load_address_overrides_from_value(&v),
            load_address_aliases_from_value(&v),
            load_auth_witness_from_value(&v),
            cache,
            spec,
            syn_unauth_lock,
            syn_unauth_unlock,
        )
    } else {
        (Vec::new(), Vec::new(), None, None, None, false, false)
    };

    Ok(RuntimeContext {
        config,
        atg,
        hypotheses,
        verbose: cli.verbose,
        address_overrides,
        address_aliases,
        auth_witness,
        replay_cache_dir,
        fork_spec_id,
        synthesize_unauth_lock,
        synthesize_unauth_unlock,
        baseline_mode: cli.baseline_mode,
    })
}

/// Read `contracts.<key>.address` pairs from a parsed metadata Value.
/// Returns an empty list when the `contracts` table is missing.
fn load_address_overrides_from_value(v: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(map) = v.get("contracts").and_then(|c| c.as_object()) {
        for (key, val) in map {
            if let Some(addr) = val.get("address").and_then(|a| a.as_str()) {
                out.push((key.clone(), addr.to_string()));
            }
        }
    }
    out
}

/// Read `address_aliases` pairs from `metadata.json` (the C2 of X3-polish
/// addition — see `docs/REIMPL_XSCOPE_X4_OUTCOME.md` §4.3). Returns an
/// empty list if the block is absent. Each entry maps an ATG-node name
/// (key of the JSON object) to a `contracts.<value>` key — the loader
/// resolves the latter to a hex address and feeds the pair into
/// [`crate::contract_loader::ContractRegistry::merge_address_overrides`]
/// alongside the standard contracts.<key>.address pairs.
fn load_address_aliases_from_value(v: &serde_json::Value) -> Vec<(String, String)> {
    let Some(aliases) = v.get("address_aliases").and_then(|c| c.as_object()) else {
        return Vec::new();
    };
    let contracts = v
        .get("contracts")
        .and_then(|c| c.as_object())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for (atg_name, target) in aliases {
        let target_key = match target.as_str() {
            Some(s) => s,
            None => continue,
        };
        let Some(addr) = contracts
            .get(target_key)
            .and_then(|v| v.get("address"))
            .and_then(|a| a.as_str())
        else {
            // Silently skip aliases pointing at missing contract keys —
            // matches the "warn-only" stance of the rest of the loader
            // so a bad metadata file degrades to no-op rather than
            // refusing to start.
            continue;
        };
        out.push((atg_name.clone(), addr.to_string()));
    }
    out
}

/// Read the `auth_witness` block from `metadata.json` and resolve its
/// `contract_key` reference to a concrete address pulled from the
/// `contracts` table. Returns `None` when the block is absent or when
/// `kind == "none"` — both signal "this bridge does not need an
/// auth-witness witness for its predicted predicate".
fn load_auth_witness_from_value(v: &serde_json::Value) -> Option<AuthWitnessRecipe> {
    let block = v.get("auth_witness")?.as_object()?;
    let kind = block.get("kind").and_then(|x| x.as_str()).unwrap_or("none");
    let contract_key = block
        .get("contract_key")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let contract_address = v
        .get("contracts")
        .and_then(|c| c.get(contract_key))
        .and_then(|c| c.get("address"))
        .and_then(|a| a.as_str())
        .map(|s| s.to_string());
    // kind="none" means "no witness check required", but we still
    // resolve contract_address so the replay-side synthetic-event
    // hooks (synthesize_unauth_lock / synthesize_unauth_unlock) can
    // address the bridge contract. Skip only when neither kind nor
    // address is meaningful.
    if kind == "none" && contract_address.is_none() {
        return None;
    }
    let threshold = block
        .get("threshold")
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);
    Some(AuthWitnessRecipe {
        kind: kind.to_string(),
        contract_address,
        threshold,
    })
}

/// Merge CLI arguments with optional base config from JSON file.
/// CLI args always take precedence over JSON config values.
fn resolve_config(cli: &CliArgs, base: Option<FuzzerConfig>) -> Result<FuzzerConfig> {
    let base = base.unwrap_or_else(|| FuzzerConfig {
        atg_path: String::new(),
        scenarios_path: String::new(),
        output_path: String::new(),
        time_budget_s: 600,
        source_rpc: String::new(),
        dest_rpc: String::new(),
        source_block: 0,
        dest_block: 0,
        runs: 1,
        alpha: 0.3,
        beta: 0.4,
        gamma: 0.3,
        random_seed: None,
        r_threshold: 0.5,
        max_corpus: 256,
        max_snapshots: 64,
        dynamic_snapshots: true,
    });

    Ok(FuzzerConfig {
        atg_path: cli.atg.to_string_lossy().to_string(),
        scenarios_path: cli.scenarios.to_string_lossy().to_string(),
        output_path: cli.output.to_string_lossy().to_string(),
        time_budget_s: cli.budget,
        source_rpc: cli
            .source_rpc
            .clone()
            .unwrap_or(base.source_rpc),
        dest_rpc: cli
            .dest_rpc
            .clone()
            .unwrap_or(base.dest_rpc),
        source_block: cli.source_block.unwrap_or(base.source_block),
        dest_block: cli.dest_block.unwrap_or(base.dest_block),
        runs: cli.runs,
        alpha: cli.alpha,
        beta: cli.beta,
        gamma: cli.gamma,
        random_seed: cli.seed.or(base.random_seed),
        r_threshold: cli.r_threshold.unwrap_or(base.r_threshold),
        max_corpus: cli.max_corpus.unwrap_or(base.max_corpus),
        max_snapshots: cli.max_snapshots.unwrap_or(base.max_snapshots),
        dynamic_snapshots: base.dynamic_snapshots && !cli.no_dynamic_snapshots,
    })
}

// ============================================================================
// File Loaders — Read and deserialize JSON input files
// ============================================================================

/// Load and deserialize ATG from a JSON file.
/// The ATG is produced by Module 1 (Semantic Extraction).
pub fn load_atg(path: &Path) -> Result<AtgGraph> {
    let content = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("Failed to read ATG file: {}", path.display()))?;
    let atg: AtgGraph = serde_json::from_str(&content)
        .wrap_err_with(|| format!("Failed to parse ATG JSON: {}", path.display()))?;

    if atg.nodes.is_empty() {
        eyre::bail!("ATG has no nodes — file may be empty or malformed: {}", path.display());
    }
    if atg.edges.is_empty() {
        eyre::bail!("ATG has no edges — file may be empty or malformed: {}", path.display());
    }
    if atg.invariants.is_empty() {
        eyre::bail!("ATG has no invariants — nothing to check: {}", path.display());
    }

    Ok(atg)
}

/// Load and deserialize attack hypotheses from a JSON file.
/// The hypotheses are produced by Module 2 (RAG Scenario Generation).
pub fn load_hypotheses(path: &Path) -> Result<HypothesesFile> {
    let content = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("Failed to read hypotheses file: {}", path.display()))?;
    let hypo: HypothesesFile = serde_json::from_str(&content)
        .wrap_err_with(|| format!("Failed to parse hypotheses JSON: {}", path.display()))?;

    if hypo.scenarios.is_empty() {
        eyre::bail!(
            "Hypotheses file has no scenarios — Module 2 may have failed: {}",
            path.display()
        );
    }

    // Validate each scenario has at least one action
    for scenario in &hypo.scenarios {
        if scenario.actions.is_empty() {
            eyre::bail!(
                "Scenario '{}' has no actions — cannot fuzz empty sequence",
                scenario.scenario_id
            );
        }
    }

    Ok(hypo)
}

// ============================================================================
// Validation — Cross-check ATG ↔ Hypotheses consistency
// ============================================================================

/// Validate that hypotheses reference invariants that actually exist in the ATG.
/// This catches integration errors between Module 1 and Module 2 early.
fn validate_context(
    _config: &FuzzerConfig,
    atg: &AtgGraph,
    hypotheses: &HypothesesFile,
) -> Result<()> {
    // Collect all invariant IDs from ATG
    let invariant_ids: std::collections::HashSet<&str> = atg
        .invariants
        .iter()
        .map(|inv| inv.invariant_id.as_str())
        .collect();

    // Check that each scenario targets an invariant that exists
    for scenario in &hypotheses.scenarios {
        if !invariant_ids.contains(scenario.target_invariant.as_str()) {
            eprintln!(
                "WARNING: Scenario '{}' targets invariant '{}' which is not in the ATG. \
                 Available invariants: {:?}",
                scenario.scenario_id,
                scenario.target_invariant,
                invariant_ids
            );
            // Warning only, not fatal — the scenario might still find bugs
        }
    }

    // Validate reward weights sum to ~1.0
    // R(σ) = α·cov + β·waypoints + γ·inv_dist
    let weight_sum = _config.alpha + _config.beta + _config.gamma;
    if (weight_sum - 1.0).abs() > 0.01 {
        eprintln!(
            "WARNING: Reward weights α={} + β={} + γ={} = {} (expected ~1.0). \
             Results may be poorly calibrated.",
            _config.alpha, _config.beta, _config.gamma, weight_sum
        );
    }

    Ok(())
}

// ============================================================================
// Display / Summary — Human-readable config output
// ============================================================================

impl RuntimeContext {
    /// Print a summary of the loaded configuration for logging.
    pub fn print_summary(&self) {
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║            BridgeSentry Fuzzing Engine v0.1.0               ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ Bridge:          {:<43}║", self.atg.bridge_name);
        println!("║ ATG:             {:<43}║", self.config.atg_path);
        println!("║ Scenarios:       {:<43}║", self.config.scenarios_path);
        println!("║ Output:          {:<43}║", self.config.output_path);
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!(
            "║ ATG Nodes:       {:<43}║",
            self.atg.nodes.len()
        );
        println!(
            "║ ATG Edges:       {:<43}║",
            self.atg.edges.len()
        );
        println!(
            "║ Invariants:      {:<43}║",
            self.atg.invariants.len()
        );
        println!(
            "║ Scenarios:       {:<43}║",
            self.hypotheses.scenarios.len()
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!(
            "║ Time Budget:     {:<40}s  ║",
            self.config.time_budget_s
        );
        println!(
            "║ Runs:            {:<43}║",
            self.config.runs
        );
        println!(
            "║ Reward Weights:  α={:.1} β={:.1} γ={:.1}{:<27}║",
            self.config.alpha, self.config.beta, self.config.gamma, ""
        );
        println!(
            "║ R-threshold:     {:<43}║",
            format!("{:.3}", self.config.r_threshold)
        );
        println!(
            "║ Max corpus:      {:<43}║",
            self.config.max_corpus
        );
        println!(
            "║ Max snapshots:   {:<43}║",
            self.config.max_snapshots
        );
        println!(
            "║ Dynamic snaps:   {:<43}║",
            self.config.dynamic_snapshots
        );
        if let Some(seed) = self.config.random_seed {
            println!("║ Random Seed:     {:<43}║", seed);
        }
        println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap() // src/
            .parent()
            .unwrap() // project root
            .join("tests")
            .join("fixtures")
    }

    #[test]
    fn test_load_atg_from_mock_fixture() {
        let path = fixtures_dir().join("atg_mock.json");
        let atg = load_atg(&path).expect("Failed to load ATG mock");

        assert_eq!(atg.bridge_name, "nomad");
        assert_eq!(atg.nodes.len(), 6);
        assert_eq!(atg.edges.len(), 5);
        assert_eq!(atg.invariants.len(), 4);
    }

    #[test]
    fn test_load_hypotheses_from_mock_fixture() {
        let path = fixtures_dir().join("hypotheses_mock.json");
        let hypo = load_hypotheses(&path).expect("Failed to load hypotheses mock");

        assert_eq!(hypo.bridge_name, "nomad");
        assert_eq!(hypo.scenarios.len(), 2);
        assert_eq!(hypo.scenarios[0].scenario_id, "s1_zero_root_bypass");
        assert_eq!(hypo.scenarios[1].scenario_id, "s2_replay_attack");
    }

    #[test]
    fn test_load_atg_file_not_found() {
        let result = load_atg(Path::new("nonexistent.json"));
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("Failed to read ATG file"),
            "Error should mention file reading failure: {}",
            err_msg
        );
    }

    #[test]
    fn test_load_hypotheses_file_not_found() {
        let result = load_hypotheses(Path::new("nonexistent.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_context_matching_invariants() {
        let atg_path = fixtures_dir().join("atg_mock.json");
        let hypo_path = fixtures_dir().join("hypotheses_mock.json");
        let atg = load_atg(&atg_path).unwrap();
        let hypo = load_hypotheses(&hypo_path).unwrap();
        let config = FuzzerConfig {
            atg_path: atg_path.to_string_lossy().to_string(),
            scenarios_path: hypo_path.to_string_lossy().to_string(),
            output_path: "results.json".to_string(),
            time_budget_s: 600,
            source_rpc: String::new(),
            dest_rpc: String::new(),
            source_block: 15259100,
            dest_block: 15259100,
            runs: 1,
            alpha: 0.3,
            beta: 0.4,
            gamma: 0.3,
            random_seed: None,
            r_threshold: 0.5,
            max_corpus: 256,
            max_snapshots: 64,
            dynamic_snapshots: true,
        };

        // Should succeed — mock fixtures have matching invariant IDs
        let result = validate_context(&config, &atg, &hypo);
        assert!(result.is_ok(), "Validation should pass for matching fixtures");
    }

    #[test]
    fn test_resolve_config_cli_only() {
        let cli = CliArgs {
            atg: PathBuf::from("atg.json"),
            scenarios: PathBuf::from("hypotheses.json"),
            output: PathBuf::from("results.json"),
            budget: 300,
            config: None,
            source_rpc: Some("https://eth.example.com".to_string()),
            dest_rpc: Some("https://bsc.example.com".to_string()),
            source_block: Some(15259100),
            dest_block: Some(15259100),
            runs: 5,
            alpha: 0.3,
            beta: 0.4,
            gamma: 0.3,
            seed: Some(42),
            r_threshold: None,
            max_corpus: None,
            max_snapshots: None,
            no_dynamic_snapshots: false,
            metadata: None,
            baseline_mode: BaselineMode::Bridgesentry,
            verbose: true,
        };

        let config = resolve_config(&cli, None).unwrap();

        assert_eq!(config.atg_path, "atg.json");
        assert_eq!(config.scenarios_path, "hypotheses.json");
        assert_eq!(config.time_budget_s, 300);
        assert_eq!(config.source_rpc, "https://eth.example.com");
        assert_eq!(config.dest_rpc, "https://bsc.example.com");
        assert_eq!(config.source_block, 15259100);
        assert_eq!(config.dest_block, 15259100);
        assert_eq!(config.runs, 5);
        assert_eq!(config.random_seed, Some(42));
    }

    #[test]
    fn test_resolve_config_cli_overrides_json() {
        let base_config = FuzzerConfig {
            atg_path: "old_atg.json".to_string(),
            scenarios_path: "old_hypo.json".to_string(),
            output_path: "old_results.json".to_string(),
            time_budget_s: 1200,
            source_rpc: "https://old-rpc.com".to_string(),
            dest_rpc: "https://old-rpc.com".to_string(),
            source_block: 10000000,
            dest_block: 10000000,
            runs: 10,
            alpha: 0.5,
            beta: 0.3,
            gamma: 0.2,
            random_seed: Some(99),
            r_threshold: 0.55,
            max_corpus: 128,
            max_snapshots: 32,
            dynamic_snapshots: true,
        };

        let cli = CliArgs {
            atg: PathBuf::from("new_atg.json"),
            scenarios: PathBuf::from("new_hypo.json"),
            output: PathBuf::from("new_results.json"),
            budget: 600, // CLI overrides JSON's 1200
            config: None,
            source_rpc: None, // Falls back to JSON config
            dest_rpc: None,   // Falls back to JSON config
            source_block: Some(15259100), // CLI overrides JSON
            dest_block: None,             // Falls back to JSON
            runs: 1,
            alpha: 0.3,
            beta: 0.4,
            gamma: 0.3,
            seed: None, // Falls back to JSON config
            r_threshold: None,
            max_corpus: None,
            max_snapshots: None,
            no_dynamic_snapshots: false,
            metadata: None,
            baseline_mode: BaselineMode::Bridgesentry,
            verbose: false,
        };

        let config = resolve_config(&cli, Some(base_config)).unwrap();

        // CLI should override
        assert_eq!(config.atg_path, "new_atg.json");
        assert_eq!(config.time_budget_s, 600);
        assert_eq!(config.source_block, 15259100);

        // JSON fallback should be used
        assert_eq!(config.source_rpc, "https://old-rpc.com");
        assert_eq!(config.dest_rpc, "https://old-rpc.com");
        assert_eq!(config.dest_block, 10000000);
        assert_eq!(config.random_seed, Some(99));
        assert!((config.r_threshold - 0.55).abs() < 1e-9);
        assert_eq!(config.max_corpus, 128);
        assert_eq!(config.max_snapshots, 32);
    }

    #[test]
    fn test_build_context_full_integration() {
        let atg_path = fixtures_dir().join("atg_mock.json");
        let hypo_path = fixtures_dir().join("hypotheses_mock.json");

        let cli = CliArgs {
            atg: atg_path,
            scenarios: hypo_path,
            output: PathBuf::from("test_results.json"),
            budget: 60,
            config: None,
            source_rpc: Some("https://eth.example.com".to_string()),
            dest_rpc: Some("https://eth.example.com".to_string()),
            source_block: Some(15259100),
            dest_block: Some(15259100),
            runs: 1,
            alpha: 0.3,
            beta: 0.4,
            gamma: 0.3,
            seed: None,
            r_threshold: None,
            max_corpus: None,
            max_snapshots: None,
            no_dynamic_snapshots: false,
            metadata: None,
            baseline_mode: BaselineMode::Bridgesentry,
            verbose: false,
        };

        let ctx = build_context_from_args(cli).expect("Should build context successfully");

        assert_eq!(ctx.atg.bridge_name, "nomad");
        assert_eq!(ctx.hypotheses.scenarios.len(), 2);
        assert_eq!(ctx.config.time_budget_s, 60);
        assert!(!ctx.verbose);
    }

    #[test]
    fn test_runtime_context_print_summary() {
        let atg_path = fixtures_dir().join("atg_mock.json");
        let hypo_path = fixtures_dir().join("hypotheses_mock.json");

        let cli = CliArgs {
            atg: atg_path,
            scenarios: hypo_path,
            output: PathBuf::from("results.json"),
            budget: 600,
            config: None,
            source_rpc: Some("https://eth.example.com".to_string()),
            dest_rpc: Some("https://eth.example.com".to_string()),
            source_block: Some(15259100),
            dest_block: Some(15259100),
            runs: 1,
            alpha: 0.3,
            beta: 0.4,
            gamma: 0.3,
            seed: Some(42),
            r_threshold: None,
            max_corpus: None,
            max_snapshots: None,
            no_dynamic_snapshots: false,
            metadata: None,
            baseline_mode: BaselineMode::Bridgesentry,
            verbose: true,
        };

        let ctx = build_context_from_args(cli).unwrap();
        // This should not panic
        ctx.print_summary();
    }

    // ========================================================================
    // C2 (X3-polish) — auth_witness + address_aliases loader tests
    // ========================================================================

    fn meta_with_auth_witness() -> serde_json::Value {
        serde_json::json!({
            "contracts": {
                "replica_ethereum": {
                    "address": "0xB923336759618F55bd0F8313bd843604592E27bd8",
                    "role": "..."
                },
                "router": {
                    "address": "0x88A69B4E698A4B090DF6CF5BD7B2D47325AD30A3",
                    "role": "..."
                }
            },
            "address_aliases": {
                "Replica": "replica_ethereum",
                "BridgeRouter": "router"
            },
            "auth_witness": {
                "kind": "zero_root",
                "contract_key": "replica_ethereum"
            }
        })
    }

    #[test]
    fn load_address_aliases_resolves_atg_node_to_contract_address() {
        let v = meta_with_auth_witness();
        let aliases = load_address_aliases_from_value(&v);
        // Order in HashMap is non-deterministic; sort for stable assert.
        let mut sorted = aliases.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            sorted,
            vec![
                ("BridgeRouter".to_string(), "0x88A69B4E698A4B090DF6CF5BD7B2D47325AD30A3".to_string()),
                ("Replica".to_string(), "0xB923336759618F55bd0F8313bd843604592E27bd8".to_string()),
            ]
        );
    }

    #[test]
    fn load_address_aliases_skips_targets_missing_from_contracts() {
        let mut v = meta_with_auth_witness();
        // Point an alias at a contract key that does not exist.
        v["address_aliases"]["GhostNode"] =
            serde_json::Value::String("nope_not_in_contracts".to_string());
        let aliases = load_address_aliases_from_value(&v);
        assert!(
            !aliases.iter().any(|(k, _)| k == "GhostNode"),
            "GhostNode should be skipped, got {:?}",
            aliases
        );
        // The two valid ones survive.
        assert_eq!(aliases.len(), 2);
    }

    #[test]
    fn load_auth_witness_resolves_contract_key_to_address() {
        let v = meta_with_auth_witness();
        let aw = load_auth_witness_from_value(&v).expect("recipe present");
        assert_eq!(aw.kind, "zero_root");
        assert_eq!(
            aw.contract_address.as_deref(),
            Some("0xB923336759618F55bd0F8313bd843604592E27bd8")
        );
        assert!(aw.threshold.is_none());
    }

    #[test]
    fn load_auth_witness_carries_threshold_for_multisig() {
        let v = serde_json::json!({
            "contracts": {
                "manager": {"address": "0xAA00000000000000000000000000000000000000"}
            },
            "auth_witness": {
                "kind": "multisig",
                "contract_key": "manager",
                "threshold": 5
            }
        });
        let aw = load_auth_witness_from_value(&v).expect("recipe present");
        assert_eq!(aw.kind, "multisig");
        assert_eq!(aw.threshold, Some(5));
    }

    #[test]
    fn load_auth_witness_returns_none_for_kind_none() {
        let v = serde_json::json!({
            "contracts": {"x": {"address": "0xAA00000000000000000000000000000000000000"}},
            "auth_witness": {"kind": "none", "contract_key": "x"}
        });
        assert!(load_auth_witness_from_value(&v).is_none());
    }

    #[test]
    fn load_auth_witness_returns_none_when_block_absent() {
        let v = serde_json::json!({
            "contracts": {"x": {"address": "0xAA00000000000000000000000000000000000000"}}
        });
        assert!(load_auth_witness_from_value(&v).is_none());
    }
}
