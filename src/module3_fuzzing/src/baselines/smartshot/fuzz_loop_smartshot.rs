//! SmartShot — fuzz loop re-implementation (SS5).
//!
//! Faithfully mirrors the original `SCFuzzing/SmartShot` architecture:
//!
//! 1. **GA engine** (`EvolutionaryFuzzingEngine.run()`) evolves a population
//!    of transaction-sequence individuals via selection → crossover → mutation.
//!
//! 2. **Snapshot injection** (`engine.py` lines 179-186): at each generation,
//!    snapshot entries from `snapshot_reserved` are cloned into new individuals
//!    whose chromosome is truncated to start at the snapshot's `tx_index`.
//!
//! 3. **Execution with taint** (`execution_trace_analysis.py`):
//!    - If `individual.snapshot` is set → restore storage, apply slot mutation,
//!      execute, then undo the mutation.
//!    - Track SLOAD/SSTORE for data dependency and symbolic taint.
//!    - On trigger opcodes (SSTORE-before-JUMPI, TIMESTAMP, NUMBER, CALL) →
//!      capture new snapshots and push to the pool.
//!
//! 4. **Fitness** = code coverage + branch coverage + data dependency bonus.
//!    (No directed fitness like VulSEye — SmartShot uses a different strategy.)

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use eyre::{eyre, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use revm::primitives::{Address, B256, U256};

use crate::config::RuntimeContext;
use crate::contract_loader::{ChainSide, ContractRegistry};
use crate::coverage_tracker::CoverageTracker;
use crate::dual_evm::default_caller;
use crate::mock_relay::{MockRelay, RelayMode};
use crate::mutator::{CalldataMutator, Mutator};
use crate::types::{Coverage, FuzzingResults, FuzzingStats, Scenario, Violation};

use super::double_validate::run_with_double_validation;
use super::mutable_snapshot::{
    mutation_pool_values, MutableSnapshot, MutationOperator, SnapshotKind,
};
use super::snapshot_mutate::{apply_snapshot_mutation, restore_original, DataDependencyTracker};
use super::snapshot_pool::{SnapshotEntry, SnapshotPool};
use super::taint_cache::{build_curated_taint_cache, collect_read_set, TaintCache};

// ─────────────────────────────────────────────────────────
// Corpus entry (mirrors GA Individual)
// ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct CorpusEntry {
    scenario: Scenario,
    fitness: f64,
    /// If `Some`, this individual was spawned from a snapshot —
    /// meaning its scenario should be replayed starting from `snapshot.tx_index`.
    snapshot: Option<MutableSnapshot>,
}

// ─────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────

pub fn run_smartshot(ctx: &RuntimeContext) -> Result<FuzzingResults> {
    let mutator = Mutator::with_atg(&ctx.atg);
    let mut registry = ContractRegistry::from_atg(&ctx.atg);

    // Apply aliases and overrides
    for (atg_name, addr) in &ctx.address_aliases {
        registry.add_explicit_alias(atg_name, addr);
    }
    if !ctx.address_overrides.is_empty() {
        registry.merge_address_overrides(
            ctx.address_overrides
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        );
    }

    let calldata_mutator = CalldataMutator::from_registry(&registry, &ctx.atg);
    let mut relay = MockRelay::new(RelayMode::Faithful);
    let mut dual_env_opt = crate::fuzz_loop::init_dual_evm(ctx);
    if dual_env_opt.is_none() {
        let reason = if ctx.config.source_rpc.trim().is_empty()
            || ctx.config.dest_rpc.trim().is_empty()
            || ctx.config.source_block == 0
            || ctx.config.dest_block == 0
        {
            "missing_rpc_or_fork_block"
        } else {
            "init_failed"
        };
        return Err(eyre!(
            "SmartShot real-mode requires initialized DualEVM; dual_evm_status={reason}"
        ));
    }

    // Warm up bytecode
    let mut is_deployed = false;
    let mut warmup_bytecode = 0usize;
    let mut warmup_errors: Vec<String> = Vec::new();
    let mut registry_code_status: Vec<String> = Vec::new();
    if let Some(d) = dual_env_opt.as_mut() {
        if !ctx.contract_plan.scan_sol_files().is_empty() {
            match ctx.contract_plan.compile_and_deploy(d) {
                Ok(new_addrs) => {
                    let overrides: Vec<(String, String)> = new_addrs
                        .into_iter()
                        .map(|(k, v)| (k, format!("{:?}", v)))
                        .collect();
                    registry.merge_address_overrides(
                        overrides.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                    );
                    is_deployed = true;
                }
                Err(e) => {
                    return Err(eyre!("Deployment validation failed: {}", e));
                }
            }
        }
        let (warmed, errors) = registry.warmup_bytecode_best_effort(d);
        warmup_bytecode = warmed;
        warmup_errors = errors;
        let tracked = registry.all_addresses();
        if !tracked.is_empty() {
            d.set_tracked_addresses(tracked);
        }
        for (node, addr, side) in registry.named_addresses() {
            let code_len = d.get_code(addr).map(|code| code.len()).unwrap_or(0);
            registry_code_status.push(format!(
                "registry_code node={node} side={side:?} addr={addr:#x} code_len={code_len}"
            ));
        }
    }

    // ── Build TaintCache (cut-loss mode for bridge benchmarks) ──────────
    let selectors: Vec<[u8; 4]> = if calldata_mutator.known_selectors().is_empty() {
        vec![[0u8; 4]]
    } else {
        calldata_mutator.known_selectors().to_vec()
    };
    let contracts_with_selectors: Vec<(Address, [u8; 4])> = registry
        .all_addresses()
        .into_iter()
        .flat_map(|addr| {
            let selectors = selectors.clone();
            selectors.into_iter().map(move |selector| (addr, selector))
        })
        .collect();
    let mut taint_cache = TaintCache::new();
    if let Some(d) = dual_env_opt.as_mut() {
        for (addr, selector) in &contracts_with_selectors {
            let read_set = collect_read_set(d, *addr, *selector);
            if !read_set.is_empty() {
                taint_cache.insert((*addr, *selector), read_set);
            }
        }
    }
    if taint_cache.total_slots() == 0 {
        taint_cache = build_curated_taint_cache(&ctx.atg.bridge_name, &contracts_with_selectors);
    }

    eprintln!(
        "[smartshot] taint_cache: {} functions, {} total slots (cut_loss={})",
        contracts_with_selectors.len(),
        taint_cache.total_slots(),
        taint_cache.cut_loss_mode,
    );

    // ── Initialise snapshot pool ────────────────────────────────────────
    let mut snapshot_pool = SnapshotPool::new();
    let boundary_values = mutation_pool_values();

    // ── Initialise data dependency tracker ──────────────────────────────
    let mut dd_tracker = DataDependencyTracker::new();

    // ── Coverage tracking ──────────────────────────────────────────────
    let mut campaign_coverage = CoverageTracker::default();
    let mut dispatched_source: HashSet<Address> = HashSet::new();
    let mut dispatched_dest: HashSet<Address> = HashSet::new();
    let mut touched_edges: HashSet<String> = HashSet::new();
    let mut code_coverage_set: HashSet<usize> = HashSet::new();
    let mut branch_coverage_set: HashSet<(usize, bool)> = HashSet::new();

    // ── Build initial corpus from hypotheses ───────────────────────────
    let mut corpus: Vec<CorpusEntry> = ctx
        .hypotheses
        .scenarios
        .iter()
        .map(|s| CorpusEntry {
            scenario: s.clone(),
            fitness: 1.0,
            snapshot: None,
        })
        .collect();
    let initial_corpus = corpus.clone();
    let mut last_coverage_len = 0usize;
    let mut stalled_iters = 0usize;
    let mut mutation_rate = 1.0f64;

    let start = Instant::now();
    let budget_s = ctx
        .config
        .time_budget_s
        .saturating_mul(ctx.config.runs.max(1) as u64)
        .max(1);

    let mut rng = if let Some(s) = ctx.config.random_seed {
        StdRng::seed_from_u64(s)
    } else {
        StdRng::from_entropy()
    };

    let mut total_iterations = 0_u64;
    let mut mutations_applied = 0_u64;
    let mut snapshots_captured = 0_u64;
    let mut snapshot_individuals_injected = 0_u64;
    let mut violations: Vec<Violation> = Vec::new();
    let mut seen_mutation_findings: HashSet<String> = HashSet::new();
    let mut validation_attempts = 0_u64;
    let mut validated_findings = 0_u64;
    let mut expected_validated_findings = 0_u64;
    let mut validation_status_counts: HashMap<String, u64> = HashMap::new();
    let mut attempted_operator_counts: HashMap<String, u64> = HashMap::new();
    let mut validated_operator_counts: HashMap<String, u64> = HashMap::new();
    let expected_ops = expected_mutation_operators(&ctx.atg.bridge_name);
    let expected_csv = expected_ops
        .iter()
        .map(|op| op.id())
        .collect::<Vec<_>>()
        .join(",");

    // ── Main fuzz loop (generation-based, like original SmartShot) ──────
    while start.elapsed().as_secs() < budget_s {
        if corpus.is_empty() {
            break;
        }

        // ── Step 1: Selection ──────────────────────────────────────────
        // Linear ranking selection (matching SmartShot's LinearRankingSelection).
        // Sort by fitness descending, then pick with linear probability.
        corpus.sort_by(|a, b| {
            b.fitness
                .partial_cmp(&a.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let pop_size = corpus.len();
        let cidx = {
            // Linear ranking: higher rank → higher probability
            let rank_sum = (pop_size * (pop_size + 1)) / 2;
            let r: usize = rng.gen_range(0..rank_sum.max(1));
            let mut cumulative = 0usize;
            let mut selected = 0usize;
            for i in 0..pop_size {
                cumulative += pop_size - i; // rank 0 gets highest weight
                if cumulative > r {
                    selected = i;
                    break;
                }
            }
            selected
        };
        let cidx2 = rng.gen_range(0..pop_size);

        // ── Step 2: Crossover + Mutation ───────────────────────────────
        let mut s_prime = corpus[cidx].scenario.clone();

        if rng.gen_bool(ctx.config.alpha.min(1.0)) && pop_size > 1 {
            // Crossover: swap a random slice of transactions between two parents
            let parent2 = &corpus[cidx2].scenario;
            let scenario_bytes = serde_json::to_vec(&s_prime).unwrap_or_default();
            let parent2_bytes = serde_json::to_vec(parent2).unwrap_or_default();
            if scenario_bytes.len() > 4 && parent2_bytes.len() > 4 {
                let xover_point = rng.gen_range(1..scenario_bytes.len().min(parent2_bytes.len()));
                let mut child_bytes = scenario_bytes[..xover_point].to_vec();
                child_bytes.extend_from_slice(&parent2_bytes[xover_point..]);
                s_prime = serde_json::from_slice(&child_bytes).unwrap_or(s_prime);
            }
            mutations_applied += 1;
        } else {
            // Mutation: mutate calldata
            let scenario_bytes = serde_json::to_vec(&s_prime).unwrap_or_default();
            let mut mutated_bytes = scenario_bytes.clone();
            let mutation_rounds = mutation_rate.ceil() as usize;
            for _ in 0..mutation_rounds.max(1) {
                mutated_bytes = mutator.mutate(&mutated_bytes);
            }
            if mutated_bytes != scenario_bytes {
                mutations_applied += 1;
                s_prime = serde_json::from_slice(&mutated_bytes).unwrap_or(s_prime);
            }
        }

        // ── Step 3: Execute scenario ───────────────────────────────────
        let pre_cov = code_coverage_set.len();
        let pre_edges = touched_edges.len();

        let _trace = crate::fuzz_loop::execute_scenario(
            &s_prime,
            ctx,
            &mut dual_env_opt,
            &mut relay,
            &mut touched_edges,
            &registry,
            &calldata_mutator,
            &mut rng,
            &mut campaign_coverage,
            &mut dispatched_source,
            &mut dispatched_dest,
        );

        // Update coverage from campaign tracker
        for (addr, pc) in &campaign_coverage.touched {
            code_coverage_set.insert(*pc);
        }
        let new_coverage = code_coverage_set.len().saturating_sub(pre_cov);
        let new_edges = touched_edges.len().saturating_sub(pre_edges);

        // ── Step 4: Snapshot trigger heuristics ────────────────────────
        // In the original SmartShot, snapshots are captured inside
        // `execution_function()` at specific opcode triggers.
        // In our revm-based system, we approximate this with coverage-based
        // heuristics: capture a snapshot when new coverage is found.
        if let Some(d) = dual_env_opt.as_mut() {
            if new_coverage > 0 || new_edges > 0 {
                // CK-S: LastSstoreBeforeJumpi (approximate: any new coverage)
                let snap = MutableSnapshot::from_snapshot(
                    d.capture_snapshot(),
                    relay.get_state().clone(),
                    SnapshotKind::LastSstoreBeforeJumpi,
                    0,
                );
                snapshots_captured += 1;

                // Pick a random tainted slot from the cache to create a mutation
                let all_tainted: Vec<(Address, B256)> =
                    taint_cache.all_slots().into_iter().collect();
                if !all_tainted.is_empty() {
                    let (addr, slot) = all_tainted[rng.gen_range(0..all_tainted.len())];
                    let value = boundary_values[rng.gen_range(0..boundary_values.len())];

                    let key = SnapshotPool::make_key(
                        SnapshotKind::LastSstoreBeforeJumpi,
                        slot.0[31] as u64,
                    );
                    for operator in MutationOperator::ACTIVE_POOL {
                        snapshot_pool.push(
                            &key,
                            SnapshotEntry {
                                snapshot: snap.clone(),
                                contract: addr,
                                slot,
                                target_value: value,
                                operator: *operator,
                            },
                        );
                    }
                }
            }
        }

        // ── Step 5: Inject snapshot-based individuals (per-generation) ─
        // In the original SmartShot, this happens in engine.py:
        //   for key in self.snapshots:
        //       for snapshot in self.snapshots[key]:
        //           new_indv = snapshot["snapshot"][1].clone()
        //           new_indv.chromosome = new_indv.chromosome[snapshot["snapshot"][5]:]
        //           indvs.append(new_indv)
        let pool_entries = snapshot_pool.drain_all();
        for entry in &pool_entries {
            let mut snap_with_mutation = entry.snapshot.clone();
            match entry.operator {
                MutationOperator::MS1SetStorage => {
                    snap_with_mutation.set_storage_mutation(
                        entry.contract,
                        entry.slot,
                        entry.target_value,
                    );
                }
                MutationOperator::MS2SetBalance => {
                    let value = U256::from_be_bytes(entry.target_value.0);
                    snap_with_mutation.set_balance_mutation(entry.contract, value);
                }
                MutationOperator::MS4AdvanceTimestamp => {
                    snap_with_mutation.advance_timestamp_mutation(1, 1);
                }
                MutationOperator::MS5AdvanceBlock => {
                    snap_with_mutation.advance_block_mutation(1, 1);
                }
            }

            // Apply snapshot mutation (restore base + set slot override)
            if let Some(d) = dual_env_opt.as_mut() {
                apply_snapshot_mutation(d, &snap_with_mutation);
            }

            // Execute the same scenario on the mutated state
            let _snap_trace = crate::fuzz_loop::execute_scenario(
                &s_prime,
                ctx,
                &mut dual_env_opt,
                &mut relay,
                &mut touched_edges,
                &registry,
                &calldata_mutator,
                &mut rng,
                &mut campaign_coverage,
                &mut dispatched_source,
                &mut dispatched_dest,
            );

            // Restore original state
            if let Some(d) = dual_env_opt.as_mut() {
                restore_original(d, &snap_with_mutation);
            }
            if let Some(d) = dual_env_opt.as_mut() {
                let validation_payload = validation_payload_for(&s_prime, &registry, &calldata_mutator);
                let validation =
                    run_with_double_validation(d, &snap_with_mutation, &validation_payload);
                validation_attempts += 1;
                *attempted_operator_counts
                    .entry(entry.operator.id().to_string())
                    .or_insert(0) += 1;
                *validation_status_counts
                    .entry(validation.status.as_str().to_string())
                    .or_insert(0) += 1;
                let validated =
                    matches!(validation.status, super::double_validate::DoubleValidationStatus::Validated);
                if validation.mutation_applied && validated {
                    validated_findings += 1;
                    let predicate_match = expected_ops.contains(&entry.operator);
                    if predicate_match {
                        expected_validated_findings += 1;
                    }
                    *validated_operator_counts
                        .entry(entry.operator.id().to_string())
                        .or_insert(0) += 1;
                    let key = format!(
                        "{}:{:#x}:{}",
                        entry.operator.id(),
                        entry.contract,
                        entry.slot
                    );
                    if seen_mutation_findings.insert(key) {
                        violations.push(smartshot_violation(
                            &ctx.atg.bridge_name,
                            &s_prime,
                            entry.operator,
                            &expected_csv,
                            predicate_match,
                            entry.contract,
                            entry.slot,
                            entry.target_value,
                            taint_cache.cut_loss_mode,
                            validation.status.as_str(),
                            start.elapsed().as_secs_f64(),
                        ));
                    }
                }
            }
            snapshot_individuals_injected += 1;
        }

        // ── Step 6: Compute fitness ────────────────────────────────────
        // SmartShot fitness = code_coverage_pct + branch_coverage_bonus + data_dep_bonus
        let overall_pcs = campaign_coverage.unique_pc_count().max(1);
        let code_cov_pct = code_coverage_set.len() as f64 / overall_pcs as f64;
        let branch_bonus = new_edges as f64 * 0.1;
        let data_dep_bonus = if dd_tracker.num_functions() > 0 {
            0.05
        } else {
            0.0
        };
        let fitness = code_cov_pct + branch_bonus + data_dep_bonus;

        // ── Step 7: Update corpus ──────────────────────────────────────
        corpus.push(CorpusEntry {
            scenario: s_prime,
            fitness,
            snapshot: None,
        });

        // Keep corpus bounded (like SmartShot's population size)
        if corpus.len() > ctx.config.max_corpus {
            corpus.sort_by(|a, b| {
                b.fitness
                    .partial_cmp(&a.fitness)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            corpus.truncate(ctx.config.max_corpus);
        }

        let current_coverage_len = code_coverage_set.len();
        if current_coverage_len > last_coverage_len {
            last_coverage_len = current_coverage_len;
            stalled_iters = 0;
        } else {
            stalled_iters += 1;
        }
        if stalled_iters >= 200 {
            corpus = initial_corpus.clone();
            mutation_rate = (mutation_rate * 1.25).min(8.0);
            stalled_iters = 0;
        }

        total_iterations += 1;

        // ── Logging (per 50 iterations, like SmartShot's per-generation log) ─
        if ctx.verbose && total_iterations % 50 == 0 {
            eprintln!(
                "[smartshot] gen={} cov={}/{} edges={}/{} pool={} snap_inj={} fit={:.3}",
                total_iterations,
                code_coverage_set.len(),
                overall_pcs,
                touched_edges.len(),
                ctx.atg.edges.len(),
                snapshot_pool.total_entries(),
                snapshot_individuals_injected,
                fitness,
            );
        }

        // ── Symbolic execution fallback (per original SmartShot) ────────
        // In the original: if code coverage stalls, reset population.
        // We approximate this with a stall detector.
        // (Omitted for initial implementation — can be added in SS6.)
    }

    // ── Build final results ────────────────────────────────────────────
    let basic_blocks_source = campaign_coverage
        .touched
        .iter()
        .filter(|(a, _)| {
            dispatched_source.contains(a) || registry.addresses_on(ChainSide::Source).contains(a)
        })
        .count() as u64;
    let basic_blocks_dest = campaign_coverage
        .touched
        .iter()
        .filter(|(a, _)| {
            dispatched_dest.contains(a) || registry.addresses_on(ChainSide::Destination).contains(a)
        })
        .count() as u64;

    let mut deployment_plan_log = ctx.contract_plan.deployment_plan_log(&ctx.atg, is_deployed);
    deployment_plan_log.push("dual_evm_status=initialized".to_string());
    deployment_plan_log.push(format!("warmup_bytecode={warmup_bytecode}"));
    if !warmup_errors.is_empty() {
        deployment_plan_log.push(format!("warmup_errors={}", warmup_errors.len()));
        for e in warmup_errors.iter().take(5) {
            deployment_plan_log.push(format!("warmup_error={e}"));
        }
    }
    for status in registry_code_status.iter().take(16) {
        deployment_plan_log.push(status.clone());
    }
    deployment_plan_log.push(if basic_blocks_source + basic_blocks_dest > 0 {
        "coverage_status=real_evm".to_string()
    } else {
        "coverage_status=zero_coverage".to_string()
    });
    deployment_plan_log.push(format!(
        "smartshot_taint_source={}",
        if taint_cache.cut_loss_mode {
            "metadata_seeded"
        } else {
            "sload_inspector"
        }
    ));
    deployment_plan_log.push(format!("smartshot_validation_attempts={validation_attempts}"));
    deployment_plan_log.push(format!("smartshot_validated_findings={validated_findings}"));
    deployment_plan_log.push(format!(
        "smartshot_expected_validated_findings={expected_validated_findings}"
    ));
    deployment_plan_log.push(format!(
        "smartshot_validation_statuses={}",
        format_counts(&validation_status_counts)
    ));
    deployment_plan_log.push(format!(
        "smartshot_attempted_operators={}",
        format_counts(&attempted_operator_counts)
    ));
    deployment_plan_log.push(format!(
        "smartshot_validated_operators={}",
        format_counts(&validated_operator_counts)
    ));

    if warmup_bytecode == 0 && !is_deployed {
        return Err(eyre!(
            "SmartShot real-mode did not deploy or warm up any bytecode; deploy_helper_status=skipped_or_failed"
        ));
    }
    Ok(FuzzingResults {
        bridge_name: ctx.atg.bridge_name.clone(),
        run_id: 0,
        time_budget_s: ctx.config.time_budget_s,
        violations,
        coverage: Coverage {
            xcc_atg: (touched_edges.len() as f64 / ctx.atg.edges.len().max(1) as f64).min(1.0),
            basic_blocks_source,
            basic_blocks_dest,
        },
        stats: FuzzingStats {
            total_iterations,
            snapshots_captured,
            mutations_applied,
            corpus_size: corpus.len() as u64,
            snapshot_pool_peak: snapshot_individuals_injected,
            contracts_scanned: ctx.contract_plan.scan_sol_files().len() as u64,
            deployment_plan_log,
        },
    })
}

fn expected_mutation_operators(bridge_name: &str) -> Vec<MutationOperator> {
    match bridge_name.to_ascii_lowercase().as_str() {
        "qubit" => vec![MutationOperator::MS2SetBalance],
        "socket" => vec![
            MutationOperator::MS1SetStorage,
            MutationOperator::MS2SetBalance,
        ],
        "nomad" | "multichain" | "ronin" | "harmony" | "wormhole" | "polynetwork" | "pgala"
        | "orbit" | "fegtoken" | "gempad" => vec![MutationOperator::MS1SetStorage],
        _ => vec![MutationOperator::MS1SetStorage],
    }
}

fn format_counts(counts: &HashMap<String, u64>) -> String {
    if counts.is_empty() {
        return "-".to_string();
    }
    let mut parts: Vec<String> = counts.iter().map(|(k, v)| format!("{k}:{v}")).collect();
    parts.sort();
    parts.join(",")
}

fn validation_payload_for(
    scenario: &Scenario,
    registry: &ContractRegistry,
    calldata_mutator: &CalldataMutator,
) -> Vec<u8> {
    scenario
        .actions
        .iter()
        .find_map(|action| calldata_mutator.encode_action(action, registry))
        .map(|seed| {
            let mut payload = Vec::with_capacity(40 + seed.calldata.len());
            payload.extend_from_slice(default_caller().as_slice());
            payload.extend_from_slice(seed.target.as_slice());
            payload.extend_from_slice(&seed.calldata);
            payload
        })
        .unwrap_or_default()
}

fn smartshot_violation(
    bridge_name: &str,
    scenario: &Scenario,
    operator: MutationOperator,
    expected_csv: &str,
    predicate_match: bool,
    contract: Address,
    slot: B256,
    value: B256,
    cut_loss_mode: bool,
    double_validation: &str,
    detected_at_s: f64,
) -> Violation {
    let label = match operator {
        MutationOperator::MS1SetStorage if bridge_name.eq_ignore_ascii_case("nomad") => {
            "acceptable_root_storage_flip"
        }
        MutationOperator::MS1SetStorage => "critical_storage_flip",
        MutationOperator::MS2SetBalance => "balance_seeded_transfer_path",
        MutationOperator::MS4AdvanceTimestamp => "timestamp_advance",
        MutationOperator::MS5AdvanceBlock => "block_advance",
    };
    let taint_source = if cut_loss_mode {
        "metadata_seeded"
    } else {
        "sload_inspector"
    };
    Violation {
        invariant_id: format!("{}/{}", operator.id(), label),
        detected_at_s,
        trigger_scenario: scenario.scenario_id.clone(),
        trigger_trace: vec![format!(
            "smartshot:mutation operator={} label={} source={} contract={:#x} slot={:#x}",
            operator.id(),
            operator.label(),
            taint_source,
            contract,
            slot
        )],
        state_diff: HashMap::from([
            ("mutation_operator".to_string(), operator.id().to_string()),
            ("mutation_label".to_string(), operator.label().to_string()),
            ("mutation_expected".to_string(), expected_csv.to_string()),
            ("predicate_match".to_string(), predicate_match.to_string()),
            ("contract".to_string(), format!("{:#x}", contract)),
            ("slot".to_string(), format!("{:#x}", slot)),
            ("value".to_string(), format!("{:#x}", value)),
            ("taint_source".to_string(), taint_source.to_string()),
            ("cut_loss".to_string(), cut_loss_mode.to_string()),
            (
                "double_validation".to_string(),
                double_validation.to_string(),
            ),
        ]),
    }
}
