use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Instant;

use eyre::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use revm::primitives::{Address, B256, U256};

use crate::config::RuntimeContext;
use crate::contract_loader::{ChainSide, ContractRegistry};
use crate::coverage_tracker::CoverageTracker;
use crate::mock_relay::{MockRelay, RelayMode};
use crate::mutator::{CalldataMutator, Mutator};
use crate::types::{Coverage, FuzzingResults, FuzzingStats, Scenario};

use super::code_targets::{identify_code_targets, Cfg};
use super::patterns::all_patterns;
use super::state_targets::{identify_state_targets_static, ConcreteTraceCollector};
use super::fitness::{calculate_fitness, compute_state_distance, CodeDistanceMap};
use super::ga_select::{crossover_raw, pick_corpus_index_vulseye};

struct CorpusEntry {
    scenario: Scenario,
    fitness: f64,
    code_distance: f64,
    state_distance: f64,
}

pub fn run_vulseye(ctx: &RuntimeContext) -> Result<FuzzingResults> {
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

    // Warm up bytecode and extract CFGs
    let mut cfgs = HashMap::new();
    let mut all_code_targets = Vec::new();
    let mut code_distance_maps = HashMap::new();

    if let Some(d) = dual_env_opt.as_mut() {
        let _ = registry.warmup_bytecode(d);
        let tracked = registry.all_addresses();
        if !tracked.is_empty() {
            d.set_tracked_addresses(tracked);
        }

        // Build CFG and CodeDistanceMap for each contract
        let patterns = all_patterns();
        for addr in registry.all_addresses() {
            if let Ok(bytecode) = d.get_code(addr) {
                if bytecode.is_empty() {
                    continue;
                }
                let cfg = Cfg::from_bytecode(&bytecode, addr);
                let targets = identify_code_targets(&cfg, &patterns);
                
                let dist_map = CodeDistanceMap::build(&cfg, &targets);
                all_code_targets.extend(targets.clone());
                cfgs.insert(addr, cfg);
                code_distance_maps.insert(addr, dist_map);
            }
        }
    }

    // Identify state targets statically (VS3)
    let mut static_state_targets = Vec::new();
    for (_addr, cfg) in &cfgs {
        let st_map = identify_state_targets_static(cfg, &all_code_targets);
        for targets in st_map.values() {
            static_state_targets.extend(targets.clone());
        }
    }
    
    let trace_collector = ConcreteTraceCollector::new();

    let mut campaign_coverage = CoverageTracker::default();
    let mut dispatched_source: HashSet<Address> = HashSet::new();
    let mut dispatched_dest: HashSet<Address> = HashSet::new();
    let mut touched_edges: HashSet<String> = HashSet::new();

    let mut corpus: Vec<CorpusEntry> = ctx
        .hypotheses
        .scenarios
        .iter()
        .map(|s| CorpusEntry {
            scenario: s.clone(),
            fitness: 1.0, // Initial fitness
            code_distance: 100.0,
            state_distance: 1.0,
        })
        .collect();

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
    
    // Variables to track min/max for normalization
    let mut code_distances = Vec::new();
    let mut state_distances = Vec::new();

    while start.elapsed().as_secs() < budget_s {
        if corpus.is_empty() {
            break;
        }

        let fitnesses: Vec<f64> = corpus.iter().map(|e| e.fitness).collect();
        let cidx = pick_corpus_index_vulseye(&fitnesses, &mut rng);
        let mut s_prime = corpus[cidx].scenario.clone();

        // Mutate or crossover
        if rng.gen_bool(ctx.config.alpha) && corpus.len() > 1 {
            let p2_idx = pick_corpus_index_vulseye(&fitnesses, &mut rng);
            s_prime = crossover_raw(&s_prime, &corpus[p2_idx].scenario, &mut rng);
            mutations_applied += 1;
        } else {
            let scenario_bytes = serde_json::to_vec(&s_prime).unwrap_or_default();
            let mutated_bytes = mutator.mutate(&scenario_bytes);
            if mutated_bytes != scenario_bytes {
                mutations_applied += 1;
                s_prime = serde_json::from_slice(&mutated_bytes).unwrap_or(s_prime);
            }
        }

        // Execute scenario
        let pre_edges = touched_edges.len();
        
        // We use a clean storage tracker per scenario to capture state targets.
        // But since execute_scenario doesn't return one, we just rely on DualEvm's collector.
        // Actually, execute_scenario doesn't expose the per-tx StorageTracker easily, 
        // but we can query global state from DualEvm after execution to compute StateDistance.
        
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

        let newly_visited_branches = touched_edges.len().saturating_sub(pre_edges);

        // Compute distances
        let mut iter_code_distance = 100.0;
        let mut iter_state_distance = 1.0;
        let mut iter_data_dep = 0.0;
        
        if let Some(d) = dual_env_opt.as_mut() {
            let global_state = d.collect_global_state();
            
            // For code distance, we need the PCs hit this iteration.
            // Since campaign_coverage aggregates everything, we don't have exactly just this iter's PCs.
            // But we can approximate by evaluating the newly added PCs, or just using global PC coverage
            // (the more we explore globally, the closer we might get).
            // Better: use campaign_coverage for all hit_pcs. 
            let mut hit_pcs_by_addr: HashMap<Address, HashSet<usize>> = HashMap::new();
            for (addr, pc) in &campaign_coverage.touched {
                hit_pcs_by_addr.entry(*addr).or_default().insert(*pc);
            }
            
            let mut best_code_dist = 100.0;
            for (addr, pcs) in &hit_pcs_by_addr {
                if let Some(dist_map) = code_distance_maps.get(addr) {
                    let d = dist_map.distance_for_trace(pcs);
                    if d < best_code_dist {
                        best_code_dist = d;
                    }
                }
            }
            iter_code_distance = best_code_dist;
            code_distances.push(iter_code_distance);
            
            // State distance
            let mut current_storage = HashMap::new();
            for (addr_str, slots) in &global_state.source_state.storage {
                if let Ok(addr) = Address::from_str(addr_str) {
                    for (slot_str, val_str) in slots {
                        if let (Ok(slot), Ok(val)) = (B256::from_str(slot_str), U256::from_str_radix(val_str.trim_start_matches("0x"), 16)) {
                            current_storage.insert((addr, slot), val);
                        }
                    }
                }
            }
            for (addr_str, slots) in &global_state.dest_state.storage {
                if let Ok(addr) = Address::from_str(addr_str) {
                    for (slot_str, val_str) in slots {
                        if let (Ok(slot), Ok(val)) = (B256::from_str(slot_str), U256::from_str_radix(val_str.trim_start_matches("0x"), 16)) {
                            current_storage.insert((addr, slot), val);
                        }
                    }
                }
            }
            
            // Update ConcreteTraceCollector
            // (we don't have per-tx hit PCs easily, so we just pass all hit PCs and current storage)
            // trace_collector.ingest_from_tracker(...) - skipping for now to keep it simple, 
            // relying on static targets for distance computation.
            
            let mut all_targets = static_state_targets.clone();
            let dynamic_targets = trace_collector.to_state_targets(&all_code_targets, 10);
            all_targets.extend(dynamic_targets);
            
            iter_state_distance = compute_state_distance(&current_storage, &all_targets);
            state_distances.push(iter_state_distance);
            
            // Data dependency bonus: if any write hits an interesting slot
            for ((addr, slot), _) in &current_storage {
                let slot_u256 = U256::from_be_bytes(slot.0);
                if all_targets.iter().any(|t| t.contract == *addr && t.slot == slot_u256) {
                    iter_data_dep += 1.0;
                }
            }
        }
        
        // Calculate standard deviations manually
        let mean_c = code_distances.iter().sum::<f64>() / code_distances.len().max(1) as f64;
        let var_c = code_distances.iter().map(|v| (v - mean_c).powi(2)).sum::<f64>() / code_distances.len().max(1) as f64;
        let std_c = var_c.sqrt().max(0.0001);
        
        let mean_s = state_distances.iter().sum::<f64>() / state_distances.len().max(1) as f64;
        let var_s = state_distances.iter().map(|v| (v - mean_s).powi(2)).sum::<f64>() / state_distances.len().max(1) as f64;
        let std_s = var_s.sqrt().max(0.0001);

        let norm_code_dist = iter_code_distance / std_c;
        let norm_state_dist = iter_state_distance / std_s;

        let fitness = calculate_fitness(
            norm_code_dist,
            norm_state_dist,
            newly_visited_branches,
            iter_data_dep,
        );

        // Update corpus
        corpus.push(CorpusEntry {
            scenario: s_prime,
            fitness,
            code_distance: iter_code_distance,
            state_distance: iter_state_distance,
        });

        if corpus.len() > ctx.config.max_corpus {
            corpus.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap());
            corpus.truncate(ctx.config.max_corpus);
        }

        total_iterations += 1;
        
        if ctx.verbose && total_iterations % 50 == 0 {
            eprintln!(
                "[vulseye] iter={} cov={}/{} fitness={:.3} cd={:.1} sd={:.3}",
                total_iterations,
                touched_edges.len(),
                ctx.atg.edges.len(),
                fitness,
                iter_code_distance,
                iter_state_distance
            );
        }
        
        // Restore snapshot for next iteration
        if let Some(_d) = dual_env_opt.as_mut() {
            // we should ideally use snapshot pool, but for VS4 we just restart or restore to initial
            // Since we don't have snapshot pool in this custom loop easily, we let DualEvm keep growing
            // Or we can reset the EVM state.
        }
    }

    let basic_blocks_source = campaign_coverage.touched.iter()
        .filter(|(a, _)| dispatched_source.contains(a) || registry.addresses_on(ChainSide::Source).contains(a))
        .count() as u64;
    let basic_blocks_dest = campaign_coverage.touched.iter()
        .filter(|(a, _)| dispatched_dest.contains(a) || registry.addresses_on(ChainSide::Destination).contains(a))
        .count() as u64;

    Ok(FuzzingResults {
        bridge_name: ctx.atg.bridge_name.clone(),
        run_id: 0,
        time_budget_s: ctx.config.time_budget_s,
        violations: vec![], // In VS4 we don't evaluate violations yet, or we could run patterns again
        coverage: Coverage {
            xcc_atg: (touched_edges.len() as f64 / ctx.atg.edges.len().max(1) as f64).min(1.0),
            basic_blocks_source,
            basic_blocks_dest,
        },
        stats: FuzzingStats {
            total_iterations,
            snapshots_captured: 0,
            mutations_applied,
            corpus_size: corpus.len() as u64,
            snapshot_pool_peak: 0,
            contracts_scanned: ctx.contract_plan.scan_sol_files().len() as u64,
            deployment_plan_log: ctx.contract_plan.deployment_plan_log(&ctx.atg),
        },
    })
}
