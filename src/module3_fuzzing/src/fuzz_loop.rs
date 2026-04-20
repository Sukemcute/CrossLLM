//! Algorithm 1 style fuzzing loop: corpus, reward-weighted seeding, snapshot pool, restore/mutate/execute.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::time::Instant;

use eyre::{eyre, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use revm::primitives::Address;

use crate::checker::InvariantChecker;
use crate::config::RuntimeContext;
use crate::dual_evm::{default_caller, DualEvm};
use crate::mock_relay::{MockRelay, RelayMode};
use crate::mutator::Mutator;
use crate::snapshot::{action_fingerprint, SnapshotPool};
use crate::types::{ChainState, Coverage, FuzzingResults, FuzzingStats, Scenario, Violation};

struct CorpusEntry {
    scenario: Scenario,
    weight: f64,
}

fn scenario_fingerprint_hash(s: &Scenario) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.scenario_id.hash(&mut h);
    serde_json::to_string(&s.actions).unwrap_or_default().hash(&mut h);
    h.finish()
}

fn pick_corpus_index(weights: &[f64], rng: &mut StdRng) -> usize {
    if weights.is_empty() {
        return 0;
    }
    let eff: Vec<f64> = weights.iter().map(|w| w.max(1e-9)).collect();
    let sum: f64 = eff.iter().sum();
    if sum <= 0.0 {
        return rng.gen_range(0..weights.len());
    }
    let mut r = rng.gen::<f64>() * sum;
    for (i, w) in eff.iter().enumerate() {
        r -= w;
        if r <= 0.0 {
            return i;
        }
    }
    weights.len() - 1
}

pub fn init_dual_evm(ctx: &RuntimeContext) -> Option<DualEvm> {
    if ctx.config.source_rpc.trim().is_empty() || ctx.config.dest_rpc.trim().is_empty() {
        return None;
    }
    if ctx.config.source_block == 0 || ctx.config.dest_block == 0 {
        return None;
    }

    let mut dual = match DualEvm::new(
        &ctx.config.source_rpc,
        &ctx.config.dest_rpc,
        ctx.config.source_block,
        ctx.config.dest_block,
    ) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("WARNING: Dual-EVM init failed, fallback to synthetic state: {err}");
            return None;
        }
    };

    let tracked: Vec<Address> = ctx
        .atg
        .nodes
        .iter()
        .filter_map(|n| Address::from_str(&n.address).ok())
        .collect();
    dual.set_tracked_addresses(tracked);
    Some(dual)
}

pub fn run(ctx: &RuntimeContext) -> Result<FuzzingResults> {
    let mutator = Mutator::with_atg(&ctx.atg);
    let mut checker = InvariantChecker::new(
        ctx.atg.invariants.clone(),
        ctx.config.alpha,
        ctx.config.beta,
        ctx.config.gamma,
    );

    let mut alpha = ctx.config.alpha;
    let mut beta = ctx.config.beta;
    let mut gamma = ctx.config.gamma;

    let mut relay = MockRelay::new(RelayMode::Faithful);
    let mut dual = init_dual_evm(ctx);

    let mut corpus: Vec<CorpusEntry> = ctx
        .hypotheses
        .scenarios
        .iter()
        .map(|s| CorpusEntry {
            scenario: s.clone(),
            weight: s.confidence.max(0.1),
        })
        .collect();

    let mut seen_hashes: HashSet<u64> = corpus
        .iter()
        .map(|e| scenario_fingerprint_hash(&e.scenario))
        .collect();

    let mut pool = SnapshotPool::new();
    pool.capture(dual.as_ref(), &relay, 0, vec![]);

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

    let mut violations = Vec::new();
    let mut violation_keys: HashSet<(String, String)> = HashSet::new();
    let mut touched_edges: HashSet<String> = HashSet::new();
    let mut total_iterations = 0_u64;
    let mut mutations_applied = 0_u64;
    let mut snapshots_captured_count: u64 = pool.len() as u64;
    let mut pool_peak = pool.len() as u64;

    let mut iter_checkpoint = 0u64;
    let mut edges_at_checkpoint = 0usize;

    while start.elapsed().as_secs() < budget_s {
        if corpus.is_empty() {
            break;
        }

        let weights: Vec<f64> = corpus.iter().map(|e| e.weight).collect();
        let cidx = pick_corpus_index(&weights, &mut rng);
        let seed_scenario = corpus[cidx].scenario.clone();

        let scenario_bytes = serde_json::to_vec(&seed_scenario).unwrap_or_default();
        let mutated_bytes = mutator.mutate(&scenario_bytes);
        if mutated_bytes != scenario_bytes {
            mutations_applied = mutations_applied.saturating_add(1);
        }
        let s_prime: Scenario =
            serde_json::from_slice(&mutated_bytes).unwrap_or_else(|_| seed_scenario.clone());

        let snap_idx = pool.select_for_seed(&mutated_bytes);
        pool.restore(snap_idx, dual.as_mut(), &mut relay)
            .map_err(|e| eyre!(e))?;

        let trace = execute_scenario(
            &s_prime,
            ctx,
            &mut dual,
            &mut relay,
            &mut touched_edges,
        );

        let mut state = crate::scenario_sim::global_state_from_scenario(&s_prime);
        state.relay_state = relay.to_relay_snapshot();
        if let Some(d) = dual.as_mut() {
            let onchain = d.collect_global_state();
            merge_balances(&mut state.source_state.balances, onchain.source_state.balances);
            merge_balances(&mut state.dest_state.balances, onchain.dest_state.balances);
        }

        for result in checker.check(&state) {
            if result.violated {
                let key = (result.invariant_id.clone(), s_prime.scenario_id.clone());
                if violation_keys.insert(key) {
                    violations.push(Violation {
                        invariant_id: result.invariant_id,
                        detected_at_s: start.elapsed().as_secs_f64(),
                        trigger_scenario: s_prime.scenario_id.clone(),
                        trigger_trace: trace.clone(),
                        state_diff: HashMap::from([
                            (
                                "source_total".to_string(),
                                total_chain_balance(&state.source_state).to_string(),
                            ),
                            (
                                "dest_total".to_string(),
                                total_chain_balance(&state.dest_state).to_string(),
                            ),
                        ]),
                    });
                }
            }
        }

        let wps = crate::scenario_sim::evaluate_waypoints(&state, &s_prime);
        let total_edges = ctx.atg.edges.len().max(1);
        let cov = (touched_edges.len() as f64 / total_edges as f64).min(1.0);
        let r = checker.reward(cov, &wps, &s_prime.waypoints, &state);

        corpus[cidx].weight *= 1.0 + 0.5 * r;

        if ctx.config.dynamic_snapshots && r > ctx.config.r_threshold {
            let h = scenario_fingerprint_hash(&s_prime);
            if !seen_hashes.contains(&h) && corpus.len() < ctx.config.max_corpus {
                seen_hashes.insert(h);
                corpus.push(CorpusEntry {
                    scenario: s_prime.clone(),
                    weight: r.max(0.1),
                });
            }
            let fingerprints: Vec<String> = s_prime.actions.iter().map(action_fingerprint).collect();
            pool.capture(
                dual.as_ref(),
                &relay,
                s_prime.actions.len(),
                fingerprints,
            );
            pool.evict_oldest_if_over(ctx.config.max_snapshots);
            snapshots_captured_count = snapshots_captured_count.saturating_add(1);
        }

        pool_peak = pool_peak.max(pool.len() as u64);
        total_iterations = total_iterations.saturating_add(1);

        if total_iterations.saturating_sub(iter_checkpoint) >= 100 {
            if touched_edges.len() == edges_at_checkpoint && total_iterations > 100 {
                let saved = alpha * 0.05;
                alpha *= 0.95;
                beta += saved / 2.0;
                gamma += saved / 2.0;
                checker.set_reward_weights(alpha, beta, gamma);
            }
            iter_checkpoint = total_iterations;
            edges_at_checkpoint = touched_edges.len();
        }

        if ctx.verbose && total_iterations % 50 == 0 {
            eprintln!(
                "[fuzz] iter={} cov={:.3} R={:.3} corpus={} pool={} viol={}",
                total_iterations,
                cov,
                r,
                corpus.len(),
                pool.len(),
                violations.len()
            );
        }
    }

    let coverage = Coverage {
        xcc_atg: if ctx.atg.edges.is_empty() {
            0.0
        } else {
            (touched_edges.len() as f64 / ctx.atg.edges.len() as f64).min(1.0)
        },
        basic_blocks_source: total_iterations,
        basic_blocks_dest: total_iterations,
    };

    Ok(FuzzingResults {
        bridge_name: ctx.atg.bridge_name.clone(),
        run_id: 0,
        time_budget_s: ctx.config.time_budget_s,
        violations,
        coverage,
        stats: FuzzingStats {
            total_iterations,
            snapshots_captured: snapshots_captured_count,
            mutations_applied,
            corpus_size: corpus.len() as u64,
            snapshot_pool_peak: pool_peak,
        },
    })
}

fn execute_scenario(
    scenario: &Scenario,
    ctx: &RuntimeContext,
    dual: &mut Option<DualEvm>,
    relay: &mut MockRelay,
    touched_edges: &mut HashSet<String>,
) -> Vec<String> {
    let mut trace = Vec::new();

    for action in &scenario.actions {
        if action.chain.eq_ignore_ascii_case("relay") {
            let mode = match action
                .action
                .as_deref()
                .unwrap_or("faithful")
                .to_ascii_lowercase()
                .as_str()
            {
                "delayed" | "delay" => RelayMode::Delayed {
                    delta_blocks: action
                        .params
                        .get("delta_blocks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(1),
                },
                "tampered" | "tamper" => RelayMode::Tampered,
                "replayed" | "replay" => RelayMode::Replayed,
                _ => RelayMode::Faithful,
            };

            relay.set_mode(mode);
            let relay_payload = serde_json::to_vec(&action.params).unwrap_or_default();
            let relay_result = relay.relay_message(&relay_payload);
            trace.push(format!(
                "relay:{}:{}",
                action.step,
                if relay_result.is_ok() { "ok" } else { "queued_or_err" }
            ));
            continue;
        }

        if let Some(ref mut dual_env) = dual {
            if let Some(contract_node_id) = action.contract.as_deref() {
                if let Some(node) = ctx.atg.nodes.iter().find(|n| n.node_id == contract_node_id) {
                    if let Ok(to) = Address::from_str(&node.address) {
                        let mut payload = Vec::with_capacity(40);
                        payload.extend_from_slice(default_caller().as_slice());
                        payload.extend_from_slice(to.as_slice());
                        let exec = if action.chain.eq_ignore_ascii_case("source") {
                            dual_env.execute_on_source(&payload)
                        } else {
                            dual_env.execute_on_dest(&payload)
                        };
                        trace.push(format!(
                            "tx:{}:{}:{}",
                            action.step,
                            contract_node_id,
                            if exec.is_ok() { "ok" } else { "err" }
                        ));
                    }
                }
            }
        } else {
            trace.push(format!("sim:{}:{}", action.step, action.description));
        }

        for edge in &ctx.atg.edges {
            if let Some(contract) = action.contract.as_deref() {
                if edge.src == contract || edge.dst == contract {
                    touched_edges.insert(edge.edge_id.clone());
                }
            }
        }
    }

    trace
}

fn merge_balances(dst: &mut HashMap<String, String>, src: HashMap<String, String>) {
    for (k, v) in src {
        dst.entry(k).or_insert(v);
    }
}

fn total_chain_balance(chain: &ChainState) -> u128 {
    chain
        .balances
        .values()
        .filter_map(|v| v.parse::<u128>().ok())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_corpus_index_deterministic() {
        let w = vec![1.0, 4.0, 1.0];
        let mut rng = StdRng::seed_from_u64(42);
        let mut counts = vec![0usize; 3];
        for _ in 0..3000 {
            counts[pick_corpus_index(&w, &mut rng)] += 1;
        }
        assert!(counts[1] > counts[0]);
        assert!(counts[1] > counts[2]);
    }
}
