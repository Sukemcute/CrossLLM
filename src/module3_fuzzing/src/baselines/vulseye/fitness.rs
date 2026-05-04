use std::collections::{HashMap, HashSet};
use revm::primitives::{Address, B256, U256};
use crate::baselines::vulseye::code_targets::{Cfg, CodeTarget};
use crate::baselines::vulseye::state_targets::{StateTarget, state_target_distance};

/// Precomputed distances from every basic block to the nearest CodeTarget.
#[derive(Clone, Debug)]
pub struct CodeDistanceMap {
    /// bb_id -> distance (number of edges to the closest CodeTarget).
    distances: HashMap<usize, f64>,
}

impl CodeDistanceMap {
    /// Build the map by running a backward BFS from all code target BBs.
    pub fn build(cfg: &Cfg, targets: &[CodeTarget]) -> Self {
        let mut distances = HashMap::new();
        // For BFS: queue of (bb_id, dist)
        let mut queue = std::collections::VecDeque::new();

        // Initialize queue with all code targets at distance 0
        for ct in targets {
            distances.insert(ct.bb_id, 0.0);
            queue.push_back((ct.bb_id, 0.0));
        }

        // Backward BFS
        while let Some((curr_bb, dist)) = queue.pop_front() {
            for pred in cfg.predecessors(curr_bb) {
                if !distances.contains_key(&pred) {
                    let next_dist = dist + 1.0;
                    distances.insert(pred, next_dist);
                    queue.push_back((pred, next_dist));
                }
            }
        }

        Self { distances }
    }

    /// Minimum distance from the executed path (set of hit BBs) to any code target.
    /// Returns 100.0 if no code target is reachable (as per VulSEye repo fallback).
    pub fn distance_for_trace(&self, hit_bbs: &HashSet<usize>) -> f64 {
        let mut min_dist = f64::MAX;
        let mut found_reachable = false;
        
        // VulSEye computes mean of top 5 lowest distance basic blocks in python:
        // transaction_distance.append(np.mean(sorted(basic_block_distances)[:set_min]))
        // Let's replicate this accurately to match their paper/repo:
        let mut bb_distances: Vec<f64> = hit_bbs
            .iter()
            .filter_map(|bb| self.distances.get(bb).copied())
            .collect();
            
        if bb_distances.is_empty() {
            return 100.0;
        }
        
        bb_distances.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let take = bb_distances.len().min(5);
        let sum: f64 = bb_distances.iter().take(take).sum();
        sum / (take as f64)
    }
}

/// Compute StateDistance per Eq 5 and the python repo.
/// Lower is better. If all targets met (find_zero), returns 1.0.
pub fn compute_state_distance(
    current_storage: &HashMap<(Address, B256), U256>,
    state_targets: &[StateTarget],
) -> f64 {
    if state_targets.is_empty() {
        return 1.0; // Same as repo: not self.state_distance -> indv.state_distance = 1
    }

    let mut sum_inverse = 0.0;
    let mut all_met = false;

    // In python, state targets are grouped by target BB (and paths).
    // For simplicity with our linear StateTarget slice:
    for st in state_targets {
        let dist = state_target_distance(st, current_storage);
        if dist <= 0.001 {
            all_met = true;
            break;
        }
        sum_inverse += 1.0 / dist;
    }

    if all_met || sum_inverse <= 0.0001 {
        1.0
    } else {
        (state_targets.len() as f64) / sum_inverse
    }
}

/// Computes the final Eq 8 Fitness for an execution iteration.
/// 
/// `norm_code_dist` and `norm_state_dist` should be `code_distance / std_dev` across corpus.
/// Since we need these std deviations, we can just pass them in or calculate online.
/// To keep it stateless, we'll pass the normalized distances directly.
pub fn calculate_fitness(
    norm_code_dist: f64,
    norm_state_dist: f64,
    newly_visited_branches: usize,
    data_dep_score: f64,
) -> f64 {
    // Eq. 8 and python matching:
    // final_score = 1 / (0.5 * normalized_code_distance + 0.5 * normalized_state_distance + 0.1)
    let final_score = 1.0 / (0.5 * norm_code_dist + 0.5 * norm_state_dist + 0.1);
    
    // score = (block_coverage_fitness + data_dependency_fitness) * 0.015
    let coverage_score = newly_visited_branches as f64;
    let score = (coverage_score + data_dep_score) * 0.015;
    
    // fitness = final_score + score
    final_score + score
}
