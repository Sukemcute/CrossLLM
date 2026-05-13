use crate::types::Scenario;
use rand::rngs::StdRng;
use rand::Rng;

/// Linear ranking selection based on fitness.
/// Probability of selecting seed S: P(S) = Fitness(S) / Σ Fitness
pub fn pick_corpus_index_vulseye(fitnesses: &[f64], rng: &mut StdRng) -> usize {
    if fitnesses.is_empty() {
        return 0;
    }
    let eff: Vec<f64> = fitnesses.iter().map(|w| w.max(1e-9)).collect();
    let sum: f64 = eff.iter().sum();
    if sum <= 0.0 {
        return rng.gen_range(0..fitnesses.len());
    }
    let mut r = rng.gen::<f64>() * sum;
    for (i, w) in eff.iter().enumerate() {
        r -= w;
        if r <= 0.0 {
            return i;
        }
    }
    fitnesses.len() - 1
}

/// Crossover uses read-after-write dependency on storage variables.
/// At the scenario level, we splice two seeds at a CALL/SSTORE boundary
/// to mix transaction sequences.
pub fn crossover_raw(parent1: &Scenario, parent2: &Scenario, rng: &mut StdRng) -> Scenario {
    let mut child = parent1.clone();
    if parent1.actions.is_empty() || parent2.actions.is_empty() {
        return child;
    }

    // Splice two seeds at an action boundary.
    // In full VulSEye this uses a data-dependency graph, but for scenario
    // fuzzing, action sequences are the dependency units.
    let split1 = rng.gen_range(0..=parent1.actions.len());
    let split2 = rng.gen_range(0..=parent2.actions.len());

    let mut new_actions = parent1.actions[..split1].to_vec();
    new_actions.extend_from_slice(&parent2.actions[split2..]);

    // If empty after slice, just fall back to parent1
    if new_actions.is_empty() {
        return child;
    }

    // Fix steps
    for (i, a) in new_actions.iter_mut().enumerate() {
        a.step = i as u32;
    }

    child.actions = new_actions;
    child
}
