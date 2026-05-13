//! VulSEye re-implementation — stateful directed graybox fuzzer.
//!
//! See `docs/REIMPL_VULSEYE_SPEC.md` for the full design contract.
//!
//! Modules:
//! - `code_targets` — CFG construction + Algorithm 1 (VS2)
//! - `patterns` — GP1-7 + BP1-6 pattern matchers (VS2)
//! - `state_targets` — concrete-trace state-target approximation (VS3)

pub mod code_targets;
pub mod fitness;
pub mod fuzz_loop_vulseye;
pub mod ga_select;
pub mod patterns;
pub mod state_targets;

pub use code_targets::{identify_code_targets, Cfg, CodeTarget};
pub use fitness::{calculate_fitness, compute_state_distance, CodeDistanceMap};
pub use fuzz_loop_vulseye::run_vulseye;
pub use ga_select::{crossover_raw, pick_corpus_index_vulseye};
pub use patterns::{all_patterns, VulPattern};
pub use state_targets::{
    identify_state_targets_static, state_target_distance, ConcreteTraceCollector, StateTarget,
    StateTargetMap, ValueConstraint,
};
