//! VulSEye re-implementation — stateful directed graybox fuzzer.
//!
//! See `docs/REIMPL_VULSEYE_SPEC.md` for the full design contract.
//!
//! Modules:
//! - `code_targets` — CFG construction + Algorithm 1 (VS2)
//! - `patterns` — GP1-7 + BP1-6 pattern matchers (VS2)
//! - `state_targets` — concrete-trace state-target approximation (VS3)

pub mod code_targets;
pub mod patterns;
pub mod state_targets;

pub use code_targets::{Cfg, CodeTarget, identify_code_targets};
pub use patterns::{VulPattern, all_patterns};
pub use state_targets::{
    ConcreteTraceCollector, StateTarget, StateTargetMap, ValueConstraint,
    identify_state_targets_static, state_target_distance,
};
