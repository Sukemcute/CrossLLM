//! Re-implementations of the cross-chain bridge baselines whose original
//! tools have no public artefact (paper §5.3 RQ1 — see
//! `docs/PLAN_REIMPL_BASELINES.md`).
//!
//! Each sub-module is the **port of the core detection algorithm** of one
//! paper (XScope ASE 2022, SmartAxe FSE 2024, VulSEye TIFS 2025,
//! SmartShot FSE 2025), wired into BridgeSentry's existing dual-EVM
//! infrastructure. The corresponding spec docs in `docs/REIMPL_<TOOL>_SPEC.md`
//! are the design contract.
//!
//! Currently shipped:
//! * [`xscope`] — six rule-based invariant predicates (X2 milestone).

pub mod xscope;
pub mod xscope_adapter;
