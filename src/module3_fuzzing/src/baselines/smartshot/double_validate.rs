//! SmartShot double-validation wrapper.

use crate::contract_loader::ChainSide;
use crate::coverage_tracker::CoverageTracker;
use crate::dual_evm::DualEvm;

use super::mutable_snapshot::MutableSnapshot;
use super::snapshot_mutate::{apply_snapshot_mutation, restore_original};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleValidationStatus {
    Validated,
    RejectedNoValidationPayload,
    RejectedMutationDidNotTrigger,
    RejectedOriginalDidNotFail,
    RejectedDifferentFailure,
}

impl DoubleValidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DoubleValidationStatus::Validated => "validated",
            DoubleValidationStatus::RejectedNoValidationPayload => "rejected_no_validation_payload",
            DoubleValidationStatus::RejectedMutationDidNotTrigger => {
                "rejected_mutation_did_not_trigger"
            }
            DoubleValidationStatus::RejectedOriginalDidNotFail => "rejected_original_did_not_fail",
            DoubleValidationStatus::RejectedDifferentFailure => "rejected_different_failure",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DoubleValidationResult {
    pub mutation_applied: bool,
    pub status: DoubleValidationStatus,
}

/// Execute the same payload on mutated and original state.
///
/// Per SmartShot's double-validation step, a report is kept only when
/// the same payload still triggers the violation after restoring the
/// original snapshot. If the mutation alone introduced the failure, the
/// candidate is discarded as synthetic.
pub fn run_with_double_validation(
    dual: &mut DualEvm,
    snap: &MutableSnapshot,
    chain: Option<ChainSide>,
    scenario_payload: &[u8],
) -> DoubleValidationResult {
    let Some(chain) = chain else {
        return DoubleValidationResult {
            mutation_applied: false,
            status: DoubleValidationStatus::RejectedNoValidationPayload,
        };
    };
    if scenario_payload.is_empty() {
        return DoubleValidationResult {
            mutation_applied: false,
            status: DoubleValidationStatus::RejectedNoValidationPayload,
        };
    }

    let mutation_applied = apply_snapshot_mutation(dual, snap);
    let mutated_failure = if mutation_applied {
        validation_failure(dual, chain, scenario_payload)
    } else {
        None
    };

    restore_original(dual, snap);
    let original_failure = validation_failure(dual, chain, scenario_payload);
    restore_original(dual, snap);

    DoubleValidationResult {
        mutation_applied,
        status: classify_double_validation(mutated_failure.as_deref(), original_failure.as_deref()),
    }
}

fn classify_double_validation(
    mutated_failure: Option<&str>,
    original_failure: Option<&str>,
) -> DoubleValidationStatus {
    match (mutated_failure, original_failure) {
        (Some(m), Some(o)) if m == o => DoubleValidationStatus::Validated,
        (Some(_), Some(_)) => DoubleValidationStatus::RejectedDifferentFailure,
        (Some(_), None) => DoubleValidationStatus::RejectedOriginalDidNotFail,
        _ => DoubleValidationStatus::RejectedMutationDidNotTrigger,
    }
}

fn validation_failure(dual: &mut DualEvm, chain: ChainSide, payload: &[u8]) -> Option<String> {
    let mut tracker = CoverageTracker::default();
    let outcome = match chain {
        ChainSide::Source => dual.execute_on_source_with_inspector_full(payload, &mut tracker),
        ChainSide::Destination => dual.execute_on_dest_with_inspector_full(payload, &mut tracker),
        ChainSide::Relay => return None,
    };

    match outcome {
        Ok(out) if out.success => None,
        Ok(out) => Some(normalize_failure_status(&out.status)),
        Err(e) => Some(normalize_failure_status(&e)),
    }
}

fn normalize_failure_status(status: &str) -> String {
    if status.starts_with("reverted:") || status.starts_with("execution reverted:") {
        "reverted".to_string()
    } else if status.starts_with("halted:") || status.starts_with("execution halted:") {
        status
            .split_once(':')
            .map(|(_, reason)| format!("halted:{}", reason.trim()))
            .unwrap_or_else(|| "halted".to_string())
    } else {
        "execution_error".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(DoubleValidationStatus::Validated.as_str(), "validated");
        assert_eq!(
            DoubleValidationStatus::RejectedNoValidationPayload.as_str(),
            "rejected_no_validation_payload"
        );
        assert_eq!(
            DoubleValidationStatus::RejectedMutationDidNotTrigger.as_str(),
            "rejected_mutation_did_not_trigger"
        );
        assert_eq!(
            DoubleValidationStatus::RejectedOriginalDidNotFail.as_str(),
            "rejected_original_did_not_fail"
        );
        assert_eq!(
            DoubleValidationStatus::RejectedDifferentFailure.as_str(),
            "rejected_different_failure"
        );
    }

    #[test]
    fn classification_matches_smartshot_double_validation() {
        assert_eq!(
            classify_double_validation(Some("reverted"), Some("reverted")),
            DoubleValidationStatus::Validated
        );
        assert_eq!(
            classify_double_validation(Some("reverted"), None),
            DoubleValidationStatus::RejectedOriginalDidNotFail
        );
        assert_eq!(
            classify_double_validation(None, Some("reverted")),
            DoubleValidationStatus::RejectedMutationDidNotTrigger
        );
        assert_eq!(
            classify_double_validation(None, None),
            DoubleValidationStatus::RejectedMutationDidNotTrigger
        );
        assert_eq!(
            classify_double_validation(Some("reverted"), Some("halted:OutOfGas")),
            DoubleValidationStatus::RejectedDifferentFailure
        );
    }
}
