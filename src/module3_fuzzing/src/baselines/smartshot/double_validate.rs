//! SmartShot double-validation wrapper.

use crate::dual_evm::DualEvm;

use super::mutable_snapshot::MutableSnapshot;
use super::snapshot_mutate::{apply_snapshot_mutation, restore_original};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleValidationStatus {
    Validated,
    RejectedNoValidationPayload,
    RejectedMutationDidNotTrigger,
    RejectedOriginalDidNotFail,
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
    scenario_payload: &[u8],
) -> DoubleValidationResult {
    if scenario_payload.is_empty() {
        return DoubleValidationResult {
            mutation_applied: false,
            status: DoubleValidationStatus::RejectedNoValidationPayload,
        };
    }

    let mutation_applied = apply_snapshot_mutation(dual, snap);
    let mutated_failed = if mutation_applied {
        dual.execute_on_source(scenario_payload).is_err()
    } else {
        false
    };

    restore_original(dual, snap);
    let original_failed = dual.execute_on_source(scenario_payload).is_err();
    restore_original(dual, snap);

    DoubleValidationResult {
        mutation_applied,
        status: classify_double_validation(mutated_failed, original_failed),
    }
}

fn classify_double_validation(
    mutated_failed: bool,
    original_failed: bool,
) -> DoubleValidationStatus {
    match (mutated_failed, original_failed) {
        (true, true) => DoubleValidationStatus::Validated,
        (true, false) => DoubleValidationStatus::RejectedOriginalDidNotFail,
        _ => DoubleValidationStatus::RejectedMutationDidNotTrigger,
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
    }

    #[test]
    fn classification_matches_smartshot_double_validation() {
        assert_eq!(
            classify_double_validation(true, true),
            DoubleValidationStatus::Validated
        );
        assert_eq!(
            classify_double_validation(true, false),
            DoubleValidationStatus::RejectedOriginalDidNotFail
        );
        assert_eq!(
            classify_double_validation(false, true),
            DoubleValidationStatus::RejectedMutationDidNotTrigger
        );
        assert_eq!(
            classify_double_validation(false, false),
            DoubleValidationStatus::RejectedMutationDidNotTrigger
        );
    }
}
