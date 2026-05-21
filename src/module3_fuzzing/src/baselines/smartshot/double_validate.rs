//! SmartShot double-validation wrapper.

use crate::dual_evm::DualEvm;

use super::mutable_snapshot::MutableSnapshot;
use super::snapshot_mutate::{apply_snapshot_mutation, restore_original};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleValidationStatus {
    Validated,
    RejectedMutationDidNotTrigger,
    RejectedOriginalAlsoFails,
}

impl DoubleValidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DoubleValidationStatus::Validated => "validated",
            DoubleValidationStatus::RejectedMutationDidNotTrigger => {
                "rejected_mutation_did_not_trigger"
            }
            DoubleValidationStatus::RejectedOriginalAlsoFails => "rejected_original_also_fails",
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
/// A mutation is validated only when the mutated execution fails and the
/// original unmutated state executes cleanly.
pub fn run_with_double_validation(
    dual: &mut DualEvm,
    snap: &MutableSnapshot,
    scenario_payload: &[u8],
) -> DoubleValidationResult {
    let mutation_applied = apply_snapshot_mutation(dual, snap);
    let mutated_failed = if mutation_applied {
        dual.execute_on_source(scenario_payload).is_err()
    } else {
        false
    };

    restore_original(dual, snap);
    let original_clean = dual.execute_on_source(scenario_payload).is_ok();
    restore_original(dual, snap);

    DoubleValidationResult {
        mutation_applied,
        status: if !mutated_failed {
            DoubleValidationStatus::RejectedMutationDidNotTrigger
        } else if !original_clean {
            DoubleValidationStatus::RejectedOriginalAlsoFails
        } else {
            DoubleValidationStatus::Validated
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(DoubleValidationStatus::Validated.as_str(), "validated");
        assert_eq!(
            DoubleValidationStatus::RejectedMutationDidNotTrigger.as_str(),
            "rejected_mutation_did_not_trigger"
        );
        assert_eq!(
            DoubleValidationStatus::RejectedOriginalAlsoFails.as_str(),
            "rejected_original_also_fails"
        );
    }
}
