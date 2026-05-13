//! SmartShot double-validation wrapper.

use crate::dual_evm::DualEvm;

use super::mutable_snapshot::MutableSnapshot;
use super::snapshot_mutate::{apply_snapshot_mutation, restore_original};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleValidationStatus {
    Validated,
    Discarded,
    MetadataSeeded,
}

impl DoubleValidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DoubleValidationStatus::Validated => "validated",
            DoubleValidationStatus::Discarded => "discarded",
            DoubleValidationStatus::MetadataSeeded => "metadata_seeded",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DoubleValidationResult {
    pub mutation_applied: bool,
    pub status: DoubleValidationStatus,
}

/// Base implementation of SmartShot's double-validation step.
///
/// The current BridgeSentry baseline checker does not expose a small pure
/// predicate for individual SmartShot MS targets, so this wrapper validates
/// the operational part: the mutated run must be applicable, then the caller
/// decides whether the benchmark predicate is metadata-seeded or fully
/// validated. It always restores the original snapshot before returning.
pub fn run_with_double_validation(
    dual: &mut DualEvm,
    snap: &MutableSnapshot,
    metadata_seeded: bool,
) -> DoubleValidationResult {
    let mutation_applied = apply_snapshot_mutation(dual, snap);
    restore_original(dual, snap);
    DoubleValidationResult {
        mutation_applied,
        status: if !mutation_applied {
            DoubleValidationStatus::Discarded
        } else if metadata_seeded {
            DoubleValidationStatus::MetadataSeeded
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
        assert_eq!(DoubleValidationStatus::Discarded.as_str(), "discarded");
        assert_eq!(
            DoubleValidationStatus::MetadataSeeded.as_str(),
            "metadata_seeded"
        );
    }
}
