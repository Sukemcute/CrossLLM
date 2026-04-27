//! Bytecode coverage tracker based on revm Inspector hooks.
//!
//! Tracks unique program counters (PCs) reached during execution.

use std::collections::HashSet;

use revm::interpreter::Interpreter;
use revm::{Database, EvmContext, Inspector};

#[derive(Default, Debug, Clone)]
pub struct CoverageTracker {
    pcs: HashSet<usize>,
}

impl CoverageTracker {
    pub fn into_pcs(self) -> HashSet<usize> {
        self.pcs
    }
}

impl<DB: Database> Inspector<DB> for CoverageTracker {
    fn step(&mut self, interp: &mut Interpreter, _ctx: &mut EvmContext<DB>) {
        self.pcs.insert(interp.program_counter());
    }
}

