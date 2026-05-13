//! CFG construction from raw EVM bytecode and code-target identification
//! (VulSEye paper Algorithm 1 — `docs/REIMPL_VULSEYE_SPEC.md` §2.1).
//!
//! Lifts deployed bytecode into a basic-block CFG, then runs pattern
//! matchers against each block to locate vulnerability-prone code targets.

use std::collections::{HashMap, HashSet};

use revm::primitives::Address;

use super::patterns::VulPattern;

// ============================================================================
// EVM opcode constants
// ============================================================================

pub mod op {
    pub const STOP: u8 = 0x00;
    pub const ADD: u8 = 0x01;
    pub const SUB: u8 = 0x03;
    pub const LT: u8 = 0x0a;
    pub const GT: u8 = 0x0b;
    pub const EQ: u8 = 0x14;
    pub const ISZERO: u8 = 0x15;
    pub const AND: u8 = 0x16;
    pub const SHA3: u8 = 0x20;
    pub const ADDRESS: u8 = 0x30;
    pub const BALANCE: u8 = 0x31;
    pub const ORIGIN: u8 = 0x32;
    pub const CALLER: u8 = 0x33;
    pub const CALLVALUE: u8 = 0x34;
    pub const CALLDATALOAD: u8 = 0x35;
    pub const CALLDATASIZE: u8 = 0x36;
    pub const CALLDATACOPY: u8 = 0x37;
    pub const BLOCKHASH: u8 = 0x40;
    pub const TIMESTAMP: u8 = 0x42;
    pub const NUMBER: u8 = 0x43;
    pub const SLOAD: u8 = 0x54;
    pub const SSTORE: u8 = 0x55;
    pub const JUMP: u8 = 0x56;
    pub const JUMPI: u8 = 0x57;
    pub const JUMPDEST: u8 = 0x5b;
    pub const PUSH0: u8 = 0x5f;
    pub const PUSH1: u8 = 0x60;
    pub const PUSH32: u8 = 0x7f;
    pub const DUP1: u8 = 0x80;
    pub const LOG0: u8 = 0xa0;
    pub const LOG3: u8 = 0xa3;
    pub const LOG4: u8 = 0xa4;
    pub const CALL: u8 = 0xf1;
    pub const CALLCODE: u8 = 0xf2;
    pub const RETURN: u8 = 0xf3;
    pub const DELEGATECALL: u8 = 0xf4;
    pub const CREATE2: u8 = 0xf5;
    pub const STATICCALL: u8 = 0xfa;
    pub const REVERT: u8 = 0xfd;
    pub const INVALID: u8 = 0xfe;
    pub const SELFDESTRUCT: u8 = 0xff;

    #[inline]
    pub fn is_push(o: u8) -> bool {
        o >= PUSH1 && o <= PUSH32
    }

    #[inline]
    pub fn push_size(o: u8) -> usize {
        (o - PUSH1 + 1) as usize
    }

    #[inline]
    pub fn is_terminator(o: u8) -> bool {
        matches!(
            o,
            STOP | JUMP | JUMPI | RETURN | REVERT | INVALID | SELFDESTRUCT
        )
    }

    #[inline]
    pub fn is_log(o: u8) -> bool {
        o >= LOG0 && o <= LOG4
    }

    #[inline]
    pub fn is_call_family(o: u8) -> bool {
        matches!(o, CALL | CALLCODE | DELEGATECALL | STATICCALL)
    }
}

// ============================================================================
// CFG types
// ============================================================================

/// Single EVM instruction with its program counter and push-immediate data.
#[derive(Clone, Debug)]
pub struct Instruction {
    pub pc: usize,
    pub opcode: u8,
    /// PUSH immediate bytes (empty for non-PUSH instructions).
    pub immediate: Vec<u8>,
}

impl Instruction {
    /// Parse the PUSH immediate as a big-endian usize (for jump targets).
    pub fn push_value_usize(&self) -> Option<usize> {
        if !op::is_push(self.opcode) || self.immediate.is_empty() {
            return None;
        }
        let mut v: usize = 0;
        for &b in &self.immediate {
            v = v.checked_shl(8)?.checked_add(b as usize)?;
        }
        Some(v)
    }
}

/// Basic block in a bytecode CFG.
#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub id: usize,
    pub start_pc: usize,
    /// PC of the last instruction in this block.
    pub end_pc: usize,
    pub instructions: Vec<Instruction>,
}

impl BasicBlock {
    /// Does this block contain the given opcode?
    pub fn contains_opcode(&self, opcode: u8) -> bool {
        self.instructions.iter().any(|i| i.opcode == opcode)
    }

    /// Flat list of opcodes in execution order.
    pub fn opcodes(&self) -> Vec<u8> {
        self.instructions.iter().map(|i| i.opcode).collect()
    }

    /// True if any opcode in `ops` appears in this block.
    pub fn contains_any(&self, ops: &[u8]) -> bool {
        self.instructions.iter().any(|i| ops.contains(&i.opcode))
    }

    /// Return the index *within `instructions`* of the first occurrence.
    pub fn find_index(&self, opcode: u8) -> Option<usize> {
        self.instructions.iter().position(|i| i.opcode == opcode)
    }

    /// Iterator of (index-in-block, &Instruction) for a given opcode.
    pub fn iter_opcode(&self, opcode: u8) -> impl Iterator<Item = (usize, &Instruction)> {
        self.instructions
            .iter()
            .enumerate()
            .filter(move |(_, i)| i.opcode == opcode)
    }
}

/// Control-flow graph lifted from raw EVM bytecode.
#[derive(Clone, Debug)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<(usize, usize)>,
    pub contract_addr: Address,
    jumpdest_to_bb: HashMap<usize, usize>,
}

/// A code target found by pattern matching (Algorithm 1 output row).
#[derive(Clone, Debug)]
pub struct CodeTarget {
    pub pattern_id: String,
    pub bb_id: usize,
    pub pc: usize,
    pub contract: Address,
}

// ============================================================================
// CFG construction
// ============================================================================

impl Cfg {
    /// Build a CFG from raw deployed bytecode.
    pub fn from_bytecode(bytecode: &[u8], addr: Address) -> Self {
        let instructions = parse_instructions(bytecode);

        // --- Split instructions into basic blocks ---
        let mut blocks: Vec<BasicBlock> = Vec::new();
        let mut cur: Vec<Instruction> = Vec::new();
        let mut block_start: usize = 0;

        for inst in &instructions {
            // A JUMPDEST starts a new block (unless it's the very first
            // instruction of the current accumulator).
            if inst.opcode == op::JUMPDEST && !cur.is_empty() {
                let bb_id = blocks.len();
                let end_pc = cur.last().unwrap().pc;
                blocks.push(BasicBlock {
                    id: bb_id,
                    start_pc: block_start,
                    end_pc,
                    instructions: std::mem::take(&mut cur),
                });
                block_start = inst.pc;
            }

            cur.push(inst.clone());

            // Terminators close the current block.
            if op::is_terminator(inst.opcode) {
                let bb_id = blocks.len();
                blocks.push(BasicBlock {
                    id: bb_id,
                    start_pc: block_start,
                    end_pc: inst.pc,
                    instructions: std::mem::take(&mut cur),
                });
                // Next instruction (if any) starts a fresh block.
                block_start = inst.pc + 1; // approximate; corrected below
            }
        }
        // Flush any trailing instructions.
        if !cur.is_empty() {
            let bb_id = blocks.len();
            let end_pc = cur.last().unwrap().pc;
            blocks.push(BasicBlock {
                id: bb_id,
                start_pc: block_start,
                end_pc,
                instructions: cur,
            });
        }

        // Fix up block_start for blocks after terminators — use the actual
        // PC of the first instruction.
        for bb in &mut blocks {
            if let Some(first) = bb.instructions.first() {
                bb.start_pc = first.pc;
            }
        }

        // --- JUMPDEST → bb_id map ---
        let mut jumpdest_to_bb = HashMap::new();
        for bb in &blocks {
            if let Some(first) = bb.instructions.first() {
                if first.opcode == op::JUMPDEST {
                    jumpdest_to_bb.insert(first.pc, bb.id);
                }
            }
        }

        // --- Build edges ---
        let mut edges = Vec::new();
        for i in 0..blocks.len() {
            let last = match blocks[i].instructions.last() {
                Some(l) => l,
                None => continue,
            };
            match last.opcode {
                op::JUMP => {
                    if let Some(target_pc) = resolve_jump_target(&blocks[i].instructions) {
                        if let Some(&tgt) = jumpdest_to_bb.get(&target_pc) {
                            edges.push((i, tgt));
                        }
                    }
                }
                op::JUMPI => {
                    // True branch → PUSH target.
                    if let Some(target_pc) = resolve_jump_target(&blocks[i].instructions) {
                        if let Some(&tgt) = jumpdest_to_bb.get(&target_pc) {
                            edges.push((i, tgt));
                        }
                    }
                    // False branch → fall-through.
                    if i + 1 < blocks.len() {
                        edges.push((i, i + 1));
                    }
                }
                op::STOP | op::RETURN | op::REVERT | op::INVALID | op::SELFDESTRUCT => {
                    // No outgoing edges.
                }
                _ => {
                    // Fall-through.
                    if i + 1 < blocks.len() {
                        edges.push((i, i + 1));
                    }
                }
            }
        }

        Cfg {
            blocks,
            edges,
            contract_addr: addr,
            jumpdest_to_bb,
        }
    }

    /// Predecessor block ids.
    pub fn predecessors(&self, bb_id: usize) -> Vec<usize> {
        self.edges
            .iter()
            .filter(|(_, to)| *to == bb_id)
            .map(|(from, _)| *from)
            .collect()
    }

    /// Successor block ids.
    pub fn successors(&self, bb_id: usize) -> Vec<usize> {
        self.edges
            .iter()
            .filter(|(from, _)| *from == bb_id)
            .map(|(_, to)| *to)
            .collect()
    }

    /// True if any block in the contract contains the opcode.
    pub fn contains_opcode(&self, opcode: u8) -> bool {
        self.blocks.iter().any(|bb| bb.contains_opcode(opcode))
    }

    /// All block ids reachable from `start` within `max_depth` BFS steps.
    pub fn reachable_from(&self, start: usize, max_depth: usize) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut frontier = vec![(start, 0usize)];
        while let Some((bb, depth)) = frontier.pop() {
            if depth > max_depth || !visited.insert(bb) {
                continue;
            }
            for s in self.successors(bb) {
                frontier.push((s, depth + 1));
            }
        }
        visited
    }

    /// All block ids reachable **backward** (via predecessor edges) from
    /// `start` within `max_depth` steps. Used by access-control checks
    /// which need to look at guards that execute *before* a sensitive op.
    pub fn predecessors_within_depth(&self, start: usize, max_depth: usize) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut frontier = vec![(start, 0usize)];
        while let Some((bb, depth)) = frontier.pop() {
            if depth > max_depth || !visited.insert(bb) {
                continue;
            }
            for p in self.predecessors(bb) {
                frontier.push((p, depth + 1));
            }
        }
        visited
    }

    /// Number of basic blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

// ============================================================================
// Algorithm 1: identify code targets
// ============================================================================

/// Run all patterns against the CFG and collect code targets (Algorithm 1).
pub fn identify_code_targets(cfg: &Cfg, patterns: &[Box<dyn VulPattern>]) -> Vec<CodeTarget> {
    let mut targets = Vec::new();
    for pat in patterns {
        let hits = pat.scan(cfg);
        targets.extend(hits);
    }
    // Deduplicate by (pattern_id, pc).
    let mut seen = HashSet::new();
    targets.retain(|t| seen.insert((t.pattern_id.clone(), t.pc)));
    targets
}

// ============================================================================
// Instruction parsing helpers
// ============================================================================

fn parse_instructions(bytecode: &[u8]) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut pc = 0;
    while pc < bytecode.len() {
        let opcode = bytecode[pc];
        let mut immediate = Vec::new();
        if op::is_push(opcode) {
            let sz = op::push_size(opcode);
            let end = (pc + 1 + sz).min(bytecode.len());
            immediate = bytecode[pc + 1..end].to_vec();
        }
        out.push(Instruction {
            pc,
            opcode,
            immediate,
        });
        if op::is_push(opcode) {
            pc += 1 + op::push_size(opcode);
        } else {
            pc += 1;
        }
    }
    out
}

/// Resolve the static jump target from PUSH instructions before a JUMP/JUMPI.
///
/// For `JUMP`: target is top-of-stack → last PUSH (instructions[-2]).
/// For `JUMPI`: target is 2nd stack item (below condition) → we need the
/// PUSH that pushed the target, which is typically instructions[-3] when
/// the pattern is `PUSH target, PUSH cond, JUMPI`. We scan backwards
/// to find the second-to-last PUSH.
fn resolve_jump_target(instructions: &[Instruction]) -> Option<usize> {
    if instructions.len() < 2 {
        return None;
    }
    let last = instructions.last()?;

    if last.opcode == op::JUMP {
        // JUMP consumes 1 stack item → target is the preceding PUSH.
        let push_inst = &instructions[instructions.len() - 2];
        return push_inst.push_value_usize();
    }

    if last.opcode == op::JUMPI {
        // JUMPI consumes 2 stack items: (condition on top, target below).
        // Find the two most recent PUSH instructions before the JUMPI.
        let pushes: Vec<&Instruction> = instructions[..instructions.len() - 1]
            .iter()
            .rev()
            .filter(|i| op::is_push(i.opcode))
            .take(2)
            .collect();
        // pushes[0] = condition PUSH (most recent), pushes[1] = target PUSH.
        if pushes.len() >= 2 {
            return pushes[1].push_value_usize();
        }
        // Fallback: only one PUSH found — treat it as the target.
        if let Some(p) = pushes.first() {
            return p.push_value_usize();
        }
    }

    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assemble a minimal bytecode sequence from raw bytes.
    fn cfg_from(bytes: &[u8]) -> Cfg {
        Cfg::from_bytecode(bytes, Address::ZERO)
    }

    #[test]
    fn parse_simple_sequence() {
        // PUSH1 0x01  PUSH1 0x02  ADD  STOP
        let bytecode = vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x00];
        let cfg = cfg_from(&bytecode);
        assert_eq!(cfg.block_count(), 1, "single basic block");
        assert_eq!(cfg.blocks[0].instructions.len(), 4);
    }

    #[test]
    fn jumpdest_splits_blocks() {
        // Block 0: PUSH1 0x04  JUMP
        // Block 1: JUMPDEST  STOP
        let bytecode = vec![
            0x60, 0x04, // PUSH1 4
            0x56, // JUMP → pc 4
            0x00, // STOP (unreachable, but forms a block)
            0x5b, // JUMPDEST at pc=4
            0x00, // STOP
        ];
        let cfg = cfg_from(&bytecode);
        assert!(cfg.block_count() >= 2);
        // Edge from block containing JUMP to block starting at JUMPDEST(pc=4).
        let has_edge = cfg.edges.iter().any(|(_, to)| {
            cfg.blocks[*to]
                .instructions
                .first()
                .map(|i| i.pc == 4)
                .unwrap_or(false)
        });
        assert!(has_edge, "JUMP should create edge to JUMPDEST at pc=4");
    }

    #[test]
    fn jumpi_creates_two_edges() {
        // PUSH1 0x06  PUSH1 0x01  JUMPI  STOP  JUMPDEST  STOP
        let bytecode = vec![
            0x60, 0x06, // PUSH1 6 (target)
            0x60, 0x01, // PUSH1 1 (condition)
            0x57, // JUMPI
            0x00, // STOP (fall-through)
            0x5b, // JUMPDEST at pc=6
            0x00, // STOP
        ];
        let cfg = cfg_from(&bytecode);
        // The JUMPI block should have 2 outgoing edges.
        let jumpi_bb = cfg
            .blocks
            .iter()
            .find(|bb| bb.contains_opcode(op::JUMPI))
            .expect("should have JUMPI block");
        let succs = cfg.successors(jumpi_bb.id);
        assert_eq!(succs.len(), 2, "JUMPI should have true + false edges");
    }

    #[test]
    fn push_value_usize_works() {
        let inst = Instruction {
            pc: 0,
            opcode: 0x61, // PUSH2
            immediate: vec![0x01, 0x00],
        };
        assert_eq!(inst.push_value_usize(), Some(256));
    }

    #[test]
    fn reachable_from_respects_depth() {
        // Linear chain: B0 → B1 → B2 → B3
        let bytecode = vec![
            0x5b, 0x00, // B0: JUMPDEST STOP
            0x5b, 0x00, // B1: JUMPDEST STOP
            0x5b, 0x00, // B2: JUMPDEST STOP
            0x5b, 0x00, // B3: JUMPDEST STOP
        ];
        let mut cfg = cfg_from(&bytecode);
        // Force linear edges for this test.
        cfg.edges.clear();
        for i in 0..cfg.block_count().saturating_sub(1) {
            cfg.edges.push((i, i + 1));
        }
        let r = cfg.reachable_from(0, 2);
        assert!(r.contains(&0));
        assert!(r.contains(&1));
        assert!(r.contains(&2));
    }
}
