//! VulSEye vulnerability pattern matchers (GP1-7 general + BP1-6 bridge-specific).
//! See `docs/REIMPL_VULSEYE_SPEC.md` §2.1 and §2.4.

use super::code_targets::{op, BasicBlock, Cfg, CodeTarget};

/// Trait for a VulSEye vulnerability pattern matcher.
pub trait VulPattern: Send + Sync {
    fn id(&self) -> &str;
    fn description(&self) -> &str;
    /// Scan the CFG and return all code targets matching this pattern.
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget>;
}

/// Build the full set of 13 patterns (7 GP + 6 BP).
pub fn all_patterns() -> Vec<Box<dyn VulPattern>> {
    vec![
        Box::new(Gp1LockEther),
        Box::new(Gp2ControlledDelegatecall),
        Box::new(Gp3DangerousDelegatecall),
        Box::new(Gp4BlockDependency),
        Box::new(Gp5Reentrancy),
        Box::new(Gp6ArbitrarySendEther),
        Box::new(Gp7Suicidal),
        Box::new(Bp1MintWithoutLock),
        Box::new(Bp2ZeroRootAcceptance),
        Box::new(Bp3MultisigUnderThreshold),
        Box::new(Bp4ReplayAccepted),
        Box::new(Bp5AuthorizationBypass),
        Box::new(Bp6RecipientZero),
    ]
}

// ---------------------------------------------------------------------------
// Helper: emit a CodeTarget for a specific instruction in a block
// ---------------------------------------------------------------------------
fn target_at(cfg: &Cfg, bb: &BasicBlock, pc: usize, pattern_id: &str) -> CodeTarget {
    CodeTarget {
        pattern_id: pattern_id.to_string(),
        bb_id: bb.id,
        pc,
        contract: cfg.contract_addr,
    }
}

/// True if any **predecessor** block (within depth 8 backward BFS) contains
/// a CALLER or ORIGIN check feeding a JUMPI — a proxy for "access control".
/// Guards execute *before* the sensitive operation, so we walk backward.
fn has_access_control(cfg: &Cfg, bb_id: usize) -> bool {
    let ancestors = cfg.predecessors_within_depth(bb_id, 8);
    for &bid in &ancestors {
        if let Some(bb) = cfg.blocks.get(bid) {
            let ops = bb.opcodes();
            let has_caller = ops.contains(&op::CALLER) || ops.contains(&op::ORIGIN);
            let has_jumpi = ops.contains(&op::JUMPI);
            if has_caller && has_jumpi {
                return true;
            }
        }
    }
    false
}

// ============================================================================
// GP1: Lock Ether — payable function with no fund-sending opcode
// ============================================================================
struct Gp1LockEther;
impl VulPattern for Gp1LockEther {
    fn id(&self) -> &str {
        "GP1"
    }
    fn description(&self) -> &str {
        "Lock Ether: payable without fund-sending opcode"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let has_callvalue = cfg.contains_opcode(op::CALLVALUE);
        let has_send = cfg.contains_opcode(op::CALL)
            || cfg.contains_opcode(op::CALLCODE)
            || cfg.contains_opcode(op::SELFDESTRUCT);
        if has_callvalue && !has_send {
            // Mark the first CALLVALUE as the target.
            for bb in &cfg.blocks {
                for inst in &bb.instructions {
                    if inst.opcode == op::CALLVALUE {
                        return vec![target_at(cfg, bb, inst.pc, "GP1")];
                    }
                }
            }
        }
        vec![]
    }
}

// ============================================================================
// GP2: Controlled Delegatecall — address arg flows from msg.data
// ============================================================================
struct Gp2ControlledDelegatecall;
impl VulPattern for Gp2ControlledDelegatecall {
    fn id(&self) -> &str {
        "GP2"
    }
    fn description(&self) -> &str {
        "Controlled Delegatecall: address from msg.data"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_opcode(op::DELEGATECALL) {
                continue;
            }
            // Heuristic: CALLDATALOAD in same block or a predecessor.
            let has_cd = bb.contains_opcode(op::CALLDATALOAD)
                || cfg.predecessors(bb.id).iter().any(|&p| {
                    cfg.blocks
                        .get(p)
                        .map_or(false, |b| b.contains_opcode(op::CALLDATALOAD))
                });
            if has_cd {
                let pc = bb
                    .iter_opcode(op::DELEGATECALL)
                    .next()
                    .map(|(_, i)| i.pc)
                    .unwrap();
                out.push(target_at(cfg, bb, pc, "GP2"));
            }
        }
        out
    }
}

// ============================================================================
// GP3: Dangerous Delegatecall — argv flows from msg.data
// ============================================================================
struct Gp3DangerousDelegatecall;
impl VulPattern for Gp3DangerousDelegatecall {
    fn id(&self) -> &str {
        "GP3"
    }
    fn description(&self) -> &str {
        "Dangerous Delegatecall: arguments from msg.data"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_opcode(op::DELEGATECALL) {
                continue;
            }
            let has_cdcopy = bb.contains_opcode(op::CALLDATACOPY)
                || cfg.predecessors(bb.id).iter().any(|&p| {
                    cfg.blocks
                        .get(p)
                        .map_or(false, |b| b.contains_opcode(op::CALLDATACOPY))
                });
            if has_cdcopy {
                let pc = bb
                    .iter_opcode(op::DELEGATECALL)
                    .next()
                    .map(|(_, i)| i.pc)
                    .unwrap();
                out.push(target_at(cfg, bb, pc, "GP3"));
            }
        }
        out
    }
}

// ============================================================================
// GP4: Block Dependency — BLOCKHASH/TIMESTAMP/NUMBER feeding JUMPI before CALL
// ============================================================================
struct Gp4BlockDependency;
impl VulPattern for Gp4BlockDependency {
    fn id(&self) -> &str {
        "GP4"
    }
    fn description(&self) -> &str {
        "Block Dependency: block info feeds JUMPI before CALL"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let block_ops = [op::BLOCKHASH, op::TIMESTAMP, op::NUMBER];
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_any(&block_ops) || !bb.contains_opcode(op::JUMPI) {
                continue;
            }
            // Check if any successor contains a CALL.
            let succs = cfg.successors(bb.id);
            let call_after = succs.iter().any(|&s| {
                cfg.blocks
                    .get(s)
                    .map_or(false, |b| b.contains_any(&[op::CALL, op::CALLCODE]))
            });
            if call_after {
                let pc = bb
                    .instructions
                    .iter()
                    .find(|i| block_ops.contains(&i.opcode))
                    .map(|i| i.pc)
                    .unwrap();
                out.push(target_at(cfg, bb, pc, "GP4"));
            }
        }
        out
    }
}

// ============================================================================
// GP5: Reentrancy — SLOAD(x) → CALL → SSTORE(x) ordering
// ============================================================================
struct Gp5Reentrancy;
impl VulPattern for Gp5Reentrancy {
    fn id(&self) -> &str {
        "GP5"
    }
    fn description(&self) -> &str {
        "Reentrancy: SLOAD → CALL → SSTORE ordering"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let mut out = Vec::new();
        // Whole-contract scan: look for SLOAD before CALL before SSTORE.
        let mut saw_sload = false;
        let mut saw_call_after_sload = false;
        let mut sload_pc = 0usize;
        let mut sload_bb = 0usize;
        for bb in &cfg.blocks {
            for inst in &bb.instructions {
                match inst.opcode {
                    op::SLOAD => {
                        saw_sload = true;
                        sload_pc = inst.pc;
                        sload_bb = bb.id;
                    }
                    op::CALL | op::CALLCODE => {
                        if saw_sload {
                            saw_call_after_sload = true;
                        }
                    }
                    op::SSTORE => {
                        if saw_call_after_sload {
                            out.push(target_at(cfg, &cfg.blocks[sload_bb], sload_pc, "GP5"));
                            saw_sload = false;
                            saw_call_after_sload = false;
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

// ============================================================================
// GP6: Arbitrary Send Ether — unprotected CALL with value
// ============================================================================
struct Gp6ArbitrarySendEther;
impl VulPattern for Gp6ArbitrarySendEther {
    fn id(&self) -> &str {
        "GP6"
    }
    fn description(&self) -> &str {
        "Arbitrary Send Ether: unprotected CALL with value"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_opcode(op::CALL) {
                continue;
            }
            let has_value_source =
                bb.contains_opcode(op::CALLVALUE) || bb.contains_opcode(op::CALLDATALOAD);
            if has_value_source && !has_access_control(cfg, bb.id) {
                let pc = bb.iter_opcode(op::CALL).next().map(|(_, i)| i.pc).unwrap();
                out.push(target_at(cfg, bb, pc, "GP6"));
            }
        }
        out
    }
}

// ============================================================================
// GP7: Suicidal — unprotected SELFDESTRUCT
// ============================================================================
struct Gp7Suicidal;
impl VulPattern for Gp7Suicidal {
    fn id(&self) -> &str {
        "GP7"
    }
    fn description(&self) -> &str {
        "Suicidal: unprotected SELFDESTRUCT"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_opcode(op::SELFDESTRUCT) {
                continue;
            }
            if !has_access_control(cfg, bb.id) {
                let pc = bb
                    .iter_opcode(op::SELFDESTRUCT)
                    .next()
                    .map(|(_, i)| i.pc)
                    .unwrap();
                out.push(target_at(cfg, bb, pc, "GP7"));
            }
        }
        out
    }
}

// ============================================================================
// BP1: Mint without lock — LOG on dest side without matching lock on src
// ============================================================================
struct Bp1MintWithoutLock;
impl VulPattern for Bp1MintWithoutLock {
    fn id(&self) -> &str {
        "BP1"
    }
    fn description(&self) -> &str {
        "Mint without lock: LOG event without preceding lock"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        // Heuristic: LOG3 (Transfer event shape) exists but no SLOAD → SSTORE
        // guard pattern (i.e. no balance bookkeeping before the log).
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_opcode(op::LOG3) {
                continue;
            }
            // Check predecessors for SLOAD+SSTORE pair (balance check).
            let has_guard = cfg.predecessors(bb.id).iter().any(|&p| {
                cfg.blocks.get(p).map_or(false, |b| {
                    b.contains_opcode(op::SLOAD) && b.contains_opcode(op::SSTORE)
                })
            }) || (bb.contains_opcode(op::SLOAD) && bb.contains_opcode(op::SSTORE));

            if !has_guard {
                let pc = bb.iter_opcode(op::LOG3).next().map(|(_, i)| i.pc).unwrap();
                out.push(target_at(cfg, bb, pc, "BP1"));
            }
        }
        out
    }
}

// ============================================================================
// BP2: Zero-root acceptance — SSTORE to root slot + SLOAD/JUMPI with 0 ok
// ============================================================================
struct Bp2ZeroRootAcceptance;
impl VulPattern for Bp2ZeroRootAcceptance {
    fn id(&self) -> &str {
        "BP2"
    }
    fn description(&self) -> &str {
        "Zero-root acceptance: SSTORE + unchecked SLOAD/JUMPI"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        // Heuristic: block with SSTORE followed (in successors) by
        // SLOAD + ISZERO + JUMPI — the loaded value is checked for zero
        // and the "zero" branch is the accept path.
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_opcode(op::SSTORE) {
                continue;
            }
            for &sid in &cfg.successors(bb.id) {
                if let Some(succ) = cfg.blocks.get(sid) {
                    let ops = succ.opcodes();
                    let has_sload = ops.contains(&op::SLOAD);
                    let has_iszero = ops.contains(&op::ISZERO);
                    let has_jumpi = ops.contains(&op::JUMPI);
                    if has_sload && has_iszero && has_jumpi {
                        let pc = bb
                            .iter_opcode(op::SSTORE)
                            .next()
                            .map(|(_, i)| i.pc)
                            .unwrap();
                        out.push(target_at(cfg, bb, pc, "BP2"));
                    }
                }
            }
        }
        out
    }
}

// ============================================================================
// BP3: Multisig under threshold — JUMPI checking counter < threshold
// ============================================================================
struct Bp3MultisigUnderThreshold;
impl VulPattern for Bp3MultisigUnderThreshold {
    fn id(&self) -> &str {
        "BP3"
    }
    fn description(&self) -> &str {
        "Multisig under threshold: SLOAD + LT/GT + JUMPI"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        // Heuristic: SLOAD (load signer count) → LT or GT (compare to
        // threshold) → JUMPI in same or adjacent block.
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            if !bb.contains_opcode(op::JUMPI) {
                continue;
            }
            let ops = bb.opcodes();
            let has_sload = ops.contains(&op::SLOAD);
            let has_cmp = ops.contains(&op::LT) || ops.contains(&op::GT);
            if has_sload && has_cmp {
                let pc = bb.iter_opcode(op::JUMPI).next().map(|(_, i)| i.pc).unwrap();
                out.push(target_at(cfg, bb, pc, "BP3"));
            }
            // Also check predecessor for SLOAD, this block for CMP+JUMPI.
            if has_cmp && !has_sload {
                let pred_has_sload = cfg.predecessors(bb.id).iter().any(|&p| {
                    cfg.blocks
                        .get(p)
                        .map_or(false, |b| b.contains_opcode(op::SLOAD))
                });
                if pred_has_sload {
                    let pc = bb.iter_opcode(op::JUMPI).next().map(|(_, i)| i.pc).unwrap();
                    out.push(target_at(cfg, bb, pc, "BP3"));
                }
            }
        }
        out
    }
}

// ============================================================================
// BP4: Replay accepted — CALL before SSTORE(processed)
// ============================================================================
struct Bp4ReplayAccepted;
impl VulPattern for Bp4ReplayAccepted {
    fn id(&self) -> &str {
        "BP4"
    }
    fn description(&self) -> &str {
        "Replay accepted: CALL before SSTORE to processed mapping"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        // Heuristic: CALL (state-changing) appears before an SSTORE that
        // writes to a mapping (SHA3 in same/predecessor block — typical for
        // `processed[hash] = true`). The ordering CALL-then-SSTORE means
        // "unlock fires before marking processed" — a replay window.
        let mut out = Vec::new();
        let mut last_call: Option<(usize, usize)> = None; // (bb_id, pc)
        let mut found_mapping_sstore_after = false;

        for bb in &cfg.blocks {
            for inst in &bb.instructions {
                if op::is_call_family(inst.opcode) && inst.opcode != op::STATICCALL {
                    last_call = Some((bb.id, inst.pc));
                    found_mapping_sstore_after = false;
                }
                if inst.opcode == op::SSTORE && last_call.is_some() {
                    // Check for SHA3 (mapping key hash) in this block or
                    // a predecessor — signals `mapping[key] = value`.
                    let has_sha3 = bb.contains_opcode(op::SHA3)
                        || cfg.predecessors(bb.id).iter().any(|&p| {
                            cfg.blocks
                                .get(p)
                                .map_or(false, |b| b.contains_opcode(op::SHA3))
                        });
                    if has_sha3 {
                        found_mapping_sstore_after = true;
                    }
                }
            }
        }
        if let Some((bb_id, pc)) = last_call {
            if found_mapping_sstore_after {
                if let Some(bb) = cfg.blocks.get(bb_id) {
                    out.push(target_at(cfg, bb, pc, "BP4"));
                }
            }
        }
        out
    }
}

// ============================================================================
// BP5: Authorization bypass — CALL without CALLER check
// ============================================================================
struct Bp5AuthorizationBypass;
impl VulPattern for Bp5AuthorizationBypass {
    fn id(&self) -> &str {
        "BP5"
    }
    fn description(&self) -> &str {
        "Authorization bypass: CALL without CALLER check"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            // Look for CALL (not STATICCALL) that transfers value.
            if !bb.contains_any(&[op::CALL, op::CALLCODE]) {
                continue;
            }
            if !has_access_control(cfg, bb.id) {
                let pc = bb
                    .instructions
                    .iter()
                    .find(|i| i.opcode == op::CALL || i.opcode == op::CALLCODE)
                    .map(|i| i.pc)
                    .unwrap();
                out.push(target_at(cfg, bb, pc, "BP5"));
            }
        }
        out
    }
}

// ============================================================================
// BP6: Recipient zero — CALL/LOG where recipient could be 0x0
// ============================================================================
struct Bp6RecipientZero;
impl VulPattern for Bp6RecipientZero {
    fn id(&self) -> &str {
        "BP6"
    }
    fn description(&self) -> &str {
        "Recipient zero: CALL/LOG with potential 0x0 recipient"
    }
    fn scan(&self, cfg: &Cfg) -> Vec<CodeTarget> {
        // Heuristic: ISZERO check on an address-like value feeding into
        // a CALL or LOG, but the JUMPI branch allows the zero case through
        // (i.e. no revert on zero). Simplified: CALL preceded by ISZERO
        // without a REVERT in the ISZERO-true branch.
        let mut out = Vec::new();
        for bb in &cfg.blocks {
            let has_call_or_log =
                bb.contains_any(&[op::CALL, op::CALLCODE]) || bb.contains_opcode(op::LOG3);
            if !has_call_or_log {
                continue;
            }
            // Check for missing zero-address guard: no ISZERO+JUMPI
            // in this block or predecessors.
            let has_zero_guard = bb.contains_opcode(op::ISZERO)
                || cfg.predecessors(bb.id).iter().any(|&p| {
                    cfg.blocks.get(p).map_or(false, |b| {
                        b.contains_opcode(op::ISZERO) && b.contains_opcode(op::JUMPI)
                    })
                });
            if !has_zero_guard {
                let pc = bb
                    .instructions
                    .iter()
                    .find(|i| op::is_call_family(i.opcode) || op::is_log(i.opcode))
                    .map(|i| i.pc)
                    .unwrap();
                out.push(target_at(cfg, bb, pc, "BP6"));
            }
        }
        out
    }
}

// ============================================================================
// Tests
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::Address;

    fn scan_bytes(pat: &dyn VulPattern, bytes: &[u8]) -> Vec<CodeTarget> {
        let cfg = Cfg::from_bytecode(bytes, Address::ZERO);
        pat.scan(&cfg)
    }

    #[test]
    fn gp1_payable_no_send() {
        // CALLVALUE POP STOP — payable, no CALL/SELFDESTRUCT.
        let hits = scan_bytes(&Gp1LockEther, &[op::CALLVALUE, 0x50, op::STOP]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern_id, "GP1");
    }

    #[test]
    fn gp1_no_hit_when_call_present() {
        // CALLVALUE POP PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 CALL STOP
        let mut bc = vec![op::CALLVALUE, 0x50];
        for _ in 0..7 {
            bc.extend_from_slice(&[0x60, 0x00]);
        }
        bc.push(op::CALL);
        bc.push(op::STOP);
        let hits = scan_bytes(&Gp1LockEther, &bc);
        assert!(hits.is_empty(), "GP1 should not fire when CALL is present");
    }

    #[test]
    fn gp5_reentrancy_pattern() {
        // SLOAD PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 CALL SSTORE STOP
        let mut bc = vec![op::SLOAD];
        for _ in 0..7 {
            bc.extend_from_slice(&[0x60, 0x00]);
        }
        bc.extend_from_slice(&[op::CALL, op::SSTORE, op::STOP]);
        let hits = scan_bytes(&Gp5Reentrancy, &bc);
        assert_eq!(hits.len(), 1, "GP5 should detect SLOAD→CALL→SSTORE");
        assert_eq!(hits[0].pattern_id, "GP5");
    }

    #[test]
    fn gp7_unprotected_selfdestruct() {
        // SELFDESTRUCT (no CALLER/ORIGIN check).
        let hits = scan_bytes(&Gp7Suicidal, &[op::SELFDESTRUCT]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern_id, "GP7");
    }

    #[test]
    fn bp3_multisig_threshold() {
        // SLOAD LT PUSH1 0x08 JUMPI STOP JUMPDEST STOP
        let bc = vec![
            op::SLOAD,
            op::LT,
            0x60,
            0x08,
            op::JUMPI,
            op::STOP,
            op::JUMPDEST,
            op::STOP,
        ];
        let hits = scan_bytes(&Bp3MultisigUnderThreshold, &bc);
        assert!(!hits.is_empty(), "BP3 should detect SLOAD+LT+JUMPI");
    }

    #[test]
    fn bp5_unprotected_call() {
        // PUSH1 0 (×7) CALL STOP — no CALLER check.
        let mut bc = Vec::new();
        for _ in 0..7 {
            bc.extend_from_slice(&[0x60, 0x00]);
        }
        bc.extend_from_slice(&[op::CALL, op::STOP]);
        let hits = scan_bytes(&Bp5AuthorizationBypass, &bc);
        assert!(!hits.is_empty(), "BP5 should detect CALL without CALLER");
    }

    #[test]
    fn all_patterns_returns_13() {
        assert_eq!(all_patterns().len(), 13);
    }
}
