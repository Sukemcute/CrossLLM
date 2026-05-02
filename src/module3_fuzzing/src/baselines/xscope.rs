//! XScope re-implementation — six rule-based invariant predicates.
//!
//! Implements [`docs/REIMPL_XSCOPE_SPEC.md`] §2 (predicate pseudocode)
//! and §3 (BridgeSentry data-model bindings). The wiring of these
//! predicates into the fuzz loop, the per-bridge event-topic table, and
//! the `MockRelay::parsed_message_log` extension are X3 scope; this
//! module ships only the pure detector.
//!
//! Source paper: Zhang, Gao, Li, Chen, Guan, Chen — *"Xscope: Hunting
//! for Cross-Chain Bridge Attacks"*, ASE 2022 (arXiv 2208.07119).
//!
//! The three documented bug classes are unfolded into six predicates,
//! two per class, so that each one can be unit-tested independently:
//!
//! | Class | Predicate | Tag |
//! |-------|-----------|-----|
//! | C1 Inconsistency of Deposits  | I-1 lock event matches balance delta              | `C1.deposit_event_no_balance_change` |
//! | C1 Inconsistency of Deposits  | I-2 lock event recipient is non-zero              | `C1.unrestricted_deposit_emitting`   |
//! | C2 Inconsistent Event Parsing | I-3 relayer-parsed amount matches source event    | `C2.amount_parse_mismatch`           |
//! | C2 Inconsistent Event Parsing | I-4 relayer-parsed recipient matches source event | `C2.recipient_parse_mismatch`        |
//! | C3 Unauthorized Unlocking     | I-5 unlock event has matching source ancestor     | `C3.unauthorized_unlocking`          |
//! | C3 Unauthorized Unlocking     | I-6 unlock carries valid authorisation witness    | `C3.{no_authorization_witness, zero_root_accepted, multisig_under_threshold}` |

use std::collections::HashMap;

use revm::primitives::{Address, B256, U256};

// ============================================================================
// View — the per-iteration data the predicates consume.
// ============================================================================

/// Cross-chain lock / deposit event observed on the source fork.
///
/// The X3 wiring builds these from `TransactionResult.logs` filtered by
/// the per-bridge `lock_topic` table (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEvent {
    /// Router / bridge contract that emitted the event.
    pub address: Address,
    /// Cross-chain message hash (typically `topics[1]`).
    pub message_hash: B256,
    /// Declared amount (decoded from event data).
    pub amount: U256,
    /// Recipient on the destination chain (decoded from event data).
    pub recipient: Address,
    /// Raw `topics[0]` — the event signature hash. Carried for evidence.
    pub topic0: B256,
}

/// Cross-chain unlock / mint / process event observed on the destination
/// fork. Same wire shape as [`LockEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockEvent {
    pub address: Address,
    pub message_hash: B256,
    pub amount: U256,
    pub recipient: Address,
    pub topic0: B256,
}

/// What the relayer parsed for one cross-chain message. Produced by the
/// `MockRelay::parsed_message_log` extension that lands in X3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRelayMessage {
    pub message_hash: B256,
    pub parsed_amount: U256,
    pub parsed_recipient: Address,
    pub parse_mode: RelayParseMode,
}

/// Mirrors the existing `mock_relay::RelayMode` but kept independent here
/// so the X2 predicate module does not depend on `mock_relay`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayParseMode {
    Faithful,
    Tampered,
    Replayed,
    Delayed,
}

/// Reconstructed authorisation evidence for a single unlock. The X3
/// wiring derives this from the storage-write inspector + `RelaySnapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthWitness {
    /// No witness reconstructed at all → unauthorised.
    None,
    /// `replica.acceptableRoot[bytes32(0)]` was set to true and the
    /// dispatched message used the zero root (Nomad pattern).
    ZeroRoot,
    /// Multisig threshold check witnessed; we know how many signers
    /// signed and what the configured threshold is.
    Multisig { signatures: u32, threshold: u32 },
    /// MPC public-key check witnessed; `matches_canonical = false` means
    /// the unlock was signed with a non-canonical key (key compromise).
    Mpc { matches_canonical: bool },
    /// `replica.acceptableRoot(root) == true && root != 0x0`. Healthy.
    AcceptableRoot,
}

/// One iteration's slice of state that the predicates examine.
///
/// All references are borrowed; this view is constructed afresh each
/// fuzz iteration by X3.
#[derive(Debug, Clone)]
pub struct XScopeView<'a> {
    pub lock_events: &'a [LockEvent],
    pub unlock_events: &'a [UnlockEvent],
    /// (router_addr) → signed `post - pre` token-balance change observed
    /// during the iteration. Positive = balance increased.
    pub balance_deltas: &'a HashMap<Address, i128>,
    /// Each parsed relayer message in `message_hash` order.
    pub relay_log: &'a [ParsedRelayMessage],
    /// Per `message_hash` authorisation witness for I-6.
    pub auth_witnesses: &'a HashMap<B256, AuthWitness>,
    /// Iteration-level fee tolerance for I-1, in parts-per-million of the
    /// declared amount. 10_000 ppm = 1 % — matches the existing
    /// `checker::check_asset_conservation` tolerance.
    pub fee_tolerance_ppm: u128,
}

// ============================================================================
// Violation reporting.
// ============================================================================

/// One violated XScope invariant. The `class` field is the paper's bug
/// class (`C1.*`, `C2.*`, `C3.*`); `predicate_id` is `"I-1"` … `"I-6"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XScopeViolation {
    pub class: String,
    pub predicate_id: &'static str,
    pub message_hash: Option<B256>,
    pub address: Option<Address>,
    pub evidence: String,
}

impl XScopeViolation {
    fn build(
        class: &str,
        predicate_id: &'static str,
        message_hash: Option<B256>,
        address: Option<Address>,
        evidence: String,
    ) -> Self {
        Self {
            class: class.to_string(),
            predicate_id,
            message_hash,
            address,
            evidence,
        }
    }
}

// ============================================================================
// Predicates I-1 .. I-6 — verbatim port of spec §2 pseudocode.
// ============================================================================

/// I-1 — Lock event amount must be backed by a real balance delta on the
/// emitter (router) contract.
///
/// The check uses a *fee tolerance* expressed in ppm of the declared
/// amount; this matches both real-world bridge fees (typically 0.05 –
/// 1 %) and the existing tolerance in
/// `checker::check_asset_conservation` so the two checkers agree on
/// conservation thresholds.
pub fn predicate_i1_lock_matches_balance(
    evt: &LockEvent,
    balance_deltas: &HashMap<Address, i128>,
    fee_tolerance_ppm: u128,
) -> Option<XScopeViolation> {
    let declared = u256_saturating_to_u128(evt.amount);
    let tol = saturating_mul_div(declared, fee_tolerance_ppm, 1_000_000) + 1;
    let min_delta_required = declared.saturating_sub(tol) as i128;

    let observed = balance_deltas.get(&evt.address).copied().unwrap_or(0);

    if observed < min_delta_required {
        Some(XScopeViolation::build(
            "C1.deposit_event_no_balance_change",
            "I-1",
            Some(evt.message_hash),
            Some(evt.address),
            format!(
                "addr={:#x} declared_amount={} real_delta={} tolerance_ppm={}",
                evt.address, declared, observed, fee_tolerance_ppm
            ),
        ))
    } else {
        None
    }
}

/// I-2 — Lock event recipient must not be the zero address. This is the
/// invariant that fired on the Qubit Bridge attack — `transfer(0x0, …)`
/// silently succeeded and a `Deposit` event was still emitted.
pub fn predicate_i2_recipient_nonzero(evt: &LockEvent) -> Option<XScopeViolation> {
    if evt.recipient == Address::ZERO {
        Some(XScopeViolation::build(
            "C1.unrestricted_deposit_emitting",
            "I-2",
            Some(evt.message_hash),
            Some(evt.address),
            format!("topic0={:#x} recipient=0x0", evt.topic0),
        ))
    } else {
        None
    }
}

/// I-3 — Relayer-parsed amount must equal the source-chain event amount.
pub fn predicate_i3_amount_roundtrips(
    evt: &LockEvent,
    relay_msg: &ParsedRelayMessage,
) -> Option<XScopeViolation> {
    if relay_msg.parsed_amount != evt.amount {
        Some(XScopeViolation::build(
            "C2.amount_parse_mismatch",
            "I-3",
            Some(evt.message_hash),
            Some(evt.address),
            format!(
                "src_amount={} parsed_amount={} mode={:?}",
                evt.amount, relay_msg.parsed_amount, relay_msg.parse_mode
            ),
        ))
    } else {
        None
    }
}

/// I-4 — Relayer-parsed recipient must equal the source-chain event recipient.
pub fn predicate_i4_recipient_roundtrips(
    evt: &LockEvent,
    relay_msg: &ParsedRelayMessage,
) -> Option<XScopeViolation> {
    if relay_msg.parsed_recipient != evt.recipient {
        Some(XScopeViolation::build(
            "C2.recipient_parse_mismatch",
            "I-4",
            Some(evt.message_hash),
            Some(evt.address),
            format!(
                "src_recipient={:#x} parsed_recipient={:#x} mode={:?}",
                evt.recipient, relay_msg.parsed_recipient, relay_msg.parse_mode
            ),
        ))
    } else {
        None
    }
}

/// I-5 — Every unlock / mint must trace back to a lock with the same
/// `message_hash`. If no source ancestor is present the relayer was
/// bypassed (root forgery, MPC compromise, multisig threshold broken,
/// keeper rotation, …).
pub fn predicate_i5_has_source_ancestor(
    unlock: &UnlockEvent,
    locks: &[LockEvent],
) -> Option<XScopeViolation> {
    let has_ancestor = locks.iter().any(|l| l.message_hash == unlock.message_hash);
    if has_ancestor {
        return None;
    }
    Some(XScopeViolation::build(
        "C3.unauthorized_unlocking",
        "I-5",
        Some(unlock.message_hash),
        Some(unlock.address),
        format!(
            "unlock_msg_hash={:#x} witnessed_lock_hashes_count={}",
            unlock.message_hash,
            locks.len()
        ),
    ))
}

/// I-6 — Authorisation witness for the unlock must be (a) a non-zero
/// `acceptableRoot`, (b) a multisig with `signatures ≥ threshold`, or
/// (c) an MPC signature matching the canonical key. Anything else fires.
pub fn predicate_i6_authorization_witness(
    unlock: &UnlockEvent,
    auth: &AuthWitness,
) -> Option<XScopeViolation> {
    match auth {
        AuthWitness::AcceptableRoot => None,
        AuthWitness::Multisig { signatures, threshold } if signatures >= threshold => None,
        AuthWitness::Mpc { matches_canonical: true } => None,

        AuthWitness::None => Some(XScopeViolation::build(
            "C3.no_authorization_witness",
            "I-6",
            Some(unlock.message_hash),
            Some(unlock.address),
            "no acceptableRoot / multisig / MPC trace".to_string(),
        )),
        AuthWitness::ZeroRoot => Some(XScopeViolation::build(
            "C3.zero_root_accepted",
            "I-6",
            Some(unlock.message_hash),
            Some(unlock.address),
            "replica accepted root=0x0 (Nomad pattern)".to_string(),
        )),
        AuthWitness::Multisig { signatures, threshold } => Some(XScopeViolation::build(
            "C3.multisig_under_threshold",
            "I-6",
            Some(unlock.message_hash),
            Some(unlock.address),
            format!(
                "multisig signatures={} < threshold={} (Ronin / Harmony pattern)",
                signatures, threshold
            ),
        )),
        AuthWitness::Mpc { matches_canonical: false } => Some(XScopeViolation::build(
            "C3.no_authorization_witness",
            "I-6",
            Some(unlock.message_hash),
            Some(unlock.address),
            "MPC public key does not match canonical key (key compromise)".to_string(),
        )),
    }
}

// ============================================================================
// Aggregate dispatcher — runs all six predicates over a single view.
// ============================================================================

/// Run every predicate over the iteration view. Returns all violations
/// in the order they were observed (lock-side first, then unlock-side).
pub fn check_all(view: &XScopeView<'_>) -> Vec<XScopeViolation> {
    let mut out = Vec::new();

    // Lock-side predicates: I-1 (balance), I-2 (recipient), I-3 / I-4 (relay roundtrip).
    for ev in view.lock_events {
        if let Some(v) = predicate_i1_lock_matches_balance(ev, view.balance_deltas, view.fee_tolerance_ppm) {
            out.push(v);
        }
        if let Some(v) = predicate_i2_recipient_nonzero(ev) {
            out.push(v);
        }
        if let Some(rly) = view.relay_log.iter().find(|r| r.message_hash == ev.message_hash) {
            if let Some(v) = predicate_i3_amount_roundtrips(ev, rly) {
                out.push(v);
            }
            if let Some(v) = predicate_i4_recipient_roundtrips(ev, rly) {
                out.push(v);
            }
        }
    }

    // Unlock-side predicates: I-5 (ancestor), I-6 (auth witness).
    for unlock in view.unlock_events {
        if let Some(v) = predicate_i5_has_source_ancestor(unlock, view.lock_events) {
            out.push(v);
        }
        let auth = view
            .auth_witnesses
            .get(&unlock.message_hash)
            .unwrap_or(&AuthWitness::None);
        if let Some(v) = predicate_i6_authorization_witness(unlock, auth) {
            out.push(v);
        }
    }

    out
}

// ============================================================================
// Small numeric helpers (kept private — predicates are the API).
// ============================================================================

fn u256_saturating_to_u128(v: U256) -> u128 {
    let limbs = v.as_limbs();
    if limbs.iter().skip(2).any(|l| *l != 0) {
        u128::MAX
    } else {
        ((limbs[1] as u128) << 64) | (limbs[0] as u128)
    }
}

fn saturating_mul_div(a: u128, b: u128, denom: u128) -> u128 {
    if denom == 0 {
        return 0;
    }
    match a.checked_mul(b) {
        Some(prod) => prod / denom,
        None => {
            // a*b overflows u128; fall back to dividing first to stay finite.
            (a / denom).saturating_mul(b)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn hash(byte: u8) -> B256 {
        B256::from([byte; 32])
    }

    fn lock(amount: U256, recipient: Address, msg: B256) -> LockEvent {
        LockEvent {
            address: addr(0xAA),
            message_hash: msg,
            amount,
            recipient,
            topic0: hash(0xCC),
        }
    }

    fn unlock(msg: B256) -> UnlockEvent {
        UnlockEvent {
            address: addr(0xBB),
            message_hash: msg,
            amount: U256::from(100u64),
            recipient: addr(0x10),
            topic0: hash(0xDD),
        }
    }

    fn parsed(msg: B256, amount: U256, recipient: Address) -> ParsedRelayMessage {
        ParsedRelayMessage {
            message_hash: msg,
            parsed_amount: amount,
            parsed_recipient: recipient,
            parse_mode: RelayParseMode::Faithful,
        }
    }

    // -------- I-1: balance-delta matching --------

    #[test]
    fn i1_holds_when_router_balance_grew_by_declared_amount() {
        let evt = lock(U256::from(1_000_000u64), addr(0x10), hash(0x01));
        let mut deltas = HashMap::new();
        deltas.insert(addr(0xAA), 1_000_000_i128);
        assert!(predicate_i1_lock_matches_balance(&evt, &deltas, 10_000).is_none());
    }

    #[test]
    fn i1_holds_within_fee_tolerance() {
        // 1 % tolerance => declared 1_000_000, observed 990_000 still holds.
        let evt = lock(U256::from(1_000_000u64), addr(0x10), hash(0x01));
        let mut deltas = HashMap::new();
        deltas.insert(addr(0xAA), 990_000_i128);
        assert!(predicate_i1_lock_matches_balance(&evt, &deltas, 10_000).is_none());
    }

    #[test]
    fn i1_violates_when_no_balance_change_at_all() {
        let evt = lock(U256::from(1_000_000u64), addr(0x10), hash(0x01));
        let deltas = HashMap::new();
        let v = predicate_i1_lock_matches_balance(&evt, &deltas, 10_000)
            .expect("should violate");
        assert_eq!(v.predicate_id, "I-1");
        assert_eq!(v.class, "C1.deposit_event_no_balance_change");
    }

    #[test]
    fn i1_violates_when_balance_grew_only_partially() {
        // Declared 1_000_000, observed 500_000 — far below 1 % tolerance.
        let evt = lock(U256::from(1_000_000u64), addr(0x10), hash(0x01));
        let mut deltas = HashMap::new();
        deltas.insert(addr(0xAA), 500_000_i128);
        let v = predicate_i1_lock_matches_balance(&evt, &deltas, 10_000)
            .expect("should violate");
        assert_eq!(v.predicate_id, "I-1");
    }

    // -------- I-2: zero-recipient (Qubit pattern) --------

    #[test]
    fn i2_holds_for_real_recipient() {
        let evt = lock(U256::from(100u64), addr(0x10), hash(0x02));
        assert!(predicate_i2_recipient_nonzero(&evt).is_none());
    }

    #[test]
    fn i2_violates_when_recipient_is_zero_address() {
        let evt = lock(U256::from(100u64), Address::ZERO, hash(0x02));
        let v = predicate_i2_recipient_nonzero(&evt).expect("should violate");
        assert_eq!(v.predicate_id, "I-2");
        assert_eq!(v.class, "C1.unrestricted_deposit_emitting");
    }

    // -------- I-3 / I-4: relay roundtrip --------

    #[test]
    fn i3_holds_when_parsed_amount_equals_source() {
        let evt = lock(U256::from(7_777u64), addr(0x10), hash(0x03));
        let rly = parsed(hash(0x03), U256::from(7_777u64), addr(0x10));
        assert!(predicate_i3_amount_roundtrips(&evt, &rly).is_none());
    }

    #[test]
    fn i3_violates_when_relay_parsed_different_amount() {
        let evt = lock(U256::from(7_777u64), addr(0x10), hash(0x03));
        let rly = parsed(hash(0x03), U256::from(9_999u64), addr(0x10));
        let v = predicate_i3_amount_roundtrips(&evt, &rly).expect("should violate");
        assert_eq!(v.predicate_id, "I-3");
        assert_eq!(v.class, "C2.amount_parse_mismatch");
    }

    #[test]
    fn i4_holds_when_parsed_recipient_equals_source() {
        let evt = lock(U256::from(100u64), addr(0x10), hash(0x04));
        let rly = parsed(hash(0x04), U256::from(100u64), addr(0x10));
        assert!(predicate_i4_recipient_roundtrips(&evt, &rly).is_none());
    }

    #[test]
    fn i4_violates_when_relay_parsed_different_recipient() {
        let evt = lock(U256::from(100u64), addr(0x10), hash(0x04));
        let rly = parsed(hash(0x04), U256::from(100u64), addr(0x99));
        let v = predicate_i4_recipient_roundtrips(&evt, &rly).expect("should violate");
        assert_eq!(v.predicate_id, "I-4");
        assert_eq!(v.class, "C2.recipient_parse_mismatch");
    }

    // -------- I-5: source ancestor --------

    #[test]
    fn i5_holds_when_unlock_has_matching_lock() {
        let locks = vec![lock(U256::from(1u64), addr(0x10), hash(0x05))];
        let u = unlock(hash(0x05));
        assert!(predicate_i5_has_source_ancestor(&u, &locks).is_none());
    }

    #[test]
    fn i5_violates_when_unlock_has_no_source_lock() {
        let locks = vec![lock(U256::from(1u64), addr(0x10), hash(0x77))];
        let u = unlock(hash(0x05));
        let v = predicate_i5_has_source_ancestor(&u, &locks).expect("should violate");
        assert_eq!(v.predicate_id, "I-5");
        assert_eq!(v.class, "C3.unauthorized_unlocking");
    }

    #[test]
    fn i5_violates_when_no_locks_at_all() {
        let u = unlock(hash(0x05));
        let v = predicate_i5_has_source_ancestor(&u, &[]).expect("should violate");
        assert_eq!(v.predicate_id, "I-5");
    }

    // -------- I-6: authorisation witness --------

    #[test]
    fn i6_holds_for_acceptable_root() {
        let u = unlock(hash(0x06));
        assert!(predicate_i6_authorization_witness(&u, &AuthWitness::AcceptableRoot).is_none());
    }

    #[test]
    fn i6_holds_for_quorum_multisig() {
        let u = unlock(hash(0x06));
        let auth = AuthWitness::Multisig { signatures: 5, threshold: 5 };
        assert!(predicate_i6_authorization_witness(&u, &auth).is_none());
    }

    #[test]
    fn i6_holds_for_canonical_mpc() {
        let u = unlock(hash(0x06));
        let auth = AuthWitness::Mpc { matches_canonical: true };
        assert!(predicate_i6_authorization_witness(&u, &auth).is_none());
    }

    #[test]
    fn i6_violates_zero_root_nomad_style() {
        let u = unlock(hash(0x06));
        let v = predicate_i6_authorization_witness(&u, &AuthWitness::ZeroRoot)
            .expect("should violate");
        assert_eq!(v.predicate_id, "I-6");
        assert_eq!(v.class, "C3.zero_root_accepted");
    }

    #[test]
    fn i6_violates_multisig_under_threshold_ronin_style() {
        let u = unlock(hash(0x06));
        let auth = AuthWitness::Multisig { signatures: 4, threshold: 5 };
        let v = predicate_i6_authorization_witness(&u, &auth).expect("should violate");
        assert_eq!(v.predicate_id, "I-6");
        assert_eq!(v.class, "C3.multisig_under_threshold");
    }

    #[test]
    fn i6_violates_mpc_key_mismatch_multichain_style() {
        let u = unlock(hash(0x06));
        let auth = AuthWitness::Mpc { matches_canonical: false };
        let v = predicate_i6_authorization_witness(&u, &auth).expect("should violate");
        assert_eq!(v.predicate_id, "I-6");
    }

    #[test]
    fn i6_violates_when_no_witness_present() {
        let u = unlock(hash(0x06));
        let v = predicate_i6_authorization_witness(&u, &AuthWitness::None)
            .expect("should violate");
        assert_eq!(v.predicate_id, "I-6");
        assert_eq!(v.class, "C3.no_authorization_witness");
    }

    // -------- aggregate dispatcher --------

    #[test]
    fn check_all_combines_lock_and_unlock_violations() {
        // Synthetic Nomad-like trace: zero-root unlock + recipient zero on lock.
        let locks = vec![lock(U256::from(50u64), Address::ZERO, hash(0x10))];
        let unlocks = vec![unlock(hash(0x10))];
        let mut deltas = HashMap::new();
        deltas.insert(addr(0xAA), 50_i128);
        let mut auth = HashMap::new();
        auth.insert(hash(0x10), AuthWitness::ZeroRoot);

        let view = XScopeView {
            lock_events: &locks,
            unlock_events: &unlocks,
            balance_deltas: &deltas,
            relay_log: &[],
            auth_witnesses: &auth,
            fee_tolerance_ppm: 10_000,
        };
        let vs = check_all(&view);
        let ids: Vec<&str> = vs.iter().map(|v| v.predicate_id).collect();
        // I-1 holds (delta=declared); I-2 fires (recipient zero);
        // I-3/I-4 absent (no relay log); I-5 holds (ancestor exists);
        // I-6 fires (zero root).
        assert_eq!(ids, vec!["I-2", "I-6"], "got {:?}", ids);
    }

    #[test]
    fn check_all_qubit_like_scenario_fires_i2() {
        // Qubit pattern: lock event with recipient = 0x0 (transfer-to-zero
        // succeeded silently, deposit event still emitted).
        let locks = vec![lock(U256::from(1_000_000u64), Address::ZERO, hash(0xA1))];
        let mut deltas = HashMap::new();
        deltas.insert(addr(0xAA), 1_000_000_i128);
        let view = XScopeView {
            lock_events: &locks,
            unlock_events: &[],
            balance_deltas: &deltas,
            relay_log: &[],
            auth_witnesses: &HashMap::new(),
            fee_tolerance_ppm: 10_000,
        };
        let vs = check_all(&view);
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].predicate_id, "I-2");
    }

    #[test]
    fn check_all_ronin_like_scenario_fires_i6_under_threshold() {
        // Ronin pattern: unlock with multisig signatures < threshold.
        let unlocks = vec![unlock(hash(0xB1))];
        let mut auth = HashMap::new();
        auth.insert(
            hash(0xB1),
            AuthWitness::Multisig { signatures: 4, threshold: 5 },
        );
        // Add a matching lock so I-5 holds and I-6 is the only violation.
        let locks = vec![lock(U256::from(1u64), addr(0x10), hash(0xB1))];
        let mut deltas = HashMap::new();
        deltas.insert(addr(0xAA), 1_i128);
        let view = XScopeView {
            lock_events: &locks,
            unlock_events: &unlocks,
            balance_deltas: &deltas,
            relay_log: &[],
            auth_witnesses: &auth,
            fee_tolerance_ppm: 10_000,
        };
        let vs = check_all(&view);
        let classes: Vec<&str> = vs.iter().map(|v| v.class.as_str()).collect();
        assert_eq!(classes, vec!["C3.multisig_under_threshold"]);
    }

    // -------- helpers --------

    #[test]
    fn u256_saturating_handles_huge_values() {
        // 2^192 fits in three limbs with limb[2] != 0 → saturate.
        let big = U256::from(1u64) << 192;
        assert_eq!(u256_saturating_to_u128(big), u128::MAX);

        // Small values round-trip.
        let small = U256::from(12345u64);
        assert_eq!(u256_saturating_to_u128(small), 12345u128);
    }
}
