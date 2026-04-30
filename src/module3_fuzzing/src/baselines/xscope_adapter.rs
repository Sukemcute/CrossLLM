//! Adapter — converts BridgeSentry per-iteration state into the
//! [`crate::baselines::xscope::XScopeView`] that the X2 predicates
//! consume. Implements the BridgeSentry data-model bindings listed in
//! [`docs/REIMPL_XSCOPE_SPEC.md`] §3.
//!
//! Lifecycle per fuzz iteration:
//!
//! 1. `XScopeBuilder::new(&AtgGraph, &ContractRegistry, fee_tolerance_ppm)` —
//!    once per iteration. Pre-computes per-bridge lock / unlock event
//!    topic tables from the ATG.
//! 2. For every successful tx on the source fork:
//!    `builder.ingest_source_logs(&logs)`.
//!    Same for destination via `ingest_dest_logs`.
//! 3. Optional balance accounting: `builder.add_balance_delta(addr, delta)`
//!    for each tracked address.
//! 4. Pull the parsed-relay log: `builder.ingest_relay_log(relay.parsed_log())`.
//! 5. Optional auth witnesses: `builder.set_auth_witness(msg_hash, kind)`.
//! 6. `builder.check()` — runs all six predicates and returns
//!    `Vec<XScopeViolation>`. The fuzz loop folds these into the run's
//!    overall violations list.

use std::collections::{HashMap, HashSet};

use revm::primitives::{Address, Log, B256, U256};

use crate::baselines::xscope::{
    self, AuthWitness, LockEvent, ParsedRelayMessage as XParsedMsg, RelayParseMode, UnlockEvent,
    XScopeView, XScopeViolation,
};
use crate::contract_loader::{canonical_signature, ChainSide, ContractRegistry};
use crate::mock_relay::ParsedRelayMessage as MockParsedMsg;
use crate::types::AtgGraph;

/// Per-iteration accumulator. All fields are populated by the X3 wiring
/// in `fuzz_loop`; the predicate dispatch happens in [`Self::check`].
pub struct XScopeBuilder<'a> {
    /// Pre-computed: every event topic considered a "lock" on the source
    /// chain. Derived from ATG edges whose label/function-signature looks
    /// like a deposit / lock / dispatch / send.
    lock_topics: HashSet<B256>,
    /// Same for destination-chain "unlock"-style events.
    unlock_topics: HashSet<B256>,
    /// Address sets per side — only logs whose emitter address matches a
    /// known bridge contract are kept.
    src_addresses: HashSet<Address>,
    dst_addresses: HashSet<Address>,

    /// Per-iteration accumulators.
    lock_events: Vec<LockEvent>,
    unlock_events: Vec<UnlockEvent>,
    balance_deltas: HashMap<Address, i128>,
    relay_log: Vec<XParsedMsg>,
    auth_witnesses: HashMap<B256, AuthWitness>,
    fee_tolerance_ppm: u128,

    /// Captured to allow a "no event topics known → fall back to label
    /// substring matching" path (see [`Self::looks_like_lock_log`]).
    fallback_lock_keywords: Vec<&'a str>,
    fallback_unlock_keywords: Vec<&'a str>,
}

impl<'a> XScopeBuilder<'a> {
    pub fn new(atg: &AtgGraph, registry: &ContractRegistry, fee_tolerance_ppm: u128) -> Self {
        let (lock_topics, unlock_topics) = topics_from_atg(atg);
        let src_addresses: HashSet<Address> =
            registry.addresses_on(ChainSide::Source).into_iter().collect();
        let dst_addresses: HashSet<Address> = registry
            .addresses_on(ChainSide::Destination)
            .into_iter()
            .collect();
        Self {
            lock_topics,
            unlock_topics,
            src_addresses,
            dst_addresses,
            lock_events: Vec::new(),
            unlock_events: Vec::new(),
            balance_deltas: HashMap::new(),
            relay_log: Vec::new(),
            auth_witnesses: HashMap::new(),
            fee_tolerance_ppm,
            fallback_lock_keywords: vec![
                "lock", "dispatch", "deposit", "submit", "send", "claim",
            ],
            fallback_unlock_keywords: vec![
                "unlock", "mint", "process", "release", "redeem", "withdraw",
            ],
        }
    }

    /// Ingest a batch of logs emitted during a single source-fork tx. We
    /// classify as "lock" if either (a) the topic[0] is in the
    /// pre-computed lock-topic table or (b) the emitter address is a
    /// known source-side bridge contract — the second branch covers
    /// real-world bridges where we did not author the metadata's
    /// `events.lock_topic` field yet.
    pub fn ingest_source_logs(&mut self, logs: &[Log]) {
        for log in logs {
            let topic0 = log.topics().first().copied().unwrap_or_default();
            let by_topic = self.lock_topics.contains(&topic0);
            let by_addr = self.src_addresses.contains(&log.address);
            if !(by_topic || by_addr) {
                continue;
            }
            self.lock_events.push(decode_log(log));
        }
    }

    /// Mirror of [`Self::ingest_source_logs`] for destination-side logs.
    pub fn ingest_dest_logs(&mut self, logs: &[Log]) {
        for log in logs {
            let topic0 = log.topics().first().copied().unwrap_or_default();
            let by_topic = self.unlock_topics.contains(&topic0);
            let by_addr = self.dst_addresses.contains(&log.address);
            if !(by_topic || by_addr) {
                continue;
            }
            self.unlock_events.push(decode_unlock_log(log));
        }
    }

    /// Add (or accumulate) a token-balance delta for one address.
    pub fn add_balance_delta(&mut self, addr: Address, delta: i128) {
        let entry = self.balance_deltas.entry(addr).or_insert(0);
        *entry = entry.saturating_add(delta);
    }

    /// Convert every entry of the relay's parsed-log into the local
    /// [`XParsedMsg`] form. We map `parse_mode` strings to the typed
    /// enum the predicates expect.
    pub fn ingest_relay_log(&mut self, log: &[MockParsedMsg]) {
        for msg in log {
            let mode = match msg.parse_mode {
                "faithful" | "faithful_already_processed" => RelayParseMode::Faithful,
                "tampered" => RelayParseMode::Tampered,
                "replayed" => RelayParseMode::Replayed,
                _ => RelayParseMode::Delayed,
            };
            let message_hash = msg.source_msg_hash.unwrap_or_default();
            self.relay_log.push(XParsedMsg {
                message_hash,
                parsed_amount: msg.parsed_amount,
                parsed_recipient: msg.parsed_recipient,
                parse_mode: mode,
            });
        }
    }

    /// Record an auth witness for one cross-chain message. Overwrites
    /// any previous setting for the same message hash.
    pub fn set_auth_witness(&mut self, msg_hash: B256, witness: AuthWitness) {
        self.auth_witnesses.insert(msg_hash, witness);
    }

    /// First-write-wins variant of [`Self::set_auth_witness`]. Used by
    /// the X3-polish C3 wiring to attach a per-bridge auth-witness
    /// recipe value to **every** unlock event captured during the
    /// scenario, while leaving relay-message-derived witnesses (set
    /// earlier via [`Self::set_auth_witness`]) intact.
    pub fn set_auth_witness_default(&mut self, msg_hash: B256, witness: AuthWitness) {
        self.auth_witnesses.entry(msg_hash).or_insert(witness);
    }

    /// Read-only access to the message hashes carried on every captured
    /// unlock-side event. The X3-polish C3 wiring iterates over these
    /// to populate fallback auth witnesses for unlock events whose
    /// hash never appeared in the relay log.
    pub fn unlock_message_hashes(&self) -> Vec<B256> {
        self.unlock_events.iter().map(|e| e.message_hash).collect()
    }

    /// Run the six predicates over the accumulated view.
    pub fn check(&self) -> Vec<XScopeViolation> {
        let view = XScopeView {
            lock_events: &self.lock_events,
            unlock_events: &self.unlock_events,
            balance_deltas: &self.balance_deltas,
            relay_log: &self.relay_log,
            auth_witnesses: &self.auth_witnesses,
            fee_tolerance_ppm: self.fee_tolerance_ppm,
        };
        xscope::check_all(&view)
    }

    /// True iff the topic table was populated from the ATG. Useful for
    /// the fuzz loop to log a warning when no events are recognisable.
    pub fn has_known_topics(&self) -> bool {
        !self.lock_topics.is_empty() || !self.unlock_topics.is_empty()
    }
}

// ============================================================================
// Topic / keyword extraction from the ATG.
// ============================================================================

/// Build (lock_topics, unlock_topics) from ATG edges. Each edge's
/// `function_signature` is canonicalised and hashed; whether it counts
/// as a lock or unlock is decided by keyword match against the edge
/// `label` (or function name when label is empty).
fn topics_from_atg(atg: &AtgGraph) -> (HashSet<B256>, HashSet<B256>) {
    let lock_kw = ["lock", "dispatch", "deposit", "submit", "send", "claim"];
    let unlock_kw = ["unlock", "mint", "process", "release", "redeem", "withdraw"];

    let mut locks = HashSet::new();
    let mut unlocks = HashSet::new();

    for edge in &atg.edges {
        let canonical = canonical_signature(&edge.function_signature);
        if canonical.is_empty() {
            continue;
        }
        let topic0 = revm::primitives::keccak256(canonical.as_bytes());
        let label = edge.label.to_ascii_lowercase();
        let bare_op = canonical
            .split('(')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let needle = if label.is_empty() { bare_op.clone() } else { label };
        if lock_kw.iter().any(|k| needle.contains(*k)) {
            locks.insert(topic0);
        }
        if unlock_kw.iter().any(|k| needle.contains(*k)) {
            unlocks.insert(topic0);
        }
    }
    (locks, unlocks)
}

/// Decode a raw revm log into our [`LockEvent`]. The X3 wiring follows
/// a pragmatic ABI assumption: `data` starts with the right-aligned
/// uint256 amount, then a right-aligned 20-byte recipient. Real bridges
/// that diverge from this layout will produce zeros for the affected
/// fields — predicates degrade gracefully (I-1 still fires off the
/// balance delta; I-2 fires if the recipient zero-pads to 0x0).
fn decode_log(log: &Log) -> LockEvent {
    let topic0 = log.topics().first().copied().unwrap_or_default();
    let message_hash = log
        .topics()
        .get(1)
        .copied()
        .unwrap_or_else(|| revm::primitives::keccak256(&log.data.data));
    let amount = read_u256_word(&log.data.data, 0);
    let recipient = read_address_word(&log.data.data, 32);
    LockEvent {
        address: log.address,
        message_hash,
        amount,
        recipient,
        topic0,
    }
}

fn decode_unlock_log(log: &Log) -> UnlockEvent {
    let topic0 = log.topics().first().copied().unwrap_or_default();
    let message_hash = log
        .topics()
        .get(1)
        .copied()
        .unwrap_or_else(|| revm::primitives::keccak256(&log.data.data));
    let amount = read_u256_word(&log.data.data, 0);
    let recipient = read_address_word(&log.data.data, 32);
    UnlockEvent {
        address: log.address,
        message_hash,
        amount,
        recipient,
        topic0,
    }
}

fn read_u256_word(data: &[u8], offset: usize) -> U256 {
    if data.len() < offset + 32 {
        return U256::ZERO;
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[offset..offset + 32]);
    U256::from_be_bytes(buf)
}

fn read_address_word(data: &[u8], offset: usize) -> Address {
    if data.len() < offset + 32 {
        return Address::ZERO;
    }
    let mut buf = [0u8; 20];
    // Last 20 bytes of the 32-byte word.
    buf.copy_from_slice(&data[offset + 12..offset + 32]);
    Address::from(buf)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use revm::primitives::{Bytes, LogData};

    use std::str::FromStr;

    // 20-byte (40-hex) addresses; deliberately picked so each contract
    // has a unique first byte (0xAA / 0xBB) for easy log debugging.
    const ROUTER_HEX: &str = "0xAA000000000000000000000000000000000000AA";
    const REPLICA_HEX: &str = "0xBB000000000000000000000000000000000000BB";

    fn atg_with_lock_unlock() -> AtgGraph {
        let json = format!(
            r#"{{
          "bridge_name": "synthetic",
          "version": "1.0",
          "nodes": [
            {{"node_id":"router","node_type":"contract","chain":"source",
              "address":"{ROUTER_HEX}","functions":[]}},
            {{"node_id":"replica","node_type":"contract","chain":"destination",
              "address":"{REPLICA_HEX}","functions":[]}}
          ],
          "edges": [
            {{"edge_id":"e1","src":"user","dst":"router","label":"lock","token":"WETH",
              "conditions":[],"function_signature":"dispatch(uint32,uint256,address)"}},
            {{"edge_id":"e2","src":"relay","dst":"replica","label":"mint","token":"WETH",
              "conditions":[],"function_signature":"mint(uint256,address)"}}
          ],
          "invariants": []
        }}"#
        );
        serde_json::from_str(&json).expect("synthetic ATG parses")
    }

    fn router_addr() -> Address {
        Address::from_str(ROUTER_HEX).expect("valid hex")
    }

    fn replica_addr() -> Address {
        Address::from_str(REPLICA_HEX).expect("valid hex")
    }

    fn make_log(addr: Address, topics: Vec<B256>, data_bytes: Vec<u8>) -> Log {
        Log {
            address: addr,
            data: LogData::new_unchecked(topics, Bytes::from(data_bytes)),
        }
    }

    fn encode_amount_recipient(amount: u64, recipient: Address) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        let amt_bytes = amount.to_be_bytes();
        out[32 - 8..32].copy_from_slice(&amt_bytes);
        out[32 + 12..64].copy_from_slice(recipient.as_slice());
        out
    }

    #[test]
    fn topics_from_atg_picks_up_lock_and_unlock_keywords() {
        let atg = atg_with_lock_unlock();
        let (locks, unlocks) = topics_from_atg(&atg);
        assert_eq!(locks.len(), 1);
        assert_eq!(unlocks.len(), 1);
    }

    #[test]
    fn ingest_source_logs_classifies_by_emitter_address() {
        // Even when topic table is empty (bridge metadata.events not
        // populated yet), logs from a known source contract still get
        // captured.
        let nodes_json = format!(
            r#"[{{"node_id":"router","node_type":"contract","chain":"source","address":"{ROUTER_HEX}","functions":[]}}]"#
        );
        let atg = AtgGraph {
            bridge_name: "x".into(),
            version: "1.0".into(),
            nodes: serde_json::from_str(&nodes_json).unwrap(),
            edges: vec![],
            invariants: vec![],
        };
        let registry = ContractRegistry::from_atg(&atg);
        let mut builder = XScopeBuilder::new(&atg, &registry, 10_000);
        assert!(!builder.has_known_topics(), "no edges → no topic table");

        let log = make_log(
            router_addr(),
            vec![B256::from([0xee; 32])],
            encode_amount_recipient(123, Address::from([0x10; 20])),
        );
        builder.ingest_source_logs(&[log]);
        let v = builder.check();
        // One lock, no balance delta recorded → I-1 should fire.
        assert!(v.iter().any(|x| x.predicate_id == "I-1"));
    }

    #[test]
    fn ingest_source_logs_filters_unknown_emitters() {
        let atg = atg_with_lock_unlock();
        let registry = ContractRegistry::from_atg(&atg);
        let mut builder = XScopeBuilder::new(&atg, &registry, 10_000);

        let log = make_log(
            Address::from([0x99; 20]),
            vec![B256::from([0xff; 32])],
            vec![0u8; 64],
        );
        builder.ingest_source_logs(&[log]);
        // Unknown emitter + unknown topic → nothing accepted.
        assert!(builder.lock_events.is_empty());
    }

    #[test]
    fn end_to_end_zero_recipient_fires_i2() {
        // Synthesise a Qubit-style log: lock event with recipient=0x0.
        let atg = atg_with_lock_unlock();
        let registry = ContractRegistry::from_atg(&atg);
        let mut builder = XScopeBuilder::new(&atg, &registry, 10_000);

        let topic_dispatch = revm::primitives::keccak256("dispatch(uint32,uint256,address)".as_bytes());
        let msg_hash = B256::from([0xa1; 32]);
        let log = make_log(
            router_addr(),
            vec![topic_dispatch, msg_hash],
            encode_amount_recipient(1_000_000, Address::ZERO),
        );
        builder.ingest_source_logs(&[log]);
        builder.add_balance_delta(router_addr(), 1_000_000);

        let v = builder.check();
        let ids: Vec<&str> = v.iter().map(|x| x.predicate_id).collect();
        // I-2 should fire (recipient zero); I-1 should hold (balance matches).
        assert!(ids.contains(&"I-2"), "got {:?}", ids);
        assert!(!ids.contains(&"I-1"));
    }

    #[test]
    fn end_to_end_unlock_without_lock_fires_i5_and_i6() {
        let atg = atg_with_lock_unlock();
        let registry = ContractRegistry::from_atg(&atg);
        let mut builder = XScopeBuilder::new(&atg, &registry, 10_000);

        let topic_mint = revm::primitives::keccak256("mint(uint256,address)".as_bytes());
        let msg_hash = B256::from([0xb1; 32]);
        let unlock_log = make_log(
            replica_addr(),
            vec![topic_mint, msg_hash],
            encode_amount_recipient(100, Address::from([0x20; 20])),
        );
        builder.ingest_dest_logs(&[unlock_log]);
        // No auth witness → I-6 should fire as no_authorization_witness.
        let v = builder.check();
        let classes: Vec<&str> = v.iter().map(|x| x.class.as_str()).collect();
        assert!(classes.contains(&"C3.unauthorized_unlocking"), "got {:?}", classes);
        assert!(classes.contains(&"C3.no_authorization_witness"), "got {:?}", classes);
    }

    #[test]
    fn relay_log_mapping_translates_modes() {
        let atg = atg_with_lock_unlock();
        let registry = ContractRegistry::from_atg(&atg);
        let mut builder = XScopeBuilder::new(&atg, &registry, 10_000);

        let mock = vec![
            MockParsedMsg {
                raw_payload: vec![],
                parsed_amount: U256::from(1u64),
                parsed_recipient: Address::ZERO,
                parse_mode: "tampered",
                source_msg_hash: Some(B256::from([0xcc; 32])),
            },
            MockParsedMsg {
                raw_payload: vec![],
                parsed_amount: U256::from(0u64),
                parsed_recipient: Address::from([0x11; 20]),
                parse_mode: "delayed_queued",
                source_msg_hash: Some(B256::from([0xdd; 32])),
            },
        ];
        builder.ingest_relay_log(&mock);
        assert_eq!(builder.relay_log.len(), 2);
        assert_eq!(builder.relay_log[0].parse_mode, RelayParseMode::Tampered);
        assert_eq!(builder.relay_log[1].parse_mode, RelayParseMode::Delayed);
    }
}
