//! Mock Relay
//!
//! Implements the message passing interface of the target bridge protocol
//! under the fuzzer's control. Supports four operation modes:
//! - Faithful: relay messages accurately
//! - Delayed: delay relay by δ blocks (timing attacks)
//! - Tampered: modify message content (forgery attacks)
//! - Replayed: replay previously consumed messages (replay attacks)

use std::collections::{HashSet, VecDeque};

use crate::types::RelayMessage;

/// Relay operation mode.
#[derive(Debug, Clone, Copy)]
pub enum RelayMode {
    Faithful,
    Delayed { delta_blocks: u64 },
    Tampered,
    Replayed,
}

/// Mock relay connecting source and destination chains.
pub struct MockRelay {
    mode: RelayMode,
    message_queue: VecDeque<QueuedMessage>,
    processed_set: HashSet<String>,
    history: Vec<Vec<u8>>,
    message_count: u64,
    current_block: u64,
}

#[derive(Clone)]
struct QueuedMessage {
    available_at_block: u64,
    id: String,
    payload: Vec<u8>,
}

impl MockRelay {
    pub fn new(mode: RelayMode) -> Self {
        Self {
            mode,
            message_queue: VecDeque::new(),
            processed_set: HashSet::new(),
            history: Vec::new(),
            message_count: 0,
            current_block: 0,
        }
    }

    pub fn set_mode(&mut self, mode: RelayMode) {
        self.mode = mode;
    }

    /// Clear queue/history and return to faithful mode (fresh state per fuzz scenario).
    pub fn reset(&mut self) {
        *self = Self::new(RelayMode::Faithful);
    }

    /// Process a message from source chain and relay to destination.
    pub fn relay_message(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.current_block = self.current_block.saturating_add(1);

        match self.mode {
            RelayMode::Faithful => {
                let id = message_id(message);
                if self.processed_set.contains(&id) {
                    return Err("message already processed".to_string());
                }
                self.processed_set.insert(id);
                self.message_count = self.message_count.saturating_add(1);
                self.history.push(message.to_vec());
                Ok(message.to_vec())
            }
            RelayMode::Delayed { delta_blocks } => {
                let id = message_id(message);
                self.message_queue.push_back(QueuedMessage {
                    available_at_block: self.current_block.saturating_add(delta_blocks),
                    id,
                    payload: message.to_vec(),
                });

                if let Some(front) = self.message_queue.front() {
                    if front.available_at_block <= self.current_block {
                        let ready = self.message_queue.pop_front().expect("front exists");
                        if self.processed_set.contains(&ready.id) {
                            return Err("delayed message already processed".to_string());
                        }
                        self.processed_set.insert(ready.id);
                        self.message_count = self.message_count.saturating_add(1);
                        self.history.push(ready.payload.clone());
                        return Ok(ready.payload);
                    }
                }

                Err("message queued for delayed delivery".to_string())
            }
            RelayMode::Tampered => {
                let tampered = tamper_payload(message);
                let id = message_id(&tampered);
                self.processed_set.insert(id);
                self.message_count = self.message_count.saturating_add(1);
                self.history.push(tampered.clone());
                Ok(tampered)
            }
            RelayMode::Replayed => {
                if self.history.is_empty() {
                    self.history.push(message.to_vec());
                }
                let idx = (self.message_count as usize) % self.history.len();
                self.message_count = self.message_count.saturating_add(1);
                Ok(self.history[idx].clone())
            }
        }
    }

    /// Get current relay state for snapshot.
    pub fn get_state(&self) -> RelayState {
        RelayState {
            mode: self.mode,
            message_queue: self
                .message_queue
                .iter()
                .map(|q| (q.available_at_block, q.id.clone(), q.payload.clone()))
                .collect(),
            processed_set: self.processed_set.iter().cloned().collect(),
            history: self.history.clone(),
            message_count: self.message_count,
            current_block: self.current_block,
        }
    }

    /// Restore relay state from snapshot.
    pub fn restore_state(&mut self, state: RelayState) {
        self.mode = state.mode;
        self.message_queue = state
            .message_queue
            .into_iter()
            .map(|(available_at_block, id, payload)| QueuedMessage {
                available_at_block,
                id,
                payload,
            })
            .collect();
        self.processed_set = state.processed_set.into_iter().collect();
        self.history = state.history;
        self.message_count = state.message_count;
        self.current_block = state.current_block;
    }

    pub fn to_relay_snapshot(&self) -> crate::types::RelaySnapshot {
        let pending_messages = self
            .message_queue
            .iter()
            .enumerate()
            .map(|(idx, q)| RelayMessage {
                nonce: idx as u64,
                source_chain: "source".to_string(),
                dest_chain: "destination".to_string(),
                sender: "relay".to_string(),
                recipient: "relay".to_string(),
                data: q.payload.clone(),
                timestamp: q.available_at_block,
            })
            .collect();

        crate::types::RelaySnapshot {
            pending_messages,
            processed_set: self.processed_set.iter().cloned().collect(),
            mode: relay_mode_name(self.mode).to_string(),
            message_count: self.message_count,
        }
    }
}

/// Serializable relay state for snapshot management.
#[derive(Clone)]
pub struct RelayState {
    mode: RelayMode,
    message_queue: Vec<(u64, String, Vec<u8>)>,
    processed_set: Vec<String>,
    history: Vec<Vec<u8>>,
    message_count: u64,
    current_block: u64,
}

fn tamper_payload(message: &[u8]) -> Vec<u8> {
    let mut tampered = message.to_vec();
    if tampered.is_empty() {
        tampered.push(0xff);
    } else {
        tampered[0] ^= 0x01;
    }
    tampered
}

fn message_id(payload: &[u8]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&payload, &mut hasher);
    format!("{:016x}", std::hash::Hasher::finish(&hasher))
}

fn relay_mode_name(mode: RelayMode) -> &'static str {
    match mode {
        RelayMode::Faithful => "faithful",
        RelayMode::Delayed { .. } => "delayed",
        RelayMode::Tampered => "tampered",
        RelayMode::Replayed => "replayed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faithful_mode_relays_same_message() {
        let mut relay = MockRelay::new(RelayMode::Faithful);
        let msg = b"bridge-message";
        let out = relay.relay_message(msg).expect("faithful relay should succeed");
        assert_eq!(out, msg);
    }

    #[test]
    fn delayed_mode_queues_then_releases() {
        let mut relay = MockRelay::new(RelayMode::Delayed { delta_blocks: 1 });
        let first = relay.relay_message(b"m1");
        assert!(first.is_err(), "first delivery should be delayed");

        let second = relay
            .relay_message(b"m2")
            .expect("second call should release first message");
        assert_eq!(second, b"m1");
    }

    #[test]
    fn tampered_mode_modifies_payload() {
        let mut relay = MockRelay::new(RelayMode::Tampered);
        let msg = b"abc";
        let out = relay.relay_message(msg).expect("tampered relay should succeed");
        assert_ne!(out, msg);
        assert_eq!(out.len(), msg.len());
    }

    #[test]
    fn replayed_mode_replays_previous_message() {
        let mut relay = MockRelay::new(RelayMode::Faithful);
        relay.relay_message(b"seed-message").expect("seed message");

        relay.set_mode(RelayMode::Replayed);
        let out = relay
            .relay_message(b"ignored-new-message")
            .expect("replay should succeed");
        assert_eq!(out, b"seed-message");
    }

    #[test]
    fn reset_clears_processed_and_queue() {
        let mut relay = MockRelay::new(RelayMode::Faithful);
        relay.relay_message(b"a").unwrap();
        relay.reset();
        relay.relay_message(b"a").expect("same payload allowed after reset");
    }

    #[test]
    fn relay_state_roundtrip() {
        let mut relay = MockRelay::new(RelayMode::Faithful);
        relay.relay_message(b"x").expect("message should relay");

        let state = relay.get_state();
        relay.set_mode(RelayMode::Tampered);
        relay.restore_state(state);

        let snapshot = relay.to_relay_snapshot();
        assert_eq!(snapshot.mode, "faithful");
        assert_eq!(snapshot.message_count, 1);
    }
}
