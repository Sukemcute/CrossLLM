//! Contract registry — maps ATG node ids to deployed contract addresses,
//! function-signature → 4-byte selector tables, and pre-warms revm's CacheDB
//! by issuing `Database::basic` lookups for every tracked address.
//!
//! Design notes (paper Phase A2):
//! - **On-chain bytecode mode** (production): bytecode lives at the metadata
//!   address on the fork block; we just need to know which address belongs to
//!   which ATG node and pre-fetch it so the first fuzz tx is not blocked on
//!   RPC. This file implements that mode.
//! - **Compile-and-deploy mode** (test bench): `solc` compiles
//!   `benchmarks/<bridge>/contracts/*.sol` to runtime bytecode, then we
//!   `CREATE` it on a fresh fork. Not implemented here — kept as a future
//!   extension that would attach a `compile_and_deploy(node_id, sol_path)`
//!   helper. Fuzzing on real on-chain bytecode is the paper-claim path.

use std::collections::HashMap;
use std::str::FromStr;

use revm::primitives::{keccak256, Address};

use crate::dual_evm::DualEvm;
use crate::types::AtgGraph;

/// Which side of the bridge a node lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainSide {
    Source,
    Destination,
    Relay,
}

impl ChainSide {
    pub fn from_atg(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "source" => Self::Source,
            "destination" | "dest" => Self::Destination,
            _ => Self::Relay,
        }
    }
}

/// Resolves ATG `node_id` strings to deployed addresses + 4-byte selectors.
#[derive(Clone, Debug, Default)]
pub struct ContractRegistry {
    addresses: HashMap<String, Address>,
    chain_of_node: HashMap<String, ChainSide>,
    selectors_of_node: HashMap<String, Vec<[u8; 4]>>,
    sigs_of_node: HashMap<String, Vec<String>>,
}

impl ContractRegistry {
    /// Augment a registry's address map by matching ATG `node_id` strings
    /// against an external `node_id -> hex address` table (case-insensitive
    /// substring match). Used to graft real on-chain addresses from a
    /// benchmark's `metadata.json` onto ATGs the LLM produced without
    /// addresses. Existing entries are not overwritten.
    pub fn merge_address_overrides<S: AsRef<str>, A: AsRef<str>>(
        &mut self,
        overrides: impl IntoIterator<Item = (S, A)>,
    ) {
        let pairs: Vec<(String, Address)> = overrides
            .into_iter()
            .filter_map(|(k, v)| {
                Address::from_str(v.as_ref().trim())
                    .ok()
                    .map(|a| (k.as_ref().to_ascii_lowercase(), a))
            })
            .collect();

        // For each ATG node still missing an address, try to find an override
        // whose key contains the node id (or vice versa, case-insensitive).
        let nodes: Vec<String> = self.chain_of_node.keys().cloned().collect();
        for node_id in nodes {
            if self.addresses.contains_key(&node_id) {
                continue;
            }
            let lower = node_id.to_ascii_lowercase();
            if let Some((_, addr)) = pairs
                .iter()
                .find(|(k, _)| k.contains(&lower) || lower.contains(k.as_str()))
            {
                self.addresses.insert(node_id, *addr);
            }
        }
    }

    /// Build the registry from an ATG. Nodes whose `address` is not parseable
    /// as a 20-byte hex (e.g. mock fixtures use `"0xAttacker"`) are skipped
    /// for the address map but still recorded in `chain_of_node` so the
    /// caller can reason about chain placement.
    ///
    /// Selectors come from edges (`function_signature` field) — for each
    /// edge we attribute the selector to the *destination* node, since that
    /// is where the call lands. Source-side dispatching edges can be
    /// inferred by re-reading the ATG; we only need receivers here.
    pub fn from_atg(atg: &AtgGraph) -> Self {
        let mut reg = Self::default();
        for node in &atg.nodes {
            reg.chain_of_node
                .insert(node.node_id.clone(), ChainSide::from_atg(&node.chain));
            if let Ok(addr) = Address::from_str(node.address.trim()) {
                reg.addresses.insert(node.node_id.clone(), addr);
            }
        }
        for edge in &atg.edges {
            if edge.function_signature.trim().is_empty() {
                continue;
            }
            let canonical = canonical_signature(&edge.function_signature);
            if canonical.is_empty() {
                continue;
            }
            let selector = function_selector(&canonical);
            reg.selectors_of_node
                .entry(edge.dst.clone())
                .or_default()
                .push(selector);
            reg.sigs_of_node
                .entry(edge.dst.clone())
                .or_default()
                .push(edge.function_signature.clone());
        }
        // Dedupe selectors per node (the same signature may appear on multiple edges).
        for v in reg.selectors_of_node.values_mut() {
            v.sort();
            v.dedup();
        }
        reg
    }

    pub fn address_of(&self, node_id: &str) -> Option<Address> {
        self.addresses.get(node_id).copied()
    }

    pub fn chain_of(&self, node_id: &str) -> Option<ChainSide> {
        self.chain_of_node.get(node_id).copied()
    }

    pub fn selectors_of(&self, node_id: &str) -> &[[u8; 4]] {
        self.selectors_of_node
            .get(node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn signatures_of(&self, node_id: &str) -> &[String] {
        self.sigs_of_node
            .get(node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// All deployed addresses, partitioned by side (source first, then destination).
    /// Convenient for [`DualEvm::set_tracked_addresses`].
    pub fn all_addresses(&self) -> Vec<Address> {
        self.addresses
            .iter()
            .map(|(_, a)| *a)
            .collect()
    }

    /// Addresses on a specific chain side.
    pub fn addresses_on(&self, side: ChainSide) -> Vec<Address> {
        self.addresses
            .iter()
            .filter_map(|(node, addr)| {
                if self.chain_of_node.get(node).copied() == Some(side) {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Pre-warm revm's CacheDB by reading each contract's account info on
    /// the relevant fork. After this returns Ok, the first fuzz transaction
    /// against any of these addresses will not block on RPC.
    pub fn warmup_bytecode(&self, dual: &mut DualEvm) -> Result<usize, String> {
        let mut warmed = 0usize;
        for (node_id, addr) in &self.addresses {
            match self.chain_of_node.get(node_id).copied() {
                Some(ChainSide::Source) => {
                    let _ = dual.source_balance(*addr)?;
                    warmed += 1;
                }
                Some(ChainSide::Destination) => {
                    let _ = dual.dest_balance(*addr)?;
                    warmed += 1;
                }
                _ => {}
            }
        }
        Ok(warmed)
    }
}

/// `"foo(uint256 amount, address token)"` → `"foo(uint256,address)"`.
/// Strips param names and any whitespace; preserves type list order.
pub fn canonical_signature(raw: &str) -> String {
    let trimmed = raw.trim();
    let Some(open) = trimmed.find('(') else {
        return String::new();
    };
    let Some(close) = trimmed.rfind(')') else {
        return String::new();
    };
    if close < open {
        return String::new();
    }
    let name = trimmed[..open].split_whitespace().last().unwrap_or("").trim();
    if name.is_empty() {
        return String::new();
    }
    let params = &trimmed[open + 1..close];
    let canonical_params: Vec<String> = params
        .split(',')
        .map(|p| {
            // First whitespace-delimited token is the type; the rest is the
            // (optional) parameter name we want to drop.
            p.split_whitespace().next().unwrap_or("").to_string()
        })
        .filter(|p| !p.is_empty())
        .collect();
    format!("{name}({})", canonical_params.join(","))
}

/// Compute the 4-byte function selector = first 4 bytes of `keccak256(canonical_signature)`.
pub fn function_selector(canonical: &str) -> [u8; 4] {
    let h = keccak256(canonical.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&h.0[..4]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AtgGraph;

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests")
            .join("fixtures")
            .join("atg_mock.json")
    }

    fn load_atg() -> AtgGraph {
        let text = std::fs::read_to_string(fixture_path()).expect("read atg fixture");
        serde_json::from_str(&text).expect("parse atg fixture")
    }

    #[test]
    fn canonical_signature_strips_param_names_and_whitespace() {
        assert_eq!(
            canonical_signature("lock(uint256 amount, address token, address recipient)"),
            "lock(uint256,address,address)"
        );
        assert_eq!(canonical_signature("dispatch()"), "dispatch()");
        assert_eq!(
            canonical_signature("  process( bytes  data , uint256 nonce )  "),
            "process(bytes,uint256)"
        );
        assert_eq!(canonical_signature(""), "");
        assert_eq!(canonical_signature("noopen"), "");
    }

    #[test]
    fn selector_matches_known_erc20_transfer() {
        // ERC-20 `transfer(address,uint256)` selector is `0xa9059cbb`.
        assert_eq!(function_selector("transfer(address,uint256)"), [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn registry_resolves_node_addresses_and_chains() {
        let atg = load_atg();
        let reg = ContractRegistry::from_atg(&atg);

        // Real hex addresses get parsed.
        let replica = reg.address_of("replica").expect("replica address");
        assert_eq!(
            format!("{replica:#x}"),
            "0x5d94309e5a0090b165fa4181519701637b6daeba"
        );
        assert_eq!(reg.chain_of("replica"), Some(ChainSide::Destination));

        let router = reg.address_of("source_router").expect("source_router address");
        assert_eq!(
            format!("{router:#x}"),
            "0xb92336759618f55bd0f8313bd843604592e27bd8"
        );
        assert_eq!(reg.chain_of("source_router"), Some(ChainSide::Source));

        // Mock-style invalid addresses are skipped from the address map but
        // the chain placement is still recorded.
        assert!(reg.address_of("user_a").is_none());
        assert_eq!(reg.chain_of("user_a"), Some(ChainSide::Source));

        // Relay chain.
        assert_eq!(reg.chain_of("relay"), Some(ChainSide::Relay));
    }

    #[test]
    fn registry_collects_selectors_from_edges() {
        let atg = load_atg();
        let reg = ContractRegistry::from_atg(&atg);

        // e3: relay -> replica via proveAndProcess(bytes,bytes,uint256)
        // e4: replica -> bridge_router via handle(uint32,uint32,bytes32,bytes)
        let replica_sels = reg.selectors_of("replica");
        assert_eq!(replica_sels.len(), 1, "replica receives one signature");
        assert_eq!(
            replica_sels[0],
            function_selector("proveAndProcess(bytes,bytes,uint256)")
        );

        let bridge_sels = reg.selectors_of("bridge_router");
        assert_eq!(bridge_sels.len(), 1);
        assert_eq!(
            bridge_sels[0],
            function_selector("handle(uint32,uint32,bytes32,bytes)")
        );

        // source_router is dst of e1 (user_a -> source_router via dispatch).
        let src_router_sels = reg.selectors_of("source_router");
        assert_eq!(src_router_sels.len(), 1);
        assert_eq!(
            src_router_sels[0],
            function_selector("dispatch(uint32,bytes32,uint256,bytes)")
        );

        // user_b is dst of e5 (transfer) but invalid hex address; we still
        // record the selector since the table is keyed on node_id (not address).
        let user_b_sels = reg.selectors_of("user_b");
        assert_eq!(user_b_sels.len(), 1);
        assert_eq!(user_b_sels[0], function_selector("transfer(address,uint256)"));
    }

    #[test]
    fn addresses_on_partitions_by_chain() {
        let atg = load_atg();
        let reg = ContractRegistry::from_atg(&atg);
        let dest = reg.addresses_on(ChainSide::Destination);
        // Destination has: replica + bridge_router (parseable hex). user_b is
        // "0xRecipient" (invalid hex) so it's not in the address map.
        assert_eq!(dest.len(), 2, "dest contracts: replica + bridge_router");
        let src = reg.addresses_on(ChainSide::Source);
        assert_eq!(src.len(), 1, "source contracts: source_router only");
    }
}
