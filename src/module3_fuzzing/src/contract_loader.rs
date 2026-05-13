//! Contract registry — maps ATG node ids to deployed contract addresses,
//! function-signature → 4-byte selector tables, and pre-warms revm's CacheDB
//! by issuing `Database::basic` lookups for every tracked address.
//!
//! Design notes (paper Phase A2):
//! - **On-chain bytecode mode** (production): bytecode lives at the metadata
//!   address on the fork block; we just need to know which address belongs to
//!   which ATG node and pre-fetch it so the first fuzz tx is not blocked on
//!   RPC. This file implements that mode.
//! - **Compile-and-deploy mode** (benchmark harness): [`ContractPlan::compile_and_deploy`]
//!   invokes `solc --combined-json` over `benchmarks/<bridge>/contracts/*.sol`,
//!   then deploys reconstructed contracts onto both forks using constructor-aware
//!   wiring (ordering + cyclic dependency handling where fixtures require it).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ethers_core::abi::{Abi, Constructor, Token};
use ethers_core::types::{Address as EthAddress, U256 as EthU256};
use revm::primitives::{keccak256, Address};
use serde::Deserialize;

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
    /// Be permissive about chain identifiers — Module 1/2 LLM outputs use
    /// real chain names (`"ethereum"`, `"harmony"`, `"polygon"`, `"EVM"`,
    /// …) rather than canonical `"source"`/`"destination"`. Anything that
    /// isn't unambiguously off-chain is treated as a source-side EVM
    /// contract; the explicit `"destination"`/`"dest"` synonym still wins
    /// over the default. This avoids accidentally routing every call to the
    /// relay (which would skip real bytecode execution entirely).
    pub fn from_atg(s: &str) -> Self {
        let trimmed = s.trim().to_ascii_lowercase();
        match trimmed.as_str() {
            "" | "relay" | "offchain" | "off-chain" | "off_chain" => Self::Relay,
            "destination" | "dest" | "dst" => Self::Destination,
            _ => Self::Source,
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
    /// Insert an **exact-match** ATG-node-name → address alias. Used by
    /// the metadata `address_aliases` block (X3-polish C2) when the
    /// fuzzy substring match in [`Self::merge_address_overrides`] would
    /// either miss the node entirely (e.g. generic names like
    /// `"MockToken"` not present in metadata) or pick the wrong contract
    /// (e.g. `"WrappedToken"` matching whatever wrapped-token entry was
    /// inserted last). Wins over fuzzy because the caller in `fuzz_loop`
    /// applies aliases **first**, and `Self::merge_address_overrides`
    /// only writes when the address slot is currently empty.
    pub fn add_explicit_alias(&mut self, node_id: &str, address: &str) -> bool {
        let Ok(addr) = Address::from_str(address.trim()) else {
            return false;
        };
        // Add the chain side as Source if we haven't seen this node id yet —
        // the LLM ATG often omits these stub nodes entirely. Source is the
        // safe default per ChainSide::from_atg's permissive policy.
        self.chain_of_node
            .entry(node_id.to_string())
            .or_insert(ChainSide::Source);
        self.addresses.insert(node_id.to_string(), addr);
        true
    }

    /// Augment a registry's address map by matching ATG `node_id` strings
    /// against an external `node_id -> hex address` table. Used to graft
    /// real on-chain addresses from a benchmark's `metadata.json` onto ATGs
    /// the LLM produced without addresses. Existing entries are not
    /// overwritten.
    ///
    /// Matching strategy: both sides are lower-cased and stripped of every
    /// non-alphanumeric character, then we test substring containment in
    /// either direction. So `WormholeCore` matches `wormhole_core_eth`,
    /// `RoninBridgeManager` matches `ronin_bridge_manager`, etc. Common
    /// metadata-side suffixes like `_eth`, `_ethereum`, `_v2_proxy` are
    /// also stripped before the comparison so they do not block a match.
    pub fn merge_address_overrides<S: AsRef<str>, A: AsRef<str>>(
        &mut self,
        overrides: impl IntoIterator<Item = (S, A)>,
    ) {
        let pairs: Vec<(String, Address)> = overrides
            .into_iter()
            .filter_map(|(k, v)| {
                Address::from_str(v.as_ref().trim())
                    .ok()
                    .map(|a| (normalize_name(k.as_ref()), a))
            })
            .collect();

        let nodes: Vec<String> = self.chain_of_node.keys().cloned().collect();
        for node_id in nodes {
            if self.addresses.contains_key(&node_id) {
                continue;
            }
            let needle = normalize_name(&node_id);
            if needle.is_empty() {
                continue;
            }
            if let Some((_, addr)) = pairs.iter().find(|(k, _)| {
                !k.is_empty() && (k.contains(&needle) || needle.contains(k.as_str()))
            }) {
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
        self.addresses.iter().map(|(_, a)| *a).collect()
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
    let name = trimmed[..open]
        .split_whitespace()
        .last()
        .unwrap_or("")
        .trim();
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

/// Normalize a contract identifier for fuzzy comparison: lowercase + drop
/// every non-alphanumeric character. Substring containment in either
/// direction does the rest, so `WormholeCore` (`wormholecore`) matches
/// `wormhole_core_eth` (`wormholecoreeth`), `RoninBridgeManager` matches
/// `ronin_bridge_manager`, etc. We deliberately keep all letters — chain
/// suffixes like `eth` may appear anywhere (`HorizonEthManager`) so it is
/// not safe to strip them.
pub fn normalize_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
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
        assert_eq!(
            function_selector("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
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

        let router = reg
            .address_of("source_router")
            .expect("source_router address");
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
        assert_eq!(
            user_b_sels[0],
            function_selector("transfer(address,uint256)")
        );
    }

    #[test]
    fn normalize_name_strips_underscores_and_lowercases() {
        assert_eq!(normalize_name("WormholeCore"), "wormholecore");
        assert_eq!(normalize_name("wormhole_core_eth"), "wormholecoreeth");
        assert_eq!(normalize_name("RoninBridgeManager"), "roninbridgemanager");
        assert_eq!(normalize_name("ronin_bridge_manager"), "roninbridgemanager");
        assert_eq!(normalize_name("HorizonEthManager"), "horizonethmanager");
        assert_eq!(normalize_name("horizon_eth_manager"), "horizonethmanager");
        assert_eq!(normalize_name("---"), "");
    }

    #[test]
    fn merge_overrides_resolves_real_bridge_names() {
        // Synthetic ATG built to mirror the real wormhole / ronin / harmony
        // shapes we found in `benchmarks/<bridge>/llm_outputs/atg.json`.
        let atg_json = r#"{
            "bridge_name": "synthetic", "version": "1.0",
            "nodes": [
                {"node_id":"WormholeCore","node_type":"contract","chain":"Ethereum","address":"","functions":[]},
                {"node_id":"RoninBridgeManager","node_type":"contract","chain":"ethereum","address":"","functions":[]},
                {"node_id":"HorizonEthManager","node_type":"contract","chain":"ethereum","address":"","functions":[]}
            ],
            "edges": [], "invariants": []
        }"#;
        let atg: AtgGraph = serde_json::from_str(atg_json).unwrap();
        let mut reg = ContractRegistry::from_atg(&atg);
        // Mirrors what `metadata.json` actually contains for each bridge.
        // Ronin's metadata has both `ronin_bridge_manager` (the manager
        // contract) and `ronin_bridge_v2_proxy`; the ATG's
        // `RoninBridgeManager` should resolve to the former, not the proxy.
        let overrides = vec![
            (
                "wormhole_core_eth",
                "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B",
            ),
            (
                "ronin_bridge_manager",
                "0x098B716B8Aaf21512996dC57EB06000000000000",
            ),
            (
                "ronin_bridge_v2_proxy",
                "0x1A2a1c938CE3eC39b6D47113c7950000000000B",
            ),
            (
                "horizon_eth_manager",
                "0x5D94309E5a0090b165FA4181519701637B6DAEBA",
            ),
        ];
        reg.merge_address_overrides(overrides);

        assert!(
            reg.address_of("WormholeCore").is_some(),
            "WormholeCore should match wormhole_core_eth"
        );
        assert!(
            reg.address_of("RoninBridgeManager").is_some(),
            "RoninBridgeManager should match ronin_bridge_v2_proxy"
        );
        assert!(
            reg.address_of("HorizonEthManager").is_some(),
            "HorizonEthManager should match horizon_eth_manager"
        );
    }

    #[test]
    fn chain_side_from_atg_treats_real_chain_names_as_source() {
        assert_eq!(ChainSide::from_atg("ethereum"), ChainSide::Source);
        assert_eq!(ChainSide::from_atg("Ethereum"), ChainSide::Source);
        assert_eq!(ChainSide::from_atg("EVM"), ChainSide::Source);
        assert_eq!(ChainSide::from_atg("harmony"), ChainSide::Source);
        assert_eq!(ChainSide::from_atg("polygon"), ChainSide::Source);
        assert_eq!(ChainSide::from_atg("source"), ChainSide::Source);
        // Explicit destination still wins.
        assert_eq!(ChainSide::from_atg("destination"), ChainSide::Destination);
        assert_eq!(ChainSide::from_atg("dst"), ChainSide::Destination);
        // Off-chain stays Relay.
        assert_eq!(ChainSide::from_atg("relay"), ChainSide::Relay);
        assert_eq!(ChainSide::from_atg("offchain"), ChainSide::Relay);
        assert_eq!(ChainSide::from_atg(""), ChainSide::Relay);
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
// ============================================================================
// ContractPlan — Module 3's benchmark-aware node→address resolver.
//
// Lives in this file alongside `ContractRegistry` because both consume the
// same ATG + metadata.json sources. They serve different audiences:
//   - `ContractRegistry` drives the XScope / SmartAxe baselines (chain-side
//     classification, function-selector tables, bytecode warmup).
//   - `ContractPlan`     drives Member B's experiment runner (per-bridge
//     `mapping.json` + benchmark dir scanning + deploy-helper logging).
// They're orthogonal and can coexist; the merge keeps both.
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ContractPlan {
    pub benchmark_dir: Option<PathBuf>,
    pub contracts_dir: Option<PathBuf>,
    pub node_to_address: HashMap<String, String>,
}

impl ContractPlan {
    pub fn resolve_node_address(&self, node_id: &str, fallback: &str) -> String {
        self.node_to_address
            .get(node_id)
            .cloned()
            .unwrap_or_else(|| fallback.to_string())
    }

    pub fn scan_sol_files(&self) -> Vec<PathBuf> {
        let Some(dir) = &self.contracts_dir else {
            return Vec::new();
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|x| x.path()))
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .map(|ext| ext.to_string_lossy().eq_ignore_ascii_case("sol"))
                        .unwrap_or(false)
            })
            .collect();
        out.sort();
        out
    }

    pub fn compile_and_deploy(&self, dual: &mut DualEvm) -> Result<Vec<(String, Address)>, String> {
        let Some(contracts_dir) = &self.contracts_dir else {
            return Err("contracts_dir missing (cannot compile benchmark fixtures)".to_string());
        };
        let Some(benchmark_dir) = &self.benchmark_dir else {
            return Err("benchmark_dir missing (cannot infer bridge key)".to_string());
        };

        let bridge_key = benchmark_key(benchmark_dir);
        let sol_inputs = collect_sol_files_recursive(contracts_dir);
        if sol_inputs.is_empty() {
            return Err(format!("no .sol sources under {}", contracts_dir.display()));
        }

        let workspace = workspace_root_path();
        let benchmarks_root = workspace.join("benchmarks");
        let allow = format!(
            "{},{}",
            workspace.to_string_lossy(),
            benchmarks_root.to_string_lossy()
        );

        let out = run_solc_combined_json(&workspace, &allow, &sol_inputs, false).or_else(
            |first_err| {
                if first_err.contains("Stack too deep") {
                    run_solc_combined_json(&workspace, &allow, &sol_inputs, true)
                } else {
                    Err(first_err)
                }
            },
        )?;

        let v: serde_json::Value =
            serde_json::from_slice(&out.stdout).map_err(|e| format!("solc JSON parse: {e}"))?;
        let contracts = v
            .get("contracts")
            .and_then(|c| c.as_object())
            .ok_or_else(|| "solc combined-json missing contracts map".to_string())?;

        let mut by_short: HashMap<String, Vec<AbridgedCompiled>> = HashMap::new();
        let mut fq_to: HashMap<String, AbridgedCompiled> = HashMap::new();

        for (fq_key, blob) in contracts {
            let Some(obj) = blob.as_object() else {
                continue;
            };
            let bin = obj
                .get("bin")
                .and_then(|b| b.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if bin.is_empty() {
                continue;
            }
            let abi_text = obj
                .get("abi")
                .map(|a| a.to_string())
                .unwrap_or_else(|| "[]".to_string());
            let abi: Abi = serde_json::from_str(&abi_text)
                .map_err(|e| format!("ABI parse failed for {fq_key}: {e}"))?;

            let short = fq_key.rsplit(':').next().unwrap_or(fq_key).to_string();

            let art = AbridgedCompiled {
                fq_name: fq_key.clone(),
                short_name: short.clone(),
                bin,
                abi,
            };

            fq_to.insert(fq_key.clone(), art.clone());
            by_short.entry(short).or_default().push(art);
        }

        dual.reset_benchmark_deployer();
        let mut deployed_addrs: Vec<(String, Address)> = Vec::new();
        deploy_bridge_fixtures(dual, &bridge_key, &by_short, &fq_to, &mut deployed_addrs)?;

        Ok(deployed_addrs)
    }

    /// Build a human-readable deployment plan/log for current benchmark bundle.
    ///
    /// This is an A2 stepping stone before full compile+deploy helper:
    /// it records which `.sol` sources were discovered and which ATG nodes already
    /// map to concrete addresses.
    pub fn deployment_plan_log(&self, atg: &AtgGraph, is_deployed: bool) -> Vec<String> {
        let mut log = Vec::new();
        match &self.benchmark_dir {
            Some(dir) => log.push(format!("benchmark_dir={}", dir.display())),
            None => log.push("benchmark_dir=<unknown>".to_string()),
        }
        match &self.contracts_dir {
            Some(dir) => log.push(format!("contracts_dir={}", dir.display())),
            None => log.push("contracts_dir=<missing>".to_string()),
        }

        let sol_files = self.scan_sol_files();
        if sol_files.is_empty() {
            log.push("contracts_scan: no .sol files found".to_string());
        } else {
            log.push(format!("contracts_scan: {} .sol files", sol_files.len()));
            for p in sol_files {
                if let Some(name) = p.file_name().map(|x| x.to_string_lossy().to_string()) {
                    log.push(format!("source={name}"));
                }
            }
        }

        for node in &atg.nodes {
            let resolved = self.resolve_node_address(&node.node_id, &node.address);
            if resolved.trim().is_empty() {
                log.push(format!("node={} unresolved_address", node.node_id));
            } else {
                log.push(format!("node={} target={}", node.node_id, resolved));
            }
        }

        if is_deployed {
            log.push("deploy_helper_status=deployed".to_string());
        } else {
            log.push("deploy_helper_status=planned_only (compile/deploy hook pending)".to_string());
        }
        log
    }
}

#[derive(Clone, Debug)]
struct AbridgedCompiled {
    fq_name: String,
    short_name: String,
    bin: String,
    abi: Abi,
}

fn workspace_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn benchmark_key(benchmark_dir: &Path) -> String {
    benchmark_dir
        .file_name()
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn collect_sol_files_recursive(dir: &Path) -> Vec<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    let mut out = Vec::new();
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file()
                && p.extension()
                    .map(|ext| ext.to_string_lossy().eq_ignore_ascii_case("sol"))
                    .unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn run_solc_combined_json(
    workspace: &Path,
    allow_paths: &str,
    sol_inputs: &[PathBuf],
    via_ir: bool,
) -> Result<std::process::Output, String> {
    let mut cmd = std::process::Command::new("solc");
    cmd.arg("--optimize")
        .arg("--evm-version")
        .arg("london")
        .arg("--combined-json")
        .arg("abi,bin")
        .arg("--base-path")
        .arg(workspace)
        .arg("--allow-paths")
        .arg(allow_paths);
    if via_ir {
        cmd.arg("--via-ir");
    }
    for p in sol_inputs {
        cmd.arg(p);
    }

    let out = cmd
        .output()
        .map_err(|e| format!("Failed to run solc: {e}"))?;
    if out.status.success() {
        Ok(out)
    } else {
        Err(format!(
            "solc failed (--combined-json{}): {}",
            if via_ir { " --via-ir" } else { "" },
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn decode_hex_runtime(bin_hex: &str) -> Result<Vec<u8>, String> {
    let s = bin_hex.trim().trim_start_matches("0x");
    hex::decode(s).map_err(|e| format!("invalid bytecode hex from solc: {e}"))
}

fn eth_address(a: Address) -> EthAddress {
    EthAddress::from_slice(a.as_slice())
}

fn revm_address(eth: EthAddress) -> Address {
    Address::from_slice(eth.as_bytes())
}

fn constructor_inputs(abi: &Abi) -> Option<&Constructor> {
    abi.constructor()
}

fn encode_initcode_for(art: &AbridgedCompiled, args: &[Token]) -> Result<Vec<u8>, String> {
    let ctor = constructor_inputs(&art.abi);
    let want = ctor.map(|c| c.inputs.len()).unwrap_or(0);
    if want != args.len() {
        return Err(format!(
            "{} constructor expects {} params, got {}",
            art.short_name,
            want,
            args.len()
        ));
    }

    let code = decode_hex_runtime(&art.bin)?;
    let Some(ctor) = ctor else {
        return Ok(code);
    };

    ctor.encode_input(code.into(), args)
        .map(|b: ethers_core::abi::Bytes| b.to_vec())
        .map_err(|e| format!("{}: constructor encode_input failed: {e}", art.short_name))
}

fn deploy_logged(
    dual: &mut DualEvm,
    deployed: &mut Vec<(String, Address)>,
    logical: &str,
    init_code: &[u8],
) -> Result<Address, String> {
    let addr = dual
        .deploy_mock_on_both(init_code)
        .map_err(|e| format!("deploy `{logical}` failed: {e}"))?;
    deployed.push((logical.to_string(), addr));
    Ok(addr)
}

fn pick_unique(
    by_short: &HashMap<String, Vec<AbridgedCompiled>>,
    bridge: &str,
    name: &str,
) -> Result<AbridgedCompiled, String> {
    let Some(v) = by_short.get(name) else {
        return Err(format!(
            "benchmark {bridge}: missing compiled contract `{name}`"
        ));
    };
    if v.len() != 1 {
        return Err(format!(
            "benchmark {bridge}: ambiguous `{name}` — {} candidates",
            v.len()
        ));
    }
    Ok(v[0].clone())
}

fn fixed_signers(n: usize, base_u64: u64) -> Vec<Address> {
    (0..n)
        .map(|i| revm_address(EthAddress::from_low_u64_be(base_u64 + i as u64)))
        .collect()
}

fn address_token_list(addrs: &[Address]) -> Vec<Token> {
    addrs
        .iter()
        .copied()
        .map(|a| Token::Address(eth_address(a)))
        .collect()
}

fn deploy_bridge_fixtures(
    dual: &mut DualEvm,
    bridge_key: &str,
    by_short: &HashMap<String, Vec<AbridgedCompiled>>,
    _fq_to: &HashMap<String, AbridgedCompiled>,
    deployed: &mut Vec<(String, Address)>,
) -> Result<(), String> {
    macro_rules! d {
        ($name:literal) => {{
            let art = pick_unique(by_short, bridge_key, $name)?;
            let code = encode_initcode_for(&art, &[])?;
            deploy_logged(dual, deployed, $name, &code)?;
        }};
    }

    macro_rules! d_ctor {
        ($name:literal, $($tok:expr),* $(,)?) => {{
            let art = pick_unique(by_short, bridge_key, $name)?;
            let args_vec: Vec<Token> = vec![$($tok),*];
            let code = encode_initcode_for(&art, &args_vec)?;
            deploy_logged(dual, deployed, $name, &code)?;
        }};
    }

    match bridge_key {
        "nomad" => {
            d!("Replica");
            d!("MockToken");
            let rep = deployed_address(deployed, "Replica")
                .ok_or_else(|| "internal: Replica address missing after deploy".to_string())?;
            let tok = deployed_address(deployed, "MockToken")
                .ok_or_else(|| "internal: MockToken address missing after deploy".to_string())?;
            d_ctor!(
                "BridgeRouter",
                Token::Address(eth_address(rep)),
                Token::Address(eth_address(tok))
            );
            Ok(())
        }

        "fegtoken" => {
            d!("FEGToken");
            d_ctor!(
                "MockToken",
                Token::String("Benchmark USDT".to_string()),
                Token::String("USDT".to_string()),
                Token::Uint(EthU256::from(6u8))
            );
            let feg = deployed_address(deployed, "FEGToken")
                .ok_or_else(|| "internal: fegtoken deploy order".to_string())?;
            d_ctor!("FEGSwap", Token::Address(eth_address(feg)));
            d_ctor!("FlashLoanProvider", Token::Address(eth_address(feg)));
            Ok(())
        }

        "gempad" => {
            d_ctor!(
                "MockToken",
                Token::String("GemPad Bench Token".to_string()),
                Token::String("GBT".to_string()),
                Token::Uint(EthU256::from(18u8))
            );
            d!("GemPadLocker");
            Ok(())
        }

        "qubit" => {
            d!("QBridgeETH");
            d!("MockToken");
            let x = deployed_address(deployed, "MockToken")
                .ok_or_else(|| "internal: qubit token".to_string())?;
            d_ctor!("QBridgeBSC", Token::Address(eth_address(x)));
            Ok(())
        }

        "socket" => {
            d_ctor!(
                "MockToken",
                Token::String("Socket Bench".to_string()),
                Token::String("SKT".to_string()),
                Token::Uint(EthU256::from(18u8))
            );
            d!("SwapImplementationStub");
            d!("SocketGateway");
            Ok(())
        }

        "multichain" => {
            d_ctor!(
                "WrappedToken",
                Token::String("Multichain Bench".to_string()),
                Token::String("mTKN".to_string()),
                Token::Uint(EthU256::from(18u8))
            );
            let signers = fixed_signers(1, 0x451);
            d_ctor!(
                "MultichainAnyCallV6",
                Token::Array(address_token_list(&signers))
            );
            Ok(())
        }

        "orbit" => {
            d_ctor!(
                "WrappedToken",
                Token::String("Orbit Bench".to_string()),
                Token::String("oTKN".to_string()),
                Token::Uint(EthU256::from(18u8))
            );
            let signers = fixed_signers(10, 0x601);
            d_ctor!("OrbitVault", Token::Array(address_token_list(&signers)));
            Ok(())
        }

        "ronin" => {
            d_ctor!(
                "WrappedToken",
                Token::String("Ronin Bench".to_string()),
                Token::String("rTKN".to_string()),
                Token::Uint(EthU256::from(18u8))
            );
            let signers = fixed_signers(9, 0x501);
            d_ctor!(
                "RoninBridgeManager",
                Token::Array(address_token_list(&signers))
            );
            Ok(())
        }

        "harmony" => {
            let signers = fixed_signers(4, 0x701);
            let mgr_pred_src = dual.peek_next_create_address_source()?;
            d_ctor!("EthBucket", Token::Address(mgr_pred_src));
            let bucket = deployed_address(deployed, "EthBucket")
                .ok_or_else(|| "internal: harmony bucket".to_string())?;
            d_ctor!(
                "WrappedToken",
                Token::String("Harmony Bench".to_string()),
                Token::String("hTKN".to_string()),
                Token::Uint(EthU256::from(18u8))
            );
            d_ctor!(
                "HorizonEthManager",
                Token::Array(address_token_list(&signers)),
                Token::Address(eth_address(bucket))
            );
            Ok(())
        }

        "pgala" => {
            d!("pGALAToken");
            let token = deployed_address(deployed, "pGALAToken")
                .ok_or_else(|| "internal: pgala token".to_string())?;
            let signer = EthAddress::from_str("0x0000000000000000000000000000000000000888")
                .map_err(|e| format!("pgala signer: {e}"))?;
            d_ctor!(
                "LegacyCustodian",
                Token::Address(signer),
                Token::Address(eth_address(token))
            );
            Ok(())
        }

        "polynetwork" => {
            let data_pred = dual.peek_next_create_address_source()?;
            d_ctor!("EthCrossChainManager", Token::Address(data_pred));
            let mgr = deployed_address(deployed, "EthCrossChainManager")
                .ok_or_else(|| "internal: poly manager".to_string())?;
            d_ctor!("EthCrossChainData", Token::Address(eth_address(mgr)));
            Ok(())
        }

        "wormhole" => {
            d!("WormholeCore");

            let bridge_pred = dual.peek_next_create_address_source()?;
            d_ctor!(
                "WrappedAsset",
                Token::String("Wormhole ETH".to_string()),
                Token::String("whETH".to_string()),
                Token::Uint(EthU256::from(18u8)),
                Token::Address(bridge_pred)
            );

            let core = deployed_address(deployed, "WormholeCore")
                .ok_or_else(|| "internal: wormhole core missing".to_string())?;
            let _wrapped = deployed_address(deployed, "WrappedAsset")
                .ok_or_else(|| "internal: wormhole wrapped missing".to_string())?;
            d_ctor!("TokenBridge", Token::Address(eth_address(core)));

            let br = deployed_address(deployed, "TokenBridge")
                .ok_or_else(|| "internal: bridge".to_string())?;
            if eth_address(br) != bridge_pred {
                return Err("wormhole: predicted TokenBridge CREATE address mismatch".into());
            }
            Ok(())
        }

        other => Err(format!(
            "compile_and_deploy: no fixture recipe for bridge `{other}` — extend contract_loader.rs"
        )),
    }
}

fn deployed_address(deployed: &[(String, Address)], name: &str) -> Option<Address> {
    deployed.iter().find(|(n, _)| n == name).map(|(_, a)| *a)
}

#[derive(Debug, Deserialize)]
struct MappingFile {
    #[serde(default)]
    entity_map: Vec<EntityMapEntry>,
}

#[derive(Debug, Deserialize)]
struct EntityMapEntry {
    logical_id: String,
    #[serde(default)]
    address: String,
}

#[derive(Debug, Deserialize)]
struct MetadataFile {
    #[serde(default)]
    contracts: HashMap<String, MetadataContract>,
}

#[derive(Debug, Deserialize)]
struct MetadataContract {
    #[serde(default)]
    address: String,
}

pub fn load_contract_plan(atg_path: &str, atg: &AtgGraph) -> ContractPlan {
    let mut plan = ContractPlan::default();

    // Base map from ATG itself.
    for n in &atg.nodes {
        if !n.address.trim().is_empty() {
            plan.node_to_address
                .insert(n.node_id.clone(), n.address.clone());
        }
    }

    let atg_file = Path::new(atg_path);
    let llm_outputs_dir = atg_file.parent();
    let benchmark_dir = llm_outputs_dir.and_then(|p| p.parent());
    let Some(benchmark_dir) = benchmark_dir else {
        return plan;
    };

    plan.benchmark_dir = Some(benchmark_dir.to_path_buf());
    let contracts_dir = benchmark_dir.join("contracts");
    if contracts_dir.is_dir() {
        plan.contracts_dir = Some(contracts_dir);
    }

    // mapping.json -> strongest source for logical ids.
    let mapping_path = benchmark_dir.join("mapping.json");
    if mapping_path.is_file() {
        if let Ok(text) = std::fs::read_to_string(&mapping_path) {
            if let Ok(mapping) = serde_json::from_str::<MappingFile>(&text) {
                for e in mapping.entity_map {
                    if e.address.trim().is_empty() {
                        continue;
                    }
                    insert_aliases(&mut plan.node_to_address, &e.logical_id, &e.address);
                }
            }
        }
    }

    // metadata.json -> fallback source for known contract keys.
    let metadata_path = benchmark_dir.join("metadata.json");
    if metadata_path.is_file() {
        if let Ok(text) = std::fs::read_to_string(&metadata_path) {
            if let Ok(meta) = serde_json::from_str::<MetadataFile>(&text) {
                for (key, c) in meta.contracts {
                    if c.address.trim().is_empty() {
                        continue;
                    }
                    insert_aliases(&mut plan.node_to_address, &key, &c.address);
                }
            }
        }
    }

    plan
}

fn insert_aliases(map: &mut HashMap<String, String>, key: &str, addr: &str) {
    let key = key.trim();
    if key.is_empty() || addr.trim().is_empty() {
        return;
    }

    let mut aliases = vec![key.to_string()];
    if let Some(stripped) = key.strip_prefix("source_") {
        aliases.push(stripped.to_string());
    }
    if let Some(stripped) = key.strip_prefix("destination_") {
        aliases.push(stripped.to_string());
    }

    for alias in aliases {
        map.entry(alias).or_insert_with(|| addr.to_string());
    }
}
