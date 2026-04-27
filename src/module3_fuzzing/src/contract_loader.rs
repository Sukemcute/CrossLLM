//! Benchmark-aware contract/address loader for Module 3.
//!
//! Reads benchmark bundle files adjacent to `atg.json`:
//! - `../mapping.json`
//! - `../metadata.json`
//! and builds a best-effort `node_id -> address` resolution table.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::types::AtgGraph;

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

    /// Build a human-readable deployment plan/log for current benchmark bundle.
    ///
    /// This is an A2 stepping stone before full compile+deploy helper:
    /// it records which `.sol` sources were discovered and which ATG nodes already
    /// map to concrete addresses.
    pub fn deployment_plan_log(&self, atg: &AtgGraph) -> Vec<String> {
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

        log.push("deploy_helper_status=planned_only (compile/deploy hook pending)".to_string());
        log
    }
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
            plan.node_to_address.insert(n.node_id.clone(), n.address.clone());
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

