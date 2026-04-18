//! Dual-EVM Environment
//!
//! Manages two independent EVM instances (source chain + destination chain)
//! connected through a mock relay process.
//!
//! Each EVM instance is initialized by forking blockchain state at a specified block number
//! via JSON-RPC ([`revm::db::EthersDB`] + [`revm::db::CacheDB`]).

use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use ethers_core::types::{BlockId as EthBlockId, H256 as EthH256};
use ethers_providers::{Http, Middleware, Provider};
use revm::db::{CacheDB, EthersDB};
use revm::{
    primitives::{
        specification::SpecId,
        AccountInfo, Address, BlockEnv, Bytes, CfgEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg,
        ExecutionResult, HandlerCfg, Output, TransactTo, TxEnv, B256, KECCAK_EMPTY, U256,
    },
    Database, DatabaseRef, Evm,
};

use crate::types::{ChainState, GlobalState, RelaySnapshot};

/// Default funded EOA used when executing calls from the fuzzer (unlimited balance in cache).
pub fn default_caller() -> Address {
    static C: OnceLock<Address> = OnceLock::new();
    *C.get_or_init(|| {
        Address::from_str("0x0000000000000000000000000000000000000001").expect("valid address")
    })
}

/// Minimum calldata length for [`DualEvm::execute_on_source`] / [`DualEvm::execute_on_dest`]:
/// `20 bytes caller || 20 bytes contract || optional ABI calldata`.
pub const EXECUTE_CALL_HEADER: usize = 40;

/// One EVM fork (CacheDB over RPC-backed state).
///
/// We rebuild [`Evm`] per transaction (clone [`CacheDB`]) so the struct stays owned and
/// lifetime-free; acceptable for fuzzing-scale state.
struct ChainVm {
    db: CacheDB<EthersDB<Provider<Http>>>,
    fork_block: BlockEnv,
    spec_id: SpecId,
    chain_id: u64,
    block_number: u64,
}

impl ChainVm {
    fn new(rpc_url: &str, fork_block: u64, spec_id: SpecId) -> Result<Self, String> {
        let provider = Arc::new(
            Provider::<Http>::try_from(rpc_url)
                .map_err(|e| format!("invalid source/dest RPC URL: {e}"))?,
        );

        let ethers_db = EthersDB::new(
            provider.clone(),
            Some(EthBlockId::Number(fork_block.into())),
        )
        .ok_or_else(|| "EthersDB::new failed (could not resolve fork block)".to_string())?;

        let mut cache_db = CacheDB::new(ethers_db);
        fund_account(&mut cache_db, default_caller(), U256::MAX / U256::from(2u8));

        let block_env = fetch_block_env(&provider, fork_block)?;

        Ok(Self {
            db: cache_db,
            fork_block: block_env,
            spec_id,
            chain_id: 1,
            block_number: fork_block,
        })
    }

    fn block_env_snapshot(&self) -> &BlockEnv {
        &self.fork_block
    }

    fn fund(&mut self, addr: Address, balance: U256) {
        fund_account(&mut self.db, addr, balance);
    }

    fn run_tx(&mut self, tx: TxEnv) -> Result<ExecutionResult, String> {
        let mut cfg = CfgEnv::default();
        cfg.chain_id = self.chain_id;
        let cfg_wh = CfgEnvWithHandlerCfg::new(cfg, HandlerCfg::new(self.spec_id));
        let env = EnvWithHandlerCfg::new_with_cfg_env(cfg_wh, self.fork_block.clone(), tx);

        let mut evm = Evm::builder()
            .with_db(self.db.clone())
            .with_env_with_handler_cfg(env)
            .build();

        let res = evm
            .transact_commit()
            .map_err(|e| format!("EVM error: {e:?}"))?;
        let (db, _) = evm.into_db_and_env_with_handler_cfg();
        self.db = db;
        Ok(res)
    }

    fn execute_raw_call(
        &mut self,
        caller: Address,
        to: Address,
        data: Bytes,
    ) -> Result<Vec<u8>, String> {
        let basefee = self.fork_block.basefee;
        let tx = TxEnv {
            caller,
            gas_limit: 30_000_000,
            gas_price: basefee.saturating_add(U256::from(1u8)),
            gas_priority_fee: None,
            transact_to: TransactTo::Call(to),
            value: U256::ZERO,
            data,
            nonce: Some(self.nonce_hint(caller)),
            chain_id: Some(self.chain_id),
            access_list: Vec::new(),
            blob_hashes: Vec::new(),
            max_fee_per_blob_gas: None,
            eof_initcodes: Vec::new(),
            eof_initcodes_hashed: Default::default(),
        };

        let result = self.run_tx(tx)?;

        match result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Err(format!(
                "execution reverted: 0x{}",
                hex::encode(output)
            )),
            ExecutionResult::Halt { reason, .. } => Err(format!("execution halted: {reason:?}")),
        }
    }

    fn nonce_hint(&mut self, caller: Address) -> u64 {
        self.db
            .basic(caller)
            .ok()
            .flatten()
            .map(|a| a.nonce)
            .unwrap_or(0)
    }

    fn deploy(&mut self, caller: Address, bytecode: Bytes) -> Result<Address, String> {
        let basefee = self.fork_block.basefee;
        let tx = TxEnv {
            caller,
            gas_limit: 5_000_000,
            gas_price: basefee.saturating_add(U256::from(1u8)),
            gas_priority_fee: None,
            transact_to: TransactTo::Create,
            value: U256::ZERO,
            data: bytecode,
            nonce: Some(self.nonce_hint(caller)),
            chain_id: Some(self.chain_id),
            access_list: Vec::new(),
            blob_hashes: Vec::new(),
            max_fee_per_blob_gas: None,
            eof_initcodes: Vec::new(),
            eof_initcodes_hashed: Default::default(),
        };

        let result = self.run_tx(tx)?;

        match result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Create(_, Some(addr)) => Ok(addr),
                Output::Create(_, None) => Err("CREATE succeeded but contract address missing".into()),
                Output::Call(_) => Err("unexpected CALL output for CREATE".into()),
            },
            ExecutionResult::Revert { output, .. } => Err(format!(
                "deploy reverted: 0x{}",
                hex::encode(output)
            )),
            ExecutionResult::Halt { reason, .. } => Err(format!("deploy halted: {reason:?}")),
        }
    }

    fn balance_of(&mut self, who: Address) -> Result<U256, String> {
        let acc = self
            .db
            .basic(who)
            .map_err(|e| format!("db.basic: {e:?}"))?;
        Ok(acc.map(|a| a.balance).unwrap_or(U256::ZERO))
    }
}

/// Dual-EVM environment containing source and destination chain instances.
pub struct DualEvm {
    source: ChainVm,
    dest: ChainVm,
    /// Addresses whose ETH balance is included in [`GlobalState`] (e.g. bridge contracts from ATG).
    tracked: Vec<Address>,
}

impl DualEvm {
    /// Initialize Dual-EVM by forking blockchain state at specified blocks.
    ///
    /// For Nomad benchmarks, both RPCs are often Ethereum mainnet; `source_block` / `dest_block`
    /// may match (e.g. `15259100`).
    ///
    /// # Panics
    /// Never; errors are returned as `Err(String)`.
    pub fn new(source_rpc: &str, dest_rpc: &str, source_block: u64, dest_block: u64) -> Result<Self, String> {
        Self::new_with_spec(
            source_rpc,
            dest_rpc,
            source_block,
            dest_block,
            SpecId::LONDON,
        )
    }

    /// Same as [`DualEvm::new`] but allows choosing the execution specification (hard fork).
    pub fn new_with_spec(
        source_rpc: &str,
        dest_rpc: &str,
        source_block: u64,
        dest_block: u64,
        spec_id: SpecId,
    ) -> Result<Self, String> {
        Ok(Self {
            source: ChainVm::new(source_rpc, source_block, spec_id)?,
            dest: ChainVm::new(dest_rpc, dest_block, spec_id)?,
            tracked: Vec::new(),
        })
    }

    /// Addresses to snapshot balances for in [`DualEvm::collect_global_state`].
    pub fn set_tracked_addresses(&mut self, addrs: Vec<Address>) {
        self.tracked = addrs;
    }

    /// Read ETH balance of an address on the source fork (through revm DB).
    pub fn source_balance(&mut self, who: Address) -> Result<U256, String> {
        self.source.balance_of(who)
    }

    /// Read ETH balance of an address on the destination fork.
    pub fn dest_balance(&mut self, who: Address) -> Result<U256, String> {
        self.dest.balance_of(who)
    }

    /// Deploy contract bytecode on the **source** fork. Returns the created address.
    pub fn deploy_mock_on_source(&mut self, bytecode: &[u8]) -> Result<Address, String> {
        self.source
            .fund(default_caller(), U256::MAX / U256::from(2u8));
        self.source
            .deploy(default_caller(), Bytes::copy_from_slice(bytecode))
    }

    /// Deploy contract bytecode on the **destination** fork.
    pub fn deploy_mock_on_dest(&mut self, bytecode: &[u8]) -> Result<Address, String> {
        self.dest
            .fund(default_caller(), U256::MAX / U256::from(2u8));
        self.dest
            .deploy(default_caller(), Bytes::copy_from_slice(bytecode))
    }

    /// Execute a transaction on the source chain.
    ///
    /// **Encoding:** at least [`EXECUTE_CALL_HEADER`] bytes: `caller (20) || to (20) || calldata`.
    /// Use empty calldata for a zero-arg call (only the selector if required).
    pub fn execute_on_source(&mut self, tx: &[u8]) -> Result<Vec<u8>, String> {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.source.execute_raw_call(caller, to, data)
    }

    /// Execute a transaction on the destination chain (same encoding as [`DualEvm::execute_on_source`]).
    pub fn execute_on_dest(&mut self, tx: &[u8]) -> Result<Vec<u8>, String> {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.dest.execute_raw_call(caller, to, data)
    }

    /// Collect global state from both chains (balances for tracked addresses + block metadata).
    pub fn collect_global_state(&mut self) -> GlobalState {
        let mut source_balances = std::collections::HashMap::new();
        let mut dest_balances = std::collections::HashMap::new();
        for a in &self.tracked {
            let key = format!("{a:#x}");
            if let Ok(b) = self.source.balance_of(*a) {
                source_balances.insert(key.clone(), b.to_string());
            }
            if let Ok(b) = self.dest.balance_of(*a) {
                dest_balances.insert(key, b.to_string());
            }
        }

        let sb = self.source.block_env_snapshot();
        let db = self.dest.block_env_snapshot();

        GlobalState {
            source_state: ChainState {
                balances: source_balances,
                storage: std::collections::HashMap::new(),
                block_number: self.source.block_number,
                timestamp: as_u64_saturating(sb.timestamp),
            },
            dest_state: ChainState {
                balances: dest_balances,
                storage: std::collections::HashMap::new(),
                block_number: self.dest.block_number,
                timestamp: as_u64_saturating(db.timestamp),
            },
            relay_state: RelaySnapshot {
                pending_messages: vec![],
                processed_set: vec![],
                mode: "faithful".to_string(),
                message_count: 0,
            },
        }
    }
}

fn parse_execute_payload(tx: &[u8]) -> Result<(Address, Address, Bytes), String> {
    if tx.len() < EXECUTE_CALL_HEADER {
        return Err(format!(
            "execute payload must be at least {EXECUTE_CALL_HEADER} bytes (caller||to||data), got {}",
            tx.len()
        ));
    }
    let caller = Address::from_slice(&tx[..20]);
    let to = Address::from_slice(&tx[20..EXECUTE_CALL_HEADER]);
    let data = Bytes::copy_from_slice(&tx[EXECUTE_CALL_HEADER..]);
    Ok((caller, to, data))
}

fn fund_account<DB: DatabaseRef>(db: &mut CacheDB<DB>, addr: Address, balance: U256) {
    let mut info = db
        .basic(addr)
        .ok()
        .flatten()
        .unwrap_or_else(|| AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: None,
        });
    info.balance = balance;
    db.insert_account_info(addr, info);
}

fn fetch_block_env(provider: &Arc<Provider<Http>>, block_num: u64) -> Result<BlockEnv, String> {
    let provider = Arc::clone(provider);
    block_on_async(async move {
        let block = provider
            .get_block(EthBlockId::Number(block_num.into()))
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("RPC returned no block for #{block_num}"))?;

        let number = U256::from(block.number.unwrap_or_default().as_u64());
        let timestamp = U256::from(block.timestamp.as_u64());
        let gas_limit = U256::from(block.gas_limit.as_u64());
        let basefee = block
            .base_fee_per_gas
            .map(|b| u256_from_ethers_u256(b))
            .unwrap_or(U256::ZERO);
        let difficulty = u256_from_ethers_u256(block.difficulty);
        let mix = block.mix_hash.map(b256_from_eth_h256);
        let author = block.author.unwrap_or_default();

        Ok(BlockEnv {
            number,
            coinbase: Address::from_slice(author.as_bytes()),
            timestamp,
            gas_limit,
            basefee,
            difficulty,
            prevrandao: mix,
            blob_excess_gas_and_price: None,
        })
    })
}

fn u256_from_ethers_u256(u: ethers_core::types::U256) -> U256 {
    let mut buf = [0u8; 32];
    u.to_big_endian(&mut buf);
    U256::from_be_bytes(buf)
}

fn b256_from_eth_h256(h: EthH256) -> B256 {
    B256::from_slice(h.as_bytes())
}

fn as_u64_saturating(ts: U256) -> u64 {
    if ts > U256::from(u64::MAX) {
        u64::MAX
    } else {
        ts.as_limbs()[0]
    }
}

/// Run async RPC on a fresh tokio runtime when not already inside one.
fn block_on_async<F, T>(f: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>> + Send + 'static,
    T: Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(f),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?
            .block_on(f),
    }
}

/// Nomad Replica on Ethereum mainnet (from project ATG fixture `atg_mock.json`).
pub fn nomad_replica_address() -> Address {
    Address::from_str("0x5D94309E5a0090b165FA4181519701637B6DAEBA").expect("valid address")
}

/// Minimal contract: `pragma solidity ^0.8.0; contract C { function id() external pure returns (uint256) { return 42; } }`
/// — runtime bytecode fragment is not portable; use a known tiny bytecode for smoke deploy tests.
///
/// Returns simple **runtime** bytecode that only returns immediately (STOP).
pub fn empty_runtime_bytecode() -> Vec<u8> {
    vec![0x00] // STOP — valid deployable init could wrap this; for CREATE we need init code.
}

/// Minimal **init** code that deploys empty runtime `0x00`.
pub fn mock_deploy_init_code() -> Vec<u8> {
    // PUSH1 0x00 PUSH1 0x0c RETURN (deploy 1 byte 0x00 at end of init)
    // Simplified: 60 00 60 0c 60 0c 39 f3  (typical minimal)
    hex::decode("6000600c6000396000f3fe00").expect("static hex")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers_providers::{Http, Provider};
    use std::sync::Arc;

    #[test]
    fn parse_execute_payload_roundtrip() {
        let mut v = vec![0u8; 40];
        v[19] = 0x01;
        v[39] = 0xab;
        v.extend_from_slice(&[1, 2, 3]);
        let (a, b, d) = parse_execute_payload(&v).unwrap();
        let mut exp_caller = [0u8; 20];
        exp_caller[19] = 1;
        let mut exp_to = [0u8; 20];
        exp_to[19] = 0xab;
        assert_eq!(a, Address::from_slice(&exp_caller));
        assert_eq!(b, Address::from_slice(&exp_to));
        assert_eq!(d.as_ref(), &[1u8, 2, 3]);
    }

    #[test]
    fn nomad_replica_addr_constant() {
        let a = nomad_replica_address();
        assert_eq!(
            format!("{a:#x}"),
            "0x5d94309e5a0090b165fa4181519701637b6daeba"
        );
    }

    /// Proof-of-concept (Phase 0 / Member B): fork Ethereum mainnet at the **latest** block and read
    /// a well-known account balance via revm + [`EthersDB`]. No archive node required.
    ///
    /// Run manually:
    /// `cargo test revm_poc_fork_mainnet_read_balance_latest -- --ignored --nocapture`
    ///
    /// Optional: `ETH_RPC_URL=https://...` (defaults to a public mainnet endpoint below).
    #[test]
    #[ignore = "network: calls public Ethereum mainnet RPC"]
    fn revm_poc_fork_mainnet_read_balance_latest() {
        let rpc = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://ethereum.publicnode.com".to_string());
        let provider = Arc::new(
            Provider::<Http>::try_from(rpc.as_str()).expect("valid RPC URL"),
        );
        let block_num = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                provider
                    .get_block_number()
                    .await
                    .expect("eth_blockNumber")
                    .as_u64()
            });

        // Vitalik's address — always holds ETH on mainnet.
        let vitalik = Address::from_str("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
            .expect("valid address");

        let mut dual = DualEvm::new(&rpc, &rpc, block_num, block_num).expect("DualEvm fork");
        let balance = dual.source_balance(vitalik).expect("read balance");
        assert!(
            balance > U256::ZERO,
            "expected positive ETH balance at block {block_num}, got {balance}"
        );
        eprintln!(
            "revm PoC OK: block={block_num} vitalik_balance_wei={balance}"
        );
    }

    /// Requires `SOURCE_RPC_URL` (or `ETH_RPC_URL`) pointing at Ethereum mainnet archival RPC.
    #[test]
    #[ignore = "needs ETH_RPC_URL with archive access"]
    fn integration_fork_replica_balance_block_15259100() {
        let rpc = std::env::var("ETH_RPC_URL")
            .or_else(|_| std::env::var("SOURCE_RPC_URL"))
            .expect("set ETH_RPC_URL");
        let mut dual = DualEvm::new(&rpc, &rpc, 15259100, 15259100).expect("dual evm");
        dual.set_tracked_addresses(vec![nomad_replica_address()]);
        let b = dual
            .dest_balance(nomad_replica_address())
            .expect("balance");
        assert!(b > U256::ZERO);
        let gs = dual.collect_global_state();
        assert_eq!(gs.source_state.block_number, 15259100);
        assert_eq!(gs.dest_state.block_number, 15259100);
        assert!(gs.dest_state.balances.contains_key("0x5d94309e5a0090b165fa4181519701637b6daeba"));
    }
}
