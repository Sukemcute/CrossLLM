//! Dual-EVM Environment
//!
//! Manages two independent EVM instances (source chain + destination chain)
//! connected through a mock relay process.
//!
//! Each EVM instance is initialized by forking blockchain state at a specified block number
//! via JSON-RPC ([`revm::db::EthersDB`] + [`revm::db::CacheDB`]).

use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use ethers_core::types::{Address as EthAddress, BlockId as EthBlockId, H256 as EthH256, U256 as EthU256};
use ethers_core::utils::get_contract_address;
use ethers_providers::{Http, Middleware, Provider};
use revm::db::{CacheDB, EthersDB};
use revm::{
    inspector_handle_register,
    primitives::{
        specification::SpecId,
        AccountInfo, Address, BlockEnv, Bytes, CfgEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg,
        ExecutionResult, HandlerCfg, Log, Output, TransactTo, TxEnv, B256, KECCAK_EMPTY, U256,
    },
    Database, DatabaseRef, Evm, Inspector,
};

use crate::coverage_tracker::CoverageTracker;
use crate::types::{ChainState, GlobalState, RelaySnapshot};

/// Default funded EOA used when executing calls from the fuzzer (unlimited balance in cache).
pub fn default_caller() -> Address {
    static C: OnceLock<Address> = OnceLock::new();
    *C.get_or_init(|| {
        Address::from_str("0x0000000000000000000000000000000000000001").expect("valid address")
    })
}

/// Dedicated CREATE deployer for benchmark fixture contracts.
/// Kept separate from [`default_caller`] so historical nonce drift on forks
/// cannot break deterministic deployment.
fn default_deployer() -> Address {
    static D: OnceLock<Address> = OnceLock::new();
    *D.get_or_init(|| {
        Address::from_str("0x000000000000000000000000000000000000dEAD").expect("valid address")
    })
}

/// Minimum calldata length for [`DualEvm::execute_on_source`] / [`DualEvm::execute_on_dest`]:
/// `20 bytes caller || 20 bytes contract || optional ABI calldata`.
pub const EXECUTE_CALL_HEADER: usize = 40;

/// CacheDB over an RPC-backed Ethers provider — one per fork. Type alias keeps
/// inspector signatures readable.
type ChainDb = CacheDB<EthersDB<Provider<Http>>>;

/// One EVM fork (CacheDB over RPC-backed state).
///
/// We rebuild [`Evm`] per transaction (clone [`CacheDB`]) so the struct stays owned and
/// lifetime-free; acceptable for fuzzing-scale state.
struct ChainVm {
    db: ChainDb,
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

    fn prepare_deployer(&mut self, addr: Address, balance: U256) {
        let mut info = self
            .db
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
        info.nonce = 0;
        info.code_hash = KECCAK_EMPTY;
        info.code = None;
        self.db.insert_account_info(addr, info);
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

    /// Variant of [`Self::run_tx`] that wires an [`Inspector`] (e.g.
    /// [`CoverageTracker`]) so per-instruction callbacks fire during execution.
    fn run_tx_with_inspector<I>(&mut self, tx: TxEnv, inspector: I) -> Result<ExecutionResult, String>
    where
        I: Inspector<ChainDb>,
    {
        let mut cfg = CfgEnv::default();
        cfg.chain_id = self.chain_id;
        let cfg_wh = CfgEnvWithHandlerCfg::new(cfg, HandlerCfg::new(self.spec_id));
        let env = EnvWithHandlerCfg::new_with_cfg_env(cfg_wh, self.fork_block.clone(), tx);

        let mut evm = Evm::builder()
            .with_db(self.db.clone())
            .with_external_context(inspector)
            .with_env_with_handler_cfg(env)
            .append_handler_register(inspector_handle_register)
            .build();

        let res = evm
            .transact_commit()
            .map_err(|e| format!("EVM error: {e:?}"))?;
        let (db, _) = evm.into_db_and_env_with_handler_cfg();
        self.db = db;
        Ok(res)
    }

    /// Convenience wrapper around [`Self::run_tx_with_inspector`] that
    /// returns the flat `HashSet<usize>` of touched PCs alongside the
    /// `ExecutionResult`. Compatibility shim for the `*_with_coverage`
    /// path that landed on `origin/main` while the inspector path was
    /// in flight on the baselines branch — both call shapes coexist.
    fn run_tx_with_coverage(
        &mut self,
        tx: TxEnv,
    ) -> Result<(ExecutionResult, std::collections::HashSet<usize>), String> {
        let mut tracker = CoverageTracker::default();
        let res = self.run_tx_with_inspector(tx, &mut tracker)?;
        Ok((res, tracker.into_pcs()))
    }

    fn execute_raw_call(
        &mut self,
        caller: Address,
        to: Address,
        data: Bytes,
    ) -> Result<Vec<u8>, String> {
        let tx = self.build_call_tx(caller, to, data);
        Self::map_call_result(self.run_tx(tx)?)
    }

    /// Variant of [`Self::execute_raw_call`] that funnels execution through an
    /// [`Inspector`] so each opcode step triggers the inspector callbacks.
    fn execute_raw_call_with_inspector<I>(
        &mut self,
        caller: Address,
        to: Address,
        data: Bytes,
        inspector: I,
    ) -> Result<Vec<u8>, String>
    where
        I: Inspector<ChainDb>,
    {
        let tx = self.build_call_tx(caller, to, data);
        Self::map_call_result(self.run_tx_with_inspector(tx, inspector)?)
    }

    /// Same as [`Self::execute_raw_call_with_inspector`] but returns the
    /// full [`TxOutcome`] including emitted log entries instead of just
    /// the call output. Reverts and halts produce `success = false` but
    /// still return Ok — the caller decides how to treat them.
    fn execute_raw_call_with_inspector_full<I>(
        &mut self,
        caller: Address,
        to: Address,
        data: Bytes,
        inspector: I,
    ) -> Result<TxOutcome, String>
    where
        I: Inspector<ChainDb>,
    {
        let tx = self.build_call_tx(caller, to, data);
        let result = self.run_tx_with_inspector(tx, inspector)?;
        Ok(TxOutcome::from_execution_result(result))
    }

    fn build_call_tx(&mut self, caller: Address, to: Address, data: Bytes) -> TxEnv {
        let basefee = self.fork_block.basefee;
        // Use 95 % of the fork block's gas limit so the tx never trips
        // revm's `CallerGasLimitMoreThanBlock` check on slightly-smaller
        // blocks (block 15012700 was ~28.7M and 30M_000_000 was over the
        // cap, which surfaced during the Harmony replay debug). Cap at
        // 30M so post-London blocks behave the same as before.
        let block_cap = as_u64_saturating(self.fork_block.gas_limit);
        let tx_gas_limit = block_cap
            .saturating_mul(95)
            .saturating_div(100)
            .min(30_000_000);
        TxEnv {
            caller,
            gas_limit: tx_gas_limit.max(1_000_000),
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
        }
    }

    fn map_call_result(result: ExecutionResult) -> Result<Vec<u8>, String> {
        match result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Err(format!(
                "execution reverted: 0x{}",
                hex::encode(output)
            )),
            ExecutionResult::Halt { reason, .. } => Err(format!("execution halted: {reason:?}")),
        }
    }

    fn execute_raw_call_with_coverage(
        &mut self,
        caller: Address,
        to: Address,
        data: Bytes,
    ) -> Result<(Vec<u8>, std::collections::HashSet<usize>), String> {
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

        let (result, touched) = self.run_tx_with_coverage(tx)?;

        match result {
            ExecutionResult::Success { output, .. } => Ok((output.into_data().to_vec(), touched)),
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
        let nonce = self.nonce_hint(caller);
        let predicted = get_contract_address(
            EthAddress::from_slice(caller.as_slice()),
            EthU256::from(nonce),
        );
        let basefee = self.fork_block.basefee;
        let tx = TxEnv {
            caller,
            // Benchmark reconstructions can be large; keep headroom so CREATE
            // does not fail with an out-of-gas style revert on big bytecode.
            gas_limit: 30_000_000,
            gas_price: basefee.saturating_add(U256::from(1u8)),
            gas_priority_fee: None,
            transact_to: TransactTo::Create,
            value: U256::ZERO,
            data: bytecode,
            nonce: Some(nonce),
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
                "deploy reverted: caller={caller:?} nonce={nonce} predicted={:?} revert=0x{}",
                predicted,
                hex::encode(output)
            )),
            ExecutionResult::Halt { reason, .. } => Err(format!(
                "deploy halted: caller={caller:?} nonce={nonce} predicted={predicted:?} reason={reason:?}"
            )),
        }
    }

    fn balance_of(&mut self, who: Address) -> Result<U256, String> {
        let acc = self
            .db
            .basic(who)
            .map_err(|e| format!("db.basic: {e:?}"))?;
        Ok(acc.map(|a| a.balance).unwrap_or(U256::ZERO))
    }

    fn capture_vm_snapshot(&self) -> ChainVmSnapshot {
        ChainVmSnapshot {
            db: self.db.clone(),
            fork_block: self.fork_block.clone(),
            spec_id: self.spec_id,
            chain_id: self.chain_id,
            block_number: self.block_number,
        }
    }

    fn restore_vm_snapshot(&mut self, s: ChainVmSnapshot) {
        self.db = s.db;
        self.fork_block = s.fork_block;
        self.spec_id = s.spec_id;
        self.chain_id = s.chain_id;
        self.block_number = s.block_number;
    }
}

/// Result of a single transaction. Unlike `Result<Vec<u8>, String>` from
/// [`DualEvm::execute_on_source`] this preserves the **emitted logs** and
/// the success/revert/halt status, which the XScope baseline detector
/// needs to reconstruct lock / unlock events.
#[derive(Debug, Clone)]
pub struct TxOutcome {
    /// Whether the call ended in `ExecutionResult::Success`.
    pub success: bool,
    /// Output bytes (success → return data, revert → revert data, halt → empty).
    pub output: Vec<u8>,
    /// Event logs emitted before the (possibly successful) end of the call.
    /// Reverts and halts produce an empty list — revm strips logs when the
    /// call did not commit.
    pub logs: Vec<Log>,
    /// Gas consumed by the transaction.
    pub gas_used: u64,
    /// One-line human-readable status (used in trace strings).
    pub status: String,
}

impl TxOutcome {
    fn from_execution_result(result: ExecutionResult) -> Self {
        match result {
            ExecutionResult::Success { gas_used, logs, output, .. } => Self {
                success: true,
                output: output.into_data().to_vec(),
                logs,
                gas_used,
                status: "ok".to_string(),
            },
            ExecutionResult::Revert { gas_used, output } => Self {
                success: false,
                output: output.to_vec(),
                logs: Vec::new(),
                gas_used,
                status: format!("reverted: 0x{}", hex::encode(&output)),
            },
            ExecutionResult::Halt { gas_used, reason } => Self {
                success: false,
                output: Vec::new(),
                logs: Vec::new(),
                gas_used,
                status: format!("halted: {reason:?}"),
            },
        }
    }
}

/// Compute `now - baseline` as a saturating signed `i128`. Both inputs are
/// 256-bit balances; we collapse to 128 bits with saturation since real
/// token balances comfortably fit.
fn u256_signed_delta(baseline: U256, now: U256) -> i128 {
    if now >= baseline {
        let diff = now - baseline;
        u256_clip_to_u128(diff) as i128
    } else {
        let diff = baseline - now;
        let clipped = u256_clip_to_u128(diff);
        if clipped > i128::MAX as u128 {
            i128::MIN
        } else {
            -(clipped as i128)
        }
    }
}

fn u256_clip_to_u128(v: U256) -> u128 {
    let limbs = v.as_limbs();
    if limbs.iter().skip(2).any(|l| *l != 0) {
        u128::MAX
    } else {
        ((limbs[1] as u128) << 64) | (limbs[0] as u128)
    }
}

/// Cloned chain VM state for synchronized dual-EVM snapshot/restore (full CacheDB copy).
#[derive(Clone)]
pub struct ChainVmSnapshot {
    db: CacheDB<EthersDB<Provider<Http>>>,
    fork_block: BlockEnv,
    spec_id: SpecId,
    chain_id: u64,
    block_number: u64,
}

/// Snapshot of both forks plus tracked addresses (paper: \(S_{\text{EVM}_S}, S_{\text{EVM}_D}\) metadata).
#[derive(Clone)]
pub struct DualEvmSnapshot {
    pub source: ChainVmSnapshot,
    pub dest: ChainVmSnapshot,
    pub tracked: Vec<Address>,
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

    /// Fund `who` on the source fork up to `balance` wei. Used by the
    /// XScope replay-mode loader to ensure cached exploit-tx senders
    /// can pay for gas regardless of what their on-chain balance was
    /// at the historical fork block. Wraps the existing `ChainVm::fund`.
    pub fn fund_source(&mut self, who: Address, balance: U256) {
        self.source.fund(who, balance);
    }

    /// Destination-side counterpart of [`Self::fund_source`].
    pub fn fund_dest(&mut self, who: Address, balance: U256) {
        self.dest.fund(who, balance);
    }

    /// Read ETH balance of an address on the destination fork.
    pub fn dest_balance(&mut self, who: Address) -> Result<U256, String> {
        self.dest.balance_of(who)
    }

    /// Reset benchmark deployer account on both forks before a fresh
    /// compile-and-deploy batch.
    pub fn reset_benchmark_deployer(&mut self) {
        let bal = U256::MAX / U256::from(2u8);
        self.source.prepare_deployer(default_deployer(), bal);
        self.dest.prepare_deployer(default_deployer(), bal);
    }

    /// Deploy contract bytecode on the **source** fork. Returns the created address.
    pub fn deploy_mock_on_source(&mut self, bytecode: &[u8]) -> Result<Address, String> {
        self.source
            .fund(default_deployer(), U256::MAX / U256::from(2u8));
        self.source
            .deploy(default_deployer(), Bytes::copy_from_slice(bytecode))
    }

    /// Deploy contract bytecode on the **destination** fork.
    pub fn deploy_mock_on_dest(&mut self, bytecode: &[u8]) -> Result<Address, String> {
        self.dest
            .fund(default_deployer(), U256::MAX / U256::from(2u8));
        self.dest
            .deploy(default_deployer(), Bytes::copy_from_slice(bytecode))
    }

    /// Next contract address that would be produced by a `CREATE` from
    /// benchmark deployer on the **source** fork (EIP-161 nonce rules).
    pub fn peek_next_create_address_source(&mut self) -> Result<EthAddress, String> {
        Self::predict_next_create_address(&mut self.source, default_deployer())
    }

    /// Same as [`Self::peek_next_create_address_source`] on the **destination** fork.
    pub fn peek_next_create_address_dest(&mut self) -> Result<EthAddress, String> {
        Self::predict_next_create_address(&mut self.dest, default_deployer())
    }

    /// Deploy identical init bytecode on **both** forks using [`default_caller`].
    /// Keeps CREATE address alignment when both forks start from the same
    /// historical nonce for the deployer EOA.
    pub fn deploy_mock_on_both(&mut self, bytecode: &[u8]) -> Result<Address, String> {
        let src = self.deploy_mock_on_source(bytecode)?;
        let dst = self.deploy_mock_on_dest(bytecode)?;
        if src != dst {
            return Err(format!(
                "dual deploy address mismatch: source={src:?} dest={dst:?} (deployer nonces diverged?)"
            ));
        }
        Ok(src)
    }

    fn predict_next_create_address(vm: &mut ChainVm, caller: Address) -> Result<EthAddress, String> {
        let n = vm.nonce_hint(caller);
        let eth_caller = EthAddress::from_slice(caller.as_slice());
        Ok(get_contract_address(eth_caller, EthU256::from(n)))
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

    /// Same as [`DualEvm::execute_on_source`] but feeds execution through a
    /// [`CoverageTracker`] so each instruction's `(address, pc)` is recorded.
    /// Returns the call's output bytes; coverage hits accumulate in `tracker`.
    pub fn execute_on_source_with_inspector(
        &mut self,
        tx: &[u8],
        tracker: &mut CoverageTracker,
    ) -> Result<Vec<u8>, String> {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.source.execute_raw_call_with_inspector(caller, to, data, tracker)
    }

    /// Destination-side counterpart of [`DualEvm::execute_on_source_with_inspector`].
    pub fn execute_on_dest_with_inspector(
        &mut self,
        tx: &[u8],
        tracker: &mut CoverageTracker,
    ) -> Result<Vec<u8>, String> {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.dest.execute_raw_call_with_inspector(caller, to, data, tracker)
    }

    /// Same as [`DualEvm::execute_on_source_with_inspector`] but returns
    /// the full [`TxOutcome`] (output + logs + success flag) so callers
    /// like the XScope baseline detector can scan emitted events. Wraps
    /// reverts as `success = false` rather than `Err`.
    ///
    /// Generic over the [`Inspector`] type so callers can pass the
    /// existing [`CoverageTracker`], the new
    /// [`crate::storage_tracker::StorageTracker`], or composite
    /// inspectors that delegate to several at once (the XScope baseline
    /// uses the latter).
    pub fn execute_on_source_with_inspector_full<I>(
        &mut self,
        tx: &[u8],
        inspector: I,
    ) -> Result<TxOutcome, String>
    where
        I: Inspector<ChainDb>,
    {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.source
            .execute_raw_call_with_inspector_full(caller, to, data, inspector)
    }

    /// Destination-side counterpart of
    /// [`DualEvm::execute_on_source_with_inspector_full`].
    pub fn execute_on_dest_with_inspector_full<I>(
        &mut self,
        tx: &[u8],
        inspector: I,
    ) -> Result<TxOutcome, String>
    where
        I: Inspector<ChainDb>,
    {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.dest
            .execute_raw_call_with_inspector_full(caller, to, data, inspector)
    }

    /// Returns the bytecode of a contract on the source or dest chain.
    pub fn get_code(&mut self, addr: Address) -> Result<Vec<u8>, String> {
        if let Ok(Some(info)) = self.source.db.basic(addr) {
            if let Some(code) = info.code {
                return Ok(code.bytecode().to_vec());
            }
        }
        if let Ok(Some(info)) = self.dest.db.basic(addr) {
            if let Some(code) = info.code {
                return Ok(code.bytecode().to_vec());
            }
        }
        Ok(Vec::new())
    }

    /// Execute on source with per-call bytecode coverage PCs (memB's
    /// shape — a flat ``HashSet<usize>`` rather than the
    /// ``(Address, usize)`` pairs the inspector path tracks). Kept as
    /// a thin wrapper so existing call sites in fuzz_loop / scenario_sim
    /// keep compiling without going through the inspector boilerplate.
    pub fn execute_on_source_with_coverage(
        &mut self,
        tx: &[u8],
    ) -> Result<(Vec<u8>, std::collections::HashSet<usize>), String> {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.source.execute_raw_call_with_coverage(caller, to, data)
    }

    /// Destination-side counterpart of
    /// [`Self::execute_on_source_with_coverage`].
    pub fn execute_on_dest_with_coverage(
        &mut self,
        tx: &[u8],
    ) -> Result<(Vec<u8>, std::collections::HashSet<usize>), String> {
        let (caller, to, data) = parse_execute_payload(tx)?;
        self.dest.execute_raw_call_with_coverage(caller, to, data)
    }

    /// Read the **token-level** balance change observed for `who` on the
    /// source fork relative to a baseline value. Used by the XScope I-1
    /// predicate to compare lock-event amount against real balance delta.
    /// The baseline is whatever the caller captured before the call —
    /// typically via [`Self::source_balance`].
    pub fn source_balance_delta_since(&mut self, who: Address, baseline: U256) -> Result<i128, String> {
        let now = self.source.balance_of(who)?;
        Ok(u256_signed_delta(baseline, now))
    }

    /// Destination-side counterpart of
    /// [`Self::source_balance_delta_since`].
    pub fn dest_balance_delta_since(&mut self, who: Address, baseline: U256) -> Result<i128, String> {
        let now = self.dest.balance_of(who)?;
        Ok(u256_signed_delta(baseline, now))
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

    /// Capture both chain DBs and tracked addresses (ItyFuzz-style full clone, not differential).
    pub fn capture_snapshot(&self) -> DualEvmSnapshot {
        DualEvmSnapshot {
            source: self.source.capture_vm_snapshot(),
            dest: self.dest.capture_vm_snapshot(),
            tracked: self.tracked.clone(),
        }
    }

    /// Restore from a prior [`DualEvm::capture_snapshot`].
    pub fn restore_snapshot(&mut self, s: DualEvmSnapshot) {
        self.source.restore_vm_snapshot(s.source);
        self.dest.restore_vm_snapshot(s.dest);
        self.tracked = s.tracked;
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

    /// Snapshot capture/restore on a real fork (archive RPC). Run with `ETH_RPC_URL` + `--ignored`.
    #[test]
    #[ignore = "needs ETH_RPC_URL with archive access"]
    fn snapshot_restore_preserves_tracked_balances() {
        let rpc = std::env::var("ETH_RPC_URL")
            .or_else(|_| std::env::var("SOURCE_RPC_URL"))
            .expect("set ETH_RPC_URL");
        let mut dual = DualEvm::new(&rpc, &rpc, 15259100, 15259100).expect("dual evm");
        dual.set_tracked_addresses(vec![nomad_replica_address()]);
        let snap = dual.capture_snapshot();
        let b_before = dual
            .dest_balance(nomad_replica_address())
            .expect("balance");
        let mut payload = vec![0u8; 40];
        payload[..20].copy_from_slice(default_caller().as_slice());
        payload[20..40].copy_from_slice(nomad_replica_address().as_slice());
        let _ = dual.execute_on_dest(&payload);
        dual.restore_snapshot(snap);
        let b_after = dual
            .dest_balance(nomad_replica_address())
            .expect("balance");
        assert_eq!(b_before, b_after);
    }
}
