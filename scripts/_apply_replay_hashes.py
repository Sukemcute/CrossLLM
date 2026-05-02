"""Apply verified exploit transaction hashes to per-bridge metadata.json.

Hashes were verified by manual lookup on Etherscan + WebFetch
(see commit message references). For each bridge with a verified
hash:
- inserts `metadata.exploit_replay.tx_hashes`
- bumps `metadata.fork.block_number` to (exploit_block - 1) so the
  replay forks at the exact pre-exploit state

Idempotent. Skips bridges not in HASHES, leaves unmentioned ones alone.
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(REPO, "benchmarks")


# (bridge, [(tx_hash, exploit_block_decimal)], rpc_env)
HASHES = {
    "nomad": {
        "rpc_env": "ETH_RPC_URL",
        "txs": [
            (
                "0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460",
                15259101,
            )
        ],
    },
    "ronin": {
        "rpc_env": "ETH_RPC_URL",
        "txs": [
            (
                "0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7",
                14442835,
            )
        ],
    },
    "polynetwork": {
        "rpc_env": "ETH_RPC_URL",
        "txs": [
            (
                "0xb1f70464bd95b774c6ce60fc706eb5f9e35cb5f06e6cfe7c17dcda46ffd59581",
                12996659,
            )
        ],
    },
    "multichain": {
        "rpc_env": "ETH_RPC_URL",
        "txs": [
            (
                "0x53ede4462d90978b992b0a88727de19afe4e96f0374aa1a221b8ff65fda5a6fe",
                17664131,
            )
        ],
    },
    "harmony": {
        "rpc_env": "ETH_RPC_URL",
        # Harmony Horizon Bridge exploit 2022-06-23: compromised admin
        # 0x812d8622C6F3c45959439e7ede3C580dA06f8f25 calls
        # `confirmTransaction(txId)` on the multisig
        # 0x715CdDa5e9Ad30A0cEd14940F9997EE611496De6 — each confirm
        # unlocks one batch of tokens from the Horizon ERC20 Bridge
        # (0x2dCCDB49…). 4 representative drain txs cached.
        "txs": [
            (
                "0x75eeae4776e453d2b43ce130007820d70898bcd4bd6f2216643bc90847a41f9c",
                15012701,
            ),
            (
                "0xc1c554988aab1ea3bc74f8b87fb2c256ffd9e3bcadaade60cf23ab258c53e6f1",
                15012703,
            ),
            (
                "0x698b6a4da3defaed0b7936e0e90d7bc94df6529f5ec8f4cd47d48f7f73729915",
                15012706,
            ),
            (
                "0x4ffe23abc37fcdb32e65af09117b9e44ecae82979d8df93884a5d3b5f698983e",
                15012721,
            ),
        ],
    },
    "socket": {
        "rpc_env": "ETH_RPC_URL",
        # Socket/Bungee exploiter 0x50DF5a2217588772471B84aDBbe4194A2Ed39066
        # deployed a malicious contract whose constructor pulled token
        # approvals from 230 victim wallets (Socket attack 2024-01-16).
        # Both deployment txs are listed; the drain happens during
        # constructor execution.
        "txs": [
            (
                "0xc6c3331fa8c2d30e1ef208424c08c039a89e510df2fb6ae31e5aa40722e28fd6",
                19021454,
            ),
            (
                "0x591d054a9db63f0976e533f447df482bed5f24d7429646570b2108a67e24ce54",
                19021465,
            ),
        ],
    },
    "orbit": {
        "rpc_env": "ETH_RPC_URL",
        # Five exploit txs from attacker 0x9263e7873613ddc598a701709875634819176aff
        # to OrbitVault (0x1Bf68A9d…) on Dec-31-2023 / Jan-01-2024, all carrying
        # function selector 0x2ac5ab1b (Orbit's signed-withdraw entry).
        "txs": [
            (
                "0x8c92301a6840eb2ed97cc5a1c55c82931a2b24ef132d78f3428070b4b13130da",
                18900175,
            ),
            (
                "0x9b9f5e075b530daf262a5ef569e73f1719d71490b4a732783cbcdd4935840ebc",
                18900180,
            ),
            (
                "0xeebfc657f47f3cb0bc8cec5cb9e591e6faf366a86f9cbe28e4398fc18060f03c",
                18900218,
            ),
            (
                "0xaa574f81b17f5635d66204a0e6584a394bdff966854e4e45f6cb79cf4409ba92",
                18900282,
            ),
            (
                "0x36b7e415d611138f5a1d447494da36bd8309ce578e7059e201832f2e05aec5c1",
                18900291,
            ),
        ],
    },
    # Qubit Finance exploit 2022-01-28: attacker
    # 0xEB645B4c35cf160e47F0A49c03DB087c421AB545 calls
    # `voteProposal(originDomainID, depositNonce, resourceID, data)`
    # on QBridge proxy 0x4d8aE68fCAe98Bf93299548545933c0D273BA23a,
    # replaying a forged ETH-side deposit to mint xETH on BSC
    # without any ETH lock on the source chain. Single representative
    # tx — that one call is the whole exploit. Source: SlowMist.
    "qubit": {
        "rpc_env": "BSC_ARCHIVE_RPC_URL",
        "txs": [
            (
                "0x33628dcc2ca6cd89a96d241bdf17cdc8785cf4322dcaf2c79766c990579aea02",
                14742533,
            ),
        ],
    },
    # Gempad reentrancy exploit 2024-12-17: attacker
    # 0xFDd9b0A7e7e16b5Fd48a3D1e242aF362bC81bCaa funds an attack
    # contract 0x8e18Fb32...477c43 (tx 1, +9.999 BNB) which then
    # re-enters `collectFees` of GempadLock via a malicious-token
    # transfer callback to free-withdraw locked LP (tx 2, drain
    # 281 BNB). Two-tx pair captures setup + drain. Source:
    # Halborn / Rekt / pcaversaccio reentrancy registry.
    "gempad": {
        "rpc_env": "BSC_ARCHIVE_RPC_URL",
        "txs": [
            (
                "0x1a50211502a413c0d6d35f3ba859fc4206c5fb899c0adaa28b74c56b644c2997",
                44946196,
            ),
            # Direct CREATE of attack contract B (0xbfcf56d4fc...) by
            # attacker EOA 0xFDd9b0A7. Sits between funding and drain;
            # required so the drain tx finds bytecode at the target
            # address in the fork. Verified via BSCscan "Contract
            # Creator" panel on the contract address page.
            (
                "0xae86dacfd261953d6b647c566be9ac77ee0bb05bba9dfda72ec0973977f3833a",
                44946208,
            ),
            (
                "0x409a5313cb47f8e4cfbd3d3f278ff6bdba402e89baf27891e60d1f648aebda43",
                44946280,
            ),
        ],
    },
    # pGala / pNetwork exploit 2022-11-04: pNetwork node misconfig
    # leaked admin key, attacker 0x1D3DbE49... used it to redeploy
    # the pGALA proxy + mint 561T GALA to themselves, then forwarded
    # to routing EOA 0xEE84D272... → drain wallet 0x6891a233... that
    # dumped on PancakeSwap. Three reps capture mint + propagation.
    # Note: metadata's pgala_token 0xd4306df0... is the POST-incident
    # redeployed contract; original exploited proxy is
    # 0xB5273D5aDb749bc3F6704DC82fFf02735D5B3e11. Investigation via
    # BSCscan tokentxns filter on the attacker EOA + pNetwork
    # post-mortem cross-check.
    "pgala": {
        "rpc_env": "BSC_ARCHIVE_RPC_URL",
        "txs": [
            (
                "0xa9b2c1efa50e88c81e5868e36e4aee9ed3c3d59e9f7f6f50fe1bb2c88be54abe",
                22753835,
            ),
            (
                "0xe6dd3d0c4d137581e5125695885e2241e95aecbeb4b8e237ae0d68d24b33f27c",
                22753902,
            ),
            (
                "0xdafba62a6a8a53a695b07db03f4c52f7e5e12a00af7c83cf4da77eb5cf384db5",
                22754085,
            ),
        ],
    },
    # FEGtoken: original benchmark spec (claimMigrator on
    # 0x4b9be7e9... + Apr 30 + block 17127537) doesn't match any
    # documented FEG exploit — that router is empty on BSC and
    # block 17127537 is Apr-21-2022. The actual on-chain exploit
    # is the May-15-2022 swapToSwap() flashloan tx
    # 0x77cf448c... at block 17832803, attacker
    # 0x73b359d5... draining FEGexPRO LP at 0x818e2013...
    # Re-pointing the benchmark fork to that tx replays the real
    # incident; predicate I-5 fires via synthesize_unauth_unlock
    # (any-of rule against expected I-1, I-5).
    "fegtoken": {
        "rpc_env": "BSC_ARCHIVE_RPC_URL",
        "txs": [
            (
                "0x77cf448ceaf8f66e06d1537ef83218725670d3a509583ea0d161533fda56c063",
                17832803,
            ),
        ],
    },
}


def main() -> int:
    n_changed = 0
    for bridge, cfg in HASHES.items():
        path = os.path.join(BENCH, bridge, "metadata.json")
        if not os.path.isfile(path):
            print(f"  SKIP {bridge}: missing {path}")
            continue
        with open(path, encoding="utf-8") as f:
            meta = json.load(f)

        # Use the EARLIEST exploit block - 1 as the fork point so all
        # replay txs in the list execute against pre-exploit state.
        earliest_block = min(b for _, b in cfg["txs"])
        meta.setdefault("fork", {})["block_number"] = earliest_block - 1

        # Preserve any existing per-bridge synthesize flags or other
        # custom keys the X3-polish A4/A5 work wrote into the block —
        # only overwrite rpc_env + tx_hashes here.
        existing = meta.get("exploit_replay", {})
        existing["rpc_env"] = cfg["rpc_env"]
        existing["tx_hashes"] = [h for h, _ in cfg["txs"]]
        meta["exploit_replay"] = existing

        with open(path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
            f.write("\n")
        n_changed += 1
        print(
            f"  WROTE {bridge:12} fork_block={earliest_block - 1} "
            f"tx_hashes={len(cfg['txs'])}"
        )
    print()
    print(f"{n_changed}/{len(HASHES)} bridges updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
