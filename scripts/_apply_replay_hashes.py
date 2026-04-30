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

        meta["exploit_replay"] = {
            "rpc_env": cfg["rpc_env"],
            "tx_hashes": [h for h, _ in cfg["txs"]],
        }

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
