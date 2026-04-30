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
