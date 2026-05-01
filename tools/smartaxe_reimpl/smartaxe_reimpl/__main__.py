"""smartaxe-reimpl CLI entry point.

SA3 ships a ``cfg`` subcommand that prints the per-contract CFG node
count for a given ``--contracts`` directory — useful as a smoke test
of the Slither install. SA5 / SA7 will add the full ``run`` subcommand.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, Sequence


def _cmd_cfg(args: argparse.Namespace) -> int:
    from .cfg_builder import build_contract_cfgs

    cfgs = build_contract_cfgs(args.contracts)
    summary = {
        "contracts_dir": str(args.contracts),
        "n_contracts": len(cfgs),
        "contracts": [
            {
                "contract": c.contract_name,
                "source": c.source_path,
                "n_functions": len(c.functions),
                "n_nodes": sum(len(ns) for ns in c.functions.values()),
            }
            for c in cfgs
        ],
    }
    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    print(
        "smartaxe-reimpl run is SA7 — not yet implemented. "
        "Use `smartaxe-reimpl cfg` for the SA3 smoke test.",
        file=sys.stderr,
    )
    return 2


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    p = argparse.ArgumentParser(
        prog="smartaxe-reimpl",
        description="SmartAxe re-implementation for BridgeSentry RQ1",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_cfg = sub.add_parser("cfg", help="Print per-contract CFG summary (SA3 smoke)")
    p_cfg.add_argument("--contracts", type=Path, required=True)
    p_cfg.set_defaults(func=_cmd_cfg)

    p_run = sub.add_parser("run", help="Full SmartAxe run (SA7 — not yet implemented)")
    p_run.add_argument("--contracts", type=Path, required=True)
    p_run.add_argument("--metadata", type=Path, required=True)
    p_run.add_argument("--output", type=Path, required=True)
    p_run.set_defaults(func=_cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
