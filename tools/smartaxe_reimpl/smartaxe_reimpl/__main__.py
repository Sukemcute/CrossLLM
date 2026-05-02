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
    """Full SmartAxe pipeline: CFG → xCFG → xDFG → detect_ccv → JSON."""

    import time

    from .bridge_config import load_bridge_config
    from .cfg_builder import build_contract_cfgs
    from .detector import detect_ccv
    from .output import write_run
    from .xcfg_builder import build_xcfg, partition_cfgs
    from .xdfg_builder import build_xdfg

    # Resolve to absolute path so a relative `--metadata metadata.json`
    # invoked from inside the bridge directory still yields a non-empty
    # bridge_id (Path('.').name == '').
    bridge_dir = args.metadata.resolve().parent
    bridge_id = bridge_dir.name

    t0 = time.perf_counter()
    bridge_cfg = load_bridge_config(bridge_dir)
    cfgs = build_contract_cfgs(args.contracts)
    src, dst = partition_cfgs(cfgs, bridge_cfg)
    xcfg = build_xcfg(src, dst, bridge_cfg)
    xdfg = build_xdfg(xcfg)
    violations = detect_ccv(xcfg, xdfg)
    analysis_s = time.perf_counter() - t0

    # Pull expected SCs from a per-bridge map if --expected-sc passed.
    expected = list(args.expected_sc) if args.expected_sc else None

    write_run(
        output_path=args.output,
        bridge_id=bridge_id,
        run_id=args.run_id,
        analysis_seconds=analysis_s,
        contracts=cfgs,
        violations=violations,
        expected_sc=expected,
    )
    print(
        f"smartaxe-reimpl: bridge={bridge_id} contracts={len(cfgs)} "
        f"violations={len(violations)} analysis_s={analysis_s:.2f}",
        file=sys.stderr,
    )
    return 0


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

    p_run = sub.add_parser("run", help="Full SmartAxe pipeline (CFG → xCFG → xDFG → detect_ccv)")
    p_run.add_argument("--contracts", type=Path, required=True)
    p_run.add_argument("--metadata", type=Path, required=True)
    p_run.add_argument("--output", type=Path, required=True)
    p_run.add_argument("--run-id", type=int, default=1)
    p_run.add_argument(
        "--expected-sc",
        action="append",
        default=None,
        help="Expected SC IDs (repeatable). Used by SA6/SA7 verifier for predicate-match.",
    )
    p_run.set_defaults(func=_cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
