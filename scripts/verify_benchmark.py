"""Verify a benchmark's metadata + contracts + RPC connectivity.

Checks performed
----------------
1. ``metadata.json`` exists and validates against ``BENCHMARK_METADATA.schema.json``.
2. ``contracts/`` has at least one ``.sol`` file (Solidity source for Module 1).
3. RPC connectivity for ``source_chain`` and ``destination_chain`` (skipped
   when the corresponding ``rpc_env`` variable is unset — useful for offline
   review).
4. The configured ``fork.block_number`` exists on the source chain.
5. Each entry in ``contracts.{name}.address`` has bytecode at the fork block
   (i.e. is a deployed contract — not an EOA placeholder).
6. References URLs are reachable (HEAD request, max 3 to keep fast).

Skipped checks (informational only) emit ``[skip]`` so a partial benchmark
still produces a useful report.

Usage
-----
::

    python scripts/verify_benchmark.py benchmarks/nomad/
    python scripts/verify_benchmark.py benchmarks/qubit/

Exit code is 0 when every actionable check passes, 1 when any issue is
found, and 2 on argument errors.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


def main(benchmark_dir: Path) -> int:
    issues: list[str] = []

    if not benchmark_dir.exists():
        return _report([f"benchmark directory not found: {benchmark_dir}"])

    metadata_path = benchmark_dir / "metadata.json"
    if not metadata_path.exists():
        return _report([f"missing {metadata_path}"])

    metadata: dict[str, Any] = json.loads(metadata_path.read_text(encoding="utf-8"))
    print(f"=== Verifying {benchmark_dir.name} ===")

    _check_schema(metadata, benchmark_dir, issues)
    _check_contracts_dir(benchmark_dir, issues)

    rpc_by_chain = _check_rpc_connectivity(metadata, issues)
    _check_fork_block(metadata, rpc_by_chain, issues)
    _check_contract_addresses(metadata, rpc_by_chain, issues)
    _check_references(metadata, issues)

    return _report(issues)


# ----------------------------------------------------------------- checks


def _check_schema(metadata: dict, benchmark_dir: Path, issues: list[str]) -> None:
    schema_path = benchmark_dir.parent / "BENCHMARK_METADATA.schema.json"
    if not schema_path.exists():
        print("[schema] [skip] BENCHMARK_METADATA.schema.json not found")
        return
    try:
        import jsonschema  # type: ignore
    except ImportError:
        print("[schema] [skip] jsonschema not installed")
        return

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(metadata, schema)
        print("[schema] OK")
    except jsonschema.ValidationError as exc:
        path = ".".join(str(p) for p in exc.absolute_path) or "<root>"
        issues.append(f"schema validation: {path}: {exc.message}")


def _check_contracts_dir(benchmark_dir: Path, issues: list[str]) -> None:
    contracts_dir = benchmark_dir / "contracts"
    if not contracts_dir.exists():
        issues.append("contracts/ directory missing")
        return
    sol_files = sorted(contracts_dir.glob("*.sol"))
    if not sol_files:
        issues.append("contracts/ has no .sol files")
        return
    print(f"[contracts] {len(sol_files)} .sol file(s): {', '.join(p.name for p in sol_files)}")


def _check_rpc_connectivity(metadata: dict, issues: list[str]) -> dict[str, Any]:
    rpc_clients: dict[str, Any] = {}

    try:
        from web3 import Web3  # type: ignore
    except ImportError:
        print("[rpc] [skip] web3 not installed")
        return rpc_clients

    for chain_field in ("source_chain", "destination_chain"):
        chain = metadata.get(chain_field) or {}
        rpc_var = chain.get("rpc_env")
        chain_name = chain.get("name", chain_field)
        if not rpc_var:
            print(f"[rpc {chain_name}] [skip] no rpc_env declared")
            continue
        rpc_url = os.getenv(rpc_var)
        if not rpc_url:
            print(f"[rpc {chain_name}] [skip] env var {rpc_var} not set")
            continue
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
            if w3.is_connected():
                latest = w3.eth.block_number
                print(f"[rpc {chain_name}] connected, latest block {latest}")
                rpc_clients[chain_field] = w3
            else:
                issues.append(f"{chain_name}: {rpc_var} not connecting")
        except Exception as exc:  # noqa: BLE001
            issues.append(f"{chain_name}: {rpc_var} error: {exc}")

    return rpc_clients


def _check_fork_block(
    metadata: dict, rpc_clients: dict[str, Any], issues: list[str]
) -> None:
    fork = metadata.get("fork") or {}
    block_number = fork.get("block_number")
    if not block_number:
        print("[fork] [skip] no fork.block_number declared")
        return

    w3 = rpc_clients.get("source_chain")
    if w3 is None:
        print(f"[fork] [skip] source RPC unavailable, declared block={block_number}")
        return

    try:
        block = w3.eth.get_block(block_number)
        print(f"[fork] block {block_number} exists, ts={block.timestamp}")
    except Exception as exc:  # noqa: BLE001
        issues.append(f"fork block {block_number} not found: {exc}")


def _check_contract_addresses(
    metadata: dict, rpc_clients: dict[str, Any], issues: list[str]
) -> None:
    block_number = (metadata.get("fork") or {}).get("block_number")
    contracts = metadata.get("contracts") or {}
    if not contracts:
        print("[code] [skip] no contracts declared")
        return

    try:
        from web3 import Web3  # type: ignore
    except ImportError:
        print("[code] [skip] web3 not installed")
        return

    # Default to source chain client; some entries may belong to dest chain.
    source_w3 = rpc_clients.get("source_chain")

    for name, info in contracts.items():
        info = info or {}
        addr_raw = info.get("address", "")
        if not addr_raw or addr_raw.startswith("<") or addr_raw.lower() in {"0x0", "0x", "0x0000000000000000000000000000000000000000"}:
            issues.append(f"contracts.{name}.address is placeholder: {addr_raw!r}")
            continue

        try:
            addr = Web3.to_checksum_address(addr_raw)
        except Exception:  # noqa: BLE001
            issues.append(f"contracts.{name}.address is not a valid address: {addr_raw!r}")
            continue

        # Pick the right client: dest chain if explicit, else source.
        chain_hint = info.get("chain", "source")
        if "dest" in chain_hint:
            w3 = rpc_clients.get("destination_chain") or source_w3
        else:
            w3 = source_w3

        if w3 is None:
            print(f"[code] [skip] {name} {addr}: RPC unavailable")
            continue

        # Allow metadata to declare an address as an EOA (recovery wallets,
        # attacker addresses, etc.) so EOA-at-fork-block isn't flagged as an
        # issue. Set ``"is_eoa": true`` on the entry to opt in.
        expect_eoa = bool(info.get("is_eoa"))

        # Try archive query at fork block first; fall back to latest if the
        # configured RPC cannot serve historical state (common for BSC public
        # endpoints which prune to recent blocks). This still confirms the
        # address is a deployed contract today even if we cannot pin it to
        # the historical block.
        code, query_label = _try_get_code(w3, addr, block_number)
        if code is None:
            issues.append(f"{name} {addr} get_code failed on both archive and latest — wrong RPC?")
            continue

        tag = "contract" if len(code) > 2 else "EOA"
        print(f"[code] {name} {addr} -> {tag} ({query_label})")
        if tag == "EOA" and not expect_eoa:
            issues.append(
                f"{name} {addr} has no bytecode — wrong address? "
                f"(set is_eoa: true in metadata if intentional)"
            )


def _try_get_code(w3: Any, addr: str, block_number: int | None) -> tuple[Any, str]:
    """Get code at fork block; fallback to latest when the RPC lacks archive data."""
    if block_number is None:
        try:
            return w3.eth.get_code(addr), "latest"
        except Exception:  # noqa: BLE001
            return None, "fail"

    try:
        return w3.eth.get_code(addr, block_identifier=block_number), f"block {block_number}"
    except Exception as exc:  # noqa: BLE001
        # Public RPCs (BSC, etc.) often return "missing trie node" for old blocks.
        msg = str(exc)
        if any(token in msg.lower() for token in ("missing trie", "pruned", "no archive", "header not found", "execution reverted")):
            try:
                return w3.eth.get_code(addr), "latest (archive unavailable)"
            except Exception:  # noqa: BLE001
                return None, "fail"
        # Other errors propagate as None so caller flags them.
        return None, f"err: {msg[:60]}"


def _check_references(metadata: dict, issues: list[str]) -> None:  # noqa: ARG001
    refs = metadata.get("references") or []
    if not refs:
        print("[ref] [skip] no references declared")
        return

    try:
        import requests  # type: ignore
    except ImportError:
        print("[ref] [skip] requests not installed")
        return

    for ref in refs[:3]:
        url = ref.get("url", "") if isinstance(ref, dict) else ""
        if not url:
            continue
        short = url if len(url) <= 70 else url[:67] + "..."
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code < 400:
                print(f"[ref] {short} -> {r.status_code}")
            else:
                # Some sites refuse HEAD; try GET as a fallback before flagging.
                r = requests.get(url, timeout=8, allow_redirects=True, stream=True)
                if r.status_code < 400:
                    print(f"[ref] {short} -> {r.status_code} (GET)")
                else:
                    print(f"[ref] {short} -> {r.status_code} [warn]")
        except Exception as exc:  # noqa: BLE001
            print(f"[ref] {short} unreachable ({exc.__class__.__name__})")


# ----------------------------------------------------------------- reporting


def _report(issues: list[str]) -> int:
    print()
    if not issues:
        print("ALL CHECKS PASSED")
        return 0
    print(f"{len(issues)} issue(s):")
    for i, msg in enumerate(issues, 1):
        print(f"  {i}. {msg}")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/verify_benchmark.py <benchmark_dir>")
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1])))
