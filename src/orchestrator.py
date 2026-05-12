"""
BridgeSentry Orchestrator — coordinates the full pipeline.

Pipeline: Module 1 (Semantic Extraction) -> Module 2 (Attack Scenarios)
          -> Module 3 (Dual-Chain Fuzzing)

Sprint 3 polish
---------------
* JSON Schema validation for ``atg.json`` and ``hypotheses.json`` before
  invoking the Rust fuzzer (stops malformed pipeline output early).
* Optional Rich progress bar (``--progress``) so long Module 1+2 runs are
  observable without parsing log lines.

Usage
-----
::

    python -m src.orchestrator \\
        --benchmark benchmarks/nomad/ \\
        --time-budget 600 --runs 5 --rag-k 5 --beta 0.4 \\
        --output results/nomad/
"""

from __future__ import annotations

import argparse
import json
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from src.common.schema_validator import SchemaError, validate_or_warn, validate_schema
from src.module1_semantic.atg_builder import ATGBuilder
from src.module1_semantic.extractor import SemanticExtractor
from src.module1_semantic.invariant_synth import InvariantSynthesizer
from src.module2_rag.scenario_gen import AttackScenarioGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BridgeSentry Pipeline Orchestrator")
    parser.add_argument("--benchmark", type=str, required=True, help="Path to benchmark directory")
    parser.add_argument("--time-budget", type=int, default=600, help="Fuzzing time budget in seconds")
    parser.add_argument("--runs", type=int, default=5, help="Number of independent runs")
    parser.add_argument("--rag-k", type=int, default=5, help="Number of retrieved exploits for RAG")
    parser.add_argument("--beta", type=float, default=0.4, help="Waypoint reward weight")
    parser.add_argument("--output", type=str, required=True, help="Output directory for results")
    parser.add_argument("--skip-fuzzer", action="store_true", help="Run Module1+2 only, skip Rust fuzzer")
    parser.add_argument(
        "--strict-schema",
        action="store_true",
        help="Raise on schema validation failure (default: warn and continue)",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show a Rich progress bar while running",
    )
    return parser.parse_args()


# ---------------------------------------------------------- progress wrapper


class _NullProgress:
    """No-op stand-in when Rich is unavailable or progress is disabled."""

    def add_task(self, description: str, total: int | None = None) -> int:  # noqa: ARG002
        print(f"[Pipeline] {description}")
        return 0

    def advance(self, task_id: int, advance: int = 1) -> None:  # noqa: ARG002
        return

    def update(self, task_id: int, **kwargs: Any) -> None:  # noqa: ARG002
        return


@contextmanager
def _progress_ctx(enabled: bool) -> Iterator[Any]:
    """Yield a Rich Progress when ``enabled`` else a silent no-op shim."""
    if not enabled:
        yield _NullProgress()
        return
    try:
        from rich.progress import (
            BarColumn,
            Progress,
            SpinnerColumn,
            TextColumn,
            TimeElapsedColumn,
        )
    except ImportError:
        yield _NullProgress()
        return

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
    )
    progress.start()
    try:
        yield progress
    finally:
        progress.stop()


# ------------------------------------------------------------- main pipeline


def run_pipeline(args: argparse.Namespace) -> None:
    """Execute the full BridgeSentry pipeline."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    benchmark_dir = Path(args.benchmark)
    contracts_dir = benchmark_dir / "contracts"
    contract_files = sorted(contracts_dir.glob("*.sol")) if contracts_dir.exists() else []
    if not contract_files:
        raise FileNotFoundError(f"No Solidity contracts found in {contracts_dir}")

    extractor = SemanticExtractor()
    atg_builder = ATGBuilder()
    invariant_synth = InvariantSynthesizer()
    scenario_gen = AttackScenarioGenerator(top_k=args.rag_k)

    with _progress_ctx(args.progress) as progress:
        # ---- Step 1: Module 1 — Semantic Extraction -----------------------
        task_extract = progress.add_task(
            "[cyan]Module 1: Extracting semantics", total=len(contract_files)
        )
        merged_semantics: dict[str, list[Any]] = {
            "entities": [],
            "functions": [],
            "asset_flows": [],
            "guards": [],
        }
        for contract_path in contract_files:
            sem = extractor.extract_from_file(str(contract_path))
            for key in merged_semantics:
                merged_semantics[key].extend(sem.get(key, []))
            progress.advance(task_extract)

        # ---- Step 1b: ATG + invariants ------------------------------------
        task_atg = progress.add_task("[green]Module 1: ATG + invariants", total=2)
        atg = atg_builder.build(merged_semantics)
        atg_json = atg_builder.to_json(atg)
        atg_json["bridge_name"] = benchmark_dir.name
        progress.advance(task_atg)

        invariants = invariant_synth.synthesize(atg_json)
        invariants = invariant_synth.validate(invariants, normal_traces=[])
        atg_json["invariants"] = invariants
        progress.advance(task_atg)

        atg_path = output_dir / "atg.json"
        atg_path.write_text(json.dumps(atg_json, ensure_ascii=False, indent=2), encoding="utf-8")
        _validate("atg", atg_json, strict=args.strict_schema)

        # ---- Step 2: Module 2 — Attack Scenario Generation ----------------
        task_scenarios = progress.add_task(
            "[yellow]Module 2: RAG scenario generation", total=len(invariants) or 1
        )
        scenarios = scenario_gen.generate(atg_json, invariants)
        progress.update(task_scenarios, completed=len(invariants) or 1)

        hypotheses = {"bridge_name": benchmark_dir.name, "scenarios": scenarios}
        hypotheses_path = output_dir / "hypotheses.json"
        hypotheses_path.write_text(
            json.dumps(hypotheses, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _validate("hypotheses", hypotheses, strict=args.strict_schema)

        # ---- Step 3: Module 3 — Dual-Chain Fuzzing ------------------------
        fuzzer_results = _run_fuzzer(
            args=args,
            atg_path=atg_path,
            hypotheses_path=hypotheses_path,
            output_dir=output_dir,
            progress=progress,
        )

        # ---- Step 4: Aggregate report -------------------------------------
        report = {
            "benchmark": benchmark_dir.name,
            "artifacts": {
                "atg": str(atg_path),
                "hypotheses": str(hypotheses_path),
            },
            "module1": {
                "contracts_processed": len(contract_files),
                "entities": len(atg_json.get("nodes", [])),
                "edges": len(atg_json.get("edges", [])),
                "invariants": len(invariants),
            },
            "module2": {"scenarios": len(scenarios)},
            "module3": {
                "runs_attempted": args.runs if not args.skip_fuzzer else 0,
                "runs_completed": len(fuzzer_results),
                "violations_total": sum(len(r.get("violations", [])) for r in fuzzer_results),
            },
        }
        (output_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[Output] Saved report to {output_dir / 'report.json'}")


def _validate(schema_name: str, payload: dict, *, strict: bool) -> None:
    """Validate a payload, raising in strict mode and warning otherwise."""
    if strict:
        try:
            validate_schema(payload, schema_name, strict=True)
        except SchemaError as exc:
            raise SystemExit(f"ERROR: {exc}") from exc
    else:
        validate_or_warn(payload, schema_name)


def _run_fuzzer(
    *,
    args: argparse.Namespace,
    atg_path: Path,
    hypotheses_path: Path,
    output_dir: Path,
    progress: Any,
) -> list[dict]:
    """Invoke the Rust fuzzer for ``--runs`` runs (skipped if ``--skip-fuzzer``)."""
    fuzzer_results: list[dict] = []
    if args.skip_fuzzer:
        progress.add_task("[dim]Module 3: skipped (--skip-fuzzer)", total=1)
        print("[Module 3] Skipped by --skip-fuzzer")
        return fuzzer_results

    fuzzer_bin = Path("src/module3_fuzzing/target/release/bridgesentry-fuzzer")
    if not fuzzer_bin.exists():
        progress.add_task("[red]Module 3: binary not built", total=1)
        print("[Module 3] Fuzzer binary not found, skipping execution.")
        return fuzzer_results

    task_fuzz = progress.add_task("[red]Module 3: Dual-chain fuzzing", total=args.runs)
    for run_id in range(args.runs):
        run_out = output_dir / f"results_run_{run_id + 1}.json"
        cmd = [
            str(fuzzer_bin),
            "--atg",
            str(atg_path),
            "--scenarios",
            str(hypotheses_path),
            "--budget",
            str(args.time_budget),
            "--output",
            str(run_out),
        ]
        try:
            subprocess.run(cmd, check=True)
            if run_out.exists():
                payload = json.loads(run_out.read_text(encoding="utf-8"))
                fuzzer_results.append(payload)
                # Validate each run output (warn-only — don't kill pipeline).
                validate_or_warn(payload, "results")
        except Exception as exc:  # noqa: BLE001
            print(f"[Module 3] Run {run_id + 1} failed: {exc}")
        finally:
            progress.advance(task_fuzz)

    return fuzzer_results


if __name__ == "__main__":
    run_pipeline(parse_args())
