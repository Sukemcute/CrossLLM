"""
BridgeSentry Orchestrator — Coordinates the full pipeline.

Pipeline: Module 1 (Semantic Extraction) -> Module 2 (Attack Scenarios) -> Module 3 (Dual-Chain Fuzzing)

Usage:
    python src/orchestrator.py \
        --benchmark benchmarks/nomad/ \
        --time-budget 600 \
        --runs 5 \
        --rag-k 5 \
        --beta 0.4 \
        --output results/nomad/
"""

import argparse
import json
import subprocess
from pathlib import Path

from src.module1_semantic.atg_builder import ATGBuilder
from src.module1_semantic.extractor import SemanticExtractor
from src.module1_semantic.invariant_synth import InvariantSynthesizer
from src.module2_rag.scenario_gen import AttackScenarioGenerator


def parse_args():
    parser = argparse.ArgumentParser(description="BridgeSentry Pipeline Orchestrator")
    parser.add_argument("--benchmark", type=str, required=True, help="Path to benchmark directory")
    parser.add_argument("--time-budget", type=int, default=600, help="Fuzzing time budget in seconds")
    parser.add_argument("--runs", type=int, default=5, help="Number of independent runs")
    parser.add_argument("--rag-k", type=int, default=5, help="Number of retrieved exploits for RAG")
    parser.add_argument("--beta", type=float, default=0.4, help="Waypoint reward weight")
    parser.add_argument("--output", type=str, required=True, help="Output directory for results")
    parser.add_argument("--skip-fuzzer", action="store_true", help="Run Module1+2 only, skip Rust fuzzer")
    return parser.parse_args()


def run_pipeline(args):
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

    # Step 1: Module 1 — Semantic Extraction
    print(f"[Module 1] Extracting semantics from {args.benchmark}...")
    merged_semantics = {"entities": [], "functions": [], "asset_flows": [], "guards": []}
    for contract_path in contract_files:
        sem = extractor.extract_from_file(str(contract_path))
        merged_semantics["entities"].extend(sem.get("entities", []))
        merged_semantics["functions"].extend(sem.get("functions", []))
        merged_semantics["asset_flows"].extend(sem.get("asset_flows", []))
        merged_semantics["guards"].extend(sem.get("guards", []))

    atg = atg_builder.build(merged_semantics)
    atg_json = atg_builder.to_json(atg)
    atg_json["bridge_name"] = benchmark_dir.name
    invariants = invariant_synth.synthesize(atg_json)
    invariants = invariant_synth.validate(invariants, normal_traces=[])
    atg_json["invariants"] = invariants
    atg_path = output_dir / "atg.json"
    atg_path.write_text(json.dumps(atg_json, ensure_ascii=False, indent=2), encoding="utf-8")

    # Step 2: Module 2 — Attack Scenario Generation
    print("[Module 2] Generating attack scenarios via RAG...")
    scenarios = scenario_gen.generate(atg_json, invariants)
    hypotheses = {"bridge_name": benchmark_dir.name, "scenarios": scenarios}
    hypotheses_path = output_dir / "hypotheses.json"
    hypotheses_path.write_text(json.dumps(hypotheses, ensure_ascii=False, indent=2), encoding="utf-8")

    # Step 3: Module 3 — Dual-Chain Fuzzing
    fuzzer_results = []
    if args.skip_fuzzer:
        print("[Module 3] Skipped by --skip-fuzzer")
    else:
        fuzzer_bin = Path("src/module3_fuzzing/target/release/bridgesentry-fuzzer")
        if not fuzzer_bin.exists():
            print("[Module 3] Fuzzer binary not found, skipping execution.")
        else:
            for run_id in range(args.runs):
                print(f"[Module 3] Fuzzing run {run_id + 1}/{args.runs} (budget: {args.time_budget}s)...")
                run_out = output_dir / f"results_run_{run_id + 1}.json"
                cmd = [
                    str(fuzzer_bin),
                    "--atg",
                    str(atg_path),
                    "--hypotheses",
                    str(hypotheses_path),
                    "--time-budget-s",
                    str(args.time_budget),
                    "--output",
                    str(run_out),
                ]
                try:
                    subprocess.run(cmd, check=True)
                    if run_out.exists():
                        fuzzer_results.append(json.loads(run_out.read_text(encoding="utf-8")))
                except Exception as exc:
                    print(f"[Module 3] Run {run_id + 1} failed: {exc}")

    # Step 4: Aggregate results
    print("[Output] Aggregating results...")
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
    (output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[Output] Saved report to {output_dir / 'report.json'}")


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(args)
