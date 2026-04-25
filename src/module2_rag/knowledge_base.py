"""
Exploit Knowledge Base — Manages structured records of 51 documented cross-chain bridge exploits.

Each record contains:
- Attack metadata (bridge, date, loss, chains)
- Vulnerability class (access_control, fake_deposit, reentrancy, signature_forgery, init_flaw, oracle_manipulation)
- Attack stage (source_chain, off_chain, destination_chain)
- Attack trace (sequence of high-level actions)
- Root cause analysis
"""

import json
from pathlib import Path
from typing import Any


class ExploitKnowledgeBase:
    """Load, manage, and query the exploit knowledge base."""

    def __init__(self, data_dir: str = "src/module2_rag/data"):
        root = Path(__file__).resolve().parents[2]
        data_path = Path(data_dir)
        if data_path.is_absolute():
            self.data_dir = data_path
        else:
            # Prefer repo-root relative semantics so calls work from any cwd.
            self.data_dir = (root / data_path).resolve()
        self.exploits: list[dict] = []

    def load(self) -> None:
        """Load all exploit records from JSON files in data directory."""
        self.exploits = []
        if not self.data_dir.exists():
            return

        for path in sorted(self.data_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    if "id" in data and "exploit_id" not in data:
                        data["exploit_id"] = data["id"]
                    if "exploit_id" not in data:
                        data["exploit_id"] = path.stem
                    self.exploits.append(data)
                elif isinstance(data, list):
                    for idx, item in enumerate(data):
                        if isinstance(item, dict):
                            if "id" in item and "exploit_id" not in item:
                                item["exploit_id"] = item["id"]
                            item.setdefault("exploit_id", f"{path.stem}_{idx}")
                            self.exploits.append(item)
            except json.JSONDecodeError:
                # Skip malformed records to keep pipeline robust during early data collection.
                continue

    def get_by_vuln_class(self, vuln_class: str) -> list[dict]:
        """Filter exploits by vulnerability class."""
        return [e for e in self.exploits if e.get("vulnerability_class") == vuln_class]

    def get_by_attack_stage(self, stage: str) -> list[dict]:
        """Filter exploits by attack stage."""
        return [e for e in self.exploits if e.get("attack_stage") == stage]

    def to_text(self, exploit: dict) -> str:
        """Convert exploit record to text for embedding."""
        fields: list[tuple[str, Any]] = [
            ("exploit_id", exploit.get("exploit_id", "")),
            ("bridge", exploit.get("bridge", "")),
            ("date", exploit.get("date", "")),
            ("loss_usd", exploit.get("loss_usd", exploit.get("loss", ""))),
            ("vulnerability_class", exploit.get("vulnerability_class", "")),
            ("attack_stage", exploit.get("attack_stage", "")),
            ("root_cause", exploit.get("root_cause", "")),
            ("summary", exploit.get("summary", "")),
        ]

        trace = exploit.get("attack_trace", [])
        trace_text = ""
        if isinstance(trace, list):
            trace_steps = []
            for step in trace:
                if isinstance(step, dict):
                    action = step.get("action") or step.get("description") or json.dumps(step, ensure_ascii=False)
                    trace_steps.append(str(action))
                else:
                    trace_steps.append(str(step))
            trace_text = " -> ".join(trace_steps)
        elif isinstance(trace, str):
            trace_text = trace

        body = "\n".join(f"{k}: {v}" for k, v in fields if v not in ("", None))
        if trace_text:
            body += f"\nattack_trace: {trace_text}"
        return body.strip()
