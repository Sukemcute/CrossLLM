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


class ExploitKnowledgeBase:
    """Load, manage, and query the exploit knowledge base."""

    def __init__(self, data_dir: str = "src/module2_rag/data"):
        self.data_dir = Path(data_dir)
        self.exploits: list[dict] = []

    def load(self) -> None:
        """Load all exploit records from JSON files in data directory."""
        # TODO: Implement loading from JSON files
        raise NotImplementedError

    def get_by_vuln_class(self, vuln_class: str) -> list[dict]:
        """Filter exploits by vulnerability class."""
        return [e for e in self.exploits if e.get("vulnerability_class") == vuln_class]

    def get_by_attack_stage(self, stage: str) -> list[dict]:
        """Filter exploits by attack stage."""
        return [e for e in self.exploits if e.get("attack_stage") == stage]

    def to_text(self, exploit: dict) -> str:
        """Convert exploit record to text for embedding."""
        # TODO: Implement text serialization
        raise NotImplementedError
