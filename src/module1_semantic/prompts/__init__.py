"""Prompt file loader for Module 1 (semantic extraction + invariant synthesis)."""

from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent


def load(name: str) -> str:
    """Load a prompt file from this directory. Accepts bare name or ``name.txt``."""
    path = _PROMPTS_DIR / name
    if not path.suffix:
        path = path.with_suffix(".txt")
    return path.read_text(encoding="utf-8").strip()
