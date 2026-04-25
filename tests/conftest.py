"""Pytest configuration.

Unit tests must run offline. This fixture strips LLM credentials from the
environment so provider resolution returns ``None`` and each module falls
back to its deterministic offline path.

Tests that explicitly want to exercise a mocked client should use
``monkeypatch.setattr("src.common.llm_client.get_llm_client", ...)``.
"""

from __future__ import annotations

import pytest


_LLM_ENV_VARS = (
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "NVIDIA_API_KEY",
    "NVIDIA_MODEL",
    "NVIDIA_BASE_URL",
)


@pytest.fixture(autouse=True)
def _isolate_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarantee offline behavior for all tests unless explicitly overridden."""
    for var in _LLM_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
