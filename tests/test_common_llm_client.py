"""Tests for the shared LLM client utility."""

from __future__ import annotations

import pytest

from src.common import llm_client
from src.common.llm_client import LLMProvider, get_llm_client, with_retry


def test_get_llm_client_returns_none_without_credentials() -> None:
    assert get_llm_client() is None


def test_get_llm_client_skips_placeholder_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-YOUR_KEY_HERE")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-YOUR_KEY_HERE")
    assert get_llm_client() is None


def test_get_llm_client_picks_openai_when_only_openai_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-abcdefghij")
    provider = get_llm_client()
    assert provider is not None
    assert isinstance(provider, LLMProvider)
    assert provider.provider_name == "openai"
    assert provider.model  # default model is populated


def test_get_llm_client_prefers_nvidia_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-abc")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-abc")
    provider = get_llm_client()
    assert provider is not None
    assert provider.provider_name == "nvidia"


def test_get_llm_client_prefer_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-abc")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-abc")
    provider = get_llm_client(prefer="openai")
    assert provider is not None
    assert provider.provider_name == "openai"


def test_with_retry_passes_through_on_success() -> None:
    calls = {"n": 0}

    @with_retry(max_retries=3, base_delay=0.0)
    def ok() -> str:
        calls["n"] += 1
        return "ok"

    assert ok() == "ok"
    assert calls["n"] == 1


def test_with_retry_raises_non_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    @with_retry(max_retries=3, base_delay=0.0)
    def bad() -> None:
        raise ValueError("not retryable")

    with pytest.raises(ValueError):
        bad()


def test_with_retry_recovers_after_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate APIConnectionError for the first two calls, then success.
    class APIConnectionError(Exception):
        pass

    calls = {"n": 0}

    @with_retry(max_retries=3, base_delay=0.0)
    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise APIConnectionError("transient")
        return "done"

    # Patch sleep to be instantaneous (retry still increments counter).
    monkeypatch.setattr(llm_client.time, "sleep", lambda _s: None)
    assert flaky() == "done"
    assert calls["n"] == 3
