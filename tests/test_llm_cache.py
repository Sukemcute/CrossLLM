"""Tests for the file-based LLM response cache."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.common import llm_cache
from src.common.llm_cache import LLMCache, get_cache, set_cache


@pytest.fixture
def tmp_cache(tmp_path: Path):
    """Replace the module-level cache with a fresh tmp-dir cache."""
    original = get_cache()
    cache = LLMCache(cache_dir=tmp_path)
    set_cache(cache)
    yield cache
    set_cache(original)


def test_cache_miss_returns_none(tmp_cache: LLMCache):
    assert tmp_cache.get("model-x", "sys", "user") is None


def test_cache_put_then_get_roundtrip(tmp_cache: LLMCache):
    tmp_cache.put("model-x", "sys", "user", '{"ok": true}')
    assert tmp_cache.get("model-x", "sys", "user") == '{"ok": true}'


def test_cache_distinguishes_models(tmp_cache: LLMCache):
    tmp_cache.put("model-a", "sys", "user", "A")
    tmp_cache.put("model-b", "sys", "user", "B")
    assert tmp_cache.get("model-a", "sys", "user") == "A"
    assert tmp_cache.get("model-b", "sys", "user") == "B"


def test_cache_distinguishes_extra_field(tmp_cache: LLMCache):
    tmp_cache.put("m", "s", "u", "low-temp", extra="temperature=0.0")
    tmp_cache.put("m", "s", "u", "hot-temp", extra="temperature=0.9")
    assert tmp_cache.get("m", "s", "u", extra="temperature=0.0") == "low-temp"
    assert tmp_cache.get("m", "s", "u", extra="temperature=0.9") == "hot-temp"


def test_cache_clear(tmp_cache: LLMCache):
    tmp_cache.put("m", "s", "u1", "1")
    tmp_cache.put("m", "s", "u2", "2")
    assert tmp_cache.size() == 2
    deleted = tmp_cache.clear()
    assert deleted == 2
    assert tmp_cache.size() == 0


def test_cache_disabled_via_env(tmp_cache: LLMCache, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BRIDGESENTRY_LLM_CACHE", "0")
    tmp_cache.put("m", "s", "u", "x")
    assert tmp_cache.get("m", "s", "u") is None


def test_cache_handles_corrupt_file(tmp_cache: LLMCache):
    # Manually create a malformed cache file
    key = tmp_cache._key("m", "s", "u")
    path = tmp_cache._path(key)
    path.write_text("not-json", encoding="utf-8")
    assert tmp_cache.get("m", "s", "u") is None


def test_chat_completion_json_uses_cache(tmp_cache: LLMCache, monkeypatch: pytest.MonkeyPatch):
    """Wired path: chat_completion_json hits the cache before calling the API."""
    from src.common import llm_client

    calls = {"n": 0}

    def fake_uncached(provider, system, user, *, temperature=0.0, max_tokens=None):
        calls["n"] += 1
        return '{"answer": 42}'

    monkeypatch.setattr(llm_client, "_chat_completion_json_uncached", fake_uncached)

    class FakeProvider:
        client = None
        model = "model-z"
        provider_name = "test"

    provider = FakeProvider()
    out1 = llm_client.chat_completion_json(provider, "sys", "user", temperature=0.0)
    out2 = llm_client.chat_completion_json(provider, "sys", "user", temperature=0.0)

    assert out1 == out2 == '{"answer": 42}'
    assert calls["n"] == 1, "Second call should hit cache, not the API"


def test_chat_completion_json_bypass_cache(tmp_cache: LLMCache, monkeypatch: pytest.MonkeyPatch):
    """use_cache=False forces a fresh API call every time."""
    from src.common import llm_client

    calls = {"n": 0}

    def fake_uncached(provider, system, user, *, temperature=0.0, max_tokens=None):
        calls["n"] += 1
        return '{"call": ' + str(calls["n"]) + "}"

    monkeypatch.setattr(llm_client, "_chat_completion_json_uncached", fake_uncached)

    class FakeProvider:
        client = None
        model = "model-z"
        provider_name = "test"

    provider = FakeProvider()
    out1 = llm_client.chat_completion_json(provider, "s", "u", use_cache=False)
    out2 = llm_client.chat_completion_json(provider, "s", "u", use_cache=False)

    assert out1 != out2
    assert calls["n"] == 2
