"""Tests for the disk-based embedding cache in :mod:`src.module2_rag.embedder`."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

from src.module2_rag.embedder import ExploitEmbedder


@pytest.fixture
def tmp_embedding_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the cache to a tmp dir so tests don't pollute the workspace."""
    monkeypatch.setenv("BRIDGESENTRY_EMBEDDING_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("BRIDGESENTRY_EMBEDDING_CACHE", "1")
    return tmp_path


def _fake_encode(texts: list[str]) -> np.ndarray:
    # Simple deterministic embedding: each text -> [len, ord(first_char)] padded to 8d.
    rows = []
    for t in texts:
        first = ord(t[0]) if t else 0
        rows.append([len(t), first] + [0.0] * 6)
    return np.asarray(rows, dtype=np.float32)


def _exploit(idx: int) -> dict:
    return {
        "exploit_id": f"e{idx}",
        "bridge": f"Bridge{idx}",
        "vulnerability_class": "fake_deposit",
        "summary": f"Summary {idx}",
    }


def test_first_build_writes_cache_file(tmp_embedding_cache: Path):
    embedder = ExploitEmbedder()
    with patch.object(ExploitEmbedder, "_encode_texts", side_effect=_fake_encode) as mock_enc:
        embedder.build_index([_exploit(1), _exploit(2)])

    assert mock_enc.call_count == 1
    cached = list(tmp_embedding_cache.glob("*.npy"))
    assert len(cached) == 1, "expected one cache file after first build"


def test_second_build_reuses_cache(tmp_embedding_cache: Path):
    embedder = ExploitEmbedder()
    with patch.object(ExploitEmbedder, "_encode_texts", side_effect=_fake_encode) as mock_enc:
        embedder.build_index([_exploit(1), _exploit(2)])

    assert mock_enc.call_count == 1
    first_matrix = embedder._matrix
    assert first_matrix is not None

    # New embedder instance, same texts -> should hit cache, no encode call.
    embedder2 = ExploitEmbedder()
    with patch.object(ExploitEmbedder, "_encode_texts", side_effect=_fake_encode) as mock_enc2:
        embedder2.build_index([_exploit(1), _exploit(2)])

    assert mock_enc2.call_count == 0, "second build should hit the cache"
    np.testing.assert_array_equal(embedder2._matrix, first_matrix)


def test_different_texts_invalidate_cache(tmp_embedding_cache: Path):
    embedder = ExploitEmbedder()
    with patch.object(ExploitEmbedder, "_encode_texts", side_effect=_fake_encode):
        embedder.build_index([_exploit(1), _exploit(2)])

    # Different exploit set -> different hash -> fresh encode call required.
    embedder2 = ExploitEmbedder()
    with patch.object(ExploitEmbedder, "_encode_texts", side_effect=_fake_encode) as mock_enc2:
        embedder2.build_index([_exploit(3), _exploit(4)])

    assert mock_enc2.call_count == 1


def test_disable_cache_via_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BRIDGESENTRY_EMBEDDING_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("BRIDGESENTRY_EMBEDDING_CACHE", "0")

    embedder = ExploitEmbedder()
    with patch.object(ExploitEmbedder, "_encode_texts", side_effect=_fake_encode) as mock_enc:
        embedder.build_index([_exploit(1)])
        embedder.build_index([_exploit(1)])

    assert mock_enc.call_count == 2, "cache must be skipped when disabled"
    assert not list(tmp_path.glob("*.npy")), "no cache file should be written"


def test_corrupt_cache_falls_through(tmp_embedding_cache: Path):
    embedder = ExploitEmbedder()
    key = embedder._cache_key([
        # _cache_key uses model_name + texts; mock kb.to_text returns the same shape
        # as ExploitKnowledgeBase, so we recreate it manually here.
    ])
    # Actually: easier — write garbage at the predicted hash.
    # We recompute the key the way build_index would compute it.
    from src.module2_rag.knowledge_base import ExploitKnowledgeBase

    kb = ExploitKnowledgeBase()
    texts = [kb.to_text(_exploit(1))]
    key = embedder._cache_key(texts)
    cache_file = tmp_embedding_cache / f"{key}.npy"
    cache_file.write_bytes(b"this is not a numpy file")

    with patch.object(ExploitEmbedder, "_encode_texts", side_effect=_fake_encode) as mock_enc:
        embedder.build_index([_exploit(1)])

    assert mock_enc.call_count == 1, "corrupt cache should fall through to fresh encode"
