"""File-based LLM response cache.

Avoids redundant API calls during development by hashing the
``(model, system, user)`` triple and persisting JSON results to disk.

Cache layout
------------
::

    .llm_cache/
        ├── ab12cd34ef.json    # one file per cache entry
        ├── ...

Each file contains::

    {
      "model": "openai/gpt-oss-120b",
      "system_hash": "8d2f7a3b",
      "user_preview": "first 200 chars of the user message...",
      "response": "<raw response string>"
    }

Behavior
--------
* Cache hit  → returns the stored ``response`` string immediately.
* Cache miss → caller invokes the LLM and stores the result.
* Disabled  → set ``BRIDGESENTRY_LLM_CACHE=0`` to bypass entirely.
* Different models / temperatures / system prompts produce different keys
  so cached responses never bleed across configurations.

Thread safety
-------------
File writes are atomic (write-to-temp + rename) so concurrent runs do not
truncate each other. Reading a partially-written file returns ``None`` and
the caller falls through to a fresh API call.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


_DEFAULT_CACHE_DIR = ".llm_cache"


def _is_enabled() -> bool:
    """Cache is on by default; disable with ``BRIDGESENTRY_LLM_CACHE=0``."""
    flag = os.getenv("BRIDGESENTRY_LLM_CACHE", "1").strip().lower()
    return flag not in {"0", "false", "no", "off"}


class LLMCache:
    """File-based cache keyed by SHA-256 of ``(model, system, user)``."""

    def __init__(self, cache_dir: str | Path | None = None):
        base = cache_dir or os.getenv("BRIDGESENTRY_LLM_CACHE_DIR", _DEFAULT_CACHE_DIR)
        self.cache_dir = Path(base)
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Fall back to a temp dir if the working directory is read-only.
            self.cache_dir = Path(tempfile.gettempdir()) / "bridgesentry_llm_cache"
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ keys

    def _key(self, model: str, system: str, user: str, extra: str = "") -> str:
        material = f"{model}\n---\n{system}\n---\n{user}\n---\n{extra}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def _path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    # ------------------------------------------------------------------ get/put

    def get(self, model: str, system: str, user: str, extra: str = "") -> str | None:
        if not _is_enabled():
            return None
        key = self._key(model, system, user, extra)
        path = self._path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        response = data.get("response")
        return response if isinstance(response, str) else None

    def put(
        self,
        model: str,
        system: str,
        user: str,
        response: str,
        extra: str = "",
    ) -> None:
        if not _is_enabled():
            return
        key = self._key(model, system, user, extra)
        path = self._path(key)
        payload: dict[str, Any] = {
            "model": model,
            "system_hash": hashlib.md5(system.encode("utf-8")).hexdigest()[:8],
            "user_preview": user[:200],
            "response": response,
        }
        # Atomic write: tmp + rename.
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            # Best-effort cache; never break the main pipeline.
            try:
                tmp.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:  # noqa: BLE001
                pass

    def clear(self) -> int:
        """Remove all cache entries; returns the number of files deleted."""
        deleted = 0
        for path in self.cache_dir.glob("*.json"):
            try:
                path.unlink()
                deleted += 1
            except OSError:
                continue
        return deleted

    def size(self) -> int:
        return sum(1 for _ in self.cache_dir.glob("*.json"))


# Module-level singleton; tests can monkeypatch this to use a tmp dir.
_cache = LLMCache()


def get_cache() -> LLMCache:
    """Return the module-level cache (override-able by tests)."""
    return _cache


def set_cache(cache: LLMCache) -> None:
    """Replace the module-level cache (used by tests)."""
    global _cache
    _cache = cache
