"""Unified LLM client resolution supporting both OpenAI and NVIDIA NIM.

Both providers are OpenAI-API-compatible — NVIDIA NIM exposes an OpenAI-style
endpoint at `https://integrate.api.nvidia.com/v1`. We normalize them behind a
single `LLMProvider` dataclass so the rest of the codebase can call
`provider.client.chat.completions.create(...)` without caring where the model
lives.

Environment variables
---------------------
* ``NVIDIA_API_KEY`` — preferred for dev (free credits for gpt-oss-120b, llama-3.3-70b).
* ``NVIDIA_BASE_URL`` — override for self-hosted NIM, defaults to the public endpoint.
* ``NVIDIA_MODEL`` — default: ``meta/llama-3.3-70b-instruct``.
* ``OPENAI_API_KEY`` — fallback for production experiments.
* ``OPENAI_MODEL`` — default: ``gpt-4o-mini``.

Use
---
>>> from src.common.llm_client import get_llm_client
>>> provider = get_llm_client()
>>> if provider:
...     resp = provider.client.chat.completions.create(
...         model=provider.model, messages=[...], temperature=0.0,
...     )
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable


@dataclass
class LLMProvider:
    """Resolved LLM provider (client + model + name)."""

    client: Any
    model: str
    provider_name: str  # "nvidia" | "openai"


def _is_placeholder(key: str | None) -> bool:
    """Return True if the key looks like a `.env.example` placeholder."""
    if not key:
        return True
    stripped = key.strip()
    if not stripped:
        return True
    placeholders = ("your", "xxx", "todo", "replace", "changeme")
    low = stripped.lower()
    return any(p in low for p in placeholders)


def get_llm_client(prefer: str = "auto") -> LLMProvider | None:
    """Resolve an LLM provider from environment variables.

    Args:
        prefer: ``"auto"`` (NVIDIA-first for free dev), ``"nvidia"``, or ``"openai"``.

    Returns:
        An ``LLMProvider`` instance or ``None`` when no usable credentials are set.
    """
    try:
        from openai import OpenAI
    except ImportError:
        return None

    providers: list[tuple[str, Any, str]] = []

    nvidia_key = os.getenv("NVIDIA_API_KEY")
    if not _is_placeholder(nvidia_key):
        providers.append(
            (
                "nvidia",
                OpenAI(
                    api_key=nvidia_key,
                    base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
                ),
                os.getenv("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct"),
            )
        )

    openai_key = os.getenv("OPENAI_API_KEY")
    if not _is_placeholder(openai_key) and openai_key.startswith("sk-"):
        providers.append(
            (
                "openai",
                OpenAI(api_key=openai_key),
                os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            )
        )

    if not providers:
        return None

    if prefer == "nvidia":
        providers.sort(key=lambda p: 0 if p[0] == "nvidia" else 1)
    elif prefer == "openai":
        providers.sort(key=lambda p: 0 if p[0] == "openai" else 1)
    # "auto": keep NVIDIA-first order naturally (NVIDIA inserted first above).

    name, client, model = providers[0]
    return LLMProvider(client=client, model=model, provider_name=name)


def with_retry(max_retries: int = 3, base_delay: float = 2.0) -> Callable:
    """Decorator: retry an LLM call on transient errors with exponential backoff.

    RateLimitError uses a longer base wait (30s) since upstream quotas usually
    reset on a per-minute window. Non-retryable errors (validation, auth)
    propagate immediately.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_error: Exception | None = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:  # noqa: BLE001 — we re-raise below
                    err_name = type(e).__name__
                    last_error = e

                    if err_name == "RateLimitError":
                        delay = 30 * (2**attempt)
                    elif err_name in (
                        "APIConnectionError",
                        "APITimeoutError",
                        "APIError",
                        "InternalServerError",
                    ):
                        delay = base_delay * (2**attempt)
                    else:
                        # Non-retryable (AuthenticationError, BadRequestError, ...)
                        raise

                    if attempt < max_retries - 1:
                        print(f"[LLM] {err_name} (attempt {attempt + 1}/{max_retries}), retry in {delay:.1f}s...")
                        time.sleep(delay)

            if last_error is not None:
                raise last_error
            return None  # unreachable

        return wrapper

    return decorator


def chat_completion_json(
    provider: LLMProvider,
    system: str,
    user: str,
    *,
    temperature: float = 0.0,
    max_tokens: int | None = None,
    use_cache: bool = True,
) -> str:
    """JSON-mode chat completion with retry **and file-based caching**.

    The cache key is ``(provider.model, system, user, extra)`` where ``extra``
    encodes ``temperature`` and ``max_tokens`` so different sampling configs
    do not share entries. Set ``use_cache=False`` to bypass.

    Returns the raw string content; caller is responsible for ``json.loads``.
    """
    from src.common.llm_cache import get_cache  # local import to avoid cycle

    cache = get_cache() if use_cache else None
    extra = f"temperature={temperature}|max_tokens={max_tokens}"

    if cache is not None:
        cached = cache.get(provider.model, system, user, extra=extra)
        if cached is not None:
            return cached

    content = _chat_completion_json_uncached(
        provider, system, user, temperature=temperature, max_tokens=max_tokens
    )

    if cache is not None and content:
        cache.put(provider.model, system, user, content, extra=extra)
    return content


@with_retry(max_retries=3)
def _chat_completion_json_uncached(
    provider: LLMProvider,
    system: str,
    user: str,
    *,
    temperature: float = 0.0,
    max_tokens: int | None = None,
) -> str:
    """Internal: actual API call with retry. Use :func:`chat_completion_json`."""
    kwargs: dict[str, Any] = {
        "model": provider.model,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens

    resp = provider.client.chat.completions.create(**kwargs)
    msg = resp.choices[0].message
    # NVIDIA gpt-oss-120b emits reasoning_content; regular chat models use content.
    content = getattr(msg, "content", None) or getattr(msg, "reasoning_content", None) or ""
    return content
