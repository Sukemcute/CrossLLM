"""JSON Schema validation helpers for the BridgeSentry pipeline.

The Member B Rust fuzzer rejects malformed ATG / hypotheses files with a
generic "deserialization failed" error. Validating the JSON against the
project schemas before invoking the binary lets the orchestrator surface a
clear field-level error instead.

Usage
-----
::

    from src.common.schema_validator import validate_schema
    validate_schema(atg_dict, "atg")  # raises ValidationError with field path
    validate_schema(hyp_dict, "hypotheses")
    validate_schema(results_dict, "results")
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = PROJECT_ROOT / "schemas"


class SchemaError(RuntimeError):
    """Raised when a payload fails JSON Schema validation."""

    def __init__(self, schema_name: str, message: str, path: list[Any] | None = None):
        self.schema_name = schema_name
        self.message = message
        self.path = path or []
        location = ".".join(str(p) for p in self.path) if self.path else "<root>"
        super().__init__(f"[schema:{schema_name}] {location}: {message}")


@lru_cache(maxsize=8)
def _load_schema(name: str) -> dict | None:
    """Load and cache a schema by short name (e.g. ``"atg"`` -> ``atg.schema.json``)."""
    candidate = SCHEMAS_DIR / f"{name}.schema.json"
    if not candidate.exists():
        return None
    return json.loads(candidate.read_text(encoding="utf-8"))


def validate_schema(payload: dict, schema_name: str, *, strict: bool = True) -> bool:
    """Validate ``payload`` against ``schemas/<schema_name>.schema.json``.

    Args:
        payload: The dict to validate.
        schema_name: Short name (``"atg"``, ``"hypotheses"``, ``"results"``).
        strict: When ``True`` (default), raise :class:`SchemaError` on failure.
            When ``False``, return ``True`` on success and ``False`` otherwise.

    Returns:
        ``True`` when the payload is valid; otherwise raises (strict) or
        returns ``False``.

    Raises:
        SchemaError: When validation fails in strict mode.
    """
    schema = _load_schema(schema_name)
    if schema is None:
        # Schema file missing — treat as no-op so the pipeline still runs.
        # The README in `schemas/` documents which files are required.
        print(f"[schema] WARN: schemas/{schema_name}.schema.json not found, skipping")
        return True

    try:
        import jsonschema  # type: ignore
        from jsonschema import Draft202012Validator  # type: ignore
    except ImportError:
        # jsonschema not installed — can happen in minimal CI environments.
        # Fall back to a no-op rather than blocking the pipeline.
        print("[schema] WARN: jsonschema not installed, skipping validation")
        return True

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if not errors:
        return True

    first = errors[0]
    if strict:
        raise SchemaError(
            schema_name,
            first.message,
            path=list(first.absolute_path),
        )
    return False


def validate_or_warn(payload: dict, schema_name: str) -> None:
    """Validate but only emit a warning on failure (never raises)."""
    try:
        validate_schema(payload, schema_name, strict=True)
    except SchemaError as exc:
        print(f"[schema] WARN: {exc}")
