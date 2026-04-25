"""Tests for the JSON Schema validator helper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.common import schema_validator
from src.common.schema_validator import (
    SchemaError,
    validate_or_warn,
    validate_schema,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_atg_mock_passes_atg_schema():
    payload = _load_fixture("atg_mock.json")
    assert validate_schema(payload, "atg") is True


def test_hypotheses_mock_passes_hypotheses_schema():
    payload = _load_fixture("hypotheses_mock.json")
    assert validate_schema(payload, "hypotheses") is True


def test_strict_mode_raises_on_invalid_atg():
    bad = {"bridge_name": "x"}  # missing required nodes/edges/invariants
    with pytest.raises(SchemaError) as exc_info:
        validate_schema(bad, "atg", strict=True)
    err = exc_info.value
    assert err.schema_name == "atg"


def test_lenient_mode_returns_false_on_invalid():
    bad = {"bridge_name": "x"}
    assert validate_schema(bad, "atg", strict=False) is False


def test_validate_or_warn_swallows_errors(capsys: pytest.CaptureFixture[str]):
    bad = {"bridge_name": "x"}
    validate_or_warn(bad, "atg")
    captured = capsys.readouterr()
    assert "schema" in captured.out.lower() or "warn" in captured.out.lower()


def test_unknown_schema_name_is_no_op(capsys: pytest.CaptureFixture[str]):
    """Asking for a non-existent schema must NOT crash the pipeline."""
    schema_validator._load_schema.cache_clear()  # ensure fresh lookup
    assert validate_schema({"any": "thing"}, "doesnotexist") is True


def test_schema_path_in_error_message():
    """SchemaError must encode the failing field path."""
    bad = {
        "bridge_name": "x",
        "version": "1.0",
        "nodes": [{"node_id": "n1"}],  # missing required fields
        "edges": [],
        "invariants": [],
    }
    with pytest.raises(SchemaError) as exc_info:
        validate_schema(bad, "atg", strict=True)
    err = exc_info.value
    assert isinstance(err.path, list)
