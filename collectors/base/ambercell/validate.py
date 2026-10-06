"""Optional debug validation against AmberCell v1 schemas."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

RAWFLOW_REQUIRED = (
    "schema_version",
    "seq_id",
    "session_id",
    "svc",
    "cell_id",
    "collector_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "transport",
    "first_seen",
    "last_seen",
    "parser_status",
    "classification_status",
)

EVENT_REQUIRED = (
    "schema_version",
    "seq_id",
    "event_id",
    "ts",
    "svc",
    "event",
    "session_id",
    "cell_id",
    "collector_id",
)

SCHEMA_VERSION_RAWFLOW = "rawflow.v1"
SCHEMA_VERSION_EVENT = "event.v1"


def debug_validation_enabled() -> bool:
    v = os.environ.get("AMBER_DEBUG_SCHEMA_VALIDATE", "").strip().lower()
    return v in ("1", "true", "yes", "on")


@lru_cache(maxsize=1)
def _schema_root() -> Path | None:
    env = os.environ.get("AMBER_SCHEMA_DIR")
    if env:
        p = Path(env)
        return p if p.is_dir() else None
    # Typical mount in image: /opt/ambercell/schemas
    for candidate in (
        Path("/opt/ambercell/schemas"),
        Path(__file__).resolve().parents[3] / "docs" / "schemas",
    ):
        if candidate.is_dir():
            return candidate
    return None


def _missing_required(record: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    missing: list[str] = []
    for key in required:
        if key not in record or record[key] is None:
            missing.append(key)
        elif isinstance(record[key], str) and not record[key].strip():
            missing.append(key)
    return missing


def _jsonschema_validate(record: dict[str, Any], schema_name: str) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "AMBER_DEBUG_SCHEMA_VALIDATE set but jsonschema not installed "
            "(pip install ambercell-collector-base[validate])"
        ) from exc

    root = _schema_root()
    if root is None:
        raise RuntimeError("Schema directory not found; set AMBER_SCHEMA_DIR")

    path = root / schema_name
    with path.open(encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.validate(record, schema)


def validate_rawflow(record: dict[str, Any]) -> None:
    if record.get("schema_version") != SCHEMA_VERSION_RAWFLOW:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION_RAWFLOW!r}")
    missing = _missing_required(record, RAWFLOW_REQUIRED)
    if missing:
        raise ValueError(f"rawflow missing required fields: {missing}")
    if debug_validation_enabled():
        _jsonschema_validate(record, "rawflow.v1.schema.json")


def validate_event(record: dict[str, Any]) -> None:
    if record.get("schema_version") != SCHEMA_VERSION_EVENT:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION_EVENT!r}")
    missing = _missing_required(record, EVENT_REQUIRED)
    if missing:
        raise ValueError(f"event missing required fields: {missing}")
    if debug_validation_enabled():
        _jsonschema_validate(record, "event.v1.schema.json")
