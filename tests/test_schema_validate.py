#!/usr/bin/env python3
"""Validate golden replay corpus + schema examples against docs/schemas/."""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("jsonschema required: pip install jsonschema", file=sys.stderr)
    raise SystemExit(2)

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = REPO / "docs" / "schemas"


def load_schema(name: str) -> dict:
    with (SCHEMAS / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def validate_file(path: Path, schema_name: str) -> None:
    schema = load_schema(schema_name)
    with path.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            jsonschema.validate(obj, schema)
            _assert_seq_and_ts(obj, path, i)


def _assert_seq_and_ts(obj: dict, path: Path, line: int) -> None:
    if "seq_id" not in obj:
        raise AssertionError(f"{path}:{line}: missing seq_id")
    sv = obj.get("schema_version", "")
    if sv in ("event.v1", "rawflow.v1", "decision.v1"):
        ts_key = "ts" if sv != "rawflow.v1" else None
        if sv == "rawflow.v1":
            for k in ("first_seen", "last_seen"):
                if k in obj and not str(obj[k]).endswith("Z"):
                    raise AssertionError(f"{path}:{line}: {k} must be UTC Zulu with ns")
        elif ts_key and obj.get(ts_key) and not str(obj[ts_key]).endswith("Z"):
            raise AssertionError(f"{path}:{line}: ts must be UTC Zulu")


def main() -> int:
    mapping = {
        "event.v1.schema.json": list((REPO / "tests" / "replay").rglob("events.golden.jsonl")),
        "rawflow.v1.schema.json": list((REPO / "tests" / "replay").rglob("flows.golden.jsonl")),
        "decision.v1.schema.json": list((REPO / "tests" / "replay").rglob("decision*.golden.jsonl"))
        + list((REPO / "tests" / "replay").rglob("*.golden.jsonl")),
    }
    # decision glob fix — only decisions dir
    mapping["decision.v1.schema.json"] = list((REPO / "tests" / "replay" / "decisions").glob("*.golden.jsonl"))

    examples = {
        "event.v1.schema.json": [SCHEMAS / "examples" / "event.example.json"],
        "rawflow.v1.schema.json": [SCHEMAS / "examples" / "rawflow.example.json"],
        "decision.v1.schema.json": [SCHEMAS / "examples" / "decision.example.json"],
    }

    for schema_name, paths in examples.items():
        schema = load_schema(schema_name)
        for p in paths:
            obj = json.loads(p.read_text(encoding="utf-8"))
            jsonschema.validate(obj, schema)

    for schema_name, paths in mapping.items():
        for p in paths:
            validate_file(p, schema_name)

    print("schema validate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
