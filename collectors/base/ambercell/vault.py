"""Append-only evidence vault: rotation moves closed segments only.

Active capture writes to ``*.jsonl.active``. Closing a segment renames the active
file to a timestamped closed name and optionally archives a copy under vault/.
Closed segments must never be rewritten in place.
"""

from __future__ import annotations

import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("ambercell.vault")

VAULT_NOTES = """\
AmberCell evidence vault (Stage-3)
- Active writers use *.jsonl.active (append-only, line-buffered).
- Rotation renames active → closed segment (*.jsonl.YYYYMMDDTHHMMSSZ); no in-place edits.
- Closed segments and vault/ archive copies are chmod 0440 (practical local WORM).
- Do not use chattr +i on live evidence trees — it fights rotation and export.
- Export and replay consume closed segments only; never the active tail unless --live.
"""


def vault_root(evidence_root: Path | None = None) -> Path:
    root = evidence_root or Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell"))
    return root / "vault"


def ensure_vault_notes(evidence_root: Path | None = None) -> None:
    root = evidence_root or Path(os.environ.get("AMBER_EVIDENCE_ROOT", "/var/ambercell"))
    notes = root / "vault" / "README.notes"
    notes.parent.mkdir(parents=True, exist_ok=True)
    if not notes.exists():
        notes.write_text(VAULT_NOTES, encoding="utf-8")
        try:
            os.chmod(notes.parent, 0o750)
        except OSError:
            pass


def active_jsonl_path(base: Path) -> Path:
    """Return active writer path for a logical JSONL file (e.g. events.jsonl → events.jsonl.active)."""
    if str(base).endswith(".active"):
        return base
    return Path(str(base) + ".active")


def ensure_lab_symlink(logical: Path, active: Path) -> None:
    """Symlink logical → active for lab smoke scripts that tail events.jsonl."""
    if logical.exists() and not logical.is_symlink():
        return
    if active.exists() and not logical.exists():
        try:
            logical.symlink_to(active.name)
        except OSError as exc:
            log.debug("symlink %s -> %s: %s", logical, active, exc)


def close_active_segment(active_path: Path, *, archive: bool = True) -> Path | None:
    """Rename active JSONL to a closed segment; return closed path or None if no active file."""
    if not active_path.is_file():
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = active_path.name
    if name.endswith(".jsonl.active"):
        closed_name = name[: -len(".active")] + f".{ts}"
    else:
        closed_name = name + f".closed.{ts}"
    closed = active_path.with_name(closed_name)
    active_path.rename(closed)
    # Closed segments are append-only WORM in practice: strip write bits in place
    # and on the vault archive copy. Do not use chattr +i (fights rotation/export).
    try:
        os.chmod(closed, 0o440)
    except OSError:
        pass
    log.info("closed JSONL segment %s", closed)
    if archive:
        root = active_path.parent
        while root.name and root != root.parent:
            if root.name in ("jsonl", "raw-flows") and root.parent.name != "vault":
                evidence = root.parent
                rel = closed.relative_to(evidence)
                dest = vault_root(evidence) / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(closed, dest)
                try:
                    os.chmod(dest, 0o440)
                except OSError:
                    pass
                log.info("vault archive %s", dest)
                break
            root = root.parent
    return closed
