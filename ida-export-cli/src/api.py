from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from launcher import default_output, run
from layout import validate_export


@dataclass(frozen=True)
class ExportResult:
    """Published export metadata returned by the public Python API."""

    input_path: Path
    output_path: Path
    manifest: dict[str, Any]
    complete_marker: str


def export_binary(
    input_path: str | Path,
    output: str | Path | None = None,
    *,
    validate_snapshot: bool = True,
) -> ExportResult:
    """Analyze a binary or IDA database and publish a validated export snapshot.

    The call uses the same launcher, worker supervision, recovery state, and
    atomic publication path as the ``ida-export-cli`` command.
    """
    source = Path(input_path)
    destination = Path(output) if output is not None else default_output(source)
    published = run(source, destination)
    if validate_snapshot:
        validate_export(published, require_complete=True)
    manifest = json.loads((published / "manifest.json").read_text(encoding="utf-8"))
    complete_marker = (published / "COMPLETE").read_text(encoding="ascii").strip()
    return ExportResult(
        input_path=source.expanduser().resolve(),
        output_path=published,
        manifest=manifest,
        complete_marker=complete_marker,
    )
