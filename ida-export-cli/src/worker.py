from __future__ import annotations

# idapro must initialize idalib before ida-domain imports any IDA module.
import idapro  # type: ignore  # noqa: F401

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import exporter
from config import ida_runtime_version, runtime_versions, stable_fingerprint
from ida_adapter import IdaDomainAdapter


_ADAPTER_CAPABILITIES = (
    "metadata",
    "functions",
    "function_name",
    "function_signature",
    "function_flags",
    "function_skip_reason",
    "function_callers",
    "function_callees",
    "function_instruction_count",
    "pseudocode",
    "disassembly",
    "strings",
    "imports",
    "exports",
    "segments",
    "read_bytes",
    "pointers",
    "capabilities",
    "function_instructions",
    "function_xrefs",
    "function_cfg",
    "string_xrefs",
    "names",
    "data_items",
    "comments",
    "types",
    "release_decompiler_cache",
)


def _write_heartbeat(path: Path | None, launch_id: str | None, **status: Any) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "launch_id": launch_id,
        "pid": os.getpid(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **status,
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _runtime_identity(adapter: IdaDomainAdapter, ida_dir: Path) -> dict[str, Any]:
    versions = runtime_versions(ida_dir)
    versions["ida_version"] = ida_runtime_version()
    capabilities = {
        name: callable(getattr(adapter, name, None)) for name in _ADAPTER_CAPABILITIES
    }
    provider = getattr(adapter, "capabilities", None)
    if callable(provider):
        try:
            reported = provider()
            # Keep the value safe to place in the launcher-to-exporter JSON
            # boundary even when a backend returns a custom mapping object.
            try:
                json.dumps(reported)
            except (TypeError, ValueError):
                reported = repr(reported)
            capabilities["adapter_reported"] = reported
        except Exception as exc:
            capabilities["adapter_reported_error"] = type(exc).__name__
    policy = {
        name: value
        for name, value in vars(exporter).items()
        if name.isupper() and isinstance(value, (bool, float, int, str, type(None)))
    }
    return {
        **versions,
        "backend": "idalib",
        "runtime_fingerprint": stable_fingerprint(versions),
        "capability_fingerprint": stable_fingerprint(capabilities),
        "policy_fingerprint": stable_fingerprint(policy),
    }


def main() -> int:
    input_value = os.environ.get("IDA_EXPORT_CLI_INPUT")
    staging_value = os.environ.get("IDA_EXPORT_CLI_STAGING")
    work_value = os.environ.get("IDA_EXPORT_CLI_WORK")
    heartbeat_value = os.environ.get("IDA_EXPORT_CLI_HEARTBEAT")
    launch_id = os.environ.get("IDA_EXPORT_CLI_LAUNCH_ID")
    if not input_value or not staging_value:
        print("ida-export-cli worker: missing private launch environment", file=sys.stderr)
        return 2
    input_path = Path(input_value).resolve()
    staging = Path(staging_value).resolve()
    heartbeat = Path(heartbeat_value).resolve() if heartbeat_value else None
    ida_dir = Path(os.environ["IDADIR"]).resolve()
    _write_heartbeat(heartbeat, launch_id, phase="worker_start")
    try:
        with IdaDomainAdapter(input_path) as adapter:
            runtime_identity = _runtime_identity(adapter, ida_dir)
            os.environ["IDA_EXPORT_CLI_RUNTIME_IDENTITY"] = json.dumps(
                runtime_identity, sort_keys=True, separators=(",", ":")
            )
            _write_heartbeat(
                heartbeat,
                launch_id,
                phase="database_opened",
                runtime_fingerprint=runtime_identity["runtime_fingerprint"],
            )
            exporter.export_snapshot(
                adapter,
                input_path,
                staging,
                Path(work_value) if work_value else None,
                write_complete_marker=False,
            )
    except Exception as exc:
        _write_heartbeat(
            heartbeat,
            launch_id,
            phase="failed",
            error_type=type(exc).__name__,
        )
        print(f"ida-export-cli worker: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _write_heartbeat(heartbeat, launch_id, phase="complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
