from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from version import __version__


SCHEMA_VERSION = 3
MEMORY_CHUNK_SIZE = 1024 * 1024
MEMORY_BYTES_PER_LINE = 16
MAX_FUNC_SIZE_FOR_DECOMPILE = 16 * 1024
MAX_FUNC_INSN_COUNT = 3000
PROGRESS_COMPACT_INTERVAL = 256
DECOMPILER_CACHE_RELEASE_INTERVAL = 250
SLOW_FUNCTION_SECONDS = 15

_SNAPSHOT_DIRECTORIES = ("functions", "instructions", "cfg", "memory")
_SNAPSHOT_FILES = (
    "COMPLETE",
    "manifest.json",
    "function_index.jsonl",
    "callgraph.jsonl",
    "function_fallbacks.jsonl",
    "function_failures.jsonl",
    "function_skipped.jsonl",
    "xrefs.jsonl",
    "string_xrefs.jsonl",
    "names.jsonl",
    "data.jsonl",
    "comments.jsonl",
    "types.jsonl",
    "strings.jsonl",
    "pointers.jsonl",
    "imports.json",
    "exports.json",
    "memory_index.jsonl",
    "segments.json",
)


def _write_export_heartbeat(
    path: Path | None, launch_id: str | None, **status: Any
) -> None:
    """Publish exporter progress for the launcher watchdog."""
    if path is None:
        return
    payload = {
        "launch_id": launch_id,
        "pid": os.getpid(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **status,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as stream:
            temporary_name = stream.name
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(10):
            try:
                os.replace(temporary_name, path)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


class AnalysisAdapter(Protocol):
    def metadata(self) -> dict[str, Any]: ...
    def functions(self) -> Any: ...
    def function_name(self, function: Any) -> str: ...
    def function_signature(self, function: Any) -> str | None: ...
    def function_flags(self, function: Any) -> list[str]: ...
    def function_skip_reason(self, function: Any) -> str | None: ...
    def function_callers(self, function: Any) -> list[dict[str, Any]]: ...
    def function_callees(self, function: Any) -> list[dict[str, Any]]: ...
    def pseudocode(self, function: Any) -> str: ...
    def function_instruction_count(self, function: Any, limit: int | None = None) -> int: ...
    def disassembly(self, function: Any) -> list[str]: ...
    def strings(self) -> Any: ...
    def imports(self) -> Any: ...
    def exports(self) -> Any: ...
    def segments(self) -> Any: ...
    def segment_name(self, segment: Any) -> str: ...
    def segment_class(self, segment: Any) -> str | None: ...
    def segment_permissions(self, segment: Any) -> dict[str, Any]: ...
    def segment_bitness(self, segment: Any) -> int: ...
    def read_bytes(self, ea: int, size: int) -> bytes: ...
    def pointers(self) -> Any: ...
    def capabilities(self) -> dict[str, Any]: ...
    def function_instructions(self, function: Any) -> Any: ...
    def function_xrefs(self, function: Any) -> Any: ...
    def function_cfg(self, function: Any) -> dict[str, Any]: ...
    def string_xrefs(self) -> Any: ...
    def names(self) -> Any: ...
    def data_items(self) -> Any: ...
    def comments(self) -> Any: ...
    def types(self) -> Any: ...


def _atomic_write_bytes(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as stream:
            temporary_name = stream.name
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    return _bytes_sha256(data)


class _ArtifactWriter:
    """Write published artifacts through a same-directory atomic replace."""

    def __init__(self, root: Path | None = None):
        self.root = root

    def _path(self, path: Path | str) -> Path:
        candidate = Path(path)
        if self.root is None:
            return candidate
        root = self.root.resolve()
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            if ".." in candidate.parts:
                raise ValueError(f"artifact path escapes root: {path}")
            resolved = (root / candidate).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"artifact path escapes root: {path}") from exc
        return resolved

    def write_bytes(self, path: Path | str, data: bytes) -> str:
        return _atomic_write_bytes(self._path(path), data)

    def write_text(self, path: Path | str, value: str) -> str:
        return self.write_bytes(path, value.encode("utf-8"))

    def write_json(self, path: Path | str, value: Any) -> str:
        return self.write_text(
            path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        )

    def write_jsonl(self, path: Path | str, values: Any) -> tuple[int, str]:
        destination = self._path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_name: str | None = None
        count = 0
        digest = hashlib.sha256()
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=destination.parent, prefix=f".{destination.name}.",
                suffix=".tmp", delete=False
            ) as stream:
                temporary_name = stream.name
                for value in values:
                    line = (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode(
                        "utf-8"
                    )
                    stream.write(line)
                    digest.update(line)
                    count += 1
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
        finally:
            if temporary_name:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
        return count, digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    _ArtifactWriter().write_json(path, value)


def _remove_stale_snapshot_artifacts(output: Path) -> None:
    """Remove only artifacts owned by this exporter before a full rebuild."""
    for relative in (*_SNAPSHOT_DIRECTORIES, *_SNAPSHOT_FILES):
        path = output / relative
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)


class _ExportState:
    """Small crash-resilient state store for one input sample."""

    def __init__(
        self,
        root: Path,
        input_path: Path,
        identity_details: dict[str, Any] | None = None,
        output: Path | None = None,
    ):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.progress_path = root / "progress.json"
        self.progress_journal_path = root / "progress.jsonl"
        self.current_path = root / "currently_processing.json"
        self.blacklist_path = root / "decompile_blacklist.json"
        self.completed: dict[str, dict[str, Any]] = {}
        self.blacklist: set[str] = set()
        self.retries: set[str] = set()
        self.stages: dict[str, dict[str, Any]] = {}
        self.memory_completed: dict[str, dict[str, Any]] = {}
        self._events_since_compact = 0
        self._previous_identity: dict[str, Any] | None = None
        if self.progress_path.is_file():
            try:
                value = json.loads(self.progress_path.read_text(encoding="utf-8"))
                self.completed = dict(value.get("completed", {}))
                self.stages = dict(value.get("stages", {}))
                self.memory_completed = dict(value.get("memory_chunks", {}))
            except (OSError, ValueError, TypeError):
                self.completed = {}
        if self.progress_journal_path.is_file():
            self._load_journal()
        if self.blacklist_path.is_file():
            try:
                value = json.loads(self.blacklist_path.read_text(encoding="utf-8"))
                self.blacklist = {str(item) for item in value.get("addresses", [])}
            except (OSError, ValueError, TypeError):
                self.blacklist = set()
        # A worker that was terminated leaves this marker behind. Only an
        # interrupted Hex-Rays call is blacklisted; metadata, disassembly and
        # artifact-write interruptions are retried on the next invocation.
        if self.current_path.is_file():
            try:
                marker = json.loads(self.current_path.read_text(encoding="utf-8"))
                ea = str(marker["ea"])
                phase = str(marker.get("phase", "decompile"))
                if phase in {"decompile", "hexrays", "pseudocode"}:
                    self.blacklist.add(ea)
                    self._write_blacklist()
            except (OSError, ValueError, TypeError, KeyError):
                pass
            self.current_path.unlink(missing_ok=True)
        identity = {
            "input": str(input_path),
            "input_sha256": _sha256(input_path),
            "schema_version": SCHEMA_VERSION,
            "generator": __version__,
        }
        if identity_details:
            identity.update(identity_details)
        identity_path = root / "identity.json"
        if identity_path.is_file():
            try:
                existing = json.loads(identity_path.read_text(encoding="utf-8"))
                if isinstance(existing, dict):
                    self._previous_identity = existing
            except (OSError, ValueError, TypeError):
                self._previous_identity = None
        self.identity = identity
        if self._previous_identity is not None and self._previous_identity != identity:
            # A changed input or policy must never reuse artifacts from the
            # previous sample. Keep the old identity for diagnostics, clear
            # only exporter-owned snapshot artifacts, and start a new journal.
            _write_json(root / "identity.previous.json", self._previous_identity)
            if output is not None:
                _remove_stale_snapshot_artifacts(output)
            self.completed.clear()
            self.stages.clear()
            self.memory_completed.clear()
            self.retries.clear()
            self.blacklist.clear()
            self._write_blacklist()
            _atomic_write_bytes(self.progress_journal_path, b"")
            self.compact()
        _write_json(identity_path, identity)

    def _load_journal(self) -> None:
        try:
            with self.progress_journal_path.open(encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    try:
                        self._apply_event(json.loads(line))
                    except (ValueError, TypeError, KeyError):
                        # A partial final line from a terminated process is
                        # ignored; the compact snapshot remains usable.
                        continue
        except OSError:
            return

    def _apply_event(self, event: Any) -> None:
        if not isinstance(event, dict):
            return
        kind = event.get("event")
        if kind == "complete":
            key = str(event["ea"])
            value = event.get("value")
            if isinstance(value, dict):
                self.completed[key] = value
        elif kind == "invalidate":
            key = str(event["ea"])
            self.completed.pop(key, None)
            self.retries.add(key)
        elif kind == "stage":
            stage = str(event["stage"])
            self.stages[stage] = dict(event)
        elif kind == "memory_chunk":
            key = str(event["key"])
            record = event.get("record")
            if isinstance(record, dict):
                self.memory_completed[key] = record

    def _append_event(self, event: dict[str, Any], *, compact: bool = False) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self.progress_journal_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self._events_since_compact += 1
        if compact or self._events_since_compact >= PROGRESS_COMPACT_INTERVAL:
            self.compact()

    def compact(self) -> None:
        _write_json(
            self.progress_path,
            {
                "completed": self.completed,
                "stages": self.stages,
                "memory_chunks": self.memory_completed,
            },
        )
        self._events_since_compact = 0

    def _write_blacklist(self) -> None:
        _write_json(self.blacklist_path, {"addresses": sorted(self.blacklist)})

    def mark_processing(
        self, ea: int, name: str, position: int, phase: str = "metadata"
    ) -> None:
        value = {
            "ea": f"0x{ea:X}",
            "name": name,
            "position": position,
            "phase": phase,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            _write_json(self.current_path, value)
        except PermissionError:
            # Windows indexers can hold this frequently replaced crash marker
            # long enough to exhaust the atomic-replace retry window. The
            # marker is advisory, so an in-place fallback is sufficient.
            self.current_path.write_text(
                json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def clear_processing(self) -> None:
        self.current_path.unlink(missing_ok=True)

    def complete(self, ea: int, value: dict[str, Any]) -> None:
        key = f"0x{ea:X}"
        self.completed[key] = value
        self._append_event({"event": "complete", "ea": key, "value": value})

    def needs_no_cache(self, ea: int) -> bool:
        return f"0x{ea:X}" in self.retries

    def completed_value(
        self, ea: int, output: Path, expected_end_ea: int | None = None
    ) -> dict[str, Any] | None:
        key = f"0x{ea:X}"
        value = self.completed.get(key)
        if not isinstance(value, dict):
            return None
        if value.get("kind") == "skipped":
            return value
        record = value.get("record")
        if (
            expected_end_ea is not None
            and isinstance(record, dict)
            and record.get("end_ea") != f"0x{expected_end_ea:X}"
        ):
            self._discard_completed(key)
            return None
        artifacts = record.get("artifacts") if isinstance(record, dict) else None
        if not isinstance(artifacts, dict):
            self._discard_completed(key)
            return None
        hashes = value.get("artifact_sha256", {})
        for kind in ("pseudocode", "disassembly"):
            relative = artifacts.get(kind)
            if not isinstance(relative, str):
                self._discard_completed(key)
                return None
            artifact = output / relative
            if not artifact.is_file():
                self._discard_completed(key)
                return None
            expected = hashes.get(kind) if isinstance(hashes, dict) else None
            if isinstance(expected, str) and _sha256(artifact) != expected:
                self._discard_completed(key)
                return None
        return value

    def _discard_completed(self, key: str) -> None:
        self.completed.pop(key, None)
        self.retries.add(key)
        self._append_event({"event": "invalidate", "ea": key})

    def mark_stage(self, stage: str, status: str, **details: Any) -> None:
        event = {
            "event": "stage",
            "stage": stage,
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **details,
        }
        self.stages[stage] = event
        self._append_event(event)

    def stage_completed(self, stage: str, path: Path | None = None) -> bool:
        event = self.stages.get(stage)
        if not isinstance(event, dict) or event.get("status") != "complete":
            return False
        if path is None:
            return True
        if not path.is_file():
            return False
        expected = event.get("artifact_sha256")
        # Older work journals did not record a stage hash. They remain
        # readable, while all newly completed stages get corruption checks.
        return not isinstance(expected, str) or _sha256(path) == expected

    def checkpoint_memory_chunk(self, key: str, record: dict[str, Any]) -> None:
        self.memory_completed[key] = record
        self._append_event({"event": "memory_chunk", "key": key, "record": record})

    def memory_chunk(self, key: str, output: Path) -> dict[str, Any] | None:
        record = self.memory_completed.get(key)
        if not isinstance(record, dict):
            return None
        relative = record.get("artifact")
        expected = record.get("artifact_sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            return None
        artifact = output / relative
        if not artifact.is_file() or _sha256(artifact) != expected:
            self.memory_completed.pop(key, None)
            return None
        return record


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bytes_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_function_name(name: str, ea: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.@$-]+", "_", name).strip("._")
    cleaned = (cleaned or "sub")[:120]
    return f"{cleaned}__{ea:016X}"


def _header_value(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("*/", "* /")


def _relation_summary(relations: list[dict[str, Any]]) -> str:
    if not relations:
        return "none"
    return ", ".join(
        f"{item.get('ea', 'unknown')}:{_header_value(item.get('name') or 'unknown')}"
        for item in relations
    )


def _c_header(
    name: str,
    ea: int,
    callers: list[dict[str, Any]],
    callees: list[dict[str, Any]],
) -> str:
    return (
        "/*\n"
        f" * func-name: {_header_value(name)}\n"
        f" * func-address: 0x{ea:X}\n"
        f" * callers: {_relation_summary(callers)}\n"
        f" * callees: {_relation_summary(callees)}\n"
        " */\n\n"
    )


def _asm_header(
    name: str,
    ea: int,
    callers: list[dict[str, Any]],
    callees: list[dict[str, Any]],
) -> str:
    return (
        f"; func-name: {_header_value(name)}\n"
        f"; func-address: 0x{ea:X}\n"
        f"; callers: {_relation_summary(callers)}\n"
        f"; callees: {_relation_summary(callees)}\n\n"
    )


def _write_hexdump(
    path: Path,
    start_ea: int,
    end_ea: int,
    segment_name: str,
    data: bytes,
    writer: _ArtifactWriter | None = None,
) -> None:
    stream = io.StringIO()
    stream.write(f"# Memory dump: 0x{start_ea:X} - 0x{end_ea:X}\n")
    stream.write(f"# Segment: {segment_name}\n")
    stream.write("# Address          | Hex Bytes                                         | ASCII\n")
    stream.write("#" + "-" * 78 + "\n")
    for offset in range(0, len(data), MEMORY_BYTES_PER_LINE):
        line = data[offset : offset + MEMORY_BYTES_PER_LINE]
        left = " ".join(f"{value:02X}" for value in line[:8])
        right = " ".join(f"{value:02X}" for value in line[8:])
        hex_text = f"{left:<23}  {right:<23}"
        ascii_text = "".join(chr(value) if 0x20 <= value <= 0x7E else "." for value in line)
        stream.write(f"{start_ea + offset:016X} | {hex_text} | {ascii_text}\n")
    (writer or _ArtifactWriter()).write_text(path, stream.getvalue())


def _export_memory(
    adapter: AnalysisAdapter,
    output: Path,
    state: _ExportState | None = None,
    writer: _ArtifactWriter | None = None,
    heartbeat: Callable[..., None] | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    writer = writer or _ArtifactWriter(output)
    memory_dir = output / "memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    segment_records: list[dict[str, Any]] = []
    chunk_count = 0
    total_bytes = 0
    index_records: list[dict[str, Any]] = []

    for segment in adapter.segments():
        start_ea = int(segment.start_ea)
        end_ea = int(segment.end_ea)
        name = adapter.segment_name(segment) or f"seg_{start_ea:X}"
        segment_class = adapter.segment_class(segment)
        permissions = adapter.segment_permissions(segment)
        bitness = adapter.segment_bitness(segment)
        segment_chunk_count = 0
        segment_bytes = 0

        for chunk_start in range(start_ea, end_ea, MEMORY_CHUNK_SIZE):
            chunk_end = min(chunk_start + MEMORY_CHUNK_SIZE, end_ea)
            expected_size = chunk_end - chunk_start
            key = f"{start_ea:X}:{chunk_start:X}:{chunk_end:X}"
            record = state.memory_chunk(key, output) if state is not None else None
            if record is None:
                data = adapter.read_bytes(chunk_start, expected_size)
                if len(data) != expected_size:
                    raise RuntimeError(
                        f"short memory read at 0x{chunk_start:X}: "
                        f"expected {expected_size}, got {len(data)}"
                    )
                artifact = f"memory/{chunk_start:016X}--{chunk_end:016X}.txt"
                artifact_path = output / artifact
                _write_hexdump(artifact_path, chunk_start, chunk_end, name, data, writer)
                record = {
                    "segment": name,
                    "segment_class": segment_class,
                    "segment_start_ea": f"0x{start_ea:X}",
                    "segment_end_ea": f"0x{end_ea:X}",
                    "start_ea": f"0x{chunk_start:X}",
                    "end_ea": f"0x{chunk_end:X}",
                    "size": len(data),
                    "bitness": bitness,
                    "permissions": permissions,
                    "artifact": artifact,
                    "sha256": _bytes_sha256(data),
                    "artifact_sha256": _sha256(artifact_path),
                }
                if state is not None:
                    state.checkpoint_memory_chunk(key, record)
            index_records.append(record)
            chunk_count += 1
            total_bytes += int(record.get("size", expected_size))
            segment_chunk_count += 1
            segment_bytes += int(record.get("size", expected_size))
            if heartbeat is not None:
                heartbeat(
                    phase="memory_chunk",
                    segment=name,
                    chunk=chunk_count,
                    start_ea=f"0x{chunk_start:X}",
                    end_ea=f"0x{chunk_end:X}",
                )

        segment_records.append(
            {
                "name": name,
                "class": segment_class,
                "start_ea": f"0x{start_ea:X}",
                "end_ea": f"0x{end_ea:X}",
                "size": end_ea - start_ea,
                "bitness": bitness,
                "permissions": permissions,
                "memory_chunks": segment_chunk_count,
                "memory_bytes": segment_bytes,
            }
        )

    writer.write_jsonl("memory_index.jsonl", index_records)
    writer.write_json("segments.json", segment_records)
    return segment_records, chunk_count, total_bytes


def _jsonl_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open(encoding="utf-8") as stream:
        return sum(1 for line in stream if line.strip())


def _p2_function_exports(
    adapter: AnalysisAdapter,
    functions: list[Any],
    function_records: list[dict[str, Any]],
    callgraph_records: list[dict[str, Any]],
    writer: _ArtifactWriter,
    heartbeat: Callable[..., None] | None = None,
) -> tuple[int, int, int]:
    """Export structured instructions, per-function CFG and call-site xrefs.

    The adapter owns every IDA access. This function only normalizes DTOs and
    writes deterministic JSON artifacts, so it remains compatible with test
    adapters that expose only the original v2 API.
    """
    by_ea = {}
    for function in functions:
        try:
            by_ea[int(function.start_ea)] = function
        except Exception:
            continue
    records_by_ea = {
        int(record["ea"], 16): record
        for record in function_records
        if isinstance(record.get("ea"), str)
    }
    callgraph_by_ea = {
        int(record["ea"], 16): record
        for record in callgraph_records
        if isinstance(record.get("ea"), str)
    }
    instruction_method = getattr(adapter, "function_instructions", None)
    xref_method = getattr(adapter, "function_xrefs", None)
    cfg_method = getattr(adapter, "function_cfg", None)
    all_xrefs: dict[tuple[str | None, str | None, str], dict[str, Any]] = {}
    instruction_count = 0
    cfg_count = 0

    total_records = len(records_by_ea)
    for position, (ea, record) in enumerate(records_by_ea.items(), 1):
        function = by_ea.get(ea)
        safe_name = record.get("safe_name") or f"sub__{ea:016X}"
        instructions: list[dict[str, Any]] = []
        if callable(instruction_method) and function is not None:
            try:
                instructions = [value for value in instruction_method(function) if isinstance(value, dict)]
            except Exception as exc:
                instructions = [{"ea": None, "read_error": f"instructions {type(exc).__name__}: {exc}"}]
        else:
            instructions = [{"ea": None, "read_error": "adapter capability unavailable"}]
        instruction_path = f"instructions/{safe_name}.jsonl"
        _, instruction_sha = writer.write_jsonl(instruction_path, instructions)
        valid_instruction_count = sum(
            1 for value in instructions if value.get("ea") is not None
        )
        instruction_count += valid_instruction_count

        cfg: dict[str, Any]
        if callable(cfg_method) and function is not None:
            try:
                value = cfg_method(function)
                cfg = value if isinstance(value, dict) else {"blocks": [], "read_error": "invalid CFG DTO"}
            except Exception as exc:
                cfg = {"function_ea": record["ea"], "blocks": [], "read_error": f"cfg {type(exc).__name__}: {exc}"}
        else:
            cfg = {"function_ea": record["ea"], "blocks": [], "read_error": "adapter capability unavailable"}
        cfg_path = f"cfg/{safe_name}.json"
        cfg_sha = writer.write_json(cfg_path, cfg)
        if cfg.get("blocks"):
            cfg_count += 1
        record.setdefault("artifacts", {})["instructions"] = instruction_path
        record["artifacts"]["cfg"] = cfg_path
        record.setdefault("artifact_hashes", {})["instructions"] = instruction_sha
        record["artifact_hashes"]["cfg"] = cfg_sha
        record["structured_instruction_count"] = valid_instruction_count

        function_xrefs: list[dict[str, Any]] = []
        if callable(xref_method) and function is not None:
            try:
                function_xrefs = [value for value in xref_method(function) if isinstance(value, dict)]
            except Exception as exc:
                function_xrefs = [{
                    "source_ea": None,
                    "target_ea": None,
                    "source_function_ea": record["ea"],
                    "xref_type": "UNKNOWN",
                    "read_error": f"xrefs {type(exc).__name__}: {exc}",
                }]
        call_sites = []
        for xref in function_xrefs:
            if _is_ordinary_flow_xref(xref):
                continue
            xref_type = xref.get(
                "xref_type", xref.get("xref_type_value", xref.get("type", "UNKNOWN"))
            )
            if "xref_type" not in xref:
                xref = {**xref, "xref_type": xref_type}
            key = (xref.get("source_ea"), xref.get("target_ea"), str(xref_type))
            all_xrefs[key] = xref
            if str(xref_type).upper().startswith("CALL"):
                call_sites.append(xref)
        record["call_site_count"] = len(call_sites)
        callgraph = callgraph_by_ea.get(ea)
        if callgraph is not None:
            callgraph["call_sites"] = sorted(
                call_sites,
                key=lambda value: str(value.get("source_ea", "")),
            )
        if heartbeat is not None:
            heartbeat(
                phase="p2_function_progress",
                completed_functions=position,
                total_functions=total_records,
            )

    xref_rows = sorted(
        all_xrefs.values(),
        key=lambda value: (
            str(value.get("source_ea", "")),
            str(value.get("target_ea", "")),
            str(value.get("xref_type", "")),
        ),
    )
    writer.write_jsonl("xrefs.jsonl", xref_rows)
    return instruction_count, len(xref_rows), cfg_count


def _is_ordinary_flow_xref(xref: dict[str, Any]) -> bool:
    """Recognize IDA's ordinary-flow xref across enum, string and numeric DTOs."""
    if xref.get("read_error"):
        return False
    for key in ("xref_type", "xref_type_value", "type"):
        value = xref.get(key)
        if value is None or isinstance(value, bool):
            continue
        name = getattr(value, "name", None)
        text = str(name if name is not None else value).strip().upper()
        if text.endswith(".ORDINARY_FLOW") or text in {"ORDINARY_FLOW", "FL_F"}:
            return True
        try:
            if int(text, 0) == 0x15:
                return True
        except ValueError:
            continue
    return False


def _p2_global_stage(
    adapter: AnalysisAdapter,
    state: _ExportState,
    writer: _ArtifactWriter,
    stage: str,
    filename: str,
    method_name: str,
    heartbeat: Callable[..., None] | None = None,
) -> int:
    path = writer._path(filename)
    if state.stage_completed(stage, path):
        count = _jsonl_count(path)
        if heartbeat is not None:
            heartbeat(phase=f"{stage}_complete", count=count, resumed=True)
        return count
    state.mark_stage(stage, "running")
    if heartbeat is not None:
        heartbeat(phase=f"{stage}_start")
    source = getattr(adapter, method_name, None)
    values = source() if callable(source) else ()
    count, artifact_sha256 = writer.write_jsonl(filename, values)
    state.mark_stage(
        stage,
        "complete",
        artifact=filename,
        artifact_sha256=artifact_sha256,
        count=count,
    )
    if heartbeat is not None:
        heartbeat(phase=f"{stage}_complete", count=count)
    return count


def _artifact_inventory(root: Path) -> dict[str, Any]:
    records = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in {"manifest.json", "COMPLETE", "task.log"}:
            continue
        if any(part.startswith(".ida-export-state") for part in path.relative_to(root).parts):
            continue
        size = path.stat().st_size
        records.append({"path": relative, "size": size, "sha256": _sha256(path)})
        total_bytes += size
    payload = "".join(
        json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    ).encode("utf-8")
    return {
        "files": len(records),
        "bytes": total_bytes,
        "inventory_sha256": _bytes_sha256(payload),
    }


def export_snapshot(
    adapter: AnalysisAdapter,
    input_path: Path,
    output: Path,
    work_dir: Path | None = None,
    *,
    write_complete_marker: bool = True,
) -> None:
    started = datetime.now(timezone.utc)
    writer = _ArtifactWriter(output)
    heartbeat_path_value = os.environ.get("IDA_EXPORT_CLI_HEARTBEAT")
    heartbeat_path = Path(heartbeat_path_value) if heartbeat_path_value else None
    launch_id = os.environ.get("IDA_EXPORT_CLI_LAUNCH_ID")

    def heartbeat(**status: Any) -> None:
        _write_export_heartbeat(heartbeat_path, launch_id, **status)

    functions_dir = output / "functions"
    functions_dir.mkdir(parents=True, exist_ok=True)
    (output / "task.log").touch(exist_ok=True)
    functions = list(adapter.functions())
    total_function_count = len(functions)
    function_records: list[dict[str, Any]] = []
    callgraph_records: list[dict[str, Any]] = []
    fallback_records: list[dict[str, Any]] = []
    failure_records: list[dict[str, Any]] = []
    skipped_records: list[dict[str, Any]] = []
    identity_details: dict[str, Any] | None = None
    runtime_identity = os.environ.get("IDA_EXPORT_CLI_RUNTIME_IDENTITY")
    if runtime_identity:
        try:
            value = json.loads(runtime_identity)
            if isinstance(value, dict):
                identity_details = value
        except (TypeError, ValueError):
            # Runtime identity is an optimization for state invalidation; a
            # malformed optional value must not prevent the export itself.
            identity_details = None
    state = _ExportState(
        work_dir or (output / ".ida-export-state"),
        input_path,
        identity_details=identity_details,
        output=output,
    )
    heartbeat(phase="export_start", total_functions=total_function_count)
    function_phase_started = time.monotonic()
    try:
        pseudocode_parameters = inspect.signature(adapter.pseudocode).parameters.values()
        pseudocode_supports_no_cache = any(
            parameter.name == "no_cache"
            or parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in pseudocode_parameters
        )
    except (TypeError, ValueError):
        pseudocode_supports_no_cache = False

    def report_function_progress() -> None:
        elapsed = max(time.monotonic() - function_phase_started, 0.001)
        rate = position / elapsed
        remaining = max(total_function_count - position, 0)
        heartbeat(
            phase="function_progress",
            completed_functions=position,
            total_functions=total_function_count,
            functions_per_second=round(rate, 3),
            eta_seconds=round(remaining / rate, 3) if rate else None,
        )

    def restore_completed(value: dict[str, Any]) -> None:
        kind = value.get("kind")
        if kind == "skipped":
            skipped_records.append(value["record"])
            return
        record = value.get("record")
        if not isinstance(record, dict):
            return
        function_records.append(record)
        callgraph_records.append(value.get("callgraph", {
            "ea": record.get("ea"), "name": record.get("name"),
            "callers": record.get("callers", []), "callees": record.get("callees", []),
        }))
        if value.get("fallback"):
            fallback_records.append(value["fallback"])
        if value.get("failure"):
            failure_records.append(value["failure"])

    for position, function in enumerate(functions, 1):
        if position > 1 and (position - 1) % DECOMPILER_CACHE_RELEASE_INTERVAL == 0:
            release_cache = getattr(adapter, "release_decompiler_cache", None)
            if callable(release_cache):
                try:
                    release_cache()
                except Exception as exc:
                    print(
                        f"ida-export-cli: decompiler cache cleanup warning: {type(exc).__name__}: {exc}",
                        flush=True,
                    )
        try:
            ea = int(function.start_ea)
            end_ea = int(function.end_ea)
        except Exception as exc:
            skipped_records.append(
                {
                    "ea": None,
                    "name": None,
                    "reason": f"invalid function object: {type(exc).__name__}: {exc}",
                }
            )
            if position % 100 == 0:
                print(f"ida-export-cli: functions {position}/{total_function_count}", flush=True)
                report_function_progress()
            continue

        previous_completion = state.completed.get(f"0x{ea:X}")
        completed_value = state.completed_value(ea, output, end_ea)
        retry_no_cache = completed_value is None and isinstance(previous_completion, dict)
        if completed_value is not None:
            restore_completed(completed_value)
            if position % 100 == 0:
                print(f"ida-export-cli: functions {position}/{total_function_count}", flush=True)
                report_function_progress()
            continue

        function_started = time.monotonic()
        analysis_errors = []
        try:
            name = adapter.function_name(function) or f"sub_{ea:X}"
        except Exception as exc:
            name = f"sub_{ea:X}"
            analysis_errors.append(f"function_name {type(exc).__name__}: {exc}")

        skip_reason = "invalid address range" if end_ea <= ea else None
        if skip_reason is None:
            try:
                skip_reason = adapter.function_skip_reason(function)
            except Exception as exc:
                skip_reason = f"function validation failed: {type(exc).__name__}: {exc}"
        if skip_reason:
            skipped_records.append(
                {"ea": f"0x{ea:X}", "name": name, "reason": skip_reason}
            )
            state.complete(ea, {"kind": "skipped", "record": skipped_records[-1]})
            if position % 100 == 0:
                print(f"ida-export-cli: functions {position}/{total_function_count}", flush=True)
                report_function_progress()
            continue

        # Mark before any remaining IDA calls.  A process-level interruption
        # during metadata/xref collection must be recoverable as well.
        state.mark_processing(ea, name, position, "metadata")
        try:
            signature = adapter.function_signature(function)
        except Exception as exc:
            signature = None
            analysis_errors.append(f"function_signature {type(exc).__name__}: {exc}")
        try:
            flags = adapter.function_flags(function)
        except Exception as exc:
            flags = []
            analysis_errors.append(f"function_flags {type(exc).__name__}: {exc}")
        try:
            callers = adapter.function_callers(function)
        except Exception as exc:
            callers = []
            analysis_errors.append(f"function_callers {type(exc).__name__}: {exc}")
        try:
            callees = adapter.function_callees(function)
        except Exception as exc:
            callees = []
            analysis_errors.append(f"function_callees {type(exc).__name__}: {exc}")

        decompile_error = None
        disassembly_error = None
        fallback_reason = None
        decompile_duration_ms: int | None = None
        function_size = end_ea - ea
        instruction_count: int | None = None
        if function_size > MAX_FUNC_SIZE_FOR_DECOMPILE:
            fallback_reason = (
                f"function too large ({function_size} bytes, limit "
                f"{MAX_FUNC_SIZE_FOR_DECOMPILE} bytes)"
            )
        elif f"0x{ea:X}" in state.blacklist:
            fallback_reason = "in crash/hang blacklist"
        else:
            try:
                counter = getattr(adapter, "function_instruction_count", None)
                if counter is not None:
                    instruction_count = int(counter(function, MAX_FUNC_INSN_COUNT + 1))
                    if instruction_count > MAX_FUNC_INSN_COUNT:
                        fallback_reason = (
                            f"too many instructions (>{MAX_FUNC_INSN_COUNT}, limit "
                            f"{MAX_FUNC_INSN_COUNT})"
                        )
            except Exception as exc:
                analysis_errors.append(f"instruction_count {type(exc).__name__}: {exc}")

        try:
            if fallback_reason:
                raise RuntimeError(fallback_reason)
            state.mark_processing(ea, name, position, "decompile")
            decompile_started = time.monotonic()
            try:
                if pseudocode_supports_no_cache:
                    pseudocode_body = adapter.pseudocode(
                        function, no_cache=retry_no_cache or state.needs_no_cache(ea)
                    ).rstrip() + "\n"
                else:
                    pseudocode_body = adapter.pseudocode(function).rstrip() + "\n"
            finally:
                decompile_duration_ms = round(
                    (time.monotonic() - decompile_started) * 1000
                )
        except Exception as exc:
            decompile_error = f"{type(exc).__name__}: {exc}"
            pseudocode_body = f"/* decompilation failed: {decompile_error} */\n"
        state.mark_processing(ea, name, position, "disassembly")
        try:
            asm = adapter.disassembly(function)
            if not asm:
                raise RuntimeError("function has no disassembly lines")
            disassembly_body = "\n".join(asm).rstrip() + "\n"
        except Exception as exc:
            disassembly_error = f"{type(exc).__name__}: {exc}"
            disassembly_body = f"; disassembly failed: {disassembly_error}\n"

        safe_name = _safe_function_name(name, ea)
        pseudocode_artifact = f"functions/{safe_name}.c"
        disassembly_artifact = f"functions/{safe_name}.asm"
        state.mark_processing(ea, name, position, "artifact_write")
        pseudocode_sha256 = writer.write_text(
            pseudocode_artifact, _c_header(name, ea, callers, callees) + pseudocode_body
        )
        disassembly_sha256 = writer.write_text(
            disassembly_artifact, _asm_header(name, ea, callers, callees) + disassembly_body
        )

        kind = "c" if decompile_error is None else "asm"
        artifact = pseudocode_artifact if kind == "c" else disassembly_artifact
        record = {
            "ea": f"0x{ea:X}",
            "end_ea": f"0x{end_ea:X}",
            "size": function_size,
            "instruction_count": instruction_count,
            "duration_ms": round((time.monotonic() - function_started) * 1000),
            "decompile_duration_ms": decompile_duration_ms,
            "slow": bool(
                decompile_duration_ms is not None
                and decompile_duration_ms >= SLOW_FUNCTION_SECONDS * 1000
            ),
            "name": name,
            "safe_name": safe_name,
            "signature": signature,
            "flags": flags,
            "callers": callers,
            "callees": callees,
            "kind": kind,
            "artifact": artifact,
            "artifacts": {
                "pseudocode": pseudocode_artifact,
                "disassembly": disassembly_artifact,
            },
            "artifact_hashes": {
                "pseudocode": pseudocode_sha256,
                "disassembly": disassembly_sha256,
            },
        }
        if analysis_errors:
            record["analysis_errors"] = analysis_errors
        if decompile_error:
            record["decompile_error"] = decompile_error
        if disassembly_error:
            record["disassembly_error"] = disassembly_error
        function_records.append(record)
        callgraph = {"ea": f"0x{ea:X}", "name": name, "callers": callers, "callees": callees}
        callgraph_records.append(callgraph)
        completion: dict[str, Any] = {
            "kind": "function",
            "record": record,
            "callgraph": callgraph,
            "artifact_sha256": {
                "pseudocode": pseudocode_sha256,
                "disassembly": disassembly_sha256,
            },
        }
        if decompile_error and not disassembly_error:
            fallback_records.append(
                {
                    "ea": f"0x{ea:X}",
                    "name": name,
                    "reason": decompile_error,
                    "artifact": disassembly_artifact,
                }
            )
            completion["fallback"] = fallback_records[-1]
        if disassembly_error:
            failure_records.append(
                {
                    "ea": f"0x{ea:X}",
                    "name": name,
                    "decompile_error": decompile_error,
                    "disassembly_error": disassembly_error,
                }
            )
            completion["failure"] = failure_records[-1]
        state.complete(ea, completion)
        state.clear_processing()
        if position % 100 == 0:
            print(f"ida-export-cli: functions {position}/{total_function_count}", flush=True)
            report_function_progress()

    release_cache = getattr(adapter, "release_decompiler_cache", None)
    if callable(release_cache):
        try:
            release_cache()
        except Exception as exc:
            print(
                f"ida-export-cli: final decompiler cache cleanup warning: {type(exc).__name__}: {exc}",
                flush=True,
            )

    structured_instruction_count, xref_count, cfg_count = _p2_function_exports(
        adapter,
        functions,
        function_records,
        callgraph_records,
        writer,
        heartbeat=heartbeat,
    )
    function_count, _ = writer.write_jsonl("function_index.jsonl", function_records)
    writer.write_jsonl("callgraph.jsonl", callgraph_records)
    writer.write_jsonl("function_fallbacks.jsonl", fallback_records)
    writer.write_jsonl("function_failures.jsonl", failure_records)
    writer.write_jsonl("function_skipped.jsonl", skipped_records)
    state.mark_stage("functions", "complete", count=function_count)
    heartbeat(phase="functions_complete", count=function_count)

    # P2 global relation and semantic records. The files are emitted even for
    # a compatibility adapter; the manifest capabilities identify which
    # records came from structured IDA APIs.
    string_xref_count = _p2_global_stage(
        adapter, state, writer, "string_xrefs", "string_xrefs.jsonl", "string_xrefs",
        heartbeat=heartbeat,
    )
    names_count = _p2_global_stage(
        adapter, state, writer, "names", "names.jsonl", "names", heartbeat=heartbeat
    )
    data_count = _p2_global_stage(
        adapter, state, writer, "data", "data.jsonl", "data_items", heartbeat=heartbeat
    )
    comment_count = _p2_global_stage(
        adapter, state, writer, "comments", "comments.jsonl", "comments",
        heartbeat=heartbeat,
    )
    type_count = _p2_global_stage(
        adapter, state, writer, "types", "types.jsonl", "types", heartbeat=heartbeat
    )

    def export_jsonl_stage(stage: str, filename: str, source_factory: Any) -> int:
        path = output / filename
        if state.stage_completed(stage, path):
            heartbeat(phase=f"{stage}_complete", count=_jsonl_count(path), resumed=True)
            return _jsonl_count(path)
        state.mark_stage(stage, "running")
        heartbeat(phase=f"{stage}_start")
        count, artifact_sha256 = writer.write_jsonl(filename, source_factory())
        state.mark_stage(
            stage,
            "complete",
            artifact=filename,
            artifact_sha256=artifact_sha256,
            count=count,
        )
        heartbeat(phase=f"{stage}_complete", count=count)
        return count

    string_count = export_jsonl_stage("strings", "strings.jsonl", adapter.strings)
    pointer_source = getattr(adapter, "pointers", None)
    pointer_count = export_jsonl_stage(
        "pointers", "pointers.jsonl", pointer_source or (lambda: ())
    )

    if state.stage_completed("imports", output / "imports.json"):
        imports = json.loads((output / "imports.json").read_text(encoding="utf-8"))
        heartbeat(phase="imports_complete", count=len(imports), resumed=True)
    else:
        state.mark_stage("imports", "running")
        heartbeat(phase="imports_start")
        imports = list(adapter.imports())
        artifact_sha256 = writer.write_json("imports.json", imports)
        state.mark_stage(
            "imports",
            "complete",
            artifact="imports.json",
            artifact_sha256=artifact_sha256,
            count=len(imports),
        )
        heartbeat(phase="imports_complete", count=len(imports))
    if state.stage_completed("exports", output / "exports.json"):
        exports = json.loads((output / "exports.json").read_text(encoding="utf-8"))
        heartbeat(phase="exports_complete", count=len(exports), resumed=True)
    else:
        state.mark_stage("exports", "running")
        heartbeat(phase="exports_start")
        exports = list(adapter.exports())
        artifact_sha256 = writer.write_json("exports.json", exports)
        state.mark_stage(
            "exports",
            "complete",
            artifact="exports.json",
            artifact_sha256=artifact_sha256,
            count=len(exports),
        )
        heartbeat(phase="exports_complete", count=len(exports))

    state.mark_stage("memory", "running")
    heartbeat(phase="memory_start")
    segments, memory_chunk_count, memory_byte_count = _export_memory(
        adapter, output, state=state, writer=writer, heartbeat=heartbeat
    )
    state.mark_stage(
        "memory", "complete", chunks=memory_chunk_count, bytes=memory_byte_count
    )
    heartbeat(
        phase="memory_complete", chunks=memory_chunk_count, bytes=memory_byte_count
    )
    decompiled_count = sum(1 for item in function_records if "decompile_error" not in item)
    disassembled_count = sum(1 for item in function_records if "disassembly_error" not in item)
    successful_count = sum(
        1
        for item in function_records
        if "decompile_error" not in item and "disassembly_error" not in item
    )
    hard_failed_count = sum(
        1
        for item in function_records
        if "decompile_error" in item and "disassembly_error" in item
    )
    call_edge_count = sum(len(item["callees"]) for item in callgraph_records)
    finished = datetime.now(timezone.utc)
    state.mark_stage("manifest", "running")
    heartbeat(phase="manifest_start")
    database_metadata = adapter.metadata()
    final_input_sha256 = _sha256(input_path)
    if final_input_sha256 != state.identity.get("input_sha256"):
        raise RuntimeError("input changed while IDA analysis was running")
    capability_report = {}
    capability_method = getattr(adapter, "capabilities", None)
    if callable(capability_method):
        try:
            value = capability_method()
            if isinstance(value, dict):
                capability_report = value
        except Exception as exc:
            capability_report = {"read_error": f"capabilities {type(exc).__name__}: {exc}"}
    capabilities = [
        name
        for name, method_name in (
            ("instructions", "function_instructions"),
            ("xrefs", "function_xrefs"),
            ("cfg", "function_cfg"),
            ("string_xrefs", "string_xrefs"),
            ("names", "names"),
            ("data", "data_items"),
            ("comments", "comments"),
            ("types", "types"),
        )
        if callable(getattr(adapter, method_name, None))
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "compatibility": {"minimum_reader": 2},
        "capabilities": capabilities,
        "generator": {"name": "ida-export-cli", "version": __version__},
        "backend": "idalib",
        "api": "ida-domain",
        "runtime": capability_report,
        "status": "complete",
        "artifacts": _artifact_inventory(output),
        "input": {
            "path": str(input_path),
            "size": input_path.stat().st_size,
            "sha256": final_input_sha256,
        },
        "database": database_metadata,
        "counts": {
            "total_functions": total_function_count,
            "functions": function_count,
            "successful": successful_count,
            "exported": disassembled_count,
            "decompiled": decompiled_count,
            "assembly": function_count,
            "disassembled": disassembled_count,
            "fallbacks": len(fallback_records),
            "skipped": len(skipped_records),
            "failed": len(failure_records),
            "hard_failed": hard_failed_count,
            "decompile_failed": function_count - decompiled_count,
            "disassembly_failed": function_count - disassembled_count,
            "call_edges": call_edge_count,
            "instructions": structured_instruction_count,
            "xrefs": xref_count,
            "cfg_functions": cfg_count,
            "string_xrefs": string_xref_count,
            "names": names_count,
            "data": data_count,
            "comments": comment_count,
            "types": type_count,
            "strings": string_count,
            "pointers": pointer_count,
            "imports": len(imports),
            "exports": len(exports),
            "segments": len(segments),
            "memory_chunks": memory_chunk_count,
            "memory_bytes": memory_byte_count,
        },
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": round((finished - started).total_seconds(), 3),
    }
    writer.write_json("manifest.json", manifest)
    print(
        "ida-export-cli: summary "
        f"total={total_function_count} successful={successful_count} "
        f"exported={disassembled_count} fallbacks={len(fallback_records)} "
        f"skipped={len(skipped_records)} failed={len(failure_records)} "
        f"memory_bytes={memory_byte_count} memory_files={memory_chunk_count}",
        flush=True,
    )
    if write_complete_marker:
        writer.write_text("COMPLETE", f"schema={SCHEMA_VERSION}\n")
    state.mark_stage("manifest", "complete")
    state.compact()
    heartbeat(phase="export_complete", total_functions=total_function_count)
