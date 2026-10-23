from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from pathlib import PurePosixPath


REQUIRED_FILES = (
    "manifest.json",
    "COMPLETE",
    "function_index.jsonl",
    "callgraph.jsonl",
    "function_fallbacks.jsonl",
    "function_failures.jsonl",
    "function_skipped.jsonl",
    "strings.jsonl",
    "pointers.jsonl",
    "imports.json",
    "exports.json",
    "segments.json",
    "memory_index.jsonl",
    "task.log",
)
SCHEMA_V2 = 2
SCHEMA_V3 = 3
V3_FILES = (
    "xrefs.jsonl",
    "string_xrefs.jsonl",
    "names.jsonl",
    "data.jsonl",
    "comments.jsonl",
    "types.jsonl",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_jsonl(path: Path, label: str) -> Iterator[tuple[int, dict]]:
    """Yield validated JSON objects with their physical source line number."""
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"invalid {label} JSON at line {line_number}") from exc
            if not isinstance(record, dict):
                raise RuntimeError(f"invalid {label} record at line {line_number}")
            yield line_number, record


def _jsonl_count(path: Path, label: str = "JSONL") -> int:
    return sum(1 for _line_number, _record in _iter_jsonl(path, label))


def _artifact_path(root: Path, value: object, prefix: str, label: str) -> Path:
    if not isinstance(value, str):
        raise RuntimeError(f"invalid {label} artifact path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or not value.startswith(f"{prefix}/"):
        raise RuntimeError(f"invalid {label} artifact path: {value}")
    root_resolved = root.resolve()
    candidate = (root / Path(*relative.parts)).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise RuntimeError(f"artifact path escapes snapshot: {value}") from exc
    return candidate


def _validate_json_array(path: Path, label: str) -> list:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"invalid {label} JSON") from exc
    if not isinstance(value, list):
        raise RuntimeError(f"{label} must contain an array")
    return value


def _artifact_inventory(root: Path) -> dict[str, int | str]:
    digest = hashlib.sha256()
    file_count = 0
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
        record = {"path": relative, "size": size, "sha256": _sha256(path)}
        digest.update(
            (
                json.dumps(
                    record, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ).encode("utf-8")
        )
        file_count += 1
        total_bytes += size
    return {
        "files": file_count,
        "bytes": total_bytes,
        "inventory_sha256": digest.hexdigest(),
    }


def validate_export(root: Path, *, require_complete: bool = True) -> None:
    required = REQUIRED_FILES if require_complete else tuple(
        name for name in REQUIRED_FILES if name != "COMPLETE"
    )
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise RuntimeError(f"worker output is incomplete; missing: {', '.join(missing)}")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    schema_version = manifest.get("schema_version")
    if schema_version not in {SCHEMA_V2, SCHEMA_V3}:
        raise RuntimeError("unsupported worker output schema")
    if manifest.get("status") != "complete":
        raise RuntimeError("worker manifest is not complete")
    if require_complete:
        complete_text = (root / "COMPLETE").read_text(
            encoding="ascii", errors="replace"
        ).strip()
        if complete_text != f"schema={schema_version}":
            raise RuntimeError("COMPLETE marker does not match manifest schema")
    if schema_version >= SCHEMA_V3:
        missing_v3 = [name for name in V3_FILES if not (root / name).is_file()]
        if missing_v3:
            raise RuntimeError(
                f"worker output is incomplete; missing schema v3 files: {', '.join(missing_v3)}"
            )
    functions_dir = root / "functions"
    if not functions_dir.is_dir():
        raise RuntimeError("worker output is incomplete; missing functions directory")

    function_eas: set[str] = set()
    artifact_paths: set[str] = set()
    function_count = 0
    decompiled = 0
    decompile_failed = 0
    disassembly_failed = 0
    disassembled = 0
    successful = 0
    hard_failed = 0
    instruction_total = 0
    cfg_function_total = 0
    for line_number, record in _iter_jsonl(
        root / "function_index.jsonl", "function index"
    ):
        function_count += 1
        ea = record.get("ea")
        if not isinstance(ea, str):
            raise RuntimeError(f"invalid function ea at line {line_number}")
        if ea in function_eas:
            raise RuntimeError(f"duplicate function ea at line {line_number}")
        try:
            int(ea, 16)
        except ValueError as exc:
            raise RuntimeError(f"invalid function ea at line {line_number}") from exc
        function_eas.add(ea)
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, dict):
            raise RuntimeError(f"invalid function artifacts at line {line_number}")
        artifact_kinds = ["pseudocode", "disassembly"]
        if schema_version >= SCHEMA_V3:
            artifact_kinds.extend(["instructions", "cfg"])
        hashes = record.get("artifact_hashes", {})
        for artifact_kind in artifact_kinds:
            prefix = "functions" if artifact_kind in {"pseudocode", "disassembly"} else artifact_kind
            artifact_path = _artifact_path(
                root, artifacts.get(artifact_kind), prefix, artifact_kind
            )
            relative = artifact_path.relative_to(root.resolve()).as_posix()
            if relative in artifact_paths:
                raise RuntimeError(f"duplicate function artifact: {relative}")
            artifact_paths.add(relative)
            if not artifact_path.is_file():
                raise RuntimeError(f"missing function artifact: {relative}")
            expected_hash = hashes.get(artifact_kind) if isinstance(hashes, dict) else None
            if isinstance(expected_hash, str) and _sha256(artifact_path) != expected_hash:
                raise RuntimeError(f"function artifact hash mismatch: {relative}")
            if artifact_kind == "instructions":
                instruction_total += sum(
                    1
                    for _instruction_line, instruction in _iter_jsonl(
                        artifact_path, "function instructions"
                    )
                    if instruction.get("ea") is not None
                )
            elif artifact_kind == "cfg":
                try:
                    cfg = json.loads(artifact_path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise RuntimeError(f"invalid CFG artifact: {relative}") from exc
                if not isinstance(cfg, dict) or not isinstance(cfg.get("blocks"), list):
                    raise RuntimeError(f"invalid CFG artifact: {relative}")
                if cfg["blocks"]:
                    cfg_function_total += 1

        has_decompile_error = "decompile_error" in record
        has_disassembly_error = "disassembly_error" in record
        decompiled += not has_decompile_error
        decompile_failed += has_decompile_error
        disassembly_failed += has_disassembly_error
        disassembled += not has_disassembly_error
        successful += not has_decompile_error and not has_disassembly_error
        hard_failed += has_decompile_error and has_disassembly_error

    counts = manifest.get("counts", {})
    expected_functions = counts.get("functions")
    if expected_functions != function_count:
        raise RuntimeError(
            f"function count mismatch: manifest={expected_functions}, index={function_count}"
        )
    if counts.get("decompiled") != decompiled or counts.get("assembly") != function_count:
        raise RuntimeError("function artifact counts do not match manifest")
    if counts.get("decompile_failed") != decompile_failed:
        raise RuntimeError("decompile failure count does not match manifest")
    if counts.get("disassembly_failed") != disassembly_failed:
        raise RuntimeError("disassembly failure count does not match manifest")
    if counts.get("disassembled") != disassembled:
        raise RuntimeError("disassembled count does not match manifest")
    if counts.get("successful") != successful:
        raise RuntimeError("successful count does not match manifest")
    if counts.get("hard_failed") != hard_failed:
        raise RuntimeError("hard failure count does not match manifest")
    if schema_version >= SCHEMA_V3:
        if counts.get("instructions") != instruction_total:
            raise RuntimeError("instruction count does not match manifest")
        if counts.get("cfg_functions") != cfg_function_total:
            raise RuntimeError("CFG function count does not match manifest")

    callgraph_count = 0
    callgraph_eas: set[str] = set()
    call_edges = 0
    for line_number, record in _iter_jsonl(root / "callgraph.jsonl", "callgraph"):
        callgraph_count += 1
        ea = record.get("ea")
        if not isinstance(ea, str):
            raise RuntimeError(f"invalid callgraph ea at line {line_number}")
        if ea in callgraph_eas:
            raise RuntimeError(f"duplicate callgraph ea at line {line_number}")
        callgraph_eas.add(ea)
        callees = record.get("callees", [])
        if not isinstance(callees, list):
            raise RuntimeError(f"invalid callgraph callees at line {line_number}")
        call_edges += len(callees)
    fallback_count = _jsonl_count(
        root / "function_fallbacks.jsonl", "fallback log"
    )
    failure_count = _jsonl_count(root / "function_failures.jsonl", "failure log")
    skipped_count = _jsonl_count(root / "function_skipped.jsonl", "skipped log")
    if callgraph_count != function_count:
        raise RuntimeError("callgraph count does not match function index")
    if callgraph_eas != function_eas:
        raise RuntimeError("callgraph function addresses do not match function index")
    if counts.get("fallbacks") != fallback_count:
        raise RuntimeError("fallback count does not match manifest")
    if counts.get("failed") != failure_count:
        raise RuntimeError("failed count does not match manifest")
    if counts.get("skipped") != skipped_count:
        raise RuntimeError("skipped count does not match manifest")
    if counts.get("total_functions") != function_count + skipped_count:
        raise RuntimeError("total function count does not match manifest")
    if counts.get("exported") != disassembled:
        raise RuntimeError("exported count does not match manifest")
    if counts.get("call_edges") != call_edges:
        raise RuntimeError("call edge count does not match manifest")

    if schema_version >= SCHEMA_V3:
        xref_keys: set[tuple[object, object, object]] = set()
        for count_name, filename, label in (
            ("xrefs", "xrefs.jsonl", "xrefs"),
            ("string_xrefs", "string_xrefs.jsonl", "string xrefs"),
            ("names", "names.jsonl", "names"),
            ("data", "data.jsonl", "data"),
            ("comments", "comments.jsonl", "comments"),
            ("types", "types.jsonl", "types"),
        ):
            record_count = 0
            for line_number, record in _iter_jsonl(root / filename, label):
                record_count += 1
                if count_name != "xrefs":
                    continue
                if "source_ea" not in record or "xref_type" not in record:
                    raise RuntimeError(f"invalid xref record at line {line_number}")
                key = (
                    record.get("source_ea"),
                    record.get("target_ea"),
                    record.get("xref_type"),
                )
                try:
                    duplicate = key in xref_keys
                except TypeError as exc:
                    raise RuntimeError(f"invalid xref key at line {line_number}") from exc
                if duplicate:
                    raise RuntimeError(f"duplicate xref at line {line_number}")
                xref_keys.add(key)
            if counts.get(count_name) != record_count:
                raise RuntimeError(f"{count_name} count does not match manifest")

    allowed_pointer_types = {
        "import_pointer",
        "string_pointer",
        "function_pointer",
        "code_pointer",
        "struct_pointer",
        "data_pointer",
        "unknown_pointer",
    }
    pointer_keys: set[tuple[str, str]] = set()
    pointer_count = 0
    for line_number, record in _iter_jsonl(root / "pointers.jsonl", "pointer index"):
        pointer_count += 1
        for field in (
            "source_ea",
            "source_segment",
            "target_ea",
            "target_segment",
            "target_name",
            "target_detail",
        ):
            if not isinstance(record.get(field), str):
                raise RuntimeError(f"invalid pointer {field} at line {line_number}")
        for field in ("source_ea", "target_ea"):
            try:
                int(record[field], 16)
            except ValueError as exc:
                raise RuntimeError(f"invalid pointer {field} at line {line_number}") from exc
        key = (record["source_ea"], record["target_ea"])
        if key in pointer_keys:
            raise RuntimeError(f"duplicate pointer at line {line_number}")
        pointer_keys.add(key)
        if record.get("target_type") not in allowed_pointer_types:
            raise RuntimeError(f"invalid pointer target_type at line {line_number}")
        evidence = record.get("evidence")
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(item not in {"data_xref", "raw_pointer"} for item in evidence)
            or len(evidence) != len(set(evidence))
        ):
            raise RuntimeError(f"invalid pointer evidence at line {line_number}")
    if counts.get("pointers") != pointer_count:
        raise RuntimeError("pointer count does not match manifest")

    string_count = _jsonl_count(root / "strings.jsonl", "strings")
    imports = _validate_json_array(root / "imports.json", "imports")
    exports = _validate_json_array(root / "exports.json", "exports")
    if counts.get("strings") != string_count:
        raise RuntimeError("strings count does not match manifest")
    if counts.get("imports") != len(imports):
        raise RuntimeError("imports count does not match manifest")
    if counts.get("exports") != len(exports):
        raise RuntimeError("exports count does not match manifest")

    memory_dir = root / "memory"
    if not memory_dir.is_dir():
        raise RuntimeError("worker output is incomplete; missing memory directory")
    memory_count = 0
    memory_bytes = 0
    for line_number, record in _iter_jsonl(root / "memory_index.jsonl", "memory index"):
        memory_count += 1
        artifact = record.get("artifact")
        if not isinstance(artifact, str) or not artifact.startswith("memory/"):
            raise RuntimeError(f"invalid memory artifact at line {line_number}")
        artifact_path = root / artifact
        if not artifact_path.is_file():
            raise RuntimeError(f"missing memory artifact: {artifact}")
        expected_sha256 = record.get("artifact_sha256")
        if not isinstance(expected_sha256, str) or _sha256(artifact_path) != expected_sha256:
            raise RuntimeError(f"memory artifact hash mismatch: {artifact}")
        size = record.get("size", 0)
        if not isinstance(size, int):
            raise RuntimeError(f"invalid memory size at line {line_number}")
        memory_bytes += size

    segments = json.loads((root / "segments.json").read_text(encoding="utf-8"))
    if not isinstance(segments, list):
        raise RuntimeError("segments.json must contain an array")
    if counts.get("segments") != len(segments):
        raise RuntimeError("segment count does not match manifest")
    if counts.get("memory_chunks") != memory_count:
        raise RuntimeError("memory chunk count does not match manifest")
    if counts.get("memory_bytes") != memory_bytes:
        raise RuntimeError("memory byte count does not match manifest")
    if schema_version >= SCHEMA_V3:
        if manifest.get("artifacts") != _artifact_inventory(root):
            raise RuntimeError("artifact inventory does not match manifest")
