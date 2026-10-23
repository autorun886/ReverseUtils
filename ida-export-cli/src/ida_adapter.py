from __future__ import annotations

import dataclasses
import gc
import hashlib
import importlib.metadata
from pathlib import Path
from typing import Any, Iterable, Iterator


class IdaDomainAdapter:
    """Small boundary around ida-domain; direct IDA APIs stay outside exporters."""

    def __init__(self, input_path: Path):
        from ida_domain.database import Database

        self._database_type = Database
        self._input_path = input_path
        self.db: Any = None

    def __enter__(self) -> "IdaDomainAdapter":
        self.db = self._database_type.open(str(self._input_path), save_on_close=False)
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.db is not None:
            self.db.close(save=False)

    def metadata(self) -> dict[str, Any]:
        value = self.db.metadata
        if dataclasses.is_dataclass(value):
            return dataclasses.asdict(value)
        if hasattr(value, "__dict__"):
            return dict(vars(value))
        return {"value": value}

    def capabilities(self) -> dict[str, Any]:
        """Return runtime capabilities as plain, serialisable values.

        The adapter is used both from ``idalib`` and from small test doubles.
        Capability probing therefore never assumes that an optional IDA module
        is importable; an unavailable feature is reported as ``False`` instead
        of making the export fail.
        """
        domain_version: str | None = None
        try:
            domain_version = importlib.metadata.version("ida-domain")
        except Exception:
            try:
                import ida_domain  # type: ignore

                domain_version = str(getattr(ida_domain, "__version__", "unknown"))
            except Exception:
                domain_version = None

        ida_version: str | None = None
        for module_name in ("idaapi", "ida_kernwin", "ida_idaapi"):
            try:
                module = __import__(module_name)
                getter = getattr(module, "get_kernel_version", None)
                if callable(getter):
                    ida_version = str(getter())
                    break
                value = getattr(module, "IDA_SDK_VERSION", None)
                if value is not None:
                    ida_version = str(value)
                    break
            except Exception:
                continue

        feature_names = {
            "functions": hasattr(self.db, "functions"),
            "pseudocode": hasattr(self.db, "pseudocode"),
            "instructions": hasattr(self.db, "instructions")
            or hasattr(getattr(self.db, "functions", None), "get_instructions"),
            "xrefs": hasattr(self.db, "xrefs"),
            "cfg": hasattr(getattr(self.db, "functions", None), "get_flowchart"),
            "strings": hasattr(self.db, "strings"),
            "names": hasattr(self.db, "names"),
            "data": hasattr(self.db, "bytes"),
            "comments": hasattr(self.db, "comments"),
            "types": hasattr(self.db, "types"),
        }
        enabled = sorted(name for name, available in feature_names.items() if available)
        return {
            "backend": "idalib",
            "adapter": "ida-domain",
            "ida_domain_version": domain_version,
            "ida_version": ida_version,
            "features": enabled,
            "feature_flags": feature_names,
            "decompilation_flags": {
                "no_wait": self._has_decompilation_flag("NO_WAIT"),
                "no_cache": self._has_decompilation_flag("NO_CACHE"),
            },
        }

    def version_info(self) -> dict[str, Any]:
        """Compatibility alias for callers that only need version fields."""
        value = self.capabilities()
        return {
            "ida_version": value.get("ida_version"),
            "ida_domain_version": value.get("ida_domain_version"),
            "backend": value.get("backend"),
            "adapter": value.get("adapter"),
        }

    def functions(self) -> Iterator[Any]:
        return iter(self.db.functions)

    def function_name(self, function: Any) -> str:
        return self.db.functions.get_name(function)

    def function_signature(self, function: Any) -> str | None:
        return self.db.functions.get_signature(function)

    def function_flags(self, function: Any) -> list[str]:
        flags = self.db.functions.get_flags(function)
        return sorted(flag.name for flag in type(flags) if flag in flags)

    def function_skip_reason(self, function: Any) -> str | None:
        from ida_domain.functions import FunctionFlags

        if not self.db.functions.is_entry_chunk(function):
            return "not a valid function entry"
        flags = self.db.functions.get_flags(function)
        if FunctionFlags.LIB in flags:
            return "library function"
        return None

    def function_callers(self, function: Any) -> list[dict[str, Any]]:
        return self._function_relations(self.db.functions.get_callers(function))

    def function_callees(self, function: Any) -> list[dict[str, Any]]:
        return self._function_relations(self.db.functions.get_callees(function))

    def _function_relations(self, functions: Any) -> list[dict[str, Any]]:
        records = {
            int(item.start_ea): {
                "ea": _ea(int(item.start_ea)),
                "name": self.db.functions.get_name(item) or f"sub_{int(item.start_ea):X}",
            }
            for item in functions
        }
        return [records[ea] for ea in sorted(records)]

    def pseudocode(self, function: Any, *, no_cache: bool = False) -> str:
        # Use the explicit Hex-Rays flags so headless runs never wait on an
        # interactive decompiler dialog.  NO_CACHE is reserved for retries or
        # functions whose previous export was interrupted.
        from ida_domain.microcode import DecompilationFlags

        flags = DecompilationFlags.NO_WAIT
        if no_cache:
            flags |= DecompilationFlags.NO_CACHE
        return str(self.db.pseudocode.decompile(function, flags))

    def function_instruction_count(self, function: Any, limit: int | None = None) -> int:
        count = 0
        for _ in self.db.functions.get_instructions(function):
            count += 1
            if limit is not None and count >= limit:
                break
        return count

    def release_decompiler_cache(self) -> dict[str, Any]:
        """Release cached Hex-Rays objects after DTO/text conversion."""
        cleared = False
        error: str | None = None
        try:
            import ida_hexrays  # type: ignore

            clear = getattr(ida_hexrays, "clear_cached_cfuncs", None)
            if callable(clear):
                clear()
                cleared = True
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        collected = gc.collect()
        return {"hexrays_cache_cleared": cleared, "gc_collected": collected, "error": error}

    def disassembly(self, function: Any) -> list[str]:
        return self.db.functions.get_disassembly(function)

    def function_instructions(self, function: Any) -> Iterator[dict[str, Any]]:
        """Yield instruction DTOs without leaking IDA/SWIG objects.

        A malformed byte or comment is represented by ``read_error`` on the
        affected instruction.  The remaining instructions are still emitted.
        """
        try:
            instructions = self.db.functions.get_instructions(function)
        except Exception as exc:
            yield self._instruction_error_record(function, exc)
            return

        try:
            iterator = iter(instructions)
        except Exception as exc:
            yield self._instruction_error_record(function, exc)
            return

        while True:
            try:
                insn = next(iterator)
            except StopIteration:
                break
            except Exception as exc:
                yield self._instruction_error_record(function, exc)
                break
            errors: list[str] = []
            ea = self._instruction_ea(insn)
            size = self._instruction_size(insn)
            if ea is None:
                errors.append("missing instruction address")
                ea_value: str | None = None
            else:
                ea_value = _ea(ea)

            raw_bytes: bytes | None = None
            if ea is not None and size > 0:
                try:
                    raw_bytes = self.read_bytes(ea, size)
                except Exception as exc:
                    errors.append(f"bytes {type(exc).__name__}: {exc}")
            elif ea is not None:
                errors.append("missing instruction size")

            mnemonic: str | None = None
            try:
                instructions_api = getattr(self.db, "instructions", None)
                getter = getattr(instructions_api, "get_mnemonic", None)
                if callable(getter):
                    mnemonic = _plain_text(getter(insn))
            except Exception as exc:
                errors.append(f"mnemonic {type(exc).__name__}: {exc}")
            if mnemonic is None and ea is not None:
                try:
                    import ida_ua  # type: ignore

                    mnemonic = _plain_text(ida_ua.print_insn_mnem(ea))
                except Exception:
                    pass

            operands: list[str] = []
            try:
                instructions_api = getattr(self.db, "instructions", None)
                getter = getattr(instructions_api, "get_operands", None)
                if callable(getter):
                    operands = [_plain_text(item) for item in getter(insn)]
                else:
                    raw_operands = getattr(insn, "ops", ())
                    operands = [
                        _plain_text(item)
                        for item in raw_operands
                        if getattr(item, "type", 1) not in (0, None)
                    ]
            except Exception as exc:
                errors.append(f"operands {type(exc).__name__}: {exc}")

            text: str | None = None
            try:
                instructions_api = getattr(self.db, "instructions", None)
                getter = getattr(instructions_api, "get_disassembly", None)
                if callable(getter):
                    text = _plain_text(getter(insn))
            except Exception as exc:
                errors.append(f"disassembly {type(exc).__name__}: {exc}")
            if text is None and ea is not None:
                try:
                    text = _plain_text(self.db.bytes.get_disassembly_at(ea))
                except Exception:
                    pass

            regular, repeatable, comment_errors = self._comments_at(ea)
            errors.extend(comment_errors)
            yield {
                "ea": ea_value,
                "size": int(size) if size else 0,
                "bytes": raw_bytes.hex(" ").upper() if raw_bytes is not None else None,
                "mnemonic": mnemonic,
                "operands": operands,
                "text": text,
                "regular_comment": regular,
                "repeatable_comment": repeatable,
                "read_error": "; ".join(errors) if errors else None,
            }

    def function_xrefs(self, function: Any) -> Iterator[dict[str, Any]]:
        """Yield xrefs originating at instructions in ``function``."""
        source_function_ea = self._function_ea(function)
        seen: set[tuple[int | None, int | None, str]] = set()
        try:
            instructions = self.db.functions.get_instructions(function)
        except Exception:
            instructions = ()
        for insn in instructions:
            source_ea = self._instruction_ea(insn)
            if source_ea is None:
                continue
            for xref in self._xrefs_from(source_ea):
                target_ea = self._xref_target(xref)
                xref_type, type_value = self._xref_type(xref)
                key = (source_ea, target_ea, xref_type)
                if key in seen:
                    continue
                seen.add(key)
                target_function_ea = self._target_function_ea(target_ea)
                yield {
                    "source_ea": _ea(source_ea),
                    "target_ea": _ea(target_ea) if target_ea is not None else None,
                    "source_function_ea": _ea(source_function_ea)
                    if source_function_ea is not None
                    else None,
                    "target_function_ea": _ea(target_function_ea)
                    if target_function_ea is not None
                    else None,
                    "xref_type": xref_type,
                    "xref_type_value": type_value,
                    "is_code": bool(getattr(xref, "is_code", getattr(xref, "iscode", False))),
                    "user": bool(getattr(xref, "user", False)),
                    "confidence": "ida_xref",
                }

    def function_cfg(self, function: Any) -> dict[str, Any]:
        """Convert an IDA flowchart to a stable JSON-compatible dictionary."""
        function_ea = self._function_ea(function)
        result: dict[str, Any] = {
            "function_ea": _ea(function_ea) if function_ea is not None else None,
            "entry_block": None,
            "blocks": [],
            "read_error": None,
        }
        try:
            flowchart = self.db.functions.get_flowchart(function)
            blocks = list(flowchart) if flowchart is not None else []
        except Exception as exc:
            result["read_error"] = f"flowchart {type(exc).__name__}: {exc}"
            return result

        records: list[dict[str, Any]] = []
        for block in blocks:
            errors: list[str] = []
            start = _int_or_none(getattr(block, "start_ea", None))
            end = _int_or_none(getattr(block, "end_ea", None))
            block_id = _int_or_none(getattr(block, "id", None))
            if start is None:
                errors.append("missing block start_ea")
            instruction_eas: list[str] = []
            try:
                getter = getattr(block, "get_instructions", None)
                block_instructions = getter() if callable(getter) else ()
                instruction_eas = [
                    _ea(ea)
                    for ea in (
                        self._instruction_ea(item)
                        for item in block_instructions or ()
                    )
                    if ea is not None
                ]
            except Exception as exc:
                errors.append(f"instructions {type(exc).__name__}: {exc}")
            successors = self._block_eas(block, "get_successors", "succs", errors)
            predecessors = self._block_eas(block, "get_predecessors", "preds", errors)
            record: dict[str, Any] = {
                # ``BasicBlock.id`` is only a flowchart ordinal.  Use the
                # start EA as the public stable identifier and retain the
                # ordinal separately for diagnostics.
                "id": _ea(start) if start is not None else (_ea(block_id) if block_id is not None else None),
                "ordinal": block_id,
                "start_ea": _ea(start) if start is not None else None,
                "end_ea": _ea(end) if end is not None else None,
                "instruction_eas": instruction_eas,
                "successors": successors,
                "predecessors": predecessors,
                "read_error": "; ".join(errors) if errors else None,
            }
            records.append(record)
        records.sort(key=lambda item: _hex_sort(item.get("start_ea")))
        result["blocks"] = records
        if records:
            result["entry_block"] = records[0]["id"]
        return result

    def string_xrefs(self) -> Iterator[dict[str, Any]]:
        """Yield data references to each IDA string item."""
        strings = getattr(self.db, "strings", ())
        seen: set[tuple[int, int]] = set()
        for item, iteration_error in _localized_items(strings):
            if iteration_error is not None:
                yield {
                    "string_ea": None,
                    "source_ea": None,
                    "source_function_ea": None,
                    "value": None,
                    "xref_type": "UNKNOWN",
                    "is_code": False,
                    "user": False,
                    "read_error": f"strings {type(iteration_error).__name__}: {iteration_error}",
                }
                break
            string_ea = _int_or_none(getattr(item, "address", None))
            if string_ea is None:
                continue
            try:
                value = str(item)
            except Exception as exc:
                value = None
                read_error = f"string {type(exc).__name__}: {exc}"
            else:
                read_error = None
            try:
                sources = tuple(self.db.xrefs.data_refs_to_ea(string_ea))
            except Exception:
                sources = tuple(self._direct_data_refs_to(string_ea))
            for source, source_error in _localized_items(sources):
                if source_error is not None:
                    break
                source_ea = _int_or_none(source)
                if source_ea is None:
                    source_ea = _int_or_none(getattr(source, "from_ea", None))
                if source_ea is None or (string_ea, source_ea) in seen:
                    continue
                seen.add((string_ea, source_ea))
                source_function = self._target_function_ea(source_ea)
                yield {
                    "string_ea": _ea(string_ea),
                    "source_ea": _ea(source_ea),
                    "source_function_ea": _ea(source_function)
                    if source_function is not None
                    else None,
                    "value": value,
                    "xref_type": "DATA",
                    "is_code": False,
                    "user": False,
                    "read_error": read_error,
                }

    def names(self) -> Iterator[dict[str, Any]]:
        """Yield all named addresses with segment/function context."""
        names = getattr(self.db, "names", None)
        try:
            if names is None:
                values = self._direct_names()
            elif callable(getattr(names, "get_all", None)):
                values = names.get_all()
            elif names is not None and hasattr(names, "__iter__"):
                values = names
            else:
                values = self._direct_names()
        except Exception as exc:
            yield {"ea": None, "name": None, "read_error": f"names {type(exc).__name__}: {exc}"}
            return
        for value, iteration_error in _localized_items(values):
            if iteration_error is not None:
                yield {
                    "ea": None,
                    "name": None,
                    "read_error": f"names {type(iteration_error).__name__}: {iteration_error}",
                }
                break
            try:
                if isinstance(value, tuple):
                    ea, name = value[0], value[1]
                else:
                    ea, name = getattr(value, "ea"), getattr(value, "name")
                ea_int = int(ea)
                name_text = str(name)
                segment = self.db.segments.get_at(ea_int)
                function = self.db.functions.get_at(ea_int)
                is_auto, name_flags = self._name_flags(ea_int)
                yield {
                    "ea": _ea(ea_int),
                    "name": name_text,
                    "segment": self.db.segments.get_name(segment) if segment else None,
                    "is_function": function is not None,
                    "function_ea": _ea(int(function.start_ea)) if function else None,
                    "is_auto": is_auto,
                    "name_flags": name_flags,
                    "read_error": None,
                }
            except Exception as exc:
                yield {
                    "ea": _ea(_int_or_none(value[0])) if isinstance(value, tuple) and _int_or_none(value[0]) is not None else None,
                    "name": None,
                    "read_error": f"name {type(exc).__name__}: {exc}",
                }

    @staticmethod
    def _direct_names() -> Iterator[tuple[int, str]]:
        try:
            import ida_name  # type: ignore

            count = int(ida_name.get_nlist_size())
            for index in range(count):
                ea = ida_name.get_nlist_ea(index)
                name = ida_name.get_nlist_name(index)
                if name:
                    yield int(ea), str(name)
        except Exception:
            return

    def data_items(self) -> Iterator[dict[str, Any]]:
        """Yield IDA data heads, including bytes and xref evidence."""
        bytes_api = getattr(self.db, "bytes", None)
        for segment in getattr(self.db, "segments", ()):
            start, end = _int_or_none(getattr(segment, "start_ea", None)), _int_or_none(
                getattr(segment, "end_ea", None)
            )
            if start is None or end is None:
                continue
            head = start
            while head < end:
                next_head = None
                try:
                    is_data = bool(bytes_api.is_data_at(head))
                except Exception as exc:
                    yield {
                        "ea": _ea(head),
                        "size": 0,
                        "segment": self._segment_name(segment),
                        "read_error": f"flags {type(exc).__name__}: {exc}",
                    }
                    is_data = False
                if is_data:
                    yield self._data_item_record(head, segment)
                try:
                    next_head = _int_or_none(bytes_api.get_next_head(head, end))
                except Exception:
                    try:
                        next_head = _int_or_none(bytes_api.get_next_head(head))
                    except Exception:
                        next_head = None
                if next_head is None or next_head <= head:
                    head += 1
                else:
                    head = next_head

    def comments(self) -> Iterator[dict[str, Any]]:
        """Yield regular, repeatable and (when exposed) extra comments."""
        comments_api = getattr(self.db, "comments", None)
        seen: set[tuple[int, str, str]] = set()
        values: Iterable[Any] = ()
        if comments_api is None:
            for ea in self._item_eas():
                regular, repeatable, errors = self._comments_at(ea)
                if regular:
                    seen.add((ea, "regular", regular))
                    record = self._comment_record(ea, regular, "regular", None)
                    record["read_error"] = "; ".join(errors) if errors else None
                    yield record
                if repeatable:
                    seen.add((ea, "repeatable", repeatable))
                    record = self._comment_record(ea, repeatable, "repeatable", None)
                    record["read_error"] = "; ".join(errors) if errors else None
                    yield record
            return
        try:
            get_all = getattr(comments_api, "get_all", None)
            if callable(get_all):
                try:
                    from ida_domain.comments import CommentKind  # type: ignore

                    values = get_all(CommentKind.ALL)
                except Exception:
                    values = get_all()
            elif comments_api is not None:
                values = comments_api
        except Exception as exc:
            yield {"ea": None, "kind": None, "text": None, "read_error": f"comments {type(exc).__name__}: {exc}"}
            return
        for item, iteration_error in _localized_items(values):
            if iteration_error is not None:
                yield {
                    "ea": None,
                    "kind": None,
                    "text": None,
                    "read_error": f"comments {type(iteration_error).__name__}: {iteration_error}",
                }
                break
            try:
                ea = int(getattr(item, "ea", item[0] if isinstance(item, tuple) else 0))
                text = getattr(item, "comment", item[1] if isinstance(item, tuple) else str(item))
                repeatable = bool(getattr(item, "repeatable", item[2] if isinstance(item, tuple) and len(item) > 2 else False))
                kind = "repeatable" if repeatable else "regular"
                key = (ea, kind, str(text))
                if key in seen:
                    continue
                seen.add(key)
                yield self._comment_record(ea, str(text), kind, None)
            except Exception as exc:
                yield {"ea": None, "kind": None, "text": None, "read_error": f"comment {type(exc).__name__}: {exc}"}

        # Extra comments are not iterable in older ida-domain releases.  Probe
        # only known item heads, keeping each lookup independent.
        extra_getter = getattr(comments_api, "get_all_extra_at", None)
        if not callable(extra_getter):
            return
        for ea in self._item_eas():
            for kind_name, enum_name in (("anterior", "ANTERIOR"), ("posterior", "POSTERIOR")):
                try:
                    from ida_domain.comments import ExtraCommentKind  # type: ignore

                    values = extra_getter(ea, getattr(ExtraCommentKind, enum_name))
                    for index, text in enumerate(values):
                        if text:
                            key = (ea, kind_name, str(text))
                            if key not in seen:
                                seen.add(key)
                                yield self._comment_record(ea, str(text), kind_name, index)
                except Exception:
                    continue

    def types(self) -> Iterator[dict[str, Any]]:
        """Yield global type declarations without exposing ``tinfo_t``."""
        types_api = getattr(self.db, "types", None)
        try:
            values = iter(types_api) if types_api is not None else iter(())
        except Exception as exc:
            yield {"name": None, "declaration": None, "read_error": f"types {type(exc).__name__}: {exc}"}
            return
        for type_info, iteration_error in _localized_items(values):
            if iteration_error is not None:
                yield {
                    "name": None,
                    "declaration": None,
                    "read_error": f"types {type(iteration_error).__name__}: {iteration_error}",
                }
                break
            errors: list[str] = []
            try:
                name_value = type_info.get_type_name() if callable(getattr(type_info, "get_type_name", None)) else getattr(type_info, "name", None)
                name = _plain_text(name_value) if name_value else None
            except Exception as exc:
                name = None
                errors.append(f"name {type(exc).__name__}: {exc}")
            try:
                declaration = _plain_text(type_info)
            except Exception as exc:
                declaration = None
                errors.append(f"declaration {type(exc).__name__}: {exc}")
            kind = None
            try:
                value = type_info.get_type_kind() if callable(getattr(type_info, "get_type_kind", None)) else getattr(type_info, "kind", None)
                kind = self._enum_record(value)
            except Exception as exc:
                errors.append(f"kind {type(exc).__name__}: {exc}")
            size = None
            try:
                getter = getattr(type_info, "get_size", None)
                size = int(getter()) if callable(getter) else _int_or_none(getattr(type_info, "size", None))
            except Exception as exc:
                errors.append(f"size {type(exc).__name__}: {exc}")
            details: Any = None
            try:
                getter = getattr(types_api, "get_details", None)
                if callable(getter):
                    value = getter(type_info)
                    details = _plain_value(value)
            except Exception as exc:
                errors.append(f"details {type(exc).__name__}: {exc}")
            yield {
                "name": name,
                "declaration": declaration,
                "kind": kind,
                "size": size,
                "details": details,
                "read_error": "; ".join(errors) if errors else None,
            }

    def _has_decompilation_flag(self, name: str) -> bool:
        try:
            from ida_domain.microcode import DecompilationFlags  # type: ignore

            return hasattr(DecompilationFlags, name)
        except Exception:
            return False

    def _instruction_error_record(self, function: Any, exc: Exception) -> dict[str, Any]:
        return {
            "ea": None,
            "size": 0,
            "bytes": None,
            "mnemonic": None,
            "operands": [],
            "text": None,
            "regular_comment": None,
            "repeatable_comment": None,
            "read_error": f"instructions {type(exc).__name__}: {exc}",
        }

    @staticmethod
    def _instruction_ea(insn: Any) -> int | None:
        try:
            return _int_or_none(getattr(insn, "ea", getattr(insn, "address", None)))
        except Exception:
            return None

    def _instruction_size(self, insn: Any) -> int:
        size = _int_or_none(getattr(insn, "size", None))
        if size is not None and size > 0:
            return size
        ea = self._instruction_ea(insn)
        if ea is not None:
            try:
                value = self.db.bytes.get_data_size_at(ea)
                if int(value) > 0:
                    return int(value)
            except Exception:
                pass
        return 0

    def _comments_at(self, ea: int | None) -> tuple[str | None, str | None, list[str]]:
        if ea is None:
            return None, None, []
        api = getattr(self.db, "comments", None)
        if api is None or not callable(getattr(api, "get_at", None)):
            try:
                import ida_bytes  # type: ignore

                return (
                    _plain_text(ida_bytes.get_cmt(ea, False)),
                    _plain_text(ida_bytes.get_cmt(ea, True)),
                    [],
                )
            except Exception:
                return None, None, []
        errors: list[str] = []
        values: list[str | None] = []
        for enum_name in ("REGULAR", "REPEATABLE"):
            try:
                item = api.get_at(ea, self._comment_kind(enum_name))
                values.append(_plain_text(getattr(item, "comment", item)) if item else None)
            except Exception as exc:
                values.append(None)
                errors.append(f"{enum_name.lower()} comment {type(exc).__name__}: {exc}")
        return values[0], values[1], errors

    @staticmethod
    def _comment_kind(name: str) -> Any:
        try:
            from ida_domain.comments import CommentKind  # type: ignore

            return getattr(CommentKind, name)
        except Exception:
            # Test doubles and older IDA wrappers commonly accept the string
            # spelling directly.  Keeping this fallback here avoids importing
            # an optional module for every instruction.
            return name.lower()

    def _function_ea(self, function: Any) -> int | None:
        return _int_or_none(getattr(function, "start_ea", getattr(function, "ea", None)))

    def _target_function_ea(self, ea: int | None) -> int | None:
        if ea is None:
            return None
        try:
            function = self.db.functions.get_at(ea)
            return self._function_ea(function) if function is not None else None
        except Exception:
            return None

    def _xrefs_from(self, ea: int) -> Iterable[Any]:
        api = getattr(self.db, "xrefs", None)
        getter = getattr(api, "from_ea", None)
        if callable(getter):
            try:
                return tuple(getter(ea))
            except Exception:
                pass
        try:
            # Materialise the fallback here: a generator defers import errors
            # until iteration, which would otherwise escape the boundary.
            return tuple(self._direct_xrefs_from(ea))
        except Exception:
            return ()

    def _direct_xrefs_from(self, ea: int) -> Iterator[Any]:
        import ida_xref  # type: ignore

        block = ida_xref.xrefblk_t()
        try:
            ok = block.first_from(ea, ida_xref.XREF_ALL)
        except Exception:
            ok = block.first_from(ea, 0)
        while ok:
            yield type(
                "Xref",
                (),
                {
                    "from_ea": int(getattr(block, "frm", ea)),
                    "to_ea": int(getattr(block, "to", 0)),
                    "is_code": bool(getattr(block, "iscode", False)),
                    "user": bool(getattr(block, "user", False)),
                    "type": int(getattr(block, "type", 0)),
                },
            )()
            ok = block.next_from()

    def _direct_data_refs_to(self, ea: int) -> Iterator[int]:
        try:
            import ida_xref  # type: ignore

            block = ida_xref.xrefblk_t()
            ok = block.first_to(ea, ida_xref.XREF_DATA)
            while ok:
                yield int(block.frm)
                ok = block.next_to()
        except Exception:
            return

    @staticmethod
    def _xref_target(xref: Any) -> int | None:
        return _int_or_none(getattr(xref, "to_ea", getattr(xref, "to", None)))

    @staticmethod
    def _xref_type(xref: Any) -> tuple[str, int | None]:
        value = getattr(xref, "type", None)
        if value is None:
            return "UNKNOWN", None
        try:
            numeric = int(value)
        except Exception:
            numeric = None
        name = getattr(value, "name", None)
        if name is None and numeric is not None:
            try:
                from ida_domain.xrefs import XrefType  # type: ignore

                name = XrefType(numeric).name
            except Exception:
                pass
        return str(name or value), numeric

    @staticmethod
    def _block_eas(block: Any, method_name: str, fallback_name: str, errors: list[str]) -> list[str]:
        try:
            getter = getattr(block, method_name, None)
            values = getter() if callable(getter) else getattr(block, fallback_name)()
            result: list[str] = []
            for value in values or ():
                ea = _int_or_none(getattr(value, "start_ea", value))
                if ea is not None:
                    result.append(_ea(ea))
            return sorted(set(result), key=_hex_sort)
        except Exception as exc:
            errors.append(f"{fallback_name} {type(exc).__name__}: {exc}")
            return []

    def _item_eas(self) -> Iterator[int]:
        bytes_api = getattr(self.db, "bytes", None)
        for segment in getattr(self.db, "segments", ()):
            start, end = _int_or_none(getattr(segment, "start_ea", None)), _int_or_none(
                getattr(segment, "end_ea", None)
            )
            if start is None or end is None:
                continue
            ea = start
            while ea < end:
                try:
                    is_head = bytes_api.is_head_at(ea) if hasattr(bytes_api, "is_head_at") else True
                except Exception:
                    is_head = False
                if is_head:
                    yield ea
                try:
                    next_ea = _int_or_none(bytes_api.get_next_head(ea, end))
                except Exception:
                    try:
                        next_ea = _int_or_none(bytes_api.get_next_head(ea))
                    except Exception:
                        next_ea = None
                ea = next_ea if next_ea is not None and next_ea > ea else ea + 1

    def _name_flags(self, ea: int) -> tuple[bool | None, int | None]:
        try:
            import ida_name  # type: ignore

            flags = int(ida_name.get_name_flags(ea))
            is_auto = bool(ida_name.is_name_auto(ea)) if hasattr(ida_name, "is_name_auto") else None
            return is_auto, flags
        except Exception:
            return None, None

    def _segment_name(self, segment: Any) -> str | None:
        try:
            return self.db.segments.get_name(segment)
        except Exception:
            return _plain_text(getattr(segment, "name", None)) if segment is not None else None

    def _data_item_record(self, ea: int, segment: Any) -> dict[str, Any]:
        errors: list[str] = []
        try:
            size = int(self.db.bytes.get_data_size_at(ea))
        except Exception as exc:
            size = 1
            errors.append(f"size {type(exc).__name__}: {exc}")
        try:
            raw = self.read_bytes(ea, max(size, 1))
            raw_hex = raw.hex(" ").upper()
            raw_hash = hashlib.sha256(raw).hexdigest()
        except Exception as exc:
            raw_hex, raw_hash = None, None
            errors.append(f"bytes {type(exc).__name__}: {exc}")
        type_name, type_value = None, None
        try:
            flags = self.db.bytes.get_flags_at(ea)
            type_name, type_value = self._enum_record(flags)
        except Exception:
            pass
        declaration = None
        try:
            type_info = self.db.types.get_at(ea)
            declaration = _plain_text(type_info) if type_info else None
        except Exception:
            pass
        refs: list[str] = []
        try:
            refs = sorted({_ea(int(value)) for value in self.db.xrefs.data_refs_to_ea(ea)}, key=_hex_sort)
        except Exception:
            pass
        return {
            "ea": _ea(ea),
            "size": size,
            "segment": self._segment_name(segment),
            "type": type_name,
            "type_value": type_value,
            "declaration": declaration,
            "bytes": raw_hex,
            "sha256": raw_hash,
            "xrefs_to": refs,
            "read_error": "; ".join(errors) if errors else None,
        }

    def _comment_record(self, ea: int, text: str, kind: str, index: int | None) -> dict[str, Any]:
        function_ea = self._target_function_ea(ea)
        return {
            "ea": _ea(ea),
            "kind": kind,
            "index": index,
            "text": text,
            "function_ea": _ea(function_ea) if function_ea is not None else None,
            "read_error": None,
        }

    @staticmethod
    def _enum_record(value: Any) -> tuple[str | None, int | None]:
        if value is None:
            return None, None
        try:
            numeric = int(value)
        except Exception:
            numeric = None
        return str(getattr(value, "name", value)), numeric

    def strings(self) -> Iterator[dict[str, Any]]:
        for item in self.db.strings:
            try:
                value = str(item)
            except Exception as exc:
                value = f"<decode-error: {type(exc).__name__}: {exc}>"
            try:
                string_type = item.type
                type_name: str = string_type.name
                type_value: int | None = int(string_type)
            except Exception:
                # Some IDA versions expose string type codes that the
                # installed ida-domain enum does not know yet. Keep the raw
                # code and continue exporting the remaining strings.
                raw_type = getattr(item, "internal_type", None)
                try:
                    from ida_nalt import get_str_type_code

                    type_value = int(get_str_type_code(raw_type))
                except Exception:
                    try:
                        type_value = int(raw_type)
                    except (TypeError, ValueError):
                        type_value = None
                type_name = f"UNKNOWN_{type_value}" if type_value is not None else "UNKNOWN"
            try:
                encoding = item.encoding
            except Exception as exc:
                encoding = f"<encoding-error: {type(exc).__name__}: {exc}>"
            yield {
                "ea": _ea(item.address),
                "length": item.length,
                "type": type_name,
                "type_value": type_value,
                "encoding": encoding,
                "value": value,
            }

    def imports(self) -> Iterator[dict[str, Any]]:
        for item in self.db.imports.get_all_imports():
            yield {
                "ea": _ea(item.address),
                "name": item.name,
                "ordinal": item.ordinal,
                "module": item.module_name,
            }

    def exports(self) -> Iterator[dict[str, Any]]:
        for item in self.db.entries:
            yield {
                "ea": _ea(item.address),
                "name": item.name,
                "ordinal": item.ordinal,
                "forwarder": item.forwarder_name or None,
            }

    def segments(self) -> Iterator[Any]:
        return iter(self.db.segments)

    def segment_name(self, segment: Any) -> str:
        return self.db.segments.get_name(segment)

    def segment_class(self, segment: Any) -> str | None:
        return self.db.segments.get_class(segment)

    def segment_permissions(self, segment: Any) -> dict[str, Any]:
        from ida_domain.segments import SegmentPermissions

        value = int(segment.perm)
        return {
            "value": value,
            "read": bool(value & int(SegmentPermissions.READ)),
            "write": bool(value & int(SegmentPermissions.WRITE)),
            "execute": bool(value & int(SegmentPermissions.EXEC)),
        }

    def segment_bitness(self, segment: Any) -> int:
        return self.db.segments.get_bitness(segment)

    def read_bytes(self, ea: int, size: int) -> bytes:
        data = self.db.bytes.get_bytes_at(ea, size)
        if data is not None and len(data) == size:
            return bytes(data)
        return bytes(
            self.db.bytes.get_byte_at(address, allow_uninitialized=True) & 0xFF
            for address in range(ea, ea + size)
        )

    def pointers(self) -> Iterator[dict[str, Any]]:
        """Yield deduplicated data references and raw data-segment pointers.

        IDA's xref database does not always contain references for compiler
        generated tables, so raw pointer scanning complements the normal data
        xrefs.  The returned records intentionally use plain values so the
        exporter and test adapters do not depend on IDA object lifetimes.
        """
        pointer_size = self._pointer_size()
        records: dict[tuple[int, int], dict[str, Any]] = {}
        import_names = {
            int(item.address): item.name or f"ordinal_{item.ordinal}"
            for item in self.db.imports.get_all_imports()
        }
        strings = {int(item.address): item for item in self.db.strings}

        def add(source_ea: int, target_ea: int, evidence: str) -> None:
            if not self._valid_ea(target_ea):
                return
            key = (source_ea, target_ea)
            record = records.get(key)
            if record is None:
                target_name, target_type, target_detail = self._classify_pointer_target(
                    target_ea, import_names, strings
                )
                source_segment = self.db.segments.get_at(source_ea)
                target_segment = self.db.segments.get_at(target_ea)
                record = {
                    "source_ea": f"0x{source_ea:X}",
                    "source_segment": self.db.segments.get_name(source_segment)
                    if source_segment
                    else "unknown",
                    "target_ea": f"0x{target_ea:X}",
                    "target_segment": self.db.segments.get_name(target_segment)
                    if target_segment
                    else "unknown",
                    "target_name": target_name,
                    "target_type": target_type,
                    "target_detail": target_detail,
                    "evidence": [],
                }
                records[key] = record
            if evidence not in record["evidence"]:
                record["evidence"].append(evidence)

        # First use IDA's data xrefs.  Iterate item heads instead of every byte
        # so large segments remain inexpensive.
        for segment in self.db.segments:
            start, end = int(segment.start_ea), int(segment.end_ea)
            head = start
            while head < end:
                try:
                    if self.db.bytes.is_head_at(head) and (
                        self.db.bytes.is_code_at(head) or self.db.bytes.is_data_at(head)
                    ):
                        for target in self.db.xrefs.data_refs_from_ea(head):
                            add(head, int(target), "data_xref")
                except Exception:
                    pass
                try:
                    next_head = self.db.bytes.get_next_head(head)
                except Exception:
                    next_head = None
                if next_head is None or int(next_head) <= head:
                    break
                else:
                    head = int(next_head)

        # Then inspect pointer-sized slots in conventional writable/readonly
        # data segments.  This catches tables where IDA did not create xrefs.
        for segment in self.db.segments:
            name = (self.db.segments.get_name(segment) or "").lower()
            klass = (self.db.segments.get_class(segment) or "").lower()
            if not (
                name.startswith((".data", ".rdata", "data", "__data", "__const"))
                or klass in {"data", "const"}
            ):
                continue
            start, end = int(segment.start_ea), int(segment.end_ea)
            head = start
            while head < end:
                try:
                    if self.db.bytes.is_head_at(head) and self.db.bytes.is_data_at(head):
                        item_size = int(self.db.bytes.get_data_size_at(head))
                        if item_size >= pointer_size:
                            for offset in range(0, item_size - pointer_size + 1, pointer_size):
                                slot = head + offset
                                try:
                                    target = (
                                        self.db.bytes.get_qword_at(slot, allow_uninitialized=True)
                                        if pointer_size == 8
                                        else self.db.bytes.get_dword_at(
                                            slot, allow_uninitialized=True
                                        )
                                    )
                                except Exception:
                                    continue
                                add(slot, int(target), "raw_pointer")
                except Exception:
                    pass
                try:
                    next_head = self.db.bytes.get_next_head(head)
                except Exception:
                    next_head = None
                if next_head is None or int(next_head) <= head:
                    break
                else:
                    head = int(next_head)

        for record in sorted(
            records.values(),
            key=lambda item: (int(item["source_ea"], 16), int(item["target_ea"], 16)),
        ):
            yield record

    def _pointer_size(self) -> int:
        bitness = self.metadata().get("bitness")
        try:
            return 8 if int(bitness) >= 64 else 4
        except (TypeError, ValueError):
            return 8

    def _valid_ea(self, ea: int) -> bool:
        if ea in (0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF):
            return False
        try:
            return self.db.segments.get_at(ea) is not None
        except Exception:
            return False

    def _classify_pointer_target(
        self,
        target_ea: int,
        import_names: dict[int, str],
        strings: dict[int, Any],
    ) -> tuple[str, str, str]:
        try:
            named_target = self.db.names.get_at(target_ea)
        except Exception:
            named_target = None
        target_name = import_names.get(target_ea) or named_target or "unknown"
        segment = None
        try:
            segment = self.db.segments.get_at(target_ea)
        except Exception:
            pass
        segment_name = (self.db.segments.get_name(segment) if segment else "").lower()
        import_segments = {
            "extern",
            ".idata",
            "idata",
            ".got",
            "got",
            ".got.plt",
            "got.plt",
            "__la_symbol_ptr",
            "__nl_symbol_ptr",
        }
        if (
            target_ea in import_names
            or target_name.startswith(("__imp_", "imp_"))
            or segment_name in import_segments
        ):
            return target_name, "import_pointer", "import_entry"
        string = strings.get(target_ea)
        if string is not None:
            try:
                preview = str(string).replace("\r", " ").replace("\n", " ")[:80]
            except Exception:
                preview = "string_literal"
            return target_name, "string_pointer", preview
        try:
            function = self.db.functions.get_at(target_ea)
        except Exception:
            function = None
        if function is not None:
            function_start = int(function.start_ea)
            function_name = self.db.functions.get_name(function) or f"sub_{function_start:X}"
            if function_start == target_ea:
                return (
                    target_name if target_name != "unknown" else function_name,
                    "function_pointer",
                    "function_start",
                )
            return (
                target_name if target_name != "unknown" else function_name,
                "code_pointer",
                f"inside_{function_name}",
            )
        try:
            if self.db.bytes.is_code_at(target_ea):
                return target_name, "code_pointer", "instruction"
            if self.db.bytes.is_struct_at(target_ea):
                return target_name, "struct_pointer", "struct_data"
            if self.db.bytes.is_data_at(target_ea):
                size = self.db.bytes.get_data_size_at(target_ea)
                return target_name, "data_pointer", f"data_item_size={size}"
        except Exception:
            pass
        return target_name, "unknown_pointer", ""


def _ea(value: int) -> str:
    return f"0x{value:X}"


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _plain_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return None


def _plain_value(value: Any) -> Any:
    """Best-effort conversion for dataclasses/enums/IDA wrapper values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if dataclasses.is_dataclass(value):
        return {str(key): _plain_value(item) for key, item in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _plain_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain_value(item) for item in value]
    name = getattr(value, "name", None)
    if name is not None:
        numeric = _int_or_none(value)
        return {"name": str(name), "value": numeric} if numeric is not None else str(name)
    return _plain_text(value)


def _localized_items(values: Iterable[Any]) -> Iterator[tuple[Any, Exception | None]]:
    """Iterate a backend collection without leaking deferred IDA errors."""
    try:
        iterator = iter(values)
    except Exception as exc:
        yield None, exc
        return
    while True:
        try:
            yield next(iterator), None
        except StopIteration:
            return
        except Exception as exc:
            yield None, exc
            return


def _hex_sort(value: Any) -> int:
    if value is None:
        return -1
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return -1
