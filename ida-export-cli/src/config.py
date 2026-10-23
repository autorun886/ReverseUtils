from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any


class IdaNotFoundError(RuntimeError):
    pass


def stable_fingerprint(value: Any) -> str:
    """Return a deterministic fingerprint for JSON-compatible policy data."""
    payload = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _normalize_install_dir(path: Path) -> Path:
    path = path.expanduser().resolve()
    macos = path / "Contents" / "MacOS"
    return macos if macos.is_dir() else path


def _configured_install_dir() -> Path | None:
    config = Path.home() / ".idapro" / "ida-config.json"
    try:
        data = json.loads(config.read_text(encoding="utf-8"))
        value = data.get("Paths", {}).get("ida-install-dir")
        return Path(value) if value else None
    except (OSError, ValueError, TypeError):
        return None


def find_ida_dir() -> Path:
    candidates: list[Path] = []
    if value := os.environ.get("IDADIR"):
        candidates.append(Path(value))
    if configured := _configured_install_dir():
        candidates.append(configured)
    if sys.platform == "darwin":
        candidates.extend(
            sorted(
                Path("/Applications").glob("IDA Professional*.app"),
                reverse=True,
            )
        )
    candidates.extend([Path("/opt/ida"), Path("/opt/idapro")])

    for candidate in candidates:
        root = _normalize_install_dir(candidate)
        names = {
            "darwin": "libidalib.dylib",
            "linux": "libidalib.so",
            "win32": "idalib.dll",
        }
        library = names.get(sys.platform, "libidalib.so")
        if (root / library).is_file():
            return root
    raise IdaNotFoundError(
        "IDA idalib installation not found; set IDADIR or activate idalib with "
        "py-activate-idalib.py"
    )


def idapro_python_path(ida_dir: Path) -> Path:
    wheel_dir = ida_dir / "idalib" / "python"
    wheels = sorted(wheel_dir.glob("idapro-*.whl"), reverse=True)
    if wheels:
        return wheels[0]
    if (wheel_dir / "idapro" / "__init__.py").is_file():
        return wheel_dir
    raise IdaNotFoundError(f"idapro package not found below {ida_dir}")


def _idapro_wheel_version(ida_dir: Path) -> str | None:
    try:
        package_path = idapro_python_path(ida_dir)
    except IdaNotFoundError:
        return None
    wheel_name = package_path.name
    match = re.match(r"^idapro-([^-]+)-", wheel_name)
    if match:
        return match.group(1)
    if package_path.is_dir():
        for metadata_path in package_path.glob("idapro*.egg-info/PKG-INFO"):
            try:
                for line in metadata_path.read_text(encoding="utf-8").splitlines():
                    if line.startswith("Version:"):
                        return line.split(":", 1)[1].strip()
            except OSError:
                continue
    return None


def runtime_versions(ida_dir: Path) -> dict[str, str | None]:
    """Collect versions available before the idalib worker is initialized."""
    return {
        "python_version": platform.python_version(),
        "platform": sys.platform,
        "ida_domain_version": distribution_version("ida-domain"),
        "idapro_version": distribution_version("idapro")
        or _idapro_wheel_version(ida_dir),
    }


def ida_runtime_version() -> str | None:
    """Read the initialized IDA kernel version without initializing IDA here."""
    try:
        import ida_kernwin  # type: ignore

        value = ida_kernwin.get_kernel_version()
        return str(value) if value is not None else None
    except Exception:
        return None
