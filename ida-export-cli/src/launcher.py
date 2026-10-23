from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Iterator

from config import find_ida_dir, idapro_python_path
from exporter import SCHEMA_VERSION
from layout import validate_export
from version import __version__


HEARTBEAT_INTERVAL_SECONDS = 5
STALL_TIMEOUT_SECONDS = 10 * 60
HARD_TIMEOUT_SECONDS = 2 * 60 * 60
# Kept as an import-level alias for callers that previously inspected it.
WORKER_TIMEOUT_SECONDS = HARD_TIMEOUT_SECONDS


class _WorkerWatchdogTimeout(TimeoutError):
    def __init__(self, kind: str, elapsed: float):
        self.kind = kind
        self.elapsed = elapsed
        super().__init__(f"worker {kind} timeout after {elapsed:.1f}s")


class _TerminationRequested(SystemExit):
    def __init__(self, signum: int):
        self.signum = signum
        super().__init__(128 + signum)


def default_output(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.name}.ida-export")


def _worker_environment(
    input_path: Path,
    staging: Path,
    ida_dir: Path,
    work_dir: Path | None = None,
    launch_id: str | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    env["IDADIR"] = str(ida_dir)
    env["IDA_EXPORT_CLI_INPUT"] = str(input_path)
    env["IDA_EXPORT_CLI_STAGING"] = str(staging)
    if work_dir is not None:
        env["IDA_EXPORT_CLI_WORK"] = str(work_dir)
        env["IDA_EXPORT_CLI_HEARTBEAT"] = str(work_dir / "heartbeat.json")
    if launch_id is not None:
        env["IDA_EXPORT_CLI_LAUNCH_ID"] = launch_id
    package_path = str(idapro_python_path(ida_dir))
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = package_path if not current else package_path + os.pathsep + current
    return env


def _job_id(input_path: Path) -> str:
    digest = hashlib.sha256()
    with input_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    digest.update(f"\0{SCHEMA_VERSION}\0{__version__}".encode("ascii"))
    return digest.hexdigest()[:24]


def _wait_after_termination(process: subprocess.Popen[bytes], timeout: float) -> bool:
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False
    except (ChildProcessError, ProcessLookupError):
        return True


def _terminate_process_group(
    process: subprocess.Popen[bytes], grace_seconds: float = 5
) -> None:
    """Terminate the complete worker process group and reap its leader."""
    if os.name == "nt":
        try:
            process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
        except (AttributeError, OSError, ProcessLookupError):
            try:
                process.terminate()
            except (OSError, ProcessLookupError):
                pass
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    if _wait_after_termination(process, grace_seconds):
        return

    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    _wait_after_termination(process, grace_seconds)


def _heartbeat_token(path: Path, launch_id: str | None) -> bytes | None:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    if launch_id is not None and value.get("launch_id") != launch_id:
        return None
    return hashlib.sha256(payload).digest()


def _wait_with_watchdog(
    process: subprocess.Popen[bytes],
    heartbeat_path: Path,
    launch_id: str | None = None,
    *,
    heartbeat_interval: float = HEARTBEAT_INTERVAL_SECONDS,
    stall_timeout: float = STALL_TIMEOUT_SECONDS,
    hard_timeout: float = HARD_TIMEOUT_SECONDS,
) -> int:
    started = time.monotonic()
    last_progress = started
    last_token: bytes | None = None
    while True:
        now = time.monotonic()
        token = _heartbeat_token(heartbeat_path, launch_id)
        if token is not None and token != last_token:
            last_token = token
            last_progress = now
        elapsed = now - started
        stalled = now - last_progress
        if elapsed >= hard_timeout:
            raise _WorkerWatchdogTimeout("hard", elapsed)
        if stalled >= stall_timeout:
            raise _WorkerWatchdogTimeout("stall", stalled)
        wait_seconds = max(
            0.001,
            min(heartbeat_interval, hard_timeout - elapsed, stall_timeout - stalled),
        )
        try:
            return process.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired:
            continue


@contextlib.contextmanager
def _termination_signal_handlers() -> Iterator[None]:
    """Turn terminal signals into exceptions so run() can reap the worker."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous: dict[int, object] = {}

    def request_termination(signum: int, _frame: object) -> None:
        raise _TerminationRequested(signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, request_termination)
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _termination_reason(exc: BaseException) -> str:
    if isinstance(exc, _WorkerWatchdogTimeout):
        return f"{exc.kind} timeout"
    if isinstance(exc, _TerminationRequested):
        try:
            return f"signal {signal.Signals(exc.signum).name}"
        except ValueError:
            return f"signal {exc.signum}"
    if isinstance(exc, KeyboardInterrupt):
        return "keyboard interrupt"
    return type(exc).__name__


def _popen_group_options() -> dict[str, object]:
    if os.name == "nt":
        return {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        }
    return {"start_new_session": True}


def _configured_hard_timeout() -> float:
    # WORKER_TIMEOUT_SECONDS was the only timeout knob in 0.4.x. Respect a
    # test or embedding caller that still overrides that symbol while the
    # production default remains the new hard wall-clock bound.
    if WORKER_TIMEOUT_SECONDS != HARD_TIMEOUT_SECONDS:
        return float(WORKER_TIMEOUT_SECONDS)
    return float(HARD_TIMEOUT_SECONDS)


def _acquire_job_lock(lock_path: Path, task_log: Path):
    """Acquire a non-blocking process lock for one persistent export job."""
    lock_path.touch(exist_ok=True)
    stream = lock_path.open("r+b")
    try:
        if os.name == "nt":
            import msvcrt

            if lock_path.stat().st_size == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        stream.close()
        raise RuntimeError(
            "an export for this input is already running; "
            f"task log: {task_log}"
        ) from exc
    stream.seek(0)
    stream.truncate()
    stream.write(f"pid={os.getpid()}\n".encode("ascii"))
    stream.flush()
    return stream


def _release_job_lock(stream) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        stream.close()


def _task_log_tail(path: Path, limit: int = 20) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-limit:])


def _publish(staging: Path, output: Path) -> None:
    backup = output.with_name(f".{output.name}.backup-{uuid.uuid4().hex}")
    had_output = output.exists()
    try:
        if had_output:
            output.rename(backup)
        staging.rename(output)
    except BaseException:
        if had_output and backup.exists() and not output.exists():
            backup.rename(output)
        raise
    else:
        if backup.is_dir():
            shutil.rmtree(backup)
        elif backup.exists():
            backup.unlink()


def _write_complete_marker(staging: Path) -> None:
    destination = staging / "COMPLETE"
    temporary = staging / f".COMPLETE.{os.getpid()}.tmp"
    with temporary.open("w", encoding="ascii") as stream:
        stream.write(f"schema={SCHEMA_VERSION}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


def run(input_path: Path, output: Path) -> Path:
    input_path = input_path.expanduser().resolve()
    output = output.expanduser().resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"input is not a file: {input_path}")
    if output == input_path:
        raise ValueError("output directory must not be the input file")
    if output.exists() and not output.is_dir():
        raise ValueError(f"output path is not a directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    work_dir = output.parent / ".ida-export-work" / _job_id(input_path)
    staging = work_dir / "snapshot"
    staging.mkdir(parents=True, exist_ok=True)
    task_log = work_dir / "task.log"
    task_log.touch(exist_ok=True)
    job_lock = _acquire_job_lock(work_dir / ".job.lock", task_log)

    try:
        with task_log.open("ab") as log_stream:
            log_stream.write(b"ida-export-cli: launcher started\n")
            log_stream.flush()
            try:
                ida_dir = find_ida_dir()
            except BaseException as exc:
                log_stream.write(
                    f"ida-export-cli: IDA discovery failed: {type(exc).__name__}: {exc}\n".encode()
                )
                log_stream.flush()
                raise
            launch_id = uuid.uuid4().hex
            heartbeat_path = work_dir / "heartbeat.json"
            heartbeat_path.unlink(missing_ok=True)
            process = subprocess.Popen(
                [sys.executable, "-m", "worker"],
                env=_worker_environment(
                    input_path, staging, ida_dir, work_dir, launch_id
                ),
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                **_popen_group_options(),
            )
            try:
                with _termination_signal_handlers():
                    return_code = _wait_with_watchdog(
                        process,
                        heartbeat_path,
                        launch_id,
                        hard_timeout=_configured_hard_timeout(),
                    )
            except BaseException as exc:
                reason = _termination_reason(exc)
                log_stream.write(
                    f"ida-export-cli: terminating worker process group: {reason}\n".encode()
                )
                log_stream.flush()
                _terminate_process_group(process)
                log_stream.write(b"ida-export-cli: worker process group terminated\n")
                log_stream.flush()
                if isinstance(exc, _WorkerWatchdogTimeout):
                    raise RuntimeError(
                        f"IDA analysis exceeded the {exc.kind} timeout; "
                        f"task.log: {task_log}"
                    ) from exc
                raise
        if return_code:
            detail = _task_log_tail(task_log)
            suffix = f"\n{detail}" if detail else ""
            raise RuntimeError(
                f"IDA worker exited with status {return_code}; task.log: {task_log}{suffix}"
            )
        shutil.copy2(task_log, staging / "task.log")
        validate_export(staging, require_complete=False)
        _write_complete_marker(staging)
        _publish(staging, output)
        shutil.rmtree(work_dir, ignore_errors=True)
        try:
            work_dir.parent.rmdir()
        except OSError:
            pass
        return output
    finally:
        _release_job_lock(job_lock)
