"""Push rustfrida and JavaScript to Android, stream output, optionally tee to a file."""
import argparse
import codecs
from pathlib import Path
import re
import queue
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import uuid

BASE = Path(__file__).resolve().parent
HOOKS = {
    'dlsym': 'hook_dlsym.js',
    'pthread_create': 'hook_pthread_create.js',
    'so_load': 'hook_so_load.js',
}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('-n', '--name', required=True, help='Android package/process name')
    p.add_argument('-o', '--output', type=Path, help='Local UTF-8 log file (overwrite)')
    selection = p.add_mutually_exclusive_group()
    selection.add_argument('-l', '--script', action='append', type=Path,
                   help='JS file; repeat to load multiple files; default: all three hooks')
    selection.add_argument('--only', nargs='+', choices=HOOKS,
                           help='Load only these built-in hooks')
    p.add_argument('--show', nargs='+', choices=HOOKS,
                   help='Show only these hook events; diagnostics and full file log are retained')
    p.add_argument('-s', '--serial', help='adb device serial')
    p.add_argument('--adb', default='adb', help='adb executable')
    p.add_argument('--rustfrida-dir', type=Path, default=BASE.parent / 'rustfrida')
    p.add_argument('--attach', action='store_true', help='Attach by name instead of spawning')
    p.add_argument('--no-su', action='store_true', help='Run directly (for an already-root adb shell)')
    p.add_argument('--duration', type=float, help='Stop after this many seconds of streaming')
    return p


def main():
    # Windows redirected stdout may default to GBK; rustfrida emits Unicode.
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    args = parser().parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:]*', args.name):
        parser().error('Invalid package/process name')
    if args.duration is not None and args.duration <= 0:
        parser().error('--duration must be positive')
    scripts = args.script or [BASE / 'rustfrida' / HOOKS[name]
                              for name in (args.only or HOOKS)]
    # Put the handle tracker first so its dlopen hook can also serve the load logger.
    scripts = sorted(scripts, key=lambda p: p.name != 'hook_dlsym.js')
    binary = args.rustfrida_dir / 'rustfrida'
    for path in [binary, *scripts]:
        if not path.is_file():
            parser().error(f'File not found: {path}')
    bundle = '\n'.join('(function () {\n' + p.read_text(encoding='utf-8-sig') +
                       '\n})();\n' for p in scripts)
    adb = [args.adb] + (['-s', args.serial] if args.serial else [])
    remote = '/data/local/tmp/rustfrida-' + uuid.uuid4().hex
    process = None
    prepared = False
    log = None
    output_queue = queue.Queue()
    reader = None
    display_pending = ''

    def display_line(line):
        if args.show:
            kind = event_kind(line)
            if kind and kind not in args.show:
                return
        sys.stdout.write(line)
        sys.stdout.flush()

    def emit(text):
        nonlocal display_pending
        if log:
            log.write(text)
            log.flush()
        if not args.show:
            sys.stdout.write(text)
            sys.stdout.flush()
            return
        display_pending += text
        while '\n' in display_pending:
            line, display_pending = display_pending.split('\n', 1)
            display_line(line + '\n')

    def run(*command):
        result = subprocess.run([*adb, *command], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=120)
        emit(result.stdout.decode('utf-8', errors='replace'))
        if result.returncode:
            raise RuntimeError(f'Command failed ({result.returncode}): {command[0]}')
        return result.stdout

    def shell(command):
        return ['shell', '-T', command if args.no_su else 'su -c ' + shlex.quote(command)]

    try:
        if args.output:
            log = args.output.open('w', encoding='utf-8', buffering=1)
        run('get-state')
        run(*shell('id'))
        run('shell', 'mkdir', '-p', remote)
        prepared = True
        run('push', str(binary), remote + '/rustfrida')
        with tempfile.TemporaryDirectory(prefix='rustfrida-') as temp:
            local = Path(temp) / 'hooks.js'
            local.write_text(bundle, encoding='utf-8')
            run('push', str(local), remote + '/hooks.js')
        run(*shell('chmod 755 ' + remote + '/rustfrida'))
        mode = '--name' if args.attach else '--spawn'
        command = (f'cd {remote} && echo $$ > runner.pid && exec ./rustfrida '
                   f'{mode} {shlex.quote(args.name)} --load-script {remote}/hooks.js')
        emit('[runner] ' + args.name + ' | ' + ', '.join(p.name for p in scripts) + '\n')
        # Keep the pipe open: EOF on stdin ends rustfrida's interactive session.
        process = subprocess.Popen([*adb, *shell(command)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')

        def read_output():
            try:
                while True:
                    data = process.stdout.read1(4096)
                    if not data:
                        break
                    output_queue.put(data)
            finally:
                output_queue.put(None)

        # A blocking pipe read on Windows can delay Ctrl+C indefinitely.
        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        started = time.monotonic()
        while True:
            if args.duration and time.monotonic() - started >= args.duration:
                emit('\n[runner] Duration reached; stopping session...\n')
                return 0
            try:
                data = output_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if data is None:
                break
            emit(decoder.decode(data))
        emit(decoder.decode(b'', final=True))
        return process.wait()
    except KeyboardInterrupt:
        emit('\n[runner] Stopping session...\n')
        return 130
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        emit(f'[runner] {exc}\n')
        return 1
    finally:
        if process and process.poll() is None:
            try:
                process.stdin.write(b'exit\n')
                process.stdin.flush()
                process.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired):
                # Only signal this session, never other rustfrida instances.
                try:
                    run(*shell(f'if [ -f {remote}/runner.pid ]; then '
                               f'kill -TERM "$(cat {remote}/runner.pid)"; fi'))
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    pass
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if process:
            if reader:
                reader.join(timeout=2)
                while not output_queue.empty():
                    data = output_queue.get_nowait()
                    if data:
                        emit(decoder.decode(data))
                emit(decoder.decode(b'', final=True))
            process.stdin.close()
            process.stdout.close()
        if prepared:
            try:
                # Fixed parent + generated hex session ID; no user-supplied deletion path.
                run(*shell('rm -rf ' + remote))
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                emit(f'[runner] Cleanup: {exc}\n')
        if log:
            log.close()
        if display_pending:
            display_line(display_pending)


def event_kind(line):
    """Classify only known hook events; retain startup/error diagnostics."""
    if '[JS]' not in line:
        return None
    if '[dlsym]' in line or '[dlsym_ret]' in line:
        return 'dlsym'
    if '[pthread_create]' in line:
        return 'pthread_create'
    if 'dlopen onEnter:' in line or 'dlopen onLeave fileName:' in line:
        return 'so_load'
    return None


if __name__ == '__main__':
    sys.exit(main())
