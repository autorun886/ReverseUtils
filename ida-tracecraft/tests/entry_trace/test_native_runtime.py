"""Opt-in integration checks against a compiled process and real local Frida.

Set TRACECRAFT_NATIVE_TESTS=1, then execute this file. Builds only in a temporary
directory; requires an existing gcc and frida Python package.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('tracecraft_native', ROOT / 'entry_trace.py')
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)


@unittest.skipUnless(os.environ.get('TRACECRAFT_NATIVE_TESTS') == '1', 'Opt-in native integration')
class NativeRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import frida
        cls.device = frida.get_local_device()
        cls.temp = tempfile.TemporaryDirectory(prefix='tracecraft-native-')
        cls.addClassCleanup(cls.cleanup_build)
        directory = Path(cls.temp.name)
        cls.exe = directory / ('fixture.exe' if os.name == 'nt' else 'fixture')
        cls.dll = directory / ('fixture.dll' if os.name == 'nt' else 'libfixture.so')
        source = str(Path(__file__).with_name('native_fixture.c'))
        compiler = shutil.which('gcc')
        if not compiler:
            raise RuntimeError('gcc is required for opt-in native tests')
        for target, options in [(cls.exe, [] if os.name == 'nt' else ['-rdynamic', '-pthread', '-ldl']),
                                (cls.dll, ['-shared', '-DFIXTURE_DLL'] + ([] if os.name == 'nt' else ['-fPIC']))]:
            subprocess.run([compiler, '-O0', '-g', source, '-o', str(target)] + options,
                           check=True, capture_output=True)

    @classmethod
    def cleanup_build(cls):
        # Windows may retain executable image mappings briefly after kill().
        for attempt in range(30):
            try:
                cls.temp.cleanup()
                return
            except PermissionError:
                if attempt == 29:
                    raise
                time.sleep(0.1)

    def setUp(self):
        self.resources = []
        self.addCleanup(self.close_resources)

    def spawn(self, argv):
        pid = self.device.spawn(argv)
        try:
            session = self.device.attach(pid)
        except Exception:
            self.kill(pid)
            raise
        self.resources.append((session, pid))
        return session, pid

    def close_resources(self):
        for session, pid in reversed(self.resources):
            self.close_session(session, pid)

    def start(self, request, dll=False, hook_types=None):
        # Probe DLL offsets in a temporary process, then unload that process.
        session, pid = self.spawn([str(self.exe)])
        probe = session.create_script('''
rpc.exports.info = function(path) {
 const m = path ? Module.load(path) : Process.mainModule;
 return {module:m.name, imagebase:m.base.toString(),
   functions:m.enumerateExports().filter(e=>e.name.startsWith('fixture_')).map(e=>({
     name:e.name, offset:e.address.sub(m.base).toString()})),
   threads:Process.enumerateThreads().map(t=>t.id)};
};''')
        probe.load()
        snapshot = probe.exports_sync.info(str(self.dll) if dll else None)
        if dll:
            # Use a fresh process so runtime observes delayed loading and removal.
            self.close_session(session, pid)
            self.resources.remove((session, pid))
            session, pid = self.spawn([str(self.exe), str(self.dll)])
        else:
            probe.unload()
        snapshot.update(schema=1, root=next(f['offset'] for f in snapshot['functions']
            if f['name'] == 'fixture_recursive'), selection_mode=request.get('mode', 'selected'))
        if hook_types:
            request = dict(request, plan={'hooks': [dict(offset=f['offset'], args=hook_types[f['name']])
                for f in snapshot['functions'] if f['name'] in hook_types]})
        source = trace.generate(dict(log_format='jsonl', **request), snapshot)['script']
        script = session.create_script(source)
        events, errors = [], []

        def log(level, message):
            for line in message.splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    errors.append(line)

        script.set_log_handler(log)
        script.on('message', lambda message, data: errors.append(message) if message['type'] == 'error' else None)
        script.load()
        self.device.resume(pid)
        return script, events, errors

    def kill(self, pid):
        try:
            self.device.kill(pid)
        except Exception:
            pass

    def close_session(self, session, pid):
        self.kill(pid)
        session.detach()

    def wait_for(self, predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.fail('Native runtime did not reach the expected state')

    def test_recursive_calls_multiple_threads_and_duration(self):
        script, events, errors = self.start(dict(mode='selected', duration=0.7, arg_types=['int']))
        self.wait_for(lambda: any(e.get('type') == 'stop' for e in events))
        status = script.exports_sync.status()
        self.assertEqual(errors, [])
        self.assertEqual(status['stopReason'], 'duration')
        enters = [e for e in events if e.get('type') == 'enter']
        self.assertGreater(len(enters), 20)
        self.assertGreaterEqual(len({e['tid'] for e in enters}), 2)
        self.assertTrue(any(e['name'] == 'fixture_recursive' for e in enters))
        self.assertEqual(status['hookFailures'], 0)

    def test_delayed_module_unload_reload(self):
        script, events, errors = self.start(dict(mode='selected', arg_types=['int']), dll=True)
        self.wait_for(lambda: sum(e.get('state') == 'ready' for e in events) >= 3)
        script.exports_sync.stop()
        self.assertEqual(errors, [])
        self.assertTrue(any(e.get('type') == 'enter' for e in events))
        self.assertGreaterEqual(sum(e.get('state') == 'waiting-module' for e in events), 3)

    def test_stalker_window_budget(self):
        script, events, errors = self.start(dict(mode='window', window_size=5, max_events=10))
        self.wait_for(lambda: any(e.get('type') == 'stop' for e in events))
        status = script.exports_sync.status()
        self.assertEqual(errors, [])
        self.assertEqual(status['stopReason'], 'max-events')
        self.assertEqual(status['accepted'], 10)
        self.assertEqual(sum(e.get('type') == 'entry' for e in events), 10)

    def test_strings_and_invalid_pointer_reads(self):
        # Reading the integer first argument as a string intentionally exercises
        # bounded read failure without changing what the native function receives.
        script, events, errors = self.start(dict(mode='selected', duration=0.4), hook_types={
            'fixture_recursive': ['cstring'], 'fixture_hot': ['int', 'cstring']})
        self.wait_for(lambda: any(e.get('type') == 'stop' for e in events))
        self.assertEqual(errors, [])
        self.assertGreater(script.exports_sync.status()['readErrors'], 0)
        self.assertTrue(any(e.get('args', [None, None])[-1] in ('main', 'worker')
                            for e in events if e.get('type') == 'enter'),
                        repr([e.get('args') for e in events if e.get('name') == 'fixture_hot'][:4]))

    def test_stalker_history_snapshots(self):
        script, events, errors = self.start(dict(mode='history', duration=0.5,
            history_size=5, window_size=5))
        self.wait_for(lambda: any(e.get('type') == 'stop' for e in events))
        self.assertEqual(errors, [])
        self.assertTrue(any(e.get('phase') == 'before' for e in events))
        self.assertTrue(any(e.get('phase') == 'after' for e in events),
                        json.dumps(dict(status=script.exports_sync.status(), events=events[-15:])))
        self.assertGreater(script.exports_sync.status()['historySnapshots'], 1)

    def test_full_trace_spawned_main_thread(self):
        script, events, errors = self.start(dict(mode='full', duration=1.2))
        self.wait_for(lambda: any(e.get('type') == 'stop' for e in events))
        self.assertEqual(errors, [])
        self.assertTrue(any(e.get('type') == 'entry' for e in events),
                        json.dumps(script.exports_sync.status()))


if __name__ == '__main__':
    unittest.main()
