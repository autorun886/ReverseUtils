"""Instance directory and routing tests; no IDA installation is required."""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("tracecraft_instance_tests", ROOT / "entry_trace.py")
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)


class InstanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tracecraft-instances-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.registry = trace.InstanceRegistry(self.directory)
        self.state_patch = mock.patch.object(trace, "state_directory", return_value=self.directory)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)

    def identity(self, name="one.so", folder="a"):
        return dict(input_path=str(self.directory / folder / name),
                    idb_path=str(self.directory / folder / (name + ".i64")),
                    module=name, database_hash="hash")

    def service(self, name="one.so", folder="a", **options):
        identity = self.identity(name, folder)
        current = [identity]
        options.setdefault("identity_provider", lambda: current[0])
        options.setdefault("dispatcher", lambda request: dict(input_path=current[0]["input_path"], functions=[]))
        service = trace.LocalService(registry=self.registry, **options)
        self.addCleanup(service.stop)
        return service, current

    def test_dynamic_ports_minimal_listing_and_selection(self):
        one, _ = self.service("one.so")
        two, _ = self.service("two.so")
        self.assertNotEqual(one.port, two.port)
        self.assertNotEqual(one._record["id"], two._record["id"])
        self.assertRegex(one._record["id"], r"^[a-z][a-z0-9]{3,15}$")
        rows = trace.list_instances()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(set(row) == {"id", "endpoint", "input_path"} for row in rows))
        self.assertEqual(trace.discover_instance(instance=one._record["id"])["port"], one.port)
        self.assertEqual(trace.discover_instance(instance=str(os.getpid()), port=two.port)["id"], two._record["id"])
        self.assertEqual(trace.discover_instance(input_name="TWO.SO")["id"], two._record["id"])
        self.assertEqual(trace.discover_instance(input_name=two.identity["input_path"])["id"], two._record["id"])
        with self.assertRaisesRegex(RuntimeError, "Multiple IDA"):
            trace.discover_instance()
        with self.assertRaisesRegex(RuntimeError, "No matching"):
            trace.discover_instance(instance="missing")

    def test_same_filename_requires_disambiguation(self):
        one, _ = self.service("same.so", "a")
        two, _ = self.service("same.so", "b")
        with self.assertRaisesRegex(RuntimeError, "Multiple IDA"):
            trace.discover_instance(input_name="same.so")
        self.assertEqual(trace.discover_instance(input_name=two.identity["input_path"])["id"], two._record["id"])
        self.assertEqual(trace.discover_instance(port=one.port, input_name="same.so")["id"], one._record["id"])

    def test_unreachable_duplicate_never_silently_selects_the_other_file(self):
        one, _ = self.service("same.so", "a")
        two, _ = self.service("same.so", "b")
        original = trace.local_request
        def request(record, *args, **kwargs):
            if record["id"] == one._record["id"]:
                raise TimeoutError("temporarily busy")
            return original(record, *args, **kwargs)
        with mock.patch.object(trace, "local_request", side_effect=request):
            with self.assertRaisesRegex(RuntimeError, "unavailable or changed"):
                trace.discover_instance(input_name="same.so")
            self.assertEqual(trace.discover_instance(instance=two._record["id"])["id"], two._record["id"])

    def test_filename_routing_does_not_probe_unrelated_instances(self):
        one, _ = self.service("one.so")
        two, _ = self.service("two.so")
        with mock.patch.object(trace, "local_request", wraps=trace.local_request) as request:
            trace.discover_instance(input_name="two.so")
        self.assertEqual([call.args[0]["id"] for call in request.call_args_list], [two._record["id"]])

    def test_generation_change_rejects_cached_request_and_rotates_registry(self):
        service, current = self.service()
        old = dict(service._record)
        current[0] = self.identity("two.so")
        with self.assertRaisesRegex(RuntimeError, "instance changed"):
            trace.local_request(old, "snapshot", {})
        new = dict(service._record)
        self.assertNotEqual(old["id"], new["id"])
        self.assertFalse((self.directory / (old["id"] + ".json")).exists())
        self.assertEqual([r["id"] for r in self.registry.records()], [new["id"]])
        self.assertEqual(trace.remote_snapshot({}, instance=new["id"])["input_path"], current[0]["input_path"])
        with self.assertRaisesRegex(RuntimeError, "No matching"):
            trace.discover_instance(instance=old["id"])

    def test_path_case_refresh_is_stable_hash_or_idb_change_rotates(self):
        service, current = self.service()
        original = service._record["id"]
        current[0] = dict(current[0], input_path=current[0]["input_path"].upper())
        service.refresh_identity()
        self.assertEqual(original, service._record["id"])
        current[0] = dict(current[0], database_hash="different")
        service.refresh_identity()
        second = service._record["id"]
        self.assertNotEqual(original, second)
        current[0] = dict(current[0], idb_path=str(self.directory / "saved.i64"))
        service.refresh_identity()
        self.assertNotEqual(second, service._record["id"])

    def test_change_during_collection_is_not_returned(self):
        current = [self.identity()]
        def collect(request):
            result = dict(input_path=current[0]["input_path"], functions=[])
            current[0] = self.identity("changed.so")
            return result
        service, _ = self.service(identity_provider=lambda: current[0], dispatcher=collect)
        with self.assertRaisesRegex(RuntimeError, "changed during"):
            trace.local_request(dict(service._record), "snapshot", {})

    def test_closed_and_reopened_database_gets_new_id(self):
        service, current = self.service()
        old = service._record["id"]
        original = dict(current[0])
        current[0] = None
        service.refresh_identity()
        self.assertEqual(trace.list_instances(), [])
        current[0] = original
        service.refresh_identity()
        self.assertNotEqual(old, service._record["id"])

    def test_no_retired_id_reuse_even_if_hash_collides(self):
        digest = mock.Mock()
        digest.digest.return_value = bytes(32)
        with mock.patch("hashlib.sha256", return_value=digest):
            service, current = self.service()
            ids = [service._record["id"]]
            for name in ["two.so", "three.so"]:
                current[0] = self.identity(name)
                service.refresh_identity()
                ids.append(service._record["id"])
        self.assertEqual(len(set(ids)), 3)
        self.assertEqual([len(value) for value in ids], [4, 5, 6])

    def test_closed_session_id_is_not_reused(self):
        digest = mock.Mock()
        digest.digest.return_value = bytes(32)
        with mock.patch("hashlib.sha256", return_value=digest):
            one, _ = self.service()
            old = one._record["id"]
            one.stop()
            two, _ = self.service("other.so")
        self.assertNotEqual(old, two._record["id"])
        self.assertTrue((self.directory / ".retired" / old).is_file())

    def test_registration_is_concurrent_and_atomic(self):
        def register(index):
            return self.registry.register(dict(self.identity("f%d.so" % index),
                pid=os.getpid(), port=30000 + index, token="test-token-with-enough-length",
                session="session-%d" % index, generation=1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(register, range(24)))
        self.assertEqual(len(self.registry.records()), 24)
        self.assertEqual(len({r["id"] for r in rows}), 24)
        self.assertEqual(list(self.directory.glob("*.tmp")), [])
        for row in rows:
            self.assertEqual(json.loads((self.directory / (row["id"] + ".json")).read_text()), row)

    def test_owner_checked_removal_and_malformed_records(self):
        service, _ = self.service()
        record = dict(service._record)
        self.registry.remove(dict(record, session="another-session"))
        self.assertEqual(len(self.registry.records()), 1)
        (self.directory / "bad.json").write_text("{")
        (self.directory / "legacy.json").write_text(json.dumps({"pid": 123, "port": 18420, "token": "old"}))
        (self.directory / "wrong.json").write_text(json.dumps(record))
        self.assertEqual(len(trace.list_instances()), 1)

    def test_dead_process_pruned_but_busy_live_process_retained(self):
        service, _ = self.service()
        with mock.patch.object(trace, "_pid_alive", return_value=None), \
             mock.patch.object(trace, "local_request", side_effect=TimeoutError()):
            self.assertEqual(trace.list_instances(), [])
        self.assertEqual(len(self.registry.records()), 1)
        old = dict(service._record, last_seen=time.time() - 1000)
        self.registry.publish(old)
        with mock.patch.object(trace, "_pid_alive", return_value=True), \
             mock.patch.object(trace, "local_request", side_effect=TimeoutError()):
            self.assertEqual(trace.list_instances(), [])
        self.assertEqual(len(self.registry.records()), 1)
        with mock.patch.object(trace, "_pid_alive", return_value=False):
            self.assertEqual(trace.list_instances(), [])
        self.assertEqual(self.registry.records(), [])

    def test_heartbeat_and_stop_remove_only_owned_record(self):
        one, _ = self.service("one.so", heartbeat_interval=0.03)
        two, _ = self.service("two.so")
        before = one._record["last_seen"]
        deadline = time.monotonic() + 2
        while one._record["last_seen"] <= before and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreater(one._record["last_seen"], before)
        one.stop()
        self.assertEqual([row["id"] for row in self.registry.records()], [two._record["id"]])

    def test_busy_instance_does_not_block_other_instance_or_info(self):
        entered, release = threading.Event(), threading.Event()
        def blocked(request):
            entered.set()
            release.wait(5)
            return dict(input_path=one.identity["input_path"], functions=[])
        one, _ = self.service("one.so", dispatcher=blocked)
        two, _ = self.service("two.so")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(trace.local_request, dict(one._record), "snapshot", {})
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(len(trace.list_instances()), 2)
                self.assertEqual(trace.remote_snapshot({}, instance=two._record["id"])["input_path"], two.identity["input_path"])
                self.assertFalse(future.done())
            finally:
                release.set()
            self.assertEqual(future.result(timeout=2)["instance_id"], one._record["id"])

    def test_credential_and_generation_header_are_both_required(self):
        service, _ = self.service()
        record = dict(service._record)
        with self.assertRaisesRegex(RuntimeError, "credentials"):
            trace.local_request(dict(record, token="wrong"), "info")
        with self.assertRaisesRegex(RuntimeError, "instance changed"):
            trace.local_request(dict(record, id="none"), "snapshot", {})

    def test_explicit_input_overrides_default_port_environment(self):
        one, _ = self.service("one.so")
        two, _ = self.service("two.so")
        with mock.patch.dict(os.environ, {"TRACECRAFT_PORT": str(one.port)}):
            self.assertEqual(trace.discover_instance()["id"], one._record["id"])
            self.assertEqual(trace.discover_instance(input_name="two.so")["id"], two._record["id"])
            self.assertEqual(trace.discover_instance(instance=two._record["id"])["id"], two._record["id"])

    def test_pid_check_and_cross_process_cli(self):
        self.assertTrue(trace._pid_alive(os.getpid()))
        service, _ = self.service()
        # The CLI uses the same directory through its normal LOCALAPPDATA interface.
        appdata = self.directory / "appdata"
        target = appdata / "IDA-Tracecraft"
        target.mkdir(parents=True)
        for record in self.registry.records():
            (target / (record["id"] + ".json")).write_text(json.dumps(record), encoding="utf-8")
        environment = dict(os.environ, LOCALAPPDATA=str(appdata))
        environment.pop("TRACECRAFT_PORT", None)
        result = subprocess.run([sys.executable, str(ROOT / "entry_trace.py"), "instances"],
                                capture_output=True, text=True, encoding="utf-8", env=environment, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual([row["id"] for row in rows], [service._record["id"]])
        self.assertEqual(set(rows[0]), {"id", "endpoint", "input_path"})


if __name__ == "__main__":
    unittest.main()
