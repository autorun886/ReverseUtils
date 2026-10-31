"""Execute the real script entry block in IDA-style and terminal contexts."""
import ast
from pathlib import Path
import unittest

PLUGIN = Path(__file__).resolve().parents[2] / "entry_trace.py"


def execute_entrypoint(ida, status=0, failure=None):
    tree = ast.parse(PLUGIN.read_text(encoding="utf-8"))
    helpers = [node for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name == "_script_entrypoint"]
    block = tree.body[-1]
    assert isinstance(block, ast.If), "Expected the script entry guard"
    def main(argv=None):
        if failure is not None:
            raise failure
        return status
    scope = {"__name__": "__main__", "idaapi": object() if ida else None, "main": main}
    exec(compile(ast.Module(body=helpers + [block], type_ignores=[]), str(PLUGIN), "exec"), scope)


class EntrypointTests(unittest.TestCase):
    def test_ida_success_does_not_raise_system_exit(self):
        execute_entrypoint(ida=True)

    def test_ida_reported_failure_does_not_exit_host(self):
        execute_entrypoint(ida=True, status=1)

    def test_ida_help_does_not_raise_system_exit(self):
        execute_entrypoint(ida=True, failure=SystemExit(0))

    def test_ida_invalid_arguments_do_not_exit_host(self):
        execute_entrypoint(ida=True, failure=SystemExit(2))

    def test_cli_preserves_success_and_failure_exit_codes(self):
        for status in (0, 1):
            with self.subTest(status=status), self.assertRaises(SystemExit) as result:
                execute_entrypoint(ida=False, status=status)
            self.assertEqual(result.exception.code, status)

    def test_cli_preserves_argparse_exit_codes(self):
        for status in (0, 2):
            with self.subTest(status=status), self.assertRaises(SystemExit) as result:
                execute_entrypoint(ida=False, failure=SystemExit(status))
            self.assertEqual(result.exception.code, status)

    def test_unexpected_exceptions_remain_visible(self):
        with self.assertRaisesRegex(RuntimeError, "unexpected"):
            execute_entrypoint(ida=True, failure=RuntimeError("unexpected"))


if __name__ == "__main__":
    unittest.main()
