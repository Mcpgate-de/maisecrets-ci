"""scripts/run_tests_parallel.py: one process per test file, one log, the exit of the whole suite."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "run_tests_parallel.py"


def run_in(files: dict) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as d:
        Path(d, "tests").mkdir()
        for name, body in files.items():
            Path(d, "tests", name).write_text(textwrap.dedent(body), encoding="utf-8")
        return subprocess.run([sys.executable, str(RUNNER), "-j", "2"], cwd=d, capture_output=True, text=True,
                              timeout=120)


class ParallelRunnerTests(unittest.TestCase):
    def test_a_file_that_prints_an_inner_summary_counts_its_own(self):
        # test_guard runs unittest in a child, whose "Ran 0 tests" came first: the runner took it for the file's
        # own and failed a green file on Windows (2026-11-01)
        p = run_in({"test_inner.py": """\
            import unittest
            class T(unittest.TestCase):
                def test_prints_a_child_summary(self):
                    import sys
                    sys.stderr.write("\\nRan 0 tests in 0.000s\\n\\nNO TESTS RAN\\n")   # before the file's own
                    print("Ran 0 tests in 0.000s")                                # stdout: after it
            """})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("Ran 1 tests\nOK", p.stdout)

    def test_a_red_test_a_crash_and_a_file_without_tests_each_fail_the_run(self):
        for name, body in (("test_red.py", "import unittest\nclass T(unittest.TestCase):\n"
                                           "    def test_x(self):\n        self.fail('no')\n"),
                           ("test_crash.py", "raise ImportError('broken')\n"),
                           ("test_empty.py", "import unittest\n")):
            with self.subTest(name=name):
                p = run_in({name: body, "test_ok.py": "import unittest\nclass T(unittest.TestCase):\n"
                                                        "    def test_y(self):\n        pass\n"})
                self.assertEqual(p.returncode, 1, p.stdout)
                self.assertIn("FAILED: " + name[:-3], p.stdout)


if __name__ == "__main__":
    unittest.main()
