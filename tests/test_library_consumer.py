"""The detection core used as a library by a server, as foreign code would (examples/library_consumer.py).

The example runs in a new process with an empty environment, HOME at a folder that does not exist, and an audit hook
that records each file the process opens under HOME. It imports the public names of maisecrets.detection only.

Run: python3 -m unittest tests.test_library_consumer -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "library_consumer.py"

RUNNER = r'''
import json, os, runpy, sys
home = os.environ["HOME"]
opened = []
def audit(event, args):
    if event == "open" and isinstance(args[0], str) and args[0].startswith(home):
        opened.append(args[0])
sys.addaudithook(audit)
sys.argv = [sys.argv[1]]
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    runpy.run_path(sys.argv[0], run_name="__main__")
result = json.loads(buf.getvalue())
result["opened_under_home"] = opened
print(json.dumps(result))
'''


class LibraryConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "no-such-home")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "PYTHONPATH": str(ROOT),
                   "PYTHONDONTWRITEBYTECODE": "1"}
            p = subprocess.run([sys.executable, "-s", "-c", RUNNER, str(EXAMPLE)], capture_output=True, text=True,
                               env=env, cwd=tmp, timeout=600)
            cls.home_made = os.path.exists(home)
        if p.returncode != 0:
            raise AssertionError(p.stderr[-3000:])
        cls.r = json.loads(p.stdout)

    def test_no_plugin_module_and_no_file_under_home(self):
        self.assertEqual([], self.r["plugin_modules"])
        self.assertEqual([], self.r["opened_under_home"])
        self.assertFalse(self.home_made)

    def test_its_own_rule_regions_and_typed_findings(self):
        self.assertTrue(self.r["typed"])
        self.assertEqual(["email", "phone-us-national", "user:acme-ticket"], self.r["us_kinds"])
        self.assertEqual(["ACME_TICKET", "EMAIL", "PHONE"], self.r["us_types"])
        # the other detector has region generic only and no rule of its own
        self.assertEqual(["email"], self.r["generic_kinds"])

    def test_a_wrong_argument_of_user_rule_raises_value_error(self):
        self.assertEqual({"bad group", "bad regex", "bad type", "id with space"}, set(self.r["user_rule_errors"]))
        self.assertEqual({"ValueError"}, set(self.r["user_rule_errors"].values()))

    def test_reset_reads_the_rules_of_the_sources_again(self):
        self.assertFalse(self.r["before_reset"])
        self.assertTrue(self.r["after_reset"])

    def test_two_detectors_in_eight_threads_give_the_serial_result(self):
        self.assertEqual([], self.r["thread_errors"])
        self.assertTrue(self.r["threads_equal_serial"])

    def test_a_large_input_and_many_requests(self):
        self.assertTrue(self.r["big_found_mail"])
        self.assertGreater(self.r["big_chars"], 1_000_000)
        # 3000 different requests after a warm-up: measured 48 KB on 0.7.1; a cache per text would grow by MBs
        self.assertLess(self.r["growth_kb_3000_requests"], 1024)


if __name__ == "__main__":
    unittest.main()
