"""scripts/measure_catalog_coverage.py on tiny catalog-shaped trees: it reads each catalog's examples as data, takes
the secret its regex reports, counts a rule as found bare or after a label, and never prints or writes an example
(docs/BENCHMARKS.md).

Run: python3 -m unittest tests.test_measure_catalog_coverage -v
The values are built at run time, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT / "scripts"))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import measure_catalog_coverage as mcc  # noqa: E402

RNG = random.Random(620)


def rnd(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def have_tomllib() -> bool:
    """The script reads the catalogs with tomllib (Python 3.11+) and PyYAML; without one it exits 2."""
    try:
        import tomllib  # noqa: F401
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


class CatalogCoverageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="catalogs-"))
        self.token = "gh" + "p_" + rnd(36)                 # a GitHub token: found bare
        self.word = "plain" + "_" + "configuration_value"  # no secret shape, no label rule takes it bare
        self.label_only = rnd(24)                          # random, no prefix: found only after `token = `
        np = self.root / "noseyparker" / "crates" / "noseyparker" / "data" / "default" / "builtin" / "rules"
        np.mkdir(parents=True)
        (np / "demo.yml").write_text(
            "rules:\n"
            "  - name: Demo token\n    id: np.demo.1\n    pattern: '(gh" + "p_[A-Za-z0-9]{36})'\n"
            f"    examples:\n      - 'GITHUB = {self.token}'\n"
            "  - name: Demo word\n    id: np.demo.2\n    pattern: 'cfg = ([a-z_]+)'\n"
            f"    examples:\n      - 'cfg = {self.word}'\n"
            "  - name: Demo random\n    id: np.demo.3\n    pattern: 'r=([A-Za-z0-9]{24})'\n"
            f"    examples:\n      - 'r={self.label_only}'\n"
            "  - name: No examples\n    id: np.demo.4\n    pattern: 'x'\n", encoding="utf-8")
        # the same id in a second file, with a value that is no secret: each rule keeps its own result (codex Gate A)
        (np / "demo2.yml").write_text(
            "rules:\n  - name: Demo token again\n    id: np.demo.1\n    pattern: 'cfg = ([a-z_]+)'\n"
            f"    examples:\n      - 'cfg = {self.word}'\n", encoding="utf-8")
        # a file that does not parse: left out by name, its text never printed
        (np / "broken.yml").write_text(f"rules:\n  - examples: [{self.label_only}\n", encoding="utf-8")
        gl = self.root / "gitleaks"
        (gl / "config").mkdir(parents=True)
        (gl / "cmd" / "generate" / "config" / "rules").mkdir(parents=True)
        (gl / "config" / "gitleaks.toml").write_text(
            '[[rules]]\nid = "demo-token"\nregex = \'\'\'(gh' + 'p_[0-9a-zA-Z]{36})\'\'\'\n', encoding="utf-8")
        (gl / "cmd" / "generate" / "config" / "rules" / "demo.go").write_text(
            "package rules\n\nfunc Demo() *config.Rule {\n\tr := config.Rule{\n\t\tRuleID: \"demo-token\",\n\t}\n"
            "\ttps := []string{\n\t\tutils.GenerateSampleSecret(\"demo\", \"gh" + "p_\" + secrets.NewSecret("
            "utils.AlphaNumeric(\"36\"))),\n\t}\n\treturn utils.Validate(r, tps, nil)\n}\n", encoding="utf-8")
        th = self.root / "trufflehog" / "pkg" / "detectors" / "demo"
        th.mkdir(parents=True)
        (th / "demo_test.go").write_text(
            "package demo\n\nvar (\n\tvalidPattern = \"demo token: " + self.token + "\"\n)\n\n"
            "func TestDemo(t *testing.T) {\n\ttests := []struct{ want []string }{\n"
            "\t\t{want: []string{\"" + self.token + "\"}},\n\t}\n}\n", encoding="utf-8")

    def run_script(self, *extra):
        out = self.root / "result.json"
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "measure_catalog_coverage.py"), str(self.root),
                            "--workers", "1", "--out", str(out), *extra],
                           capture_output=True, text=True, timeout=300, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        return r.stdout + r.stderr, json.loads(out.read_text(encoding="utf-8")), out.read_text(encoding="utf-8")

    def test_counts_found_bare_and_after_a_label_and_prints_no_example(self):
        if not have_tomllib():
            self.skipTest("tomllib is Python 3.11+, and the script needs PyYAML")
        printed, data, raw = self.run_script()
        np = data["counts"]["maisecrets"]["noseyparker"]
        self.assertEqual((np["rules"], np["with_examples"]), (5, 4))
        self.assertIn("broken.yml left out", printed)
        both = [(b, lab) for c, r, b, lab in data["rules"]["maisecrets"] if r == "np.demo.1"]
        self.assertEqual(sorted(both), [(False, False), (True, True)])
        rules = {(c, r): (b, lab) for c, r, b, lab in data["rules"]["maisecrets"] if r != "np.demo.1"}
        self.assertEqual(rules[("noseyparker", "np.demo.2")][0], False)
        self.assertEqual(rules[("noseyparker", "np.demo.3")], (False, True))
        self.assertEqual(rules[("gitleaks", "demo-token")], (True, True))     # built by NewSecret
        self.assertEqual(rules[("trufflehog", "demo")], (True, True))
        for value in (self.token, self.word, self.label_only):
            self.assertNotIn(value, printed)
            self.assertNotIn(value, raw)

    def test_a_baseline_gets_its_own_counts(self):
        if not have_tomllib():
            self.skipTest("tomllib is Python 3.11+, and the script needs PyYAML")
        printed, data, _ = self.run_script("--baseline", str(ROOT))
        self.assertEqual(data["counts"]["maisecrets"], data["counts"]["baseline"])
        self.assertIn("baseline bare", printed)

    def test_the_secret_is_the_part_the_catalogs_regex_reports(self):
        crx = mcc.compile_rx(r"(?i)key\s*=\s*([a-z0-9]{8})")
        self.assertEqual(mcc.secret_of(crx, "KEY = ab12cd34"), "ab12cd34")
        self.assertEqual(mcc.secret_of(None, "  whole  "), "whole")
        self.assertEqual(mcc.secret_of(mcc.compile_rx("nomatch"), "text"), "text")
        self.assertTrue(mcc.compile_rx(r"(?x) \b ( [[:alnum:]]{4} ) \b").fullmatch("ab12"))   # not a set of ":alnum"
        self.assertEqual(mcc._re2_to_python(r"[[:alnum:]]"), "[A-Za-z0-9]")

    def test_new_secret_is_seeded_and_matches_its_regex(self):
        import re
        for rx in (r"[a-z0-9]{32}", r"AKIA[0-9A-Z]{16}", r"(?:ab|cd)_[A-Fa-f0-9]{10,20}"):
            a = mcc.new_secret(rx, random.Random("r"))
            b = mcc.new_secret(rx, random.Random("r"))
            with self.subTest(rx=rx):
                self.assertEqual(a, b)
                self.assertRegex(a, "^" + rx + "$")
                self.assertTrue(re.fullmatch(rx, a))

    def test_the_go_examples_take_literals_variables_and_samples(self):
        src = ('prefix := "ab" + "cd"\n tps := []string{"x " + prefix, utils.GenerateSampleSecret("svc", "zz"),'
               ' unknownCall()}\n fps := []string{"no"}\n')
        got = mcc.GoExamples(mcc.go_tokens(src)).run()
        self.assertEqual(got[0], "x abcd")
        self.assertEqual((str(got[1]), got[1].secret), ('svc_api_token = "zz"', "zz"))
        self.assertEqual(len(got), 2)


if __name__ == "__main__":
    unittest.main()
