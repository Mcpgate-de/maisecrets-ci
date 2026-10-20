"""The detection core as a package (maisecrets/detection/): a small API in __all__, the old names of maisecrets.* as the
same module objects, the rule data next to the core, and a library caller that imports nothing of the plugin.

Run: python3 -m unittest tests.test_detection_package -v
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, detection  # noqa: E402

API = {"Active", "Detector", "Host", "LazyRegex", "Match", "NO_REFERENCES", "NO_SOURCES", "References", "Rule",
       "Sources", "THIS_COMPUTER", "resolve_regions", "user_rule"}
# maisecrets.<old name> -> the module of the package it is
OLD_NAMES = {"detect": "core", "checksums": "checksums", "lazy_regex": "lazy_regex", "normalise": "normalise",
             "regions": "regions", "registry": "registry", "rulespec": "rulespec", "rule_filter": "rule_filter",
             "personal": "personal"}


def fresh(code: str, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
    return subprocess.run([sys.executable, "-I", "-c", "import sys\nsys.path.insert(0, sys.argv[1])\n" + code,
                           str(ROOT), *args], capture_output=True, text=True, env=env, timeout=120)


class ApiTests(unittest.TestCase):
    def test_the_api_is_the_names_of_all_and_each_is_there(self):
        self.assertEqual(set(detection.__all__), API)
        for name in API:
            with self.subTest(name):
                self.assertTrue(hasattr(detection, name))
        self.assertIs(detection.Detector, detect.Detector)
        self.assertIs(detection.Active, sys.modules["maisecrets.detection.regions"].Active)

    def test_a_star_import_gives_the_api_only(self):
        ns: dict = {}
        exec("from maisecrets.detection import *", ns)
        # the warning of the deprecated LazyRegex leaves __warningregistry__ in the namespace
        self.assertEqual({k for k in ns if not k.startswith("__")}, API)

    def test_a_library_caller_imports_the_package_and_nothing_of_the_plugin(self):
        r = fresh('''
import json
from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES
d = Detector(regions=Active(regions=("generic", "us"), languages=("en",), source="lib"),
             sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="lib", year=2030))
kinds = [m.kind for m in d.findings(sys.argv[2], channel="tool")]
print(json.dumps([kinds, sorted(m for m in sys.modules if m.startswith("maisecrets"))]))
''', "SSN: " + "-".join(("536", "22", "8726")))
        self.assertEqual(r.returncode, 0, r.stderr)
        kinds, mods = json.loads(r.stdout)
        self.assertEqual(kinds, ["us-ssn#2"], "the premise: the scan ran")
        outside = [m for m in mods if m not in ("maisecrets", "maisecrets.detection")
                   and not m.startswith("maisecrets.detection.")]
        self.assertEqual(outside, [], "a library caller loads no module of the plugin and no old name")


class UserRuleTests(unittest.TestCase):
    """user_rule is the stable way to a rule of your own (docs/DETECTION.md, "The API"); LazyRegex is deprecated."""

    def test_the_signature_is_the_promised_one(self):
        import inspect
        params = inspect.signature(detection.user_rule).parameters
        self.assertEqual([(n, p.default) for n, p in params.items()],
                         [("id", inspect.Parameter.empty), ("type", inspect.Parameter.empty),
                          ("pattern", inspect.Parameter.empty), ("keywords", ()), ("secret_group", 0)])
        self.assertEqual([f.name for f in __import__("dataclasses").fields(detection.Match)][:5],
                         ["kind", "type", "value", "start", "end"])

    def test_a_rule_of_your_own_finds_its_group_in_a_detector(self):
        class Mine(detection.Sources):
            def user_rules(self):
                return [detection.user_rule("order-ref", "SECRET", r"ORD-(\d{6})", keywords=("ord-",),
                                            secret_group=1)]
        d = detection.Detector(regions=detection.Active(regions=("generic",), languages=("en",), source="t"),
                               sources=Mine(), references=detection.NO_REFERENCES,
                               host=detection.Host(user="t", year=2026))
        hits = [(m.kind, m.value) for m in d.findings("ref ORD-" + "123456 done", channel="tool")]
        self.assertEqual(hits, [("user:order-ref", "123456")])

    def test_a_wrong_argument_raises_value_error(self):
        for kw in ({"id": "a b", "type": "SECRET", "pattern": "x"}, {"id": "a", "type": "secret", "pattern": "x"},
                   {"id": "a", "type": "SECRET", "pattern": "("},
                   {"id": "a", "type": "SECRET", "pattern": "x", "secret_group": 1},
                   {"id": "a", "type": "SECRET", "pattern": "x", "keywords": ("",)}):
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    detection.user_rule(**kw)

    def test_lazy_regex_still_imports_and_warns(self):
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            cls = detection.LazyRegex
        self.assertIs(cls, detect.LazyRegex)
        self.assertTrue(any(issubclass(x.category, DeprecationWarning) for x in w))


class OldNamesTests(unittest.TestCase):
    def test_each_old_name_is_the_module_of_the_package(self):
        import importlib
        for old, new in OLD_NAMES.items():
            with self.subTest(old):
                self.assertIs(importlib.import_module(f"maisecrets.{old}"),
                              importlib.import_module(f"maisecrets.detection.{new}"))

    def test_a_patch_through_the_old_name_reaches_the_core(self):
        text = "SSN: " + "-".join(("536", "22", "8726"))
        d = detection.Detector(regions=detection.Active(regions=("generic", "us"), languages=("en",), source="t"),
                               sources=detection.NO_SOURCES)
        self.assertEqual([m.kind for m in d.scan(text, channel="tool")], ["us-ssn#2"], "the premise")
        off = detection.Detector(regions=detection.Active(regions=("generic", "us"), languages=("en",), source="t"),
                                 sources=detection.NO_SOURCES)
        with mock.patch.object(detect, "allow_list", return_value=(frozenset(), frozenset({"us-ssn"}))):
            self.assertEqual([m.kind for m in off.scan(text, channel="tool")], [])

    def test_each_old_name_imports_first_in_a_fresh_process(self):
        for old, new in OLD_NAMES.items():
            with self.subTest(old):
                r = fresh(f"import maisecrets.{old}\n"
                          f"assert sys.modules['maisecrets.{old}'] is sys.modules['maisecrets.detection.{new}']\n")
                self.assertEqual(r.returncode, 0, r.stderr)
        for new in set(OLD_NAMES.values()):
            with self.subTest(new):
                r = fresh(f"import maisecrets.detection.{new}\n")
                self.assertEqual(r.returncode, 0, r.stderr)


class DataTests(unittest.TestCase):
    def test_the_rule_data_lies_next_to_the_core(self):
        self.assertEqual(detect.RULES_DIR, ROOT / "maisecrets" / "detection" / "rules")
        for name in ("betterleaks.json", "detect_secrets.json", "presidio.json", "own_secret_rules.json",
                     "prefixes.txt", "words_en.txt", "bip39_english.txt", "public_test_values.txt"):
            with self.subTest(name):
                self.assertTrue((detect.RULES_DIR / name).is_file())
        self.assertTrue(list((detect.RULES_DIR / "labels").glob("*.txt")))

    def test_the_plugin_keeps_only_its_own_two_files(self):
        self.assertEqual(sorted(p.name for p in (ROOT / "maisecrets" / "rules").iterdir()),
                         ["freemail_domains.txt", "term_stoplist.txt"])
        from maisecrets import placeholder, terms
        self.assertTrue(terms.stoplist(), "terms.py reads its stop list from maisecrets/rules")
        self.assertIn("gmail.com", placeholder.freemail_domains(), "placeholder.py reads its list from there")


if __name__ == "__main__":
    unittest.main()
