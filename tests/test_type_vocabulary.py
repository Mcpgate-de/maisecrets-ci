"""The published type vocabulary (maisecrets/detection/types.json, maisecrets.detection.TYPES; docs/DETECTION.md, "The
type vocabulary"): every type a rule, a pass or a path can put into Match.type is listed, and every listed type has a
rule or a pass that emits it. The emitted types are derived from the code and the rule data, not from a list here.

Run: python3 -m unittest tests.test_type_vocabulary -v
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import terms  # noqa: E402
from maisecrets.detection import TYPES, Active, core, personal, regions  # noqa: E402

FAMILIES = ("secret", "pii")


def every_region() -> tuple:
    """Every region a rule names: the regional rules, the Presidio recognizers and the regions with a language."""
    presidio = json.loads((core.RULES_DIR / "presidio.json").read_text(encoding="utf-8"))["recognizers"]
    return tuple(sorted({"generic"} | set(regions.REGION_LANGUAGE) | {d["region"] for d in core.REGIONAL_RULES}
                        | {core.presidio_region(r["id"]) for r in presidio}))


def emitted_types() -> dict:
    """{type: where it comes from} for every rule of every region and label language, and every pass."""
    active = Active(regions=every_region(), languages=tuple(regions.label_languages_available()), source="vocabulary")
    out: dict = {}
    for spec, rule in core.rule_specs(active):
        out.setdefault(rule.type, set()).add("rule " + spec.source)
    for spec in core.pass_specs():
        if spec.type == "COLUMN":
            # a table or record pass: the type of each value comes from its column name (personal._column_type), and
            # an account-number column gives ID_NUMBER
            columns = {personal._column_type(c) for c in personal._STRONG_COLS | personal._WEAK_COLS}
            for t in columns | {personal.ID_NUMBER}:
                out.setdefault(t, set()).add("pass " + spec.id)
        else:
            out.setdefault(spec.type, set()).add("pass " + spec.id)
    return out


class TheVocabulary(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.emitted = emitted_types()

    def test_every_type_a_rule_or_a_pass_emits_is_listed(self):
        missing = {t: sorted(w) for t, w in self.emitted.items() if t not in TYPES}
        self.assertEqual(missing, {}, "add each to maisecrets/detection/types.json with its family and class")

    def test_every_listed_type_is_emitted(self):
        # a type whose last rule went keeps its entry with "deprecated" (the deprecation path of docs/DETECTION.md):
        # a consumer of an older release can still meet it
        unused = sorted(t for t, v in TYPES.items() if t not in self.emitted and "deprecated" not in v)
        self.assertEqual(unused, [])

    def test_the_terms_and_the_imported_values_take_listed_types(self):
        # maisecrets/terms.py and values.py give their matches one of these types (the plugin, not the wheel)
        self.assertEqual(sorted(set(terms.TYPES) - set(TYPES)), [])

    def test_each_entry_has_a_family_and_a_class_of_the_benchmark(self):
        sys.path.insert(0, str(ROOT))
        from bench.cases import CLASSES
        for t, v in TYPES.items():
            with self.subTest(type=t):
                self.assertLessEqual({"family", "class"}, set(v))
                self.assertLessEqual(set(v), {"family", "class", "deprecated"})
                self.assertIn(v["family"], FAMILIES)
                # the family alone when the type does not say which kind (SECRET), else a class of the benchmark
                self.assertTrue(v["class"] == v["family"] or v["class"] in CLASSES, v["class"])
                self.assertTrue(v["class"].split(".")[0] == v["family"])

    def test_the_constant_is_the_file_and_cannot_be_changed(self):
        data = json.loads((ROOT / "maisecrets" / "detection" / "types.json").read_text(encoding="utf-8"))["types"]
        self.assertEqual({t: dict(v) for t, v in TYPES.items()}, data)
        with self.assertRaises(TypeError):
            TYPES["NEW"] = {"family": "pii", "class": "pii.name"}   # type: ignore[index]
        with self.assertRaises(TypeError):
            TYPES["SECRET"]["class"] = "pii.name"   # type: ignore[index]

    def test_the_benchmark_reads_its_classes_from_the_vocabulary(self):
        from bench import sources
        from bench.adapters import maisecrets as adapter
        for t, v in TYPES.items():
            self.assertEqual(sources.TYPE_CLASS[t], v["class"])
            self.assertEqual(adapter.cls_of(t), v["class"])


if __name__ == "__main__":
    unittest.main()
