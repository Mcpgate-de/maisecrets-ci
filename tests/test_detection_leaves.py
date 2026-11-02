"""maisecrets/detection/leaves.py: one scan of an object's JSON text, each finding placed in its string.

The JSON text is the one json.dumps writes; a span comes back in the coordinates of the string the caller holds, also
when the string needs escapes; a finding in a key belongs to no string. The values are built from parts or are
placeholders of their own, so the repository scan finds no value.

Run: python3 -m unittest tests.test_detection_leaves -v
"""
from __future__ import annotations

import json
import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host  # noqa: E402
from maisecrets.detection import leaves as L  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de"), languages=("en", "de"), source="leaves-test"),
             sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026))
MAIL = "lena.weber" + "@" + "nordwerk.internal"
TOKEN = "glpat-" + "Xk2mQ9vR4tL8wZ1pB7nC"


class JsonTextTests(unittest.TestCase):
    def test_the_text_is_the_one_json_dumps_writes(self):
        rng = random.Random(7)
        chars = 'ab"\\\n\t\x00\x1fü€ 𝄞'
        for _ in range(500):
            s = "".join(rng.choice(chars) for _ in range(rng.randint(0, 10)))
            obj = {"k" + s: [s, {"n": 1, "f": 2.5, "b": True, "z": None, "s": s}], "t": (s,)}
            text, leaves = L.json_text(obj)
            self.assertEqual(text, json.dumps(obj, ensure_ascii=False))
            self.assertEqual([x.value for x in leaves], [s, s, s])
            self.assertEqual([x.path for x in leaves], [("k" + s, 0), ("k" + s, 1, "s"), ("t", 0)])

    def test_each_character_maps_to_its_place(self):
        text, leaves = L.json_text({"a": 'x"y\\z\nü\x01'})
        leaf = leaves[0]
        for i, ch in enumerate(leaf.value):
            part = text[leaf.start + leaf.places[i]:leaf.start + leaf.places[i + 1]]
            self.assertEqual(json.loads('"' + part + '"'), ch)

    def test_a_str_subclass_is_written_as_json_dumps_writes_it(self):
        class Odd(str):
            def __iter__(self):
                return iter("changed")

            def __str__(self):
                return "changed"
        obj = {Odd("key"): Odd("original")}
        text, leaves = L.json_text(obj)
        self.assertEqual(text, json.dumps(obj, ensure_ascii=False))
        self.assertEqual((leaves[0].path, leaves[0].value), (("key",), "original"))

    def test_a_depth_json_dumps_writes_is_written(self):
        obj = "deep"
        for _ in range(900):
            obj = [obj]
        try:
            want = json.dumps(obj, ensure_ascii=False)
        except RecursionError:
            self.skipTest("this interpreter's json.dumps stops before 900")
        text, leaves = L.json_text(obj)
        self.assertEqual(text, want)
        self.assertEqual(len(leaves[0].path), 900)
        deeper = "deep"
        for _ in range(20000):
            deeper = [deeper]
        self.assertEqual(L.json_text(deeper)[1][0].value, "deep")

    def test_what_json_cannot_hold_raises_as_json_does(self):
        with self.assertRaises(TypeError):
            L.json_text({"a": b"bytes"})
        loop = []
        loop.append(loop)
        with self.assertRaises(ValueError):
            L.json_text(loop)


class FindingsByLeafTests(unittest.TestCase):
    def test_a_span_is_one_of_the_string_the_caller_holds(self):
        obj = {"items": [{"author": {"email": MAIL}}, {"note": 'he said "hi"\n\tthe token ' + TOKEN}]}
        found = L.findings_by_leaf(D, obj)
        placed = [(leaf.path, m.type, leaf.value[m.start:m.end]) for leaf, m in found if leaf]
        self.assertIn((("items", 0, "author", "email"), "EMAIL", MAIL), placed)
        self.assertIn((("items", 1, "note"), "SECRET", TOKEN), [(p, t, v) for p, t, v in placed if t == "SECRET"])
        for leaf, m in found:
            if leaf:
                self.assertEqual(m.value, leaf.value[m.start:m.end])

    def test_it_finds_what_a_scan_of_each_string_after_its_key_finds(self):
        obj = {"user": {"email": MAIL, "phone": "+49 171 4829" + "173"}, "token": TOKEN, "title": "Release 2026.11"}
        one = sorted((leaf.path[-1], m.type, m.start, m.end) for leaf, m in L.findings_by_leaf(D, obj) if leaf)
        each = []
        for path, value in (("email", MAIL), ("phone", obj["user"]["phone"]), ("token", TOKEN),
                            ("title", obj["title"])):
            lead = len(path) + 2
            each += [(path, m.type, m.start - lead, m.end - lead)
                     for m in D.findings(f"{path}: {value}", channel="tool") if m.start >= lead]
        self.assertTrue(one, "the premise: something is found")
        self.assertEqual(one, sorted(each))

    def test_a_point_inside_an_escape_stays_a_point(self):
        import dataclasses

        @dataclasses.dataclass(frozen=True)
        class M:
            start: int
            end: int
            type: str
            value: str

        class Det:
            def findings(self, text, channel, **kw):
                at = text.index('\\"') + 1   # between the backslash and the quote of the escape
                return [M(at, at, "X", "")]
        (leaf, m), = L.findings_by_leaf(Det(), {"a": 'x"y'})
        self.assertEqual((m.start, m.end, m.value), (1, 1, ""))

    def test_a_record_can_add_a_finding_that_a_string_alone_does_not_give(self):
        # documented, not a defect: one scan sees the strings around a string (personal.py, the JSON record rules)
        first, last = "Ada" + "eze", "Hun" + "ter"
        found = {leaf.path[-1] for leaf, m in L.findings_by_leaf(D, {"last_name": last, "first_name": first}) if leaf}
        alone = {k for k, v in (("last_name", last), ("first_name", first))
                 if [m for m in D.findings(f"{k}: {v}", channel="tool") if m.start > len(k)]}
        self.assertLess(alone, found)
        self.assertIn("last_name", found - alone)

    def test_a_finding_in_a_key_belongs_to_no_string(self):
        found = L.findings_by_leaf(D, {MAIL: "x"})
        self.assertTrue(found, "the premise: the address in the key is found")
        self.assertTrue(all(leaf is None for leaf, _ in found))


if __name__ == "__main__":
    unittest.main()
