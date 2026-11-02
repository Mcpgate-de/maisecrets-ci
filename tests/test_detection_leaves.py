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
        (leaf, m), = L.findings_by_leaf(Det(), {"a": 'x"y'}, layout="json")
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


def _oracle(obj) -> list:
    """What the gateway's shadow finds: each string scanned alone after its last key (its own rule, not L._label: the
    shapes below have plain keys)."""
    out = []
    for leaf in L.json_text(obj)[1]:
        key = next((part for part in reversed(leaf.path) if isinstance(part, str)), "")
        lead = f"{key}: " if key else ""
        out += [(leaf.path, m.type, m.start - len(lead), m.end - len(lead))
                for m in D.findings(lead + leaf.value, channel="tool") if m.start >= len(lead)]
    return sorted(out)


def _got(obj, layout: str) -> list:
    return sorted((leaf.path, m.type, m.start, m.end) for leaf, m in L.findings_by_leaf(D, obj, layout=layout) if leaf)


class LinesLayoutTests(unittest.TestCase):
    """The shapes the gateway's check of 0.8.10 found (2026-11-02): in the JSON text a line break is two characters and
    a quote gets a backslash, and a record next to another gave it context. The layout "lines" finds what each string
    alone after its key finds. The values are synthetic."""
    SHAPES = {
        "a line break ends an address": {"body": "Hallo,\nbitte an meine Adresse: Hauptstraße 5, 10115 Berlin\n"
                                                 "Danke und Gruß\nTeam"},
        "JSON inside a string keeps its label": {"body": 'payload: {"username": "jdoe84", "role": "dev"}'},
        "a record gives no context to the next": [{"note": "Steuer-ID folgt im nächsten Feld"},
                                                  {"value": "860957" + "42719"}],
        # a Figma file key under file_key: after "file_key: " a key, in the JSON text not (gateway suite, 2026-11-02)
        "a key name is read as the label of its value": {"meta": {"components": [
            {"file_key": "qwert" + "7" + "yuiopas" + "42" + "dfghjkl", "name": "Button"}]}},
    }

    def test_the_json_layout_differs_on_these_shapes(self):
        for name, obj in self.SHAPES.items():
            with self.subTest(name):
                self.assertNotEqual(_got(obj, "json"), _oracle(obj), "the premise")

    def test_the_lines_layout_finds_what_each_string_after_its_key_finds(self):
        table = {"description": "| Büro | Straße | PLZ |\n|---|---|---|\n| Nord | Hafenweg 2 | 20457 |\n"
                                "| Süd | Bahnweg 9 | 80331 |"}
        for name, obj in {**self.SHAPES, "a markdown table": table}.items():
            with self.subTest(name):
                self.assertEqual(_got(obj, "lines"), _oracle(obj))
        self.assertTrue(_oracle(self.SHAPES["a line break ends an address"]), "the premise: an address is found")

    def test_one_call_per_record(self):
        calls = []

        class Det:
            def findings(self, text, channel, **kw):
                calls.append(text)
                return []
        L.findings_by_leaf(Det(), {"ok": "yes", "items": [{"a": "1", "b": {"c": ["2", "3"]}}, {"a": "4"}]})
        self.assertEqual(calls, ["ok: yes", "a: 1\nc: 2\nc: 3", "a: 4"])

    def test_a_key_that_could_change_the_label_line_is_no_label(self):
        want = {"email": "email", "file_key": "file_key", "Straße": "Straße", "a b": "a b",
                "x\rpassword": "", "x\u2028password": "", "x\u0085password": "", "x\x0bpassword": "", "x\npassword": "",
                "x:password": "", "x=password": "", "x|password": "", 'x"password': "", "x'password": "",
                "nextPageToken": "", "page_token": "", "k" * 65: "", "": ""}
        for key, label in want.items():
            with self.subTest(n=len(key)):
                self.assertEqual(L._label(("a", key)), label)

    def test_points_at_the_end_of_a_string_and_in_an_empty_string_keep_their_string(self):
        import dataclasses

        @dataclasses.dataclass(frozen=True)
        class M:
            start: int
            end: int
            type: str
            value: str

        class Det:
            def __init__(self, at):
                self.at = at

            def findings(self, text, channel, **kw):
                return [M(self.at(text), self.at(text), "X", "")]
        (leaf, m), = L.findings_by_leaf(Det(lambda t: t.index("abc") + 3), {"a": "abc", "b": "def"})
        self.assertEqual((leaf.value, m.start, m.end), ("abc", 3, 3))
        found = L.findings_by_leaf(Det(lambda t: 0), [["", "z"]])   # no labels: one scan for each string
        self.assertEqual([(leaf.value, m.start) for leaf, m in found], [("", 0), ("z", 0)])
        (leaf, m), = L.findings_by_leaf(Det(lambda t: len(t)), {"a": ""})
        self.assertEqual((leaf.value, m.start, m.end), ("", 0, 0))

    def test_placing_the_findings_grows_linearly(self):
        from _timing import assert_linear
        import dataclasses

        @dataclasses.dataclass(frozen=True)
        class M:
            start: int
            end: int
            type: str
            value: str

        class Det:
            def findings(self, text, channel, **kw):
                found, at = [], 0
                for line in text.split("\n"):
                    found.append(M(at + 3, at + 4, "X", ""))
                    at += len(line) + 1
                return found
        assert_linear(self, lambda obj: L.findings_by_leaf(Det(), obj), lambda n: {f"k{i}": "abcd" for i in range(n)},
                      16_000)

    def test_a_line_of_one_string_never_labels_a_string_without_a_label(self):
        v = "Zq8v" + "Lm2p" + "R7xw" + "Kd4n"   # built from parts: the repository scan reads literals
        for obj in ({"a": "prefix\npassword:", "": v}, {"a": "password:", "": v},
                    {"a": "prefix\npassword:", "nextPageToken": v}, {"a": "password:", "x=y": v}):
            with self.subTest(keys=list(obj)):
                self.assertEqual([x for x in _got(obj, "lines") if x[1] == "SECRET"], [])
        self.assertTrue([x for x in _got({"a": "x", "password": v}, "lines") if x[1] == "SECRET"],
                        "the premise: the value is a secret after its own label")

    def test_the_scan_texts_carry_no_unsafe_label(self):
        calls = []

        class Det:
            def findings(self, text, channel, **kw):
                calls.append(text)
                return []
        L.findings_by_leaf(Det(), {"email": "a", "x\rpassword": "b", "x=password": "c", "nextPageToken": "d"})
        self.assertEqual(calls, ["email: a", "b", "c", "d"])

    def test_the_name_of_a_persons_role_is_read_after_its_role(self):
        calls = []

        class Det:
            def findings(self, text, channel, **kw):
                calls.append(text)
                return []
        L.findings_by_leaf(Det(), {"author": {"name": "a"}, "reviewers": [{"name": "b"}],
                                   "fields": {"assignee": {"displayName": "c"}}, "project": {"name": "d"}})
        # the object's own strings are one record; the item of the list "reviewers" is a record of its own
        self.assertEqual(calls, ["author_name: a\nassignee_display_name: c\nname: d", "reviewer_name: b"])

    def test_a_surname_that_is_a_word_is_found_under_a_role_and_a_team_is_not(self):
        name = "Nora" + " " + "Baker"
        self.assertEqual([m.type for _l, m in L.findings_by_leaf(D, {"name": name})], [], "the premise: weak label")
        for obj in ({"author": {"name": name}}, {"reviewers": [{"name": name}]},
                    {"fields": {"reporter": {"displayName": name}}}, {"merge_user": {"name": name}}):
            with self.subTest(obj=list(obj)):
                self.assertEqual([m.type for _l, m in L.findings_by_leaf(D, obj)], ["NAME"])
        for team in ("Deleted User", "Platform Team", "Human Resources", "Plattform Mannschaft", "GitLab Bot"):
            with self.subTest(team=team):
                self.assertEqual([m for _l, m in L.findings_by_leaf(D, {"author": {"name": team}})], [])

    def test_an_unknown_layout_is_refused(self):
        with self.assertRaises(ValueError):
            L.findings_by_leaf(D, {}, layout="xml")


if __name__ == "__main__":
    unittest.main()
