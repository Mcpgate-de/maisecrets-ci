"""In a record scan (leaves.findings_by_leaf), a negative context of one field does not hide a finding of another: the
record finds every span that a scan of the field alone after its label finds. The gateway's review fuzzed 38 kinds of
neighbour and found a test marker (def test_, import pytest, class Test …) 40 lines up and a company word on the line
before an address suppressing findings in other fields (2026-11-03). Synthetic values, built from parts."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import Active, Detector, leaves  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de"), languages=("en", "de"), source="record test"))
PW = "Qz" + "7!vRk2" + "pLm9"
TOKEN = "a8f3" + "K9zQx2" + "Lm7vPwR4tY"
STREET = "Linden" + "strasse 12, 10115 Berlin"
SURNAME = "Kowal" + "czyk"


def _iban() -> str:
    bban = "37040044" + "0532013000"
    num = int("".join(str(int(c, 36)) for c in bban + "DE00"))
    return f"DE{98 - num % 97:02d}{bban}"


TARGETS = [("password", PW), ("note", "Passwort: " + PW), ("api_key", TOKEN), ("comment", "token=" + TOKEN),
           ("address", STREET), ("iban", _iban()), ("name", "Svet" + "lana " + SURNAME)]
NEIGHBOURS = {
    "test def": "x = 1\ndef test_login():\n    pass",
    "import pytest": "notes\nimport pytest",
    "describe": "ok\ndescribe('login', () => {",
    "class Test": "y\nclass TestLogin:",
    "func Test": "z\nfunc TestLogin(t *testing.T) {",
    "grep path": "tests/test_auth.py:12: assert ok",
    "diff": "diff --git a/tests/test_a.py b/tests/test_a.py\n+++ b/tests/test_a.py",
    "company": "Beispiel GmbH",
    "hotel": "Hotel Adlon",
    "office": "Office",
    "firmensitz": "Firmensitz",
    "curl": "curl -H 'x: y' \\",
    "pem": "-----BEGIN CERTIFICATE-----",
    "html": "&lt;b&gt;x&lt;/b&gt;",
    "csv header": "id;status;code",
    "json example": '{"example": {',
}


def _leaf_spans(obj) -> list:
    """(path, start, end) of each span a scan of one field alone after its label finds."""
    out = []
    for leaf in leaves.json_text(obj)[1]:
        label = leaves.label(leaf.path)
        lead = f"{label}: " if label else ""
        for m in D.findings(lead + leaf.value, channel="tool"):
            a, b = max(m.start - len(lead), 0), m.end - len(lead)
            if b > a:
                out.append((leaf.path, a, b))
    return out


def _lost(obj) -> list:
    covered: dict = {}
    for leaf, m in leaves.findings_by_leaf(D, obj, channel="tool"):
        if leaf is not None:
            covered.setdefault(leaf.path, set()).update(range(m.start, m.end))
    return [(p, a, b) for p, a, b in _leaf_spans(obj) if not set(range(a, b)) <= covered.get(p, set())]


class RecordNegativeContextTests(unittest.TestCase):
    def test_a_neighbour_field_hides_no_finding(self):
        checked = 0
        for kind, neighbour in NEIGHBOURS.items():
            for key, value in TARGETS:
                for obj in ({"text": neighbour, key: value}, {"items": [{"body": neighbour, key: value}]}):
                    with self.subTest(neighbour=kind, target=key):
                        alone = _leaf_spans(obj)
                        self.assertTrue(alone, "premise: the field alone has a finding")
                        self.assertEqual(_lost(obj), [])
                        checked += 1
        self.assertEqual(checked, len(NEIGHBOURS) * len(TARGETS) * 2)

    def test_each_field_decodes_with_its_own_budget(self):
        # the decode stage spends at most 64 runs per text; a record shared them across its fields, so 70 hashes kept a
        # base64 secret in a later field from being decoded (gateway review, 2026-11-03)
        import base64
        import hashlib
        token = "gh" + "p_" + "".join("abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7) % 36] for i in range(36))
        blob = base64.b64encode(f"export GITHUB_TOKEN={token}\n".encode()).decode()
        obj = {f"h{i}": hashlib.sha1(str(i).encode()).hexdigest() for i in range(70)}
        obj["blob"] = blob
        self.assertTrue([m for m in D.findings("blob: " + blob, channel="tool") if m.type == "SECRET"],
                        "premise: the field alone decodes it")
        self.assertEqual(_lost(obj), [])

    def test_a_test_marker_inside_the_field_still_counts(self):
        # the boundary only stops a context of ANOTHER field: a marker in the field's own text still marks a fixture
        obj = {"code": "def test_login():\n    password = '" + PW + "'"}
        alone = _leaf_spans(obj)
        record = [(leaf.path, m.start, m.end) for leaf, m in leaves.findings_by_leaf(D, obj, channel="tool")]
        self.assertEqual(sorted(record), sorted(alone))

    def test_a_positive_context_still_spans_the_record(self):
        # the record keeps what a field gives its neighbour: first and last name in two fields
        obj = {"first_name": "Svet" + "lana", "last_name": SURNAME}
        kinds = {(leaf.path, m.type) for leaf, m in leaves.findings_by_leaf(D, obj, channel="tool") if leaf}
        self.assertIn((("last_name",), "NAME"), kinds)


if __name__ == "__main__":
    unittest.main()
