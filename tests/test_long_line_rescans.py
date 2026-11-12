"""The two rescans of a long line read only what can change (maisecrets/detection/reach.py).

A field label is put before a copy of its value and that copy is scanned again (fields.added), and a tool result is
scanned again in its cleaned copy around each changed line (core._changed_windows_scan). On a text of one long line
both read the whole text again. Since 0.9.7 a value or a line longer than reach.LONG is rescanned only as far as the
label or the change can reach, and the whole text only when that part shows something new.

The oracle is the scan of before: the same detector with reach.LONG set past every text, so both rescans read whole
lines as they did up to 0.9.6. Every generated text, one line and several, with values at the start, near 2,048,
near each cut and far from both, must give the same hits, span for span, with and without a field label.

Run: python3 -m unittest tests.test_long_line_rescans -v
"""
from __future__ import annotations

import json
import os
import random
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host  # noqa: E402
from maisecrets.detection import core, reach  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de"), languages=("en", "de"), source="long-line-test"),
             sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026))

WORDS = ("Die Anwendung speichert jede Antwort im Verlauf und zeigt sie im Bericht der Woche an. Der Kunde meldet "
         "einen Fehler beim Export der Tabelle, die Spalten verschieben sich um eins. Wir prüfen die Ursache im Modul "
         "für den Import und schreiben einen Test für den Fall. Die Messung ergab 42 Prozent weniger Zeit, im Mittel "
         "1,8 Sekunden pro Lauf bei 300 Läufen. The next step changes the order of the rules and measures again."
         ).split()
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _token(rnd: random.Random, prefix: str, n: int) -> str:
    return prefix + "".join(rnd.choice(ALNUM) for _ in range(n))


def _iban(rnd: random.Random) -> str:
    """A German IBAN with a valid check number, made at run time: the repository scan reads literals."""
    bban = "".join(rnd.choice("0123456789") for _ in range(18))
    n = int(bban + "131400")          # D=13, E=14, then 00
    return f"DE{98 - n % 97:02d}{bban}"


def _values(rnd: random.Random) -> list:
    """Values of real shape that a scan finds in the raw text."""
    return [
        _token(rnd, "gh" + "p_", 36),
        _token(rnd, "sk" + "_live_", 24),
        "AK" + "IA" + "".join(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)),
        f"{rnd.choice(['lena', 'jonas', 'mira'])}.{rnd.randint(10, 99)}@beispiel-firma.de",
        "IBAN " + _iban(rnd),
        "passwort: " + "Kx9" + _token(rnd, "", 9) + "!",
    ]


def _hidden(rnd: random.Random) -> str:
    """A value that only the cleaned copy finds: a zero-width space, an HTML entity or an ANSI code inside it."""
    tok = _token(rnd, "gh" + "p_", 36)
    how = rnd.choice(("zw", "entity", "ansi"))
    if how == "zw":
        return tok[:10] + "​" + tok[10:]
    if how == "entity":
        return tok[:2] + "&#112;" + tok[3:]           # p as an entity
    return tok[:8] + "\x1b[31m" + tok[8:]


def _labelled_start(rnd: random.Random) -> tuple:
    """(field name, a start of the value that is a finding only after that name)."""
    return rnd.choice([
        ("password", "Mauve-" + "Otter-" + str(rnd.randint(1000, 9999))),
        ("telefon", "0171 " + str(rnd.randint(1000000, 9999999))),
        ("api_key", _token(rnd, "", 32)),
    ])


def _prose(rnd: random.Random, n: int) -> str:
    out, size = [], 0
    while size < n:
        k = rnd.random()
        if k < 0.06:
            s = f"\n## Abschnitt {rnd.randint(1, 99)}\n\n- Punkt: {rnd.randint(10, 9999)} Einträge\n"
        elif k < 0.1:
            s = f"\n| Spalte | Wert |\n|---|---|\n| Läufe | {rnd.randint(1, 500)} |\n"
        else:
            s = " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(6, 24))) + " "
        out.append(s)
        size += len(s)
    return "".join(out)


def _place(body: str, items: list) -> str:
    """body with each (position, text) put in at the next space at or after the position, as a word."""
    for pos, item in sorted(items, reverse=True):
        i = body.find(" ", min(pos, len(body) - 1))
        i = len(body) if i < 0 else i
        body = body[:i] + " " + item + " " + body[i:]
    return body


def generated(seed: int) -> tuple:
    """(text, field name) of one case: a long body with values at the positions that the windows cut at, a
    hidden value far into it, and a start that only its field name makes a finding. Even seeds are one line of
    JSON, odd seeds keep their lines."""
    rnd = random.Random(seed)
    size = rnd.choice((reach.LONG + 3_000, 28_000, 34_000))
    body = _prose(rnd, size)
    hide = rnd.randint(reach.LABEL_REACH + 4_000, len(body) - 2_000)
    edges = [0, 40, 2_000, 2_060, 4_000, reach.LABEL_REACH - 30, reach.LABEL_REACH + 5, reach.LABEL_REACH + 700,
             hide - reach.COPY_MARGIN - 20, hide - reach.COPY_MARGIN + 30, hide - 4_000, hide - 2_048, hide - 300,
             hide + 200, hide + 2_048, hide + reach.COPY_MARGIN - 30, hide + reach.COPY_MARGIN + 40, len(body) - 50]
    vals = _values(rnd)
    items = [(p, rnd.choice(vals)) for p in edges if 0 <= p < len(body)]
    items.append((hide, _hidden(rnd)))
    if rnd.random() < 0.5:
        items.append((rnd.randint(200, reach.LABEL_REACH), _hidden(rnd)))   # a second change near the start
    body = _place(body, items)
    name, start = _labelled_start(rnd)
    body = start + " " + body
    if seed % 2 == 0:
        body = json.dumps({"model": "m", "messages": [{"role": "user", "content": body}]}, ensure_ascii=False)
    return body, name


def spans(ms) -> list:
    return [(m.kind, m.type, m.start, m.end) for m in ms]


def all_ways(text: str, name: str, every: bool = False) -> dict:
    """The hits of the text with a field over all of it, in both channels (the tool channel holds the hits of the
    text and of its cleaned copy); with `every` also bare, with a field over a part, and through scan()."""
    whole = [(0, len(text), ("messages", 1, name))]
    out = {
        "tool+field": spans(D.findings(text, channel="tool", fields=whole)),
        "prompt+field": spans(D.findings(text, channel="prompt", fields=whole)),
    }
    if every:
        part = [(len(text) // 3, len(text) - 10, (name,))]
        out["tool"] = spans(D.findings(text, channel="tool"))
        out["tool+part"] = spans(D.findings(text, channel="tool", fields=part))
        out["scan+field"] = spans(D.scan(text, channel="tool", fields=whole))
    return out


def as_before():
    """The scans of 0.9.6: no line and no value is long enough for a bounded rescan."""
    return mock.patch.object(reach, "LONG", 10 ** 12)


# a run of a few seconds; scratch runs of the same generator over many more seeds are named in the commit message
SEEDS = range(3)


class SameHitsAsTheWholeLineTests(unittest.TestCase):
    def test_generated_long_texts_give_the_hits_of_the_whole_line_rescans(self):
        hidden = labelled = 0
        for seed in SEEDS:
            text, name = generated(seed)
            with self.subTest(seed=seed, chars=len(text), lines=text.count("\n") + 1):
                with as_before():
                    want = all_ways(text, name)
                self.assertEqual(all_ways(text, name), want)
                # the premises: a value only the cleaned copy finds, a start only the label makes a finding
                hidden += any(t[3] - t[2] > 40 and t[1] == "SECRET" for t in want["tool+field"]) and \
                    len(want["tool+field"]) > len(want["prompt+field"])
                labelled += any(t[2] < 120 for t in want["tool+field"])
        self.assertEqual((hidden, labelled), (len(SEEDS), len(SEEDS)))

    def test_a_label_whose_reach_is_not_bounded_reads_the_whole_value(self):
        rnd = random.Random(3)
        known = [_token(rnd, "gh" + "p_", 36) for _ in range(160)]          # found bare: no hit near the label is new
        keys = ["".join(rnd.choice("0123456789abcdef") for _ in range(40)) for _ in range(200)]
        # the label's own word stands far on in the value, so no gate is opened and only the guard of the case holds
        cases = {
            # a list after its label runs on to its closing bracket: the keys far past the cut are found by the label
            "list": ("api_keys", "[" + ", ".join(f'"{v}"' for v in known + keys) + "] " + _prose(rnd, 4_000)
                     + " api_keys "),
            # a label that ends its line takes the next line that is not blank, however far
            "blank lines": ("password", "\n" * 7_000 + "Mauve-" + "Otter-4821 " + _prose(rnd, 12_000) + " password "),
            # the label opens a gate: a rule then reads the whole value
            "gate": ("curl", "-u admin:" + "Mauve-" + "Otter-4821 " + _prose(rnd, reach.LONG + 500)),
            # a value the label makes a finding at the start, the label's word far on (no gate to open): the part
            # scan finds it, and the whole value is scanned for it
            "start": ("password", "Mauve-" + "Otter-4821 " + _prose(rnd, 9_000) + " password " + _prose(rnd, 9_000)),
        }
        for case, (name, value) in cases.items():
            with self.subTest(case=case):
                field = [(0, len(value), (name,))]
                with as_before():
                    want = spans(D.findings(value, channel="tool", fields=field))
                self.assertGreater(len(want), len(spans(D.findings(value, channel="tool"))), "the premise")
                self.assertEqual(spans(D.findings(value, channel="tool", fields=field)), want)


class ProportionalWorkTests(unittest.TestCase):
    """The characters each rescan reads on one line of about 40,000 characters with one change far into it."""

    def setUp(self):
        rnd = random.Random(5)
        body = _place(_prose(rnd, 40_000), [(30_000, "wei­ter")])   # a soft hyphen far into the line
        self.text = json.dumps({"messages": [{"role": "user", "content": body}]}, ensure_ascii=False)
        self.assertNotIn("\n", self.text)

    def read(self, **kw) -> list:
        sizes = []
        real = core._scan

        def counting(text, *a, **k):
            sizes.append((len(text), bool(k.get("_copy"))))
            return real(text, *a, **k)
        with mock.patch.object(core, "_scan", counting):
            D.findings(self.text, channel="tool", **kw)
        return sizes

    def test_the_cleaned_copy_reads_a_window_around_the_change_not_the_line(self):
        copies = [n for n, copy in self.read() if copy]
        self.assertTrue(copies, "the premise: the soft hyphen makes a cleaned copy")
        self.assertLess(max(copies), len(self.text) // 2, copies)

    def test_the_label_reads_the_start_of_the_value_not_the_value(self):
        whole = [(0, len(self.text), ("messages", 0, "content"))]
        sizes = self.read(fields=whole)
        raw = [n for n, copy in sizes if not copy]
        self.assertEqual(raw[0], len(self.text), "the scan of the text")
        self.assertLess(max(raw[1:]), len(self.text) // 2, sizes)


if __name__ == "__main__":
    unittest.main()
