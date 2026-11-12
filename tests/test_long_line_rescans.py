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

import hashlib
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

from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host, Sources, user_rule  # noqa: E402
from maisecrets.detection import checksums, core, reach  # noqa: E402

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
SEEDS = range(5)


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


class CopyReachTests(unittest.TestCase):
    """A change of the cleaned copy that a hit far from it depends on: the window around the change is not enough,
    and the whole line is read (reach.py)."""

    @staticmethod
    def one_line(rnd: random.Random, n: int) -> str:
        return _prose(rnd, n).replace("\n", " ")

    def test_a_seed_phrase_with_its_context_word_far_back_on_its_line(self):
        rnd = random.Random(11)
        words = sorted(checksums.bip39_words(), key=checksums.bip39_words().get)
        entropy = bytes(rnd.randrange(256) for _ in range(16))
        bits = "".join(f"{b:08b}" for b in entropy) + f"{hashlib.sha256(entropy).digest()[0]:08b}"[:4]
        phrase = [words[int(bits[i:i + 11], 2)] for i in range(0, 132, 11)]
        self.assertTrue(checksums.bip39_ok(phrase), "the premise: a valid phrase, made at run time")
        phrase[5] = phrase[5][:2] + "\u00ad" + phrase[5][2:]      # the raw text holds 11 words and a broken one
        # the window around the change is less than half the line, so it is read in a window
        text = "my wallet seed backup follows later. " + self.one_line(rnd, 9_000) + " " + " ".join(phrase) + " " \
            + self.one_line(rnd, 16_000)
        with as_before():
            want = spans(D.findings(text, channel="tool"))
        self.assertEqual([t[0] for t in want], ["crypto-seed-phrase"], "the premise: found in the copy only")
        self.assertEqual(spans(D.findings(text, channel="tool")), want)

    def test_a_gate_word_the_cleaning_makes_far_from_the_value(self):
        class Own(Sources):
            def user_rules(self):
                # a rule of your own: its keyword gates it in the whole text, its regex does not hold the keyword
                return [user_rule("zebra-code", "SECRET", r"QX\d{6}", keywords=("zebra",))]
        d = Detector(regions=Active(regions=("generic",), languages=("en",), source="long-line-test"), sources=Own(),
                     references=NO_REFERENCES, host=Host(user="", year=2026))
        rnd = random.Random(12)
        text = "ze\u00adbra " + self.one_line(rnd, 9_000) + " QX" + "123456 " + self.one_line(rnd, 9_000)
        with as_before():
            want = spans(d.findings(text, channel="tool"))
        self.assertEqual([t[0] for t in want], ["user:zebra-code"], "the premise: the copy opens the rule")
        self.assertEqual(spans(d.findings(text, channel="tool")), want)


def _own(rule) -> Detector:
    class Own(Sources):
        def user_rules(self):
            return [rule]
    return Detector(regions=Active(regions=("generic",), languages=("en",), source="long-line-test"), sources=Own(),
                    references=NO_REFERENCES, host=Host(user="", year=2026))


class RulesOfYourOwnTests(unittest.TestCase):
    """A rule of your own may read any distance: with one, both rescans read the whole text (codex Gate A, b0848c45:
    both cases gave no hit where the scans of before gave one)."""

    def test_a_label_a_rule_of_your_own_reads_9000_characters_back(self):
        d = _own(user_rule("far-label", "SECRET", r"(?s)(?<=zebra: ).{9000}QX" + "123456"))
        value = "a " * 4_500 + "QX" + "123456 " + "b " * 6_000
        field = [(0, len(value), ("zebra",))]
        with as_before():
            want = spans(d.findings(value, channel="tool", fields=field))
        self.assertEqual([t[0] for t in want], ["user:far-label"], "the premise")
        self.assertEqual(spans(d.findings(value, channel="tool", fields=field)), want)

    def test_a_change_a_rule_of_your_own_reads_9000_characters_on(self):
        d = _own(user_rule("far-copy", "SECRET", r"(?s)[M]AGIC.{9000}QX" + "123456"))
        text = "MA\u00adGIC" + "a " * 4_500 + "QX" + "123456 " + "b " * 6_000
        with as_before():
            want = spans(d.findings(text, channel="tool"))
        self.assertEqual([t[0] for t in want], ["user:far-copy"], "the premise")
        self.assertEqual(spans(d.findings(text, channel="tool")), want)


    def test_with_a_rule_of_your_own_the_cleaned_copy_reads_the_whole_line(self):
        d = _own(user_rule("near", "SECRET", r"QX\d{6}"))
        rnd = random.Random(13)
        text = _place(_prose(rnd, 40_000).replace("\n", " "), [(30_000, "wei\u00adter")])
        sizes = []
        real = core._scan

        def counting(t, *a, **k):
            sizes.append((len(t), bool(k.get("_copy"))))
            return real(t, *a, **k)
        with mock.patch.object(core, "_scan", counting):
            d.findings(text, channel="tool")
        self.assertGreater(max(n for n, copy in sizes if copy), len(text) * 9 // 10, sizes)


class BuiltInReachTests(unittest.TestCase):
    """The reach of the built-in rules, worked out from their regexes (maisecrets/detection/regex_reach.py)."""

    def test_a_private_key_whose_header_the_cleaning_mends_far_from_its_end(self):
        # private-key reads from BEGIN to END over any characters: the window around the mended header holds no END,
        # so the rule is a far rule, and as it matches in the line the line is read whole
        rnd = random.Random(21)
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        body = " ".join("".join(rnd.choice(b64) for _ in range(64)) for _ in range(140))
        text = _prose(rnd, 3_000).replace("\n", " ") + " -----BEGIN PRIVATE K\u00adEY----- " + body \
            + " -----END PRIVATE KEY----- " + _prose(rnd, 16_000).replace("\n", " ")
        with as_before():
            want = spans(D.findings(text, channel="tool"))
        self.assertEqual([t[0] for t in want], ["private-key"], "the premise: found in the copy only")
        self.assertEqual(spans(D.findings(text, channel="tool")), want)

    def test_the_spread_of_known_shapes(self):
        from maisecrets.detection import regex_reach as rr
        self.assertLess(rr.spread(r"password\s*[:=]\s*(\S+)")[0], 200, "a label, a run of spaces, a token")
        self.assertGreaterEqual(rr.spread(r"(?s)[M]AGIC.{9000}QX")[0], 9000)
        self.assertGreaterEqual(rr.spread(r"(?<=zebra: ).{9000}QX")[1], 9000)
        self.assertEqual(rr.spread(r"key=(.+)$"), (rr.FAR, rr.FAR), "a dot runs over spaces without end")
        self.assertGreaterEqual(rr.spread(r"tok(?=.{0,6000}end)")[1], 6000, "a lookahead reads on")
        self.assertEqual(rr.spread(r"<(\w+) [^>]*>.*</\1>"), (rr.FAR, rr.FAR), "a back reference has no bound")
        self.assertLess(max(rr.spread(r"[A-Za-z0-9+/]{40,}")), 1, "no whitespace: it cannot cross a cut")

    def test_every_built_in_rule_that_reads_far_is_held_by_a_guard(self):
        from maisecrets.detection import regex_reach as rr, rescan
        with D.activate():
            order = core._in_scan_order(core.rules())
            far = {id(r) for r in rescan.far_rules(order)}
        limit = min(reach.COPY_MARGIN, reach.LABEL_REACH) - reach.CONTEXT
        for rule in order:
            if rescan.is_marker(rule) or id(rule) in far:
                continue
            with self.subTest(rule=rule.id):
                before, after = rr.spread(rule.regex.pattern, rule.regex.flags or 0)
                self.assertLess(before, limit)
                self.assertLess(after, reach.COPY_MARGIN - reach.AFTER)
        self.assertGreater(len(far), 0, "the premise: some built-in rules read far")

    def test_every_regex_of_the_core_over_a_whole_text_reads_near_or_is_guarded(self):
        # a regex that personal.py, core.py or a part runs over the whole text (`rx.finditer(text)`), found from the
        # syntax tree: one that can read far is a record reader (rescan.record_hits), a long personal match
        # (rescan.long_personal_match), the seed phrase (checksums), or reads a value or a path, not the text
        import ast
        import importlib
        from maisecrets.detection import regex_reach as rr
        reviewed = {
            ("personal", "_SQL_CREATE_RE"), ("personal", "_HTML_TABLE_RE"), ("personal", "_SQL_STMT_RE"),
            ("personal", "_JSON_STRING_RE"),                                     # record readers
            ("personal", "_DE_TITLE_RE"), ("personal", "_XML_NAME_ELEMENT_RE"),  # long_personal_match
            ("checksums", "_WORD_RUN_RE"),                                       # the seed phrase guard
            ("core", "_GENERIC_TYPE"), ("core", "_PART_TEMPLATE_RE"), ("core", "_LITERAL_PLACEHOLDER_RE"),
            ("core", "_CLOSED_TEMPLATE_RE"), ("core", "_EXPORT_NAME_RE"),         # a value or a path
            ("text_index", "_TEST_PATH_RE"), ("text_index", "_REAL_VALUE_FILE_RE"),   # a path
            ("fields", "_MD_KV_ROW_RE"), ("fields", "_WORD_SPLIT"),             # a table row of a line; a label
        }
        found = set()
        for name in ("personal", "core", "secret_table", "encoded_mail", "fields", "text_index", "value_checks",
                     "keyword_tail", "checksums", "own_rules", "normalise"):
            mod = importlib.import_module("maisecrets.detection." + name)
            for node in ast.walk(ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("finditer", "search", "findall", "sub", "subn", "split")
                        and isinstance(node.func.value, ast.Name) and len(node.args) == 1 and not node.keywords):
                    continue
                rx = getattr(mod, node.func.value.id, None)
                pattern = getattr(rx, "pattern", None)
                if not isinstance(pattern, str):
                    continue
                flags = rx._args[1] if hasattr(rx, "_args") and len(rx._args) > 1 else getattr(rx, "flags", 0)
                before, after = rr.spread(pattern, flags)
                if before >= reach.COPY_MARGIN - reach.CONTEXT or after >= reach.COPY_MARGIN - reach.AFTER:
                    found.add((name, node.func.value.id))
        self.assertEqual(found - reviewed, set(), "a new regex over the whole text reads far: guard it in rescan.py")


class RememberedScanTests(unittest.TestCase):
    def test_no_text_is_kept_after_a_call(self):
        rnd = random.Random(8)
        text = _prose(rnd, reach.LONG + 2_000)
        D.findings(text, channel="tool", fields=[(0, len(text), ("notes",))])
        D.scan(text, channel="tool", fields=[(0, len(text), ("notes",))])
        D.findings(text, channel="tool")
        from maisecrets.detection import rescan
        self.assertIsNone(rescan.LAST_SCAN.get())


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
            got = spans(D.findings(self.text, channel="tool", **kw))
        with as_before():
            self.assertEqual(got, spans(D.findings(self.text, channel="tool", **kw)), "the hits of before")
        return sizes

    def test_the_cleaned_copy_reads_a_window_around_the_change_not_the_line(self):
        copies = [n for n, copy in self.read() if copy]
        self.assertTrue(copies, "the premise: the soft hyphen makes a cleaned copy")
        self.assertLess(max(copies), len(self.text) // 2, copies)

    def test_a_change_whose_window_ends_near_the_end_of_the_line_still_reads_a_window(self):
        # the window would end a few characters before the end of the line, where no whitespace follows: it takes
        # the end of the line (a Markdown page whose last bold label stood 6,145 characters before its end)
        rnd = random.Random(6)
        body = _prose(rnd, 40_000).replace("\n", " ").rstrip() + "x" * 40
        at = len(body) - reach.COPY_MARGIN - 20
        text = body[:at] + "\u00ad" + body[at:]
        self.text = text
        copies = [n for n, copy in self.read() if copy]
        self.assertTrue(copies, "the premise: the soft hyphen makes a cleaned copy")
        self.assertLess(max(copies), len(text) // 2, copies)

    def test_the_label_reads_the_start_of_the_value_not_the_value(self):
        whole = [(0, len(self.text), ("messages", 0, "content"))]
        sizes = self.read(fields=whole)
        raw = [n for n, copy in sizes if not copy]
        self.assertEqual(raw[0], len(self.text), "the scan of the text")
        self.assertLess(max(raw[1:]), len(self.text) // 2, sizes)


if __name__ == "__main__":
    unittest.main()
