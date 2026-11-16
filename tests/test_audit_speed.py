"""The session audit of the secret-hygiene skill is fast enough to use (#59) and finds what it found before.

Each speed step has a test that the old work is gone and a test that the findings stay (the personal pass:
tests/test_personal_steps.py): the binary blocks are left out, each distinct text is scanned once, the pool
uses the cores, the fast tier runs the rules only near an anchor, and the progress names no value."""
from __future__ import annotations

import base64
import importlib
import io
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
SCRIPTS = ROOT / "skills" / "secret-hygiene" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import _detector  # noqa: E402
import _fast  # noqa: E402
import audit_transcripts as at  # noqa: E402

ALNUM = string.ascii_letters + string.digits
LETTERS_PW = "pozk" + "emva"      # random small letters that read as no word (tests/test_skill.py)


def _key(n: int) -> str:
    """A random value of n characters that reads as no word: no run of more than two letters (a random value with
    a word in it was sometimes not a secret to the detector, and the test failed one run in about 30)."""
    out = ""
    while len(out) < n:
        out += _rnd(2, string.ascii_letters) + _rnd(1, string.digits)
    return out[:n]


def _rnd(n: int, alphabet: str = ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _gh() -> str:
    return "gh" + "p_" + _rnd(36)


class StringsTests(unittest.TestCase):
    """The binary blocks of a record are left out; a text document in base64 is read."""

    def test_images_signatures_and_data_urls_are_left_out_a_text_document_is_decoded_and_a_pdf_is_read(self):
        img = base64.b64encode(os.urandom(3000)).decode()
        pdf = base64.b64encode(b"%PDF-1.4 " + os.urandom(300)).decode()
        doc_text = "the deploy notes\nGITHUB_TOKEN=" + _gh()
        rec = {"type": "user", "message": {"content": [
            {"type": "tool_result", "content": [{"type": "image", "source": {
                "type": "base64", "media_type": "image/png", "data": img}}]},
            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": pdf}},
            {"type": "document", "source": {"type": "base64", "media_type": "text/plain",
                                            "data": base64.b64encode(doc_text.encode()).decode()}},
            {"type": "input_image", "image_url": "data:image/png;base64," + img},
            {"type": "thinking", "thinking": "plan the step", "signature": img},
            {"type": "redacted_thinking", "data": img}]},
            "toolUseResult": {"type": "image", "file": {"base64": img, "type": "image/png"}},
            "payload": {"type": "reasoning", "encrypted_content": img}}
        got = list(at.strings_of(rec))
        self.assertFalse([s for s in got if img in s or img[:200] in s], "a binary block was scanned")
        self.assertIn(doc_text, got)
        self.assertEqual([s for s in got if isinstance(s, at.Whole)], [pdf], "a PDF is read as before, whole")
        self.assertIn("plan the step", got)
        self.assertIn("image/png", got)


def _lines(*recs) -> list:
    return [json.dumps(r) + "\n" for r in recs]


class DedupeTests(unittest.TestCase):
    """Each distinct text is scanned once per worker (the fast scan; --full reads each record as one text, as
    0.9.13 did); its findings are reported at every line that holds it."""

    def setUp(self):
        at._SEEN.clear()
        self.addCleanup(at._SEEN.clear)
        _detector._worker_init(_detector.secret_rules(_detector.load()), "fast")

    def counting(self):
        calls = []
        real = _fast.scan

        def count(detect, text, *a, **k):
            calls.append(len(text))
            return real(detect, text, *a, **k)
        p = mock.patch.object(_fast, "scan", count)
        p.start()
        self.addCleanup(p.stop)
        return calls

    def test_a_repeated_text_is_scanned_once_and_reported_at_each_line(self):
        out = "build log\n" * 80 + f"GITHUB_TOKEN={_gh()}\n" + "done\n" * 40
        rec = {"type": "user", "message": {"content": [{"type": "tool_result", "content": out}]},
               "toolUseResult": {"stdout": out}}
        calls = self.counting()
        _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(dict(rec, uuid="a"), dict(rec, uuid="b"))))
        self.assertEqual(sorted({r[0] for r in rows}), [0, 1])
        self.assertEqual([r[0] for r in rows].count(0), 2, "the stdout copy is a second place in the record")
        self.assertEqual(calls.count(len(out)), 1, "the long text was scanned more than once")

    def test_a_changed_text_is_scanned_again(self):
        base = "build log\n" * 80
        a, b = base + f"GITHUB_TOKEN={_gh()}\n", base + f"GITHUB_TOKEN={_gh()}\n"
        recs = [{"type": "user", "message": {"content": [{"type": "tool_result", "content": t}]}} for t in (a, b)]
        _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(*recs)))
        self.assertEqual(len({r[5] for r in rows}), 2, "the second text was taken for the first")

    def test_the_same_text_as_a_prompt_and_as_a_tool_result_is_judged_by_each_channel(self):
        pw = LETTERS_PW
        # the password line stands away from the borders of the string, so only the scan of the string sees it
        text = "x" * 600 + "\nstep" * 6 + f'\npassword = Some("{pw}"),' + "\nnext step" * 6
        recs = [{"type": "user", "message": {"content": text}},
                {"type": "user", "message": {"content": [{"type": "tool_result", "content": text}]}}]
        _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(*recs)))
        self.assertEqual([(r[0], r[1]) for r in rows if r[5] == pw], [(1, "tool result")])

    def test_a_long_text_is_cut_into_parts_that_repeat_after_a_change(self):
        sections = ["# Section %d\n\n" % i + ("word " * 300) for i in range(12)]
        one = "\n\n".join(sections)
        two = "\n\n".join(sections[:3] + ["# Inserted\n\n" + "other " * 50] + sections[3:])
        p1, p2 = at._cut(one), at._cut(two)
        self.assertGreater(len(p1), 4)
        self.assertGreaterEqual(len(set(p1) & set(p2)), len(p1) - 2)
        self.assertEqual("\n\n".join(p1), one)


class GateAFixTests(unittest.TestCase):
    """The four findings of Gate A on the first version of #59."""

    def setUp(self):
        at._SEEN.clear()
        self.addCleanup(at._SEEN.clear)
        self.detect = _detector.load()
        self.enabled = _detector.secret_rules(self.detect)

    def straddling(self):
        """A long text that _cut() cuts between a password label and its value: the value paragraph is one whose
        hash makes a cut. Returns the text and the value."""
        import zlib
        filler = "\n\n".join(f"Step {i}: the build of module {i} took {i * 3} ms and passed." for i in range(60))
        while True:
            value = LETTERS_PW + _rnd(4, string.digits) + "#Q"
            if zlib.crc32(value[:64].encode()) % 8 == 0:
                break
        # the label's paragraph alone fills a part (PART characters), so the cut before the value is certain
        log = "\n".join(f"deploy step {i} finished in {i * 7} ms on the build host" for i in range(30))
        text = filler + "\n\n" + log + "\nThe database password:\n\n" + value + "\n\n" + filler
        return text, value

    def test_a_label_and_its_value_on_both_sides_of_a_cut_are_found_fast_and_full(self):
        text, value = self.straddling()
        whole = [m.value for m in _detector.scan_text(self.detect, text, self.enabled, "tool")]
        self.assertIn(value, whole, "the detector must find it in the whole text")
        bodies = at._cut(text)
        self.assertTrue(any(b.endswith("password:") for b in bodies), "the cut must fall between label and value")
        rec = {"type": "user", "message": {"content": [{"type": "tool_result", "content": text}]}}
        for mode in ("fast", "full"):
            with self.subTest(mode):
                at._SEEN.clear()
                _detector._worker_init(self.enabled, mode)
                _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(rec)))
                self.assertEqual([r[5] for r in rows].count(value), 1)

    def test_full_scans_a_long_string_whole(self):
        text, _value = self.straddling()
        _detector._worker_init(self.enabled, "full")
        self.assertEqual(at.units({"x": text}), [(text, "\n", False)])
        _detector._worker_init(self.enabled, "fast")
        self.assertGreater(len(at.units({"x": text})), 1)

    def sibling_record(self, first: str, second: str) -> dict:
        return {"type": "user", "message": {"content": [{"type": "tool_result", "content": "ok"}]},
                "toolUseResult": {"stdout": first, "stderr": second}}

    def test_a_label_and_its_value_in_two_sibling_strings_are_found_in_both_orders_fast_and_full(self):
        """0.9.13 joined the strings of a record; a label at the end of one string and its value in the next were
        one finding. Round 2 of Gate A: the long string was scanned apart from its short sibling."""
        value = LETTERS_PW + "4711#Q"
        log = "\n".join(f"deploy step {i} finished in {i * 7} ms on the build host" for i in range(40))
        cases = {"long, then short": (log + "\nThe database password:", value),
                 "short, then long": ("The database password:", value + "\n" + log)}
        for name, (first, second) in cases.items():
            rec = self.sibling_record(first, second)
            joined = "\n".join(at.strings_of(rec))
            self.assertIn(value, [m.value for m in _detector.scan_text(self.detect, joined, self.enabled, "tool")])
            for mode in ("fast", "full"):
                with self.subTest(name=name, mode=mode):
                    at._SEEN.clear()
                    _detector._worker_init(self.enabled, mode)
                    _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(rec)))
                    self.assertEqual([r[5] for r in rows].count(value), 1)

    def test_a_hit_near_a_border_counts_once(self):
        token = "gh" + "p_" + _rnd(36)
        log = "\n".join(f"deploy step {i} finished in {i * 7} ms on the build host" for i in range(40))
        for first, second in ((log, "GITHUB_TOKEN=" + token), ("GITHUB_TOKEN=" + token, log)):
            rec = self.sibling_record(first, second)
            for mode in ("fast", "full"):
                with self.subTest(mode=mode, first=first[:12]):
                    at._SEEN.clear()
                    _detector._worker_init(self.enabled, mode)
                    _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(rec)))
                    self.assertEqual([r[5] for r in rows], [token])

    def test_an_opaque_blob_is_left_out_only_in_its_own_schema(self):
        tokens = {name: "gh" + "p_" + _rnd(36) for name in ("enc", "sig", "url")}
        png = "data:image/png;base64,"
        opaque = {"type": "response_item", "payload": {
            "type": "reasoning", "encrypted_content": "GITHUB_TOKEN=" + tokens["enc"], "content": [
                {"type": "input_image", "image_url": png + tokens["url"]},
                {"type": "thinking", "thinking": "plan", "signature": "GITHUB_TOKEN=" + tokens["sig"]}]}}
        got = "\n".join(at.strings_of(opaque))
        for token in tokens.values():
            self.assertNotIn(token, got)
        ordinary = {"type": "user", "toolUseResult": {
            "encrypted_content": "GITHUB_TOKEN=" + tokens["enc"], "signature": "GITHUB_TOKEN=" + tokens["sig"],
            "stdout": png + tokens["url"]}}
        got = "\n".join(at.strings_of(ordinary))
        for token in tokens.values():
            self.assertIn(token, got)

    def test_a_border_window_takes_its_lines_from_more_than_one_neighbour(self):
        """Round 5 of Gate A: an AWS key id at the end of field A, field B of two long lines, the secret in field C.
        The key id and the secret are three lines apart, across two borders; the fast scan finds what --full finds."""
        log = "\n".join(f"deploy step {i} finished in {i * 7} ms on the build host" for i in range(40))
        key_id = "AK" + "IA" + _rnd(16, string.ascii_uppercase + "234567")
        secret = _rnd(40, ALNUM + "+/")
        # two lines, over SMALL characters together, each under the 400 characters the AWS rule reads across
        middle = ("the build log of step one " * 12).strip() + "\n" + ("the build log of step two " * 12).strip()
        self.assertGreaterEqual(len(middle), at.SMALL)
        rec = {"type": "user", "message": {"content": [{"type": "tool_result", "content": "ok"}]},
               "toolUseResult": {"stdout": log + "\naws_access_key_id = " + key_id, "stderr": middle,
                                 "note": secret}}
        joined = "\n".join(at.strings_of(rec))
        old = {(m.kind, m.value) for m in _detector.scan_text(self.detect, joined, self.enabled, "tool")}
        self.assertIn("aws-secret-after-access-key", {k for k, _v in old})
        got = {}
        for mode in ("full", "fast"):
            at._SEEN.clear()
            _detector._worker_init(self.enabled, mode)
            _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(rec)))
            got[mode] = sorted((r[4], r[5]) for r in rows)
        self.assertEqual(got["fast"], got["full"])
        self.assertEqual(set(got["full"]), old)
        self.assertEqual(len(got["fast"]), len(set(got["fast"])), "a hit counted twice in two windows")

    def test_a_border_walks_across_an_empty_field(self):
        """Round 6 of Gate A: a label at the end of one long field, an empty field, the value at the start of the
        next long field. 0.9.13 joined them with an empty line between; the fast scan finds what --full finds."""
        log = "\n".join(f"deploy step {i} finished in {i * 7} ms on the build host" for i in range(40))
        value = LETTERS_PW + "4711#Q"
        rec = {"type": "user", "message": {"content": [{"type": "tool_result", "content": "ok"}]},
               "toolUseResult": {"stdout": log + "\nThe database password:", "stderr": "",
                                 "note": value + "\n" + log}}
        joined = "\n".join(at.strings_of(rec))
        self.assertIn(value, [m.value for m in _detector.scan_text(self.detect, joined, self.enabled, "tool")])
        _detector._worker_init(self.enabled, "fast")
        self.assertIn(("", "\n", False), at.units(rec), "the empty field is a text of its own")
        got = {}
        for mode in ("full", "fast"):
            at._SEEN.clear()
            _detector._worker_init(self.enabled, mode)
            _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(rec)))
            got[mode] = sorted((r[4], r[5]) for r in rows)
        self.assertEqual(got["fast"], got["full"])
        self.assertIn(value, [v for _k, v in got["fast"]])

    def test_full_reads_a_record_as_one_text_as_before(self):
        """Round 4 of Gate A: an AWS key id at the end of one long field and its secret on the fourth line of the
        next; 0.9.13 joined the record and found both. --full does again."""
        log = "\n".join(f"deploy step {i} finished in {i * 7} ms on the build host" for i in range(40))
        key_id = "AK" + "IA" + _rnd(16, string.ascii_uppercase + "234567")
        secret = _rnd(40, ALNUM + "+/")
        rec = self.sibling_record(log + "\naws_access_key_id = " + key_id, "one\ntwo\nthree\n" + secret + "\n" + log)
        joined = "\n".join(at.strings_of(rec))
        old = {m.kind for m in _detector.scan_text(self.detect, joined, self.enabled, "tool")}
        self.assertIn("aws-secret-after-access-key", old)
        _detector._worker_init(self.enabled, "full")
        self.assertEqual(at.units(rec), [(joined, "\n", False)])
        _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(rec)))
        self.assertEqual({r[4] for r in rows}, old)

    def test_the_cache_knows_the_rule_selection_and_the_mode(self):
        text = "x" * 600 + "\nexport GITHUB_TOKEN=" + "gh" + "p_" + _rnd(36)
        _detector._worker_init(self.enabled, "full")
        self.assertTrue(at.scan_once(self.detect, text, self.enabled, "tool"))
        self.assertEqual(at.scan_once(self.detect, text, {"aws-access-token"}, "tool"), ())
        with mock.patch.object(_fast, "scan", lambda *a: []):
            _detector._worker_init(self.enabled, "fast")
            self.assertEqual(at.scan_once(self.detect, text, self.enabled, "tool"), ())

    def test_a_lone_surrogate_does_not_end_the_audit(self):
        # each paragraph starts with the lone surrogate, so parts() hashes one (json.loads accepts it)
        long = "\n\n".join(f"\ud800 paragraph {i} " + "word " * 60 for i in range(40))
        line = json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "content": long}]}})
        self.assertIn("\\ud800", line)
        token = "gh" + "p_" + _rnd(36)
        good = json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "content": "t=" + token}]}})
        _detector._worker_init(self.enabled, "fast")
        _tag, rows, notes = at.worker_jsonl((("f", 0), "claude", [line + "\n", good + "\n"]))
        self.assertEqual([r[5] for r in rows], [token])
        self.assertEqual(notes.get("unread", 0), 0)

    def test_a_record_that_breaks_a_step_is_counted_and_the_rest_is_scanned(self):
        token = "gh" + "p_" + _rnd(36)
        recs = [{"type": "user", "message": {"content": "first"}},
                {"type": "user", "message": {"content": [{"type": "tool_result", "content": "t=" + token}]}}]
        real = at.units

        def flaky(rec, notes=None):
            if rec["message"]["content"] == "first":
                raise UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")
            return real(rec, notes)
        _detector._worker_init(self.enabled, "fast")
        with mock.patch.object(at, "units", flaky):
            _tag, rows, notes = at.worker_jsonl((("f", 0), "claude", _lines(*recs)))
        self.assertEqual(([r[5] for r in rows], notes), ([token], {"unread": 1}))

    def test_an_uncompressed_pdf_in_a_tool_result_is_read_as_before(self):
        """0.9.13 found a token in an uncompressed PDF in a tool result: the decoder of the full scan reads the
        base64. Both modes keep that; an image is still left out."""
        token = "gh" + "p_" + _rnd(36)
        stream = b"BT /F1 12 Tf 10 10 Td (GITHUB_TOKEN=" + token.encode() + b") Tj ET"
        pdf = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n4 0 obj<</Length "
               + str(len(stream)).encode() + b">>stream\n" + stream + b"\nendstream endobj\n%%EOF\n")
        data = base64.b64encode(pdf).decode()
        rec = {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t", "content": [
            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": data}},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}]}]}}
        for mode in ("fast", "full"):
            with self.subTest(mode):
                at._SEEN.clear()
                _detector._worker_init(self.enabled, mode)
                _tag, rows, _notes = at.worker_jsonl((("f", 0), "claude", _lines(rec)))
                # the decoder reports the base64 run that holds the token, as 0.9.13 did; once: not the image copy
                self.assertEqual([(r[1], r[3], r[5]) for r in rows], [("tool result", "SECRET", data)])


class FastTierTests(unittest.TestCase):
    """The fast tier finds what the full scan finds where a value has a prefix or a label near it."""

    def setUp(self):
        self.detect = _detector.load()
        self.enabled = _detector.secret_rules(self.detect)

    def both(self, text):
        full = sorted((m.kind, m.value) for m in _detector.scan_text(self.detect, text, self.enabled, "tool"))
        fast = sorted((m.kind, m.value) for m in _fast.scan(self.detect, text, self.enabled, "tool",
                                                            _detector.scan_text))
        return full, fast

    def test_prefixes_labels_flags_and_urls_are_found_as_by_the_full_scan(self):
        filler = "\n".join(f"step {i}: the build of module {i} took {i * 3} ms" for i in range(200))
        pw = LETTERS_PW
        for name, make in (
                ("prefix", lambda: f"GITHUB_TOKEN={_gh()}"),
                ("letters after a password label", lambda: f'password = Some("{pw}"),'),
                ("a flag", lambda: f"mysql -u root --passwd {LETTERS_PW}!#Q -h db"),
                ("json key", lambda: '{"service": "billing", "apiKey": "' + _key(28) + '"}'),
                ("url", lambda: f"DATABASE_URL=postgres://app:{_key(10)}!{_key(5)}@db.example:5432/app"),
                ("bearer", lambda: f"Authorization: Bearer {_key(40)}"),
                ("a key word inside a name", lambda: f'    nkey = "{_key(30)}"'),
                ("a value that starts with the literal", lambda: '    "id": "AK' + "IA"
                 + _rnd(16, string.ascii_uppercase + "234567") + '",'),
                ("wide spaces before the sign", lambda: f'  db_password    = "{LETTERS_PW}9!"'),
                ("a scheme and a token", lambda: "it { expect(header).to eq('Basic " + _key(20) + "1') }")):
            with self.subTest(name):
                # a rare random value is no secret to the detector; the test compares the tiers, so it draws again
                for _ in range(20):
                    full, fast = self.both(filler + "\n" + make() + "\n" + filler)
                    if full:
                        break
                self.assertTrue(full, "the full scan must find it")
                self.assertEqual(fast, full)

    def test_a_value_before_its_literal_is_found_as_by_the_full_scan(self):
        """Round 4 of Gate A: label-password-use-as has the value before "password", and a detect-secrets rule
        compares a quoted value with a key word; the fast tier took both literals for labels of a value after."""
        filler = "\n".join(f"step {i}: the build of module {i} took {i * 3} ms" for i in range(50))
        for name, make in (("use ... as the password", lambda: f"Please use {_key(14)} as the password."),
                           ("a value compared with a key word", lambda: f'assert "{_key(16)}" == secret')):
            with self.subTest(name):
                for _ in range(20):
                    full, fast = self.both(filler + "\n" + make() + "\n" + filler)
                    if full:
                        break
                self.assertTrue(full, "the full scan must find it")
                self.assertEqual(fast, full)

    def test_the_labelled_cases_of_the_detection_matrix_and_every_label_language_agree(self):
        """The detector's labelled test inputs, each between other lines: the generated matrix (tests/
        detection_matrix.py, its negatives) and the label examples of every language file with a value. The rule
        specs carry no examples of their own, so these stand in for them. The fast tier gives the same hits."""
        sys.path.insert(0, str(ROOT / "tests"))
        import detection_matrix as dm
        from maisecrets.detection import regions
        texts = [c.text for c in dm.cases(600, seed=59)] + [t for t, _why in dm.NEGATIVES]
        for lang_file in sorted((ROOT / "maisecrets" / "detection" / "rules" / "labels").glob("*.txt")):
            for label in regions.load_labels(lang_file.stem):
                texts += [f"{ex}: {_key(14)}" for ex in label.examples]
        above = "\n".join(f"line {i} of the log" for i in range(8))
        differ = []
        for text in texts:
            full, fast = self.both(above + "\n" + text + "\n" + above)
            if full != fast:
                differ.append((text[:40], [k for k, _v in full], [k for k, _v in fast]))
        self.assertGreater(len(texts), 600)
        self.assertEqual(differ, [])

    def test_a_key_word_inside_a_long_token_is_an_anchor(self):
        anchors, _rx_c, _bare = _fast.build(self.detect, self.enabled)
        self.assertEqual(anchors.kind.get("azfu"), anchors.WORD)
        self.assertIn(16, [p for p, _lit in anchors.hits("the " + "q1w2e3r4t5y6" + "azfu" + "z9x8c7v6b5n4" + " end")])
        self.assertEqual(anchors.hits("the azfu field"), [])

    def test_a_text_without_an_anchor_runs_only_the_rules_without_one(self):
        rx_i, rx_c, bare = _fast.build(self.detect, self.enabled)
        self.assertEqual(_fast.windows("the build took 12 ms\nall checks passed\n", rx_i, rx_c), [])
        self.assertIn("telegram-bot-token", bare)

    def test_a_literal_that_starts_inside_another_is_found(self):
        """The search goes on from the next position after a hit, not from its end: a prefix of a token can start
        inside a key word that does not count there (x + mysqladmi + napi_…)."""
        anchors, _rx_c, _bare = _fast.build(self.detect, self.enabled)
        strong = sorted(x for x, c in anchors.kind.items() if c == anchors.STRONG and x[:1].isalpha())
        words = sorted(x for x, c in anchors.kind.items() if c == anchors.WORD)
        pair = next(((w, x, k) for w in words for x in strong for k in range(1, min(len(w), len(x)))
                     if w[-k:] == x[:k]), None)
        self.assertIsNotNone(pair)
        w, x, k = pair
        self.assertEqual(anchors.hits("say x" + w + "!"), [])
        # an anchor there: the literal or a shorter one at its place
        self.assertIn(5 + len(w) - k, [p for p, _lit in anchors.hits("say x" + w[:-k] + x + "q1w2e3r4t5")])

    def test_the_windows_hold_the_lines_around_an_anchor_and_a_whole_key_block(self):
        rx_i, rx_c, _bare = _fast.build(self.detect, self.enabled)
        lines = [f"line {i}" for i in range(40)]
        lines[20] = f"GITHUB_TOKEN={_gh()}"
        text = "\n".join(lines)
        (a, b), = _fast.windows(text, rx_i, rx_c)
        # three lines on each side: the window the corpus and CredData were measured with (#59)
        self.assertEqual(text[a:b].splitlines(), lines[17:24])
        block = "-----BEGIN " + "PRIVATE KEY-----\n" + "\n".join(_rnd(64) for _ in range(30)) + "\n-----END " \
            + "PRIVATE KEY-----"
        text = "\n".join(lines[:5] + [block] + lines[5:])
        self.assertTrue(any(block in text[a:b] for a, b in _fast.windows(text, rx_i, rx_c)))


def _session(dirpath: Path, recs: list) -> Path:
    proj = dirpath / "projects" / "-x"
    proj.mkdir(parents=True, exist_ok=True)
    f = proj / f"{_rnd(8)}.jsonl"
    f.write_text("".join(_lines(*recs)), encoding="utf-8")
    old = time.time() - 3600
    os.utime(f, (old, old))
    return f


class RunTests(unittest.TestCase):
    """The cores minus one by default; the size, the estimate, the progress and the time on stderr, with no value."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-audit-speed-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.token = _gh()
        _session(self.dir, [{"type": "user", "timestamp": "2026-10-01T10:00:00Z",
                             "message": {"content": [{"type": "tool_result", "content": f"x={self.token}"}]}}]
                 + [{"type": "assistant", "message": {"content": [{"type": "text", "text": "ok " * 200}]}}] * 30)
        self.env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.dir), "CODEX_HOME": str(self.dir / "c")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_main(self, *args):
        err, out = io.StringIO(), io.StringIO()
        mod = importlib.reload(at)
        self.addCleanup(importlib.reload, at)
        with mock.patch.object(mod, "SAMPLE_BYTES", 1), mock.patch.object(mod, "PROGRESS_SECONDS", 0), \
                redirect_stderr(err), mock.patch("sys.stdout", out):
            code = mod.main(["--claude", *args])
        return code, out.getvalue(), err.getvalue()

    def test_a_scan_that_never_reaches_its_sample_size_still_gets_an_estimate(self):
        out = io.StringIO()
        progress = at.Progress([], 1, out=out)
        progress.total = 1000      # a file that shrank while the scan read it
        progress.step(400, 1)
        progress.end()
        text = out.getvalue()
        self.assertIn("Estimate: about", text)
        self.assertLess(text.index("Estimate:"), text.index("Scanned "))

    def test_the_default_is_the_cores_minus_one(self):
        with mock.patch.object(os, "cpu_count", return_value=10):
            self.assertEqual(at.default_workers(), 9)
        with mock.patch.object(os, "cpu_count", return_value=1):
            self.assertEqual(at.default_workers(), 1)

    def test_a_job_ends_at_its_byte_limit(self):
        f = _session(self.dir, [{"type": "user", "message": {"content": "y" * 1000}}] * 50)
        with mock.patch.object(at, "JOB_BYTES", 10_000):
            jobs = list(at.jobs_for([("claude", f)]))
        self.assertGreater(len(jobs), 4)
        self.assertEqual(sum(len(j[2]) for j in jobs), 50)

    def test_the_progress_names_size_estimate_and_time_and_no_value(self):
        code, out, err = self.run_main("--workers", "1")
        self.assertEqual(code, 1, out + err)
        self.assertIn("Scanning 1 transcript file(s)", err)
        self.assertIn("Estimate: about", err)
        self.assertIn("Scanned", err)
        self.assertIn("Reached the AI provider: 1 distinct value(s).", out)
        for part in (self.token, self.token[4:]):
            self.assertNotIn(part, out + err)

    def test_a_closed_scan_does_not_wait_for_the_jobs_it_fetched_ahead(self):
        """--estimate stops after the sample: the jobs fetched ahead are cancelled and the running ones not waited
        for (round 2 of Gate A: the pool waited for 4 x workers jobs)."""
        import concurrent.futures
        import threading
        files = []
        for _ in range(20):
            files.append(("claude", _session(self.dir, [{"type": "user", "message": {"content": "y " * 30000}}])))
        release, started = threading.Event(), []
        self.addCleanup(release.set)

        def worker(job):
            started.append(job[0])
            if len(started) > 1:
                release.wait(10)
            return job[0], [], {}
        with mock.patch.object(at._detector, "pool",
                               lambda *a, **k: concurrent.futures.ThreadPoolExecutor(max_workers=2)), \
                mock.patch.object(at, "worker_jsonl", worker):
            scan = at.run(files, None, 2)
            next(scan)
            t0 = time.monotonic()
            scan.close()
            took = time.monotonic() - t0
        self.assertLess(took, 2.0, "the close waited for the running jobs")
        self.assertLessEqual(len(started), 3, "the jobs fetched ahead ran")

    def test_estimate_stops_after_the_sample(self):
        code, out, err = self.run_main("--estimate", "--workers", "1")
        self.assertEqual(code, 0)
        self.assertIn("Estimate: about", err)
        self.assertNotIn("Reached the AI provider", out)

    def test_full_and_fast_report_the_same_here(self):
        _c1, fast, _e = self.run_main("--workers", "1")
        _c2, full, _e = self.run_main("--workers", "1", "--full")
        self.assertEqual(fast, full)

    def test_the_pool_reports_what_one_process_reports(self):
        _session(self.dir, [{"type": "user", "message": {"content": [{"type": "tool_result",
                                                                       "content": "z" * 2000 + _gh()}]}}] * 600)
        _c1, one, _e = self.run_main("--workers", "1")
        _c2, two, err = self.run_main("--workers", "2")
        self.assertIn("with 2 process(es)", err)
        self.assertEqual(one, two)


class ScrubTests(unittest.TestCase):
    """--scrub --yes removes what the audit reports, also where the raw line does not show it as text, and never
    counts a value as replaced that it did not find (round 6 of Gate A)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-scrub-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.token = _gh()

    def audit(self, *args):
        env = dict(os.environ, PYTHONUTF8="1", CLAUDE_CONFIG_DIR=str(self.dir / "claude"),
                   CODEX_HOME=str(self.dir / "codex"))
        return subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--claude", *args],
                              capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)

    def test_a_value_in_a_text_document_and_a_key_with_line_breaks_are_removed(self):
        doc = base64.b64encode(("notes\nGITHUB_TOKEN=" + self.token + "\n").encode()).decode()
        key = "-----BEGIN " + "PRIVATE KEY-----\nMIIEv" + _rnd(60, string.ascii_letters) + "\n-----END " \
            + "PRIVATE KEY-----"
        f = _session(self.dir / "claude", [
            {"type": "user", "message": {"content": [{"type": "document", "source": {
                "type": "base64", "media_type": "text/plain", "data": doc}}]}},
            {"type": "user", "message": {"content": [{"type": "tool_result", "content": "key:\n" + key}]}}])
        report = self.audit()
        self.assertIn("Reached the AI provider: 2 distinct value(s).", report.stdout, report.stdout + report.stderr)
        done = self.audit("--scrub", "--yes")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertNotIn("not scrubbed", done.stdout)
        lines = [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines()]
        decoded = base64.b64decode(lines[0]["message"]["content"][0]["source"]["data"]).decode()
        self.assertNotIn(self.token, decoded)
        self.assertIn("⟦SCRUBBED_S", decoded)
        self.assertNotIn("MIIEv", json.dumps(lines[1]))
        self.assertEqual(self.audit().stdout.count("Reached the AI provider: 0 distinct"), 1)

    def test_a_value_that_is_not_in_the_file_as_text_is_reported_and_not_counted(self):
        f = _session(self.dir / "claude", [{"type": "user", "message": {"content": "nothing to see"}}])
        before = f.read_bytes()
        n_left, n_missing, n_changed = at._scrub_file(f, {self.token}, {self.token: "S1"})
        self.assertEqual((n_left, n_missing, n_changed), (0, 1, 0))
        self.assertEqual(f.read_bytes(), before, "a file with nothing to replace is not written")

    def test_a_record_appended_while_the_copy_is_written_is_kept(self):
        f = _session(self.dir / "claude", [{"type": "user", "message": {"content": "GITHUB_TOKEN=" + self.token}}])
        late = b'{"type": "user", "message": {"content": "appended late"}}\n'
        real_chmod = os.chmod

        def chmod_then_append(p, mode):  # the client appends after the copy is written, before the replace
            real_chmod(p, mode)
            with open(f, "ab") as fh:
                fh.write(late)

        with mock.patch.object(at.os, "chmod", chmod_then_append):
            self.assertIsNone(at._scrub_file(f, {self.token}, {self.token: "S1"}))
        self.assertTrue(f.read_bytes().endswith(late), "the late record is still there")
        self.assertEqual(list(f.parent.glob("*.tmp")), [], "no copy is left")


class EstimateProcessTests(unittest.TestCase):
    """The script as the skill runs it, in a child process (round 3 of Gate A)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-estimate-"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def corpus(self, files: int, records: int) -> Path:
        home = self.dir / "claude"
        for _ in range(files):
            # each record its own text: the cache would make a repeated one free
            _session(home, [{"type": "user", "message": {"content": [{"type": "tool_result", "content":
                     "\n".join(f"build step {i} ok {_rnd(6)}" for i in range(40))}]}, "uuid": _rnd(8)}
                            for _ in range(records)])
        return home

    def run_script(self, scripts: Path, home: Path, *args, timeout=120):
        env = dict(os.environ, PYTHONUTF8="1", CLAUDE_CONFIG_DIR=str(home), CODEX_HOME=str(self.dir / "codex"))
        t0 = time.monotonic()
        r = subprocess.run([sys.executable, str(scripts / "audit_transcripts.py"), "--claude", *args],
                           capture_output=True, text=True, encoding="utf-8", env=env, timeout=timeout)
        return r, time.monotonic() - t0

    def test_a_small_corpus_gets_an_estimate_in_the_scan_and_with_estimate(self):
        home = self.corpus(2, 5)
        for args in ((), ("--estimate",)):
            with self.subTest(args=args):
                r, _took = self.run_script(SCRIPTS, home, *args)
                self.assertIn("Estimate: about", r.stderr, r.stdout + r.stderr)

    def test_crlf_lines_and_letters_of_several_bytes_reach_the_estimate(self):
        """The Windows runner: write_text writes CRLF, the scan read the file as text and counted characters, the
        sum never reached the file size, and no estimate came. Written in bytes here, so every system sees it."""
        proj = self.dir / "claude" / "projects" / "-x"
        proj.mkdir(parents=True)
        for k in range(2):
            rows = [json.dumps({"type": "user", "message": {"content": f"Grüße aus Köln, Schritt {i}"}},
                               ensure_ascii=False) for i in range(20)]
            f = proj / f"crlf{k}.jsonl"
            f.write_bytes("\r\n".join(rows).encode("utf-8") + b"\r\n")
            old = time.time() - 3600
            os.utime(f, (old, old))
        r, _took = self.run_script(SCRIPTS, self.dir / "claude", "--workers", "1")
        self.assertRegex(r.stderr, r"Estimate: about .*on the first", r.stdout + r.stderr)
        self.assertLess(r.stderr.index("Estimate:"), r.stderr.index("Scanned "))

    @unittest.skipIf(os.name == "nt", "the slow copy links the detector package")
    def test_estimate_ends_after_its_sample_and_starts_no_pool(self):
        """A copy of the scripts whose scan of a text takes 50 ms: the full scan would take minutes. --estimate
        samples 2 s in one process and ends; a pool that it started would keep the process alive for its jobs."""
        tree = self.dir / "tree" / "skills" / "secret-hygiene"
        shutil.copytree(SCRIPTS, tree / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        (self.dir / "tree" / "maisecrets").symlink_to(ROOT / "maisecrets", target_is_directory=True)
        fast = tree / "scripts" / "_fast.py"
        fast.write_text(fast.read_text(encoding="utf-8") + "\n\n_scan = scan\n\n\ndef scan(*a):\n"
                        "    import time\n    time.sleep(0.05)\n    return _scan(*a)\n", encoding="utf-8")
        script = tree / "scripts" / "audit_transcripts.py"
        text = script.read_text(encoding="utf-8")
        self.assertIn("SAMPLE_SECONDS = 20", text)
        script.write_text(text.replace("SAMPLE_SECONDS = 20", "SAMPLE_SECONDS = 2"), encoding="utf-8")
        home = self.corpus(30, 60)
        r, took = self.run_script(tree / "scripts", home, "--estimate", "--workers", "2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Estimate: about", r.stderr)
        self.assertLess(took, 12, "the estimate ran on after its sample")


class CliTests(unittest.TestCase):
    def test_the_user_guide_says_what_the_fast_scan_can_miss(self):
        text = (ROOT / "docs" / "USING.md").read_text(encoding="utf-8")
        part = text[text.index("`audit_transcripts.py`"):text.index("`audit_approvals.py`")]
        self.assertNotIn("lists every secret", part)
        self.assertIn("lists the secrets it finds", part)
        self.assertIn("`--full`", part)
        self.assertIn("can miss", part)

    def test_the_help_names_workers_full_and_estimate(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--help"], capture_output=True,
                           text=True, timeout=60)
        for flag in ("--workers", "--full", "--estimate"):
            self.assertIn(flag, r.stdout)


if __name__ == "__main__":
    unittest.main()
