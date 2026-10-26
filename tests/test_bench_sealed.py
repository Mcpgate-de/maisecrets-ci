"""bench/sealed.py, bench/nym.py and bench/dialogpii.py: the grouped split, the seal, and the cases of a record.
Synthetic values only."""
import collections
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import dialogpii, nym, score, sealed  # noqa: E402


class SealedSplitTests(unittest.TestCase):
    def test_the_split_is_fixed_and_near_60_20_20(self):
        got = collections.Counter(sealed.split_of(b"salt", f"g{n}") for n in range(5000))
        self.assertAlmostEqual(got["dev"] / 5000, 0.6, delta=0.03)
        self.assertAlmostEqual(got["val"] / 5000, 0.2, delta=0.03)
        self.assertAlmostEqual(got["holdout"] / 5000, 0.2, delta=0.03)
        self.assertEqual(sealed.split_of(b"salt", "g7"), sealed.split_of(b"salt", "g7"))

    def test_a_group_never_crosses_splits_and_a_seal_is_written_once(self):
        recs = [{"id": f"r{n}", "group": f"g{n % 40}"} for n in range(400)]
        with tempfile.TemporaryDirectory() as tmp:
            out = sealed.write(recs, b"salt", Path(tmp))
            where = {}
            for s in sealed.SPLITS:
                for r in sealed.read(Path(tmp), s, out["sha256"], "test"):
                    self.assertEqual(where.setdefault(r["group"], s), s)
            self.assertEqual(len(where), 40)
            with self.assertRaises(sealed.DataError):
                sealed.write(recs, b"salt", Path(tmp))
            with self.assertRaises(sealed.DataError):
                list(sealed.read(Path(tmp), "dev", {"dev": "0" * 64}, "test"))
            with self.assertRaises(sealed.DataError):
                list(sealed.read(Path(tmp), "all", out["sha256"], "test"))

    def test_trim_drops_outer_space_only(self):
        self.assertEqual(sealed.trim(" ab c ", 0, 6), (1, 5))
        self.assertEqual(sealed.trim("   ", 0, 3)[1] - sealed.trim("   ", 0, 3)[0], 0)


class NymTests(unittest.TestCase):
    def test_the_group_is_the_label_sequence(self):
        a = nym.group_of("Zzz Qqq at 555", [{"start": 0, "end": 3, "label": "GIVEN_NAME"},
                                            {"start": 11, "end": 14, "label": "PHONE"}])
        b = nym.group_of("Ein anderer Satz: Xx, 1", [{"start": 22, "end": 23, "label": "PHONE"},
                                                    {"start": 18, "end": 20, "label": "GIVEN_NAME"}])
        self.assertEqual(a, b)
        self.assertNotEqual(nym.group_of("no span here", []), nym.group_of("other text", []))

    def test_a_record_maps_labels_trims_and_scores(self):
        text = "Kunde Aaa Bbb, Tel 0000 1111, Stadt Ccc"
        rec = {"id": "test/1", "text": text, "entities": [
            {"start": 6, "end": 10, "label": "GIVEN_NAME"},       # with the space after it
            {"start": 10, "end": 13, "label": "SURNAME"},
            {"start": 19, "end": 28, "label": "PHONE"},
            {"start": 36, "end": 39, "label": "CITY"},
            {"start": 30, "end": 99, "label": "PHONE"}]}
        stats = collections.Counter()
        (case,) = nym.cases_of(rec, "dev", stats)
        self.assertEqual(stats["spans with outer space (trimmed)"], 1)
        self.assertEqual(stats["spans outside the text (left out)"], 1)
        by = {text[s["start"]:s["end"]]: s for s in case["spans"]}
        self.assertEqual(by["Aaa"]["class"], "pii.name")
        self.assertTrue(by["Ccc"]["neutral"])
        found = [(6, 13, "pii.name"), (36, 39, "pii.address")]
        sc = score.score_case(case, found, ("pii.",))
        self.assertEqual([o["outcome"] for o in sc["spans"]], ["full", "full", "missed"])
        self.assertEqual(sc["fp"], 0, "a finding on a neutral span is neither right nor wrong")


class DialogPiiTests(unittest.TestCase):
    def test_turns_become_lines_with_spans_in_place(self):
        rec = {"id": "original/EN/x/1", "form": "original", "language": "SP", "scenario": "x", "turns": [
            {"speaker": "Speaker1", "text": "Me llamo Aaa.", "annotations": [
                {"start": 9, "end": 12, "text": "Aaa", "type": "PERSON"}]},
            {"speaker": "Speaker2", "text": "Vivo en Ccc, 12 ", "annotations": [
                {"start": 8, "end": 11, "text": "Ccc", "type": "LOC_CITY"},
                {"start": 13, "end": 16, "text": "12 ", "type": "LOC_HOUSENUMBER"},
                {"start": 0, "end": 4, "text": "nope", "type": "PERSON"}]}]}
        stats = collections.Counter()
        (case,) = dialogpii.cases_of(rec, "dev", stats)
        self.assertEqual(case["lang"], "es")
        got = [(case["text"][s["start"]:s["end"]], s["class"], bool(s.get("neutral"))) for s in case["spans"]]
        self.assertEqual(got, [("Aaa", "pii.name", False), ("Ccc", "pii.other", True), ("12", "pii.address", False)])
        self.assertEqual(stats["spans whose text differs from the turn (left out)"], 1)
        self.assertEqual(json.loads(json.dumps(case))["text"].count("\n"), 2)


if __name__ == "__main__":
    unittest.main()
