"""scripts/measure_datasets.py on small synthetic records: the loaders parse each dataset's shape, every cleaning rule
does what docs/BENCHMARKS.md says, the scoring counts each class once, and a run prints and writes no value.

Run: python3 -m unittest tests.test_measure_datasets -v
The values are built at run time (check digits computed here), so no literal sits in the tree and the tree scan
stays clean.
"""
from __future__ import annotations

import collections
import gzip
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "maisecrets" / "detection" / "rules"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

_spec = importlib.util.spec_from_file_location("measure_datasets", ROOT / "scripts" / "measure_datasets.py")
md = importlib.util.module_from_spec(_spec)
sys.modules["measure_datasets"] = md
_spec.loader.exec_module(md)


def luhn_complete(body: str) -> str:
    """body plus the Luhn check digit."""
    for d in "0123456789":
        if md.luhn_ok(body + d):
            return body + d
    raise AssertionError("no check digit")


def luhn_broken(body: str) -> str:
    """body plus a digit that fails Luhn."""
    for d in "0123456789":
        if not md.luhn_ok(body + d):
            return body + d
    raise AssertionError("every digit passes")


def iban_complete(country: str, bban: str) -> str:
    for cd in range(100):
        cand = f"{country}{cd:02d}{bban}"
        if md.iban_ok(cand):
            return cand
    raise AssertionError("no check digits")


def spaced(digits: str) -> str:
    return " ".join(digits[i:i + 4] for i in range(0, len(digits), 4))


def personal_email() -> str:
    return "my-test-user" + "@" + "mail-test" + ".de"


def reserved_email() -> str:
    return "my-test-user" + "@" + "example" + ".com"


def us_phone(area: str, exchange: str, line: str) -> str:
    return f"({area}) {exchange}-{line}"


def counts_of(dataset, sample):
    counts: dict = {}
    gold = md.clean(dataset, sample, counts)
    return gold, counts


class CleaningTests(unittest.TestCase):
    def one(self, dataset, text, label, start=None, end=None, expect=None):
        value_start = 0 if start is None else start
        value_end = len(text) if end is None else end
        span = {"start": value_start, "end": value_end, "label": label}
        if expect is not None:
            span["expect"] = expect
        gold, counts = counts_of(dataset, {"id": "t:1", "text": text, "spans": [span]})
        return gold, counts

    def test_a_value_that_fails_its_checksum_is_uncertain(self):
        card = spaced(luhn_broken("411111111111111"))
        gold, counts = self.one("gretel", "card " + card, "credit_card_number", 5)
        self.assertEqual((gold[0]["gold"], gold[0]["reason"]), ("uncertain", "checksum"))
        self.assertEqual(counts["CARD"]["uncertain: checksum"], 1)

    def test_a_valid_value_stays_positive(self):
        card = spaced(luhn_complete("411111111111111"))
        gold, _ = self.one("gretel", "card " + card, "credit_card_number", 5)
        self.assertEqual((gold[0]["gold"], gold[0]["start"], gold[0]["end"]), ("pos", 5, 5 + len(card)))

    def test_an_iban_that_fails_mod_97_is_uncertain(self):
        good = iban_complete("DE", "37040044" + "0532013000")
        bad = good[:2] + f"{(int(good[2:4]) + 1) % 100:02d}" + good[4:]
        self.assertEqual(self.one("gretel", good, "iban")[0][0]["gold"], "pos")
        self.assertEqual(self.one("gretel", bad, "iban")[0][0]["gold"], "uncertain")

    def test_an_aba_number_that_fails_its_checksum_is_uncertain(self):
        body = "02100002"
        good = next(body + d for d in "0123456789" if md.aba_ok(body + d))
        bad = next(body + d for d in "0123456789" if not md.aba_ok(body + d))
        self.assertEqual(self.one("gretel", good, "bank_routing_number")[0][0]["gold"], "pos")
        self.assertEqual(self.one("gretel", bad, "bank_routing_number")[0][0]["reason"], "checksum")

    def test_placeholder_phone_numbers_are_uncertain(self):
        for phone in (us_phone("123", "456", "7890"), us_phone("800", "123", "4567"), "-".join(["555"] * 2 + ["5555"]),
                      us_phone("292", "555", "0134")):
            gold, counts = self.one("gretel", phone, "phone_number")
            self.assertEqual((gold[0]["gold"], gold[0]["reason"]), ("uncertain", "placeholder"), phone.count("5"))
        gold, _ = self.one("gretel", us_phone("415", "555", "0134"), "phone_number")
        self.assertEqual(gold[0]["gold"], "pos")

    def test_a_placeholder_ssn_is_uncertain(self):
        gold, _ = self.one("gretel", "-".join(["123", "45", "6789"]), "ssn")
        self.assertEqual(gold[0]["gold"], "uncertain")
        gold, _ = self.one("gretel", "-".join(["536", "22", "1458"]), "ssn")
        self.assertEqual(gold[0]["gold"], "pos")

    def test_a_reserved_email_domain_is_uncertain_and_a_personal_one_positive(self):
        gold, _ = self.one("gretel", reserved_email(), "email")
        self.assertEqual((gold[0]["gold"], gold[0]["reason"]), ("uncertain", "reserved domain"))
        gold, _ = self.one("gretel", personal_email(), "email")
        self.assertEqual(gold[0]["gold"], "pos")

    def test_a_private_address_is_uncertain(self):
        gold, _ = self.one("gretel", ".".join(["10", "1", "2", "3"]), "ipv4")
        self.assertEqual((gold[0]["gold"], gold[0]["reason"]), ("uncertain", "not public"))

    def test_a_span_with_nothing_of_its_type_is_negative(self):
        gold, counts = self.one("gretel", "[Phone Number]", "phone_number")
        self.assertEqual((gold[0]["gold"], gold[0]["reason"]), ("neg", "label error"))
        gold, _ = self.one("gretel", "adresse e-mail professionnelle", "email")
        self.assertEqual(gold[0]["gold"], "neg")

    def test_a_card_block_is_trimmed_to_the_number(self):
        card = spaced(luhn_complete("540000000000000"))
        block = f"Visa, Test Holder, {card}, 12/29, CVC 123"
        text = "Payment: " + block + "."
        start = text.index(block)
        gold, counts = self.one("mendeley", text, "credit_card", start, start + len(block))
        g = gold[0]
        self.assertEqual((g["gold"], g["reason"]), ("pos", "trimmed"))
        self.assertEqual(text[g["start"]:g["end"]], card)
        self.assertEqual(counts["CARD"]["pos: trimmed"], 1)

    def test_a_trailing_expiry_is_cut_off_but_a_group_never(self):
        card = spaced(luhn_complete("540000000000000"))
        gold, _ = self.one("gretel", card + " 12", "credit_card_number")
        self.assertEqual((gold[0]["gold"], gold[0]["end"]), ("pos", len(card)))
        # a fake number of five groups whose first four pass Luhn: cutting the last group would make a "valid"
        # fragment, so the span stays uncertain
        for tail in range(10000):
            fake = card + f" {tail:04d}"
            if not md.luhn_ok(fake):
                break
        self.assertTrue(md.luhn_ok(fake[:-5]))
        gold, _ = self.one("gretel", fake, "credit_card_number")
        self.assertEqual((gold[0]["gold"], gold[0]["end"]), ("uncertain", len(fake)))

    def test_the_us_layout_is_judged_in_english_text_only(self):
        mobile = "333 012 3456"
        gold, _ = counts_of("gretel", {"id": "t:1", "lang": "it", "text": mobile,
                                       "spans": [{"start": 0, "end": len(mobile), "label": "phone_number"}]})
        self.assertEqual(gold[0]["gold"], "pos")
        gold, _ = counts_of("gretel", {"id": "t:1", "lang": "en", "text": mobile,
                                       "spans": [{"start": 0, "end": len(mobile), "label": "phone_number"}]})
        self.assertEqual((gold[0]["gold"], gold[0]["reason"]), ("uncertain", "placeholder"))

    def test_a_full_stop_after_an_address_is_trimmed_off(self):
        email = personal_email()
        gold, counts = self.one("nemotron", email + ".", "email")
        self.assertEqual((gold[0]["gold"], gold[0]["reason"], gold[0]["end"]), ("pos", "trimmed", len(email)))

    def test_overlapping_values_of_one_type_count_once(self):
        email = personal_email()
        text = "Mail " + email + " now"
        a = text.index(email)
        sample = {"id": "t:1", "text": text, "spans": [{"start": a, "end": a + len(email), "label": "email"},
                                                       {"start": a, "end": a + len(email), "label": "email"}]}
        gold, counts = counts_of("gretel", sample)
        self.assertEqual(len([g for g in gold if g["gold"] == "pos"]), 1)
        self.assertEqual(counts["EMAIL"]["merged: overlaps a value of its type"], 1)
        self.assertEqual(md.merge_original([("EMAIL", 5, 9), ("EMAIL", 5, 9), ("PHONE", 5, 9)]),
                         [("EMAIL", 5, 9), ("PHONE", 5, 9)])

    def test_cut_ok_refuses_a_cut_at_a_group_boundary(self):
        self.assertFalse(md.cut_ok("4111 1111 1111", " 1111"))
        self.assertTrue(md.cut_ok("4111 1111 1111 1111", " 12"))
        self.assertFalse(md.cut_ok("4111 1111 1111 111", "1"))

    def test_a_shifted_offset_is_repaired_onto_its_value(self):
        email = personal_email()
        text = "Contact: " + email + " today."
        at = text.index(email)
        gold, counts = self.one("nemotron", text, "email", at - 4, at - 4 + len(email), expect=email)
        self.assertEqual(text[gold[0]["start"]:gold[0]["end"]], email)
        self.assertEqual(gold[0]["gold"], "pos")
        self.assertEqual(counts["EMAIL"]["offset repaired"], 1)

    def test_a_shifted_offset_without_its_value_near_is_uncertain(self):
        email = personal_email()
        text = "Contact: someone today, nothing else here at all."
        gold, counts = self.one("nemotron", text, "email", 9, 9 + 7, expect=email)
        self.assertEqual((gold[0]["gold"], gold[0]["reason"]), ("uncertain", "offset broken"))
        self.assertEqual(counts["EMAIL"]["offset broken"], 1)

    def test_a_span_outside_the_text_is_dropped_and_counted(self):
        gold, counts = self.one("gretel", "short", "email", 2, 50)
        self.assertEqual(gold, [])
        self.assertEqual(counts["EMAIL"]["dropped: offset outside the text"], 1)

    def test_an_account_number_written_as_an_iban_becomes_an_iban(self):
        iban = iban_complete("FR", "30006000011234567890189")
        gold, counts = self.one("nemotron", spaced(iban), "account_number")
        self.assertEqual((gold[0]["type"], gold[0]["gold"]), ("IBAN", "pos"))
        self.assertEqual(counts["US_BANK_NUMBER"]["retyped as IBAN"], 1)

    def test_an_out_of_scope_label_is_neutral_and_an_unknown_label_stops(self):
        gold, _ = self.one("gretel", "Test Company", "company")
        self.assertEqual(gold[0]["gold"], "oos")
        with self.assertRaises(md.DataError) as cm:
            self.one("gretel", "my-test-value-text", "my_test_label_name")
        self.assertNotIn("my-test-value-text", str(cm.exception))
        self.assertNotIn("my_test_label_name", str(cm.exception))

    def test_every_label_maps_to_a_type_maisecrets_reports_or_out_of_scope(self):
        sys.path.insert(0, str(ROOT))
        from maisecrets import detect
        presidio = json.loads((RULES / "presidio.json").read_text(encoding="utf-8"))
        known = ({detect.ENTITY_TYPE.get(r["entity"], r["entity"]) for r in presidio["recognizers"]} | {"SECRET"}
                 | {r.type for r in detect._load_own()})
        from maisecrets import personal
        known |= {personal.NAME, personal.ADDRESS, personal.BIRTH_DATE, personal.ID_NUMBER, personal.USERNAME}
        self.assertEqual(set(md.TIER_OF), set(md.CORE) | set(md.PERSONAL))
        for typ in md.TIER_OF:
            self.assertIn(typ, known)
        for dataset, table in md.LABELS.items():
            for label, typ in table.items():
                self.assertTrue(typ == md.OUT_OF_SCOPE or typ in known, (dataset, label, typ))


class LoaderTests(unittest.TestCase):
    def test_gretel_drops_low_quality_and_tags_structured_formats(self):
        stats = collections.Counter()
        spans = json.dumps([{"start": 0, "end": 3, "label": "name"}])
        recs = [("train", {"index": 1, "language": "German", "document_type": "CSV", "quality_score": 95,
                           "generated_text": "abc", "pii_spans": spans}),
                ("test", {"index": 2, "language": "France", "document_type": "Email", "quality_score": 80,
                          "generated_text": "abc", "pii_spans": "[]"})]
        out = list(md.gretel_samples(recs, stats))
        self.assertEqual([(s["id"], s["lang"], s["tags"]) for s in out], [("train:1", "de", ["format:structured"])])
        self.assertEqual(stats["records below quality 90"], 1)

    def test_nemotron_reads_its_spans_as_a_literal_and_refuses_code(self):
        recs = [{"uid": "u1", "locale": "us", "document_format": "unstructured", "text": "abc",
                 "spans": repr([{"start": 0, "end": 3, "text": "abc", "label": "city"}])}]
        out = list(md.nemotron_samples(recs, collections.Counter()))
        self.assertEqual(out[0]["id"], "us:u1")
        self.assertEqual(out[0]["spans"][0]["expect"], "abc")
        recs[0]["spans"] = "__import__('os').getcwd()"
        with self.assertRaises(md.DataError):
            list(md.nemotron_samples(recs, collections.Counter()))

    def test_piilo_rebuilds_the_text_and_joins_bio_runs(self):
        rec = {"document": 7, "tokens": ["Mail", "me", "at", "x", "y", "."], "trailing_whitespace":
               [True, True, True, True, False, False], "labels": ["O", "O", "O", "B-EMAIL", "I-EMAIL", "O"]}
        rec["full_text"] = "Mail me at x y."
        out = list(md.piilo_samples([rec], collections.Counter()))
        self.assertEqual(out[0]["spans"], [{"start": 11, "end": 14, "label": "EMAIL"}])
        stats = collections.Counter()
        rec["full_text"] = "something else"
        self.assertEqual(list(md.piilo_samples([rec], stats)), [])
        self.assertEqual(stats["records whose tokens do not rebuild the text"], 1)

    def test_mendeley_reads_the_sheet_and_repairs_mojibake(self):
        right = "The auditor’s note for Test Holder."
        broken = right.encode("utf-8").decode("cp1252")
        self.assertNotEqual(broken, right)
        self.assertEqual(md.repair_mojibake(broken), right)
        at = right.index("Test Holder")
        tmp = Path(tempfile.mkdtemp(prefix="mendeley-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "Training_Set.xlsx"
        cells = md.MENDELEY_COLUMNS
        row = ["Test Holder", "", "", "", "", "", "", "", broken, repr([(at, at + len("Test Holder"), "name")])]
        shared = cells + row
        ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'

        def esc(s):
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        sst = f'<sst {ns}>' + "".join(f"<si><t>{esc(s)}</t></si>" for s in shared) + "</sst>"
        rows = ""
        for r, vals in enumerate((cells, row)):
            cs = "".join(f'<c r="{chr(65 + i)}{r + 1}" t="s"><v>{r * len(cells) + i}</v></c>'
                         for i, v in enumerate(vals))
            rows += f'<row r="{r + 1}">{cs}</row>'
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("xl/sharedStrings.xml", sst)
            z.writestr("xl/worksheets/sheet1.xml", f'<worksheet {ns}><sheetData>{rows}</sheetData></worksheet>')
        stats = collections.Counter()
        out = list(md.mendeley_samples([("Training_Set", md.read_xlsx(path))], stats))
        self.assertEqual(out[0]["id"], "Training_Set:2")
        self.assertEqual(out[0]["text"], right)
        self.assertEqual(stats["texts with mojibake repaired"], 1)
        gold, _ = counts_of("mendeley", out[0])
        self.assertEqual((gold[0]["start"], gold[0]["end"]), (at, at + len("Test Holder")))

    def test_a_data_directory_inside_the_repository_is_refused(self):
        with self.assertRaises(md.DataError):
            md.check_data_dir(ROOT / "data")
        self.assertEqual(md.check_data_dir(Path(tempfile.gettempdir())), Path(tempfile.gettempdir()).resolve())


class ScoreTests(unittest.TestCase):
    def test_each_detection_and_each_value_counts_once(self):
        gold = [{"start": 0, "end": 10, "type": "CARD", "gold": "pos"},
                {"start": 20, "end": 30, "type": "CARD", "gold": "uncertain"},
                {"start": 40, "end": 50, "type": md.OUT_OF_SCOPE, "gold": "oos"},
                {"start": 60, "end": 70, "type": "PHONE", "gold": "pos"},
                {"start": 80, "end": 90, "type": "PHONE", "gold": "neg"}]
        dets = [(0, 10, "CARD", "credit-card"), (20, 30, "CARD", "credit-card"), (40, 50, "PHONE", "phone"),
                (80, 90, "PHONE", "phone"), (95, 99, "EMAIL", "email")]
        original = [("CARD", 0, 10), ("CARD", 20, 30), ("PHONE", 60, 70)]
        c, classes, found = md.score_sample(gold, dets, original)
        self.assertEqual(classes, ["tp", "neutral", "neutral", "fp", "fp"])
        self.assertEqual(found, [True, True, True, False, True])
        card, phone = md.metrics(c["CARD"]), md.metrics(c["PHONE"])
        self.assertEqual((card["tp"], card["fn"], card["fp"], card["unc_hit"]), (1, 0, 0, 1))
        self.assertEqual((phone["tp"], phone["fn"], phone["fp"]), (0, 1, 1))
        self.assertEqual((card["raw_tp"], phone["raw_fn"]), (2, 1))
        self.assertEqual(md.metrics(c["EMAIL"])["fp"], 1)
        self.assertEqual(card["P"], 1.0)
        self.assertEqual(phone["P"], 0.0)

    def test_a_detection_of_another_type_finds_a_value_but_adds_no_precision(self):
        gold = [{"start": 0, "end": 10, "type": "NAME", "gold": "pos"}]
        c, classes, _ = md.score_sample(gold, [(0, 10, "SECRET", "rule")], [("NAME", 0, 10)])
        self.assertEqual(classes, ["tp"])
        self.assertEqual(md.metrics(c["NAME"])["tp"], 1)
        self.assertEqual(md.metrics(c["NAME"])["R_own"], 0.0)
        secret = md.metrics(c["SECRET"])
        self.assertEqual((secret["hits"], secret["cross"], secret["P"]), (0, 1, None))

    def test_a_partial_overlap_finds_a_value_but_does_not_cover_it(self):
        gold = [{"start": 0, "end": 10, "type": "PHONE", "gold": "pos"},
                {"start": 20, "end": 30, "type": "PHONE", "gold": "pos"}]
        dets = [(0, 6, "PHONE", "a"), (20, 25, "PHONE", "a"), (25, 30, "PHONE", "b")]
        c, _, _ = md.score_sample(gold, dets, [])
        m = md.metrics(c["PHONE"])
        self.assertEqual((m["tp"], m["covered"], m["R"], m["R_covered"]), (2, 1, 1.0, 0.5))


class RunTests(unittest.TestCase):
    def test_a_run_prints_and_writes_counts_never_a_value(self):
        data = Path(tempfile.mkdtemp(prefix="datasets-"))
        self.addCleanup(shutil.rmtree, data, True)
        card = spaced(luhn_complete("540000000000000"))
        email = personal_email()
        bad_card = spaced(luhn_broken("540000000000000"))
        text = f"Kreditkarte {card} von {email}; alte Karte {bad_card}."
        spans = [{"start": text.index(v), "end": text.index(v) + len(v), "label": lab}
                 for v, lab in ((card, "credit_card_number"), (email, "email"), (bad_card, "credit_card_number"))]
        (data / "gretel").mkdir()
        for split in ("train", "test"):
            rec = {"index": 1, "language": "German", "document_type": "Email", "quality_score": 95,
                   "generated_text": text, "pii_spans": json.dumps(spans)}
            with gzip.open(data / "gretel" / f"{split}-00000-of-00001.jsonl.gz", "wt", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        out = data / "result.json"
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "measure_datasets.py"), "run", "--data", str(data),
                            "--only", "gretel", "--workers", "1", "--out", str(out)],
                           capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        written = out.read_text(encoding="utf-8")
        for v in (card, email, bad_card, card.replace(" ", ""), text):
            self.assertNotIn(v, r.stdout + r.stderr)
            self.assertNotIn(v, written)
        res = json.loads(written)["datasets"][0]
        self.assertEqual(res["samples"], 2)
        self.assertEqual(res["cleaning"]["CARD"]["uncertain: checksum"], 2)
        tool = res["channels"]["tool"]["types"]
        self.assertEqual((tool["CARD"]["tp"], tool["CARD"]["fn"]), (2, 0))
        self.assertEqual((tool["EMAIL"]["tp"], tool["EMAIL"]["fn"]), (2, 0))
        self.assertEqual(tool["CARD"]["raw_tp"] + tool["CARD"]["raw_fn"], 4)
        self.assertEqual(set(res["channels"]), {"prompt", "tool"})
        core = res["channels"]["tool"]["tiers"]["core"]["total"]
        self.assertEqual((core["tp"], core["fn"]), (4, 0))
        self.assertEqual(core["R_raw"], round(4 / 6, 4))
        self.assertEqual(res["rows"][0]["id"], "test:1")
        self.assertIn("de", res["groups"]["de de_DE"]["regions"])


if __name__ == "__main__":
    unittest.main()
