"""Benchmark V1 (docs/BENCHMARK-V1.md): the case format, the marks of the bank and the span metric."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import cases, score  # noqa: E402


def case(text, spans, **kw):
    return {"id": "t", "text": text, "channel": "tool", "context": "prose", "spans": spans, "split": "dev",
            "source": {"name": "test"}, **kw}


class MarkTests(unittest.TestCase):
    def test_the_marks_give_the_offsets_and_leave_the_text(self):
        text, spans = cases.unmark("key: «ab§cd» and «x»")
        self.assertEqual(text, "key: abcd and x")
        self.assertEqual([text[s:e] for s, e in spans], ["abcd", "x"])

    def test_a_broken_mark_is_an_error(self):
        for raw in ("«a", "a»", "««a»»"):
            with self.subTest(raw=raw), self.assertRaises(cases.CaseError):
                cases.unmark(raw)

    def test_a_bank_case_needs_one_class_per_mark(self):
        with self.assertRaises(cases.CaseError):
            cases.bank_case(case("«a» «b»", [{"class": "pii.email"}]), "x")
        with self.assertRaises(cases.CaseError):
            cases.bank_case(case("«a»", [{"class": "pii.unknown"}]), "x")
        c = cases.bank_case(case("mail «a@b»", [{"class": "pii.email"}]), "x")
        self.assertEqual(c["spans"][0]["start"], 5)

    def test_the_split_of_a_record_is_fixed_and_about_60_20_20(self):
        # golden values: a rewrite that moves records between splits fails here, not only one that breaks 60/20/20
        golden = {("nemotron", "us:1"): "dev", ("bank", "x"): "holdout", ("catalogs", "np.aws.1"): "dev",
                  ("gretel", "test:7"): "val", ("piilo", "42"): "dev"}
        self.assertEqual({k: cases.split_of(*k) for k in golden}, golden)
        counts = {s: 0 for s in cases.SPLITS}
        for i in range(10000):
            counts[cases.split_of("src", str(i))] += 1
        self.assertTrue(5700 < counts["dev"] < 6300 and 1700 < counts["val"] < 2300, counts)

    def test_the_bank_files_load(self):
        bank = ROOT / "bench" / "bank"
        loaded = cases.load_bank(bank)
        self.assertGreater(len(loaded), 0)
        for c in loaded:
            self.assertNotIn(cases.SPLIT_MARK, c["text"])
            self.assertNotIn(cases.OPEN, c["text"])
            self.assertNotIn(cases.CLOSE, c["text"])

    def test_the_bank_files_are_what_the_templates_give(self):
        sys.path.insert(0, str(ROOT / "bench" / "bank"))
        import make_bank
        built = make_bank.build()
        on_disk = {p.relative_to(ROOT / "bench" / "bank").as_posix(): p.read_text(encoding="utf-8")
                   for p in sorted((ROOT / "bench" / "bank").rglob("*.jsonl"))}
        self.assertEqual(sorted(built), sorted(on_disk))
        for name in built:
            with self.subTest(name=name):
                self.assertEqual(built[name], on_disk[name])

    def test_every_value_with_a_checksum_in_the_bank_passes_it(self):
        # 2026-10-19: the first generator wrote German tax ids that failed the IdNr rules, so a correct detector was
        # scored as missing them
        sys.path.insert(0, str(ROOT / "scripts"))
        import measure_datasets as md
        from maisecrets.detection.core import _de_tax_id_ok
        check = {"pii.tax_id": _de_tax_id_ok, "pii.iban": lambda v: md.iban_ok(v.replace(" ", "")),
                 "pii.card": md.luhn_ok}
        n = 0
        for c in cases.load_bank(ROOT / "bench" / "bank"):
            for sp in c["spans"]:
                if sp["class"] in check:
                    n += 1
                    with self.subTest(case=c["id"], cls=sp["class"]):
                        self.assertTrue(check[sp["class"]](c["text"][sp["start"]:sp["end"]]))
        self.assertGreaterEqual(n, 12)

    def test_two_cases_with_one_id_are_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            line = json.dumps(case("«a@b»", [{"class": "pii.email"}]))
            Path(d, "a.jsonl").write_text(line + "\n" + line + "\n", encoding="utf-8")
            with self.assertRaises(cases.CaseError):
                cases.load_bank(Path(d))


class SpanMetricTests(unittest.TestCase):
    URL = "https://x.example/" + "a" * 186     # 204 characters, as the Teams webhook of 0.6.38

    def test_a_webhook_masked_17_of_204_is_partial_not_found(self):
        c = case(f"hook: {self.URL}", [{"class": "secret.webhook", "start": 6, "end": 210}])
        sc = score.score_case(c, [(6 + 50, 6 + 67, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "partial")
        self.assertEqual(sc["spans"][0]["covered"], 17)
        sc = score.score_case(c, [(6, 210, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "full")

    def test_two_findings_that_together_cover_the_span_are_full(self):
        c = case("v=abcdefgh", [{"class": "secret.generic", "start": 2, "end": 10}])
        sc = score.score_case(c, [(2, 6, "secret"), (6, 10, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "full")

    def test_an_alt_range_counts_as_full(self):
        c = case('k="abcdef"', [{"class": "secret.generic", "start": 2, "end": 10, "alt": [[3, 9]]}])
        sc = score.score_case(c, [(3, 9, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "full")

    def test_a_span_outside_the_scope_is_neither_missed_nor_a_false_positive(self):
        c = case("a@example.com key", [{"class": "pii.email", "start": 0, "end": 13}])
        sc = score.score_case(c, [(0, 13, "secret")], ("secret.",))
        self.assertEqual((sc["spans"], sc["fp"]), ([], 0))

    def test_a_finding_on_no_span_is_a_false_positive(self):
        c = case("plain words here", [])
        sc = score.score_case(c, [(0, 5, "secret")], ("secret.",))
        self.assertEqual((sc["fp"], sc["negative"]), (1, True))

    def test_masking_the_label_is_not_too_wide_but_the_next_line_is(self):
        text = "pass" + "word: hunter2xyz\nnext line of ordinary text here"
        c = case(text, [{"class": "secret.password", "start": 10, "end": 20}])
        self.assertEqual(score.score_case(c, [(0, 20, "secret")], ("secret.",))["too_wide"], 0)
        self.assertEqual(score.score_case(c, [(10, len(text), "secret")], ("secret.",))["too_wide"], 1)

    def test_the_family_of_the_finding_is_reported_not_scored(self):
        c = case("a@example.com", [{"class": "pii.email", "start": 0, "end": 13}])
        sc = score.score_case(c, [(0, 13, "secret")], ("pii.",))
        self.assertEqual((sc["spans"][0]["outcome"], sc["spans"][0]["family_right"]), ("full", False))

    def test_aggregate_counts_strict_and_lenient_recall_and_fp_density(self):
        res = []
        for i in range(40):
            c = case("x" * 20, [{"class": "secret.token", "start": 0, "end": 20}])
            f = [(0, 20, "secret")] if i < 30 else [(0, 5, "secret")] if i < 35 else []
            res.append((c, score.score_case(c, f, ("secret.",))))
        neg = case("y" * 10, [])
        res.append((neg, score.score_case(neg, [(0, 3, "secret")], ("secret.",))))
        m = score.aggregate(res)
        self.assertEqual((m["secret.token"]["full"], m["secret.token"]["partial"], m["secret.token"]["missed"]),
                         (30, 5, 5))
        self.assertEqual(m["secret.token"]["recall_strict"], 0.75)
        self.assertEqual(m["secret.token"]["recall_lenient"], 0.875)
        self.assertEqual(m["all"]["fp"], 1)
        self.assertEqual(m["all"]["precision"], round(35 / 36, 4))
        self.assertEqual(m["all"]["fp_per_1000_negative"], 1000.0)

    def test_precision_and_f1_are_per_family(self):
        # codex Gate A: a scanner that finds every secret and no personal data had the overall F1 in both rows
        res = []
        for i in range(30):
            sec = case("x" * 10, [{"class": "secret.token", "start": 0, "end": 10}])
            res.append((sec, score.score_case(sec, [(0, 10, "secret")], ("secret.", "pii."))))
            per = case("y" * 10, [{"class": "pii.email", "start": 0, "end": 10}])
            res.append((per, score.score_case(per, [], ("secret.", "pii."))))
        m = score.aggregate(res)
        self.assertEqual((m["secret"]["precision"], m["secret"]["f1"]), (1.0, 1.0))
        self.assertEqual(m["pii"]["recall_strict"], 0.0)
        self.assertEqual(m["all"]["f1"], round(2 * 1.0 * 0.5 / 1.5, 4))

    def test_f1_is_zero_when_nothing_is_found_whole(self):
        res = []
        for _ in range(30):
            c = case("z" * 6, [{"class": "secret.token", "start": 0, "end": 6}])
            res.append((c, score.score_case(c, [(0, 1, "secret")], ("secret.",))))
        m = score.aggregate(res)
        self.assertEqual((m["all"]["precision"], m["all"]["recall_strict"], m["all"]["f1"]), (1.0, 0.0, 0.0))

    def test_a_wide_finding_over_a_neutral_span_is_a_false_positive(self):
        text = "w" * 100
        c = case(text, [{"class": "pii.other", "start": 10, "end": 20, "neutral": True}])
        self.assertEqual(score.score_case(c, [(10, 20, "pii.name")], ("pii.",))["fp"], 0)
        self.assertEqual(score.score_case(c, [(0, 100, "pii.name")], ("pii.",))["fp"], 1)

    def test_family_right_needs_the_right_family_to_cover_the_span(self):
        c = case("a@example.com", [{"class": "pii.email", "start": 0, "end": 13}])
        sc = score.score_case(c, [(0, 13, "secret"), (0, 2, "pii.email")], ("pii.",))
        self.assertEqual((sc["spans"][0]["outcome"], sc["spans"][0]["family_right"]), ("full", False))

    def test_prose_before_the_label_is_not_the_label(self):
        text = "x" * 60 + " key: " + "v" * 10
        start = len(text) - 10
        c = case(text, [{"class": "secret.generic", "start": start, "end": len(text)}])
        self.assertEqual(score.score_case(c, [(start - 6, len(text), "secret")], ("secret.",))["too_wide"], 0)
        self.assertEqual(score.score_case(c, [(0, len(text), "secret")], ("secret.",))["too_wide"], 1)

    def test_a_class_with_few_spans_gives_no_rate(self):
        c = case("x" * 5, [{"class": "pii.iban", "start": 0, "end": 5}])
        m = score.aggregate([(c, score.score_case(c, [(0, 5, "pii")], ("pii.",)))])
        self.assertTrue(m["pii.iban"]["too_few"])
        self.assertNotIn("recall_strict", m["pii.iban"])


class RoundTwoTests(unittest.TestCase):
    """codex Gate A, round 2 on the benchmark."""

    def test_an_alt_range_makes_the_span_full_but_not_its_core_covered(self):
        c = case("k" * 10, [{"class": "secret.generic", "start": 0, "end": 10, "core": [0, 4], "alt": [[6, 10]]}])
        sc = score.score_case(c, [(6, 10, "secret")], ("secret.",))
        self.assertEqual((sc["spans"][0]["outcome"], sc["spans"][0]["covered"]), ("full", 0))

    def test_an_empty_or_outside_core_or_alt_range_is_an_error(self):
        for extra in ({"alt": [[3, 3]]}, {"core": [0, 0]}, {"alt": [[0, 9]]}, {"core": [True, 2]}):
            with self.subTest(extra=extra), self.assertRaises(cases.CaseError):
                cases.bank_case(case("x «abcd» y", [{"class": "secret.generic", **extra}]), "x")
        cases.bank_case(case("x «abcd» y", [{"class": "secret.generic", "core": [3, 5], "alt": [[2, 6]]}]), "x")

    def test_a_case_path_must_stay_below_its_folder(self):
        for bad in ("/etc/x", "../x", "a/../../x", "c:/x", "\\\\host\\x", ""):
            with self.subTest(path=bad), self.assertRaises(cases.CaseError):
                cases.bank_case(case("«a@b»", [{"class": "pii.email"}], path=bad), "x")
        self.assertTrue(cases.safe_path("tests/fixtures/app.env"))

    def test_the_case_hash_changes_with_the_text_not_only_the_id(self):
        sys.path.insert(0, str(ROOT / "bench"))
        import run
        a = [case("one", [])]
        b = [case("two", [])]
        self.assertNotEqual(run.cases_hash(a), run.cases_hash(b))
        self.assertEqual(run.cases_hash(a), run.cases_hash([case("one", [])]))

    def test_a_worker_that_hangs_ends_with_an_error(self):
        from bench.adapters import _proc
        with self.assertRaises(_proc.AdapterError):
            _proc.run([sys.executable, "-c", "import time; time.sleep(30)"], "slow", env=dict(os.environ),
                      cwd=str(ROOT), timeout=1)


class RoundThreeTests(unittest.TestCase):
    """codex Gate A, round 3 on the benchmark."""

    def test_the_order_of_overlapping_spans_does_not_move_a_finding_between_families(self):
        sec = {"class": "secret.token", "start": 0, "end": 20}
        per = {"class": "pii.email", "start": 10, "end": 30}
        for f in ((15, 16), (2, 12), (18, 29)):
            a = score.score_case(case("q" * 30, [sec, per]), [(*f, "secret")], ("secret.", "pii."))
            b = score.score_case(case("q" * 30, [per, sec]), [(*f, "secret")], ("secret.", "pii."))
            with self.subTest(finding=f):
                self.assertEqual(a["on_target"], b["on_target"])
        self.assertEqual(score.score_case(case("q" * 30, [sec, per]), [(18, 29, "secret")],
                                          ("secret.", "pii."))["on_target"], {"pii": 1})

    def test_the_catalog_source_needs_all_six_catalogs(self):
        from bench import sources
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "gitleaks"))
            with self.assertRaises(SystemExit):
                next(iter(sources.catalog_cases(Path(d))))

    def test_a_result_from_a_modified_tree_is_refused_in_a_report(self):
        sys.path.insert(0, str(ROOT / "bench"))
        import report
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "r.json")
            p.write_text(json.dumps({"bench_dirty": True, "scanner": {"scanner": "x", "scope": []}, "source": "bank",
                                     "split": "dev", "cases": 0, "metrics": {}}), encoding="utf-8")
            self.assertEqual(report.main([str(p)]), 2)

    def test_a_pinned_version_or_commit_that_does_not_match_is_an_error(self):
        from bench.adapters import _proc
        got = _proc.identity(sys.executable, "pip")
        self.assertIsNone(got["commit"])
        with self.assertRaises(_proc.AdapterError):
            _proc.identity(sys.executable, "pip", version="0.0.1")
        with self.assertRaises(_proc.AdapterError):
            _proc.identity(sys.executable, "pip", commit="0" * 40)


class RoundFourTests(unittest.TestCase):
    def test_a_case_with_only_scoped_out_or_neutral_spans_is_a_negative_case(self):
        for sp in ({"class": "pii.email", "start": 0, "end": 5}, {"class": "secret.token", "start": 0, "end": 5,
                                                                  "neutral": True}):
            c = case("a" * 5 + " " + "b" * 20, [sp])
            m = score.aggregate([(c, score.score_case(c, [(8, 20, "secret")], ("secret.",)))])
            with self.subTest(span=sp):
                self.assertEqual((m["all"]["negative_cases"], m["all"]["fp_per_1000_negative"]), (1, 1000.0))

    def test_a_run_without_a_readable_commit_ends(self):
        sys.path.insert(0, str(ROOT / "bench"))
        import run
        with mock.patch.dict(os.environ, {"GIT_DIR": "/definitely/not/a/repository"}):
            self.assertRegex(run._commit(), r"^[0-9a-f]{40}$")     # GIT_DIR of a caller is ignored
        with mock.patch.object(run, "ROOT", Path(tempfile.mkdtemp())), self.assertRaises(SystemExit):
            run._commit()

    def test_allow_dirty_never_lets_an_unknown_state_through(self):
        sys.path.insert(0, str(ROOT / "bench"))
        import report
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "r.json")
            base = {"bench_commit": "a" * 40, "source": "bank", "split": "dev", "cases": 0, "metrics": {}}
            for extra, want in (({"bench_dirty": None, "scanner": {"scanner": "x", "scope": []}}, 2),
                                ({"bench_dirty": False, "scanner": {"scanner": "maisecrets", "scope": []}}, 2),
                                ({"bench_dirty": False, "scanner": {"scanner": "x", "scope": [], "dirty": None}}, 2),
                                ({"bench_dirty": True, "scanner": {"scanner": "x", "scope": []}}, 0)):
                p.write_text(json.dumps({**base, **extra}), encoding="utf-8")
                with self.subTest(extra=extra), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(report.main(["--allow-dirty", str(p)]), want)

    def test_a_maisecrets_copy_without_git_has_an_unknown_state(self):
        from bench.adapters import maisecrets
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".claude-plugin").mkdir()
            Path(d, ".claude-plugin", "plugin.json").write_text('{"version": "0.0.1"}', encoding="utf-8")
            desc = maisecrets.describe(Path(d), "de")
        self.assertEqual((desc["commit"], desc["dirty"]), (None, None))

    def test_an_untracked_file_in_the_maisecrets_checkout_makes_it_dirty(self):
        from bench.adapters import maisecrets
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".claude-plugin").mkdir()
            Path(d, ".claude-plugin", "plugin.json").write_text('{"version": "0.0.1"}', encoding="utf-8")
            for cmd in (["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@example.com",
                                                        "commit", "-q", "-m", "x"]):
                subprocess.run(["git", "-C", d, *cmd], check=True, env=env, capture_output=True)
            self.assertIs(maisecrets.describe(Path(d), "de")["dirty"], False)
            Path(d, "maisecrets.py").write_text("x = 1\n", encoding="utf-8")
            self.assertIs(maisecrets.describe(Path(d), "de")["dirty"], True)

    def test_a_result_without_a_commit_or_a_dirty_flag_is_refused(self):
        sys.path.insert(0, str(ROOT / "bench"))
        import report
        with tempfile.TemporaryDirectory() as d:
            for extra in ({"bench_commit": ""}, {"bench_commit": "a" * 40}):
                p = Path(d, "r.json")
                p.write_text(json.dumps({**extra, "scanner": {"scanner": "x", "scope": []}, "source": "bank",
                                         "split": "dev", "cases": 0, "metrics": {}}), encoding="utf-8")
                with self.subTest(extra=extra):
                    self.assertEqual(report.main([str(p)]), 2)


class AdapterOutputTests(unittest.TestCase):
    def test_a_missing_result_or_a_finding_outside_the_text_is_an_error(self):
        from bench.adapters import _proc
        cs = [case("abc", []), case("def", [])]
        with self.assertRaises(_proc.AdapterError):
            _proc.check("x", cs, [[]])
        with self.assertRaises(_proc.AdapterError):
            _proc.check("x", cs, [[[0, 9, "secret", "r"]], []])
        self.assertEqual(_proc.check("x", cs, [[[0, 2, "secret", "r"]], []]), [[(0, 2, "secret", "r")], []])


class AdapterInventoryTests(unittest.TestCase):
    """Each foreign scanner is pinned (a requirements file with every distribution at an exact version or commit) and
    maps its findings only to classes of Benchmark V1 (docs/BENCHMARK-V2.md, reproducible scanner configurations)."""

    def test_every_foreign_adapter_has_a_pinned_requirements_file(self):
        import importlib
        from bench import run
        for name in run.ADAPTERS:
            if name == "maisecrets":
                continue
            with self.subTest(adapter=name):
                mod = importlib.import_module(f"bench.adapters.{name}")
                for attr in ("NAME", "SCOPE", "describe", "scan"):
                    self.assertTrue(hasattr(mod, attr), attr)
                req = ROOT / "bench" / "adapters" / "requirements" / f"{mod.NAME}.txt"
                lines = [ln for ln in req.read_text(encoding="utf-8").splitlines() if ln and not ln.startswith("#")]
                self.assertTrue(lines)
                for ln in lines:
                    self.assertRegex(ln, r"==|@ (git\+)?https://", f"{req.name}: {ln} is not pinned")

    def test_presidio_maps_only_to_benchmark_classes(self):
        import re
        from bench import cases
        from bench.adapters import presidio
        named = set(re.findall(r'"(pii\.[a-z_]+)"', presidio._WORKER))
        self.assertTrue(named)
        self.assertLessEqual(named, set(cases.CLASSES))


class ReproducibilityTests(unittest.TestCase):
    """Benchmark V2 writes its environment and a CSV of the report next to the results (docs/BENCHMARK-V2.md)."""

    def test_the_manifest_names_the_trees_the_datasets_and_each_scanner_python(self):
        from bench import manifest
        m = manifest.manifest(ROOT, {"BENCH_PYTHON": sys.executable})
        self.assertEqual(sorted(m), ["benchmark", "catalogs", "datasets", "date", "maisecrets", "platform",
                                     "scanners"])
        self.assertIn("privy", m["datasets"])
        self.assertEqual(m["scanners"]["maisecrets"]["python"], sys.executable)
        self.assertIsInstance(m["benchmark"]["dirty"], (bool, type(None)))

    def test_the_csv_holds_one_row_per_claimed_group(self):
        import csv
        import tempfile
        from bench import report
        run = {"source": "bank", "split": "dev", "every": 1, "cases": 2, "cases_sha256": "x", "bench_commit": "y",
               "scanner": {"scanner": "s", "version": "1", "scope": ["pii."]}, "timing": {"median_ms": 1.0},
               "metrics": {"all": {}, "pii": {"spans": 3, "full": 2}, "pii.email": {"spans": 3, "full": 2},
                           "secret": {"spans": 1}}}
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.csv"
            report.write_csv([run], str(out))
            rows = list(csv.DictReader(out.open(encoding="utf-8")))
        self.assertEqual([r["group"] for r in rows], ["pii", "pii.email"])
        self.assertEqual(rows[0]["full"], "2")


class CompareBenchTests(unittest.TestCase):
    """scripts/compare_bench.py lists what a reviewer must explain (docs/REGRESSION-POLICY.md)."""

    def run_compare(self, base: dict, new: dict, fp_base=None, fp_new=None) -> list:
        import tempfile
        sys.path.insert(0, str(ROOT / "scripts"))
        import compare_bench
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a", Path(d) / "b"
            for p, metrics, fp in ((a, base, fp_base), (b, new, fp_new)):
                p.mkdir()
                (p / "gretel-val-maisecrets.json").write_text(json.dumps({"metrics": metrics}), encoding="utf-8")
                if fp is not None:
                    (p / "fpbank-7trees.json").write_text(json.dumps(
                        {"trees": {"t": {"rules": {f"tests|X|{r}": [n, n] for r, n in fp.items()}}}}),
                        encoding="utf-8")
            return compare_bench.compare(a, b)

    def test_a_loss_on_val_a_new_partial_and_a_new_bank_hit_are_findings(self):
        base = {"all": {"fp": 100}, "pii.name": {"spans": 1000, "full": 500, "partial": 10}}
        new = {"all": {"fp": 100}, "pii.name": {"spans": 1000, "full": 490, "partial": 11}}
        found = self.run_compare(base, new, {"email": 3}, {"email": 4})
        self.assertEqual(len(found), 3, found)

    def test_small_changes_inside_the_lines_are_no_finding(self):
        base = {"all": {"fp": 1000}, "pii.name": {"spans": 1000, "full": 500, "partial": 10}}
        new = {"all": {"fp": 1005}, "pii.name": {"spans": 1000, "full": 497, "partial": 9}}
        self.assertEqual(self.run_compare(base, new, {"email": 3}, {"email": 3}), [])



class TracesSourceTests(unittest.TestCase):
    """bench/traces.py makes the protocol traces at run time: the same cases on every run, each span on its value."""

    def test_the_cases_are_the_same_on_every_run_and_each_span_holds_a_value(self):
        from bench import sources, traces
        a, b = list(traces.generate(count=200)), list(traces.generate(count=200))
        self.assertEqual(a, b)
        self.assertIn("traces", sources.SOURCES)
        spans = [(c, s) for c in a for s in c["spans"]]
        self.assertGreater(len(spans), 200, "the premise: the cases have spans")
        for c, s in spans:
            v = c["text"][s["start"]:s["end"]]
            self.assertTrue(v and v == v.strip() and s["class"] in cases.CLASSES, c["id"])

    def test_every_format_and_both_decision_splits_are_there(self):
        from bench import traces
        cs = list(traces.generate())
        self.assertEqual({t for c in cs for t in c["tags"]}, {f"format:{n}" for n, _ in traces.FORMATS})
        self.assertGreater(sum(c["split"] == "val" for c in cs), 400)


if __name__ == "__main__":
    unittest.main()
