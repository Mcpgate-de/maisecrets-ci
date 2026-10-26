"""scripts/extended_baseline.py and bench/structured_b.py: the reuse rule, the runs, the sections and the seal of set
B. Synthetic data only: no dataset, no scanner binary."""
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import extended_baseline as xb  # noqa: E402
import measure_resources as mr  # noqa: E402
from bench import run as brun  # noqa: E402
from bench import structured_b  # noqa: E402

SCOPE = {"labelled": ["email"], "scored": ["pii.email"]}


def stored(**over):
    base = {"cases_sha256": "c" * 64, "bench_commit": "0" * 40, "v3": {"scope": SCOPE},
            "scanner": {"scanner": "gitleaks", "version": "8.30.1", "configuration": "default"}}
    base.update(over)
    return base


class ReuseRuleTests(unittest.TestCase):
    def check(self, s=None, cases="c" * 64, scope=None, now=None, code=True, score=True):
        return xb.reuse_check(s or stored(), "gitleaks", cases, SCOPE if scope is None else scope, now, code, score)

    def test_an_unchanged_result_is_reused(self):
        self.assertEqual(self.check(), [])
        same = {"scanner": "gitleaks", "version": "8.30.1", "configuration": "default"}
        self.assertEqual(self.check(now=same), [])

    def test_each_change_alone_forces_a_new_run(self):
        self.assertIn("dataset", self.check(cases="d" * 64)[0])
        self.assertIn("dataset", self.check(cases=None)[0])
        self.assertIn("scoring", self.check(score=False)[0])
        self.assertIn("scoring", self.check(score=None)[0])
        self.assertIn("scoring", self.check(scope={"labelled": [], "scored": []})[0])
        self.assertIn("configuration", self.check(code=False)[0])
        self.assertIn("configuration", self.check(code=None)[0])
        old = stored(scanner={"scanner": "gitleaks", "version": "8.29.0", "configuration": "default"})
        self.assertIn("version", self.check(s=old)[0])
        other = {"scanner": "gitleaks", "version": "8.30.1", "configuration": "--no-banner"}
        self.assertIn("configuration", self.check(now=other)[0])

    def test_a_scanner_without_pin_and_without_environment_is_not_reused(self):
        s = stored(scanner={"scanner": "x", "version": "1"})
        why = xb.reuse_check(s, "no_such_adapter", "c" * 64, SCOPE, None, True, True)
        self.assertTrue(any("no pin" in w for w in why))

    def test_the_stored_distributions_must_match_the_pinned_requirements(self):
        pins = xb.requirement_pins("presidio")
        self.assertTrue(pins)
        name, version = sorted(pins.items())[0]
        desc = {"scanner": "presidio", "version": "2.2.364",
                "installed": [f"{n}=={v}" for n, v in pins.items() if n != name] + [f"{name}=={version}.post9"]}
        why = xb.reuse_check(stored(scanner=desc), "presidio", "c" * 64, SCOPE, None, True, True)
        self.assertTrue(any("distributions" in w for w in why))
        desc["installed"] = [f"{n}=={v}" for n, v in pins.items()]
        self.assertEqual(xb.reuse_check(stored(scanner=desc), "presidio", "c" * 64, SCOPE, None, True, True), [])

    def test_the_scanner_is_read_from_the_file_name(self):
        self.assertEqual(xb.scanner_of("bank-dev-pii_anon.json.gz"), "pii_anon")
        self.assertEqual(xb.scanner_of("nemotron-val-every25-detect_secrets.json"), "detect_secrets")

    def test_an_unknown_commit_is_no_proof_of_an_unchanged_file(self):
        self.assertIsNone(xb._unchanged("f" * 40, ["bench/score.py"]))


class RunsTests(unittest.TestCase):
    def test_the_sets_meet_only_the_scanners_that_share_them(self):
        jobs = xb.new_jobs()
        by = {}
        for j in jobs:
            by.setdefault(j["source"], set()).add(j["scanner"])
        self.assertEqual(by["ghissues"], {"maisecrets", *xb.SECRET_SCANNERS})
        for pii in ("nym", "dialogpii", "structured", "structured-b"):
            self.assertEqual(by[pii], {"maisecrets", *xb.PII_SCANNERS}, pii)
        self.assertFalse(any("prowl" in j["name"].lower() for j in jobs))
        self.assertEqual(len({j["name"] for j in jobs}), len(jobs))

    def test_a_slow_scanner_reads_a_smaller_sample_that_maisecrets_also_reads(self):
        jobs = xb.new_jobs()
        names = {j["name"] for j in jobs}
        for j in jobs:
            if j["scanner"] in xb.SLOW and j["source"] in xb.SLOW[j["scanner"]]:
                self.assertEqual(j["every"], xb.SLOW[j["scanner"]][j["source"]])
                self.assertIn(j["name"].replace(j["scanner"], "maisecrets"), names)
        self.assertEqual(jobs[-1]["scanner"], "preserve")

    def test_the_structured_corpus_carries_its_label_and_has_no_holdout_of_set_a(self):
        for j in xb.new_jobs():
            if j["source"].startswith("structured"):
                self.assertIn("regression", j["label"])
                self.assertEqual(j["section"], "new-structured")
            else:
                self.assertEqual(j["label"], "")
        splits = {j["split"] for j in xb.new_jobs() if j["source"] == "structured"}
        self.assertEqual(splits, {"dev", "val"})

    def test_the_ghissues_rows_say_snippet_level(self):
        for j in xb.new_jobs():
            self.assertEqual(j["level"] == xb.SNIPPET, j["source"] == "ghissues")

    def test_a_run_without_its_data_is_skipped_and_set_b_needs_a_release_candidate(self):
        jobs = {j["name"]: j for j in xb.new_jobs()}
        cand, out = Path("/cand"), Path("/out/x.json")
        self.assertIsNone(xb.run_args(jobs["dialogpii-dev-full-maisecrets.json"], cand, {}, out))
        args = xb.run_args(jobs["dialogpii-dev-full-maisecrets.json"], cand, {"dialogpii": Path("/d")}, out)
        self.assertEqual(args[args.index("--data") + 1], str(Path("/d")))   # a Windows path prints \\d
        b = xb.run_args(jobs["structured-b-holdout-full-presidio.json"], cand, {"structured_b": Path("/b")}, out)
        self.assertIn("--release-candidate", b)
        nym = xb.run_args(jobs["nym-dev-every25-presidio.json"], cand, {"nym": Path("/n")}, out)
        self.assertEqual(nym[nym.index("--every") + 1], "25")
        self.assertEqual(nym[nym.index("--sample-salt") + 1], "v3/")

    def test_a_scanner_without_its_environment_is_named(self):
        self.assertEqual(xb.missing_env("gitleaks", {}), "BENCH_GITLEAKS")
        self.assertIsNone(xb.missing_env("gitleaks", {"BENCH_GITLEAKS": "/bin/gitleaks"}))
        self.assertIsNone(xb.missing_env("maisecrets", {}))


class ReportTests(unittest.TestCase):
    def test_new_sets_stand_in_their_own_sections(self):
        rows = [{"section": "new-structured", "name": "structured-dev-full-maisecrets.json", "scanner": "maisecrets",
                 "status": "measured", "level": xb.SPAN,
                 "summary": {"scanner": "maisecrets", "version": "0.8.2", "cases": 10, "spans": 20,
                             "recall_strict": 0.5, "precision": 1.0, "fp": 0}},
                {"section": "new-secret", "name": "ghissues-dev-full-gitleaks.json", "scanner": "gitleaks",
                 "status": "not run: BENCH_GITLEAKS is not set", "level": xb.SNIPPET}]
        text = xb.report(rows, Path("/out"), None, None)
        self.assertIn("## Structured corpus (targeted regression benchmark", text)
        self.assertIn("snippet + span", text)
        self.assertNotIn("Benchmark V3: maisecrets", text)
        structured = text.split("## Structured corpus")[1].split("## ")[0]
        self.assertNotIn("ghissues", structured)

    def test_the_summary_takes_v3_precision_and_the_snippet_level(self):
        res = {"metrics": {"all": {"spans": 4, "recall_strict": 0.5, "precision": 0.9, "fp": 3}},
               "v3": {"all": {"precision": 0.95, "fp": 1}}, "scanner": {"scanner": "s", "version": "1"},
               "ghissues": {"candidate_precision": 0.8, "candidate_recall": 0.7}}
        s = xb.summary(res)
        self.assertEqual((s["precision"], s["fp"]), (0.95, 1))
        self.assertEqual(s["snippet"], {"candidate_precision": 0.8, "candidate_recall": 0.7})


def _case(n, split="holdout", name="structured-b", spans=True):
    text = f"user_email: x{n}@example.org\nphone: 0"
    sp = [{"class": "pii.email", "start": 12, "end": 12 + len(f"x{n}@example.org"), "neutral": True,
           "field": "user_email", "style": "snake", "lang": "en"}] if spans else []
    return {"id": f"b{n}", "text": text, "channel": "tool", "context": "config", "spans": sp, "split": split,
            "source": {"name": name}, "lookalikes": []}


class SetBTests(unittest.TestCase):
    def write(self, cases):
        tmp = tempfile.mkdtemp()
        p = Path(tmp) / "cases.jsonl"
        p.write_text("".join(json.dumps(c) + "\n" for c in cases), encoding="utf-8")
        return p, hashlib.sha256(p.read_bytes()).hexdigest()

    def test_the_sealed_file_loads(self):
        p, sha = self.write([_case(1), _case(2, spans=False)])
        self.assertEqual(len(structured_b.verify(p, sha, 2)), 2)

    def test_another_file_is_refused_before_it_is_read(self):
        p, sha = self.write([_case(1)])
        with self.assertRaisesRegex(structured_b.SealError, "sha256"):
            structured_b.verify(p, "0" * 64, 1)
        with self.assertRaisesRegex(structured_b.SealError, "seal says"):
            structured_b.verify(p, sha, 2)

    def test_a_case_outside_the_holdout_of_set_b_is_refused(self):
        for bad in (_case(1, split="dev"), _case(1, name="structured")):
            p, sha = self.write([bad])
            with self.assertRaisesRegex(structured_b.SealError, "split or source.name"):
                structured_b.verify(p, sha, 1)

    def test_the_pinned_seal_is_the_one_of_the_holdout_log(self):
        log = (ROOT / "bench" / "HOLDOUT-LOG.md").read_text(encoding="utf-8")
        self.assertIn(structured_b.SHA256, log)
        self.assertIn(f"{structured_b.CASES} cases", log)

    def test_run_refuses_set_b_without_a_release_candidate(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
            brun.main(["--source", "structured-b", "--holdout", "/nonexistent"])
        self.assertIn("release-candidate", str(e.exception))


class ResourcesTests(unittest.TestCase):
    def test_the_peak_rss_is_read_on_macos_and_on_linux(self):
        self.assertEqual(mr.peak_rss_bytes("  1.0 real\n  52428800  maximum resident set size\n"), 52428800)
        self.assertEqual(mr.peak_rss_bytes("\tMaximum resident set size (kbytes): 2048\n"), 2048 * 1024)
        self.assertIsNone(mr.peak_rss_bytes("no time output"))

    def test_the_recorder_wraps_each_process_and_restores_the_runner(self):
        from bench.adapters import _proc
        orig = _proc.run
        seen = []

        def fake(cmd, name, env, cwd, timeout=0):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "  1048576  maximum resident set size\n")
        _proc.run = fake
        try:
            with mr.Recorder() as rec:
                _proc.run(["scanner", "in"], "x", {}, "/")
            self.assertEqual(seen[0][:len(mr.TIME_CMD)], mr.TIME_CMD)
            self.assertEqual(rec.calls[0]["rss"], 1048576)
            self.assertIs(_proc.run, fake)
        finally:
            _proc.run = orig

    def test_the_table_names_the_machine_the_load_and_what_was_not_measured(self):
        res = {"machine": {"cpu": "Test CPU", "cpus": 4, "ram_gb": 8, "os": "TestOS 1"},
               "load_average": {"start": 9.0, "end": 1.0},
               "scanners": {"maisecrets": {"cells": {"prompt": {"mode": "one process, calls in a row",
                                                                "cold_start_ms": 50, "warm": {"median_ms": 0.4,
                                                                                              "p95_ms": 0.9},
                                                                "peak_rss_mb": 40},
                                                     "tool_1mb": {"error": "MemoryError"}},
                                           "footprint": {"what": "x", "disk_mb": 5, "models_mb": 0, "torch": False},
                                           "network": "no"},
                            "presidio": {"skipped": "not installed here"}},
               "ner_doc": mr.NER_DOC}
        text = mr.markdown(res)
        self.assertIn("Test CPU, 4 CPUs, 8 GB RAM, TestOS 1", text)
        self.assertIn("the times say little", text)
        self.assertIn("| presidio | – | not installed here", text)
        self.assertIn("failed: MemoryError", text)
        self.assertIn("not measured here", text)

    def test_a_scanner_counts_as_installed_only_with_its_environment(self):
        self.assertTrue(mr.available("maisecrets", {}))
        self.assertFalse(mr.available("presidio", {}))
        self.assertTrue(mr.available("presidio", {"BENCH_PRESIDIO_PYTHON": "/p"}))
        self.assertFalse(mr.available("maisecrets_ner", {"BENCH_NER_PYTHON": "/p"}))


class StagedTests(unittest.TestCase):
    def stage(self, name, **over):
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        tmp = Path(tempfile.mkdtemp())
        (tmp / "results").mkdir()
        res = {"bench_commit": head, "bench_dirty": False, "cases_sha256": "c" * 64, "source": "ghissues",
               "scanner": {"scanner": "gitleaks", "version": "8.30.1"}}
        res.update(over)
        (tmp / "results" / name).write_text(json.dumps(res), encoding="utf-8")
        return tmp

    def plan(self, staged, name):
        jobs = [j for j in xb.new_jobs() if j["name"] == name]
        xb.staged_plan(jobs, staged, {})
        return jobs[0]

    def test_a_staged_result_of_another_scanner_is_taken_when_unchanged(self):
        name = "ghissues-holdout-full-gitleaks.json"
        self.assertTrue(self.plan(self.stage(name), name)["reuse"]["ok"])

    def test_a_staged_result_is_refused_when_its_tree_was_modified_or_its_version_differs(self):
        name = "ghissues-holdout-full-gitleaks.json"
        self.assertFalse(self.plan(self.stage(name, bench_dirty=True), name)["reuse"]["ok"])
        old = self.stage(name, scanner={"scanner": "gitleaks", "version": "8.29.0"})
        self.assertFalse(self.plan(old, name)["reuse"]["ok"])
        unknown = self.stage(name, bench_commit="f" * 40)
        self.assertFalse(self.plan(unknown, name)["reuse"]["ok"])

    def test_a_staged_maisecrets_result_is_never_taken(self):
        name = "ghissues-holdout-full-maisecrets.json"
        self.assertNotIn("reuse", self.plan(self.stage(name), name))


class MergeResourcesTests(unittest.TestCase):
    def test_the_staged_rows_of_the_other_scanners_join_the_candidates_rows(self):
        tmp = Path(tempfile.mkdtemp())
        m = {"cpu": "Test CPU", "cpus": 4, "ram_gb": 8, "os": "TestOS"}
        row = {"cells": {}, "footprint": {"what": "x", "disk_mb": 1, "models_mb": 0, "torch": False}, "network": "no"}
        mine = {"machine": m, "load_average": {"start": 1, "end": 1}, "scanners": {"maisecrets": row}}
        staged = {"machine": m, "load_average": {"start": 2, "end": 3}, "date": "2026-10-25",
                  "scanners": {"maisecrets": {"skipped": "old candidate"}, "presidio": row}}
        (tmp / "resources.json").write_text(json.dumps(mine), encoding="utf-8")
        (tmp / "staged.json").write_text(json.dumps(staged), encoding="utf-8")
        res = xb.merge_resources(tmp / "resources.json", tmp / "staged.json")
        self.assertEqual(set(res["scanners"]), {"maisecrets", "presidio"})
        self.assertNotIn("skipped", res["scanners"]["maisecrets"])
        self.assertTrue(res["scanners"]["presidio"]["staged"])
        self.assertIn("staging run", (tmp / "resources.md").read_text(encoding="utf-8"))
        staged["machine"] = {**m, "cpu": "Other CPU"}
        (tmp / "staged.json").write_text(json.dumps(staged), encoding="utf-8")
        (tmp / "resources.json").write_text(json.dumps(mine), encoding="utf-8")
        self.assertIn("staged_not_merged", xb.merge_resources(tmp / "resources.json", tmp / "staged.json"))


if __name__ == "__main__":
    unittest.main()
