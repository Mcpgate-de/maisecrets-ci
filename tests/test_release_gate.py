"""scripts/release_gate.py: the diff since the last release decides what to measure, and a span the candidate masks
worse than the release stops the gate (2026-10-22: 0.7.6 shipped a phone number it lost, found only after release)."""
from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import release_gate as gate  # noqa: E402


def result(outcomes: dict, sha: str = "abc") -> dict:
    return {"cases_sha256": sha, "per_case": outcomes}


class ReleaseGateTests(unittest.TestCase):
    def test_the_diff_decides_whether_to_measure(self):
        kind = gate.classify(["maisecrets/detection/personal.py", "docs/BENCHMARKS.md"])
        self.assertTrue(kind["retest"])
        self.assertFalse(kind["live"])
        kind = gate.classify(["maisecrets/hooks.py", "claude-mod/maisecrets-mod.mjs", "tests/test_x.py"])
        self.assertFalse(kind["retest"])
        self.assertTrue(kind["live"])
        kind = gate.classify(["docs/BENCHMARK-V3.md", "bench/run.py", ".gitlab-ci.yml", ".claude-plugin/plugin.json"])
        self.assertEqual((False, False), (kind["retest"], kind["live"]))

    def test_a_span_masked_worse_stops_the_gate(self):
        base = result({"a": ["full", "missed", "fp"], "b": ["partial"]})
        better = result({"a": ["full", "full", "fp"], "b": ["full"]})
        worse = result({"a": ["missed", "full"], "b": ["partial", "fp", "fp"]})
        self.assertEqual(0, gate.compare(base, better)["worse"])
        r = gate.compare(base, worse)
        self.assertEqual(1, r["worse"])
        self.assertEqual([1, 2], r["fp"])
        self.assertFalse(gate.compare(base, result({}, sha="other"))["comparable"])
        kind = gate.classify(["maisecrets/detection/core.py"])
        self.assertTrue(gate.report(kind, {"x": gate.compare(base, worse)}, None)[1])
        self.assertFalse(gate.report(kind, {"x": gate.compare(base, better)}, None)[1])

    def test_holdout_recall_may_not_fall(self):
        kind = gate.classify(["maisecrets/detection/core.py"])
        self.assertTrue(gate.report(kind, {}, (0.63, 0.61))[1])
        self.assertFalse(gate.report(kind, {}, (0.63, 0.63))[1])

    def test_the_run_is_compared_with_the_gzip_results_of_the_release(self):
        with tempfile.TemporaryDirectory() as d:
            base, run = Path(d) / "base", Path(d) / "run"
            base.mkdir()
            run.mkdir()
            with gzip.open(base / "nemotron-dev-maisecrets-full.json.gz", "wt", encoding="utf-8") as f:
                json.dump(result({"a": ["full"]}), f)
            (run / "nemotron-dev-maisecrets-full.json").write_text(json.dumps(result({"a": ["missed"]})))
            (run / "gretel-dev-maisecrets-full.json").write_text(json.dumps(result({"a": ["full"]})))
            out = gate.compare_dirs(base, run)
            self.assertEqual(1, out["nemotron-dev-maisecrets-full"]["worse"])
            self.assertFalse(out["gretel-dev-maisecrets-full"]["comparable"])



def git(cwd: Path, *args: str) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.com")
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


class MeasuredBaselineTests(unittest.TestCase):
    """The measurement of the gate is the next baseline: the release commit changes only the version, so the tag
    holds the measured code, and --verify-tag shows it by the git trees."""

    def repo(self, d: str) -> Path:
        r = Path(d) / "repo"
        (r / "maisecrets").mkdir(parents=True)
        (r / ".claude-plugin").mkdir()
        (r / "maisecrets" / "core.py").write_text("x = 1\n")
        (r / ".claude-plugin" / "plugin.json").write_text('{"version": "0.0.1"}\n')
        git(r, "init", "-q")
        git(r, "add", "-A")
        git(r, "commit", "-qm", "a")
        return r

    def test_the_next_version_moves_the_last_number(self):
        self.assertEqual("0.7.7", gate.next_version("v0.7.6"))
        self.assertEqual("1.0.10", gate.next_version("v1.0.9"))

    def test_kept_results_are_gzip_without_local_paths_and_name_the_measured_trees(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.repo(d)
            out, dest = Path(d) / "out", Path(d) / "dest"
            out.mkdir()
            run = result({"a": ["full"]})
            run["scanner"] = {"python": str(Path.home() / "venv" / "bin" / "python3"), "checkout": str(r)}
            (out / "nemotron-dev-maisecrets-full.json").write_text(json.dumps(run))
            (out / "holdout-v2.json").write_text(json.dumps(run))
            (out / "release-gate.md").write_text("**Gate: passed**\n")
            gate.keep(out, dest, r, "0.0.2")
            text = gzip.open(dest / "nemotron-dev-maisecrets-full.json.gz", "rt", encoding="utf-8").read()
            self.assertNotIn(str(Path.home()), text)
            self.assertIn("<candidate>", text)
            self.assertTrue((dest / "holdout-v2" / "holdout-v2-v0.0.2.json.gz").exists())
            self.assertTrue((dest / "release-gate.md").exists())
            first = (dest / "nemotron-dev-maisecrets-full.json.gz").read_bytes()
            gate.keep(out, dest, r, "0.0.2")
            self.assertEqual(first, (dest / "nemotron-dev-maisecrets-full.json.gz").read_bytes())
            measured = json.loads((dest / "measured.json").read_text())
            self.assertEqual(git(r, "rev-parse", "HEAD"), measured["commit"])
            self.assertIn({"dir": "maisecrets", "tree": git(r, "rev-parse", "HEAD:maisecrets")}, measured["trees"])
            self.assertIn("measured.json", (dest / "SHA256SUMS").read_text())

    def test_a_windows_path_escaped_inside_json_is_replaced_too(self):
        # json.dumps writes C:\\Users\\… for C:\Users\…; the first version replaced only the plain form, and the
        # Windows runner kept the local paths (2026-10-22, release MR !213)
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            r = self.repo(d)
            out, dest = Path(d) / "out", Path(d) / "dest"
            out.mkdir()
            home = "C:\\Users\\tester"
            run = result({"a": ["full"]})
            run["scanner"] = {"python": home + "\\venv\\python.exe"}
            (out / "nemotron-dev-maisecrets-full.json").write_text(json.dumps(run))
            with mock.patch.object(gate.Path, "home", return_value=Path(home)):
                gate.keep(out, dest, r, "0.0.2")
            text = gzip.open(dest / "nemotron-dev-maisecrets-full.json.gz", "rt", encoding="utf-8").read()
            self.assertNotIn("tester", text)
            self.assertIn("<home>", text)

    def test_a_tag_that_changes_only_the_version_holds_the_measured_code(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.repo(d)
            res = r / "bench" / "results" / "2026-01-01-v3-0.0.2"
            res.mkdir(parents=True)
            trees = [{"dir": k, "tree": v} for k, v in gate.runtime_trees("HEAD", r).items()]
            (res / "measured.json").write_text(json.dumps({"trees": trees}))
            (r / ".claude-plugin" / "plugin.json").write_text('{"version": "0.0.2"}\n')
            git(r, "commit", "-qam", "release")
            git(r, "tag", "v0.0.2")
            self.assertEqual([], gate.verify_tag("v0.0.2", r))
            (r / "maisecrets" / "core.py").write_text("x = 2\n")
            git(r, "commit", "-qam", "change")
            git(r, "tag", "v0.0.3")
            (res.parent / "2026-01-01-v3-0.0.3").mkdir()
            (res.parent / "2026-01-01-v3-0.0.3" / "measured.json").write_text((res / "measured.json").read_text())
            self.assertEqual(["maisecrets"], gate.verify_tag("v0.0.3", r))



class CoverageAndTimeTests(unittest.TestCase):
    """The gate's floor for the catalog coverage and its limit for the CPU time (0.7.9)."""

    def test_coverage_may_not_fall_and_another_catalog_commit_is_not_compared(self):
        from unittest import mock
        pinned = {"commits": {"a": "c1", "b": "c1", "c": "c1"},
                  "counts": {"a": {"bare": 10, "label": 20}, "b": {"bare": 5, "label": 5},
                             "c": {"bare": 1, "label": 1}}}
        got = {"commits": {"a": "c1", "b": "c1", "c": "other"},
               "counts": {"maisecrets": {"a": {"bare": 11, "label": 20}, "b": {"bare": 4, "label": 6},
                                         "c": {"bare": 0, "label": 0}}}}
        with tempfile.TemporaryDirectory() as d:
            out, cov = Path(d), Path(d) / "pinned.json"
            cov.write_text(json.dumps(pinned))

            def fake_run(cmd, **_kw):
                (out / "coverage.json").write_text(json.dumps(got))
            with mock.patch.object(gate, "COVERAGE", cov), mock.patch.object(gate.subprocess, "run", fake_run):
                lines, failed = gate.coverage_check(Path(d), Path(d), out, "python3")
        self.assertTrue(failed)
        text = "\n".join(lines)
        self.assertIn("| b | 5 → 4 **fell** | 5 → 6 |", text)
        self.assertIn("| a | 10 → 11 | 20 → 20 |", text)
        self.assertIn("| c | not compared", text)
        got["counts"]["maisecrets"]["b"]["bare"] = 5
        with tempfile.TemporaryDirectory() as d:
            out, cov = Path(d), Path(d) / "pinned.json"
            cov.write_text(json.dumps(pinned))
            with mock.patch.object(gate, "COVERAGE", cov), mock.patch.object(
                    gate.subprocess, "run", lambda cmd, **_k: (out / "coverage.json").write_text(json.dumps(got))):
                self.assertFalse(gate.coverage_check(Path(d), Path(d), out, "python3")[1])

    def test_more_than_a_fifth_more_cpu_time_stops_the_gate(self):
        med = {"base": {"tool_1mb": 4.0, "prompt": 0.5}, "candidate": {"tool_1mb": 4.4, "prompt": 0.65}}
        # +30 % on a prompt is 0.15 ms: too small to stop a release
        self.assertFalse(gate.time_report(med, "v1", 3, (1.0, 1.0), 8)[1])
        med["candidate"]["tool_1mb"] = 4.9
        lines, failed = gate.time_report(med, "v1", 3, (1.0, 1.0), 8)
        self.assertTrue(failed)
        self.assertIn("**slower**", "\n".join(lines))
        self.assertIn("say little", "\n".join(gate.time_report(med, "v1", 3, (12.0, 3.0), 8)[0]))


if __name__ == "__main__":
    unittest.main()
