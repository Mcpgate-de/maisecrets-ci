"""scripts/measure_fp_bank.py: each tree is pinned to a full commit, a tree that is not at its commit is refused, the
result holds counts and no text of the tree, and compare fails only when the acted hits rose.

Run: python3 -m unittest tests.test_measure_fp_bank -v
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("measure_fp_bank", ROOT / "scripts" / "measure_fp_bank.py")
fb = importlib.util.module_from_spec(_spec)
sys.modules["measure_fp_bank"] = fb
_spec.loader.exec_module(fb)

PROBE = "fpbankprobe-word-in-the-tree"
IP = ".".join(["52", "14", "7", "9"])  # a public address the ip rule acts on, built here so the file holds none


def git(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}   # no GIT_DIR of a calling hook
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(cwd), *args],
                          check=True, capture_output=True, text=True, env=env).stdout.strip()


class PinTests(unittest.TestCase):
    def test_each_tree_has_a_unique_name_and_a_full_commit(self):
        names = [t[1] for t in fb.TREES]
        self.assertEqual(len(names), 7)
        self.assertEqual(len(set(names)), len(names))
        for commit, name, url, sub in fb.TREES:
            self.assertRegex(commit, r"^[0-9a-f]{40}$", name)
            self.assertTrue(url.startswith("https://github.com/") and url.endswith(".git"), name)
            self.assertFalse(sub.startswith("/") or ".." in sub, name)


class MeasureTests(unittest.TestCase):
    """A local repository stands in for the public tree, so fetch and measure run without the network."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix="fpbank-test-"))
        self.addCleanup(fb.remove_tree, base)
        self.cache = base / "cache"
        d = self.source = base / "source"
        (d / "src").mkdir(parents=True)
        (d / "src" / "notes.md").write_text(f"{PROBE}\nthe host is {IP} today\n")
        (d / "src" / "run.bat").write_text("@echo off\n")   # a checkout writes it with CRLF
        (d / ".gitattributes").write_text("*.bat text eol=crlf\n")
        (d / "src" / ".gitignore").write_text("*.log\n")
        if os.name != "nt":   # Windows writes a link as a file (core.symlinks=false), which the bank refuses
            os.symlink("missing.md", d / "src" / "link.md")   # a link without a target, as in detect-secrets
            (d / "src" / "data").mkdir()
            (d / "src" / "data" / "blob.bin").write_bytes(b"x")
            os.symlink("data", d / "src" / "data-link")   # a link to a directory
        (d / "src" / "skip.bin").write_text(PROBE)
        (d / "outside.md").write_text(f"{PROBE} {IP}\n")
        git(d, "init", "-q")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "tiny")
        self.commit = git(d, "rev-parse", "HEAD")
        self.fetch()

    def trees(self, commit=None):
        return mock.patch.object(fb, "TREES", ((commit or self.commit, "tiny", str(self.source), "src"),))

    def fetch(self, commit=None):
        with self.trees(commit), contextlib.redirect_stdout(io.StringIO()) as out:
            fb.fetch(self.cache)
        return out.getvalue()

    def run_bank(self, commit=None):
        with self.trees(commit):
            return fb.measure(self.cache, detect)

    def test_fetch_makes_a_clone_at_the_commit_and_keeps_it_the_second_time(self):
        clone = self.cache / "tiny"
        self.assertEqual(git(clone, "rev-parse", "HEAD"), self.commit)
        self.assertTrue((clone / "src" / "notes.md").is_file())
        self.assertEqual([p.name for p in self.cache.iterdir()], ["tiny"], "no temp directory is left")
        self.assertIn("tiny: at", self.fetch())

    def test_fetch_only_reads_a_directory_it_did_not_make(self):
        # a checkout or a fetch could run a hook or a filter of that repository; rev-parse and status run neither
        calls = []
        real = fb.git

        def spy(cwd, *args):
            calls.append((Path(cwd), args[0]))
            return real(cwd, *args)

        with mock.patch.object(fb, "git", spy):
            self.fetch()
        mine = {a for cwd, a in calls if cwd == self.cache / "tiny"}
        self.assertEqual(mine, {"rev-parse", "ls-tree"})
        fb.remove_tree(self.cache / "tiny")
        with mock.patch.object(fb, "git", spy):
            self.fetch()
        made = {a for cwd, a in calls if cwd.parent == self.cache and cwd.name.startswith(".tiny-")}
        self.assertTrue({"init", "fetch", "checkout"} <= made, "the premise: a new clone is made in a new directory")
        fb.remove_tree(self.cache / "tiny")
        (self.cache / "tiny").mkdir()
        (self.cache / "tiny" / "keep.txt").write_text("mine")
        with self.assertRaises(SystemExit) as cm:
            self.fetch()
        self.assertIn("remove it and fetch again", str(cm.exception))
        self.assertEqual((self.cache / "tiny" / "keep.txt").read_text(), "mine", "the directory stays as it is")

    def test_the_git_env_of_a_calling_hook_does_not_reach_the_bank(self):
        # a hook in a linked worktree exports GIT_DIR and GIT_INDEX_FILE; a sentinel repository stands in for the
        # real one, so the probe never points git at a repository that matters
        sentinel = self.source.parent / "sentinel"
        sentinel.mkdir()
        git(sentinel, "init", "-q")
        (sentinel / "a.txt").write_text("a\n")
        git(sentinel, "add", "a.txt")
        git(sentinel, "commit", "-q", "-m", "sentinel")
        before = (git(sentinel, "rev-parse", "HEAD"), (sentinel / ".git" / "config").read_text())
        fb.remove_tree(self.cache / "tiny")
        hook_env = {"GIT_DIR": str(sentinel / ".git"), "GIT_INDEX_FILE": str(sentinel / ".git" / "index")}
        with mock.patch.dict(os.environ, hook_env):
            self.fetch()
            self.assertEqual(self.run_bank()["trees"]["tiny"]["files"], 1)
        self.assertEqual(git(self.cache / "tiny", "rev-parse", "HEAD"), self.commit)
        self.assertEqual((git(sentinel, "rev-parse", "HEAD"), (sentinel / ".git" / "config").read_text()), before)
        self.assertEqual(git(sentinel, "status", "--porcelain"), "", "nothing staged or changed in the sentinel")

    def test_a_failed_or_empty_fetch_leaves_nothing_behind(self):
        fb.remove_tree(self.cache / "tiny")
        with self.assertRaises(subprocess.CalledProcessError):
            self.fetch("0" * 40)   # a commit the source does not have
        with mock.patch.object(fb, "TREES", ((self.commit, "tiny", str(self.source), "no-such-dir"),)):
            with self.assertRaises(SystemExit) as cm:   # a clean clone without the subdirectory would count nothing
                fb.fetch(self.cache)
        self.assertIn("not a clean tree", str(cm.exception))
        self.assertEqual(list(self.cache.iterdir()), [], "no clone and no temp directory")

    def test_a_changed_clone_is_refused(self):
        notes = self.cache / "tiny" / "src" / "notes.md"
        changes = ("added", "changed", "deleted", "ignored", "skipped") + (("link as file",) if os.name != "nt" else ())
        for change in changes:
            with self.subTest(change):
                if change == "added":
                    (notes.parent / "extra.md").write_text("x\n")
                elif change == "changed":
                    notes.write_text("other text\n")
                elif change == "link as file":   # what a checkout with core.symlinks=false writes
                    (notes.parent / "link.md").unlink()
                    (notes.parent / "link.md").write_text("missing.md")
                elif change == "ignored":   # git status does not list it, the walk reads it
                    (notes.parent / "extra.log").write_text("x\n")
                elif change == "skipped":   # git status does not miss it
                    git(self.cache / "tiny", "update-index", "--skip-worktree", "src/notes.md")
                    notes.unlink()
                else:
                    notes.unlink()
                with self.assertRaises(SystemExit):
                    self.run_bank()
                git(self.cache / "tiny", "update-index", "--no-skip-worktree", "src/notes.md")
                git(self.cache / "tiny", "checkout", "-q", "--", ".")
                for name in ("extra.md", "extra.log"):
                    (notes.parent / name).unlink(missing_ok=True)
        self.assertEqual(self.run_bank()["trees"]["tiny"]["files"], 1, "the restored clone is measured again")

    def test_a_tree_at_its_commit_is_counted_in_its_subdirectory_only(self):
        result = self.run_bank()
        tree = result["trees"]["tiny"]
        self.assertEqual(tree["commit"], self.commit)
        self.assertEqual(tree["files"], 1, "src/notes.md only: no .bin, and outside.md is not in src")
        self.assertRegex(result["maisecrets"], r"^[0-9a-f]{40}$")
        for key, (hits, acted) in tree["rules"].items():
            self.assertRegex(key, r"^(tests|other)\|[A-Z_]+\|[\w.-]+$")
            self.assertLessEqual(acted, hits)
        self.assertEqual(tree["rules"], {"other|IP|ip": [1, 1]}, "one address, in src only")

    def test_the_result_holds_no_text_of_the_tree(self):
        text = json.dumps(self.run_bank())
        for part in (PROBE, IP, "notes.md"):
            self.assertNotIn(part, text)

    def test_a_tree_not_at_its_commit_is_refused(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_bank("0" * 40)
        self.assertIn("run fetch first", str(cm.exception))


def bank(commit="c" * 40, **rules):
    return {"maisecrets": "m" * 40, "trees": {"t": {"commit": commit, "files": 1, "chars": 1,
                                                       "rules": {k.replace("__", "|"): v for k, v in rules.items()}}}}


class CompareTests(unittest.TestCase):
    def compare(self, before, after):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fb.compare(before, after)
        return code, out.getvalue()

    def test_more_acted_hits_fail_and_name_the_rule(self):
        code, out = self.compare(bank(other__EMAIL__email=[3, 2]), bank(other__EMAIL__email=[4, 3]))
        self.assertEqual(code, 1)
        self.assertIn("other|EMAIL|email", out)
        self.assertIn("+1", out)

    def test_fewer_or_equal_acted_hits_pass(self):
        self.assertEqual(self.compare(bank(other__IP__ip=[5, 5]), bank(other__IP__ip=[5, 4]))[0], 0)
        self.assertEqual(self.compare(bank(other__IP__ip=[5, 5]), bank(other__IP__ip=[9, 5]))[0], 0,
                         "a hit the test-code rule drops is not a false alarm a user sees")

    def test_a_new_rule_counts_and_a_moved_commit_is_not_compared(self):
        self.assertEqual(self.compare(bank(), bank(tests__SECRET__jwt=[1, 1]))[0], 1)
        code, out = self.compare(bank(other__IP__ip=[1, 1]), bank("d" * 40, other__IP__ip=[9, 9]))
        self.assertEqual(code, 2, "two runs on different input are no result, not a pass")
        self.assertIn("not comparable", out)
        self.assertEqual(self.compare(bank(), {"maisecrets": "m" * 40, "trees": {}})[0], 2, "a tree is missing")

    def test_the_totals_split_test_code_from_the_rest(self):
        tree = bank(other__IP__ip=[5, 4], tests__IP__ip=[3, 1])["trees"]["t"]
        self.assertEqual(fb.totals(tree), (8, 5, 4))


class FalseAlarmScriptTests(unittest.TestCase):
    def test_the_script_prints_the_same_table_as_before_the_split(self):
        d = Path(tempfile.mkdtemp(prefix="fpbank-mfa-"))
        self.addCleanup(fb.remove_tree, d)
        (d / "a.md").write_text(f"the host is {IP} today\n")
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "measure_false_alarms.py"), str(d)],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(out, "1 files, 0.0 MB\n"
                              "where  type               rule                                       hits  acted\n"
                              "other  IP                 ip                                            1      1\n")


if __name__ == "__main__":
    unittest.main()
