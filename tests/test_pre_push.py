"""The pre-push hook skips its checks only for commits that a branch of origin already holds.

Run: python3 -m unittest tests.test_pre_push -v
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / ".githooks" / "pre-push"
ZERO = "0" * 40


# on Windows `bash` on the PATH is the WSL launcher, not the bash of Git that runs the hook there (windows-latest,
# 2026-11-07: "Windows Subsystem for Linux has no installed distributions")
@unittest.skipIf(os.name == "nt", "the hook runs under the bash of Git for Windows, not the bash on the PATH")
@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class PrePushTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pre-push-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        # no GIT_* of the caller: a hook's environment (GIT_DIR, GIT_INDEX_FILE) would point the commits below at the
        # outer repository
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env = dict(env, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL=os.devnull)
        self.env = env
        self.git("init", "-q", "-b", "main")
        (self.dir / "a.txt").write_text("a\n")
        self.git("add", "a.txt")
        self.git("commit", "-q", "-m", "a")
        self.pushed = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.pushed)   # what a fetch of origin leaves
        (self.dir / "b.txt").write_text("b\n")
        self.git("add", "b.txt")
        self.git("commit", "-q", "-m", "b")
        self.new = self.git("rev-parse", "HEAD")

    def git(self, *args) -> str:
        return subprocess.run(["git", *args], cwd=self.dir, env=self.env, capture_output=True, text=True,
                              check=True).stdout.strip()

    def push(self, sha: str, ref: str = "refs/heads/main"):
        return subprocess.run(["bash", str(HOOK), "netcup", "x"], cwd=self.dir, env=self.env, capture_output=True,
                              text=True, input=f"{ref} {sha} {ref} {ZERO}\n", timeout=60)

    def test_a_commit_on_origin_is_not_checked_again(self):
        r = self.push(self.pushed)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("nothing new to check", r.stdout)

    def test_a_new_commit_runs_the_checks(self):
        # this repository has none of the scripts, so the checks fail: the proof that they ran
        r = self.push(self.new)
        self.assertNotIn("nothing new to check", r.stdout)
        self.assertNotEqual(r.returncode, 0)

    def test_a_commit_on_another_branch_of_origin_runs_the_checks(self):
        # a branch push gets no pipeline: only main and next count as checked
        self.git("update-ref", "refs/remotes/origin/bench/x", self.new)
        r = self.push(self.new)
        self.assertNotIn("nothing new to check", r.stdout)

    def test_a_tag_push_is_refused_even_when_the_commit_is_on_origin(self):
        r = self.push(self.pushed, "refs/tags/v9.9.9")
        self.assertEqual(r.returncode, 1)
        self.assertIn("tag pushes are refused", r.stdout)


if __name__ == "__main__":
    unittest.main()
