"""The release tooling: subjects to versions, reverts, and the GitHub wait under network errors."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseClassificationTests(unittest.TestCase):
    def setUp(self):
        self.r = _load("release")

    def test_types_decide_a_release_and_docs_release_nothing(self):
        r = self.r
        self.assertEqual(r.bump_for([("a", "feat(x): y", "")]), "minor")
        self.assertEqual(r.bump_for([("a", "fix(x): y", "")]), "patch")
        self.assertIsNone(r.bump_for([("a", "docs: y", ""), ("b", "ci(x): z", ""), ("c", "test: t", "")]))
        self.assertIsNone(r.bump_for([("a", "Merge branch x", "")]), "a merge subject releases nothing")
        self.assertEqual(r.next_version("0.3.24", "minor"), "0.3.25", "a feature moves the last number")
        self.assertEqual(r.next_version("0.3.24", "major"), "0.3.25", "a break too, without approval")
        self.assertEqual(r.next_version("1.2.3", "minor"), "1.2.4")

    def test_any_revert_is_a_patch_under_reverts_and_passes_the_format_check(self):
        r = self.r
        for subject in ('Revert "feat(x): y"', 'Revert "refactor(hooks): y"', 'Revert "Merge branch x"'):
            with self.subTest(subject):
                typ, text, breaking = r.classify(subject, "")
                self.assertEqual((typ, breaking), ("revert", False))
                self.assertTrue(text.startswith("revert: "))
                self.assertEqual(r.bump_for([("a", subject, "")]), "patch")
        typ, text, _b = r.classify('Revert "Revert "feat(x): y""', "")
        self.assertEqual(typ, "revert")
        self.assertTrue(text.startswith("re-apply: "))
        self.assertIn("Reverts", r.render_notes("0.3.99", [("abc1234", 'Revert "feat(x): y"', "")]))


class GitHubWaitTests(unittest.TestCase):
    def test_network_errors_are_waited_out_and_green_checks_end_the_wait(self):
        w = _load("wait_for_github_checks")
        answers = [urllib.error.URLError("dns"), TimeoutError(), {"check_runs": [
            {"name": "tests (ubuntu-latest)", "status": "completed", "conclusion": "success"},
            {"name": "tests (windows-latest)", "status": "completed", "conclusion": "skipped"}]}]

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=30):
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return _Resp(json.dumps(a).encode())
        with mock.patch.object(w.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.object(w, "_main_moved", lambda sha: False), \
                mock.patch.object(w.time, "sleep", lambda s: None), \
                mock.patch.object(sys, "stdout", io.StringIO()) as out:
            rc = w.main(["wait", "deadbeef"])
        self.assertEqual(rc, 0)
        self.assertIn("unreachable", out.getvalue())
        self.assertIn("green", out.getvalue())

    def test_a_failed_check_ends_the_wait_red_and_a_moved_main_steps_aside(self):
        w = _load("wait_for_github_checks")

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        red = {"check_runs": [{"name": "tests (windows-latest)", "status": "completed", "conclusion": "failure"}]}
        with mock.patch.object(w.urllib.request, "urlopen", lambda req, timeout=30: _Resp(json.dumps(red).encode())), \
                mock.patch.object(w, "_main_moved", lambda sha: False), \
                mock.patch.object(w.time, "sleep", lambda s: None), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(w.main(["wait", "deadbeef"]), 1)
        with mock.patch.object(w, "_main_moved", lambda sha: True), mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(w.main(["wait", "deadbeef"]), 0)

    def test_a_cancelled_run_that_a_newer_one_replaced_is_no_failure(self):
        # release of 0.6.6: the commit had a cancelled run and, beside it, a newer green one; the gate went red
        w = _load("wait_for_github_checks")

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def runs(newest: str) -> dict:
            return {"check_runs": [
                {"id": 1, "name": "tests (windows-latest)", "status": "completed", "conclusion": "cancelled"},
                {"id": 2, "name": "tests (macos-latest)", "status": "completed", "conclusion": "cancelled"},
                {"id": 3, "name": "tests (windows-latest)", "status": "completed", "conclusion": newest},
                {"id": 4, "name": "tests (macos-latest)", "status": "completed", "conclusion": "success"}]}
        for newest, want in (("success", 0), ("failure", 1)):
            with self.subTest(newest), \
                    mock.patch.object(w.urllib.request, "urlopen",
                                      lambda req, timeout=30, n=newest: _Resp(json.dumps(runs(n)).encode())), \
                    mock.patch.object(w, "_main_moved", lambda sha: False), \
                    mock.patch.object(w.time, "sleep", lambda s: None), \
                    mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(w.main(["wait", "deadbeef"]), want)


if __name__ == "__main__":
    unittest.main()


class ListingManifestTests(unittest.TestCase):
    """What each directory reads before it shows the plugin. Anthropic's portal names its icon
    rule in the ICON_MISSING finding: `icon` in plugin.json, or .claude-plugin/icon.svg|png, or
    assets/icon.*, square, at least 128 px. OpenAI reads .codex-plugin/plugin.json and shows
    interface.composerIcon and interface.logo (every example in github.com/openai/plugins ships
    a square PNG or SVG between 32 and 1024 px). The release script must bump every manifest,
    or the Codex listing would fall behind the Claude one."""

    def setUp(self):
        self.r = _load("release")
        self.claude = json.loads((ROOT / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
        self.codex = json.loads((ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))

    @staticmethod
    def _png_size(path: Path) -> tuple[int, int]:
        head = path.read_bytes()[:24]
        assert head[:8] == b"\x89PNG\r\n\x1a\n", f"{path} is not a PNG"
        return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")

    def test_every_manifest_is_bumped_by_the_release_and_agrees_now(self):
        self.assertIn(".codex-plugin/plugin.json", self.r.MANIFESTS)
        versions = {rel: self.r.manifest_version(rel) for rel in self.r.MANIFESTS}
        self.assertEqual(len(set(versions.values())), 1, versions)
        for rel in self.r.MANIFESTS:
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertEqual(1, len(self.r.re.findall(r'"version":\s*"\d+\.\d+\.\d+"', text)), rel)

    def test_the_release_job_stages_every_manifest_it_bumps(self):
        """release.py apply rewrites every entry of MANIFESTS in the working tree, but the release
        job commits only what its `git add` line names: v0.3.29 bumped two manifests and left the
        Codex one at 0.3.28 (2026-09-27). The list in the job must cover MANIFESTS."""
        ci = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        adds = [line for line in ci.splitlines() if line.strip().startswith("- git add -- ")]
        self.assertEqual(1, len(adds), adds)
        for rel in self.r.MANIFESTS:
            self.assertIn(f" {rel} ", adds[0] + " ", rel)
        # verify_release compares the release commit's sorted file list with a fixed string;
        # v0.3.30 failed there after the Codex manifest joined (2026-09-27)
        expected = " ".join(sorted(list(self.r.MANIFESTS) + ["CHANGELOG.md"])) + " "
        self.assertIn(f'"{expected}")', ci, "verify_release must list exactly the files the release commits")

    def test_the_directory_hold_stops_only_the_release_branch(self):
        """With MAISECRETS_DIRECTORY_HOLD "1", mirror_tag ends before it moves the GitHub branch
        release, which the Anthropic directory tracks, and after it pushed main and the tag, which the
        organisation marketplace and the Codex install read. notify_marketplace still runs."""
        ci = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        # the switch is set in one place; its value is the maintainer's (off since the approval of 0.5.9, 2026-09-30)
        self.assertRegex(ci, r'\nvariables:\n  MAISECRETS_DIRECTORY_HOLD: "[01]"\n')
        job = ci[ci.index("\nmirror_tag:"):]
        end = job.find("\n\n", job.index("script:"))
        job = job if end < 0 else job[:end]            # the last job of the file ends with it
        main = job.index('"$CI_COMMIT_SHA:refs/heads/main"')
        tag = job.index('"refs/tags/$CI_COMMIT_TAG"')
        hold = job.index('if [ "${MAISECRETS_DIRECTORY_HOLD:-0}" = "1" ]; then')
        release = job.index(':refs/heads/release"')
        self.assertLess(main, hold)
        self.assertLess(tag, hold)
        self.assertLess(hold, release)
        self.assertIn("exit 0", job[hold:release])
        notify = ci[ci.index("\nnotify_marketplace:"):]
        self.assertNotIn("MAISECRETS_DIRECTORY_HOLD", notify[:notify.index("\n\n")])

    def test_the_tag_pipeline_trusts_verify_release_instead_of_testing_twice(self):
        """Every test job extends the one rule that keeps it off a tag, and nothing on the tag path
        waits for a job that does not run there. verify_release must keep every check the skip
        rests on: the file list, the subject, the release identity, main, the version."""
        ci = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        jobs, name = {}, None
        for line in ci.splitlines():
            if line and not line[0].isspace() and not line.startswith("#"):
                name = line[:-1] if line.endswith(":") else None
                if name:
                    jobs[name] = ""
            elif name:
                jobs[name] += line + "\n"
        for name in ("unit", "beliefs_can_fail_replay", "harness_claude", "harness_codex"):
            self.assertIn("extends: .tested_before_the_tag", jobs[name], name)
        self.assertIn("if: $CI_COMMIT_TAG\n      when: never", jobs[".tested_before_the_tag"])
        for name in ("mirror_tag", "notify_marketplace"):
            needs = next(line for line in jobs[name].splitlines() if line.strip().startswith("needs:"))
            for skipped in ("unit", "harness_claude", "harness_codex", "beliefs_can_fail_replay"):
                self.assertNotRegex(needs, rf"\b{skipped}\b", f"{name} waits for {skipped}, which a tag never runs")
            self.assertIn("verify_release", needs, name)
        vr = jobs["verify_release"]
        for check in ("git diff --name-only HEAD^ HEAD", "^chore(release): v", "ci@maisecrets.local",
                      "git merge-base --is-ancestor HEAD origin/main", "tag and manifest version differ"):
            self.assertIn(check, vr, check)

    def test_the_matrix_runs_in_a_release_merge_request_and_wherever_the_tests_read_code(self):
        """windows_macos runs in every merge request into main and, into next, for every change outside the
        documentation: the matrix runs the whole unit suite, so every file a test reads must start it. A pattern that
        names no file never starts the job, so each one must name a file (the first rule named platform paths only,
        and a test with a POSIX-only import reached next untested on Windows, !194)."""
        import ast
        ci = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        job = ci[ci.index("\nwindows_macos:"):]
        job = job[:job.index("\n  variables:")]
        release = job.index('$CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"')
        changes = job.index("changes:")
        self.assertLess(release, changes, "the release rule must come before the path rule")
        patterns = [line.strip()[2:] for line in job[changes:].splitlines()[1:] if line.strip().startswith("- ")]
        self.assertGreaterEqual(len(patterns), 10, "the premise: the rule lists paths")
        matched = set()
        for p in patterns:
            files = {f.relative_to(ROOT).as_posix() for f in ROOT.glob(p) if f.is_file()}
            self.assertTrue(files, f"{p} names no file, so it never starts the job")
            matched |= files
        # every top folder a test imports from or names, and every test itself
        tops = set()
        for f in sorted((ROOT / "tests").glob("test_*.py")):
            self.assertIn(f.relative_to(ROOT).as_posix(), matched)
            for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for name in ([node.module] if isinstance(node, ast.ImportFrom) and node.module else
                                 [a.name for a in node.names]):
                        if name and (ROOT / name.split(".")[0]).is_dir():
                            tops.add(name.split(".")[0])
        self.assertGreaterEqual(tops, {"maisecrets", "bench"}, "the premise: tests import the core and the bench")
        for top in tops | {"hooks", "scripts", "harness", "beliefs"}:
            self.assertTrue(any(m.startswith(top + "/") for m in matched), f"{top}/ starts no matrix run")
        self.assertFalse(any(m.startswith("docs/") for m in matched), "documentation alone needs no matrix run")

    def test_the_codex_manifest_mirrors_the_claude_one(self):
        for key in ("name", "version", "description", "author", "homepage", "repository", "license", "keywords"):
            self.assertEqual(self.claude[key], self.codex[key], key)
        ui = self.codex["interface"]
        self.assertEqual(self.claude["privacyPolicyUrl"], ui["privacyPolicyURL"])
        self.assertEqual(self.claude["supportUrl"], ui["supportURL"])
        self.assertNotIn("hooks", self.codex,
                         "Codex discovers hooks/hooks.json only while the manifest defines no hooks")

    def test_the_icon_is_where_each_directory_looks(self):
        # Anthropic: the manifest field, the .claude-plugin file, the assets file (all three named by the portal).
        # The field is a URL: the portal's listing preview renders a URL and shows a letter for a repo
        # path ("This icon is given as a path inside your plugin. This page can't display it", 2026-09-27).
        # The URL must point at a file on the tracked branch of this repository, so it moves with it.
        prefix = "https://raw.githubusercontent.com/Mcpgate-de/maisecrets/main/"
        self.assertTrue(self.claude["icon"].startswith(prefix), self.claude["icon"])
        icon = ROOT / self.claude["icon"][len(prefix):]
        self.assertTrue(icon.is_file(), self.claude["icon"])
        # no .claude-plugin/icon.*: the portal showed that file ahead of the manifest URL and could
        # not render it ("given as a path inside your plugin", 2026-09-27)
        self.assertFalse(list((ROOT / ".claude-plugin").glob("icon.*")))
        self.assertTrue(list((ROOT / "assets").glob("icon.*")))
        w, h = self._png_size(icon)
        self.assertEqual(w, h, "square")
        self.assertGreaterEqual(w, 128)
        # OpenAI: both interface paths, relative to the plugin root with a ./ prefix
        for key in ("composerIcon", "logo"):
            rel = self.codex["interface"][key]
            self.assertTrue(rel.startswith("./"), rel)
            self.assertTrue((ROOT / rel).is_file(), rel)
        self.assertRegex(self.codex["interface"]["brandColor"], r"^#[0-9A-Fa-f]{6}$")
        self.assertLessEqual(len(self.codex["interface"]["shortDescription"]), 30, "the OpenAI form allows 30")
