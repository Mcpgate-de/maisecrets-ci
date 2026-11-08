"""The release scripts against a throw-away repository and a mocked network: release.py
(classify, next, notes, apply, check), wait_for_github_checks.py and notify_marketplace.py.

Nothing here reads or changes the real repository, its tags or its remote: release.py gets a
temp git repository with copies of the three manifests and the changelog, and every urlopen
and every git call of the two network scripts is replaced.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_rel_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


class _Repo:
    """A temp git repository whose commits are made with plumbing (no hooks run), holding
    copies of the files release.py reads and writes."""

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-release-"))
        for rel in (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", ".codex-plugin/plugin.json",
                    "CHANGELOG.md"):
            (self.dir / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / rel, self.dir / rel)
            if rel.endswith(".json"):
                # a fixed version: a copy of the live manifests made every release turn these tests red
                path = self.dir / rel
                path.write_text(re.sub(r'("version":\s*")\d+\.\d+\.\d+(")', r"\g<1>0.4.1\g<2>",
                                       path.read_text(encoding="utf-8")), encoding="utf-8")
        self.env = dict(_clean_env(), GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
                        GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-q", "-b", "main")
        self.tree = self.git("write-tree").strip()
        self.head: str | None = None

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.dir, env=self.env, check=True, capture_output=True,
                              text=True).stdout

    def commit(self, subject: str, body: str = "") -> str:
        args = ["commit-tree", self.tree, "-m", subject] + (["-m", body] if body else [])
        if self.head:
            args += ["-p", self.head]
        self.head = self.git(*args).strip()
        self.git("update-ref", "refs/heads/main", self.head)
        return self.head

    def merge(self, other: str, subject: str = "Merge branch 'x' into 'next'") -> str:
        self.head = self.git("commit-tree", self.tree, "-m", subject, "-p", self.head, "-p", other).strip()
        self.git("update-ref", "refs/heads/main", self.head)
        return self.head

    def side(self, base: str, subject: str) -> str:
        return self.git("commit-tree", self.tree, "-m", subject, "-p", base).strip()

    def tag(self, name: str) -> None:
        self.git("tag", name, self.head)

    def version(self, rel: str) -> str:
        data = json.loads((self.dir / rel).read_text())
        return data["plugins"][0]["version"] if rel.endswith("marketplace.json") else data["version"]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.r = _load("release")
        self.repo = _Repo()
        self.addCleanup(shutil.rmtree, self.repo.dir, True)
        self.r.ROOT = self.repo.dir
        self.r.CHANGELOG = self.repo.dir / "CHANGELOG.md"
        # release.py runs git with the inherited environment: no GIT_DIR of a calling hook
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for k in [k for k in os.environ if k.startswith("GIT_")]:
            del os.environ[k]
        # the owner's approval for one pipeline (a CI variable) must not move the versions these tests expect: the
        # main pipeline of 0.6.0 failed here with 0.5.0 for 0.4.2 (2026-10-06)
        os.environ.pop("MAISECRETS_RELEASE_BUMP", None)

    def _main(self, *argv: str) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.object(sys, "stderr", io.StringIO()):
            rc = self.r.main(["release.py", *argv])
        return rc, buf.getvalue()

    def test_classify_every_type_the_bang_breaking_change_and_unknown_subjects(self):
        r = self.r
        for typ in sorted(r.KNOWN - {"revert"}):
            with self.subTest(typ):
                self.assertEqual(r.classify(f"{typ}(scope): the text", ""), (typ, "the text", False))
                self.assertEqual(r.classify(f"{typ}: the text", ""), (typ, "the text", False))
                self.assertEqual(r.classify(f"{typ}(scope)!: the text", ""), (typ, "the text", True))
                self.assertEqual(r.classify(f"{typ}: the text", "x\n\nBREAKING CHANGE: y"), (typ, "the text", True))
        for subject in ("wip: x", "Update README", "feat:no space", "Feat: capital", "feat(x) y"):
            with self.subTest(subject):
                self.assertEqual(r.classify(subject, ""), ("other", subject, False))
        self.assertEqual(r.classify("Update README", "BREAKING CHANGE: gone"), ("other", "Update README", True))
        # the words in a sentence are no footer: 0.4.2 became 0.5.0 by such a body (2026-09-27)
        for body in ("A `chore:` with BREAKING CHANGE bumps the level.", "BREAKING CHANGE", "x BREAKING CHANGE: y"):
            with self.subTest(body):
                self.assertEqual(r.classify("fix(release): x", body), ("fix", "x", False))
        self.assertEqual(r.classify('Revert "Revert "Revert "fix: a"""', ""), ("revert", "revert: fix: a", False))
        self.assertEqual(r._unrevert('Revert "feat: x"'), "feat: x")
        self.assertEqual(r._unrevert("feat: x"), "feat: x")

    def test_the_bump_is_the_highest_level_and_the_0x_scale_shifts_it_down(self):
        r = self.r
        c = lambda *subjects: [(f"s{i}", s, "") for i, s in enumerate(subjects)]  # noqa: E731
        self.assertEqual(r.bump_for(c("docs: a", "fix: b", "feat: c", "perf: d")), "minor")
        self.assertEqual(r.bump_for(c("fix: b", "refactor!: e")), "major")
        self.assertEqual(r.bump_for(c("chore(release): v9.9.9", "Merge branch x", "docs: a")), None)
        self.assertEqual(r.bump_for(c("tidy things")), "patch", "an untyped subject is a patch")
        for typ in ("perf", "security", "deps"):
            self.assertEqual(r.bump_for(c(f"{typ}: x")), "patch", typ)
        self.assertEqual(r.bump_for([("s", "chore: x", "BREAKING CHANGE: y")]), "major")
        # only the last number moves, whatever the level; a higher one needs the owner's approval
        for cur in ("0.5.0", "1.4.1"):
            for level in ("patch", "minor", "major"):
                with self.subTest(cur=cur, level=level):
                    head, last = cur.rsplit(".", 1)
                    self.assertEqual(r.next_version(cur, level), f"{head}.{int(last) + 1}")
        self.assertEqual(r.next_version("0.5.7", "patch", "minor"), "0.6.0")
        self.assertEqual(r.next_version("0.5.7", "patch", "major"), "1.0.0")

    def test_notes_group_by_section_in_a_fixed_order_and_skip_silent_types(self):
        commits = [("a" * 40, "deps: bump x", ""), ("b" * 40, "fix(hooks): a fix", ""),
                   ("c" * 40, "docs: words", ""), ("d" * 40, "feat: a feature", ""),
                   ("e" * 40, "security: a hole", ""), ("f" * 40, "odd subject", ""),
                   ("1" * 40, "chore(release): v0.0.1", ""), ("2" * 40, "feat!: a break", ""),
                   ("3" * 40, 'Revert "fix: y"', ""), ("4" * 40, "perf: faster", "")]
        notes = self.r.render_notes("0.9.0", commits)
        self.assertTrue(notes.startswith("## [0.9.0] - "))
        heads = [line for line in notes.splitlines() if line.startswith("### ")]
        self.assertEqual(heads, ["### Breaking", "### Features", "### Fixes", "### Security", "### Reverts",
                                 "### Dependencies", "### Other"])
        self.assertIn("- a break (2222222)", notes)
        self.assertIn("- a fix (bbbbbbb)\n- faster (4444444)", notes)
        self.assertIn("- revert: fix: y (3333333)", notes)
        self.assertNotIn("words", notes)
        self.assertNotIn("v0.0.1", notes)
        self.assertTrue(notes.endswith(")\n"))

    def test_a_merge_commit_subject_is_no_release_note(self):
        commits = [("a" * 40, "Merge branch 'feat/x' into 'main'", "feat: x\n\nSee merge request !61"),
                   ("b" * 40, "Merge remote-tracking branch 'origin/main'", ""),
                   ("c" * 40, "fix: a fix", ""), ("d" * 40, "odd subject", "")]
        notes = self.r.render_notes("0.9.0", commits)
        self.assertNotIn("Merge", notes)
        self.assertIn("- a fix (ccccccc)", notes)
        self.assertIn("- odd subject (ddddddd)", notes)   # a subject without a type still shows

    def test_a_breaking_change_of_a_silent_type_is_listed_under_breaking(self):
        """`refactor!:` bumps the break level, so the release exists because of it; before the fix
        the notes skipped every docs/ci/test/chore/build/style/refactor commit, breaking or not,
        and the release said nothing about its reason."""
        for subject, body in (("refactor(api)!: drop the old flag", ""), ("chore: drop the old flag",
                                                                           "BREAKING CHANGE: gone")):
            with self.subTest(subject):
                notes = self.r.render_notes("0.9.0", [("a" * 40, subject, body)])
                self.assertIn("### Breaking", notes)
                self.assertIn("drop the old flag (aaaaaaa)", notes)
                # a header-only section made apply() fail to split it when an Unreleased block exists
                (self.repo.dir / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n- by hand\n")
                self.r.apply("0.9.0", notes)
                self.assertIn("- by hand", (self.repo.dir / "CHANGELOG.md").read_text())

    def test_an_api_footer_is_listed_under_api_whatever_the_type(self):
        """docs/DETECTION.md promises that a change of the library API is named under "API"; 0.7.0 listed the
        deprecation of LazyRegex under Features. A footer `API: …` puts it there, also from a docs commit."""
        commits = [("a" * 40, "feat(detect): user_rule",
                    "Body.\n\nAPI: user_rule is the stable way to a rule of your own"),
                   ("b" * 40, "docs(detection): note", "API: LazyRegex is deprecated until 0.8"),
                   ("c" * 40, "fix: a fix", "")]
        notes = self.r.render_notes("0.9.0", commits)
        self.assertIn("### API", notes)
        self.assertIn("- user_rule is the stable way to a rule of your own (aaaaaaa)", notes)
        self.assertIn("- LazyRegex is deprecated until 0.8 (bbbbbbb)", notes)
        self.assertLess(notes.index("### API"), notes.index("### Features"))
        self.assertNotIn("### API", self.r.render_notes("0.9.0", commits[2:]))

    def test_a_change_taken_back_before_its_release_is_no_line_of_the_notes(self):
        repo = self.repo
        old = repo.commit("fix: shipped before")
        repo.tag("v0.4.1")
        merged = repo.merge(repo.side(repo.head, "fix: masks a card in a UUID"))
        repo.commit("fix: a digest is no secret")
        plain = repo.commit("feat: a feature taken back")
        repo.commit("chore(detect): take the card back", f"This reverts commit {merged}.")
        repo.commit('Revert "feat: a feature taken back"', f"This reverts commit {plain}.")
        repo.commit('Revert "fix: shipped before"', f"This reverts commit {old}.")
        commits = self.r.without_reverted(self.r.commits_since("v0.4.1"))
        notes = self.r.render_notes("0.4.2", commits)
        self.assertIn("a digest is no secret", notes)
        self.assertIn("revert: fix: shipped before", notes, "a revert of a released commit stays")
        for gone in ("masks a card", "a feature taken back"):
            with self.subTest(gone=gone):
                self.assertNotIn(gone, notes)
        self.assertEqual(self.r.bump_for(commits), "patch")

    def test_apply_writes_every_manifest_and_keeps_the_unreleased_block(self):
        cl = self.repo.dir / "CHANGELOG.md"
        cl.write_text("# Changelog\n\n## Unreleased\n\n- **Hand-written** line.\n\n## [0.4.1] - 2026-09-27\n\n"
                      "### Fixes\n\n- old fix (f8172bf)\n")
        notes = "## [0.4.2] - 2026-09-28\n\n### Fixes\n\n- new fix (abcdef1)\n"
        self.r.apply("0.4.2", notes)
        for rel in self.r.MANIFESTS:
            with self.subTest(rel):
                self.assertEqual(self.repo.version(rel), "0.4.2")
        self.assertEqual(json.loads((self.repo.dir / ".claude-plugin/marketplace.json").read_text())["name"],
                         "maisecrets")
        self.assertEqual(cl.read_text(), "# Changelog\n\n## Unreleased\n\n## [0.4.2] - 2026-09-28\n\n"
                                         "- **Hand-written** line.\n\n### Fixes\n\n- new fix (abcdef1)\n\n"
                                         "## [0.4.1] - 2026-09-27\n\n### Fixes\n\n- old fix (f8172bf)\n")

    def test_apply_without_an_unreleased_block_or_a_changelog_and_a_manifest_without_a_version(self):
        cl = self.repo.dir / "CHANGELOG.md"
        cl.unlink()
        self.r.apply("0.5.0", "## [0.5.0] - 2026-09-28\n\n### Features\n\n- x (1234567)\n")
        self.assertEqual(cl.read_text(), "# Changelog\n\n## Unreleased\n\n## [0.5.0] - 2026-09-28\n\n"
                                         "### Features\n\n- x (1234567)\n")
        (self.repo.dir / ".codex-plugin/plugin.json").write_text('{"name": "maisecrets"}')
        with self.assertRaises(SystemExit) as cm:
            self.r.apply("0.5.1", "## [0.5.1] - d\n")
        self.assertIn("no version field", str(cm.exception))

    def test_check_passes_well_formed_subjects_and_names_a_bad_one_and_a_mismatch(self):
        repo = self.repo
        repo.commit("chore: start")
        repo.tag("v0.4.1")
        repo.commit("feat(x): a feature")
        repo.commit("Merge branch 'x' into main")
        repo.commit('Revert "whatever was here"')
        repo.commit("chore(release): v0.4.2")
        rc, out = self._main("check", "v0.4.1")
        self.assertEqual(rc, 0, out)
        self.assertIn("manifests agree: 0.4.1", out)
        self.assertIn("commit subjects since v0.4.1: well-formed", out)
        bad = repo.commit("Fixed the thing")
        repo.commit("wip: more")
        rc, out = self._main("check", "v0.4.1")
        self.assertEqual(rc, 1)
        self.assertIn(f"  {bad[:7]} Fixed the thing", out)
        self.assertIn("wip: more", out)
        self.assertNotIn("a feature", out)
        self.assertIn("known types:", out)
        rc, out = self._main("check")
        self.assertEqual(rc, 0, "without a base only the manifests are checked")
        m = repo.dir / ".codex-plugin/plugin.json"
        m.write_text(m.read_text().replace('"0.4.1"', '"0.4.0"'))
        rc, out = self._main("check")
        self.assertEqual(rc, 1)
        self.assertIn("version mismatch", out)
        self.assertIn("'.codex-plugin/plugin.json': '0.4.0'", out)

    def test_next_notes_apply_and_nothing_to_release_in_a_temp_repository(self):
        repo = self.repo
        repo.commit("feat: first")
        rc, out = self._main("next")
        self.assertEqual((rc, out), (0, "0.4.2\n"), "without a tag the manifest is the current version")
        repo.tag("v0.4.1")
        repo.tag("v9.9.9-rc1")          # not a release tag
        self.assertEqual(self.r.last_tag(), "v0.4.1")
        rc, out = self._main("next")
        self.assertEqual(rc, 3, "nothing since the tag")
        repo.commit("docs: only words")
        self.assertEqual(self._main("next")[0], 3)
        sha = repo.commit("fix(hooks): a real fix")
        repo.commit("feat!: a break")
        rc, out = self._main("next")
        self.assertEqual((rc, out), (0, "0.4.2\n"), "a break without approval moves the last number")
        with mock.patch.dict(os.environ, {"MAISECRETS_RELEASE_BUMP": "minor"}):
            self.assertEqual(self._main("next"), (0, "0.5.0\n"))
        with mock.patch.dict(os.environ, {"MAISECRETS_RELEASE_BUMP": "huge"}), self.assertRaises(SystemExit):
            self._main("next")
        rc, out = self._main("notes")
        self.assertIn(f"- a real fix ({sha[:7]})", out)
        self.assertIn("### Breaking", out)
        rc, out = self._main("apply")
        self.assertEqual((rc, out), (0, "0.4.1 -> 0.4.2: manifests and CHANGELOG.md updated\n"))
        for rel in self.r.MANIFESTS:
            self.assertEqual(repo.version(rel), "0.4.2", rel)
        self.assertIn("## [0.4.2] - ", (repo.dir / "CHANGELOG.md").read_text())
        rc, out = self._main("frobnicate")
        self.assertEqual(rc, 2)
        self.assertIn("Subcommands:", out)
        self.assertEqual([c[1] for c in self.r.commits_since(None)][-1], "feat: first")


class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _runs(*spec) -> dict:
    return {"check_runs": [{"name": n, "status": s, "conclusion": c} for n, s, c in spec]}


class WaitForChecksTests(unittest.TestCase):
    def setUp(self):
        self.w = _load("wait_for_github_checks")

    def _wait(self, answers: list, argv: list[str] | None = None, moved=lambda sha: False):
        urls, sleeps = [], []

        def fake_urlopen(req, timeout=30):
            urls.append(req.full_url)
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return _Resp(json.dumps(a).encode() if isinstance(a, dict) else a)
        buf = io.StringIO()
        with mock.patch.object(self.w.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.object(self.w, "_main_moved", moved), \
                mock.patch.object(self.w.time, "sleep", sleeps.append), redirect_stdout(buf):
            rc = self.w.main(argv or ["wait", "cafe1234beef"])
        return rc, buf.getvalue(), urls, sleeps

    def test_pending_then_green_after_no_runs_and_a_rate_limit(self):
        answers = [urllib.error.HTTPError("u", 403, "rate", {}, None), {"check_runs": []},
                   _runs(("win", "in_progress", None), ("mac", "completed", "success")),
                   b"{half", _runs(("win", "completed", "success"), ("mac", "completed", "success"))]
        rc, out, urls, sleeps = self._wait(answers, ["wait", "cafe1234beef", "--repo", "o/r", "--timeout-min", "5"])
        self.assertEqual(rc, 0)
        self.assertEqual(urls[0], "https://api.github.com/repos/o/r/commits/cafe1234beef/check-runs")
        self.assertIn("github 403; waiting", out)
        self.assertIn("no check runs yet", out)
        self.assertIn("waiting for win", out)
        self.assertIn("github unreachable (JSONDecodeError)", out)
        self.assertIn("GitHub Actions green for cafe123 : win, mac", out)
        self.assertEqual(sleeps, [60, 30, 30, 60])

    def test_a_failed_or_cancelled_check_is_red_and_names_it(self):
        rc, out, _u, _s = self._wait([_runs(("win", "completed", "success"), ("lin", "completed", "cancelled"),
                                            ("mac", "in_progress", None))])
        self.assertEqual(rc, 1)
        self.assertIn("GitHub Actions failed for cafe123 : lin", out)

    def test_the_wait_ends_red_at_the_timeout(self):
        clock = iter([0.0, 10.0, 200.0])
        with mock.patch.object(self.w.time, "time", lambda: next(clock)):
            rc, out, urls, _s = self._wait([_runs(("win", "queued", None))], ["wait", "cafe1234beef", "--timeout-min",
                                                                             "3"])
        self.assertEqual(rc, 1)
        self.assertEqual(len(urls), 1)
        self.assertIn("timeout waiting for GitHub Actions on cafe123", out)

    def test_a_moved_main_steps_aside_before_any_request(self):
        rc, out, urls, _s = self._wait([], moved=lambda sha: True)
        self.assertEqual((rc, urls), (0, []))
        self.assertIn("superseded", out)

    def test_main_moved_reads_the_remote_head_and_treats_errors_as_not_moved(self):
        def run_with(stdout=None, exc=None):
            def fake(argv, **kw):
                self.assertEqual(argv[:3], ["git", "ls-remote", "--quiet"])
                if exc:
                    raise exc
                return subprocess.CompletedProcess(argv, 0, stdout=stdout)
            return fake
        for stdout, exc, want in (("cafe1234beef\trefs/heads/main\n", None, False),
                                  ("0123abcd\trefs/heads/main\n", None, True), ("", None, False),
                                  (None, OSError("no git"), False),
                                  (None, subprocess.TimeoutExpired("git", 30), False)):
            with self.subTest(stdout=stdout, exc=repr(exc)), mock.patch("subprocess.run", run_with(stdout, exc)):
                self.assertEqual(self.w._main_moved("cafe1234beef"), want)


class NotifyMarketplaceTests(unittest.TestCase):
    SECRET_RAW = bytes(range(32))

    def setUp(self):
        self.n = _load("notify_marketplace")
        self.env = {"MAISECRETS_CLAUDE_MARKETPLACE_URL": "https://hooks.example.invalid/m/1",
                    "MAISECRETS_CLAUDE_WEBHOOK_SECRET": "whsec_" + base64.b64encode(self.SECRET_RAW).decode(),
                    "CI_COMMIT_SHA": "cafe" * 10, "CI_PROJECT_PATH": "grp/proj",
                    "CI_PROJECT_URL": "https://gitlab.example.invalid/grp/proj", "CI_DEFAULT_BRANCH": "main"}

    def _notify(self, env: dict, answer) -> tuple[int, str, list]:
        sent = []

        def fake_urlopen(req, timeout=30):
            sent.append(req)
            if isinstance(answer, Exception):
                raise answer
            return _Resp(answer)
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS_CLAUDE_", "CI_"))}
        buf = io.StringIO()
        with mock.patch.dict(os.environ, dict(clean, **env), clear=True), \
                mock.patch.object(self.n.urllib.request, "urlopen", fake_urlopen), redirect_stdout(buf):
            rc = self.n.main()
        return rc, buf.getvalue(), sent

    def test_the_signed_push_event_matches_the_standard_webhooks_scheme(self):
        rc, out, sent = self._notify(self.env, b'{"status": "published", "published": true}')
        self.assertEqual(rc, 0, out)
        self.assertIn("http 200", out)
        req = sent[0]
        self.assertEqual((req.full_url, req.get_method()), ("https://hooks.example.invalid/m/1", "POST"))
        h = {k.lower(): v for k, v in req.header_items()}
        body = req.data.decode()
        # computed here from the documented scheme: HMAC-SHA256 over "id.timestamp.body" with the
        # base64-decoded secret after the whsec_ prefix, sent as "v1,<base64>"
        want = base64.b64encode(hmac.new(self.SECRET_RAW, f"{h['webhook-id']}.{h['webhook-timestamp']}.{body}"
                                         .encode(), hashlib.sha256).digest()).decode()
        self.assertEqual(h["webhook-signature"], "v1," + want)
        self.assertTrue(h["webhook-id"].startswith("msg_"))
        self.assertTrue(h["webhook-timestamp"].isdigit())
        self.assertEqual(h["x-gitlab-event"], "Push Hook")
        self.assertEqual(h["content-type"], "application/json")
        event = json.loads(body)
        self.assertEqual((event["object_kind"], event["ref"], event["checkout_sha"], event["after"]),
                         ("push", "refs/heads/main", "cafe" * 10, "cafe" * 10))
        self.assertEqual(event["project"], {"path_with_namespace": "grp/proj", "default_branch": "main",
                                            "web_url": "https://gitlab.example.invalid/grp/proj",
                                            "git_http_url": "https://gitlab.example.invalid/grp/proj.git"})
        self.assertEqual(event["repository"], {"name": "proj", "homepage": "https://gitlab.example.invalid/grp/proj"})
        # a secret without the prefix is the same key
        env = dict(self.env, MAISECRETS_CLAUDE_WEBHOOK_SECRET=base64.b64encode(self.SECRET_RAW).decode())
        _rc, _o, sent = self._notify(env, b'{"published": true}')
        h = {k.lower(): v for k, v in sent[0].header_items()}
        want = base64.b64encode(hmac.new(self.SECRET_RAW, f"{h['webhook-id']}.{h['webhook-timestamp']}."
                                         f"{sent[0].data.decode()}".encode(), hashlib.sha256).digest()).decode()
        self.assertEqual(h["webhook-signature"], "v1," + want)

    def test_a_fork_has_nothing_to_notify_and_the_canonical_project_must_have_the_variables(self):
        rc, out, sent = self._notify({"CI_PROJECT_PATH": "someone/fork"}, b"")
        self.assertEqual((rc, sent), (0, []))
        self.assertIn("nothing to notify", out)
        for path in sorted(self.n.CANONICAL_PROJECTS):
            with self.subTest(path):
                rc, out, sent = self._notify({"CI_PROJECT_PATH": path,
                                              "MAISECRETS_CLAUDE_MARKETPLACE_URL": "https://x.invalid"}, b"")
                self.assertEqual((rc, sent), (1, []))
                self.assertIn("missing on the canonical project", out)

    def test_each_further_organisation_gets_the_event_signed_with_its_own_secret(self):
        raw2 = bytes(range(32, 64))
        env = dict(self.env, MAISECRETS_CLAUDE_MARKETPLACE_URL_2="https://hooks.example.invalid/m/2",
                   MAISECRETS_CLAUDE_WEBHOOK_SECRET_2="whsec_" + base64.b64encode(raw2).decode())
        rc, out, sent = self._notify(env, b'{"published": true}')
        self.assertEqual(rc, 0, out)
        self.assertEqual([r.full_url for r in sent], ["https://hooks.example.invalid/m/1",
                                                      "https://hooks.example.invalid/m/2"])
        for req, raw in zip(sent, (self.SECRET_RAW, raw2)):
            h = {k.lower(): v for k, v in req.header_items()}
            want = base64.b64encode(hmac.new(raw, f"{h['webhook-id']}.{h['webhook-timestamp']}."
                                             f"{req.data.decode()}".encode(), hashlib.sha256).digest()).decode()
            self.assertEqual(h["webhook-signature"], "v1," + want)

    def test_a_half_set_further_organisation_is_red_and_the_others_are_still_notified(self):
        for half in ({"MAISECRETS_CLAUDE_MARKETPLACE_URL_2": "https://hooks.example.invalid/m/2"},
                     {"MAISECRETS_CLAUDE_WEBHOOK_SECRET_2": "whsec_" + base64.b64encode(b"k" * 32).decode()}):
            with self.subTest(sorted(half)):
                rc, out, sent = self._notify(dict(self.env, **half), b'{"published": true}')
                self.assertEqual(rc, 1, out)
                self.assertIn("org 2: URL or secret missing", out)
                self.assertEqual([r.full_url for r in sent], ["https://hooks.example.invalid/m/1"])

    def test_one_failed_delivery_is_red_and_does_not_stop_the_next(self):
        env = dict(self.env, MAISECRETS_CLAUDE_MARKETPLACE_URL_2="https://hooks.example.invalid/m/2",
                   MAISECRETS_CLAUDE_WEBHOOK_SECRET_2="whsec_" + base64.b64encode(b"k" * 32).decode())
        answers = iter([b'{"published": false}', b'{"published": true}'])
        sent = []

        def fake_urlopen(req, timeout=30):
            sent.append(req)
            return _Resp(next(answers))
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS_CLAUDE_", "CI_"))}
        buf = io.StringIO()
        with mock.patch.dict(os.environ, dict(clean, **env), clear=True), \
                mock.patch.object(self.n.urllib.request, "urlopen", fake_urlopen), redirect_stdout(buf):
            rc = self.n.main()
        self.assertEqual(rc, 1, buf.getvalue())
        self.assertEqual(len(sent), 2)

    def _http_403(self) -> urllib.error.HTTPError:
        err = urllib.error.HTTPError("u", 403, "x", {}, io.BytesIO(b"Missing sig"))
        self.addCleanup(err.close)
        return err

    def test_every_answer_but_published_true_is_red(self):
        for name, answer in (("published false", b'{"published": false}'), ("not json", b"<html>ok</html>"),
                             ("http 403", self._http_403()),
                             ("dns", urllib.error.URLError("no such host"))):
            with self.subTest(name):
                rc, out, _sent = self._notify(self.env, answer)
                self.assertEqual(rc, 1, out)
        rc, out, _s = self._notify(self.env, self._http_403())
        self.assertIn("http 403 Missing sig", out)
        rc, out, _s = self._notify(self.env, b'{"published": false}')
        self.assertIn("did not answer published=true", out)


if __name__ == "__main__":
    unittest.main()
