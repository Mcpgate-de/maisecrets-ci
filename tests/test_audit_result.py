"""The session audit ends with a verdict and what to do: which real tokens to rotate, with the page to do it.

Each found value gets a class (REAL, TEST, UNKNOWN) from signals that the audit can check on this computer, and
stdout carries only the summary: the verdict, at most 10 real tokens, one line with the rest and the report path. No
value appears in the summary or in the report. Every value here is built at run time or names itself."""
from __future__ import annotations

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
from collections import Counter
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
SCRIPTS = ROOT / "skills" / "secret-hygiene" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import audit_transcripts as at  # noqa: E402
from maisecrets import detect  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402

ALNUM = string.ascii_letters + string.digits


def _rnd(n: int) -> str:
    # no test word by chance: the class "names itself" would take it
    while True:
        v = "".join(secrets.choice(ALNUM) for _ in range(n))
        if not at._TEST_WORD_RE.search("-" + v + "-"):
            return v


def _gl() -> str:
    return "glp" + "at-" + _rnd(20)


def _gh() -> str:
    return "gh" + "p_" + _rnd(36)


def _env(base: Path, home: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX", "GIT_"))}
    env.update(MAISECRETS_HOME=str(home), PYTHONUTF8="1", CLAUDE_CONFIG_DIR=str(base / "claude"),
               CODEX_HOME=str(base / "codex"))
    return env


def _home(base: Path) -> Path:
    home = base / "home"
    home.mkdir()
    (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}\n', encoding="utf-8")
    return home


def _store(env: dict, *values: str) -> None:
    """Put values into the temp store of `env` in a child: this process keeps its own temp home."""
    code = (f"import sys; sys.path.insert(0, {str(ROOT)!r}); from maisecrets.vault import Vault; v = Vault()\n"
            f"for x in sys.argv[1:]: v.put(x, 'SECRET', 'label-password')")
    subprocess.run([sys.executable, "-c", code, *values], env=env, check=True, timeout=60)


def _tool(content: str, stamp: str, path: str = "") -> dict:
    rec = {"type": "user", "timestamp": stamp, "message": {"content": [{"type": "tool_result", "content": content}]}}
    if path:
        rec["toolUseResult"] = {"type": "text", "file": {"filePath": path, "content": content}}
    return rec


def _session(base: Path, rows: list, name: str = "abcdef12-0000") -> Path:
    proj = base / "claude" / "projects" / "-Users-x-repo"
    proj.mkdir(parents=True, exist_ok=True)
    f = proj / f"{name}.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    old = time.time() - 3600
    os.utime(f, (old, old))
    return f


class ClassificationRunTests(unittest.TestCase):
    """A synthetic history with one value of each class, and a temp store that holds one of them."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="maisecrets-audit-result-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.env = _env(self.base, _home(self.base))
        self.gl, self.gh, self.model = _gl(), _gh(), _gh()
        self.test_body = "gh" + "p_test" + _rnd(32)   # a real format whose random body starts with "test"
        self.stored, self.guess, self.in_test = "Qz" + _rnd(14), "Wx" + _rnd(14), "Kv" + _rnd(14)
        _store(self.env, self.stored)
        _session(self.base, [
            {"type": "user", "timestamp": "2026-11-10T10:00:00Z", "message": {"content": f"use {self.gl} here"}},
            _tool(f"GITLAB_TOKEN={self.gl}", "2026-11-16T10:00:00Z"),
            _tool(f"export GITHUB_TOKEN={self.gh}", "2026-10-06T10:00:00Z"),
            _tool(f'db_password = "{self.stored}"', "2026-10-22T10:00:00Z"),
            _tool(f'db_password = "{self.guess}"', "2026-10-23T10:00:00Z"),
            _tool(f'db_password = "{self.in_test}"', "2026-10-23T11:00:00Z", "/repo/tests/test_login.py"),
            _tool(f"export GITHUB_TOKEN={self.test_body}", "2026-10-24T10:00:00Z"),
            {"type": "assistant", "timestamp": "2026-11-01T10:00:00Z",
             "message": {"content": [{"type": "text", "text": f"For example GITHUB_TOKEN={self.model}"}]}},
        ])
        self.report = self.base / "report.txt"
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(self.report)],
                           capture_output=True, text=True, encoding="utf-8", env=self.env, timeout=120)
        self.r, self.full = r, self.report.read_text(encoding="utf-8")

    def classes(self) -> dict:
        """(class, reason) per rule-and-reason row of the report."""
        out = Counter()
        for line in self.full.splitlines():
            if line.startswith("  S"):
                out[(line.split()[1], line.split("(")[-1].split(")")[0])] += 1
        return out

    def test_each_value_gets_its_class_and_reason(self):
        self.assertEqual(self.r.returncode, 1, self.r.stdout + self.r.stderr)
        self.assertEqual(self.classes(), Counter({
            ("REAL", "provider format, in your input or a tool result"): 3,   # GitLab, GitHub, GitHub "test…"
            ("REAL", "in your maisecrets store"): 1,
            ("UNKNOWN", "keyword guess"): 1,
            ("TEST", "only in test code"): 1,
            ("TEST", "only in model output"): 1,
        }), self.full)

    def test_the_summary_is_the_verdict_the_real_rows_and_one_line(self):
        lines = self.r.stdout.splitlines()
        self.assertEqual(lines[0], "AI history, last 30 days: 4 real token(s) reached Anthropic. Rotate them:")
        self.assertEqual(len(lines), 6, self.r.stdout)
        self.assertTrue(lines[1].startswith("  1. GitLab personal access token"), lines[1])
        self.assertIn("1 session(s), last 2026-11-16", lines[1])
        self.assertIn("-> https://gitlab.com/-/user_settings/personal_access_tokens", lines[1])
        self.assertTrue(any("value after a password label" in x and "see the provider's settings" in x
                            for x in lines[1:5]), self.r.stdout)
        self.assertEqual(lines[5], "Not shown: 2 test values, 1 unclear. Full report: the file you gave with --out")
        self.assertTrue(self.full.startswith(self.r.stdout), "the report begins with the summary")

    def test_no_value_in_the_summary_or_the_report(self):
        text = self.r.stdout + self.r.stderr + self.full
        for v in (self.gl, self.gh, self.model, self.test_body, self.stored, self.guess, self.in_test):
            self.assertNotIn(v, text)
            self.assertNotIn(v[6:], text)

    def test_the_report_says_how_the_store_was_compared_and_lists_the_classes_per_rule(self):
        self.assertIn("Your maisecrets store: compared in this process by keyed fingerprint; no stored value was read.",
                      self.full)
        self.assertIn("BY RULE", self.full)
        self.assertRegex(self.full, r"github-pat +3: REAL provider format, in your input or a tool result 2; "
                                    r"TEST only in model output 1")


class SummaryShapeTests(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="maisecrets-audit-result-"))
        self.addCleanup(shutil.rmtree, self.base, True)

    def run_audit(self, home: Path):
        report = self.base / "report.txt"
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(report)],
                           capture_output=True, text=True, encoding="utf-8", env=_env(self.base, home), timeout=120)
        return r, report.read_text(encoding="utf-8")

    def test_at_most_ten_real_rows_and_the_rest_counted(self):
        tokens = [_gl() for _ in range(12)]
        _session(self.base, [_tool(f"GITLAB_TOKEN={t}", f"2026-11-{i + 1:02d}T10:00:00Z")
                             for i, t in enumerate(tokens)])
        r, full = self.run_audit(_home(self.base))
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], "AI history, last 30 days: 12 real token(s) reached Anthropic. Rotate them:")
        self.assertEqual(len(lines), 12, r.stdout)
        self.assertTrue(lines[10].startswith("  10. "), lines[10])
        self.assertTrue(lines[11].startswith("Not shown: 2 more real token(s). Full report: "), lines[11])
        self.assertIn("last 2026-11-12", lines[1], "the latest first when the session counts are equal")
        for t in tokens:
            self.assertNotIn(t, r.stdout + full)

    def test_without_a_real_token_the_verdict_says_so_and_without_a_store_the_line_says_so(self):
        _session(self.base, [_tool(f'db_password = "{"Wx" + _rnd(14)}"', "2026-11-01T10:00:00Z")])
        home = self.base / "nothing-stored"
        home.mkdir()
        r, _full = self.run_audit(home)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.splitlines()[0],
                         "AI history, last 30 days: no token that is surely real reached Anthropic.")
        self.assertIn("(your maisecrets store was not compared: maisecrets has stored nothing on this computer)",
                      r.stdout)

    def test_a_provider_format_only_in_test_files_gets_its_own_line_not_a_row(self):
        rows = [_tool(f"GITHUB_TOKEN={_gh()}", "2026-11-01T10:00:00Z", f"/repo/tests/test_api{n}.py") for n in range(2)]
        rows.append(_tool(f"GITLAB_TOKEN={_gl()}", "2026-11-02T10:00:00Z", "/repo/tests/fixtures/conf.txt"))
        rows.append(_tool(f"GITLAB_TOKEN={_gl()}", "2026-11-03T10:00:00Z"))
        _session(self.base, rows)
        r, full = self.run_audit(_home(self.base))
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], "AI history, last 30 days: 1 real token(s) reached Anthropic. Rotate them:")
        self.assertEqual(lines[2], "Also check: 3 provider-format token(s) seen only in test files (GitHub personal "
                                   "access token 2, GitLab personal access token 1). The report lists them.")
        self.assertTrue(lines[3].startswith("Not shown: nothing. Full report: the file you gave with --out"),
                        lines[3])
        self.assertEqual(len(lines), 4, r.stdout)
        self.assertEqual(full.count("(provider format, only in test code)"), 3)

    def test_a_path_given_with_out_is_not_echoed_and_the_temp_path_is(self):
        token = _gh()
        folder = self.base / f"reports-{token}"
        folder.mkdir()
        _session(self.base, [_tool(f"GITLAB_TOKEN={_gl()}", "2026-11-01T10:00:00Z")])
        env = _env(self.base, _home(self.base))
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(folder / "r.txt")],
                           capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
        text = r.stdout + r.stderr + (folder / "r.txt").read_text(encoding="utf-8")
        for part in (token, token[4:], token[-12:]):
            self.assertNotIn(part, text)
        self.assertIn("Full report: the file you gave with --out", r.stdout)
        tmp = self.base / f"tmp-{token}"
        tmp.mkdir()
        env["TMPDIR"] = str(tmp)
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py")], capture_output=True, text=True,
                           encoding="utf-8", env=env, timeout=120)
        made = list(tmp.glob("maisecrets-ai-history-*.txt"))
        self.assertEqual(len(made), 1)
        self.assertIn(f"Full report: {made[0].name} in your temp folder", r.stdout)
        for part in (token, token[4:], token[-12:], str(tmp)):
            self.assertNotIn(part, r.stdout + r.stderr + made[0].read_text(encoding="utf-8"))

    def test_a_report_that_cannot_be_written_names_the_error_and_no_path(self):
        token = _gh()
        _session(self.base, [_tool(f"GITLAB_TOKEN={_gl()}", "2026-11-01T10:00:00Z")])
        env = _env(self.base, _home(self.base))
        out = self.base / f"missing-{token}" / "r.txt"
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(out)],
                           capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(r.stdout, "The report file could not be written (FileNotFoundError).\n")
        for part in (token, token[4:], token[-12:]):
            self.assertNotIn(part, r.stdout + r.stderr)
        env["CLAUDE_CONFIG_DIR"] = str(self.base / "no-claude")   # no transcripts: the short report fails the same way
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(out)],
                           capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
        self.assertEqual((r.returncode, r.stdout), (2, "The report file could not be written (FileNotFoundError).\n"))

    def test_a_stored_value_only_in_a_local_record_is_not_a_row(self):
        value = "Qz" + _rnd(14)
        home = _home(self.base)
        _store(_env(self.base, home), value)
        _session(self.base, [{"type": "attachment", "timestamp": "2026-11-01T10:00:00Z",
                              "attachment": {"type": "hook_success", "content": f'db_password = "{value}"'}}])
        r, full = self.run_audit(home)
        self.assertEqual(r.stdout.splitlines()[0],
                         "AI history, last 30 days: no token that is surely real reached Anthropic.")
        self.assertIn("Not shown: 1 only on this computer.", r.stdout)
        self.assertIn("(in your maisecrets store)", full)
        self.assertNotIn(value, r.stdout + full)

    def test_nothing_found_is_one_line_and_exit_zero(self):
        _session(self.base, [_tool("all quiet", "2026-11-01T10:00:00Z")])
        r, _full = self.run_audit(_home(self.base))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "AI history, last 30 days: no secret found in 1 session file(s).\n")


class VerdictSignalTests(unittest.TestCase):
    """verdict_of, one signal at a time."""

    def e(self, sure="shape", kinds=("tool result",), test_all=False, typ="SECRET", rule="github-pat"):
        return {"type": typ, "sure": sure, "kinds": Counter(kinds), "test_all": test_all, "rule": rule}

    def test_the_signals_in_their_order(self):
        tok = _gh()
        self.assertEqual(at.verdict_of(self.e(), tok, False)[0], at.REAL)
        self.assertEqual(at.verdict_of(self.e(sure="guess"), tok, False), (at.UNKNOWN, "keyword guess"))
        self.assertEqual(at.verdict_of(self.e(sure="guess"), tok, True), (at.REAL, "in your maisecrets store"))
        self.assertEqual(at.verdict_of(self.e(sure="guess"), "my-test-token-" + _rnd(12), False)[0], at.TEST)
        self.assertEqual(at.verdict_of(self.e(rule="label-pw-literal"), "testpass", False)[0], at.TEST)
        self.assertEqual(at.verdict_of(self.e(), "gh" + "p_test" + _rnd(32), False),
                         (at.REAL, "provider format, in your input or a tool result"),
                         "a provider format whose random body starts with test is no self-named value")
        self.assertEqual(at.verdict_of(self.e(sure="guess"), "my-test-token-" + _rnd(12), True),
                         (at.REAL, "in your maisecrets store"), "the store comes before a test word")
        self.assertEqual(at.verdict_of(self.e(kinds=("model output",)), tok, False),
                         (at.TEST, "only in model output"))
        self.assertEqual(at.verdict_of(self.e(kinds=("model output", "tool result")), tok, False)[0], at.REAL)
        self.assertEqual(at.verdict_of(self.e(sure="guess", test_all=True), tok, False),
                         (at.TEST, "only in test code"))
        self.assertEqual(at.verdict_of(self.e(test_all=True), tok, False),
                         (at.UNKNOWN, "provider format, only in test code"))
        self.assertEqual(at.verdict_of(self.e(rule="label-pw-literal"), tok, False), (at.UNKNOWN, "keyword guess"),
                         "letters after a password label are no provider format")
        self.assertEqual(at.verdict_of(self.e(kinds=("local record",)), tok, False),
                         (at.UNKNOWN, "only in local records"))

    def test_a_test_mode_key_whose_format_holds_test_is_no_self_named_value(self):
        key = "sk" + "_test_" + _rnd(24)
        self.assertTrue(at.format_has_test("stripe-access-token"))
        self.assertFalse(at.format_has_test("github-pat"))
        self.assertFalse(at.names_itself(key, "stripe-access-token"))
        self.assertEqual(at.verdict_of(self.e(rule="stripe-access-token"), key, False),
                         (at.REAL, "provider format, in your input or a tool result"))

    def test_a_test_word_counts_only_at_a_border_of_the_value(self):
        for v in ("my-test-token", "testpass", "sk-fake-" + _rnd(20), _rnd(16) + "EXAMPLE", "ghp_test" + _rnd(32)):
            self.assertTrue(at.names_itself(v), v)
        for v in ("ghp_" + _rnd(10) + "Test" + _rnd(22), "Contest-Winter-" + _rnd(8)):
            self.assertFalse(at.names_itself(v), v)

    def test_a_documented_test_value_is_test(self):
        self.assertIs(at.public_test_value("not-a-documented-" + _rnd(10), "SECRET"), False)
        with mock.patch("maisecrets.detection.core.is_public_test_value", return_value=True):
            self.assertEqual(at.verdict_of(self.e(), _gh(), False), (at.TEST, "a documented test value"))


class StrongestFindingTests(unittest.TestCase):
    """A value found as a keyword guess and as a provider format keeps the provider format, in either order."""

    def run_rows(self, rules: list) -> str:
        base = Path(tempfile.mkdtemp(prefix="maisecrets-strong-"))
        self.addCleanup(shutil.rmtree, base, True)
        f = _session(base, [_tool("x", "2026-11-01T10:00:00Z")])
        value = "Ab" + _rnd(38)
        rows = [(n, "tool result", "2026-11-01", "SECRET", rule, value, None, False) for n, rule in enumerate(rules)]
        report = base / "report.txt"
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(base / "claude")}), \
                mock.patch.object(at, "run", lambda *a, **k: iter([((str(f), 0), rows, {}, 10)])), \
                mock.patch("sys.stdout", new=__import__("io").StringIO()), \
                mock.patch("sys.stderr", new=__import__("io").StringIO()):
            at.main(["--claude", "--out", str(report)])
        text = report.read_text(encoding="utf-8")
        self.assertNotIn(value, text)
        return next(line for line in text.splitlines() if line.startswith("  S1"))

    def test_both_orders(self):
        for rules in (["ds-keyword-equal-signs", "aws-secret-after-access-key"],
                      ["aws-secret-after-access-key", "ds-keyword-equal-signs"],
                      ["label-pw-literal", "aws-secret-after-access-key", "ds-keyword-equal-signs"]):
            with self.subTest(rules):
                row = self.run_rows(rules)
                self.assertIn("REAL    SECRET  aws-secret-after-access-key", row)


class ReportFileTests(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="maisecrets-report-file-"))
        self.addCleanup(shutil.rmtree, self.base, True)

    def test_a_token_in_a_folder_name_is_not_in_the_report(self):
        token = _gh()
        proj = self.base / "claude" / "projects" / f"-Users-x-{token}"
        proj.mkdir(parents=True)
        f = proj / "1a2b3c4d-0000-4000-8000-000000000000.jsonl"
        f.write_text(json.dumps(_tool(f"GITLAB_TOKEN={_gl()}", "2026-11-01T10:00:00Z")) + "\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(f, (old, old))
        report = self.base / "report.txt"
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(report)],
                           capture_output=True, text=True, encoding="utf-8", env=_env(self.base, _home(self.base)),
                           timeout=120)
        text = report.read_text(encoding="utf-8")
        self.assertIn("Claude 1a2b3c4d", text)
        for part in (token, token[4:], token[-12:]):
            self.assertNotIn(part, r.stdout + r.stderr + text)

    def test_only_a_session_id_in_the_clients_form_is_shown(self):
        uid = "1a2b3c4d-0000-4000-8000-000000000000"
        self.assertEqual(at.session_label("claude", Path(f"/p/{uid}.jsonl")), "Claude 1a2b3c4d")
        self.assertEqual(at.session_label("codex", Path(f"/s/rollout-2026-11-01T10-00-00-{uid}.jsonl")),
                         "Codex 1a2b3c4d")
        at._UNNAMED.clear()
        labels = []
        for stem in (f"sk_{uid}", f"{uid}-extra", f"xx-rollout-2026-11-01T10-00-00-{uid}", f"sk_{uid}"):
            path = Path(f"/p/{stem}.jsonl")
            label = at.session_label("claude", path)
            labels.append(label)
            import hashlib
            digest = hashlib.sha256(str(path).encode()).hexdigest()
            for part in ("1a2b3c4d", digest[:8], digest[:4]):
                self.assertNotIn(part, label, stem)
        self.assertEqual(labels, ["Claude session 1", "Claude session 2", "Claude session 3", "Claude session 1"])

    def test_without_transcripts_the_report_is_written_and_named(self):
        report = self.base / "report.txt"
        r = subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), "--out", str(report)],
                           capture_output=True, text=True, encoding="utf-8", env=_env(self.base, _home(self.base)),
                           timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "AI history, last 30 days: no transcripts found.\n"
                                   "Full report: the file you gave with --out\n")
        self.assertEqual(report.read_text(encoding="utf-8"), r.stdout)
        if os.name != "nt":
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "no Unix mode bits")
    def test_an_existing_out_file_gets_mode_0600_and_a_new_report_follows_no_link(self):
        out = self.base / "out.txt"
        out.write_text("old\n", encoding="utf-8")
        os.chmod(out, 0o644)
        at.write_report(out, "new\n")
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        self.assertEqual(out.read_text(encoding="utf-8"), "new\n")
        target = self.base / "target.txt"
        target.write_text("keep\n", encoding="utf-8")
        link = self.base / "link.txt"
        link.symlink_to(target)
        with self.assertRaises(FileExistsError):
            at.write_report(link, "new\n", new=True)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")


class RotationTableTests(unittest.TestCase):

    def setUp(self):
        self.table = at.load_rotation()

    def test_each_provider_has_a_name_a_place_and_the_docs_that_name_it(self):
        self.assertGreaterEqual(len(self.table["providers"]), 10)
        for key, p in self.table["providers"].items():
            self.assertEqual(set(p), {"name", "where", "docs"}, key)
            self.assertTrue(p["docs"].startswith("https://"), key)

    def test_each_prefix_names_a_known_provider_and_matches_a_rule(self):
        ids = {r.id for r in detect.rules() if r.type == "SECRET"}
        for row in self.table["rules"]:
            prefix, provider, noun = row[:3]
            self.assertIn(len(row), (3, 4), prefix)
            self.assertIn(provider, self.table["providers"], prefix)
            self.assertTrue(noun)
            self.assertTrue(any(i.startswith(prefix) for i in ids), f"{prefix} matches no rule")

    def test_the_longest_prefix_wins_and_an_unknown_rule_gets_the_settings(self):
        self.assertEqual(at.rotation_for("slack-bot-token", self.table)[0], "Slack bot token")
        self.assertEqual(at.rotation_for("slack-session-token", self.table),
                         ("Slack token", "see the provider's settings"))
        self.assertEqual(at.rotation_for("some-unknown-rule", self.table), ("some-unknown-rule",
                                                                            "see the provider's settings"))
        self.assertEqual(at.rotation_for("generic-api-key", self.table, "guess")[0], "value after a password label")

    def test_each_token_kind_gets_its_own_page_or_the_settings(self):
        want = {
            "github-pat": "github.com: Settings, Developer settings, Personal access tokens",
            "github-fine-grained-pat": "github.com: Settings, Developer settings, Personal access tokens",
            "github-oauth": "github.com: Settings, Applications, Authorized OAuth Apps",
            "github-refresh-token": "github.com: Settings, Applications, Authorized GitHub Apps",
            "github-app-token": "see the provider's settings",          # user and installation tokens in one rule
            "github-app-installation-jwt": "see the provider's settings",
            "gitlab-deploy-token": "see the provider's settings",
            "gitlab-runner-token": "see the provider's settings",
            "slack-session-cookie": "see the provider's settings",
            "slack-webhook-url": "see the provider's settings",
            "stripe-organization-api-key": "see the provider's settings",
            "cloudflare-account-api-token-2026-scannable": "see the provider's settings",
            "openai-api-key": "see the provider's settings",            # project, service account and admin keys
            "anthropic-admin-api-key": "see the provider's settings",
            "bitbucket-app-password": "see the provider's settings",
        }
        for rule, where in want.items():
            self.assertEqual(at.rotation_for(rule, self.table)[1], where, rule)
        self.assertTrue(at.rotation_for("gitlab-pat-routable", self.table)[1].startswith("https://gitlab.com/"))
        self.assertEqual(at.rotation_for("cloudflare-user-api-token", self.table)[1],
                         "https://dash.cloudflare.com/profile/api-tokens")

    def test_the_reference_names_every_provider_of_the_table(self):
        text = (ROOT / "skills" / "secret-hygiene" / "references" / "rotation.md").read_text(encoding="utf-8")
        for p in self.table["providers"].values():
            self.assertIn(p["name"], text)


class SkillFlowTests(unittest.TestCase):
    """SKILL.md shows the summary as it is and ends with the choices, never with an offer to write a script."""

    def test_the_skill_shows_the_summary_as_is_and_offers_the_choices(self):
        text = (ROOT / "skills" / "secret-hygiene" / "SKILL.md").read_text(encoding="utf-8")
        part = text[text.index("## Check what the AI agents already received"):text.index("## Contain a leak")]
        self.assertIn("show its stdout AS IS", part)
        self.assertIn("Never offer to write a script that compares the findings", part)
        for choice in ('"Show me how to rotate them"', '"Clean the local copies"', '"Show details"', '"Done"'):
            self.assertIn(choice, part)
        self.assertIn("AskUserQuestion", part)
        self.assertIn("numbered list", part)
        self.assertLess(part.index("`--scrub`"), part.index("`--scrub --yes`"))
        self.assertIn("explicit yes", part)


class HeldAmongTests(unittest.TestCase):
    """Vault.held_among: a live or a purged entry counts, a weak one does not, and a store with nothing in it gets
    no fingerprint key."""

    def test_live_purged_and_weak(self):
        v = Vault()
        a, b, c = "Qa" + _rnd(14), "Qb" + _rnd(14), "Qc" + _rnd(14)
        keys = [v.put(x, "SECRET", "label-password").key for x in (a, b)]
        v2 = Vault()
        v2._index["entries"][keys[0]]["purged"] = True   # in memory only
        self.assertEqual(v2.held_among([a, b, c]), {a, b})
        v2._index["entries"][keys[1]]["weak"] = True
        self.assertEqual(v2.held_among([a, b, c]), {a})

    def test_a_store_without_its_key_is_not_compared_and_nothing_is_made(self):
        for backend in ("jsonfile", "encrypted-file"):
            with self.subTest(backend):
                base = Path(tempfile.mkdtemp(prefix="maisecrets-held-"))
                self.addCleanup(shutil.rmtree, base, True)
                home = base / "home"
                home.mkdir()
                (home / "config.json").write_text(json.dumps({"backend": backend, "allow_plaintext_store": True}),
                                                  encoding="utf-8")
                (home / "index.json").write_text(json.dumps({"entries": {"SECRET_c1": {
                    "fingerprint": "0" * 16, "type": "SECRET"}}, "counters": {}, "by_fingerprint": {}}),
                    encoding="utf-8")
                if backend == "encrypted-file":   # an entry for the key: reading it would make the key file
                    (home / "vault.enc.json").write_text(json.dumps({"_maisecrets_fpkey": {"c": "AAAA", "t": "0"}}),
                                                         encoding="utf-8")
                before = sorted(p.name for p in home.iterdir())
                code = (f"import sys; sys.path.insert(0, {str(ROOT)!r}); from maisecrets.vault import Vault\n"
                        "print(Vault().held_among(['x' * 20]))")
                env = _env(base, home)
                env.pop("MAISECRETS_KEY_FILE", None)
                r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
                self.assertEqual(r.stdout.strip(), "None", r.stderr)
                self.assertEqual(sorted(p.name for p in home.iterdir()), before)

    def test_an_empty_store_gets_no_key(self):
        base = Path(tempfile.mkdtemp(prefix="maisecrets-held-"))
        self.addCleanup(shutil.rmtree, base, True)
        home = _home(base)
        code = (f"import sys; sys.path.insert(0, {str(ROOT)!r}); from maisecrets.vault import Vault\n"
                "print(sorted(Vault().held_among(['x' * 20])))")
        r = subprocess.run([sys.executable, "-c", code], env=_env(base, home), capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(r.stdout.strip(), "[]", r.stderr)
        self.assertEqual(sorted(p.name for p in home.iterdir()), ["config.json"])


if __name__ == "__main__":
    unittest.main()
