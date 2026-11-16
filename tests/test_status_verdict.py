"""The verdict on top of /maisecrets:status (maisecrets/status_verdict.py): each line ok, warn or FAIL, from temp
fakes of hooks.log, the marketplace copies of Claude Code and Codex, the store and the incident record.
Never the real paths.

Run: python3 -m unittest tests.test_status_verdict -v
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, incidents, status_verdict as sv  # noqa: E402

HOME = Path(os.environ["MAISECRETS_HOME"])
SESSION = "abcdef12-3456-7890"


def st(c) -> tuple[str, str]:
    """(state, all of the check's text): the fact, the next command and the longer detail."""
    return c.state, " | ".join(x for x in (c.fact, c.next and "Next: " + c.next, c.detail) if x)


def stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t))


def plugin(folder: Path, version: str, codex: bool = False) -> Path:
    d = folder / (".codex-plugin" if codex else ".claude-plugin")
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.json").write_text(json.dumps({"name": "maisecrets", "version": version}))
    return folder


def marketplace(checkout: Path, version: str) -> None:
    plugin(checkout, version)
    plugin(checkout, version, codex=True)
    (checkout / ".claude-plugin" / "marketplace.json").write_text(json.dumps(
        {"name": "maisecrets", "plugins": [{"name": "maisecrets", "source": "./", "version": "0.0.1"}]}))


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.claude = self.tmp / "claude"
        self.codex = self.tmp / "codex"


class HooksLineTests(_Tmp):
    def log(self, rows) -> Path:
        p = self.tmp / "hooks.log"
        p.write_text("".join(f"{stamp(t)}\t{ev}\tclaude\t{sess}\tBash\tpass\t5ms\tok\n" for t, ev, sess in rows))
        return p

    def test_ok_when_the_tool_call_hook_of_this_session_just_ran(self):
        now = time.time()
        log = self.log([(now - 180, "user-prompt", SESSION), (now - 2, "pre-tool", SESSION)])
        state, text = st(sv.hooks_verdict(log, SESSION, now))
        self.assertEqual(state, "ok")
        self.assertIn("ran (prompt 3 min ago, tool call 2 s ago)", text)
        self.assertNotIn("result", text.split(" | ")[0], "the short fact names only the hooks that ran")
        self.assertIn("the tool-result hook not yet", text)

    def test_fail_when_no_hook_of_this_session_ran(self):
        now = time.time()
        log = self.log([(now - 2, "pre-tool", "otherses")])
        state, text = st(sv.hooks_verdict(log, SESSION, now))
        self.assertEqual(state, "FAIL")
        self.assertIn("a new session", text)

    def test_warn_when_this_command_has_no_tool_call_hook(self):
        now = time.time()
        log = self.log([(now - 900, "user-prompt", SESSION), (now - 900, "pre-tool", SESSION)])
        state, text = st(sv.hooks_verdict(log, SESSION, now))
        self.assertEqual(state, "warn")
        self.assertIn("Next:", text)

    def test_fail_when_only_the_tool_call_hook_ran(self):
        # the session's prompts (/maisecrets:status itself, in Claude Code) fired UserPromptSubmit: no row is a failure
        now = time.time()
        state, text = st(sv.hooks_verdict(self.log([(now - 5, "pre-tool", SESSION)]), SESSION, now))
        self.assertEqual(state, "FAIL")
        self.assertIn("the prompt hook did not run", text)
        self.assertIn("the tool-call hook 5 s ago", text)

    def test_two_sessions_with_the_same_first_characters_are_told_apart(self):
        # Codex thread ids (UUIDv7) share their first characters for about a minute
        now = time.time()
        other = SESSION[:8] + "-other-thread"
        log = self.log([(now - 5, "user-prompt", other), (now - 2, "pre-tool", other)])
        self.assertEqual(sv.hooks_verdict(log, SESSION, now)[0], "FAIL")

    def test_the_session_whose_tool_call_hook_just_ran_is_this_one(self):
        # Claude Code started from a Codex shell inherits CODEX_THREAD_ID; the hooks ran under the Claude session
        now = time.time()
        log = self.log([(now - 60, "user-prompt", SESSION), (now - 2, "pre-tool", SESSION),
                        (now - 3000, "user-prompt", "outer-codex-thread"),
                        (now - 3000, "pre-tool", "outer-codex-thread")])
        self.assertEqual(sv.hooks_verdict(log, ["outer-codex-thread", SESSION], now)[0], "ok")
        self.assertEqual(sv.hooks_verdict(log, [SESSION, "outer-codex-thread"], now)[0], "ok")

    def test_warn_outside_a_session(self):
        now = time.time()
        state, text = st(sv.hooks_verdict(self.log([(now - 5, "pre-tool", "x")]), None, now))
        self.assertEqual(state, "warn")
        self.assertIn("Next:", text)


class VersionLineTests(_Tmp):
    def claude_install(self, installed: str, newest: str | None) -> Path:
        root = plugin(self.claude / "plugins" / "cache" / "maisecrets" / "maisecrets" / installed, installed)
        if newest:
            checkout = self.claude / "plugins" / "marketplaces" / "maisecrets"
            marketplace(checkout, newest)
            (self.claude / "plugins" / "known_marketplaces.json").write_text(json.dumps({"maisecrets": {
                "installLocation": str(checkout), "lastUpdated": "2026-11-15T10:00:00.000Z"}}))
        return root

    def codex_install(self, installed: str, newest: str | None) -> Path:
        root = plugin(self.codex / "plugins" / "cache" / "maisecrets" / "maisecrets" / installed, installed,
                      codex=True)
        if newest:
            marketplace(self.codex / ".tmp" / "marketplaces" / "maisecrets", newest)
        return root

    def verdict(self, root: Path) -> tuple[str, str]:
        return st(sv.version_verdict(sv.newest(root, self.claude, self.codex)))

    def test_claude_code_warns_with_the_update_command_when_the_copy_is_newer(self):
        state, text = self.verdict(self.claude_install("0.9.10", "0.9.11"))
        self.assertEqual(state, "warn")
        self.assertIn("0.9.11", text)
        self.assertIn("claude plugin update maisecrets@maisecrets", text)

    def test_ok_when_the_copy_holds_the_same_version(self):
        state, text = self.verdict(self.claude_install("0.9.11", "0.9.11"))
        self.assertEqual(state, "ok")
        self.assertIn("2026-11-15 10:00", text)

    def test_newest_unknown_without_a_copy_is_no_ok(self):
        state, text = self.verdict(self.claude_install("0.9.11", None))
        self.assertEqual(state, "warn")
        self.assertIn("newest unknown", text)

    def test_a_checkout_is_newest_unknown(self):
        state, text = self.verdict(plugin(self.tmp / "src", "0.9.11"))
        self.assertEqual(state, "warn")
        self.assertIn("newest unknown", text)

    def test_an_unreadable_or_pre_release_installed_version_is_no_ok(self):
        for inst in ("?", "0.9.0-rc1"):
            info = {"installed": inst, "newest": "0.9.1", "kind": "claude", "market": "m", "fetched": None,
                    "where": "Claude Code"}
            self.assertEqual(sv.version_verdict(info)[0], "warn", inst)

    def test_codex_warns_with_its_own_command(self):
        state, text = self.verdict(self.codex_install("0.9.10", "0.9.12"))
        self.assertEqual(state, "warn")
        self.assertIn("codex plugin add maisecrets@maisecrets", text)

    def test_a_marketplace_entry_that_points_elsewhere_gives_no_version(self):
        root = self.codex_install("0.9.10", "0.9.12")
        mkt = self.codex / ".tmp" / "marketplaces" / "maisecrets" / ".claude-plugin" / "marketplace.json"
        mkt.write_text(json.dumps({"plugins": [{"name": "maisecrets", "source": {"source": "url", "url": "x"}}]}))
        self.assertIn("newest unknown", self.verdict(root)[1])

    def test_a_source_outside_the_checkout_is_not_read(self):
        root = self.claude_install("0.9.10", "0.9.12")
        plugin(self.tmp / "elsewhere", "9.9.9")
        mkt = self.claude / "plugins" / "marketplaces" / "maisecrets" / ".claude-plugin" / "marketplace.json"
        mkt.write_text(json.dumps({"plugins": [{"name": "maisecrets", "source": "../../../../elsewhere"}]}))
        self.assertIn("newest unknown", self.verdict(root)[1])

    def test_the_session_start_note_names_the_newer_version_only(self):
        self.assertIn("0.9.11", sv.newer_version_note(self.claude_install("0.9.10", "0.9.11"), self.claude,
                                                      self.codex))
        shutil.rmtree(self.claude)
        self.assertIsNone(sv.newer_version_note(self.claude_install("0.9.11", "0.9.11"), self.claude, self.codex))


class CodexLineTests(_Tmp):
    def test_not_applicable_without_a_codex_install(self):
        self.assertEqual(sv.codex_verdict(self.tmp / "src", self.codex)[0], "n/a")

    def test_fail_when_the_hooks_are_not_trusted(self):
        root = self.codex / "plugins" / "cache" / "maisecrets" / "maisecrets" / "0.9.12"
        shutil.copytree(ROOT / "hooks", root / "hooks")
        plugin(root, "0.9.12", codex=True)
        (self.codex / "config.toml").write_text('[plugins."maisecrets@maisecrets"]\nenabled = true\n')
        lines = ["WARNING: maisecrets does not protect Codex now: codex hooks: 3 of 8 not trusted: open /hooks"]
        with mock.patch("maisecrets.codex_trust.status_lines", return_value=lines):
            state, text = st(sv.codex_verdict(self.tmp / "src", self.codex))
        self.assertEqual(state, "FAIL")
        self.assertIn("Next: trust them in /hooks", text)

    def test_ok_when_trusted(self):
        root = self.codex / "plugins" / "cache" / "maisecrets" / "maisecrets" / "0.9.12"
        (root / "hooks").mkdir(parents=True)
        (root / "hooks" / "hooks.json").write_text("{}")
        with mock.patch("maisecrets.codex_trust.status_lines", return_value=["codex hooks: trusted (8 of 8)"]):
            self.assertEqual(sv.codex_verdict(root, self.codex)[0], "ok")


class StoreLineTests(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def test_the_test_store_answers_and_says_test_mode(self):
        state, text = st(sv.store_verdict())
        self.assertEqual(state, "warn")
        self.assertIn("test file, 0 values | Next: set backend in config.json", text)

    def test_ok_for_a_real_store_that_answers(self):
        with mock.patch("maisecrets.vault.JsonFileBackend.test_mode", False):
            self.assertEqual(sv.store_verdict()[0], "ok")

    def test_fail_when_the_store_does_not_answer(self):
        with mock.patch("maisecrets.vault.JsonFileBackend.get", side_effect=OSError("locked")):
            state, text = st(sv.store_verdict())
        self.assertEqual(state, "FAIL")
        self.assertIn("Next:", text)


class IncidentLineTests(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        incidents.clear(HOME)
        self.addCleanup(lambda: incidents.clear(HOME))

    def test_ok_without_incidents(self):
        self.assertEqual(sv.incidents_verdict()[0], "ok")

    def test_warn_with_the_report_command_and_what_it_means(self):
        today = time.strftime("%Y-%m-%d")
        (HOME / "incidents.json").write_text(json.dumps({"version": 1, "groups": {"store.lock/lock": {
            "code": "store.lock", "cause": "lock", "class": "fail-closed", "event": "UserPromptSubmit",
            "tool_class": "-", "client": "claude", "days": [today], "count": 3, "plugin_version": "0.9.12"}}}))
        state, text = st(sv.incidents_verdict())
        self.assertEqual(state, "warn")
        self.assertIn("/maisecrets:report incident", text)
        self.assertIn("3 in 30 days", text)
        self.assertIn("3 times maisecrets refused a call", text)


def check(state: str, name: str, fact: str = "x", nxt: str | None = None) -> sv.Check:
    return sv.Check(state, name, fact, nxt, None)


OK6 = [check("ok", n) for n in sv.NAMES]


class HeadLineTests(unittest.TestCase):
    def test_all_ok_is_protected_with_all_checks_ok(self):
        self.assertEqual(sv.head_line("0.9.13", OK6, "claude"),
                         "\U0001F512 maisecrets 0.9.13 protects this session \u00b7 all checks ok")

    def test_warns_are_counted_as_notes(self):
        checks = OK6[:4] + [check("warn", "incidents", nxt="/maisecrets:report incident"),
                            check("warn", "self-test", nxt="/maisecrets:status test")]
        self.assertEqual(sv.head_line("0.9.13", checks, "claude"),
                         "\U0001F512 maisecrets 0.9.13 protects this session \u00b7 2 notes")

    def test_a_fail_opens_the_lock(self):
        checks = [check("FAIL", "hooks", nxt="a")] + OK6[1:4] + [check("warn", "incidents", nxt="b"), OK6[5]]
        head = sv.head_line("0.9.13", checks, "codex")
        self.assertEqual(head, "\u26a0\ufe0f maisecrets 0.9.13 is NOT protecting this session \u00b7 1 failure")
        self.assertNotIn("\U0001F512", head)

    def test_outside_a_session_no_lock_and_no_claim(self):
        for checks in (OK6, [check("warn", "hooks", nxt="a")] + OK6[1:], [check("FAIL", "store", nxt="a")] + OK6[1:]):
            head = sv.head_line("0.9.13", checks, None)
            self.assertTrue(head.startswith("maisecrets 0.9.13 \u00b7 status outside a client session"), head)
            self.assertNotIn("protect", head)
            self.assertNotIn("\U0001F512", head)
            self.assertNotIn("\u26a0\ufe0f", head)


class CheckLineTests(_Tmp):
    """Realistic facts: every state of every check, built by the verdict functions, fits in 80 columns."""

    def all_checks(self) -> list:
        now = time.time()
        log = self.tmp / "hooks.log"
        rows = [(now - 3599, "user-prompt"), (now - 59, "pre-tool"), (now - 86399, "post-tool")]
        log.write_text("".join(f"{stamp(t)}\t{ev}\tclaude\t{SESSION}\tBash\tpass\t5ms\tok\n" for t, ev in rows))
        out = [sv.hooks_verdict(log, SESSION, now, client=c) for c in (None, "claude", "codex")]
        out += [sv.hooks_verdict(self.tmp / "none.log", s, now, client=c) for s in (SESSION, None)
                for c in (None, "claude", "codex")]
        log2 = self.tmp / "h2.log"
        log2.write_text(f"{stamp(now - 5)}\tpre-tool\tclaude\t{SESSION}\tBash\tpass\t5ms\tok\n")
        out.append(sv.hooks_verdict(log2, SESSION, now))
        log2.write_text(f"{stamp(now - 900)}\tuser-prompt\tclaude\t{SESSION}\tBash\tpass\t5ms\tok\n"
                        f"{stamp(now - 900)}\tpre-tool\tclaude\t{SESSION}\tBash\tpass\t5ms\tok\n")
        out.append(sv.hooks_verdict(log2, SESSION, now))
        for kind in ("claude", "codex", "synced", "other"):
            for inst, new in (("0.9.13", "0.9.13"), ("0.9.12", "0.9.13"), ("0.9.13", None), ("0.10.0-rc1", "0.9.13")):
                out.append(sv.version_verdict({"installed": inst, "newest": new, "kind": kind, "market": "maisecrets",
                                               "fetched": "2026-11-15T10:00:00.000Z", "where": "Claude Code"}))
        lines = ["WARNING: maisecrets does not protect Codex now: codex hooks: 3 of 8 not trusted: open /hooks"]
        with mock.patch("maisecrets.codex_trust.status_lines", return_value=lines):
            out.append(sv.codex_verdict(ROOT, self.codex))
        with mock.patch("maisecrets.vault.JsonFileBackend.get", side_effect=TimeoutError("slow")):
            out.append(sv.store_verdict())
        out.append(sv.store_verdict())
        out.append(sv.Check("ok", "store", "Windows Credential Locker, 9999 values", None, None))
        out.append(sv.Check("warn", "incidents", "9999 in 30 days", "/maisecrets:report incident", None))
        return out

    def test_no_check_line_over_80_characters(self):
        from maisecrets import selftest
        checks = self.all_checks()
        with mock.patch.object(selftest, "load", return_value={}):
            checks.append(selftest.verdict(sessions=[SESSION]))
        texts = {"tool": 1.0, "prompt": None, "leak": None}
        for res in ({"tool": 1.0}, {"prompt": 1.0}, {"leak": 1.0}, {"tool": 1.0, "prompt": 2.0}):
            with mock.patch.object(selftest, "load", return_value={"result": {**texts, **res}}):
                for c in (None, "claude", "codex"):
                    checks.append(selftest.verdict(now=86000.0, sessions=[SESSION], client=c))
        with mock.patch.object(selftest, "load", return_value={"result": {**texts, "tool": 1.0, "prompt": 2.0,
                                                                          "session": "other", "version": "0"}}):
            checks.append(selftest.verdict(now=86000.0 * 3, sessions=[SESSION], version="0.9.13"))
        self.assertIn("warn", {c.state for c in checks})
        self.assertIn("FAIL", {c.state for c in checks})
        for client in (None, "claude", "codex"):
            lines = sv.check_lines(checks, client)
            for line in lines:
                with self.subTest(line=line):
                    self.assertLessEqual(len(line), 80)
            arrows = {line.index("\u2192") for line in lines if "\u2192" in line}
            self.assertEqual(arrows, {sv.NAME_COL + 4 + sv.FACT_COL + 2}, "every arrow in one column")
        for c in checks:
            if c.state in ("warn", "FAIL"):
                self.assertLessEqual(len(c.fact), sv.FACT_COL, c)

    def test_marks_and_the_arrow_for_warn_and_fail_only(self):
        lines = sv.check_lines([check("ok", "hooks", "ran"), check("warn", "version", "a", "x"),
                                check("FAIL", "store", "b", "y"), check("n/a", "codex", "not installed")], "claude")
        self.assertEqual([ln[1] for ln in lines], ["\u2713", "!", "\u2717", "\u2013"])
        self.assertEqual(lines[0], " \u2713 hooks       ran")
        self.assertEqual(lines[1], " ! version     " + "a".ljust(sv.FACT_COL) + "  \u2192  x")
        self.assertNotIn("\u2192", lines[3])

    def test_codex_gets_the_typed_form(self):
        c = check("warn", "self-test", "not run", "/maisecrets:status test")
        self.assertTrue(sv.check_lines([c], "codex")[0].endswith("\u2192  maisecrets: status test"))
        self.assertTrue(sv.check_lines([c], "claude")[0].endswith("\u2192  /maisecrets:status test"))
        self.assertEqual(sv.form("status all", None), "/maisecrets:status all (Codex: maisecrets: status all)")
        self.assertEqual(sv.form("status all", "codex"), "maisecrets: status all")


class StatusOutputTests(unittest.TestCase):
    def run_status(self, args: list, servers: int = 0) -> list[str]:
        buf = io.StringIO()
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        if servers:
            Path(tmp, "claude").mkdir()
            Path(tmp, "claude", ".claude.json").write_text(json.dumps({"mcpServers": {
                f"srv{i}": {"type": "http", "url": f"https://mcp{i}.example.com/mcp"} for i in range(servers)}}))
        # the client folders are temp fakes: never the real ones
        with redirect_stdout(buf), mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": tmp + "/claude",
                                                                "CODEX_HOME": tmp + "/codex"}):
            cli.cmd_status(args)
        return buf.getvalue().splitlines()

    def test_the_default_is_a_head_six_check_lines_and_one_line_of_facts(self):
        out = self.run_status([])
        self.assertTrue(out[0].startswith("maisecrets ") or out[0][:1] in ("\U0001F512", "\u26a0"), out[0])
        self.assertEqual(out[1], "")
        checks = out[2:8]
        self.assertEqual([ln.split()[1] for ln in checks], list(sv.NAMES))
        for line in checks:
            mark = line.split()[0]
            self.assertIn(mark, sv.MARK.values())
            self.assertEqual("\u2192" in line, mark in ("!", "\u2717"), line)
        self.assertEqual(out[8], "")
        self.assertRegex(out[9], r"^names: .+ \u00b7 rules: \d+ \u00b7 regions?: .+ \u00b7 \d+ label languages?$")
        self.assertTrue(out[10].startswith("all details: /maisecrets:status all"))
        self.assertEqual(len(out), 11, "the default shows no details")
        self.assertNotIn("Details", out)

    def test_all_shows_the_checks_then_the_details_with_grouped_vault_references(self):
        out = self.run_status(["all"], servers=8)
        self.assertEqual([ln.split()[1] for ln in out[2:8]], list(sv.NAMES))
        details = out[out.index("Details"):]
        self.assertTrue(any(ln.startswith("maisecrets ") for ln in details))
        self.assertTrue(any(ln.startswith("hooks: ") for ln in details), "the longer fact of a check")
        refs = [ln for ln in details if ln.startswith("vault references: ") and "client config" not in ln]
        self.assertEqual(refs, ["vault references: not used yet: 8 (srv0, srv1, \u2026)"])
        self.assertFalse(any(ln.startswith("all details:") for ln in out))


if __name__ == "__main__":
    unittest.main()
