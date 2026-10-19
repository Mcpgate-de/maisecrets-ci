"""The guard outside the plugin folder (hooks/guard.py) and the heartbeat maisecrets writes for it.

The guard and maisecrets run as two hooks of the same event, in parallel, as Claude Code runs them.
The guard lets a call pass only when maisecrets wrote the heartbeat for exactly that call; it stays
silent where maisecrets is not meant to run. The real client is in the harness (plugin_folder_moved
with the guard); these tests hold the parts: the name both sides compute, the account check, the
answers per event, and that the heartbeat exists only when the guard is installed.

Run: python3 -m unittest tests.test_guard -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402
import _hygiene  # noqa: E402

sys.path.insert(0, str(ROOT / "hooks"))
import guard  # noqa: E402

GUARD = ROOT / "hooks" / "guard.py"
DISPATCH = ROOT / "hooks" / "dispatch.py"
PAYLOADS = {
    "UserPromptSubmit": {"hook_event_name": "UserPromptSubmit", "prompt": "hello", "prompt_id": "p1",
                         "session_id": "S1", "transcript_path": "", "cwd": "/tmp"},
    "PreToolUse": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"},
                   "tool_use_id": "call_1", "prompt_id": "p1", "session_id": "S1", "transcript_path": "",
                   "cwd": "/tmp"},
    "PostToolUse": {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"},
                    "tool_response": {"stdout": "a", "stderr": ""}, "tool_use_id": "call_1", "prompt_id": "p1",
                    "session_id": "S1", "transcript_path": "", "cwd": "/tmp"},
}
EVENT = {"UserPromptSubmit": "user-prompt", "PreToolUse": "pre-tool", "PostToolUse": "post-tool"}


def _reason(out: dict) -> str:
    """The text a refusal shows, for each of the three event shapes."""
    spec = out.get("hookSpecificOutput") or {}
    return out.get("reason") or spec.get("permissionDecisionReason") or spec.get("updatedToolOutput") or ""


def tearDownModule():  # noqa: N802 - unittest hook
    for f in ("guard.json",):
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    _hygiene.assert_pristine()


class _Env(unittest.TestCase):
    def setUp(self):
        self.claude = Path(tempfile.mkdtemp(prefix="maisecrets-guard-claude-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.claude, ignore_errors=True))
        patcher = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.claude)})
        patcher.start()
        self.addCleanup(patcher.stop)
        __import__("shutil").rmtree(Path(HOME, "alive"), ignore_errors=True)
        self.addCleanup(lambda: Path(HOME, "guard.json").unlink(missing_ok=True))

    def installed(self, expect: str) -> None:
        Path(HOME, "guard.json").write_text(json.dumps({"expect": expect}))

    def account(self, org: str = "org-1", acc: str = "acc-1", synced: bool = True) -> None:
        (self.claude / ".claude.json").write_text(json.dumps({"oauthAccount": {"organizationUuid": org,
                                                                               "accountUuid": acc}}))
        if synced:
            d = self.claude / "plugins" / "synced" / f"{org}_{acc}" / "maisecrets" / ".claude-plugin"
            d.mkdir(parents=True)
            (d / "plugin.json").write_text("{}")


class ExpectedTests(_Env):
    def test_the_account_decides_whether_maisecrets_is_meant_to_run(self):
        self.installed("synced")
        self.account(synced=True)
        self.assertTrue(guard.expected())
        # another account of the same machine, with no maisecrets synced for it
        self.account(org="org-1", acc="acc-2", synced=False)
        self.assertFalse(guard.expected())
        # installed from a marketplace instead
        (self.claude / "plugins" / "installed_plugins.json").write_text(
            json.dumps({"plugins": {"maisecrets@maisecrets": [{}]}}))
        self.assertTrue(guard.expected())
        # switched off by the user
        (self.claude / "settings.json").write_text(json.dumps({"enabledPlugins": {"maisecrets@maisecrets": False}}))
        self.assertFalse(guard.expected())

    def test_the_account_a_synced_copy_wrote_counts_for_that_account_only(self):
        # the root of the copy that registered may be gone; its account's synced folder decides
        Path(HOME, "guard.json").write_text(json.dumps({"expect": "synced", "root": "/gone/maisecrets",
                                                        "accounts": ["org-1_acc-1"]}))
        self.account("org-1", "acc-1", synced=True)
        self.assertTrue(guard.expected())
        self.account("org-1", "acc-2", synced=False)
        self.assertFalse(guard.expected(), "another account of the machine")

    def test_an_organisation_that_takes_maisecrets_out_of_the_sync_is_not_blocked_for_good(self):
        Path(HOME, "guard.json").write_text(json.dumps({"expect": "synced", "accounts": ["org-1_acc-1"]}))
        self.account("org-1", "acc-1", synced=False)
        self.assertFalse(guard.expected(), "no synced folder and nothing in the trash: removed from the sync")
        # an update moved the folder to the trash a moment ago: the guard expects maisecrets. A move keeps the
        # folder's old mtime (APFS), so the folder is made old first and then moved, as Claude Code moves it
        trash = self.claude / "plugins" / ".trash"
        trash.mkdir(parents=True)
        (trash / "a-plain-file").write_text("x")              # one file in the trash must not stop the scan
        src = self.claude / "plugins" / "maisecrets-old"
        src.mkdir()
        old = time.time() - guard.TRASH_WINDOW - 3600
        os.utime(src, (old, old))
        (trash / "1790000000000-1-abc").mkdir()
        os.rename(src, trash / "1790000000000-1-abc" / "maisecrets")
        self.assertTrue(guard.expected())
        with mock.patch.object(guard.time, "time", return_value=time.time() + guard.TRASH_WINDOW + 60):
            self.assertFalse(guard.expected(), "long gone: the organisation removed it")
        # the synced folder is there (an update rewrote it in place): expected
        self.account("org-1", "acc-1", synced=True)
        self.assertTrue(guard.expected())

    def test_every_generation_of_the_synced_folder_counts(self):
        # an update writes maisecrets~g2 beside maisecrets, then moves the old one away (measured 2026-09-29);
        # the next update writes ~g3. A guard that knew one name went silent after the next update
        Path(HOME, "guard.json").write_text(json.dumps({"expect": "synced", "accounts": ["org-1_acc-1"],
                                                        "roots": {"org-1_acc-1": "/gone/maisecrets~g2"}}))
        self.account("org-1", "acc-1", synced=False)
        base = self.claude / "plugins" / "synced" / "org-1_acc-1"
        for name, want in (("maisecrets-other", False), ("maisecrets~gx", False), ("maisecrets~g3", True)):
            with self.subTest(name):
                (base / name / ".claude-plugin").mkdir(parents=True)
                (base / name / ".claude-plugin" / "plugin.json").write_text("{}")
                with mock.patch.object(guard, "_recently_trashed", return_value=False):
                    self.assertEqual(guard.expected(), want)
        # and without a guard.json the account's own copy of any generation counts too
        Path(HOME, "guard.json").unlink()
        self.assertTrue(guard.expected())

    def test_a_second_profile_on_the_same_home_keeps_its_own_synced_folder(self):
        root_a = self.claude / "plugins" / "synced" / "org-1_acc-1" / "maisecrets"
        (root_a / ".claude-plugin").mkdir(parents=True)
        (root_a / ".claude-plugin" / "plugin.json").write_text("{}")
        Path(HOME, "guard.json").write_text(json.dumps({"expect": "synced", "root": str(root_a),
                                                        "accounts": ["org-1_acc-1"]}))
        self.account("org-1", "acc-2", synced=True)            # profile B, with its own synced copy
        self.assertTrue(guard.expected(), "profile A's root must not silence profile B")

    def test_no_guard_json_and_no_synced_copy_expects_nothing(self):
        # a manual install whose home went away: maisecrets writes no heartbeat, so the guard must not wait
        # for one (review, 2026-09-29: the healthy session was blocked)
        (self.claude / "plugins").mkdir(parents=True)
        (self.claude / "plugins" / "installed_plugins.json").write_text(
            json.dumps({"plugins": {"maisecrets@maisecrets": [{}]}}))
        self.assertFalse(guard.expected())

    def test_a_second_copy_switched_off_is_not_maisecrets_switched_off(self):
        # the directory copy off, the synced copy on: maisecrets is meant to run, so the guard watches it
        # (field report, 2026-10-07: the guard stayed silent and a session without maisecrets let a@b.com through)
        self.installed("synced")
        self.account(synced=True)
        # the field case: the directory copy installed and switched off, the synced copy on
        (self.claude / "plugins" / "installed_plugins.json").write_text(json.dumps({"plugins": {
            "maisecrets@anthropic-plugin-directory": [{}]}}))
        (self.claude / "settings.json").write_text(json.dumps({"enabledPlugins": {
            "maisecrets@anthropic-plugin-directory": False, "maisecrets@synced": True}}))
        self.assertTrue(guard.expected())
        (self.claude / "settings.json").write_text(json.dumps({"enabledPlugins": {
            "maisecrets@anthropic-plugin-directory": False, "maisecrets@synced": False}}))
        self.assertFalse(guard.expected(), "every copy off")

    def test_only_the_ids_of_installed_copies_count(self):
        # codex review of the guard fix, 2026-10-07: a stale key of a copy that is not installed decides nothing,
        # an installed copy with no entry is on, a marketplace may list maisecrets under another name
        self.installed("always")
        plugins = self.claude / "plugins"
        plugins.mkdir(parents=True, exist_ok=True)
        copy = Path(tempfile.mkdtemp(prefix="maisecrets-copy-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(copy, ignore_errors=True))
        (copy / ".claude-plugin").mkdir()
        (copy / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "maisecrets"}))
        (plugins / "installed_plugins.json").write_text(json.dumps({"plugins": {
            "privacy-guard@corp": [{"installPath": str(copy)}], "notmaisecrets-tool@x": [{}]}}))
        settings = self.claude / "settings.json"
        cases = (({"privacy-guard@corp": False}, False, "the renamed copy is off"),
                 ({"privacy-guard@corp": False, "maisecrets@old": True}, False, "a stale key on decides nothing"),
                 ({"maisecrets@old": False}, True, "a stale key off decides nothing; the copy has no entry: on"),
                 ({"notmaisecrets-tool@x": False}, True, "another plugin with the word in its name"),
                 ({"privacy-guard@corp": False, "notmaisecrets-tool@x": True}, False,
                  "another installed plugin with the word in its name is no copy of maisecrets"))
        for plugins_set, want, why in cases:
            with self.subTest(why):
                settings.write_text(json.dumps({"enabledPlugins": plugins_set}))
                self.assertEqual(guard.expected(), want, why)

    def test_the_repository_root_local_file_wins_over_an_old_nested_one(self):
        self.installed("synced")
        self.account(synced=True)
        repo = Path(tempfile.mkdtemp(prefix="maisecrets-repo-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        (repo / ".git").mkdir()
        (repo / ".claude").mkdir()
        (repo / ".claude" / "settings.local.json").write_text(
            json.dumps({"enabledPlugins": {"maisecrets@synced": False}}))
        (repo / "sub" / ".claude").mkdir(parents=True)
        (repo / "sub" / ".claude" / "settings.local.json").write_text(
            json.dumps({"enabledPlugins": {"maisecrets@synced": True}}))
        self.assertFalse(guard.expected(str(repo / "sub")))

    def test_a_project_switch_wins_over_the_user_switch(self):
        self.installed("synced")
        self.account(synced=True)
        (self.claude / "settings.json").write_text(json.dumps({"enabledPlugins": {"maisecrets@synced": True}}))
        project = Path(tempfile.mkdtemp(prefix="maisecrets-project-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(project, ignore_errors=True))
        (project / ".claude").mkdir()
        (project / ".claude" / "settings.json").write_text(json.dumps({"enabledPlugins": {"maisecrets@synced": False}}))
        self.assertFalse(guard.expected(str(project)))
        (project / ".claude" / "settings.local.json").write_text(
            json.dumps({"enabledPlugins": {"maisecrets@synced": True}}))
        self.assertTrue(guard.expected(str(project)), "local wins over the project file")

    def test_a_project_that_switches_maisecrets_off_is_left_alone(self):
        self.installed("always")
        project = Path(tempfile.mkdtemp(prefix="maisecrets-project-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(project, ignore_errors=True))
        (project / ".claude").mkdir()
        (project / ".claude" / "settings.local.json").write_text(
            json.dumps({"enabledPlugins": {"maisecrets@synced": False}}))
        (project / "sub").mkdir()
        self.assertFalse(guard.expected(str(project / "sub")))
        self.assertTrue(guard.expected(str(Path(tempfile.gettempdir()))))

    def test_off_from_a_terminal(self):
        self.installed("always")
        r = subprocess.run([sys.executable, str(GUARD), "--off"], capture_output=True, text=True,
                           env=dict(os.environ))
        self.assertIn("is off", r.stdout)
        self.assertFalse(guard.expected())
        self.assertIn("--off", guard.MESSAGE, "the refusal names the way out")

    def test_the_mode_in_guard_json(self):
        self.installed("always")
        self.assertTrue(guard.expected(), "always: the harness and a machine that must have it")
        self.installed("off")
        self.assertFalse(guard.expected())
        Path(HOME, "guard.json").unlink()
        self.assertFalse(guard.expected(), "not installed: synced by default, and no account here")


class DecisionTests(_Env):
    def test_no_heartbeat_blocks_each_event_and_names_the_way_out(self):
        self.installed("always")
        want = {"UserPromptSubmit": lambda o: o["decision"] == "block",
                "PreToolUse": lambda o: o["hookSpecificOutput"]["permissionDecision"] == "deny",
                "PostToolUse": lambda o: "withheld" in o["hookSpecificOutput"]["updatedToolOutput"]}
        for name, payload in PAYLOADS.items():
            with self.subTest(name):
                started = time.monotonic()
                out = guard.decide(payload, wait=0.3)
                self.assertTrue(want[name](out), out)
                self.assertIn("/reload-plugins", json.dumps(out))
                # after a synced update /reload-plugins keeps the gone folder: the refusal gives the restart
                # command of this very session and the bug behind it
                self.assertIn(f"claude --resume {payload['session_id']}", json.dumps(out))
                self.assertIn("anthropics/claude-code#97847", json.dumps(out))
                # the command stands on a line of its own, so it is seen, and a triple click copies just it
                self.assertIn(f"\n\n    claude --resume {payload['session_id']}\n\n", _reason(out))
                self.assertGreaterEqual(time.monotonic() - started, 0.3, "it waits before it refuses")

    def test_a_refusal_leaves_a_marker_for_the_incident_report_and_a_pass_leaves_none(self):
        import io
        self.installed("always")
        marker = Path(HOME, "incident-marker.guard.fired")
        with mock.patch.dict(os.environ, {"MAISECRETS_GUARD_WAIT": "0.1"}), \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps(PAYLOADS["UserPromptSubmit"]))), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            guard.main()
        self.assertTrue(marker.is_dir())
        marker.rmdir()
        with mock.patch.object(sys, "stdin", io.StringIO("{}")), mock.patch.object(sys, "stdout", io.StringIO()):
            guard.main()
        self.assertFalse(marker.exists(), "no refusal, no marker")

    def test_the_resume_command_goes_to_the_clipboard_once_per_session(self):
        self.installed("always")
        clip = Path(tempfile.mkdtemp()) / "clip.txt"
        self.addCleanup(lambda: __import__("shutil").rmtree(clip.parent, ignore_errors=True))
        # a stand-in for pbcopy: appends what it reads, so a second copy would show
        writer = [sys.executable, "-c", f"import sys; open({str(clip)!r}, 'a').write(sys.stdin.read() + '\\n')"]
        with mock.patch.dict(os.environ, {"MAISECRETS_GUARD_CLIPBOARD": "on"}), \
                mock.patch.object(guard, "_clipboard_commands", return_value=[writer]):
            first = json.dumps(guard.decide(PAYLOADS["UserPromptSubmit"], wait=0.1))
            second = json.dumps(guard.decide(PAYLOADS["PreToolUse"], wait=0.1))
        self.assertEqual(clip.read_text(), "claude --resume S1\n", "copied once, for this session")
        self.assertIn("It was copied to your clipboard", first)
        self.assertIn("It was copied to your clipboard", second)

    def test_no_clipboard_writer_means_no_clipboard_claim(self):
        self.installed("always")
        failing = [sys.executable, "-c", "import sys; sys.exit(1)"]
        for cmds in ([], [failing]):
            with self.subTest(cmds=bool(cmds)), mock.patch.dict(os.environ, {"MAISECRETS_GUARD_CLIPBOARD": "on"}), \
                    mock.patch.object(guard, "_clipboard_commands", return_value=cmds):
                out = json.dumps(guard.decide(PAYLOADS["UserPromptSubmit"], wait=0.1))
                self.assertNotIn("clipboard", out)
                self.assertIn("claude --resume S1", out)

    def test_the_heartbeat_of_this_call_lets_it_pass_and_stays_for_a_second_guard(self):
        self.installed("always")
        for name, payload in PAYLOADS.items():
            with self.subTest(name):
                hooks._heartbeat(EVENT[name], payload, done=True)
                path = Path(HOME, "alive", guard.heartbeat_name("S1", EVENT[name],
                                                               payload.get("tool_use_id") or payload["prompt_id"]))
                self.assertTrue(path.exists(), "maisecrets and the guard compute the same name")
                self.assertEqual(guard.decide(payload, wait=0.3), {})
                # a second registration (user and managed settings) waits for the same heartbeat (review:
                # the first guard took it away, and the second one refused a healthy call)
                self.assertTrue(path.exists())
                self.assertEqual(guard.decide(payload, wait=0.3), {})

    def test_a_hook_that_started_and_never_answered_is_refused(self):
        # a fatal error after the start leaves the start mark only (Codex review, 2026-09-29)
        self.installed("always")
        hooks._heartbeat("pre-tool", PAYLOADS["PreToolUse"])
        with mock.patch.dict(guard.ANSWER_WAIT, {"PreToolUse": 0.3}):
            out = guard.decide(PAYLOADS["PreToolUse"], wait=0.2)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_the_refusal_asks_for_a_retry_first_unless_an_update_is_seen(self):
        # a busy computer delayed maisecrets once and the next call went through; "exit this session" stopped an
        # autonomous run for a person (2026-09-29). Only a folder in the trash is a sign of an update
        self.installed("always")
        for trashed, first in ((False, "Run it again. If every call fails this way"),
                               (True, "a plugin update replaced its folder")):
            with self.subTest(trashed=trashed), mock.patch.object(guard, "_recently_trashed", return_value=trashed):
                reason = _reason(guard.decide(PAYLOADS["PreToolUse"], wait=0.2))
                self.assertIn(first, reason)
                self.assertIn(f"claude --resume {PAYLOADS['PreToolUse']['session_id']}", reason)
                self.assertEqual("Run it again" in reason, not trashed)

    def test_a_hook_that_started_is_no_update_and_asks_for_a_retry_only(self):
        self.installed("always")
        for name in ("PreToolUse", "PostToolUse"):
            with self.subTest(name):
                hooks._heartbeat(EVENT[name], PAYLOADS[name])
                with mock.patch.dict(guard.ANSWER_WAIT, {name: 0.2}), \
                        mock.patch.object(guard, "_recently_trashed", return_value=True):
                    reason = _reason(guard.decide(PAYLOADS[name], wait=0.1))
                self.assertIn("started for this call but did not answer in time", reason)
                self.assertNotIn("claude --resume", reason, "maisecrets is there: no restart helps")
                # after a tool the call ran: running it again would repeat it
                self.assertEqual("Run it again" in reason, name == "PreToolUse")

    def test_the_guard_waits_as_long_as_maisecrets_may_take(self):
        from maisecrets import cli
        for event, timeout in cli.GUARD_TIMEOUTS.items():
            with self.subTest(event):
                watchdog = hooks.WATCHDOG_SECONDS[EVENT[event]]
                self.assertGreater(guard.ANSWER_WAIT[event], watchdog, "an answer at the watchdog still counts")
                self.assertGreater(timeout, 5 + guard.ANSWER_WAIT[event], "the hook timeout covers both waits")

    def test_the_heartbeat_of_another_call_does_not_count(self):
        self.installed("always")
        other = dict(PAYLOADS["PreToolUse"], tool_use_id="call_2")
        hooks._heartbeat("pre-tool", other, done=True)
        self.assertIn("hookSpecificOutput", guard.decide(PAYLOADS["PreToolUse"], wait=0.2))
        other_session = dict(PAYLOADS["PreToolUse"], session_id="S2")
        hooks._heartbeat("pre-tool", other_session, done=True)
        self.assertIn("hookSpecificOutput", guard.decide(PAYLOADS["PreToolUse"], wait=0.2))

    def test_silent_for_codex_an_unguarded_event_and_an_account_without_maisecrets(self):
        self.installed("always")
        codex = dict(PAYLOADS["PreToolUse"], turn_id="t1")
        codex.pop("prompt_id")
        self.assertEqual(guard.decide(codex, wait=0.2), {})
        self.assertEqual(guard.decide({"hook_event_name": "SessionStart", "session_id": "S1"}, wait=0.2), {})
        self.installed("synced")
        self.account(synced=False)
        started = time.monotonic()
        self.assertEqual(guard.decide(PAYLOADS["PreToolUse"], wait=2), {})
        self.assertLess(time.monotonic() - started, 1, "it does not wait where maisecrets is not meant to run")


class HeartbeatTests(_Env):
    def test_the_heartbeat_exists_only_when_the_guard_is_installed(self):
        hooks._heartbeat("pre-tool", PAYLOADS["PreToolUse"])
        self.assertFalse(Path(HOME, "alive").exists(), "no guard, no file")
        self.installed("synced")
        codex = dict(PAYLOADS["PreToolUse"], turn_id="t")
        codex.pop("prompt_id")                  # Codex sends turn_id, never prompt_id
        hooks._heartbeat("pre-tool", codex)
        self.assertFalse(Path(HOME, "alive").exists() and any(Path(HOME, "alive").iterdir()),
                         "Codex: no heartbeat")

    def test_a_home_it_cannot_stat_does_not_raise(self):
        # Path.exists raises PermissionError before Python 3.12 when the home cannot be searched; the call
        # stood before the hook's try, so the process exited 1 without an answer, and exit 1 lets the prompt
        # through (Opus review, 2026-10-09)
        with mock.patch("pathlib.Path.exists", side_effect=PermissionError(13, "denied")):
            hooks._heartbeat("user-prompt", PAYLOADS["UserPromptSubmit"])
            hooks._heartbeat("pre-tool", PAYLOADS["PreToolUse"], done=True)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "root and Windows ignore the mode bits")
    def test_a_prompt_with_a_token_is_blocked_when_the_home_cannot_be_searched(self):
        import random
        import string
        import shutil
        base = Path(tempfile.mkdtemp(prefix="maisecrets-nosearch-"))
        home = base / "home"
        home.mkdir()
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        os.chmod(home, 0o600)
        self.addCleanup(lambda: (os.chmod(home, 0o700), shutil.rmtree(base, ignore_errors=True)))
        token = "glpat-" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
        env.update(MAISECRETS_HOME=str(home), PYTHONUTF8="1", MS_TEST_CLIP=str(base / "clip"))
        payload = dict(PAYLOADS["UserPromptSubmit"], prompt=f"use {token}", cwd=str(base))
        r = subprocess.run([sys.executable, str(DISPATCH), "user-prompt"], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, cwd=str(base))
        self.assertEqual(r.returncode, 0, r.stderr.replace(token, "<token>"))
        self.assertEqual(json.loads(r.stdout).get("decision"), "block")
        self.assertNotIn(token, r.stdout)

    def test_an_old_heartbeat_is_swept(self):
        self.installed("synced")
        hooks._heartbeat("pre-tool", PAYLOADS["PreToolUse"])
        old = next(Path(HOME, "alive").iterdir())
        os.utime(old, (time.time() - 3600, time.time() - 3600))
        hooks._heartbeat("pre-tool", dict(PAYLOADS["PreToolUse"], tool_use_id="call_9"))
        self.assertFalse(old.exists())


@unittest.skipIf(os.name == "nt", "a synced install registers the guard on POSIX only (hooks/dispatch.py)")
class SyncedInstallTests(_Env):
    """A synced install gets the guard without a step by its user: the session start places the script,
    the heartbeat is on, and the admin registers the hooks once in the organisation's managed settings."""

    def test_a_synced_install_writes_the_heartbeat_without_guard_json(self):
        with mock.patch.object(hooks, "_from_a_synced_folder", return_value=True):
            hooks._heartbeat("pre-tool", PAYLOADS["PreToolUse"])
        self.assertTrue(any(Path(HOME, "alive").iterdir()))

    def test_the_folder_check_reads_the_synced_path(self):
        synced = os.path.join(os.sep, "u", ".claude", "plugins", "synced", "o_a", "maisecrets")
        with mock.patch.object(hooks.os.path, "realpath", return_value=synced):
            self.assertTrue(hooks._from_a_synced_folder())
        self.assertFalse(hooks._from_a_synced_folder(), "the checkout is no synced folder")

    def synced_copy(self) -> Path:
        import shutil
        base = Path(tempfile.mkdtemp(prefix="maisecrets-synced-"))
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        copy = base / "plugins" / "synced" / "org_acc" / "maisecrets"
        for part in ("hooks", "maisecrets", ".claude-plugin"):
            shutil.copytree(ROOT / part, copy / part, ignore=shutil.ignore_patterns("__pycache__"))
        for f in (".guard-removed", "guard.json"):
            Path(HOME, f).unlink(missing_ok=True)
        self.addCleanup(lambda: Path(HOME, ".guard-removed").unlink(missing_ok=True))
        return copy

    def start(self, copy: Path) -> str:
        r = subprocess.run([sys.executable, str(copy / "hooks" / "dispatch.py"), "session-start"],
                           input=json.dumps({"session_id": "S1", "hook_event_name": "SessionStart"}),
                           capture_output=True, text=True, env=dict(os.environ, CLAUDECODE="1"), timeout=60)
        return json.loads(r.stdout)["systemMessage"]

    def guard_entries(self) -> int:
        settings = self.claude / "settings.json"
        if not settings.exists():
            return 0
        hooks_cfg = json.loads(settings.read_text()).get("hooks") or {}
        return sum("maisecrets-guard.py" in e["hooks"][0]["command"] for es in hooks_cfg.values() for e in es)

    def test_the_session_start_of_a_synced_copy_places_and_registers_the_guard_once(self):
        copy = self.synced_copy()
        script = self.claude / "maisecrets-guard.py"
        script.write_text("an older guard")
        (self.claude / "settings.json").write_text(json.dumps({"model": "x"}))
        self.account("org-1", "acc-1", synced=False)
        msg = self.start(copy)
        self.assertIn("is on", msg)
        self.assertIn("registered its guard", msg)
        written = json.loads(Path(HOME, "guard.json").read_text())
        self.assertEqual((written["accounts"], written["root"]), (["org-1_acc-1"], str(copy.resolve())))
        self.assertEqual(written["roots"], {"org-1_acc-1": str(copy.resolve())}, "the measured folder per account")
        self.assertTrue(guard.expected(), "the measured folder counts, wherever Claude Code put it")
        # a second profile on the same maisecrets home adds its account and keeps the first one
        self.account("org-1", "acc-2", synced=False)
        self.start(copy)
        self.assertEqual(json.loads(Path(HOME, "guard.json").read_text())["accounts"], ["org-1_acc-1", "org-1_acc-2"])
        roots = json.loads(Path(HOME, "guard.json").read_text())["roots"]
        self.assertEqual(sorted(roots), ["org-1_acc-1", "org-1_acc-2"])
        self.assertEqual(script.read_bytes(), GUARD.read_bytes(), "the stale script was replaced")
        self.assertEqual(self.guard_entries(), 3, "UserPromptSubmit, PreToolUse, PostToolUse")
        self.assertEqual(json.loads((self.claude / "settings.json").read_text())["model"], "x")
        self.assertNotIn("registered its guard", self.start(copy), "said once")
        self.assertEqual(self.guard_entries(), 3, "registered once")

    def test_a_guard_removed_by_hand_or_switched_off_stays_off(self):
        from maisecrets import cli
        copy = self.synced_copy()
        self.start(copy)
        cli.remove_guard()
        self.assertEqual(self.guard_entries(), 0)
        self.assertNotIn("registered its guard", self.start(copy))
        self.assertEqual(self.guard_entries(), 0, "removed by hand: the next session start does not undo it")
        Path(HOME, ".guard-removed").unlink()
        cfg = json.loads(Path(HOME, "config.json").read_text())
        Path(HOME, "config.json").write_text(json.dumps({**cfg, "guard": False}))
        try:
            self.start(copy)
            self.assertEqual(self.guard_entries(), 0, '"guard": false keeps it off')
        finally:
            Path(HOME, "config.json").write_text(json.dumps(cfg))

    def test_the_registration_follows_the_plugins_matchers_after_an_update(self):
        from maisecrets import cli
        copy = self.synced_copy()
        self.start(copy)
        settings = self.claude / "settings.json"
        data = json.loads(settings.read_text())
        for e in data["hooks"]["PreToolUse"]:
            if "maisecrets-guard.py" in e["hooks"][0]["command"]:
                e["matcher"] = "Bash|OldTool"               # what an older release registered
        settings.write_text(json.dumps(data))
        self.start(copy)
        now = [e["matcher"] for e in json.loads(settings.read_text())["hooks"]["PreToolUse"]
               if "maisecrets-guard.py" in e["hooks"][0]["command"]]
        plugin = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]["matcher"]
        self.assertEqual(now, [plugin])
        self.assertEqual(cli._guard_entries()["PreToolUse"][0]["matcher"], plugin)

    def test_the_settings_keep_their_mode_and_their_symlink(self):
        copy = self.synced_copy()
        real = self.claude / "dotfiles-settings.json"
        real.write_text(json.dumps({"model": "x"}))
        os.chmod(real, 0o600)
        (self.claude / "settings.json").symlink_to(real)
        self.start(copy)
        self.assertTrue((self.claude / "settings.json").is_symlink(), "the dotfiles link stays a link")
        self.assertEqual(os.stat(real).st_mode & 0o777, 0o600)
        self.assertIn("maisecrets-guard.py", real.read_text())

    def test_settings_of_another_shape_do_not_break_the_session_start(self):
        copy = self.synced_copy()
        for text in ("[]", json.dumps({"hooks": "x"}), json.dumps({"hooks": {"PreToolUse": ["x", 3]}})):
            with self.subTest(text):
                (self.claude / "settings.json").write_text(text)
                self.assertIn("is on", self.start(copy))
                self.assertEqual((self.claude / "settings.json").read_text(), text)

    def test_off_from_a_terminal_survives_the_next_session_start(self):
        copy = self.synced_copy()
        self.start(copy)
        subprocess.run([sys.executable, str(GUARD), "--off"], capture_output=True, text=True, env=dict(os.environ))
        self.start(copy)
        self.assertEqual(json.loads(Path(HOME, "guard.json").read_text())["expect"], "off")

    def test_after_guard_remove_the_script_is_not_placed_again(self):
        from maisecrets import cli
        copy = self.synced_copy()
        self.start(copy)
        cli.remove_guard()
        self.start(copy)
        self.assertFalse((self.claude / "maisecrets-guard.py").exists())

    def test_the_backup_is_as_private_as_the_settings(self):
        copy = self.synced_copy()
        settings = self.claude / "settings.json"
        settings.write_text(json.dumps({"env": {"A_TOKEN": "x"}}))
        os.chmod(settings, 0o600)
        self.start(copy)
        backups = list(self.claude.glob("settings.json.bak-maisecrets-*"))
        self.assertTrue(backups)
        self.assertEqual(os.stat(backups[0]).st_mode & 0o777, 0o600)

    def test_only_our_hook_object_is_ours(self):
        from maisecrets import cli
        wrapper = {"type": "command", "command": "/opt/tools/run-maisecrets-guard.py-audit"}
        mixed = {"matcher": "Bash", "hooks": [wrapper, {"type": "command", "command": cli.GUARD_COMMAND}]}
        out = cli._without_guard({"PreToolUse": [mixed]})
        self.assertEqual(out, {"PreToolUse": [{"matcher": "Bash", "hooks": [wrapper]}]},
                         "the user's hook beside ours, and a command that merely names the file, stay")
        shaped = {"type": "command", "command": '"/opt/bin/audit" "/u/.claude/maisecrets-guard.py"'}
        self.assertEqual(cli._without_guard({"PreToolUse": [{"hooks": [shaped]}]}),
                         {"PreToolUse": [{"hooks": [shaped]}]}, "a wrapper of the same shape is not ours")
        old = {"hooks": [{"type": "command", "command": '"/usr/bin/python3" "/u/.claude/maisecrets-guard.py"'}]}
        self.assertEqual(cli._without_guard({"PostToolUse": [old]}), {}, "an older registration of ours goes")

    def test_guard_false_in_the_policy_switches_a_registered_guard_off_and_back(self):
        copy = self.synced_copy()
        self.start(copy)
        cfg = json.loads(Path(HOME, "config.json").read_text())
        Path(HOME, "config.json").write_text(json.dumps({**cfg, "guard": False}))
        try:
            self.start(copy)
            written = json.loads(Path(HOME, "guard.json").read_text())
            self.assertEqual((written["expect"], written.get("by")), ("off", "policy"))
            self.assertFalse(guard.expected())
        finally:
            Path(HOME, "config.json").write_text(json.dumps(cfg))
        self.start(copy)
        self.assertEqual(json.loads(Path(HOME, "guard.json").read_text())["expect"], "synced",
                         "the policy allows it again: the policy's off ends, a person's --off would not")

    def test_guard_false_without_a_guard_json_and_a_persons_off_under_the_policy(self):
        from maisecrets import cli
        Path(HOME, "guard.json").unlink(missing_ok=True)
        cli.guard_off_by_policy()
        self.assertEqual(json.loads(Path(HOME, "guard.json").read_text()),
                         {"expect": "off", "by": "policy"}, "a managed guard reads it too")
        subprocess.run([sys.executable, str(GUARD), "--off"], capture_output=True, text=True, env=dict(os.environ))
        self.assertNotIn("by", json.loads(Path(HOME, "guard.json").read_text()), "now the person's own off")

    def test_settings_that_are_not_json_are_left_alone(self):
        copy = self.synced_copy()
        (self.claude / "settings.json").write_text("{not json")
        msg = self.start(copy)
        self.assertIn("is on", msg)
        self.assertEqual((self.claude / "settings.json").read_text(), "{not json")

    def test_the_managed_settings_use_the_plugins_matchers_and_answer_without_the_script(self):
        from maisecrets import cli
        managed = cli.managed_guard_settings()["hooks"]
        plugin = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
        for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse"):
            # the plugin's groups, without those of a Codex-only tool: Claude Code has no apply_patch
            self.assertEqual([e.get("matcher") for e in managed[event]],
                             [e.get("matcher") for e in plugin[event]
                              if e.get("matcher") not in cli.CODEX_ONLY_MATCHERS])
        home = Path(tempfile.mkdtemp(prefix="maisecrets-nohome-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        r = subprocess.run(["sh", "-c", cli.MANAGED_GUARD_COMMAND], input="{}", capture_output=True, text=True,
                           env=dict(os.environ, HOME=str(home)))
        self.assertEqual(r.stdout, "{}", "a machine where maisecrets never ran: nothing happens")


class ParallelProcessTests(_Env):
    """Both hooks as processes, started together, as Claude Code starts the hooks of one event."""

    def run_both(self, payload: dict, with_maisecrets: bool, guards: int = 1) -> list:
        env = dict(os.environ, MAISECRETS_GUARD_WAIT="5" if with_maisecrets else "1")
        # every process started before any gets its input: Claude Code starts the hooks of one event together
        procs = [subprocess.Popen([sys.executable, str(GUARD)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  env=env, text=True) for _ in range(guards)]
        if with_maisecrets:
            m = subprocess.Popen([sys.executable, str(DISPATCH), EVENT[payload["hook_event_name"]]],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, text=True)
            m.communicate(json.dumps(payload), timeout=30)
        return [json.loads(p.communicate(json.dumps(payload), timeout=30)[0]) for p in procs]

    def test_with_maisecrets_running_every_event_passes_and_without_it_every_event_is_stopped(self):
        self.installed("always")
        for name, payload in PAYLOADS.items():
            with self.subTest(name):
                self.assertEqual(self.run_both(payload, with_maisecrets=True, guards=2), [{}, {}],
                                 "two registrations of the guard both let a healthy call pass")
                other = dict(payload, prompt_id="p-other", tool_use_id="call-other")
                self.assertNotEqual(self.run_both(other, with_maisecrets=False), [{}])


if __name__ == "__main__":
    unittest.main()
